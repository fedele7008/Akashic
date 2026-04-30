// Package clientservice consolidates the OAuth-client CRUD primitives
// shared between the api-server's bearer-authenticated /clients
// surface (pkg/server/api/clients_handlers.go) and the control-plane
// mTLS-gated /clients surface (pkg/server/control/clients_handlers.go).
//
// Both surfaces had identical client_id-generation, secret-generation,
// bcrypt-hashing, and row-construction logic — diverging only on the
// HTTP shape (request body parsing, response envelope, owner-scoped
// vs. operator-level access). This package owns the domain operations;
// the handlers stay focused on translating HTTP ↔ domain.
//
// Pure domain logic: no http.ResponseWriter, no JSON envelopes, no
// CSRF / session handling. Errors are typed so each handler can map
// them to whichever wire-level error code its caller expects.
package clientservice

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// CreateParams describes the OAuth client to register. Caller is
// responsible for validating input shape (name non-empty, redirect_uris
// well-formed) before calling — this package focuses on the
// generate-secret-and-persist-the-row sequence, not request parsing.
type CreateParams struct {
	Name          string
	Description   string
	HomepageURL   string
	// Public=false → WEB / confidential client (gets a client_secret).
	// Public=true  → SPA / public client (no secret, PKCE-only).
	Public bool
	// RequirePKCE applies to confidential clients (operator-configurable);
	// the model's normalize() hook forces true for Public regardless,
	// so callers can pass anything when Public=true.
	RequirePKCE bool
	// Comma-separated redirect URI allowlist; matched exact-string at
	// /authorize.
	RedirectURIs string
	// Space-separated scope allowlist. Pass "" to use the model's
	// default of "openid profile email".
	AllowedScopes string
	// Owner-scoping. Set for tenant-developer-side calls (api-server
	// /clients with bearer auth — token's `sub` is the owner). Leave
	// nil for operator-side calls (control-plane /clients with mTLS —
	// no per-user owner). The model's `canManage()` check honours this
	// distinction at edit/delete time.
	OwnerUserID *uuid.UUID

	// IsTenantPortal marks this row as the deployment's primary
	// portal — at most one row may have this set. Operator-only;
	// the api-server's bearer-authenticated /clients endpoint does
	// NOT thread this through to clientservice (passes false).
	IsTenantPortal bool
}

// CreateResult is what Create returns on success.
type CreateResult struct {
	Client *models.ClientService
	// Secret is the plaintext client_secret, populated only for
	// confidential (Public=false) clients. Caller must surface this
	// to the operator exactly once; only the bcrypt hash persists.
	Secret string
}

// Create generates a fresh client_id, mints+bcrypts a secret if the
// client is confidential, and persists the row. Returns the new row
// plus (for confidential clients) the plaintext secret.
//
// Built-in clients are NOT created via this function — they live in
// pkg/oauth/builtin.go's EnsureBuiltInClients reconcile loop.
//
// Cross-row constraint: at most one row may have IsTenantPortal=true.
// When p.IsTenantPortal is true and another row already holds the
// flag, returns ErrTenantPortalAlreadySet — caller maps this to the
// surface-appropriate error code (CLI exit, 409, etc.) and is
// expected to surface the existing primary's client_id so the
// operator can decide whether to clear it first.
func Create(ctx context.Context, db *gorm.DB, p CreateParams) (*CreateResult, error) {
	if p.IsTenantPortal {
		var existing models.ClientService
		err := db.WithContext(ctx).
			Where("is_tenant_portal = ?", true).
			Limit(1).Find(&existing).Error
		if err != nil {
			return nil, fmt.Errorf("check existing tenant portal: %w", err)
		}
		if existing.ClientID != "" {
			return nil, fmt.Errorf("%w (current: %s)", ErrTenantPortalAlreadySet, existing.ClientID)
		}
	}

	clientID, err := generateClientID()
	if err != nil {
		return nil, fmt.Errorf("generate client_id: %w", err)
	}

	var (
		secret string
		hash   string
	)
	if !p.Public {
		secret, err = generateSecret()
		if err != nil {
			return nil, fmt.Errorf("generate secret: %w", err)
		}
		h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash secret: %w", err)
		}
		hash = string(h)
	}

	scopes := p.AllowedScopes
	if scopes == "" {
		scopes = "openid profile email"
	}

	row := models.ClientService{
		ClientID:         clientID,
		ClientSecretHash: hash,
		Name:             p.Name,
		Description:      p.Description,
		HomepageURL:      p.HomepageURL,
		RedirectURIs:     p.RedirectURIs,
		AllowedScopes:    scopes,
		AuthTypes:        string(models.AuthTypeAuthorizationCode),
		BuiltIn:          false,
		Public:           p.Public,
		RequirePKCE:      p.RequirePKCE,
		OwnerUserID:      p.OwnerUserID,
		IsTenantPortal:   p.IsTenantPortal,
	}
	if err := db.WithContext(ctx).Create(&row).Error; err != nil {
		return nil, fmt.Errorf("db insert: %w", err)
	}
	return &CreateResult{Client: &row, Secret: secret}, nil
}

// Sentinel errors. Handlers errors.Is()-check to map them to specific
// HTTP error codes (BUILTIN_IMMUTABLE, PUBLIC_CLIENT_NO_SECRET,
// TENANT_PORTAL_ALREADY_SET).
var (
	ErrBuiltInImmutable       = errors.New("built-in client secrets are server-managed")
	ErrPublicClientNoSecret   = errors.New("public clients have no shared secret to rotate")
	ErrTenantPortalAlreadySet = errors.New("a tenant portal is already registered")
)

// RotateSecret issues a fresh client_secret for an existing
// confidential client and invalidates the old one. Returns the
// plaintext for the caller to surface (shown ONCE).
//
// Refuses for built-in clients (server-managed) and public clients
// (PKCE replaces the shared secret on every authorization).
func RotateSecret(ctx context.Context, db *gorm.DB, c *models.ClientService) (string, error) {
	if c.BuiltIn {
		return "", ErrBuiltInImmutable
	}
	if c.Public {
		return "", ErrPublicClientNoSecret
	}
	secret, err := generateSecret()
	if err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash secret: %w", err)
	}
	if err := db.WithContext(ctx).Model(c).
		Update("client_secret_hash", string(hash)).Error; err != nil {
		return "", fmt.Errorf("db update: %w", err)
	}
	return secret, nil
}

// generateClientID produces a `tc-` (tenant-client) prefixed
// 10-hex-char ID. Used by both api-server and control-plane create
// paths so a row inspector can't tell at a glance which surface
// registered any given row.
func generateClientID() (string, error) {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const hex = "0123456789abcdef"
	out := make([]byte, len(buf)*2)
	for i, b := range buf {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return "tc-" + string(out), nil
}

// generateSecret produces a 32-byte base64url-encoded secret.
// 256 bits of entropy; matches the entropy of the auth-code TTL
// material so the same brute-force budget threatens both equally.
func generateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
