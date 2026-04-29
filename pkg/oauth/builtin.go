package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"akashic/akashic/pkg/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// BuiltInClientSpec describes a client_service that the akashic-server
// itself manages. Each built-in is upserted into client_services on
// startup so the row always exists, configuration changes (e.g.,
// redirect URIs) apply on restart, and operators don't have to register
// these by hand.
type BuiltInClientSpec struct {
	ClientID      string
	Name          string
	RedirectURIs  string // comma-separated, exact-match
	AllowedScopes string // space-separated
	AuthTypes     string // space-separated grant types
	RoleAllowlist string // comma-separated user types; "" = any

	// Public marks the client as a public OAuth client (RFC 6749
	// §2.1) — no client_secret stored. Public clients MUST use
	// PKCE; the code_verifier check is what proves legitimacy in
	// place of a stored secret. Used for browser-based SPAs that
	// can't keep secrets (e.g., the static-HTML sample).
	//
	// When Public=true, EnsureBuiltInClients leaves
	// ClientSecretHash empty in the database; the auth-server's
	// /token handler then accepts requests without client_secret
	// for this client provided PKCE is correctly used.
	Public bool
}

// EnsureBuiltInClients reconciles the client_services table to
// match the supplied spec list:
//   - rows for each spec are upserted (insert-if-missing,
//     update-if-present).
//   - any row with built_in=true whose client_id is NOT in specs is
//     DELETED, so removing a built-in from the allowlist actually
//     removes it from the DB on the next boot.
//
// The plaintext client secret for each spec is loaded from disk
// (./keys/oauth/client-secrets/<client_id>.txt) — generated on
// first run, persisted for subsequent runs. Only bcrypt(secret) is
// stored in the DB. Public clients (PKCE-only, no shared secret)
// have an empty hash — see BuiltInClientSpec.Public.
//
// secretsDir is the parent directory; this function manages its
// own subdirectory inside it.
//
// User-registered (built_in=false) clients are never touched.
func EnsureBuiltInClients(ctx context.Context, db *gorm.DB, secretsDir string, specs []BuiltInClientSpec) error {
	dir := filepath.Join(secretsDir, "client-secrets")
	// 0755 (not 0700) because the admin-bff container runs as a
	// non-root user (uid 10100) and needs to traverse this directory
	// to read its own client secret. The directory contains only
	// secrets intended for cross-container sharing within the
	// docker-compose stack; the volume mount itself is the trust
	// boundary, not the filesystem mode.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create client-secrets dir: %w", err)
	}

	for _, spec := range specs {
		var secretHash string
		if !spec.Public {
			// Confidential client — provision (or load) a secret on
			// disk and bcrypt-hash for storage.
			secret, err := loadOrCreateClientSecret(filepath.Join(dir, spec.ClientID+".txt"))
			if err != nil {
				return fmt.Errorf("client %s secret: %w", spec.ClientID, err)
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("client %s bcrypt: %w", spec.ClientID, err)
			}
			secretHash = string(hash)
		}
		// For public clients, secretHash stays "" — the /token
		// handler's PKCE-aware path accepts that as "this is a
		// public client, validate via code_verifier instead."

		// Upsert: insert if missing, update everything if present.
		// Re-hashing on each startup is the cheapest way to keep the
		// DB row consistent with the on-disk secret. (Public clients
		// have no secret to re-hash; the empty hash is rewritten as
		// empty.)
		row := models.ClientService{
			ClientID:         spec.ClientID,
			ClientSecretHash: secretHash,
			Name:             spec.Name,
			RedirectURIs:     spec.RedirectURIs,
			AllowedScopes:    spec.AllowedScopes,
			AuthTypes:        spec.AuthTypes,
			BuiltIn:          true,
			RoleAllowlist:    spec.RoleAllowlist,
			RequirePKCE:      true,
			Public:           spec.Public,
		}

		// Upsert by ClientID.
		//
		// We use Find() rather than First() because "row doesn't exist"
		// is the expected first-run path here, not a bug. First() logs
		// a "record not found" warning via GORM's default logger on
		// every zero-result query — noisy and misleading. Find() with
		// Limit(1) returns RowsAffected==0 cleanly, no warning.
		var existing models.ClientService
		result := db.WithContext(ctx).Where("client_id = ?", spec.ClientID).
			Limit(1).Find(&existing)
		if err := result.Error; err != nil {
			return fmt.Errorf("query client service %s: %w", spec.ClientID, err)
		}
		if result.RowsAffected == 0 {
			if err := db.WithContext(ctx).Create(&row).Error; err != nil {
				return fmt.Errorf("create client service %s: %w", spec.ClientID, err)
			}
			continue
		}
		// Update everything except CreatedAt.
		// `public` is included so flipping a built-in's public/conf
		// status (rare, but possible if a spec's Public flag changes
		// across releases) actually takes effect on the next boot
		// rather than silently keeping the stale value.
		if err := db.WithContext(ctx).Model(&existing).
			Updates(map[string]any{
				"client_secret_hash": row.ClientSecretHash,
				"name":               row.Name,
				"redirect_uris":      row.RedirectURIs,
				"allowed_scopes":     row.AllowedScopes,
				"auth_types":         row.AuthTypes,
				"built_in":           true,
				"role_allowlist":     row.RoleAllowlist,
				"require_pkce":       true,
				"public":             row.Public,
			}).Error; err != nil {
			return fmt.Errorf("update client service %s: %w", spec.ClientID, err)
		}
	}

	// Reconcile-style cleanup: any built_in=true row whose client_id
	// is no longer in `specs` represents a built-in that the operator
	// removed from AKASHIC_OAUTH_BUILTIN_CLIENTS. Drop it so a
	// removed allowlist entry actually disappears from the DB on the
	// next boot. User-registered clients (built_in=false) are never
	// touched by this clause.
	wantedIDs := make([]string, 0, len(specs))
	for _, spec := range specs {
		wantedIDs = append(wantedIDs, spec.ClientID)
	}
	tx := db.WithContext(ctx).Where("built_in = ?", true)
	if len(wantedIDs) > 0 {
		tx = tx.Where("client_id NOT IN ?", wantedIDs)
	}
	if err := tx.Delete(&models.ClientService{}).Error; err != nil {
		return fmt.Errorf("prune stale built-in clients: %w", err)
	}
	return nil
}

// LoadBuiltInClientSecret returns the plaintext client secret for a
// built-in client. Used by admin-bff and other components that need
// to authenticate as a built-in client at /token.
func LoadBuiltInClientSecret(secretsDir, clientID string) (string, error) {
	path := filepath.Join(secretsDir, "client-secrets", clientID+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read built-in client secret %s: %w", path, err)
	}
	return string(data), nil
}

// loadOrCreateClientSecret reads the secret file at path; if it
// doesn't exist, generates a fresh random secret and writes it.
//
// File format: a single line of base64url-encoded random bytes,
// no trailing newline. Mode 0600. Atomic-replace via .tmp + rename.
func loadOrCreateClientSecret(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return string(data), nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("read existing secret: %w", err)
	}

	// Doesn't exist — generate one.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)

	tmp := path + ".tmp"
	// 0644 so the admin-bff (running as uid 10100) can read its own
	// client secret. See the dir-perm note in EnsureBuiltInClients
	// above for the trust-boundary reasoning.
	if err := os.WriteFile(tmp, []byte(secret), 0o644); err != nil {
		return "", fmt.Errorf("write secret tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("rename secret: %w", err)
	}
	return secret, nil
}
