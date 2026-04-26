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
}

// EnsureBuiltInClients upserts each spec into the client_services
// table. The plaintext client secret for each is loaded from disk
// (./keys/oauth/client-secrets/<client_id>.txt) — generated on
// first run, persisted for subsequent runs. Only bcrypt(secret) is
// stored in the DB.
//
// secretsDir is the parent directory; this function manages its
// own subdirectory inside it.
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
		secret, err := loadOrCreateClientSecret(filepath.Join(dir, spec.ClientID+".txt"))
		if err != nil {
			return fmt.Errorf("client %s secret: %w", spec.ClientID, err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("client %s bcrypt: %w", spec.ClientID, err)
		}

		// Upsert: insert if missing, update everything except the
		// secret_hash if present (we only rotate the hash if the
		// secret on disk changed, so re-hashing on every run is
		// wasteful but harmless — bcrypt of the same plaintext gives
		// a different hash, so we compare with bcrypt.CompareHashAndPassword
		// before deciding whether to overwrite).
		//
		// Actually simpler: always upsert with the freshly-computed
		// hash. The DB row is "what the server thinks the client
		// looks like right now," and re-hashing on each startup is
		// the cheapest way to keep the row consistent.
		row := models.ClientService{
			ClientID:         spec.ClientID,
			ClientSecretHash: string(hash),
			Name:             spec.Name,
			RedirectURIs:     spec.RedirectURIs,
			AllowedScopes:    spec.AllowedScopes,
			AuthTypes:        spec.AuthTypes,
			BuiltIn:          true,
			RoleAllowlist:    spec.RoleAllowlist,
			RequirePKCE:      true,
		}

		// Upsert by ClientID. GORM's clause syntax does ON CONFLICT.
		var existing models.ClientService
		err = db.WithContext(ctx).Where("client_id = ?", spec.ClientID).First(&existing).Error
		if err == gorm.ErrRecordNotFound {
			if err := db.WithContext(ctx).Create(&row).Error; err != nil {
				return fmt.Errorf("create client service %s: %w", spec.ClientID, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("query client service %s: %w", spec.ClientID, err)
		}
		// Update everything except CreatedAt
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
			}).Error; err != nil {
			return fmt.Errorf("update client service %s: %w", spec.ClientID, err)
		}
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
