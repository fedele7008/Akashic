package models

import (
	"time"

	"github.com/google/uuid"
)

// MFATrustedDevice records a "remember this device" cookie issued
// during a successful MFA challenge. Phase 9f.
//
// The cookie value lives only in the user's browser; the server
// stores SHA-256 of the cookie value, so a DB dump alone can't
// forge a trusted-device session — you'd also need to break the
// hash. The 32-byte random cookie token gives 256 bits of entropy,
// well past brute-force.
//
// One row per (user, browser) pair. A user with three devices
// (laptop, phone, work machine) ends up with three rows. Revoking
// is per-row — the user can drop a single device without affecting
// the others, and an operator (or the user themselves) can wipe all
// rows for a user as part of a security incident response.
//
// Lifecycle:
//
//	issue   — minted on successful MFA when "remember this device"
//	          is checked. ExpiresAt is min(user-pick, policy ceiling).
//	use     — login flow finds the cookie hash, confirms not
//	          revoked + not expired, bumps LastUsedAt, skips MFA.
//	revoke  — RevokedAt set; the cookie no longer satisfies the
//	          trusted-device check. Row stays for audit.
//	expire  — ExpiresAt elapses; row stays for audit, periodic
//	          PurgeExpired() drops them after a grace period (30d
//	          past expiry — keeps the audit trail useful).
type MFATrustedDevice struct {
	ID     uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`
	UserID uuid.UUID `gorm:"type:uuid;not null;index:idx_mfa_trusted_user" json:"user_id"`

	// CookieTokenHash is SHA-256 of the cookie's plaintext value.
	// Lookups happen by hash, so the column carries a unique-index
	// to make the WHERE clause point-lookup-fast and to prevent
	// (the vanishingly rare but real) hash collision from creating
	// ambiguity. bytea (32 bytes) — not text, so no encoding
	// surprises.
	CookieTokenHash []byte `gorm:"type:bytea;not null;uniqueIndex:idx_mfa_trusted_hash" json:"-"`

	// Label is a human-readable name for the device, derived best-
	// effort from the user-agent at issuance time ("Chrome on
	// macOS"). Shown in the user's MFA-settings widget so they can
	// pick which device to revoke. Free-form; user can rename via
	// a future API but v1 doesn't expose that surface.
	Label string `gorm:"size:255;not null" json:"label"`

	IssuedAt   time.Time `gorm:"autoCreateTime;not null" json:"issued_at"`
	ExpiresAt  time.Time `gorm:"not null;index" json:"expires_at"`
	LastUsedAt time.Time `gorm:"not null" json:"last_used_at"`

	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (MFATrustedDevice) TableName() string { return "mfa_trusted_devices" }
