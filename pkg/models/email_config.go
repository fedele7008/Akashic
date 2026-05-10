package models

import (
	"time"

	"github.com/google/uuid"
)

// EmailConfig is the singleton row holding the deployment's
// outbound-email settings. Phase 9 — operator-edited via admin web.
//
// Singleton model: id=1, enforced at the application layer (the
// `email.Service.EnsureSingleton` call seeds the row at first run;
// `Update` operates on `WHERE id = 1`). Same shape as
// `tenant_policies`.
//
// Why a separate table from `tenant_policies`: email config has
// driver-specific fields (SendGrid key today; SMTP host+port+user
// later) that don't belong on the policy row. Keeping the domain
// separate makes future provider additions a column add here, not
// a policy bloat.
//
// Secret handling: the SendGrid API key is stored in plaintext
// here. A future hardening pass could move secrets to Vault and
// keep only references on this row; for Phase 9 the trade-off
// (operator simplicity > plaintext-at-rest exposure) is OK
// because the same plaintext lived in env vars before. Operators
// with strict secret-management requirements should rely on
// PG-level encryption-at-rest + restricted DB user grants.
type EmailConfig struct {
	// ID is fixed at 1 — singleton. Same `bigserial`-with-explicit-
	// ID-on-insert pattern as TenantPolicy.
	ID uint `gorm:"primaryKey" json:"-"`

	// Provider names the active driver. Recognised values:
	//   ""         → email disabled
	//   "sendgrid" → SendGrid HTTP API (requires SendGridAPIKey)
	//   (future)   → "smtp", "postmark", "resend", "ses"
	// Validation lives in pkg/email/service.go's Update path.
	Provider string `gorm:"type:text;not null;default:''" json:"provider"`

	// FromAddress is the envelope-from + header-from address.
	// Required when Provider is non-empty.
	FromAddress string `gorm:"type:text;not null;default:''" json:"from_address"`

	// FromName is the human-readable display name. Optional;
	// defaults to "Akashic" at render time when blank.
	FromName string `gorm:"type:text;not null;default:''" json:"from_name"`

	// SendGridAPIKey is required when Provider == "sendgrid".
	// Plaintext at rest. Marshalled as JSON tag `-` so a stray
	// `json.Marshal(row)` never leaks it; the control-plane handler
	// returns it as a masked placeholder via a separate view type.
	SendGridAPIKey string `gorm:"type:text;not null;default:''" json:"-"`

	// VerifyURLBase is the externally-reachable URL prefix used in
	// verification email links. Typically the auth-server's public
	// URL (e.g., https://auth.akashic.example.com).
	VerifyURLBase string `gorm:"type:text;not null;default:''" json:"verify_url_base"`

	UpdatedAt time.Time  `gorm:"autoUpdateTime;not null" json:"updated_at"`
	UpdatedBy *uuid.UUID `gorm:"type:uuid" json:"updated_by,omitempty"`
}

// TableName fixes the table name regardless of GORM's pluralization.
func (EmailConfig) TableName() string { return "email_configs" }

// HasSendGridKey reports whether the SendGrid API key field is
// populated. Used by the control-plane GET handler to render the
// masked placeholder without exposing the value.
func (c *EmailConfig) HasSendGridKey() bool {
	return c.SendGridAPIKey != ""
}
