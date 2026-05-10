package models

import (
	"time"

	"github.com/google/uuid"
)

// EmailVerification is a one-shot verification token sent to a
// user's claimed email address. Phase 9 — email verification flow.
//
// Lifecycle:
//   - Created on signup (and on email-change re-verification, Phase 9c).
//   - Consumed when user clicks the link in the verification email
//     and reaches `GET /verify-email?token=<raw>` — `used_at` is set
//     and `User.EmailVerified` flips to true.
//   - Expired silently after `expires_at` (no cleanup — `used_at` and
//     `expires_at` are the only state that matters for validation).
//
// Storage: opaque random tokens (256-bit base64url) hashed with
// SHA-256, same shape as refresh tokens. Plaintext is in the email
// only; only the hash persists. SHA-256 is the right tool here
// (high-entropy lookup key); bcrypt would be overkill and slower.
//
// Per-user single-active is enforced in the repository's Create
// path: any existing UNUSED row for the user is implicitly
// invalidated by the new one (we set `used_at = now` to mean
// "consumed OR superseded"). The user only ever has one click
// target at a time, so resending the email always supersedes the
// previous one. This avoids "the old email's link still works
// after I asked for a new one" footguns.
type EmailVerification struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// UserID is the user the verification is for. Indexed so the
	// "is there a pending verification for this user" lookup is
	// fast on the resend path.
	UserID uuid.UUID `gorm:"type:uuid;not null;index:idx_email_verification_user" json:"user_id"`

	// Email is the address the verification was sent TO. We store
	// it explicitly rather than dereferencing User.Email at consume
	// time because the user might have changed their email mid-
	// verification (e.g., signup with foo@x then PATCH email to
	// bar@y); the token's effect is to verify the address it was
	// sent to, not the user's CURRENT email.
	Email string `gorm:"size:320;not null" json:"email"`

	// TokenHash is SHA-256 of the opaque token in the email link.
	// Indexed unique so the verify-link lookup is one indexed read.
	TokenHash []byte `gorm:"type:bytea;not null;uniqueIndex:idx_email_verification_token" json:"-"`

	IssuedAt  time.Time `gorm:"autoCreateTime;not null" json:"issued_at"`
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at"`

	// UsedAt is set when the verification is consumed (link clicked
	// successfully) OR superseded (a newer verification for the
	// same user was created). Either way, the row is dead — the
	// validation path treats both as "no longer valid."
	UsedAt *time.Time `gorm:"index" json:"used_at,omitempty"`
}

func (EmailVerification) TableName() string { return "email_verifications" }
