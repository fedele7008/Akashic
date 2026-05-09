package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthRefreshToken records a single refresh token issued via the
// OAuth `/token` endpoint with `offline_access` scope.
//
// Storage shape: opaque random tokens (256 bits of entropy) hashed
// with SHA-256. Plaintext is returned to the client at issuance and
// never persisted. Lookups happen by hash via the unique index.
//
// Why opaque + DB instead of JWT: a JWT refresh token can't be
// revoked without a side-table anyway, and a 30-day RT requires
// instant revocation when (a) a user revokes consent, (b) the
// client is deleted, or (c) replay is detected on the rotation
// chain. Storing them as opaque rows in PG gives us those for
// free at the cost of one DB lookup per refresh — fine because
// refresh is a rare operation by design (every 15 min, not every
// API call).
//
// Rotation invariant (OAuth 2.1 §6.1): every successful
// `grant_type=refresh_token` exchange consumes the presented RT
// (sets `consumed_at`) and issues a NEW row in the same chain
// (same `chain_id`, `parent_id` = the consumed row). If a
// presented RT has `consumed_at` already set OR `revoked_at`
// already set, that's a replay signal — we revoke ALL rows in
// the chain (`UpdateChainRevoked`) and return invalid_grant.
//
// Lifetimes:
//   - `expires_at` is the per-row sliding TTL. Default 30 days
//     from issuance, configurable via tenant policy + per-client
//     override. Each rotation re-establishes a fresh sliding
//     window — long-lived sessions stay logged in as long as
//     they keep using the app.
//   - `chain_expires_at` is the absolute cap on the entire
//     rotation chain. Default 90 days from the FIRST RT in the
//     chain. Even with continuous use, a chain dies on its
//     birthday; the user has to re-authenticate via /authorize
//     after that. Inherited from the parent on rotation.
//
// Both are checked at exchange time; whichever expires sooner
// wins.
type OAuthRefreshToken struct {
	// ID is the row's PK; `parent_id` references it for chain
	// audit trails. Not used as the token value — that's the
	// SHA-256 hash in TokenHash.
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// TokenHash is SHA-256 of the opaque random token value
	// returned to the client. We index it unique so lookup-by-
	// presented-token is one indexed read. Stored as bytea (32
	// bytes) — fixed width, smaller than hex-encoding.
	//
	// Why SHA-256 and not bcrypt: the source secret already has
	// 256 bits of entropy from crypto/rand, so the slow-hash
	// property bcrypt provides is unnecessary (and would cost
	// us 100ms per refresh). Plain SHA-256 is the right tool
	// for high-entropy lookup keys.
	TokenHash []byte `gorm:"type:bytea;not null;uniqueIndex:idx_refresh_token_hash" json:"-"`

	UserID   uuid.UUID `gorm:"type:uuid;not null;index:idx_refresh_user" json:"user_id"`
	ClientID string    `gorm:"size:255;not null;index:idx_refresh_client" json:"client_id"`

	// Scope copied from the originating auth code. Refresh exchange
	// MAY narrow but MUST NOT widen scope (RFC 6749 §6).
	Scope string `gorm:"type:text;not null" json:"scope"`

	// ChainID identifies the rotation lineage. Shared across all
	// rows that descended from the same /token authorization_code
	// exchange. Used for replay-detection chain revocation.
	ChainID uuid.UUID `gorm:"type:uuid;not null;index:idx_refresh_chain" json:"chain_id"`

	// ParentID is the previous RT in the chain (NULL for the
	// initial RT minted at /token + offline_access time).
	ParentID *uuid.UUID `gorm:"type:uuid" json:"parent_id,omitempty"`

	IssuedAt        time.Time `gorm:"not null" json:"issued_at"`
	ExpiresAt       time.Time `gorm:"not null;index" json:"expires_at"`
	ChainExpiresAt  time.Time `gorm:"not null" json:"chain_expires_at"`

	// ConsumedAt: this row was successfully exchanged for a new
	// pair. Re-presenting a consumed RT is replay → revoke chain.
	ConsumedAt *time.Time `gorm:"index" json:"consumed_at,omitempty"`

	// RevokedAt + RevokedReason: row is dead, regardless of
	// consumed/expired state. Reasons:
	//   "rotated"          — superseded by a child (also implied
	//                        by ConsumedAt; redundant but explicit
	//                        for human audit log readability).
	//   "replay_detected"  — chain-revocation cascade after a
	//                        consumed/revoked RT was re-presented.
	//   "user_revoke"      — user revoked consent for the client,
	//                        which cascades to all RTs of that
	//                        (user, client) pair.
	//   "client_deleted"   — the client_services row was deleted;
	//                        cascades to all RTs for that client.
	//   "policy_revoke"    — operator forced re-auth via admin
	//                        action.
	RevokedAt     *time.Time `gorm:"index" json:"revoked_at,omitempty"`
	RevokedReason string     `gorm:"size:64" json:"revoked_reason,omitempty"`
}

// TableName fixes the table name regardless of GORM's pluralization
// guess (which would also produce `oauth_refresh_tokens`, but being
// explicit keeps schema reviewers from depending on knowing the
// pluralizer).
func (OAuthRefreshToken) TableName() string { return "oauth_refresh_tokens" }

// Active reports whether the row is currently valid for exchange.
// True iff: not consumed, not revoked, sliding window unexpired,
// chain window unexpired. The exchange handler still checks each
// of these individually (so it can report a precise failure
// reason); this is a convenience predicate for repository queries
// like `ListActiveByUser` that want the full live-set.
func (t *OAuthRefreshToken) Active(now time.Time) bool {
	if t.ConsumedAt != nil || t.RevokedAt != nil {
		return false
	}
	if !now.Before(t.ExpiresAt) {
		return false
	}
	if !now.Before(t.ChainExpiresAt) {
		return false
	}
	return true
}
