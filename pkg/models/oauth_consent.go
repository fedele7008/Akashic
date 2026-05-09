package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthConsent records that a specific user has granted a specific
// client permission to access a specific set of scopes. Phase 7.
//
// One row per (user_id, client_id) pair — the composite unique
// index enforces that. When a user re-grants for new scopes, we
// UPDATE the row's `scopes` field rather than inserting a new row;
// this keeps the consent history simple (one current state per
// user-client) and matches OAuth's "your most recent grant wins"
// expectation.
//
// Soft-delete via `revoked_at`: a non-nil value means the user has
// revoked consent and the next /authorize must prompt again. We
// don't hard-delete because the row's `granted_at` timestamp is a
// useful audit datapoint ("did this user EVER consent to this
// client?").
//
// Scopes are stored space-separated. For comparison, the consent
// package sorts both sides before doing the subset check; the
// table doesn't enforce sort order on writes (avoids a normalisation
// dance every time we update).
type OAuthConsent struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	// UserID + ClientID together form the natural key. The composite
	// uniqueIndex prevents duplicate rows for the same (user, client)
	// pair — re-grants UPDATE in place.
	UserID   uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_consent_user_client" json:"user_id"`
	ClientID string    `gorm:"not null;size:255;uniqueIndex:idx_consent_user_client" json:"client_id"`

	// Scopes that the user approved on the most recent grant.
	// Space-separated. The consent.Required check runs a subset
	// test against the requested scopes — if the client comes
	// back asking for a strict superset, we re-prompt and update
	// this column on the new approval.
	Scopes string `gorm:"not null;size:1024" json:"scopes"`

	GrantedAt time.Time  `gorm:"autoCreateTime;not null" json:"granted_at"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime;not null" json:"updated_at"`
	RevokedAt *time.Time `gorm:"index" json:"revoked_at,omitempty"`
}

// TableName fixes the table name regardless of GORM's pluralisation
// guess (which would also be `oauth_consents` for this struct, but
// being explicit keeps schema reviewers from having to know GORM's
// pluraliser to check the migration).
func (OAuthConsent) TableName() string { return "oauth_consents" }
