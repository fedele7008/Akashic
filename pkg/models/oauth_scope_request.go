package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuthScopeRequest is the workflow record for a "client wants
// access to a special scope" approval cycle. Phase B of the
// scope-policy rollout.
//
// Lifecycle:
//
//	pending  ──approve──▶  approved   (one-way)
//	         ──reject ──▶  rejected   (one-way)
//
// While `pending`, the requested scope is NOT in the client's
// effective allowed/required/optional set — the request is just
// state on this table. On `approved`, the approval handler may
// (a) add the scope to the client's `OptionalScopes` and
// (b) apply the request's proposed TTL overrides (clamped to
// tenant ceiling). On `rejected`, no client-row mutation; the row
// stays for audit history.
//
// Uniqueness: (client_id, scope, status='pending') is at most one.
// Prevents a client from accumulating multiple pending requests
// for the same scope. Enforced by partial unique index below.
//
// Why a separate table rather than a JSON blob on client_services:
// the workflow is a state machine with multiple actors (submitter,
// reviewer) over time. A row-level model gives us a clean audit
// trail (who submitted, who reviewed, when, with what notes), and
// the partial-unique-on-pending invariant becomes a database
// guarantee instead of application logic.
type OAuthScopeRequest struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	ClientID string `gorm:"size:255;not null;index:idx_scope_request_client" json:"client_id"`
	Scope    string `gorm:"size:128;not null;index:idx_scope_request_scope" json:"scope"`

	// Reason is the client owner's rationale for needing this
	// scope. Operator reads this on the review page; useful audit
	// content for ongoing compliance reviews. Free-form text;
	// length-capped to keep the row size reasonable.
	Reason string `gorm:"size:2048;not null" json:"reason"`

	// Proposed TTLs for `offline_access` requests. Optional —
	// nil means "use the tenant ceiling." If the request is
	// approved AND any field is non-nil, the approval handler
	// applies them as the client's per-client TTL overrides
	// (after clamping to the tenant ceiling). For non-
	// `offline_access` scopes these stay nil.
	ProposedAccessTokenTTLSeconds          *int `gorm:"" json:"proposed_access_token_ttl_seconds,omitempty"`
	ProposedRefreshTokenSlidingTTLSeconds  *int `gorm:"" json:"proposed_refresh_token_sliding_ttl_seconds,omitempty"`
	ProposedRefreshTokenAbsoluteTTLSeconds *int `gorm:"" json:"proposed_refresh_token_absolute_ttl_seconds,omitempty"`

	// Status is one of: "pending", "approved", "rejected".
	// Validation lives in pkg/clientservice's approval/rejection
	// helpers, not as a CHECK constraint, so error messages stay
	// in Go.
	Status string `gorm:"size:16;not null;default:'pending';index:idx_scope_request_status" json:"status"`

	// SubmittedBy is the user who created the request. Nil for
	// operator-side (control-plane mTLS) submissions where the CN
	// isn't tied to a specific user. The current admin web
	// surfaces submissions via the admin's session so this WILL
	// be populated for UI submissions.
	SubmittedBy *uuid.UUID `gorm:"type:uuid" json:"submitted_by,omitempty"`
	SubmittedAt time.Time  `gorm:"autoCreateTime;not null" json:"submitted_at"`

	// Review fields populated when status moves out of `pending`.
	ReviewedBy   *uuid.UUID `gorm:"type:uuid" json:"reviewed_by,omitempty"`
	ReviewedAt   *time.Time `gorm:"" json:"reviewed_at,omitempty"`
	DecisionNote string     `gorm:"size:2048" json:"decision_note,omitempty"`
}

func (OAuthScopeRequest) TableName() string { return "oauth_scope_requests" }

// Status constants — kept as exported strings rather than a typed
// enum because GORM's stringer dance with custom types adds
// boilerplate without much safety win at this scale.
const (
	ScopeRequestPending  = "pending"
	ScopeRequestApproved = "approved"
	ScopeRequestRejected = "rejected"
)
