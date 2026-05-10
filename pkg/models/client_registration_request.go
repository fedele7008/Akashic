package models

import (
	"time"

	"github.com/google/uuid"
)

// ClientRegistrationRequest is one user's attempt to register an
// OAuth client when the tenant policy requires admin approval.
// Phase 9e v2.
//
// Lifecycle:
//
//	pending  ──approve──▶  approved   (one-way; materializes a
//	                                   client_services row)
//	         ──reject ──▶  rejected   (one-way; no client created)
//
// Each row maps to ONE proposed client. A user may have multiple
// pending rows simultaneously (one per intended client) — the
// per-user cap is enforced as
// `existing_clients + pending_requests <= effective_cap` so a
// flood of pending submissions can't bypass the cap.
//
// On approve, the approval orchestrator (see pkg/clientregistration)
// reads the stored client params, calls `clientservice.Create` to
// materialize the `client_services` row owned by `UserID`, and
// stores the new client_id in `CreatedClientID` for audit.
//
// Storing client params as structured columns (rather than a JSON
// blob) keeps the admin reviewer page friendly: each column is
// directly searchable / sortable, and the schema diffs cleanly
// against `client_services` if the latter ever grows new fields.
type ClientRegistrationRequest struct {
	ID uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()" json:"id"`

	UserID uuid.UUID `gorm:"type:uuid;not null;index:idx_client_reg_request_user" json:"user_id"`

	// Reason is the user's free-form rationale ("I'm building an
	// internal tool for the design team; needs two redirect URIs").
	// Surfaced on the admin reviewer page; useful audit content.
	Reason string `gorm:"size:2048;not null" json:"reason"`

	// ─── Proposed client params ──────────────────────────────────
	// Mirror the columns on `client_services` 1:1 so the approval
	// path can construct a CreateParams without per-field mapping
	// decisions. The reviewer sees these on the request card and
	// approves "as proposed"; v1 doesn't allow editing on approve
	// (operator rejects with a note instructing the user to
	// resubmit if changes are needed).
	Name           string `gorm:"size:255;not null" json:"name"`
	Description    string `gorm:"size:1024" json:"description,omitempty"`
	HomepageURL    string `gorm:"size:512" json:"homepage_url,omitempty"`
	ClientType     string `gorm:"size:8;not null" json:"client_type"` // "WEB" | "SPA"
	RedirectURIs   string `gorm:"type:text;not null" json:"redirect_uris"`
	RequiredScopes string `gorm:"type:text" json:"required_scopes,omitempty"`
	OptionalScopes string `gorm:"type:text" json:"optional_scopes,omitempty"`
	// RequirePKCE only meaningful for WEB; SPA always-PKCE per the
	// model invariant. Stored as a regular bool — the value is
	// ignored for SPA at apply time.
	RequirePKCE bool `gorm:"not null;default:true" json:"require_pkce"`

	// ─── Workflow state ──────────────────────────────────────────
	Status string `gorm:"size:16;not null;default:'pending';index:idx_client_reg_request_status" json:"status"`

	SubmittedAt  time.Time  `gorm:"autoCreateTime;not null" json:"submitted_at"`
	ReviewedBy   *uuid.UUID `gorm:"type:uuid" json:"reviewed_by,omitempty"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
	DecisionNote string     `gorm:"size:2048" json:"decision_note,omitempty"`

	// CreatedClientID is the `client_services.client_id` minted
	// during approval. nil while pending or rejected. Lets the
	// admin reviewer page link from the request row to the
	// resulting client.
	CreatedClientID *string `gorm:"size:255" json:"created_client_id,omitempty"`
}

func (ClientRegistrationRequest) TableName() string {
	return "client_registration_requests"
}

const (
	ClientRegRequestPending  = "pending"
	ClientRegRequestApproved = "approved"
	ClientRegRequestRejected = "rejected"
)
