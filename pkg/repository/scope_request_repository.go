package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OAuthScopeRequestRepository is the SQL surface for the
// `oauth_scope_requests` table. Phase B of scope policy.
//
// State transitions are application-enforced (see ApprovePending
// and RejectPending) rather than via DB constraints — keeps the
// error messages in Go and the schema portable.
type OAuthScopeRequestRepository struct {
	db *gorm.DB
}

func NewOAuthScopeRequestRepository(db *gorm.DB) *OAuthScopeRequestRepository {
	return &OAuthScopeRequestRepository{db: db}
}

// ErrScopeRequestExists is returned by Create when a pending
// request already exists for the same (client_id, scope). Callers
// surface this as 409 Conflict so the UI can prompt the user to
// edit the existing pending row instead of duplicating.
var ErrScopeRequestExists = errors.New("a pending scope request for this client+scope already exists")

// ErrScopeRequestNotFound is returned by Get/Approve/Reject when
// the row doesn't exist (or, for Approve/Reject, has already left
// pending state).
var ErrScopeRequestNotFound = errors.New("scope request not found or no longer pending")

// Create inserts a new request in `pending` state. Returns
// ErrScopeRequestExists if (client_id, scope) already has a
// pending row — clients should EDIT the existing one rather than
// stack duplicates.
func (r *OAuthScopeRequestRepository) Create(ctx context.Context, req *models.OAuthScopeRequest) error {
	// Pre-check the partial unique invariant. We could rely on a
	// DB unique-where-pending index but Postgres syntax for that
	// (`CREATE UNIQUE INDEX ... WHERE status = 'pending'`) doesn't
	// roundtrip cleanly through GORM's AutoMigrate. App-level
	// check + a serializable transaction would be the rigorous
	// answer; for the modest write-rate of an admin-driven flow,
	// a precheck-then-insert is fine — collision rate is near zero.
	var existing int64
	if err := r.db.WithContext(ctx).Model(&models.OAuthScopeRequest{}).
		Where("client_id = ? AND scope = ? AND status = ?",
			req.ClientID, req.Scope, models.ScopeRequestPending).
		Count(&existing).Error; err != nil {
		return fmt.Errorf("count existing scope requests: %w", err)
	}
	if existing > 0 {
		return ErrScopeRequestExists
	}
	req.Status = models.ScopeRequestPending
	if err := r.db.WithContext(ctx).Create(req).Error; err != nil {
		return fmt.Errorf("create scope request: %w", err)
	}
	return nil
}

// Get returns the row by ID, or ErrScopeRequestNotFound.
func (r *OAuthScopeRequestRepository) Get(ctx context.Context, id uuid.UUID) (*models.OAuthScopeRequest, error) {
	var row models.OAuthScopeRequest
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrScopeRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scope request: %w", err)
	}
	return &row, nil
}

// List returns rows filtered by status (empty status = all). Newest
// first so the admin review page has the most-recent submissions
// at the top. Bounded by `limit` to keep the response small —
// callers paginate by passing a max larger than current count if
// they need everything.
func (r *OAuthScopeRequestRepository) List(ctx context.Context, status string, limit int) ([]*models.OAuthScopeRequest, error) {
	q := r.db.WithContext(ctx).Order("submitted_at DESC")
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []*models.OAuthScopeRequest
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list scope requests: %w", err)
	}
	return rows, nil
}

// ListByClient returns every request (any status) for a single
// client_id. Used by the ClientsEdit "Special scopes" panel to
// show the request history for the client being edited.
func (r *OAuthScopeRequestRepository) ListByClient(ctx context.Context, clientID string) ([]*models.OAuthScopeRequest, error) {
	var rows []*models.OAuthScopeRequest
	err := r.db.WithContext(ctx).
		Where("client_id = ?", clientID).
		Order("submitted_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list scope requests for client: %w", err)
	}
	return rows, nil
}

// HasApproved reports whether (clientID, scope) has at least one
// row in `approved` state. Used by the client write-time
// validation as the gate for special scopes — a special scope may
// appear in RequiredScopes/OptionalScopes only when a corresponding
// approval exists.
func (r *OAuthScopeRequestRepository) HasApproved(ctx context.Context, clientID, scope string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&models.OAuthScopeRequest{}).
		Where("client_id = ? AND scope = ? AND status = ?",
			clientID, scope, models.ScopeRequestApproved).
		Count(&n).Error
	if err != nil {
		return false, fmt.Errorf("check approved scope requests: %w", err)
	}
	return n > 0, nil
}

// transitionPending moves a row out of pending. Atomic UPDATE that
// only succeeds when the row is still pending — concurrent reviews
// of the same row collapse to one winner. Caller passes the new
// status; both Approve and Reject route through here for the
// same compare-and-swap shape.
func (r *OAuthScopeRequestRepository) transitionPending(
	ctx context.Context,
	id uuid.UUID,
	newStatus string,
	reviewedBy uuid.UUID,
	note string,
) (*models.OAuthScopeRequest, error) {
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&models.OAuthScopeRequest{}).
		Where("id = ? AND status = ?", id, models.ScopeRequestPending).
		Updates(map[string]any{
			"status":        newStatus,
			"reviewed_by":   reviewedBy,
			"reviewed_at":   &now,
			"decision_note": note,
		})
	if res.Error != nil {
		return nil, fmt.Errorf("transition scope request: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		// Either the row doesn't exist OR another reviewer just
		// transitioned it. Same surface either way — caller maps
		// to 404.
		return nil, ErrScopeRequestNotFound
	}
	return r.Get(ctx, id)
}

// ApprovePending moves a pending row to approved. Returns the
// updated row so the caller (clientservice approval handler) can
// read the proposed TTL fields and apply them to the client.
func (r *OAuthScopeRequestRepository) ApprovePending(
	ctx context.Context,
	id uuid.UUID,
	reviewedBy uuid.UUID,
	note string,
) (*models.OAuthScopeRequest, error) {
	return r.transitionPending(ctx, id, models.ScopeRequestApproved, reviewedBy, note)
}

// RejectPending moves a pending row to rejected. The row stays
// for audit; the client's effective scope set is unchanged.
func (r *OAuthScopeRequestRepository) RejectPending(
	ctx context.Context,
	id uuid.UUID,
	reviewedBy uuid.UUID,
	note string,
) (*models.OAuthScopeRequest, error) {
	return r.transitionPending(ctx, id, models.ScopeRequestRejected, reviewedBy, note)
}
