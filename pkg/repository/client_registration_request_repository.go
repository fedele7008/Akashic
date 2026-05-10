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

// ClientRegistrationRequestRepository is the SQL surface for the
// `client_registration_requests` table. Phase 9e v2.
//
// Each row maps to ONE proposed client registration. Multiple
// pending rows per user are permitted (one per intended client);
// the per-user cap is enforced at the service layer as
// `existing_clients + pending_requests <= effective_cap`.
//
// State transitions are application-enforced (atomic compare-and-
// swap inside `transitionPending`) rather than via DB constraints.
type ClientRegistrationRequestRepository struct {
	db *gorm.DB
}

func NewClientRegistrationRequestRepository(db *gorm.DB) *ClientRegistrationRequestRepository {
	return &ClientRegistrationRequestRepository{db: db}
}

// ErrClientRegRequestNotFound is returned by Get/Approve/Reject
// when the row doesn't exist (or, for Approve/Reject, has already
// left pending state).
var ErrClientRegRequestNotFound = errors.New("client-registration request not found or no longer pending")

// Create inserts a new request in `pending` state. Caller is
// responsible for cap enforcement before calling — the repo just
// persists. (Atomic cap check would require a serializable txn
// across this table + `client_services`; for the modest write rate
// of approval-gated registration, app-level pre-check is fine.)
func (r *ClientRegistrationRequestRepository) Create(ctx context.Context, req *models.ClientRegistrationRequest) error {
	req.Status = models.ClientRegRequestPending
	if err := r.db.WithContext(ctx).Create(req).Error; err != nil {
		return fmt.Errorf("create client-registration request: %w", err)
	}
	return nil
}

// Get returns the row by ID, or ErrClientRegRequestNotFound.
func (r *ClientRegistrationRequestRepository) Get(ctx context.Context, id uuid.UUID) (*models.ClientRegistrationRequest, error) {
	var row models.ClientRegistrationRequest
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrClientRegRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get client-registration request: %w", err)
	}
	return &row, nil
}

// CountPendingForUser counts the user's pending rows. Used by the
// service's cap enforcement: the cap counts (existing clients) +
// (pending requests) so a user can't flood the queue.
func (r *ClientRegistrationRequestRepository) CountPendingForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&models.ClientRegistrationRequest{}).
		Where("user_id = ? AND status = ?", userID, models.ClientRegRequestPending).
		Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("count pending requests: %w", err)
	}
	return n, nil
}

// List returns rows filtered by status (empty status = all).
// Newest first; bounded by `limit`.
func (r *ClientRegistrationRequestRepository) List(ctx context.Context, status string, limit int) ([]*models.ClientRegistrationRequest, error) {
	q := r.db.WithContext(ctx).Order("submitted_at DESC")
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []*models.ClientRegistrationRequest
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list client-registration requests: %w", err)
	}
	return rows, nil
}

// ListByUser returns every request (any status) for a single user.
// Used by the eligibility endpoint to surface the user's history
// alongside the current cap state.
func (r *ClientRegistrationRequestRepository) ListByUser(ctx context.Context, userID uuid.UUID) ([]*models.ClientRegistrationRequest, error) {
	var rows []*models.ClientRegistrationRequest
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("submitted_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list client-registration requests for user: %w", err)
	}
	return rows, nil
}

// transitionPending moves a row out of pending. Atomic UPDATE that
// only succeeds when the row is still pending — concurrent reviews
// of the same row collapse to one winner. `createdClientID` is set
// on approve (the materialized client_services row's id), nil on
// reject.
func (r *ClientRegistrationRequestRepository) transitionPending(
	ctx context.Context,
	id uuid.UUID,
	newStatus string,
	reviewedBy uuid.UUID,
	note string,
	createdClientID *string,
) (*models.ClientRegistrationRequest, error) {
	now := time.Now().UTC()
	updates := map[string]any{
		"status":        newStatus,
		"reviewed_by":   reviewedBy,
		"reviewed_at":   &now,
		"decision_note": note,
	}
	if createdClientID != nil {
		updates["created_client_id"] = createdClientID
	}
	res := r.db.WithContext(ctx).Model(&models.ClientRegistrationRequest{}).
		Where("id = ? AND status = ?", id, models.ClientRegRequestPending).
		Updates(updates)
	if res.Error != nil {
		return nil, fmt.Errorf("transition client-registration request: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, ErrClientRegRequestNotFound
	}
	return r.Get(ctx, id)
}

// ApprovePending moves a pending row to approved and stamps the
// id of the materialized client_services row. Service layer is
// responsible for actually creating that row before calling this.
func (r *ClientRegistrationRequestRepository) ApprovePending(
	ctx context.Context,
	id uuid.UUID,
	reviewedBy uuid.UUID,
	note string,
	createdClientID string,
) (*models.ClientRegistrationRequest, error) {
	return r.transitionPending(ctx, id, models.ClientRegRequestApproved, reviewedBy, note, &createdClientID)
}

// RejectPending moves a pending row to rejected. No client row is
// created; the row stays for audit + so the user can see the note.
func (r *ClientRegistrationRequestRepository) RejectPending(
	ctx context.Context,
	id uuid.UUID,
	reviewedBy uuid.UUID,
	note string,
) (*models.ClientRegistrationRequest, error) {
	return r.transitionPending(ctx, id, models.ClientRegRequestRejected, reviewedBy, note, nil)
}
