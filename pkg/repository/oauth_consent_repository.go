package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// OAuthConsentRepository is the SQL surface for the oauth_consents
// table. Phase 7.
//
// Concurrency note: the Upsert method uses ON CONFLICT (user_id,
// client_id) so two concurrent /consent/submit calls from the same
// user-client pair (rare — same browser, same OAuth flow) collapse
// to one row update rather than racing on which INSERT wins.
type OAuthConsentRepository struct {
	db *gorm.DB
}

func NewOAuthConsentRepository(db *gorm.DB) *OAuthConsentRepository {
	return &OAuthConsentRepository{db: db}
}

// Get returns the consent row for (userID, clientID), or
// gorm.ErrRecordNotFound if none exists. Callers that need the
// "no record OR revoked → re-prompt" semantic should compose the
// check themselves rather than have this method paper over the
// distinction.
func (r *OAuthConsentRepository) Get(ctx context.Context, userID uuid.UUID, clientID string) (*models.OAuthConsent, error) {
	var c models.OAuthConsent
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND client_id = ?", userID, clientID).
		First(&c).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Upsert writes the user's consent for a specific scope set. If the
// (user_id, client_id) row exists, it's updated (scopes replaced,
// updated_at bumped, revoked_at cleared so a previously-revoked
// consent un-revokes when the user grants again). If not, a new
// row is inserted.
//
// Single round-trip via ON CONFLICT — important so that the
// consent submit handler can write + redirect synchronously
// without a read-then-write race window.
func (r *OAuthConsentRepository) Upsert(ctx context.Context, userID uuid.UUID, clientID, scopes string) (*models.OAuthConsent, error) {
	row := models.OAuthConsent{
		UserID:   userID,
		ClientID: clientID,
		Scopes:   scopes,
	}
	res := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "user_id"}, {Name: "client_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"scopes":     scopes,
				"updated_at": time.Now(),
				"revoked_at": nil,
			}),
		}).
		Create(&row)
	if res.Error != nil {
		return nil, fmt.Errorf("upsert consent: %w", res.Error)
	}
	// Re-read so the caller gets the post-conflict state (the
	// Create call returns the input row, not the merged row).
	return r.Get(ctx, userID, clientID)
}

// Revoke marks a consent row as revoked. The next /authorize call
// for this (user, client) will require a fresh prompt. Idempotent
// — revoking an already-revoked or missing row is a no-op.
func (r *OAuthConsentRepository) Revoke(ctx context.Context, userID uuid.UUID, clientID string) error {
	now := time.Now()
	res := r.db.WithContext(ctx).
		Model(&models.OAuthConsent{}).
		Where("user_id = ? AND client_id = ? AND revoked_at IS NULL", userID, clientID).
		Update("revoked_at", &now)
	if res.Error != nil {
		return fmt.Errorf("revoke consent: %w", res.Error)
	}
	return nil
}

// ListForUser returns all non-revoked consent rows for a user.
// Used by the future "Connected apps" page (Phase 7.5) so users
// can see and revoke their grants. Ordered by most-recent-first
// because the user's latest activity is the likeliest target for
// revocation.
func (r *OAuthConsentRepository) ListForUser(ctx context.Context, userID uuid.UUID) ([]*models.OAuthConsent, error) {
	var out []*models.OAuthConsent
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Order("updated_at DESC").
		Find(&out).Error
	if err != nil {
		return nil, fmt.Errorf("list consents: %w", err)
	}
	return out, nil
}

// IsNotFound reports whether err is gorm.ErrRecordNotFound. Callers
// of Get use this to distinguish "consent missing" from "DB error".
func IsNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }
