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

// MFATrustedDeviceRepository is the SQL surface for the
// `mfa_trusted_devices` table. Phase 9f.
//
// Lookups happen by SHA-256 hash of the cookie value (the plaintext
// only ever lives in the user's browser). Revocation is per-row;
// "kill all my trusted devices" is a separate sweep call.
type MFATrustedDeviceRepository struct {
	db *gorm.DB
}

func NewMFATrustedDeviceRepository(db *gorm.DB) *MFATrustedDeviceRepository {
	return &MFATrustedDeviceRepository{db: db}
}

// ErrTrustedDeviceNotFound covers "no row" plus "row exists but is
// no longer usable" (revoked / expired). Same conflation as the
// refresh-token repo's invalid sentinel — the *reason* is logged,
// the wire surface is uniform.
var ErrTrustedDeviceNotFound = errors.New("trusted device not found, revoked, or expired")

// Create inserts a fresh row. ExpiresAt is computed by the caller
// (clamped to the policy ceiling there). LastUsedAt seeded to the
// issuance moment so the first use's bump shows up as a no-op
// rather than a confusing far-past timestamp.
func (r *MFATrustedDeviceRepository) Create(ctx context.Context, row *models.MFATrustedDevice) error {
	if row.LastUsedAt.IsZero() {
		row.LastUsedAt = time.Now().UTC()
	}
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("create trusted device: %w", err)
	}
	return nil
}

// FindActiveByHash returns the row matching the given hash IF it
// is unrevoked AND unexpired. Returns ErrTrustedDeviceNotFound for
// any non-active state — caller doesn't need to distinguish.
func (r *MFATrustedDeviceRepository) FindActiveByHash(ctx context.Context, hash []byte) (*models.MFATrustedDevice, error) {
	now := time.Now().UTC()
	var row models.MFATrustedDevice
	err := r.db.WithContext(ctx).
		Where("cookie_token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
			hash, now).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrTrustedDeviceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find trusted device: %w", err)
	}
	return &row, nil
}

// BumpLastUsed updates LastUsedAt to now. Called from the login
// flow when a trusted-device cookie matches and short-circuits
// the MFA prompt — gives the user surface a "last seen" timestamp
// for revoke decisions.
func (r *MFATrustedDeviceRepository) BumpLastUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	return r.db.WithContext(ctx).Model(&models.MFATrustedDevice{}).
		Where("id = ?", id).
		Update("last_used_at", now).Error
}

// ListForUser returns every row (active + revoked + expired) for a
// user, newest first. The widget filters to "show me my active
// devices" client-side; admin reviewers may want to see the full
// history (kept for audit).
func (r *MFATrustedDeviceRepository) ListForUser(ctx context.Context, userID uuid.UUID) ([]*models.MFATrustedDevice, error) {
	var rows []*models.MFATrustedDevice
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("issued_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("list trusted devices: %w", err)
	}
	return rows, nil
}

// RevokeByID marks one row revoked. The id+user_id WHERE clause is
// belt-and-braces against UI bugs that would let a user revoke
// somebody else's device — at the application layer the handler
// also gates on session ownership.
func (r *MFATrustedDeviceRepository) RevokeByID(ctx context.Context, id, userID uuid.UUID) error {
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&models.MFATrustedDevice{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).
		Update("revoked_at", &now)
	if res.Error != nil {
		return fmt.Errorf("revoke trusted device: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrTrustedDeviceNotFound
	}
	return nil
}

// RevokeAllForUser kills every active trusted device for a user.
// Used after a forced password reset (Phase 9d) and after self-
// service password change — same threat model as the refresh-token
// revocation we already do there. Returns the number revoked.
func (r *MFATrustedDeviceRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	now := time.Now().UTC()
	res := r.db.WithContext(ctx).Model(&models.MFATrustedDevice{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now)
	if res.Error != nil {
		return 0, fmt.Errorf("revoke all trusted devices: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// PurgeExpired drops rows whose ExpiresAt elapsed more than the
// grace window ago. Grace lets the audit trail survive shortly
// after expiry without keeping rows forever. Called from a periodic
// sweeper (or manually); not on the request path.
func (r *MFATrustedDeviceRepository) PurgeExpired(ctx context.Context, grace time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-grace)
	res := r.db.WithContext(ctx).
		Where("expires_at < ?", cutoff).
		Delete(&models.MFATrustedDevice{})
	if res.Error != nil {
		return 0, fmt.Errorf("purge expired trusted devices: %w", res.Error)
	}
	return res.RowsAffected, nil
}
