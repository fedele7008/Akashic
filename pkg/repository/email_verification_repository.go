package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ErrEmailVerificationInvalid covers all "this token can't be
// consumed" cases (not found, expired, already used, superseded).
// The /verify-email handler maps this to a single user-facing
// "link expired or already used" message — distinguishing in the
// UI would be more confusing than helpful.
var ErrEmailVerificationInvalid = errors.New("email verification token invalid or expired")

// OAuthEmailVerificationRepository covers create + consume of
// `email_verifications` rows. Naming matches the existing repo
// style (`OAuth` prefix kept even though strictly this isn't an
// OAuth artefact — convention beats consistency).
type EmailVerificationRepository struct {
	db *gorm.DB
}

func NewEmailVerificationRepository(db *gorm.DB) *EmailVerificationRepository {
	return &EmailVerificationRepository{db: db}
}

// VerificationTokenBytes is the size of the random material before
// base64url encoding. 32 bytes = 256 bits; base64url-encoded
// produces ~43 char tokens. Same shape as refresh tokens.
const verificationTokenBytes = 32

// VerificationTokenLifetime is how long a verification link stays
// valid. 24 hours strikes a balance: long enough that a user can
// realistically read the email later (work account + check-mail-
// in-evening pattern) and short enough that a stolen email box
// doesn't yield indefinite verification capacity.
const VerificationTokenLifetime = 24 * time.Hour

// Create generates a fresh token, supersedes any existing un-used
// verification rows for the user (sets `used_at = now`), and
// inserts a new row. Returns the RAW token (caller emails it) plus
// the row (caller may want the expiry timestamp for UX copy).
//
// Two operations in a single transaction so a partial apply can't
// leave two active rows.
func (r *EmailVerificationRepository) Create(
	ctx context.Context,
	userID uuid.UUID,
	email string,
) (rawToken string, row *models.EmailVerification, err error) {
	buf := make([]byte, verificationTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("read random: %w", err)
	}
	rawToken = base64.RawURLEncoding.EncodeToString(buf)
	hash := sha256.Sum256([]byte(rawToken))

	now := time.Now().UTC()
	expires := now.Add(VerificationTokenLifetime)

	err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Supersede: mark every still-active row for the user as
		// used. Now even if the user clicks an OLDER email's link
		// after a resend, that row is dead.
		if err := tx.Model(&models.EmailVerification{}).
			Where("user_id = ? AND used_at IS NULL", userID).
			Update("used_at", &now).Error; err != nil {
			return fmt.Errorf("supersede prior verifications: %w", err)
		}

		row = &models.EmailVerification{
			UserID:    userID,
			Email:     email,
			TokenHash: hash[:],
			IssuedAt:  now,
			ExpiresAt: expires,
		}
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("insert verification: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return rawToken, row, nil
}

// Consume looks up a token by its hash, validates it (not used,
// not expired), atomically marks it used, and returns the row so
// the caller (handler) can read the user_id + email to flip
// User.EmailVerified.
//
// Atomic via the same compare-and-swap pattern as refresh-token
// rotation: an UPDATE with `WHERE used_at IS NULL` ensures
// concurrent verifies of the same link see exactly one win.
func (r *EmailVerificationRepository) Consume(
	ctx context.Context,
	rawToken string,
) (*models.EmailVerification, error) {
	if rawToken == "" {
		return nil, ErrEmailVerificationInvalid
	}
	hash := sha256.Sum256([]byte(rawToken))
	now := time.Now().UTC()

	var row models.EmailVerification
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("token_hash = ?", hash[:]).First(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrEmailVerificationInvalid
			}
			return fmt.Errorf("lookup verification: %w", err)
		}
		if row.UsedAt != nil || !now.Before(row.ExpiresAt) {
			return ErrEmailVerificationInvalid
		}
		// Compare-and-swap on used_at.
		res := tx.Model(&row).
			Where("id = ? AND used_at IS NULL", row.ID).
			Update("used_at", &now)
		if res.Error != nil {
			return fmt.Errorf("consume verification: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			// Concurrent consume won; treat as invalid.
			return ErrEmailVerificationInvalid
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}
