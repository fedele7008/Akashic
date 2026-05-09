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

// ErrRefreshTokenInvalid is the catch-all "this RT can't be
// exchanged" sentinel returned by FindActiveByHash. Distinct
// reasons (not-found / expired / consumed / revoked) all collapse
// to this single error from the perspective of the OAuth /token
// handler, which must respond with `invalid_grant` per RFC 6749
// §5.2 regardless of why the RT was rejected (info-leak
// prevention).
//
// The repository's logging layer is where we record the precise
// reason for operator audit; the handler stays at "invalid_grant".
var ErrRefreshTokenInvalid = errors.New("refresh token invalid or expired")

// ErrRefreshTokenReplay signals that a presented RT was already
// consumed or revoked — i.e., a replay/theft signature.
// `FindForExchange` returns this distinct from
// ErrRefreshTokenInvalid so the handler can trigger chain-
// revocation cascade as the cleanup step. Externally the handler
// still answers `invalid_grant` (the spec doesn't expose the
// distinction to clients).
var ErrRefreshTokenReplay = errors.New("refresh token replay detected")

// OAuthRefreshTokenRepository is the SQL surface for the
// `oauth_refresh_tokens` table.
//
// Concurrency model: the rotation flow takes a transaction so
// "consume the old + insert the new" is atomic. Two concurrent
// refresh attempts on the same RT will serialize on the row's
// `consumed_at` UPDATE — whichever transaction commits first
// wins; the loser's UPDATE matches zero rows and the handler
// returns invalid_grant. This naturally provides the rotation
// invariant without requiring application-level locking.
type OAuthRefreshTokenRepository struct {
	db *gorm.DB
}

func NewOAuthRefreshTokenRepository(db *gorm.DB) *OAuthRefreshTokenRepository {
	return &OAuthRefreshTokenRepository{db: db}
}

// CreateInitial inserts the FIRST refresh token of a chain — i.e.,
// the one minted at /token authorization_code exchange when
// `offline_access` was granted. ChainID is generated fresh,
// ParentID stays nil, ChainExpiresAt is computed from the
// absolute-TTL policy.
//
// Returns the row's ID so the handler can log the chain identity
// alongside the access-token mint event.
func (r *OAuthRefreshTokenRepository) CreateInitial(
	ctx context.Context,
	tokenHash []byte,
	userID uuid.UUID,
	clientID, scope string,
	now time.Time,
	slidingTTL, absoluteTTL time.Duration,
) (*models.OAuthRefreshToken, error) {
	row := &models.OAuthRefreshToken{
		TokenHash:      tokenHash,
		UserID:         userID,
		ClientID:       clientID,
		Scope:          scope,
		ChainID:        uuid.New(),
		ParentID:       nil,
		IssuedAt:       now,
		ExpiresAt:      now.Add(slidingTTL),
		ChainExpiresAt: now.Add(absoluteTTL),
	}
	if err := r.db.WithContext(ctx).Create(row).Error; err != nil {
		return nil, fmt.Errorf("create initial refresh token: %w", err)
	}
	return row, nil
}

// FindForExchange looks up a presented refresh-token-hash and
// returns the row, classifying the result for the caller:
//
//   (row, nil)                       → row is active, ready to rotate.
//   (row, ErrRefreshTokenReplay)     → row exists but is already
//                                       consumed or revoked (= replay).
//                                       Caller should revoke the
//                                       chain via RevokeChain.
//   (nil,  ErrRefreshTokenInvalid)   → row not found, OR found and
//                                       expired (sliding or absolute).
//
// Returning the row alongside the replay sentinel is what lets the
// handler call `RevokeChain(row.ChainID, "replay_detected")`. We
// don't auto-revoke inside this method because the handler also
// wants to log the user_id + client_id for the security alert,
// and that's clearer with the row in hand.
func (r *OAuthRefreshTokenRepository) FindForExchange(
	ctx context.Context,
	tokenHash []byte,
	now time.Time,
) (*models.OAuthRefreshToken, error) {
	var row models.OAuthRefreshToken
	err := r.db.WithContext(ctx).
		Where("token_hash = ?", tokenHash).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrRefreshTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	// Replay first — a consumed/revoked token re-presented is the
	// signature we care about most.
	if row.ConsumedAt != nil || row.RevokedAt != nil {
		return &row, ErrRefreshTokenReplay
	}
	// Window checks. Sliding window may have expired even if not
	// consumed (the legitimate client just didn't refresh in time);
	// absolute window applies to the whole chain.
	if !now.Before(row.ExpiresAt) || !now.Before(row.ChainExpiresAt) {
		return nil, ErrRefreshTokenInvalid
	}
	return &row, nil
}

// Rotate atomically: marks the parent row consumed AND inserts the
// new child row, in a single transaction. ChainID + ChainExpiresAt
// are inherited; ParentID points back to the parent. The new row's
// ExpiresAt is `now + slidingTTL` (a fresh sliding window each
// rotation) but the chain's absolute window doesn't slide.
//
// Returns the new row so the handler can include its hash in the
// /token response.
//
// If two concurrent refresh calls hit the same parent, exactly one
// will see RowsAffected=1 on the consume UPDATE; the other gets
// RowsAffected=0 and we surface as ErrRefreshTokenInvalid (which
// the handler turns into invalid_grant). This is the application-
// level guarantee that a single RT rotates exactly once.
func (r *OAuthRefreshTokenRepository) Rotate(
	ctx context.Context,
	parent *models.OAuthRefreshToken,
	newHash []byte,
	now time.Time,
	slidingTTL time.Duration,
) (*models.OAuthRefreshToken, error) {
	var child *models.OAuthRefreshToken
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Atomic-consume: only succeed if the row is still un-consumed.
		// This is what serializes concurrent refresh attempts.
		res := tx.Model(&models.OAuthRefreshToken{}).
			Where("id = ? AND consumed_at IS NULL AND revoked_at IS NULL", parent.ID).
			Updates(map[string]any{
				"consumed_at":    &now,
				"revoked_at":     &now,
				"revoked_reason": "rotated",
			})
		if res.Error != nil {
			return fmt.Errorf("consume parent: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			// A racing exchange got there first; we don't get to rotate.
			return ErrRefreshTokenInvalid
		}
		row := &models.OAuthRefreshToken{
			TokenHash:      newHash,
			UserID:         parent.UserID,
			ClientID:       parent.ClientID,
			Scope:          parent.Scope,
			ChainID:        parent.ChainID,
			ParentID:       &parent.ID,
			IssuedAt:       now,
			ExpiresAt:      now.Add(slidingTTL),
			ChainExpiresAt: parent.ChainExpiresAt,
		}
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("insert rotated refresh token: %w", err)
		}
		child = row
		return nil
	})
	if err != nil {
		return nil, err
	}
	return child, nil
}

// RevokeChain marks every row sharing the given chain_id as
// revoked, regardless of consumed/expired state. Used for replay-
// detected chains AND user-initiated consent revocation cascades.
// Idempotent — already-revoked rows are skipped via the WHERE
// clause.
//
// Returns the number of rows newly revoked (zero is OK; means the
// chain was already fully dead).
func (r *OAuthRefreshTokenRepository) RevokeChain(
	ctx context.Context,
	chainID uuid.UUID,
	reason string,
) (int64, error) {
	now := time.Now()
	res := r.db.WithContext(ctx).
		Model(&models.OAuthRefreshToken{}).
		Where("chain_id = ? AND revoked_at IS NULL", chainID).
		Updates(map[string]any{
			"revoked_at":     &now,
			"revoked_reason": reason,
		})
	if res.Error != nil {
		return 0, fmt.Errorf("revoke chain: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// RevokeAllForUserClient cascades revocation across every chain
// belonging to a (user, client) pair. Used when a user revokes
// consent for a client — the chained refresh tokens issued under
// that consent should die immediately rather than continue working
// until natural expiry.
func (r *OAuthRefreshTokenRepository) RevokeAllForUserClient(
	ctx context.Context,
	userID uuid.UUID,
	clientID string,
	reason string,
) (int64, error) {
	now := time.Now()
	res := r.db.WithContext(ctx).
		Model(&models.OAuthRefreshToken{}).
		Where("user_id = ? AND client_id = ? AND revoked_at IS NULL", userID, clientID).
		Updates(map[string]any{
			"revoked_at":     &now,
			"revoked_reason": reason,
		})
	if res.Error != nil {
		return 0, fmt.Errorf("revoke user-client refresh tokens: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// RevokeAllForClient kills every refresh token issued for a given
// client. Used when an OAuth client is deleted — pre-existing
// refresh tokens for it should not continue to work.
func (r *OAuthRefreshTokenRepository) RevokeAllForClient(
	ctx context.Context,
	clientID string,
	reason string,
) (int64, error) {
	now := time.Now()
	res := r.db.WithContext(ctx).
		Model(&models.OAuthRefreshToken{}).
		Where("client_id = ? AND revoked_at IS NULL", clientID).
		Updates(map[string]any{
			"revoked_at":     &now,
			"revoked_reason": reason,
		})
	if res.Error != nil {
		return 0, fmt.Errorf("revoke client refresh tokens: %w", res.Error)
	}
	return res.RowsAffected, nil
}
