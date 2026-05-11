package email

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"akashic/akashic/pkg/database/akashic_redis"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// MFASetupTokenStore mints one-shot tokens that authorize *only* the
// "enable MFA after email verification" action. Phase 9f follow-up.
//
// Authority shape (chained-token security):
//
//	verification token  ──consume──▶  marks email_verified
//	                                  AND mints setup token
//
//	setup token         ──consume──▶  flips users.mfa_enabled = true
//	                                  AND is destroyed
//
// Both tokens are one-shot and short-lived. The setup token is
// strictly narrower than the verification token (can ONLY enable
// MFA — disabling is not a valid use of this credential), which
// rules out the downgrade attack where an attacker who intercepts
// an email-change re-verification link could otherwise turn off
// an already-on MFA setting.
//
// Token layout:
//
//	mfa-setup:<sha256-hex>   → user-id  (TTL 5 min)
//
// Plaintext lives in the user's browser (rendered as a hidden form
// field on the verify-email success page); the server stores only
// the SHA-256.

const (
	// MFASetupTokenLifetime is the post-verify window during which
	// the setup token is acceptable. 5 minutes is long enough for
	// the user to read the prompt and click; short enough that an
	// intercepted page screenshot is useless.
	MFASetupTokenLifetime = 5 * time.Minute

	// mfaSetupTokenBytes is the random-token length. 32 bytes →
	// 256 bits → no realistic brute-force.
	mfaSetupTokenBytes = 32
)

// ErrMFASetupTokenInvalid covers "no token" / "wrong token" /
// "expired" / "already consumed". Single sentinel keeps the
// handler's branching simple — every failure looks the same to
// the user.
var ErrMFASetupTokenInvalid = errors.New("mfa setup token invalid or expired")

// MFASetupTokenStore mints + consumes these tokens against Redis.
type MFASetupTokenStore struct {
	rdb *akashic_redis.Client
}

func NewMFASetupTokenStore(rdb *akashic_redis.Client) *MFASetupTokenStore {
	return &MFASetupTokenStore{rdb: rdb}
}

// Create mints a fresh token for the given user_id, stores the
// hash in Redis with a 5-min TTL, and returns the plaintext.
// Caller (verify-email handler) puts the plaintext on the success
// page as a hidden form field.
func (s *MFASetupTokenStore) Create(ctx context.Context, userID uuid.UUID) (string, error) {
	buf := make([]byte, mfaSetupTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	hashHex := hashHex(token)
	if err := s.rdb.Set(ctx, mfaSetupKey(hashHex), userID.String(), MFASetupTokenLifetime).Err(); err != nil {
		return "", fmt.Errorf("store mfa setup token: %w", err)
	}
	return token, nil
}

// Consume validates the supplied token and atomically deletes it.
// Returns the bound user_id on success; ErrMFASetupTokenInvalid
// otherwise. Atomic GetDel guarantees that two concurrent submits
// of the same token can't both succeed.
func (s *MFASetupTokenStore) Consume(ctx context.Context, supplied string) (uuid.UUID, error) {
	if supplied == "" {
		return uuid.Nil, ErrMFASetupTokenInvalid
	}
	hashHex := hashHex(supplied)
	raw, err := s.rdb.GetDel(ctx, mfaSetupKey(hashHex)).Result()
	if errors.Is(err, redis.Nil) {
		return uuid.Nil, ErrMFASetupTokenInvalid
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("get mfa setup token: %w", err)
	}
	userID, err := uuid.Parse(raw)
	if err != nil {
		// Stored value was corrupted — treat as invalid rather
		// than escalating; the audit log catches the anomaly.
		return uuid.Nil, ErrMFASetupTokenInvalid
	}
	return userID, nil
}

func mfaSetupKey(hashHex string) string {
	return "mfa-setup:" + hashHex
}

// hashHex is the canonical token-plaintext → storage-hash encoding.
// Reused inside this package — pulled into a tiny helper so the
// same SHA-256 + lowercase-hex shape is guaranteed across Create
// and Consume.
func hashHex(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
