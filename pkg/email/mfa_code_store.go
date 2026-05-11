package email

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"akashic/akashic/pkg/database/akashic_redis"

	"github.com/redis/go-redis/v9"
)

// Phase 9f: MFA email-code store. Same Redis-backed pattern as the
// forgot-password store (auto-TTL, no PG accumulation).
//
// Keyed by **session id** (the partial session minted at /login/submit
// when MFA is required) rather than user id. Session-keying scopes a
// code to one specific login attempt — re-issuing during the same
// pending login overwrites cleanly, but a parallel login from another
// device gets its own pending row.
//
// Two Redis namespaces:
//
//	mfa:sid:<session-id>    JSON {code_hash, attempts, user_id, expires_at}
//	                        TTL = 10 min.
//
//	mfa:rate:user:<uuid>    counter (TTL 1h).
//	                        Per-user rate limit on code issuance.
//	                        Defends against attackers re-triggering
//	                        sends to fish for a low-entropy code.

// ErrMFACodeInvalid is the catch-all "this code can't be used"
// sentinel — wrong code, expired, or attempts exhausted. Same
// info-leak-prevention shape as the password-reset store.
var ErrMFACodeInvalid = errors.New("mfa code invalid or expired")

// ErrMFARateLimited fires when too many code-issue requests stack up
// for one user inside the rate-limit window. Surfaced to the UI as
// a generic "try again later" message.
var ErrMFARateLimited = errors.New("mfa code rate limit exceeded")

// MFACodeStore manages email-MFA 6-digit codes. All state in Redis.
type MFACodeStore struct {
	rdb *akashic_redis.Client
}

func NewMFACodeStore(rdb *akashic_redis.Client) *MFACodeStore {
	return &MFACodeStore{rdb: rdb}
}

// Tunables. 10-minute window matches industry conventions (Google,
// GitHub use ~10m for email-MFA codes). Hourly rate limit of 10
// gives a user room to retry on email-delivery delay without
// allowing a code-fishing attack.
const (
	MFACodeLifetime    = 10 * time.Minute
	MFAMaxAttempts     = 5
	MFAUserHourlyCap   = 10
	mfaUserRateWindow  = time.Hour
)

// pendingMFACode is the JSON payload under `mfa:sid:<session-id>`.
type pendingMFACode struct {
	CodeHash  string    `json:"code_hash"`
	UserID    string    `json:"user_id"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Create issues a fresh 6-digit code for the given session id and
// stores it in Redis with a 10-min TTL. Any prior outstanding code
// for the same session is replaced (Set with TTL overwrites).
// Returns the RAW code so the caller can email it.
//
// Per-user rate-limit gate runs first; over-cap callers get
// ErrMFARateLimited and no code is generated.
func (s *MFACodeStore) Create(
	ctx context.Context,
	sessionID string,
	userID string,
) (rawCode string, err error) {
	rateKey := mfaUserRateKey(userID)
	count, err := s.rdb.Incr(ctx, rateKey).Result()
	if err != nil {
		return "", fmt.Errorf("incr mfa rate counter: %w", err)
	}
	if count == 1 {
		_ = s.rdb.Expire(ctx, rateKey, mfaUserRateWindow).Err()
	}
	if count > MFAUserHourlyCap {
		return "", ErrMFARateLimited
	}

	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	rawCode = fmt.Sprintf("%06d", n.Int64())
	codeHash := sha256.Sum256([]byte(rawCode))

	now := time.Now().UTC()
	payload := pendingMFACode{
		CodeHash:  hex.EncodeToString(codeHash[:]),
		UserID:    userID,
		Attempts:  0,
		ExpiresAt: now.Add(MFACodeLifetime),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal mfa code: %w", err)
	}
	if err := s.rdb.Set(ctx, mfaSessionKey(sessionID), body, MFACodeLifetime).Err(); err != nil {
		return "", fmt.Errorf("store mfa code: %w", err)
	}
	return rawCode, nil
}

// Verify consumes-on-match: returns nil and deletes the row when
// the supplied code matches the stored hash; returns ErrMFACodeInvalid
// (and increments the attempt counter, with auto-consume on cap)
// otherwise.
func (s *MFACodeStore) Verify(
	ctx context.Context,
	sessionID string,
	suppliedCode string,
) error {
	suppliedCode = strings.TrimSpace(suppliedCode)
	if len(suppliedCode) != 6 {
		return ErrMFACodeInvalid
	}
	key := mfaSessionKey(sessionID)
	raw, err := s.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrMFACodeInvalid
		}
		return fmt.Errorf("get mfa code: %w", err)
	}
	var p pendingMFACode
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return fmt.Errorf("unmarshal mfa code: %w", err)
	}
	if !time.Now().UTC().Before(p.ExpiresAt) {
		_ = s.rdb.Del(ctx, key).Err()
		return ErrMFACodeInvalid
	}

	suppliedHash := sha256.Sum256([]byte(suppliedCode))
	if hex.EncodeToString(suppliedHash[:]) != p.CodeHash {
		p.Attempts++
		if p.Attempts >= MFAMaxAttempts {
			_ = s.rdb.Del(ctx, key).Err()
			return ErrMFACodeInvalid
		}
		body, _ := json.Marshal(p)
		_ = s.rdb.Set(ctx, key, body, redis.KeepTTL).Err()
		return ErrMFACodeInvalid
	}

	// Match. Consume the code so resubmission of the same code
	// won't re-pass — caller should now finalize the session.
	_ = s.rdb.Del(ctx, key).Err()
	return nil
}

// Delete drops a pending row without verifying. Used when a partial
// session is being torn down (logout, password-reset interrupting
// the MFA flow) so a stale code doesn't sit in Redis until TTL.
func (s *MFACodeStore) Delete(ctx context.Context, sessionID string) error {
	return s.rdb.Del(ctx, mfaSessionKey(sessionID)).Err()
}

func mfaSessionKey(sessionID string) string {
	return "mfa:sid:" + sessionID
}

func mfaUserRateKey(userID string) string {
	return "mfa:rate:user:" + userID
}
