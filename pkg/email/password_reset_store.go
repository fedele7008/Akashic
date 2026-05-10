package email

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"akashic/akashic/pkg/database/akashic_redis"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Phase 9c: forgot-password 6-digit code flow. Same Redis-backed
// pattern as the verification store (auto-TTL, no PG accumulation).
//
// Three Redis namespaces:
//
//   pwr:user:<uuid>          → JSON {code_hash, attempts, email, expires_at}
//                              TTL = 15 min (the user's pending code).
//                              Keyed by user-id because the user
//                              types email + code; we look up the
//                              user from email then check the code.
//
//   pwr:ready:<hash(cookie)> → user-id (TTL 5 min).
//                              Set after a successful code verify.
//                              The /reset page is gated by a cookie
//                              whose hash maps here. Without this,
//                              anyone who knew a user's email could
//                              navigate directly to /reset.
//
//   pwr:rate:email:<hash>    → counter (TTL 24h).
//                              Per-email rate limit; defends against
//                              email-bombing a target.
//
// SHA-256-hashing the 6-digit code at-rest is defense-in-depth
// rather than a hard security property — an attacker with Redis
// dump access could pre-compute all 1M codes. The real defense
// is the per-code attempt counter (5 wrong → consumed) plus
// per-IP and per-email rate limits.

// ErrResetInvalid is the catch-all "this code can't be used"
// sentinel. Distinct underlying causes (no code outstanding, code
// expired, wrong code, attempts exhausted) all collapse here so
// the user-facing message stays uniform.
var ErrResetInvalid = errors.New("password reset code invalid or expired")

// ErrResetRateLimited fires when the per-email rate limit kicks
// in. Surfaced to the UI as a generic "too many attempts" message
// (we don't say "for this email" to avoid email-existence leaks).
var ErrResetRateLimited = errors.New("password reset rate limit exceeded")

// PasswordResetStore manages 6-digit reset codes and the
// "verified-code, may now reset" cookie tokens. All state in Redis.
type PasswordResetStore struct {
	rdb *akashic_redis.Client
}

func NewPasswordResetStore(rdb *akashic_redis.Client) *PasswordResetStore {
	return &PasswordResetStore{rdb: rdb}
}

// Tunables. Per the user spec ("15 min window time"); per-code
// attempt cap is 5 (industry-standard); per-email rate is 5/day
// (deters bombing without blocking legitimate retries during an
// email-delivery delay).
const (
	ResetCodeLifetime    = 15 * time.Minute
	ResetReadyLifetime   = 5 * time.Minute
	ResetMaxAttempts     = 5
	ResetEmailDailyCap   = 5
	resetReadyCookieBytes = 32
)

// pendingCode is the JSON payload under `pwr:user:<uuid>`.
type pendingCode struct {
	CodeHash  string    `json:"code_hash"`
	Email     string    `json:"email"`
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Create issues a fresh 6-digit numeric code for the given user
// and stores it under `pwr:user:<uuid>` with a 15-min TTL. Any
// prior outstanding code for the same user is replaced (the SET
// with TTL overwrites). Returns the RAW code (caller emails it).
//
// Per-email rate limit: increments `pwr:rate:email:<hash>` on
// each call; once it exceeds ResetEmailDailyCap, returns
// ErrResetRateLimited without issuing a new code.
func (s *PasswordResetStore) Create(
	ctx context.Context,
	userID uuid.UUID,
	email string,
) (rawCode string, err error) {
	// Per-email rate-limit gate. INCR returns the new value; if
	// over the cap, we don't issue. The TTL is set on first INCR
	// only (Redis INCR alone doesn't set TTL); we use a Lua-style
	// pipeline to add EXPIRE if the new value is 1.
	rateKey := emailRateKey(email)
	count, err := s.rdb.Incr(ctx, rateKey).Result()
	if err != nil {
		return "", fmt.Errorf("incr rate counter: %w", err)
	}
	if count == 1 {
		// First request in this window — set the TTL.
		_ = s.rdb.Expire(ctx, rateKey, 24*time.Hour).Err()
	}
	if count > ResetEmailDailyCap {
		return "", ErrResetRateLimited
	}

	// Generate a 6-digit code. crypto/rand-derived to defend
	// against attackers predicting from PRNG output. We use
	// rand.Int(big.NewInt(1_000_000)) and zero-pad — produces a
	// uniformly-distributed 000000-999999.
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	rawCode = fmt.Sprintf("%06d", n.Int64())
	codeHash := sha256.Sum256([]byte(rawCode))

	now := time.Now().UTC()
	payload := pendingCode{
		CodeHash:  hex.EncodeToString(codeHash[:]),
		Email:     email,
		Attempts:  0,
		ExpiresAt: now.Add(ResetCodeLifetime),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal code: %w", err)
	}
	if err := s.rdb.Set(ctx, userKeyForReset(userID), body, ResetCodeLifetime).Err(); err != nil {
		return "", fmt.Errorf("store code: %w", err)
	}
	return rawCode, nil
}

// Verify checks the user-supplied code against the stored hash,
// increments the attempt counter on miss, and returns:
//   - (nil) on success — caller should call StartReadyToken next.
//   - ErrResetInvalid on miss / expiry / exhaustion. The code row
//     is auto-consumed when attempts hit ResetMaxAttempts so the
//     attacker can't keep trying with a fresh code by waiting.
//
// The user-id is looked up by the caller from the email; we don't
// do that here because the user-repository lives outside this
// package and we'd rather keep this store dependency-free.
func (s *PasswordResetStore) Verify(
	ctx context.Context,
	userID uuid.UUID,
	suppliedCode string,
) error {
	suppliedCode = strings.TrimSpace(suppliedCode)
	if len(suppliedCode) != 6 {
		return ErrResetInvalid
	}
	key := userKeyForReset(userID)
	raw, err := s.rdb.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return ErrResetInvalid
		}
		return fmt.Errorf("get code: %w", err)
	}
	var p pendingCode
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return fmt.Errorf("unmarshal code: %w", err)
	}
	if !time.Now().UTC().Before(p.ExpiresAt) {
		_ = s.rdb.Del(ctx, key).Err()
		return ErrResetInvalid
	}

	suppliedHash := sha256.Sum256([]byte(suppliedCode))
	if hex.EncodeToString(suppliedHash[:]) != p.CodeHash {
		// Wrong code. Increment attempts; if at cap, consume.
		p.Attempts++
		if p.Attempts >= ResetMaxAttempts {
			_ = s.rdb.Del(ctx, key).Err()
			return ErrResetInvalid
		}
		// Re-store with bumped counter (TTL is preserved by KEEPTTL).
		body, _ := json.Marshal(p)
		_ = s.rdb.Set(ctx, key, body, redis.KeepTTL).Err()
		return ErrResetInvalid
	}

	// Match. Consume the code (one-shot — verifying twice fails
	// the second time, even though both submissions would have
	// been "correct").
	_ = s.rdb.Del(ctx, key).Err()
	return nil
}

// StartReadyToken creates a short-lived "you've verified the
// code, now go reset" cookie token. Returns the raw cookie value
// (caller sets it as an HttpOnly Secure SameSite=Lax cookie); the
// SHA-256 hash is what's keyed in Redis.
//
// Cookie scope: handler sets `Path=/forgot-password/reset` so the
// cookie is sent ONLY to the reset endpoint. Outside that scope
// (regular pages, API endpoints) the cookie is not present.
func (s *PasswordResetStore) StartReadyToken(
	ctx context.Context,
	userID uuid.UUID,
) (cookieValue string, err error) {
	buf := make([]byte, resetReadyCookieBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	cookieValue = base64.RawURLEncoding.EncodeToString(buf)
	hash := sha256.Sum256([]byte(cookieValue))
	hashHex := hex.EncodeToString(hash[:])
	if err := s.rdb.Set(ctx, readyKey(hashHex), userID.String(), ResetReadyLifetime).Err(); err != nil {
		return "", fmt.Errorf("store ready token: %w", err)
	}
	return cookieValue, nil
}

// ConsumeReadyToken validates the ready cookie + atomically
// consumes it. Returns the bound user-id on success; the cookie
// value is dead after this returns regardless of outcome.
//
// Atomic via GETDEL — defends against double-submit races where
// the user clicks the reset button twice rapidly.
func (s *PasswordResetStore) ConsumeReadyToken(
	ctx context.Context,
	cookieValue string,
) (uuid.UUID, error) {
	if cookieValue == "" {
		return uuid.Nil, ErrResetInvalid
	}
	hash := sha256.Sum256([]byte(cookieValue))
	hashHex := hex.EncodeToString(hash[:])
	raw, err := s.rdb.GetDel(ctx, readyKey(hashHex)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return uuid.Nil, ErrResetInvalid
		}
		return uuid.Nil, fmt.Errorf("getdel ready token: %w", err)
	}
	uid, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, fmt.Errorf("malformed ready token value: %w", err)
	}
	return uid, nil
}

func userKeyForReset(userID uuid.UUID) string {
	return "pwr:user:" + userID.String()
}

func readyKey(hashHex string) string {
	return "pwr:ready:" + hashHex
}

func emailRateKey(email string) string {
	// Hash the email so a Redis dump doesn't reveal the recipient.
	// Lowercase first — case-insensitive matching for the rate cap.
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "pwr:rate:email:" + hex.EncodeToString(h[:])
}
