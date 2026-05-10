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
	"time"

	"akashic/akashic/pkg/database/akashic_redis"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// Phase 9 (revised): email-verification tokens live in Redis with
// native TTL, not in PG. The pattern: short-lived single-use codes
// belong in Redis (auto-GC, transient by design); durable answers
// (`User.EmailVerified` + `EmailVerifiedAt`) stay in PG.
//
// Why the move: the prior PG-backed `email_verifications` table
// accumulated rows forever — every signup + every resend wrote a
// new row. With Phase 9c (forgot-password codes) and Phase 9f (MFA
// codes) on the way, the row-accumulation pattern would compound
// across three features. Redis keys with TTL solve all three at
// once and remove a manual GC requirement we'd otherwise need to
// add later.
//
// Trade-off: Redis volatility. A Redis restart without persistence
// drops every pending verification token; affected users resend.
// Same posture as a server crash mid-flow — verification was
// always a "best-effort, retry on failure" feature.

// ErrVerificationInvalid covers all "this token can't be consumed"
// cases (not found, already used, never existed). The handler maps
// to a single user-facing "link expired or already used" message
// — distinguishing the underlying cause to the user would be more
// confusing than helpful AND would leak token state.
var ErrVerificationInvalid = errors.New("email verification token invalid or expired")

// VerificationStore is the Redis-backed replacement for the
// pkg/repository/email_verification_repository.go that previously
// served the same purpose against PG.
//
// Key layout:
//
//	primary:                     ev:tok:<sha256-hex>  → JSON {user_id, email, ts}
//	secondary (per-user pointer): ev:user:<uuid>      → <sha256-hex of latest token>
//
// Both keys carry the same TTL (24h). The secondary key exists
// solely to support supersede-on-resend: when a new verification
// is created, we read the secondary, DEL the OLD primary, then
// write both new keys. Without it, an old verification email's
// link would stay valid alongside the new one — a minor footgun
// but worth closing.
type VerificationStore struct {
	rdb *akashic_redis.Client
}

// NewVerificationStore constructs the store. The Redis client must
// already be connected (akashic context wiring guarantees this).
func NewVerificationStore(rdb *akashic_redis.Client) *VerificationStore {
	return &VerificationStore{rdb: rdb}
}

// VerificationData is the JSON shape stored under the primary key.
// Time is stored as an ISO-8601 string for human-readable Redis
// inspection during debugging (`redis-cli GET ev:tok:abc...`).
type VerificationData struct {
	UserID    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// VerificationLifetime mirrors the prior PG-version constant. 24h
// is long enough for "check email tomorrow morning" patterns and
// short enough that a stolen mailbox doesn't yield indefinite
// verification capacity.
const VerificationLifetime = 24 * time.Hour

// Create mints a fresh token, supersedes any prior un-used token
// for the user (deletes its primary key), and writes the new
// primary + per-user pointer with TTL. Returns the RAW token
// (caller emails it); the SHA-256 hash is what's keyed in Redis.
func (s *VerificationStore) Create(
	ctx context.Context,
	userID uuid.UUID,
	email string,
) (rawToken string, err error) {
	// 32 bytes = 256 bits of entropy. Same shape as refresh tokens
	// + previous PG-version verification tokens.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	rawToken = base64.RawURLEncoding.EncodeToString(buf)
	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])

	now := time.Now().UTC()
	data := VerificationData{
		UserID:    userID,
		Email:     email,
		IssuedAt:  now,
		ExpiresAt: now.Add(VerificationLifetime),
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal verification data: %w", err)
	}

	pKey := primaryKey(hashHex)
	uKey := userKey(userID)

	// Supersede: read the old per-user pointer (if any) and DEL
	// the old primary key. Best-effort — if Redis returns an error
	// here we proceed with the new write anyway, so the user's
	// experience isn't blocked by a transient cleanup failure.
	if oldHash, err := s.rdb.Get(ctx, uKey).Result(); err == nil && oldHash != "" {
		_ = s.rdb.Del(ctx, primaryKey(oldHash)).Err()
	}

	// Write the new primary + secondary atomically via pipeline.
	// We don't need EXACT atomicity (a crash between the two SETs
	// leaves the user-pointer dangling at most until TTL expires);
	// pipeline is just a network-roundtrip optimisation.
	pipe := s.rdb.Pipeline()
	pipe.Set(ctx, pKey, payload, VerificationLifetime)
	pipe.Set(ctx, uKey, hashHex, VerificationLifetime)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("write verification keys: %w", err)
	}
	return rawToken, nil
}

// Consume validates the token and atomically removes it. Uses
// GETDEL (Redis 6.2+) so two concurrent consumes for the same
// token cannot both succeed — the second gets ErrVerificationInvalid.
//
// Returns the per-token data so the caller can read the user_id
// and email to flip `User.EmailVerified`.
func (s *VerificationStore) Consume(
	ctx context.Context,
	rawToken string,
) (*VerificationData, error) {
	if rawToken == "" {
		return nil, ErrVerificationInvalid
	}
	hash := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(hash[:])
	primary := primaryKey(hashHex)

	// GETDEL atomically reads + deletes. Guarantees exactly-once
	// semantics for concurrent verifies (one wins, the other
	// receives ErrVerificationInvalid because the second GETDEL
	// returns the empty/redis.Nil state).
	payload, err := s.rdb.GetDel(ctx, primary).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrVerificationInvalid
		}
		return nil, fmt.Errorf("getdel verification: %w", err)
	}
	if payload == "" {
		return nil, ErrVerificationInvalid
	}

	var data VerificationData
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return nil, fmt.Errorf("unmarshal verification data: %w", err)
	}
	// TTL on the key already enforced expiry, but the IssuedAt /
	// ExpiresAt fields are kept for audit-log clarity at the
	// caller. Defensive recheck:
	if !time.Now().UTC().Before(data.ExpiresAt) {
		return nil, ErrVerificationInvalid
	}

	// Best-effort: clean up the per-user pointer too. The pointer
	// would expire naturally inside 24h; cleaning explicitly
	// keeps the Redis keyspace tidier during short test loops.
	_ = s.rdb.Del(ctx, userKey(data.UserID)).Err()
	return &data, nil
}

// primaryKey is the Redis key for a token-hash → data mapping.
func primaryKey(hashHex string) string {
	return "ev:tok:" + hashHex
}

// userKey is the Redis key for a user-id → latest-token-hash
// pointer. Used only by Create to look up + delete the previous
// token when superseding on resend.
func userKey(userID uuid.UUID) string {
	return "ev:user:" + userID.String()
}
