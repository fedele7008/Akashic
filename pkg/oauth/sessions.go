package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// AuthSession is an auth-server session — created when a user
// successfully POSTs to /login/submit, used by /authorize to skip
// re-prompting for credentials, expired by absolute or idle timeout.
//
// Distinct from the admin-bff's session (which lives in the BFF's
// Redis namespace and tracks browser-to-BFF state). The auth-server
// session lives only as long as the user is bouncing between
// /login → /authorize → various clients within a single browser
// session. SSO ergonomics: log in once at the IdP, multiple clients
// can complete /authorize without re-prompting.
type AuthSession struct {
	UserID       string    `json:"user_id"`
	LDAPDN       string    `json:"ldap_dn"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	UserType     string    `json:"user_type"`
	IssuedAt     time.Time `json:"issued_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	IP           string    `json:"ip"`

	// Phase 9d: when true, this is a "partial" session — the user
	// authenticated with an admin-issued temporary password and
	// MUST complete /forced-password-reset before any other
	// endpoint accepts the session. /authorize and other flows
	// check this flag and 302 to the reset page until the user
	// picks a new password. Cleared (alongside User.PasswordResetRequired)
	// on successful reset; the session ID is rotated at the same
	// time so any leak of the partial-session cookie can't ride
	// the upgrade.
	ResetRequired bool `json:"reset_required,omitempty"`
}

// SessionStore manages auth-server sessions in Redis. Two TTLs:
//   - Idle: refreshed on each access; session expires this long
//     after the most recent /authorize visit
//   - Absolute: never extended; even with active use, session must
//     end by IssuedAt + Absolute
type SessionStore struct {
	r          *redis.Client
	idleTTL    time.Duration
	absoluteTTL time.Duration
}

// NewSessionStore constructs a SessionStore with given TTLs.
func NewSessionStore(r *redis.Client, idle, absolute time.Duration) *SessionStore {
	return &SessionStore{r: r, idleTTL: idle, absoluteTTL: absolute}
}

func sessionKey(sid string) string { return "akashic:auth:session:" + sid }

// Create starts a new session and returns its ID. The ID is 32 bytes
// random, base64url-encoded — used as the cookie value.
//
// IssuedAt and LastSeenAt are set to now; absolute TTL is enforced
// by the Redis EXPIRE call (idle TTL is enforced on each Touch).
func (ss *SessionStore) Create(ctx context.Context, s *AuthSession) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	sid := base64.RawURLEncoding.EncodeToString(buf)

	now := time.Now().UTC()
	s.IssuedAt = now
	s.LastSeenAt = now

	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}
	// Use the absolute TTL on Redis; idle is enforced by Touch
	// updating LastSeenAt and re-setting EXPIRE.
	if err := ss.r.Set(ctx, sessionKey(sid), payload, ss.absoluteTTL).Err(); err != nil {
		return "", fmt.Errorf("redis SET session: %w", err)
	}
	return sid, nil
}

// ErrSessionExpired indicates the session no longer exists (idle
// or absolute timeout, or explicit Delete).
var ErrSessionExpired = errors.New("session expired or not found")

// Get fetches a session by ID. Doesn't extend its TTL; call Touch
// for that. Returns ErrSessionExpired on miss.
//
// Does NOT enforce idle timeout itself — the absolute TTL on the
// Redis key handles that automatically (Redis just deletes it).
// Idle timeout is enforced via Touch's check below.
func (ss *SessionStore) Get(ctx context.Context, sid string) (*AuthSession, error) {
	payload, err := ss.r.Get(ctx, sessionKey(sid)).Result()
	if err == redis.Nil {
		return nil, ErrSessionExpired
	}
	if err != nil {
		return nil, fmt.Errorf("redis GET session: %w", err)
	}
	var s AuthSession
	if err := json.Unmarshal([]byte(payload), &s); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	// Idle-timeout check: if more than idleTTL has passed since
	// LastSeenAt, the session is stale even though Redis still
	// holds it (within the absolute TTL).
	if time.Since(s.LastSeenAt) > ss.idleTTL {
		_ = ss.Delete(ctx, sid)
		return nil, ErrSessionExpired
	}
	return &s, nil
}

// Touch updates LastSeenAt to now (idle TTL refresh). Called from
// /authorize on every successful session-bearing visit. Returns the
// updated session.
func (ss *SessionStore) Touch(ctx context.Context, sid string) (*AuthSession, error) {
	s, err := ss.Get(ctx, sid)
	if err != nil {
		return nil, err
	}
	s.LastSeenAt = time.Now().UTC()
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}
	// Compute remaining absolute TTL — never extends it past
	// IssuedAt + absoluteTTL.
	absRemaining := time.Until(s.IssuedAt.Add(ss.absoluteTTL))
	if absRemaining <= 0 {
		_ = ss.Delete(ctx, sid)
		return nil, ErrSessionExpired
	}
	if err := ss.r.Set(ctx, sessionKey(sid), payload, absRemaining).Err(); err != nil {
		return nil, fmt.Errorf("redis SET session (touch): %w", err)
	}
	return s, nil
}

// Delete removes a session — used by /logout, by post-login session
// rotation (defense against session fixation), and as cleanup when
// idle-timeout fires inside Get.
func (ss *SessionStore) Delete(ctx context.Context, sid string) error {
	return ss.r.Del(ctx, sessionKey(sid)).Err()
}
