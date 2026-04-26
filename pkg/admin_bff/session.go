package admin_bff

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

// BFF browser-session store.
//
// Two TTLs (mirrors auth-server's pkg/oauth.SessionStore so the
// behavior is parallel):
//
//   - Idle TTL: refreshed on each authenticated request. Session
//     expires this long after the most recent activity.
//   - Absolute TTL: never extended. Hard ceiling on session lifetime
//     even with continuous activity.
//
// Why both: idle alone lets a stolen cookie live forever as long as
// the attacker keeps polling; absolute alone forces re-login on a
// schedule that may interrupt active work. The pair is the standard
// session-management trade-off.
//
// Distinct from the auth-server's "akashic:auth:session:" namespace --
// this BFF session lives at "akashic:bff:admin:session:<sid>" so the
// two never collide and an operator can wipe one independently of the
// other (e.g., for a session-revocation incident scoped to admin-bff).

// Session captures everything the BFF needs across a logged-in
// browser's lifecycle. The access_token field is what the BFF uses to
// call back to the auth-server's /userinfo or future protected
// endpoints; it never leaves the BFF↔auth-server boundary, so the FE
// (and any XSS in it) cannot extract it.
type Session struct {
	UserID         string    `json:"user_id"`
	UserType       string    `json:"user_type"`
	Username       string    `json:"username"`
	Email          string    `json:"email"`
	AccessToken    string    `json:"access_token"`
	IDToken        string    `json:"id_token"`
	AccessExpires  time.Time `json:"access_expires"`
	IssuedAt       time.Time `json:"issued_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	IP             string    `json:"ip"`
}

type sessionStore struct {
	r           *redis.Client
	idleTTL     time.Duration
	absoluteTTL time.Duration
}

func newSessionStore(r *redis.Client, idle, absolute time.Duration) *sessionStore {
	return &sessionStore{r: r, idleTTL: idle, absoluteTTL: absolute}
}

func bffSessionKey(sid string) string { return "akashic:bff:admin:session:" + sid }

// Create writes a new session and returns its ID. Caller is expected
// to set `s.IP` before calling (we don't peek inside the http.Request
// here -- keeps the store free of HTTP coupling).
func (ss *sessionStore) Create(ctx context.Context, s *Session) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	sid := base64.RawURLEncoding.EncodeToString(buf)

	now := time.Now().UTC()
	s.IssuedAt = now
	s.LastActivityAt = now

	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}

	// Absolute TTL on the Redis key is the floor; idle TTL is enforced
	// inside Get/Touch by checking LastActivityAt. The Redis key
	// disappears no later than IssuedAt + absoluteTTL no matter what.
	if err := ss.r.Set(ctx, bffSessionKey(sid), payload, ss.absoluteTTL).Err(); err != nil {
		return "", fmt.Errorf("redis SET: %w", err)
	}
	return sid, nil
}

// ErrSessionMissing means the cookie's session no longer exists.
// Could be expired (idle or absolute), revoked, or the cookie was
// never valid in the first place.
var ErrSessionMissing = errors.New("session expired or not found")

// Get fetches a session WITHOUT extending its TTL. Returns
// ErrSessionMissing on miss, idle expiry, or absolute expiry.
//
// Idle check happens here, not just in Touch, because some callers
// (like a session-info endpoint or a logout audit log) want to read
// the session without committing to refresh it.
func (ss *sessionStore) Get(ctx context.Context, sid string) (*Session, error) {
	if sid == "" {
		return nil, ErrSessionMissing
	}
	payload, err := ss.r.Get(ctx, bffSessionKey(sid)).Result()
	if err == redis.Nil {
		return nil, ErrSessionMissing
	}
	if err != nil {
		return nil, fmt.Errorf("redis GET: %w", err)
	}
	var s Session
	if err := json.Unmarshal([]byte(payload), &s); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	// Idle-timeout enforcement.
	if time.Since(s.LastActivityAt) > ss.idleTTL {
		_ = ss.Delete(ctx, sid)
		return nil, ErrSessionMissing
	}
	return &s, nil
}

// Touch is Get + LastActivityAt update. Used by the session-required
// middleware on every authenticated /api/* request.
func (ss *sessionStore) Touch(ctx context.Context, sid string) (*Session, error) {
	s, err := ss.Get(ctx, sid)
	if err != nil {
		return nil, err
	}
	s.LastActivityAt = time.Now().UTC()

	// Compute remaining absolute TTL — never extends past
	// IssuedAt + absoluteTTL.
	absRemaining := time.Until(s.IssuedAt.Add(ss.absoluteTTL))
	if absRemaining <= 0 {
		_ = ss.Delete(ctx, sid)
		return nil, ErrSessionMissing
	}

	payload, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}
	if err := ss.r.Set(ctx, bffSessionKey(sid), payload, absRemaining).Err(); err != nil {
		return nil, fmt.Errorf("redis SET (touch): %w", err)
	}
	return s, nil
}

// Delete removes a session — explicit logout, post-callback rotation
// against fixation, or admin force-logout (Phase 8+).
func (ss *sessionStore) Delete(ctx context.Context, sid string) error {
	if sid == "" {
		return nil
	}
	return ss.r.Del(ctx, bffSessionKey(sid)).Err()
}
