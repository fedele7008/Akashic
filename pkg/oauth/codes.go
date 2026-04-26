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

// AuthorizationCode is the data bound to an OAuth authorization
// code. The auth server creates one of these at /authorize, stores
// it in Redis under the random code value, and the /token handler
// retrieves it (atomically, single-use) for code → token exchange.
//
// All fields except Issued are filled in by /authorize before storage;
// /token reads them and validates against the request before minting.
type AuthorizationCode struct {
	// ClientID identifies the client service this code was issued
	// for. /token must reject if the authenticating client doesn't
	// match (RFC 6749 §4.1.3 — codes are bound to the client they
	// were issued to).
	ClientID string `json:"client_id"`

	// UserID is the authenticated user's UUID. Becomes the `sub`
	// claim on the issued tokens.
	UserID string `json:"user_id"`

	// LDAPDN is preserved so /token can re-look-up the user (e.g.,
	// to check is_disabled hasn't flipped between /authorize and
	// /token, which would catch a "user disabled mid-flow" race).
	LDAPDN string `json:"ldap_dn"`

	// RedirectURI is the URI /authorize redirected the user to.
	// /token must verify the same value is sent in the exchange
	// request (RFC 6749 §4.1.3) — guards against substitution attacks
	// where an attacker tries to swap in a different redirect_uri.
	RedirectURI string `json:"redirect_uri"`

	// Scope is space-separated; carried into the issued tokens.
	Scope string `json:"scope"`

	// CodeChallenge / CodeChallengeMethod come from /authorize per
	// RFC 7636 (PKCE). /token verifies SHA256(code_verifier) ==
	// CodeChallenge (when method is "S256"). Akashic only supports
	// S256; "plain" is forbidden.
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`

	// Nonce, if present, is echoed into the ID token's nonce claim
	// (OIDC core §3.1.2.1) so the client can verify the ID token
	// matches the authentication request it initiated.
	Nonce string `json:"nonce,omitempty"`

	// SessionID is the auth-server session that issued this code.
	// Used during /token to confirm the user's session is still
	// valid (catches "session expired between /authorize and /token"
	// — rare but possible during slow networks).
	SessionID string `json:"session_id"`

	// UserType is the user's type at /authorize time. Stored so
	// /token can populate the user_type claim without re-querying
	// LDAP (saves a round-trip on the hot path).
	UserType string `json:"user_type"`

	// Issued is the wall-clock time of code generation. Used for
	// audit logging only; expiry is enforced by Redis TTL, not by
	// reading this field.
	Issued time.Time `json:"issued"`
}

// CodeStore wraps Redis with the OAuth-specific access patterns:
// generate, atomic-consume (get-then-delete), simple existence check.
type CodeStore struct {
	r   *redis.Client
	ttl time.Duration
}

// NewCodeStore returns a CodeStore backed by the given Redis client.
// ttl is the authorization-code TTL (RFC 6749 recommends ≤10 min;
// Akashic uses 60s default to limit interception window).
func NewCodeStore(r *redis.Client, ttl time.Duration) *CodeStore {
	return &CodeStore{r: r, ttl: ttl}
}

// codeKey returns the Redis key for a given code value.
func codeKey(code string) string {
	return "akashic:oauth:code:" + code
}

// Generate creates a new authorization code, stores the binding
// data under it, and returns the code string for the redirect URL.
//
// Code is 32 bytes random, base64url-encoded → 43-char URL-safe
// string. Single-use: Consume deletes it on first read.
func (cs *CodeStore) Generate(ctx context.Context, data *AuthorizationCode) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate code bytes: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(buf)

	data.Issued = time.Now().UTC()
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal code data: %w", err)
	}

	if err := cs.r.Set(ctx, codeKey(code), payload, cs.ttl).Err(); err != nil {
		return "", fmt.Errorf("redis SET code: %w", err)
	}
	return code, nil
}

// ErrCodeNotFound is returned by Consume when the code isn't in
// Redis — could be expired, never issued, or already consumed.
// /token returns "invalid_grant" in all three cases (the spec doesn't
// distinguish, and distinguishing would leak information).
var ErrCodeNotFound = errors.New("authorization code not found or expired")

// Consume atomically retrieves and deletes the code's binding.
// The Redis Lua script ensures GET+DEL happen as one operation;
// without it, two concurrent /token requests for the same code
// could both succeed (token theft via race condition).
func (cs *CodeStore) Consume(ctx context.Context, code string) (*AuthorizationCode, error) {
	// GET + DEL atomically. EVAL is the Redis idiom for this.
	const luaGetDel = `
		local v = redis.call('GET', KEYS[1])
		if v then
			redis.call('DEL', KEYS[1])
		end
		return v
	`
	res, err := cs.r.Eval(ctx, luaGetDel, []string{codeKey(code)}).Result()
	if err == redis.Nil {
		return nil, ErrCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("redis EVAL get-del: %w", err)
	}
	if res == nil {
		return nil, ErrCodeNotFound
	}
	payloadStr, ok := res.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected redis return type %T", res)
	}

	var data AuthorizationCode
	if err := json.Unmarshal([]byte(payloadStr), &data); err != nil {
		return nil, fmt.Errorf("unmarshal code data: %w", err)
	}
	return &data, nil
}
