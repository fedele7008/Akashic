package admin_bff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// admin-bff acts as an OAuth 2.1 client to the Akashic auth server.
//
// Responsibilities of this file:
//   1. Generate state + PKCE verifier on /login
//   2. Exchange the auth code for tokens at /token
//   3. Verify the ID token's signature, iss, aud, exp using the
//      auth-server's published JWKS
//
// Why hand-rolled instead of e.g. coreos/go-oidc: simplicity. We
// already use golang-jwt/v5 in the server-side auth code; reusing it
// here keeps the dependency surface flat. Discovery + JWKS fetch are
// ~80 lines combined; pulling go-oidc would be more code (init dance,
// provider object lifecycle) than what we save.

// oauthClient holds the BFF's OAuth-client identity + the static URLs
// it talks to. Constructed once at server startup; the fields are
// immutable after that.
//
// The split between `issuer` and `internalBaseURL` is deliberate and
// is the standard pattern for OIDC behind a reverse proxy:
//
//   - issuer (public): what the auth-server bakes into the JWT `iss`
//     claim, what's published in /.well-known/openid-configuration,
//     and what the *browser* navigates to for /authorize and /login.
//
//   - internalBaseURL (private): where the BFF dials when calling
//     /token and /jwks.json. From inside the docker network the
//     public issuer hostname may not resolve, or may force an
//     unnecessary trip through the host load balancer. The internal
//     URL is the docker-network alias (https://auth.akashic.local:8080)
//     which is in the auth-server's cert SAN list so TLS still verifies.
//
// The token's `iss` claim is still validated against `issuer` (public),
// because the cryptographic identity of the IdP is what matters, not
// which network path you used to reach it.
type oauthClient struct {
	issuer          string // public, used for iss validation + browser-facing /authorize
	internalBaseURL string // private, used for /token and /jwks.json (server-to-server)
	clientID        string // "akashic-admin"
	clientSecret    string // plaintext — read once from disk
	redirectURI     string // must match the row in client_services exactly
	scopes          string // space-separated, e.g. "openid profile email"
	httpC           *http.Client
	jwks            *jwksCache
}

// newOAuthClient wires up the OAuth-client side. The HTTP client uses
// the supplied CA bundle for TLS verification when talking to
// auth.akashic.local; the cert is signed by the same internal CA that
// signs the control-plane cert (different intermediate, same root),
// so we can't reuse the mTLS-CA bundle verbatim.
func newOAuthClient(cfg *Config) (*oauthClient, error) {
	secret, err := os.ReadFile(cfg.OAuthClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("read client secret %s: %w", cfg.OAuthClientSecretFile, err)
	}

	httpC, err := buildOAuthHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("build oauth http client: %w", err)
	}

	issuer := strings.TrimRight(cfg.OAuthIssuer, "/")
	// Internal base URL falls back to the (public) issuer when not
	// configured -- preserves single-URL-deployment behavior for
	// operators who don't need the split.
	internal := strings.TrimRight(cfg.OAuthInternalURL, "/")
	if internal == "" {
		internal = issuer
	}
	return &oauthClient{
		issuer:          issuer,
		internalBaseURL: internal,
		clientID:        cfg.OAuthClientID,
		clientSecret:    strings.TrimSpace(string(secret)),
		redirectURI:     cfg.OAuthRedirectURI,
		scopes:          cfg.OAuthScopes,
		httpC:           httpC,
		// JWKS fetch goes via the internal URL too — the BFF doesn't
		// need to round-trip through the public load balancer to grab
		// signing keys.
		jwks: newJWKSCache(internal+"/jwks.json", httpC),
	}, nil
}

// buildOAuthHTTPClient builds the HTTP client used for outbound calls
// to /token and /jwks.json. It uses TLS ONLY (no client cert -- this
// is OAuth, not mTLS) and verifies the auth-server cert against the
// supplied CA bundle.
func buildOAuthHTTPClient(cfg *Config) (*http.Client, error) {
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(cfg.OAuthCAFile)
	if err != nil {
		return nil, fmt.Errorf("read auth CA %s: %w", cfg.OAuthCAFile, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("auth CA %s contained no usable certificates", cfg.OAuthCAFile)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}, nil
}

// ─── PKCE + state generation ────────────────────────────────────────

// generatePKCE returns a (verifier, challenge) pair per RFC 7636.
// Verifier is 64 random bytes base64url-encoded (~86 chars; well
// inside the spec's 43-128 char range).
//
// Challenge is SHA256(verifier) base64url-encoded.
func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// generateState returns 32 bytes of base64url-encoded randomness for
// CSRF protection on the OAuth flow. Bound to the browser via the
// pre-session cookie set during /login and verified during /callback.
func generateState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// authorizeURL builds the URL the browser is sent to on /login.
// Uses the PUBLIC issuer because the browser is the consumer; the
// auth-server's /authorize endpoint validates every parameter against
// the registered client_services row.
func (c *oauthClient) authorizeURL(state, challenge string) string {
	u, _ := url.Parse(c.issuer + "/authorize")
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.clientID)
	q.Set("redirect_uri", c.redirectURI)
	q.Set("scope", c.scopes)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// ─── Code exchange ──────────────────────────────────────────────────

// tokenResponse mirrors the auth-server's /token JSON response.
// Fields tagged with `omitempty` are absent for non-OIDC flows; for
// admin-bff (which always requests `openid`), id_token is required.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// exchangeCode posts the auth code to /token, authenticated via HTTP
// Basic with the client's bcrypt'd secret. RFC 6749 §4.1.3.
func (c *oauthClient) exchangeCode(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.redirectURI)
	form.Set("code_verifier", verifier)

	// Back-channel call goes via the INTERNAL URL. The bearer of this
	// call is the BFF, not the browser, so it doesn't need (and
	// shouldn't pay the cost of) routing through the public load
	// balancer.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.internalBaseURL+"/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		// Auth-server returns {error:..., error_description:...} per
		// RFC 6749 §5.2. Surface that verbatim into the error so the
		// admin sees what failed.
		return nil, fmt.Errorf("token exchange %d: %s", resp.StatusCode, string(body))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	return &tr, nil
}

// ─── ID token verification ──────────────────────────────────────────

// IDClaims is the minimal subset of an OIDC ID token we care about.
// Future Phase 8+ may add more (auth_time, acr, amr) but for the
// admin-bff role check we only need iss/aud/exp/sub/user_type.
//
// `aud` is jwt.ClaimStrings, not a plain string, because OIDC permits
// the audience claim to be a JSON array even when only one audience
// is bound (RFC 7519 §4.1.3). The auth-server uses jwt.RegisteredClaims,
// which marshals as an array; if we used `string` here the JSON
// decode would fail with "cannot unmarshal array into Go struct
// field of type string".
type IDClaims struct {
	Issuer            string           `json:"iss"`
	Subject           string           `json:"sub"`
	Audience          jwt.ClaimStrings `json:"aud"`
	ExpiresAt         int64            `json:"exp"`
	IssuedAt          int64            `json:"iat"`
	UserType          string           `json:"user_type"`
	PreferredUsername string           `json:"preferred_username"`
	Email             string           `json:"email"`
	Nonce             string           `json:"nonce"`
}

// Valid implements jwt.Claims. We don't put much logic here; the
// real verification (iss/aud/exp/nbf) happens in verifyIDToken below
// where we have the expected values to compare against.
func (c *IDClaims) Valid() error { return nil }

// GetExpirationTime / GetIssuedAt / GetAudience / GetIssuer / GetSubject
// implement jwt.Claims (v5 interface).
func (c *IDClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}
func (c *IDClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}
func (c *IDClaims) GetNotBefore() (*jwt.NumericDate, error) { return nil, nil }
func (c *IDClaims) GetIssuer() (string, error)              { return c.Issuer, nil }
func (c *IDClaims) GetSubject() (string, error)             { return c.Subject, nil }
func (c *IDClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}

// verifyIDToken parses + verifies the ID token using a key from the
// JWKS cache. Verifies: signature (RS256), iss == configured issuer,
// aud == clientID, exp > now, nonce == expectedNonce (if non-empty).
//
// Why we verify ourselves rather than trust /token's response: the
// /token call goes through TLS so MITM is implausible *in this
// deployment*, but verifying locally is the spec-compliant behavior
// and means the BFF gets the same correctness guarantees anywhere
// (e.g., behind a corporate proxy that terminates TLS).
func (c *oauthClient) verifyIDToken(ctx context.Context, raw, expectedNonce string) (*IDClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.clientID),
		jwt.WithExpirationRequired(),
	)
	claims := &IDClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		kidVal, _ := t.Header["kid"].(string)
		if kidVal == "" {
			return nil, fmt.Errorf("id token missing kid header")
		}
		return c.jwks.publicKey(ctx, kidVal)
	})
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("id token not valid")
	}
	if expectedNonce != "" && claims.Nonce != expectedNonce {
		return nil, fmt.Errorf("id token nonce mismatch")
	}
	return claims, nil
}
