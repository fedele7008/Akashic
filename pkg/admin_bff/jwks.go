package admin_bff

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWKS cache for the BFF's ID-token verification.
//
// The auth-server publishes its JWKS at <issuer>/jwks.json. We fetch
// once per rotation interval (default 5 min, mirroring the auth
// server's own Cache-Control max-age), cache by kid, and serve
// verifies from memory. On a cache miss for a previously-unseen kid
// we trigger an immediate refetch -- this handles the rotation
// overlap window where the auth server has signed something with a
// new key before our cache TTL expires.
//
// Thread-safety: the keys map is read under a mutex. The fetch lock
// (singleflight-ish) prevents thundering-herd refetches when many
// requests arrive at the same time after expiry.

type jwksCache struct {
	url   string
	httpC *http.Client // TLS-configured to trust the auth-server CA

	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	loadedAt time.Time

	fetchMu sync.Mutex
}

func newJWKSCache(url string, httpC *http.Client) *jwksCache {
	return &jwksCache{
		url:   url,
		httpC: httpC,
		keys:  map[string]*rsa.PublicKey{},
	}
}

const jwksRefreshInterval = 5 * time.Minute

// publicKey returns the RSA public key for a given kid, refetching
// the JWKS if the cached version is stale or doesn't contain it.
func (c *jwksCache) publicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if k := c.cached(kid); k != nil {
		return k, nil
	}

	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()

	// Re-check inside the lock; another goroutine may have just refreshed.
	if k := c.cached(kid); k != nil {
		return k, nil
	}

	if err := c.refetch(ctx); err != nil {
		return nil, fmt.Errorf("jwks refetch: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("jwks: kid %q not found", kid)
}

// cached returns the public key from the cache iff it's still fresh
// AND the kid is present. Returns nil otherwise (caller refetches).
func (c *jwksCache) cached(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Since(c.loadedAt) >= jwksRefreshInterval {
		return nil
	}
	return c.keys[kid]
}

type jwksDoc struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// refetch fetches the JWKS document, parses each RSA key, and
// replaces the cache wholesale. Keys that disappeared from the
// document are dropped -- correct behavior, since the auth-server's
// keystore publishes every still-trusted key.
func (c *jwksCache) refetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", c.url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwksKeyToRSA(k)
		if err != nil {
			// Skip malformed keys but don't fail the whole refresh;
			// the auth-server may publish a key type we don't yet
			// understand and that's fine as long as at least one
			// is valid.
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks contained no usable RSA keys")
	}

	c.mu.Lock()
	c.keys = keys
	c.loadedAt = time.Now().UTC()
	c.mu.Unlock()
	return nil
}

// jwksKeyToRSA decodes the base64url-encoded n/e fields of an RSA
// JWK into a *rsa.PublicKey. RFC 7518 §6.3.1.
func jwksKeyToRSA(k jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	if len(eBytes) > 4 {
		return nil, fmt.Errorf("e too large (%d bytes)", len(eBytes))
	}
	// Pad e to 4 bytes for big-endian uint32 read.
	var eUint32 uint32
	for _, b := range eBytes {
		eUint32 = (eUint32 << 8) | uint32(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(eUint32),
	}, nil
}
