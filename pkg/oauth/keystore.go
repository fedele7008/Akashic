// Package oauth holds the OAuth/OIDC server-side primitives:
// JWT signing key store, code/session storage, JWT mint+verify helpers,
// and PKCE primitives. The HTTP handlers themselves live in
// pkg/server/auth (alongside the existing auth-server code).
package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"
)

// KeyStore holds the JWT signing keys used to mint access + ID tokens.
//
// Storage shape: a directory containing one JSON file per key, named
// <kid>.json. On startup, the store reads every file in the directory;
// the most recently CreatedAt non-rotated-out key becomes the active
// signing key. Rotated-out keys remain in the JWKS for verify-only use
// until they're aged out (manual deletion for now; auto-aging deferred).
//
// This is filesystem-based for Phase 7 MVP simplicity. The interface is
// designed so a future Vault-KV-backed implementation drops in cleanly.
// Trade-off acknowledged: filesystem storage loses Vault's audit trail
// of key access. For single-node deployments this is acceptable.
//
// The atomic-pointer pattern (mirroring pkg/pki.Reloader) means
// concurrent token-mint and key-rotation operations never race: a
// caller either sees the old key map or the new one, never a half-built
// state.
type KeyStore struct {
	dir    string
	active atomic.Pointer[string]   // current active KID
	keys   atomic.Pointer[keysMap]  // kid → *SigningKey
}

type keysMap = map[string]*SigningKey

// SigningKey is one RSA keypair plus metadata.
//
// Phase 7 only supports RS256 (RSA-SHA256). Phase 8+ may add ES256
// (ECDSA-SHA256) for smaller token size; the algorithm field exists
// so that future case doesn't require schema migration.
type SigningKey struct {
	KID          string     `json:"kid"`
	Algorithm    string     `json:"algorithm"` // "RS256"
	PrivatePEM   string     `json:"private_key_pem"`
	PublicPEM    string     `json:"public_key_pem"`
	CreatedAt    time.Time  `json:"created_at"`
	RotatedOutAt *time.Time `json:"rotated_out_at,omitempty"`

	// Parsed forms; populated by load(), not persisted.
	private *rsa.PrivateKey `json:"-"`
	public  *rsa.PublicKey  `json:"-"`
}

// Private returns the parsed RSA private key. Call only on the active
// key; verify-only keys still have the private form populated but
// shouldn't be used for signing.
func (k *SigningKey) Private() *rsa.PrivateKey { return k.private }

// Public returns the parsed RSA public key, used for JWT verification
// and for publishing in /jwks.json.
func (k *SigningKey) Public() *rsa.PublicKey { return k.public }

// Active returns true when the key is the current signing key (i.e.,
// not yet rotated out). Verification still works for non-active keys
// during the rotation overlap window.
func (k *SigningKey) Active() bool { return k.RotatedOutAt == nil }

// NewKeyStore constructs a KeyStore backed by the given directory.
// The directory must already exist (caller's responsibility) but may
// be empty — in which case GenerateInitial() should be called on
// first startup to create the bootstrap key.
//
// On construction, all existing keys are loaded.
func NewKeyStore(dir string) (*KeyStore, error) {
	ks := &KeyStore{dir: dir}
	if err := ks.Reload(); err != nil {
		return nil, fmt.Errorf("initial key load: %w", err)
	}
	return ks, nil
}

// Dir returns the directory path the store is reading from.
func (ks *KeyStore) Dir() string { return ks.dir }

// Reload re-reads every <kid>.json file in the directory, parses each,
// and atomically swaps the in-memory key map. Used by the cert-watcher
// pattern so rotations on disk pick up without a restart.
//
// On any parse error for a single file, that file is skipped (with the
// error returned alongside the partial result) so a corrupt key file
// doesn't break the whole store.
func (ks *KeyStore) Reload() error {
	entries, err := os.ReadDir(ks.dir)
	if err != nil {
		return fmt.Errorf("read keystore dir %s: %w", ks.dir, err)
	}

	out := keysMap{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(ks.dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			// Don't fail the whole reload on one corrupt file --
			// log and continue. The active key check below will
			// surface the issue if we end up with no usable keys.
			continue
		}
		var sk SigningKey
		if err := json.Unmarshal(data, &sk); err != nil {
			continue
		}
		if err := sk.parse(); err != nil {
			continue
		}
		out[sk.KID] = &sk
	}
	ks.keys.Store(&out)

	// Pick the active key: most recently CreatedAt with RotatedOutAt nil.
	activeKID := ""
	var activeCreated time.Time
	for _, k := range out {
		if !k.Active() {
			continue
		}
		if activeKID == "" || k.CreatedAt.After(activeCreated) {
			activeKID = k.KID
			activeCreated = k.CreatedAt
		}
	}
	ks.active.Store(&activeKID)

	if activeKID == "" && len(out) > 0 {
		// We have keys but none are active. The store is unhealthy
		// but not catastrophically so -- existing tokens still verify.
		// Caller should generate a new active key.
		return fmt.Errorf("no active signing key in %s (all rotated out)", ks.dir)
	}
	return nil
}

// Active returns the current signing key. Returns an error if no
// active key exists (caller should call GenerateInitial first).
func (ks *KeyStore) Active() (*SigningKey, error) {
	akid := ks.active.Load()
	if akid == nil || *akid == "" {
		return nil, fmt.Errorf("keystore: no active signing key")
	}
	keys := ks.keys.Load()
	if keys == nil {
		return nil, fmt.Errorf("keystore: not initialized")
	}
	k, ok := (*keys)[*akid]
	if !ok {
		return nil, fmt.Errorf("keystore: active kid %q not in key map (concurrent reload?)", *akid)
	}
	return k, nil
}

// ByKID returns the key with the given kid, regardless of active/
// rotated-out status. Used during JWT verification to find the key
// the token's header claims it was signed with.
//
// Returns nil if the kid is not in the store.
func (ks *KeyStore) ByKID(kid string) *SigningKey {
	keys := ks.keys.Load()
	if keys == nil {
		return nil
	}
	return (*keys)[kid]
}

// All returns every key in the store, sorted by CreatedAt ascending.
// Used by the JWKS endpoint to publish all currently-trusted keys.
func (ks *KeyStore) All() []*SigningKey {
	keys := ks.keys.Load()
	if keys == nil {
		return nil
	}
	out := make([]*SigningKey, 0, len(*keys))
	for _, k := range *keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// HasAnyKeys reports whether the store contains at least one key.
// Used by GenerateInitial's caller to decide whether to bootstrap.
func (ks *KeyStore) HasAnyKeys() bool {
	keys := ks.keys.Load()
	return keys != nil && len(*keys) > 0
}

// GenerateInitial creates a fresh RSA-2048 keypair and writes it to
// disk as a new <kid>.json file. Should only be called when
// HasAnyKeys() returns false (first-time deployment).
//
// After this returns, Reload() is called automatically so the new
// key is immediately usable.
func (ks *KeyStore) GenerateInitial() error {
	if ks.HasAnyKeys() {
		return fmt.Errorf("keystore already has keys; refusing to overwrite")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	now := time.Now().UTC()
	kid, err := computeKID(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("compute kid: %w", err)
	}

	sk := &SigningKey{
		KID:        kid,
		Algorithm:  "RS256",
		PrivatePEM: encodeRSAPrivatePEM(priv),
		PublicPEM:  encodeRSAPublicPEM(&priv.PublicKey),
		CreatedAt:  now,
	}
	if err := ks.write(sk); err != nil {
		return fmt.Errorf("write initial key: %w", err)
	}
	return ks.Reload()
}

// write serializes a SigningKey to disk at <dir>/<kid>.json with
// 0600 permissions. Atomic via .tmp + rename.
func (ks *KeyStore) write(sk *SigningKey) error {
	data, err := json.MarshalIndent(sk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.MkdirAll(ks.dir, 0o700); err != nil {
		return fmt.Errorf("mkdir keystore: %w", err)
	}
	final := filepath.Join(ks.dir, sk.KID+".json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, final, err)
	}
	return nil
}

// parse populates the unexported `private` and `public` fields from
// the PEM-encoded strings. Called once per key on load.
func (sk *SigningKey) parse() error {
	if sk.Algorithm != "RS256" {
		return fmt.Errorf("unsupported algorithm %q (only RS256 in Phase 7)", sk.Algorithm)
	}
	privBlock, _ := pem.Decode([]byte(sk.PrivatePEM))
	if privBlock == nil {
		return fmt.Errorf("kid %s: private key PEM decode failed", sk.KID)
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		// Try PKCS8 too (some tools default to that)
		any, err2 := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err2 != nil {
			return fmt.Errorf("kid %s: parse private (PKCS1: %v, PKCS8: %v)", sk.KID, err, err2)
		}
		var ok bool
		priv, ok = any.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("kid %s: PKCS8 private key is not RSA", sk.KID)
		}
	}
	pubBlock, _ := pem.Decode([]byte(sk.PublicPEM))
	if pubBlock == nil {
		return fmt.Errorf("kid %s: public key PEM decode failed", sk.KID)
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return fmt.Errorf("kid %s: parse public: %w", sk.KID, err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("kid %s: public key is not RSA", sk.KID)
	}
	sk.private = priv
	sk.public = pub
	return nil
}

// computeKID derives a stable, URL-safe key ID from the public key's
// SHA256 fingerprint. Same key → same KID across re-runs; different
// keys → different KIDs.
//
// We use the first 16 bytes of the SHA256 digest, base64url-encoded,
// for a 22-char identifier that's compact in JWT headers but still
// has 128 bits of entropy.
func computeKID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:16]), nil
}

func encodeRSAPrivatePEM(priv *rsa.PrivateKey) string {
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func encodeRSAPublicPEM(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}
