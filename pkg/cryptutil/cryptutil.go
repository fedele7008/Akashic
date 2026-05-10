// Package cryptutil is the deployment's column-encryption helper.
//
// Phase 9: secrets stored in PG (today: SendGrid API key; future:
// SMTP credentials, Postmark token, etc.) are encrypted with a key
// derived from `AKASHIC_SECRET`. A DB dump or accidental log-line
// of an encrypted field shows ciphertext, not plaintext.
//
// Cipher: AES-256-GCM (authenticated, stdlib). Key derivation:
// HKDF-SHA256 with a domain-separation `info` tag per call site,
// so the keys protecting different column families never collide
// cryptographically — a leak of one purpose's per-call key tells
// an attacker nothing about another's.
//
// Wire format: base64(nonce || ciphertext-with-tag). Single column,
// stays human-comparable, no schema changes when fields rotate.
//
// Trust model: the master secret lives in the operator's env (or
// secret-manager-mounted file) at deploy time. Anyone with both
// DB-read AND env-read access can decrypt — that's by design.
// The threat this defends against is single-source compromise
// (DB dump leaks alone, log line prints alone). Vault migration
// is the next step up the trust ladder, deferred to Phase 10+.
package cryptutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// keySize is the AES-256 key length. AES-256 is overkill for the
// threat model (operator-secret recovery) but matches the codebase's
// other crypto choices (RSA 4096 / ECDSA P-384 in pkg/pki) for
// consistency.
const keySize = 32

// nonceSize is the AES-GCM nonce length. 12 bytes is the
// stdlib-recommended size; mixing sizes between encrypt/decrypt
// would break round-trips, so this is a single-source-of-truth
// constant.
const nonceSize = 12

// hkdfSalt is a fixed deployment-wide salt for the HKDF extraction
// step. Per RFC 5869 §3.1 a salt is OPTIONAL but recommended. We
// use a constant rather than a random per-deployment salt because
// the master secret IS the per-deployment uniqueness root — adding
// a salt elsewhere would either need persistent storage (chicken-
// and-egg with the email_configs row we're trying to encrypt) or
// add no real security.
//
// The salt's value is irrelevant cryptographically; it just needs
// to be domain-separated from any future use of HKDF in this
// codebase. The string is human-readable for operator forensics.
var hkdfSalt = []byte("akashic-db-encrypt-v1")

// Cipher is a configured-once-at-startup encrypt/decrypt helper
// for a single domain (purpose). Construct once via New and call
// Encrypt/Decrypt for that purpose's column family. Different
// purposes get different Ciphers (and thus different per-purpose
// keys), constructed from the same master secret with different
// `info` tags.
type Cipher struct {
	aead cipher.AEAD
}

// New derives a per-purpose key from the master secret + the given
// `info` tag, and returns a Cipher ready to encrypt/decrypt for
// that purpose. Returns an error if the master secret is empty or
// the cipher construction fails (effectively impossible with valid
// stdlib AES-GCM).
//
// `info` is the domain-separation tag — pick a stable, descriptive
// string per call site (e.g., "email-config-sendgrid-key"). Two
// callers with the same info produce identical keys (good — it's
// a deterministic derivation); two callers with different info
// produce cryptographically independent keys.
//
// Best practice: name the info tag after the column family. If the
// schema for that family ever changes the wire format
// incompatibly, bump a version suffix ("…-v2") so old ciphertexts
// fail to decrypt loudly instead of silently mis-parsing.
func New(masterSecret []byte, info string) (*Cipher, error) {
	if len(masterSecret) == 0 {
		return nil, errors.New("cryptutil: master secret is empty")
	}
	if info == "" {
		return nil, errors.New("cryptutil: info (domain-separation tag) is required")
	}
	key := make([]byte, keySize)
	r := hkdf.New(sha256.New, masterSecret, hkdfSalt, []byte(info))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm new: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals `plaintext` with a fresh random nonce. Returns the
// base64-encoded `nonce || ciphertext-with-tag` string suitable
// for direct DB storage.
//
// Empty plaintext returns empty string (callers can use empty-
// string as a "field unset" sentinel without round-tripping
// through the cipher). Non-empty plaintext always produces
// non-empty ciphertext.
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	out := make([]byte, 0, nonceSize+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt. Empty input returns empty plaintext
// (matching the Encrypt-of-empty contract). Returns an error on
// malformed input or authentication failure (wrong key, tampered
// ciphertext, truncated nonce).
//
// IsPlaintext can be used by callers that need to handle a
// migration window where some rows still hold pre-encryption
// plaintext. The function handles the most common case: input
// that doesn't start with valid base64 of nonce-plus-ciphertext.
func (c *Cipher) Decrypt(ciphertextB64 string) (string, error) {
	if ciphertextB64 == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, sealed := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("aead open: %w", err)
	}
	return string(plaintext), nil
}

// IsPlaintext reports whether the input is *probably* unencrypted
// data (vs a properly-formatted ciphertext from Encrypt). Used by
// the email-config service's startup migration to detect rows
// that haven't been encrypted yet (e.g., pre-Phase-9-revision
// deployments that stored the API key in cleartext).
//
// Heuristic: an Encrypt output is base64(nonce + sealed) which is
// AT LEAST `nonceSize + GCM_TAG_SIZE` = 28 raw bytes = ~40 base64
// chars. Anything that decodes-as-base64 but is shorter than the
// minimum, OR doesn't decode as base64 at all, is treated as
// plaintext. False-positive risk: a 40+ char base64-shaped string
// that happens to be plaintext. Acceptable for the migration use
// case because:
//   - Real plaintexts (SendGrid keys are like "SG.xxxx.yyyy" with
//     dots, which break base64) won't accidentally look like our
//     ciphertext format.
//   - The worst case is a one-time mis-classification that
//     manifests as a decrypt error on next read; operator notices,
//     re-saves the key.
func IsPlaintext(maybeCiphertext string) bool {
	if maybeCiphertext == "" {
		return false // empty is empty, neither plaintext nor ciphertext
	}
	raw, err := base64.StdEncoding.DecodeString(maybeCiphertext)
	if err != nil {
		return true // not base64 → can't be our ciphertext
	}
	// Minimum sealed length: nonce (12) + at least 1 byte plaintext
	// + GCM tag (16). Anything shorter is too small to be valid.
	const minSealedLen = nonceSize + 1 + 16
	return len(raw) < minSealedLen
}
