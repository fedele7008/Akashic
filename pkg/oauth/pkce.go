package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// PKCE (RFC 7636) primitives. Akashic only supports the S256 method
// — "plain" is forbidden because it adds zero security over no PKCE
// at all (an attacker who can intercept the code can just as easily
// see the verifier in the same request).
//
// The flow:
//   client (admin-bff)                         auth-server
//     │ generate code_verifier (random)
//     │ compute code_challenge = SHA256(verifier)
//     │ /authorize?code_challenge=...&method=S256 ────────▶
//     │                                          stores challenge
//     │                                          alongside auth code
//     │ <──────── redirect with auth code ──────────────────
//     │ /token + code + code_verifier ────────────────────▶
//     │                                          verify
//     │                                          SHA256(verifier) ==
//     │                                          stored challenge

const (
	// PKCEMethodS256 is the only supported challenge method.
	// The plain method is rejected at /authorize (RFC 7636 §4.3
	// allows "S256" or "plain"; OAuth 2.1 deprecates "plain").
	PKCEMethodS256 = "S256"
)

// ErrPKCEMethodUnsupported is returned by /authorize when the client
// requests an unsupported challenge method.
var ErrPKCEMethodUnsupported = errors.New("only S256 challenge method is supported")

// ErrPKCEVerifierMismatch is returned by /token when SHA256(verifier)
// doesn't match the stored challenge.
var ErrPKCEVerifierMismatch = errors.New("PKCE code_verifier does not match stored challenge")

// VerifyChallenge checks that SHA256(verifier) base64url-encoded
// (no padding) equals the stored challenge. Constant-time compare
// to defeat timing attacks (probably overkill for a hash comparison
// of a one-shot value, but free).
//
// Caller is responsible for confirming method is S256 first; this
// function assumes S256 because we don't support anything else.
func VerifyChallenge(verifier, storedChallenge string) error {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(storedChallenge)) != 1 {
		return ErrPKCEVerifierMismatch
	}
	return nil
}

// ValidateChallenge ensures the supplied challenge string is well-
// formed (length, charset). RFC 7636 §4.2 says:
//   - length: 43 chars (the base64url of a 32-byte SHA256)
//   - charset: base64url alphabet (A-Z, a-z, 0-9, -, _)
// We're permissive on length (require 43-128, common range) and
// strict on charset.
func ValidateChallenge(challenge string) error {
	if len(challenge) < 43 || len(challenge) > 128 {
		return errors.New("code_challenge length out of range (43-128)")
	}
	for _, c := range challenge {
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return errors.New("code_challenge contains invalid character")
		}
	}
	return nil
}
