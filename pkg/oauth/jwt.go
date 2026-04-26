package oauth

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// rawURLEncoding is base64url without padding — the encoding mandated
// by JWS / JWE / JWK (RFC 7515 §2). Used in JWKS public-key encoding
// and (elsewhere) in PKCE code_challenge computation.
var rawURLEncoding = base64.RawURLEncoding

// AccessTokenClaims is the JWT-claim shape for OAuth access tokens.
//
// Fields beyond the standard set:
//   - Scope (space-separated, per RFC 8693 §4.2)
//   - UserType (Akashic-specific; admin BFF uses this for role checks)
//
// The `aud` claim is the client_id the token was minted for; verifiers
// MUST check this matches their expected audience to prevent
// cross-client token replay.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
	Scope    string `json:"scope"`
	UserType string `json:"user_type,omitempty"`
}

// IDTokenClaims adds the OIDC profile/email claims on top of the
// access-token base. Optional claims are populated only when the
// matching scope was granted (caller's responsibility).
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce             string `json:"nonce,omitempty"`
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	UserType          string `json:"user_type,omitempty"`
}

// MintInput is the per-token data passed to MintAccessToken /
// MintIDToken. Common fields up here so we don't repeat ourselves.
type MintInput struct {
	Issuer    string        // iss claim — base URL of the auth server
	Subject   string        // sub claim — user's UUID
	Audience  string        // aud claim — client_id
	IssuedAt  time.Time     // iat (defaults to now if zero)
	ExpiresIn time.Duration // exp = IssuedAt + ExpiresIn
}

// MintAccessToken signs an access-token JWT with the keystore's active
// signing key. Returns the compact-serialized token string.
//
// On any error (no active key, signing failure), the function returns
// an empty string + non-nil error; callers should treat as 500.
func MintAccessToken(ks *KeyStore, in MintInput, scope, userType string) (string, error) {
	active, err := ks.Active()
	if err != nil {
		return "", err
	}
	if in.IssuedAt.IsZero() {
		in.IssuedAt = time.Now().UTC()
	}
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    in.Issuer,
			Subject:   in.Subject,
			Audience:  jwt.ClaimStrings{in.Audience},
			IssuedAt:  jwt.NewNumericDate(in.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(in.IssuedAt.Add(in.ExpiresIn)),
		},
		Scope:    scope,
		UserType: userType,
	}
	return signWithKey(active, claims)
}

// IDTokenInput is the user-profile data needed to mint an ID token.
// Caller fills only the fields whose scopes were granted; empty
// strings get omitted from the resulting token via omitempty tags.
type IDTokenInput struct {
	MintInput
	Nonce             string
	Name              string
	Email             string
	PreferredUsername string
	UserType          string
}

// MintIDToken signs an ID-token JWT (OIDC) with the active key.
// Caller is responsible for honoring scope-based field omission;
// passing only the fields the granted scopes permit.
func MintIDToken(ks *KeyStore, in IDTokenInput) (string, error) {
	active, err := ks.Active()
	if err != nil {
		return "", err
	}
	if in.IssuedAt.IsZero() {
		in.IssuedAt = time.Now().UTC()
	}
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    in.Issuer,
			Subject:   in.Subject,
			Audience:  jwt.ClaimStrings{in.Audience},
			IssuedAt:  jwt.NewNumericDate(in.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(in.IssuedAt.Add(in.ExpiresIn)),
		},
		Nonce:             in.Nonce,
		Name:              in.Name,
		Email:             in.Email,
		PreferredUsername: in.PreferredUsername,
		UserType:          in.UserType,
	}
	return signWithKey(active, claims)
}

// signWithKey is the shared sign path. Sets the kid header so verifiers
// know which key from /jwks.json to use.
func signWithKey(key *SigningKey, claims jwt.Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = key.KID
	signed, err := tok.SignedString(key.Private())
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

// VerifyAccessToken parses and verifies an access-token JWT using the
// keystore. Validates signature, expiry, and audience.
//
// expectedAudience is the caller's own client_id; verification fails
// if the token's `aud` claim doesn't match. Pass empty string to skip
// audience check (e.g., for /userinfo where the caller doesn't know
// which client to expect).
func VerifyAccessToken(ks *KeyStore, tokenStr, expectedAudience string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, keyFunc(ks),
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("token invalid")
	}
	if expectedAudience != "" {
		if !claims.VerifyAudience(expectedAudience) {
			return nil, fmt.Errorf("audience mismatch (token aud=%v, expected %q)",
				claims.Audience, expectedAudience)
		}
	}
	return claims, nil
}

// VerifyAudience is a small helper because jwt.RegisteredClaims's
// VerifyAudience method was removed in v5 in favor of validator
// options. We add it back for clarity at call sites.
func (c *AccessTokenClaims) VerifyAudience(expected string) bool {
	for _, a := range c.Audience {
		if a == expected {
			return true
		}
	}
	return false
}

// keyFunc returns a jwt.Keyfunc that looks up the kid header in the
// keystore. Reject tokens without a kid (we never sign without one)
// and tokens signed by a key the store doesn't know about.
func keyFunc(ks *KeyStore) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kidIface, ok := t.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}
		kid, ok := kidIface.(string)
		if !ok {
			return nil, fmt.Errorf("token kid header is not a string")
		}
		key := ks.ByKID(kid)
		if key == nil {
			return nil, fmt.Errorf("unknown kid %q (key may have been rotated out)", kid)
		}
		return key.Public(), nil
	}
}

// JWKS produces the /jwks.json response body. Includes every key in
// the store (active + verify-only), formatted per RFC 7517.
//
// Verify-only keys (RotatedOutAt != nil) stay in the JWKS until they
// can no longer have minted an unexpired token. For Phase 7 we don't
// auto-age (operators delete the file when ready); auto-aging is on
// the Phase 8+ list.
func JWKS(ks *KeyStore) map[string]any {
	keys := []map[string]any{}
	for _, k := range ks.All() {
		keys = append(keys, jwkFromRSA(k.KID, k.public))
	}
	return map[string]any{"keys": keys}
}

// jwkFromRSA builds the JWK representation of one RSA public key.
// "n" and "e" are base64url-encoded big-endian integers per RFC 7517.
func jwkFromRSA(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64URLBigInt(pub.N.Bytes()),
		"e":   base64URLBigInt(rsaExponentBytes(pub.E)),
	}
}

// rsaExponentBytes returns the minimum-length big-endian byte
// representation of an RSA public exponent. Standard exponent is 65537
// (0x010001), so this is usually 3 bytes.
func rsaExponentBytes(e int) []byte {
	bytes := []byte{}
	for e > 0 {
		bytes = append([]byte{byte(e & 0xff)}, bytes...)
		e >>= 8
	}
	if len(bytes) == 0 {
		return []byte{0}
	}
	return bytes
}

func base64URLBigInt(b []byte) string {
	// Strip leading zeros (RFC 7517 §3 says the integer must not have
	// leading zeros)
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return base64URLNoPadding(b)
}

// base64URLNoPadding wraps stdlib's base64.RawURLEncoding for clarity.
func base64URLNoPadding(b []byte) string {
	return rawURLEncoding.EncodeToString(b)
}
