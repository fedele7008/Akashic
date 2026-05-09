package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

// Package note: all refresh-token logic that touches the database
// lives in `pkg/repository/refresh_token_repository.go`. This file
// is the value-object layer — generation, hashing, equality, and
// the TTL-resolution pure function. Keeping these here means the
// handler code in `pkg/server/auth` and the test suite both
// depend on the primitives without pulling in GORM.

// RefreshScopeOfflineAccess is the OIDC §11 scope that signals a
// client wants long-lived offline use. /token issues a refresh
// token alongside the access token only when this scope is in the
// granted set; without it, refresh tokens never enter the system.
const RefreshScopeOfflineAccess = "offline_access"

// refreshTokenEntropyBytes is the size of the raw random material
// behind a refresh token. 32 bytes = 256 bits of entropy, base64url-
// encoded to ~43 ASCII chars. Matches the size of authorization
// codes elsewhere in the codebase and exceeds the OAuth 2.1 §3.2.1
// recommendation of 128-bit entropy by a comfortable margin.
const refreshTokenEntropyBytes = 32

// MintRefreshTokenValue generates a fresh opaque refresh-token
// string and its SHA-256 hash. The plaintext is returned to the
// caller (which sends it to the OAuth client in the /token
// response); the hash is what's persisted.
//
// Failure mode: if crypto/rand fails (effectively never on a
// healthy system, but possible inside a sandbox or under
// catastrophic entropy starvation), returns ("", nil, err). The
// caller should treat as a 500 — minting a token without
// cryptographic randomness is worse than failing the request.
func MintRefreshTokenValue() (raw string, hash []byte, err error) {
	buf := make([]byte, refreshTokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	hash = HashRefreshToken(raw)
	return raw, hash, nil
}

// HashRefreshToken returns the SHA-256 hash of a presented refresh
// token value, suitable for the database lookup-by-hash pattern.
//
// SHA-256 (not bcrypt) is the right choice here: the source secret
// has 256 bits of entropy, so the slow-hash property bcrypt
// provides is unnecessary, and bcrypt's variable-cost nature would
// rule out the unique-index lookup we use for replay detection.
func HashRefreshToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// ConstantTimeHashEqual is a thin wrapper around
// subtle.ConstantTimeCompare for hash equality. The lookup itself
// is by indexed unique key (so no timing-leak on the hash bytes),
// but callers occasionally need to compare a re-derived hash
// against a stored one (e.g. integration tests). Wrapping subtle
// here keeps the test code from accidentally using `bytes.Equal`,
// which is fast-fail at the first differing byte.
func ConstantTimeHashEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// TokenTTLPolicy is the resolved (i.e. min(override, ceiling))
// effective TTL set for a particular client's tokens. Returned by
// ResolveTokenTTLs and consumed at /token mint time.
type TokenTTLPolicy struct {
	Access          time.Duration
	RefreshSliding  time.Duration
	RefreshAbsolute time.Duration
}

// TokenTTLInputs is the raw policy state needed to compute an
// effective TTL set. Kept as plain ints (seconds) so the function
// is portable across the model layer (which holds these as table
// columns) without dragging GORM into pkg/oauth.
//
// All four override fields are "optional" in the *int sense — nil
// means "no per-client override; inherit the ceiling." The
// resolution rule is: `effective = min(override, ceiling)`. If the
// override is greater than the ceiling, we use the ceiling — this
// is belt-and-braces with the policy.Service.UpdateClientOverrides
// validation that enforces the same invariant at write time.
type TokenTTLInputs struct {
	CeilingAccessSeconds          int
	CeilingRefreshSlidingSeconds  int
	CeilingRefreshAbsoluteSeconds int

	OverrideAccessSeconds          *int
	OverrideRefreshSlidingSeconds  *int
	OverrideRefreshAbsoluteSeconds *int
}

// ResolveTokenTTLs computes the effective per-mint TTL set from the
// tenant ceiling + per-client overrides. Pure function — no I/O.
//
// Used by /token at mint time (both for fresh auth-code exchanges
// and for refresh-token rotations). Takes the ceiling from the
// TenantPolicy singleton row and the override from the
// ClientService row; output is what `MintAccessToken` /
// repository.CreateRefreshToken should use.
func ResolveTokenTTLs(in TokenTTLInputs) TokenTTLPolicy {
	return TokenTTLPolicy{
		Access:          time.Duration(resolveSeconds(in.OverrideAccessSeconds, in.CeilingAccessSeconds)) * time.Second,
		RefreshSliding:  time.Duration(resolveSeconds(in.OverrideRefreshSlidingSeconds, in.CeilingRefreshSlidingSeconds)) * time.Second,
		RefreshAbsolute: time.Duration(resolveSeconds(in.OverrideRefreshAbsoluteSeconds, in.CeilingRefreshAbsoluteSeconds)) * time.Second,
	}
}

func resolveSeconds(override *int, ceiling int) int {
	if override == nil {
		return ceiling
	}
	if *override <= 0 {
		// Defensive: a zero or negative override is nonsense; fall
		// back to the ceiling. policy validation rejects these at
		// write time, but if a row got into this state somehow we
		// don't want to mint zero-TTL tokens.
		return ceiling
	}
	if *override > ceiling {
		return ceiling
	}
	return *override
}

// ─── Validation helpers (used at policy/client write time) ──────

// Per-field floors. Kept tight enough to prevent foot-guns
// (zero-TTL tokens) while still allowing aggressive testing
// configurations (30-second access tokens for refresh-flow demos).
const (
	MinAccessTokenTTLSeconds          = 30
	MinRefreshSlidingTTLSeconds       = 60
	// Absolute floor mirrors sliding — an absolute window below
	// the sliding TTL is meaningless (the sliding window would
	// extend past it on first use, which we'd then immediately
	// clamp).
	MinRefreshAbsoluteTTLSeconds = 60

	// Loose ceiling on operator-set ceilings themselves. 5-year
	// access tokens are a security antipattern; we cap the
	// CEILING (not just the per-client value) so even an operator
	// who pastes 999_999_999 into the admin UI gets a sensible
	// upper bound. 10 years for absolute, 1 year for sliding,
	// 24 hours for access.
	MaxAccessTokenTTLSeconds          = 24 * 60 * 60
	MaxRefreshSlidingTTLSeconds       = 365 * 24 * 60 * 60
	MaxRefreshAbsoluteTTLSeconds      = 10 * 365 * 24 * 60 * 60
)

// ValidateCeilings checks that a proposed TenantPolicy ceiling set
// is internally consistent and within the hard caps. Returns the
// first error found.
func ValidateCeilings(accessSec, slidingSec, absoluteSec int) error {
	if accessSec < MinAccessTokenTTLSeconds {
		return errors.New("access_token_ttl_seconds must be at least 30")
	}
	if accessSec > MaxAccessTokenTTLSeconds {
		return errors.New("access_token_ttl_seconds must be at most 86400 (24h)")
	}
	if slidingSec < MinRefreshSlidingTTLSeconds {
		return errors.New("refresh_token_sliding_ttl_seconds must be at least 60")
	}
	if slidingSec > MaxRefreshSlidingTTLSeconds {
		return errors.New("refresh_token_sliding_ttl_seconds must be at most one year")
	}
	if absoluteSec < MinRefreshAbsoluteTTLSeconds {
		return errors.New("refresh_token_absolute_ttl_seconds must be at least 60")
	}
	if absoluteSec > MaxRefreshAbsoluteTTLSeconds {
		return errors.New("refresh_token_absolute_ttl_seconds must be at most ten years")
	}
	if absoluteSec < slidingSec {
		return errors.New("refresh_token_absolute_ttl_seconds must be >= refresh_token_sliding_ttl_seconds")
	}
	return nil
}

// ValidateOverrideAgainstCeiling enforces the per-client override
// invariant at write time. Called by pkg/clientservice when an
// operator (or tenant developer) updates a client_services row.
// nil override is always allowed (means "inherit").
func ValidateOverrideAgainstCeiling(override *int, ceiling int, fieldName string) error {
	if override == nil {
		return nil
	}
	if *override <= 0 {
		return errors.New(fieldName + " override must be positive (or omitted to inherit the ceiling)")
	}
	// Re-use the ceiling-floor logic so a 5-second per-client
	// override is rejected even if the ceiling is 30 seconds.
	switch fieldName {
	case "access_token_ttl_seconds_override":
		if *override < MinAccessTokenTTLSeconds {
			return errors.New(fieldName + " must be at least 30 seconds")
		}
	case "refresh_token_sliding_ttl_seconds_override",
		"refresh_token_absolute_ttl_seconds_override":
		if *override < MinRefreshSlidingTTLSeconds {
			return errors.New(fieldName + " must be at least 60 seconds")
		}
	}
	if *override > ceiling {
		return errors.New(fieldName + " must be at most the tenant ceiling")
	}
	return nil
}
