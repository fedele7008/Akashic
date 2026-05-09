package api

import (
	"testing"

	"akashic/akashic/pkg/oauth"

	"github.com/golang-jwt/jwt/v5"
)

// The audience-based "first-party only" gate is the load-bearing
// defense that keeps third-party OAuth-flow tokens (which a user has
// legitimately granted to some app via /authorize) from reaching
// account-mutation endpoints like /users/me/uid, /users/me/password,
// or /clients/*.
//
// `requireFirstPartyBearer` is built on top of `requireBearer`, but
// the keystore-backed signature path is exercised by the existing
// /oauth/token <-> /userinfo round-trip in the auth-server tests.
// What's NEW with the first-party gate is the audience predicate, so
// that's what this test isolates: given a parsed AccessTokenClaims,
// does VerifyAudience return the right answer for each case the
// route table cares about?
func TestVerifyAudience_FirstPartyOnly(t *testing.T) {
	cases := []struct {
		name     string
		audience jwt.ClaimStrings
		// What we expect when the wrapper checks for SessionTokenAudience.
		// `true` means "endpoint accepts this token", `false` means 403.
		wantFirstParty bool
	}{
		{
			name:           "session-bearer minted via /session/token",
			audience:       jwt.ClaimStrings{oauth.SessionTokenAudience},
			wantFirstParty: true,
		},
		{
			name:           "third-party OAuth-flow token (client_id audience)",
			audience:       jwt.ClaimStrings{"some-third-party-client"},
			wantFirstParty: false,
		},
		{
			name:           "empty audience (malformed token)",
			audience:       jwt.ClaimStrings{},
			wantFirstParty: false,
		},
		{
			name:           "wrong literal that happens to start similarly",
			audience:       jwt.ClaimStrings{"akashic-session-other"},
			wantFirstParty: false,
		},
		{
			// Defense-in-depth: jwt.ClaimStrings is a slice. If a token
			// somehow carries multiple audiences and one of them is the
			// session marker, the bearer SHOULD pass — the user is
			// effectively authenticated through both routes. This shape
			// is unusual today (mint sets a single audience) but the
			// JWT spec allows it.
			name:           "multi-audience token containing session marker",
			audience:       jwt.ClaimStrings{"some-client", oauth.SessionTokenAudience},
			wantFirstParty: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := &oauth.AccessTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{Audience: tc.audience},
			}
			got := claims.VerifyAudience(oauth.SessionTokenAudience)
			if got != tc.wantFirstParty {
				t.Fatalf("VerifyAudience(%q) over %v = %v, want %v",
					oauth.SessionTokenAudience, tc.audience, got, tc.wantFirstParty)
			}
		})
	}
}

// Sanity check: SessionTokenAudience is a non-empty constant. A
// regression where someone defines it as "" would silently re-open
// the gate — every token has empty in its zero state, so an empty-
// string check would accept everything. Catching that here is a one-
// line guarantee.
func TestSessionTokenAudience_NonEmpty(t *testing.T) {
	if oauth.SessionTokenAudience == "" {
		t.Fatal("oauth.SessionTokenAudience must not be empty: an empty audience string would make the first-party gate accept every token")
	}
}
