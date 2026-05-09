package oauth

import (
	"strings"
	"testing"
	"time"
)

func TestMintRefreshTokenValue_Uniqueness(t *testing.T) {
	// Generate enough tokens to make a collision astronomically
	// improbable — two 256-bit randoms colliding within 1000 trials
	// would mean the RNG is broken. This is a smoke test, not a
	// statistical proof.
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		raw, hash, err := MintRefreshTokenValue()
		if err != nil {
			t.Fatalf("MintRefreshTokenValue() iter %d: %v", i, err)
		}
		if raw == "" {
			t.Fatalf("MintRefreshTokenValue() iter %d: empty raw", i)
		}
		if len(hash) != 32 {
			t.Fatalf("MintRefreshTokenValue() iter %d: hash len = %d, want 32", i, len(hash))
		}
		if _, dup := seen[raw]; dup {
			t.Fatalf("MintRefreshTokenValue() iter %d: collision on %q", i, raw)
		}
		seen[raw] = struct{}{}
	}
}

func TestHashRefreshToken_Deterministic(t *testing.T) {
	const raw = "kjsdfh-some-random-test-string"
	first := HashRefreshToken(raw)
	second := HashRefreshToken(raw)
	if !ConstantTimeHashEqual(first, second) {
		t.Fatal("HashRefreshToken is not deterministic for the same input")
	}
	other := HashRefreshToken(raw + "x")
	if ConstantTimeHashEqual(first, other) {
		t.Fatal("HashRefreshToken returned same hash for different inputs")
	}
}

// MintRefreshTokenValue must base64url-encode (no `+`, `/`, or `=`
// — these would be ambiguous in a URL or HTTP form context).
func TestMintRefreshTokenValue_URLSafeEncoding(t *testing.T) {
	for i := 0; i < 50; i++ {
		raw, _, err := MintRefreshTokenValue()
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if strings.ContainsAny(raw, "+/=") {
			t.Fatalf("iter %d: token %q contains URL-unsafe characters", i, raw)
		}
	}
}

func TestResolveTokenTTLs(t *testing.T) {
	intp := func(v int) *int { return &v }

	cases := []struct {
		name string
		in   TokenTTLInputs
		want TokenTTLPolicy
	}{
		{
			name: "all defaults — no overrides, ceilings used",
			in: TokenTTLInputs{
				CeilingAccessSeconds:          900,
				CeilingRefreshSlidingSeconds:  2592000,
				CeilingRefreshAbsoluteSeconds: 7776000,
			},
			want: TokenTTLPolicy{
				Access:          900 * time.Second,
				RefreshSliding:  2592000 * time.Second,
				RefreshAbsolute: 7776000 * time.Second,
			},
		},
		{
			name: "all overrides below ceiling — overrides win",
			in: TokenTTLInputs{
				CeilingAccessSeconds:           900,
				CeilingRefreshSlidingSeconds:   2592000,
				CeilingRefreshAbsoluteSeconds:  7776000,
				OverrideAccessSeconds:          intp(30),
				OverrideRefreshSlidingSeconds:  intp(120),
				OverrideRefreshAbsoluteSeconds: intp(600),
			},
			want: TokenTTLPolicy{
				Access:          30 * time.Second,
				RefreshSliding:  120 * time.Second,
				RefreshAbsolute: 600 * time.Second,
			},
		},
		{
			name: "override above ceiling — clamped to ceiling",
			in: TokenTTLInputs{
				CeilingAccessSeconds:          900,
				OverrideAccessSeconds:         intp(99999),
				CeilingRefreshSlidingSeconds:  120,
				OverrideRefreshSlidingSeconds: intp(99999),
				CeilingRefreshAbsoluteSeconds: 600,
			},
			want: TokenTTLPolicy{
				Access:          900 * time.Second,
				RefreshSliding:  120 * time.Second,
				RefreshAbsolute: 600 * time.Second,
			},
		},
		{
			name: "zero/negative override — defensively falls back to ceiling",
			in: TokenTTLInputs{
				CeilingAccessSeconds:           900,
				OverrideAccessSeconds:          intp(0),
				CeilingRefreshSlidingSeconds:   2592000,
				OverrideRefreshSlidingSeconds:  intp(-1),
				CeilingRefreshAbsoluteSeconds:  7776000,
				OverrideRefreshAbsoluteSeconds: intp(0),
			},
			want: TokenTTLPolicy{
				Access:          900 * time.Second,
				RefreshSliding:  2592000 * time.Second,
				RefreshAbsolute: 7776000 * time.Second,
			},
		},
		{
			name: "mixed — only access overridden",
			in: TokenTTLInputs{
				CeilingAccessSeconds:          900,
				CeilingRefreshSlidingSeconds:  2592000,
				CeilingRefreshAbsoluteSeconds: 7776000,
				OverrideAccessSeconds:         intp(60),
			},
			want: TokenTTLPolicy{
				Access:          60 * time.Second,
				RefreshSliding:  2592000 * time.Second,
				RefreshAbsolute: 7776000 * time.Second,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveTokenTTLs(tc.in)
			if got != tc.want {
				t.Fatalf("ResolveTokenTTLs(...) = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestValidateCeilings(t *testing.T) {
	cases := []struct {
		name    string
		access  int
		sliding int
		abs     int
		wantErr bool
	}{
		{"healthy defaults", 900, 2592000, 7776000, false},
		{"access below floor", 5, 2592000, 7776000, true},
		{"sliding below floor", 900, 30, 7776000, true},
		{"absolute below sliding", 900, 600, 300, true},
		{"absolute below sliding (equal is ok)", 900, 300, 300, false},
		{"access too high", 99999999, 2592000, 7776000, true},
		{"access at the day cap is ok", 24 * 60 * 60, 2592000, 7776000, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCeilings(tc.access, tc.sliding, tc.abs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateCeilings(%d,%d,%d) err = %v, wantErr=%v",
					tc.access, tc.sliding, tc.abs, err, tc.wantErr)
			}
		})
	}
}

func TestValidateOverrideAgainstCeiling(t *testing.T) {
	intp := func(v int) *int { return &v }

	cases := []struct {
		name     string
		override *int
		ceiling  int
		field    string
		wantErr  bool
	}{
		{"nil override always allowed", nil, 900, "access_token_ttl_seconds_override", false},
		{"override below ceiling", intp(60), 900, "access_token_ttl_seconds_override", false},
		{"override at ceiling", intp(900), 900, "access_token_ttl_seconds_override", false},
		{"override above ceiling", intp(901), 900, "access_token_ttl_seconds_override", true},
		{"zero override", intp(0), 900, "access_token_ttl_seconds_override", true},
		{"negative override", intp(-1), 900, "access_token_ttl_seconds_override", true},
		{"access override below 30s floor", intp(10), 900, "access_token_ttl_seconds_override", true},
		{"sliding override below 60s floor", intp(30), 900, "refresh_token_sliding_ttl_seconds_override", true},
		{"absolute override below 60s floor", intp(30), 900, "refresh_token_absolute_ttl_seconds_override", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateOverrideAgainstCeiling(tc.override, tc.ceiling, tc.field)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateOverrideAgainstCeiling(%v, %d, %q) err = %v, wantErr=%v",
					tc.override, tc.ceiling, tc.field, err, tc.wantErr)
			}
		})
	}
}
