package oauth

import "testing"

func TestParseScopes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"openid", []string{"openid"}},
		{"openid email", []string{"email", "openid"}},
		{"  openid    email  ", []string{"email", "openid"}},
		{"openid email openid", []string{"email", "openid"}},     // dedupe
		{"openid\temail", []string{"email", "openid"}},           // tab whitespace
		{"profile email openid", []string{"email", "openid", "profile"}}, // sorted
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := ParseScopes(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseScopes(%q) = %v (len %d), want %v (len %d)",
					tc.in, got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseScopes(%q)[%d] = %q, want %q",
						tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestScopeSet_Operations(t *testing.T) {
	openIDEmail := ParseScopeSet("openid email")
	openIDEmailProfile := ParseScopeSet("openid email profile")
	offlineOnly := ParseScopeSet("offline_access")

	// Subset
	if !openIDEmail.IsSubsetOf(openIDEmailProfile) {
		t.Fatal("openid email should be a subset of openid email profile")
	}
	if openIDEmailProfile.IsSubsetOf(openIDEmail) {
		t.Fatal("the superset should NOT be a subset of the smaller")
	}

	// Disjoint
	if !openIDEmail.IsDisjointFrom(offlineOnly) {
		t.Fatal("openid email should be disjoint from offline_access")
	}
	if openIDEmail.IsDisjointFrom(openIDEmailProfile) {
		t.Fatal("openid email shares tokens with openid email profile; not disjoint")
	}

	// String round-trip is sorted
	if openIDEmail.String() != "email openid" {
		t.Fatalf("String() not sorted: %q", openIDEmail.String())
	}
}

func TestUnionScopes(t *testing.T) {
	cases := []struct {
		a, b string
		want string
	}{
		{"", "", ""},
		{"openid", "", "openid"},
		{"", "openid", "openid"},
		{"openid email", "profile", "email openid profile"},
		{"openid email", "openid profile", "email openid profile"},   // dedup
		{"profile openid email", "email openid", "email openid profile"},
	}
	for _, tc := range cases {
		t.Run(tc.a+"|"+tc.b, func(t *testing.T) {
			got := UnionScopes(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("UnionScopes(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestIsSpecialScope(t *testing.T) {
	if !IsSpecialScope("offline_access") {
		t.Fatal("offline_access should be flagged special")
	}
	if IsSpecialScope("openid") {
		t.Fatal("openid is not special")
	}
	if IsSpecialScope("") {
		t.Fatal("empty string is not a special scope")
	}
}

func TestValidateScopeString(t *testing.T) {
	good := []string{"", "openid", "openid email profile", "custom:scope/path", "akashic.read"}
	for _, s := range good {
		if err := ValidateScopeString(s); err != nil {
			t.Errorf("ValidateScopeString(%q) unexpected err: %v", s, err)
		}
	}
	// Bad: backslash and double-quote are forbidden by RFC 6749 §3.3
	bad := []string{`bad"scope`, `bad\scope`}
	for _, s := range bad {
		if err := ValidateScopeString(s); err == nil {
			t.Errorf("ValidateScopeString(%q) should have rejected", s)
		}
	}
}

func TestValidateClientScopeSplit(t *testing.T) {
	cases := []struct {
		name     string
		required string
		optional string
		ceiling  string
		wantErr  bool
	}{
		{"both within ceiling, disjoint", "openid", "email profile", "openid email profile", false},
		{"required outside ceiling", "openid wallet", "email", "openid email", true},
		{"optional outside ceiling", "openid", "email wallet", "openid email", true},
		{"required overlaps optional", "openid email", "email profile", "openid email profile", true},
		{"empty required and optional", "", "", "openid email", false},
		{"only required", "openid", "", "openid email", false},
		{"only optional", "", "email", "openid email", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClientScopeSplit(tc.required, tc.optional, tc.ceiling)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateClientScopeSplit(%q, %q, %q) err=%v wantErr=%v",
					tc.required, tc.optional, tc.ceiling, err, tc.wantErr)
			}
		})
	}
}

func TestEffectiveRequiredScopes(t *testing.T) {
	// Legacy row: empty required, populated allowed → fall back
	if got := EffectiveRequiredScopes("", "openid email"); got != "openid email" {
		t.Fatalf("legacy fallback: %q", got)
	}
	// Phase-A row: required populated, allowed populated → required wins
	if got := EffectiveRequiredScopes("openid", "openid email profile"); got != "openid" {
		t.Fatalf("phase-A: %q", got)
	}
	// Edge: both empty → empty (a fresh client with no scopes yet)
	if got := EffectiveRequiredScopes("", ""); got != "" {
		t.Fatalf("both empty: %q", got)
	}
}
