package auth

import "testing"

// isScopeSubset is the predicate that enforces the OAuth 2.1 §6.1
// rule: a refresh-token exchange may NARROW the requested scope but
// not WIDEN it. A bug here would let an attacker who owned a
// narrowly-scoped token escalate to full grant on rotation.
func TestIsScopeSubset(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		granted   string
		want      bool
	}{
		{"empty requested → vacuously true", "", "openid email", true},
		{"requested == granted", "openid email", "openid email", true},
		{"requested ⊂ granted", "openid", "openid email profile", true},
		{"single missing token → false", "openid wallet:read", "openid email", false},
		{"superset (extra token) → false", "openid email profile", "openid email", false},
		{"order-insensitive subset", "email openid", "openid email profile", true},
		{"whitespace-tolerant", "  openid    email  ", "openid email profile", true},
		{"granted empty, requested non-empty → false", "openid", "", false},
		{"both empty → true (vacuous)", "", "", true},
		{"duplicate tokens in requested don't break the check",
			"openid openid email", "openid email profile", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isScopeSubset(tc.requested, tc.granted); got != tc.want {
				t.Fatalf("isScopeSubset(%q, %q) = %v, want %v",
					tc.requested, tc.granted, got, tc.want)
			}
		})
	}
}
