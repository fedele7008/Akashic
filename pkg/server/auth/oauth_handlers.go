package auth

import (
	"encoding/json"
	"net/http"

	"akashic/akashic/pkg/oauth"
)

// handleDiscovery serves GET /.well-known/openid-configuration.
//
// The response is built dynamically from server config so the
// `issuer` URL stays consistent with however the deployment is
// addressed (different production domains, different dev setups).
//
// Cached for 1 hour at clients per the OIDC discovery spec
// recommendation (the underlying values change rarely; clients can
// re-fetch on token verification failure if they suspect drift).
func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := s.config.GetConfig()
	issuer := cfg.OAuth.Issuer

	doc := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat",
			"name", "email", "preferred_username", "user_type",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(doc)
}

// handleJWKS serves GET /jwks.json. The response includes ALL keys
// currently in the keystore (active + verify-only) so clients with
// in-flight tokens signed by an older key can still verify them
// during the rotation overlap window.
//
// Returns 503 if the keystore is nil — happens briefly during akashic
// startup before SetOAuthKeyStore is called. Clients caching the
// JWKS will retry on next request; transient.
//
// Cached for 5 min at clients — short enough that rotated-in keys
// become usable promptly, long enough to amortize the request.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ks := s.OAuthKeyStore()
	if ks == nil {
		http.Error(w, "OAuth keystore not yet initialized", http.StatusServiceUnavailable)
		return
	}

	doc := oauth.JWKS(ks)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}
