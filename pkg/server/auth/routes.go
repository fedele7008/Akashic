package auth

import (
	"net/http"
)

// registerRoutes sets up the auth server routes
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// OAuth/OIDC discovery + JWKS (Phase 7 Step 3).
	// Reachable without authentication; cached at clients.
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)
}
