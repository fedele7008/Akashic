package auth

import (
	"net/http"
)

// registerRoutes sets up the auth server routes
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// OAuth/OIDC discovery + JWKS (Phase 7 Step 3).
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks.json", s.handleJWKS)

	// Login UI (Phase 7 Step 4)
	mux.HandleFunc("/login", s.handleLoginPage)
	mux.HandleFunc("/login/submit", s.handleLoginSubmit)
	mux.HandleFunc("/logout", s.handleLogout)

	// OAuth flow endpoints (Phase 7 Steps 5-7)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/userinfo", s.handleUserInfo)

	// Static assets (the login page's stylesheet)
	mux.Handle("/static/", staticAssets())
}
