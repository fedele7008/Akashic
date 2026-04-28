package auth

import (
	"net/http"

	"akashic/akashic/pkg/middleware"
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

	// Phase 8b Step 4: bearer-exchange endpoint for first-party
	// widgets. CORS is enforced at the route level using the
	// operator-configured `AKASHIC_PORTAL_TENANT_ORIGINS` allowlist —
	// only origins on that list can read the response (and thus the
	// bearer token they need to call api.<tenant>).
	mux.Handle("/session/token",
		s.tenantCORS()(http.HandlerFunc(s.handleSessionToken)))

	// Static assets (the login page's stylesheet)
	mux.Handle("/static/", staticAssets())
}

// tenantCORS builds a CORS middleware seeded from the operator's
// configured tenant origins. Used on the bearer-exchange endpoint
// today; future widget-related endpoints reuse it.
func (s *Server) tenantCORS() middleware.Middleware {
	origins := splitTenantOrigins(s.config.GetConfig().Portal.TenantOrigins)
	return middleware.CORS(&middleware.CORSConfig{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Akashic-CSRF"},
		AllowCredentials: true,
		MaxAge:           600,
	})
}
