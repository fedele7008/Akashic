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

	// OAuth flow endpoints (Phase 7 Steps 5-7).
	//
	// /authorize is a top-level browser navigation (the SPA / portal
	// does `location.href = ".../authorize?..."`), so there's no
	// cross-origin fetch and no CORS preflight to satisfy — the
	// browser is going TO this origin, not calling it from another.
	//
	// /token, /userinfo, and the well-known endpoints below are
	// different: SPA-style public clients call them programmatically
	// via fetch() from the tenant's origin (akashic.<tenant>) against
	// the auth server's origin (auth.<tenant>). That's a cross-origin
	// request, so the response MUST carry Access-Control-Allow-Origin
	// for the browser to hand the body back to the calling JS. We
	// gate the allowlist via the same operator-curated
	// AKASHIC_PORTAL_TENANT_ORIGINS list that `/session/token` uses
	// (origins permitted to embed Akashic = origins permitted to
	// drive Akashic OAuth flows).
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.Handle("/token",
		s.tenantCORS()(http.HandlerFunc(s.handleToken)))
	mux.Handle("/userinfo",
		s.tenantCORS()(http.HandlerFunc(s.handleUserInfo)))

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
