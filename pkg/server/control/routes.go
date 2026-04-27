package control

import (
	"net/http"
)

// registerRoutes sets up the control server routes.
//
// Phase 8 architectural note: the control plane is **strictly admin /
// operator surface**. End-user-facing endpoints (registration, profile,
// password change, OAuth client CRUD) live on the dedicated API server
// (pkg/server/api/) where they're gated by OAuth bearer tokens rather
// than mTLS. The control plane only handles operations that are too
// powerful or too sensitive to expose via bearer tokens — bootstrap,
// server lifecycle, TLS rotation, and (Phase 8+) admin overrides.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)

	// Configuration
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/config/reload", s.handleConfigReload)

	// Auth server control (port 8080 — OIDC IdP)
	mux.HandleFunc("/auth/start", s.handleAuthStart)
	mux.HandleFunc("/auth/stop", s.handleAuthStop)
	mux.HandleFunc("/auth/restart", s.handleAuthRestart)

	// API server control (port 8082 — bearer-authenticated resource
	// server, Phase 8). Same lifecycle primitives as the auth server
	// — operators can stop/start/restart the API surface without
	// touching the OIDC surface, and vice versa.
	mux.HandleFunc("/api/start", s.handleAPIStart)
	mux.HandleFunc("/api/stop", s.handleAPIStop)
	mux.HandleFunc("/api/restart", s.handleAPIRestart)

	// Server control
	mux.HandleFunc("/server/quit", s.handleServerQuit)

	// TLS cert reload (Phase 4). Manual trigger for cert rotation when the
	// optional in-process watcher (AKASHIC_PKI_CERT_WATCHER_ENABLED=false)
	// is disabled, or as an override when it is.
	mux.HandleFunc("/tls/reload", s.handleTLSReload)

	// Bootstrap routes. Identity is enforced via mTLS client-cert CN.
	// /bootstrap/status is intentionally NOT gated by requireBootstrapMode
	// because it's the very thing answering "are you in bootstrap mode?";
	// token endpoints are CLI-only; /bootstrap/root is reachable by any
	// allowed client (CLI today, BFF later).
	//
	// Rate-limited endpoints (/bootstrap/root and token regenerate) wrap
	// the rate limiter OUTERMOST so denied requests don't even check the
	// bootstrap-mode flag — keeps DB load down under attacker probing.
	mux.HandleFunc("/bootstrap/status", s.handleBootstrapStatus)
	mux.HandleFunc("/bootstrap/token",
		requireClientIdentity("cli.akashic.local")(
			s.requireBootstrapMode(s.handleGetBootstrapToken)))
	mux.HandleFunc("/bootstrap/token/regenerate",
		requireClientIdentity("cli.akashic.local")(
			s.rateLimitBootstrap(s.bootstrapLimiter,
				s.requireBootstrapMode(s.handleRegenerateToken))))
	mux.HandleFunc("/bootstrap/root",
		requireClientIdentity("cli.akashic.local", "bff.akashic.local")(
			s.rateLimitBootstrap(s.bootstrapLimiter,
				s.requireBootstrapMode(s.handleCreateRootUser))))
}
