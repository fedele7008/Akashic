package control

import (
	"net/http"

	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
)

// registerRoutes sets up the control server routes
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)

	// Configuration
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/config/reload", s.handleConfigReload)

	// Auth server control
	mux.HandleFunc("/auth/start", s.handleAuthStart)
	mux.HandleFunc("/auth/stop", s.handleAuthStop)
	mux.HandleFunc("/auth/restart", s.handleAuthRestart)

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

	// ─── Phase 8: user-management routes ───────────────────────────
	// Gated by mTLS — only callers presenting a portal-client cert
	// (CN portal.akashic.local) reach these handlers. The portal
	// also passes an X-Akashic-On-Behalf-Of header to identify the
	// end user; per-user handlers extract it via requireOnBehalfOf.
	const portalCN = "portal.akashic.local"
	const adminBffCN = "bff.akashic.local"

	// Public-ish — no on-behalf-of header (no user yet)
	mux.HandleFunc("/users/register",
		requireClientIdentity(portalCN)(
			s.requireUserDeps(s.handleRegisterUser)))

	// Stub: returns operator-configured "contact admin" info.
	// Phase 9 replaces with real token-based reset.
	mux.HandleFunc("/users/forgot-password-help",
		requireClientIdentity(portalCN)(
			s.handleForgotPasswordHelp))

	// Per-user — require X-Akashic-On-Behalf-Of header
	mux.HandleFunc("/users/me",
		requireClientIdentity(portalCN, adminBffCN)(
			s.requireUserDeps(requireOnBehalfOf(func(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
				switch r.Method {
				case http.MethodGet:
					s.handleGetMe(w, r, uid)
				case http.MethodPatch:
					s.handlePatchMe(w, r, uid)
				default:
					response.WriteJSON(w, http.StatusMethodNotAllowed,
						response.Fail(response.ErrMethodNotAllowed,
							"only GET and PATCH are allowed", nil))
				}
			}))))

	mux.HandleFunc("/users/me/password",
		requireClientIdentity(portalCN, adminBffCN)(
			s.requireUserDeps(requireOnBehalfOf(s.handleChangePassword))))

	// ─── Phase 8: OAuth-client management routes ───────────────────
	// Same gating model. The /clients/ prefix dispatches into one
	// handler that parses path-suffixes — keeps us using plain
	// ServeMux (no router dependency) at the cost of slightly less
	// pretty routing logic.
	mux.HandleFunc("/clients/mine",
		requireClientIdentity(portalCN, adminBffCN)(
			s.requireUserDeps(requireOnBehalfOf(s.handleListMyClients))))
	mux.HandleFunc("/clients",
		requireClientIdentity(portalCN, adminBffCN)(
			s.requireUserDeps(requireOnBehalfOf(s.handleCreateClient))))
	mux.HandleFunc("/clients/",
		requireClientIdentity(portalCN, adminBffCN)(
			s.requireUserDeps(requireOnBehalfOf(s.handleClientByID))))
}
