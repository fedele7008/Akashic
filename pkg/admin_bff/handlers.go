package admin_bff

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// adminTool is the wire shape for one row in the tools card grid.
// Hardcoded label + icon-key; only URL is operator-supplied so the
// FE renders a closed catalog of known tools rather than an
// arbitrary "any URL becomes a card" surface.
type adminTool struct {
	Key   string `json:"key"`   // stable id used by the FE for icon lookup
	Label string `json:"label"` // human-readable name shown on the card
	URL   string `json:"url"`   // operator-configured target URL
}

// handleAdminTools is GET /api/admin/tools — Phase 8c.5. Returns the
// configured external tool URLs (Grafana, Adminer, RedisInsight,
// Vault, phpLDAPadmin) as a list of {key, label, url}. Tools whose
// URL is empty in config are OMITTED from the response — the FE then
// renders only configured tools, which is the right behavior for
// production deployments that don't ship every tool.
//
// Session-gated to admin/root. The catalog is operator metadata, not
// secret per se, but it's also not for end users; same gate as the
// rest of /api/admin/*.
func (s *Server) handleAdminTools(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	// Define the catalog inline rather than loop-driven — small fixed
	// set, every entry has its own label, and adding a new tool is
	// also a FE change (icon, possibly translated label) so the
	// "shared list with FE" abstraction wouldn't pay off.
	all := []adminTool{
		{Key: "grafana", Label: "Grafana", URL: s.cfg.ToolsGrafanaURL},
		{Key: "adminer", Label: "Adminer", URL: s.cfg.ToolsAdminerURL},
		{Key: "redisinsight", Label: "RedisInsight", URL: s.cfg.ToolsRedisInsightURL},
		{Key: "vault", Label: "Vault", URL: s.cfg.ToolsVaultURL},
		{Key: "phpldapadmin", Label: "phpLDAPadmin", URL: s.cfg.ToolsPhpLDAPAdminURL},
	}
	out := make([]adminTool, 0, len(all))
	for _, t := range all {
		if strings.TrimSpace(t.URL) != "" {
			out = append(out, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"tools": out},
	})
}

// handleSetupStatus is GET /api/admin/setup-status. Pass-through to
// the control plane's aggregator (bootstrap done? portal registered?
// LDAP healthy?). Used by the React FE's <SetupStatusBanner> on every
// page render so the operator always sees outstanding setup steps
// without having to dig through logs.
//
// Session-gated to admin/root: the banner is operator UI, not a
// public health probe. Pre-bootstrap there's no session yet, so this
// returns 401 — but pre-bootstrap the FE shows the bootstrap form,
// not the banner-bearing dashboard, so that's fine.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	status, err := s.controlClient.SetupStatusGet(r.Context())
	if err != nil {
		s.writeControlError(w, err, "fetching setup status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    status,
	})
}

// handleBootstrapStatus is GET /api/bootstrap/status. Pass-through to
// the control plane. Used by the React FE on page load to decide
// which view to render (form vs. "already complete").
//
// This endpoint is reachable in BOTH bootstrap and normal modes -- it's
// the question being answered, not gated by the answer.
func (s *Server) handleBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	status, err := s.controlClient.BootstrapStatusGet(r.Context())
	if err != nil {
		s.writeControlError(w, err, "fetching bootstrap status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    status,
	})
}

// handleBootstrapCreateRoot is POST /api/bootstrap/create-root. The
// browser submits the form here; we forward to the control plane over
// mTLS. On any error path, we map control-plane error codes to a small
// browser-friendly set so the FE can render appropriate messages
// without parsing internal codes.
//
// CSRF is enforced by middleware (Step 4); rate limit too. By the time
// we reach this handler, the request is already authenticated and
// throttled.
func (s *Server) handleBootstrapCreateRoot(w http.ResponseWriter, r *http.Request) {
	var body CreateRootRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Could not parse request body. Please refresh and try again.")
		return
	}
	defer r.Body.Close()

	// Cheap up-front validation -- rejecting an obviously-empty submit
	// at the BFF saves a control-plane round-trip.
	if body.Token == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Bootstrap token is required.")
		return
	}
	if body.Username == "" || body.Email == "" || body.Password == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Username, email, and password are all required.")
		return
	}

	resp, err := s.controlClient.BootstrapCreateRoot(r.Context(), &body)
	if err != nil {
		s.writeControlError(w, err, "creating root user")
		return
	}

	// Success: the BFF re-shapes the server's user payload into the
	// shape the FE expects. Currently identical, but having the
	// translation layer here means future control-plane changes
	// don't necessarily break the FE contract.
	writeJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"data": map[string]any{
			"user": resp.User,
		},
	})
}

// requireAdminSession enforces the "logged-in admin/root" gate that
// every /api/clients/* handler shares. Returns true when the request
// passes; on failure it writes the appropriate error envelope and
// returns false (caller bails immediately).
//
// Three rejection codes the FE branches on:
//   NOT_AUTHENTICATED — no session cookie at all (re-render to landing)
//   SESSION_EXPIRED   — cookie present but no Redis row (clear + re-render)
//   INSUFFICIENT_ROLE — session exists but user_type isn't admin/root
//
// Splitting these out keeps the React shell responsive: a logged-out
// user gets the sign-in landing; an expired session clears the dead
// cookie before doing the same; an under-privileged user gets a
// permission error rather than being silently bounced to login.
func (s *Server) requireAdminSession(w http.ResponseWriter, r *http.Request) bool {
	sid := readCookie(r, sessionCookieName)
	if sid == "" {
		writeError(w, http.StatusUnauthorized, "NOT_AUTHENTICATED",
			"You must be signed in to manage OAuth clients.")
		return false
	}
	sess, err := s.sessions.Touch(r.Context(), sid)
	if err != nil {
		clearCookie(w, sessionCookieName, r)
		writeError(w, http.StatusUnauthorized, "SESSION_EXPIRED",
			"Your session has expired. Please sign in again.")
		return false
	}
	if sess.UserType != "admin" && sess.UserType != "root" {
		writeError(w, http.StatusForbidden, "INSUFFICIENT_ROLE",
			"Only admin or root users may manage OAuth clients.")
		return false
	}
	return true
}

// handleCreateClient is POST /api/clients. Session-gated to admin or
// root user types — registering OAuth clients is an operator action,
// not something the average end-user should reach via this endpoint.
//
// Forwards to the control plane's /clients (mTLS via the BFF's own
// client cert). On success, the plaintext client_secret returned by
// the control plane is passed through to the FE so it can render the
// "shown once" panel — same UX as Auth0/Okta dashboards.
//
// CSRF is enforced by middleware; rate limit too. By the time we
// reach this handler, the request is already authenticated AND
// throttled.
func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}

	var body CreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Could not parse request body.")
		return
	}
	defer r.Body.Close()

	// Cheap up-front validation — rejecting an obviously-empty submit
	// at the BFF saves a control-plane round-trip and gives a sharper
	// message than the generic VALIDATION_FAILED echoed from upstream.
	if body.Name == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED",
			"A client name is required.")
		return
	}
	if body.RedirectURIs == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED",
			"A redirect_uri is required.")
		return
	}
	if body.ClientType == "" {
		writeError(w, http.StatusBadRequest, "VALIDATION_FAILED",
			"Client type is required: WEB (server-side, gets a client_secret) or SPA (browser/native, PKCE-only).")
		return
	}

	resp, err := s.controlClient.ClientCreate(r.Context(), &body)
	if err != nil {
		s.writeControlError(w, err, "registering OAuth client")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"success": true,
		"data": map[string]any{
			"client":        resp.Client,
			"client_secret": resp.ClientSecret,
		},
	})
}

// handleListClients is GET /api/clients. Session-gated; proxies to
// the control plane's GET /clients which returns every registered
// row (built-in + tenant). The FE renders this as a table with
// per-row Delete / Rotate-Secret actions.
//
// Response envelope: `{success:true, data:{clients:[...]}}` —
// pass-through of the control-plane shape.
func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	resp, err := s.controlClient.ClientList(r.Context())
	if err != nil {
		s.writeControlError(w, err, "listing OAuth clients")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"clients": resp.Clients},
	})
}

// handleClientByID dispatches DELETE/POST on /api/clients/<id>[/<action>].
// Path parsing extracts the id (and optional `rotate-secret` action);
// the method then determines the operation. Session-gated as a single
// upfront check.
//
// Why a single dispatcher rather than two HandleFunc registrations:
// Go's http.ServeMux pattern routing for `/api/clients/` matches both
// `/api/clients/abc` and `/api/clients/abc/rotate-secret` — splitting
// would force two registrations + duplicate auth gates. One dispatcher,
// one auth check, branch on parsed action.
func (s *Server) handleClientByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	id, action := splitAdminClientPath(r.URL.Path)
	if id == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND",
			"No route for this path.")
		return
	}
	switch action {
	case "":
		if r.Method != http.MethodDelete {
			writeError(w, http.StatusMethodNotAllowed,
				"METHOD_NOT_ALLOWED", "Only DELETE is allowed on this path.")
			return
		}
		s.deleteClient(w, r, id)
	case "rotate-secret":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed,
				"METHOD_NOT_ALLOWED", "Only POST is allowed on rotate-secret.")
			return
		}
		s.rotateClientSecret(w, r, id)
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND",
			"No route for this path.")
	}
}

// splitAdminClientPath parses `/api/clients/<id>[/<action>]`. Returns
// empty id when the path doesn't match the expected shape (404 case).
func splitAdminClientPath(path string) (id, action string) {
	const prefix = "/api/clients/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 2)
	id = parts[0]
	if len(parts) == 2 {
		action = parts[1]
	}
	return id, action
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.controlClient.ClientDelete(r.Context(), id); err != nil {
		s.writeControlError(w, err, "deleting OAuth client")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"deleted": true},
	})
}

func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request, id string) {
	resp, err := s.controlClient.ClientRotateSecret(r.Context(), id)
	if err != nil {
		s.writeControlError(w, err, "rotating client secret")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data": map[string]any{
			"client_id":     resp.ClientID,
			"client_secret": resp.ClientSecret,
		},
	})
}

// writeControlError translates an upstream control-plane error into a
// browser-facing response. We deliberately re-map most server error
// codes to a smaller browser-friendly set; passing through internal
// codes verbatim leaks implementation detail and confuses end users.
//
// `context` is a short human phrase ("creating root user") that gets
// prepended to network-level errors so the operator sees what was
// being attempted when the error happened.
func (s *Server) writeControlError(w http.ResponseWriter, err error, context string) {
	var ctlErr *ControlError
	if errors.As(err, &ctlErr) {
		switch ctlErr.Code {
		case "INVALID_TOKEN":
			writeError(w, http.StatusUnauthorized, "INVALID_TOKEN",
				"The bootstrap token is invalid or expired. Get a fresh one from the server logs.")
		case "BOOTSTRAP_COMPLETE":
			// 410 Gone is the canonical status for "this endpoint
			// permanently won't accept submissions anymore". Browsers
			// don't render anything special for it, but it's the
			// semantically correct code.
			writeError(w, http.StatusGone, "BOOTSTRAP_COMPLETE",
				"Bootstrap is already complete. The form is no longer accepting submissions.")
		case "PASSWORD_POLICY_VIOLATION":
			// Pass through the specific rule (server side validates with
			// pkg/auth.PasswordPolicy).
			writeError(w, http.StatusBadRequest, "PASSWORD_POLICY_VIOLATION",
				ctlErr.Message)
		case "VALIDATION_FAILED":
			writeError(w, http.StatusBadRequest, "VALIDATION_FAILED",
				ctlErr.Message)
		case "RATE_LIMITED":
			// Pass through the retry-after info if present.
			details := ctlErr.Details
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"success": false,
				"error": map[string]any{
					"code":    "RATE_LIMITED",
					"message": "Too many attempts. Please wait and try again.",
					"details": details,
				},
			})
		case "MTLS_REQUIRED", "CLIENT_NOT_ALLOWED":
			// These should never reach the user under normal operation
			// -- they indicate the BFF's own cert is broken. Surface
			// generically and audit-log loudly in Step 4.
			writeError(w, http.StatusBadGateway, "BFF_AUTH_FAILED",
				"The admin UI's connection to the server is misconfigured. Contact the deployment operator.")
		case "CLIENT_NOT_FOUND":
			writeError(w, http.StatusNotFound, "CLIENT_NOT_FOUND",
				"No client with that id exists.")
		case "BUILTIN_IMMUTABLE":
			// Server-managed clients (akashic-admin) — operators
			// configure them via env, not via this UI. Reflecting
			// the server's message verbatim is fine here; it
			// already names the env var.
			writeError(w, http.StatusForbidden, "BUILTIN_IMMUTABLE",
				ctlErr.Message)
		case "PUBLIC_CLIENT_NO_SECRET":
			// SPA / public clients have no secret to rotate. The
			// FE should hide the rotate button for these rows;
			// this branch is the safety net for race conditions
			// where the UI sees a stale row.
			writeError(w, http.StatusBadRequest, "PUBLIC_CLIENT_NO_SECRET",
				"This is a public (SPA) client; PKCE replaces the shared secret on every authorization, so there is nothing to rotate.")
		case "BOOTSTRAP_INCOMPLETE":
			// Hit when an admin user has a session predating a DB
			// reset. The natural fix is to bootstrap again; surface
			// it clearly so the operator knows what to do.
			writeError(w, http.StatusConflict, "BOOTSTRAP_INCOMPLETE",
				"Bootstrap is not yet complete. Run `akashic-cli bootstrap create-root` first.")
		case "DB_NOT_READY":
			writeError(w, http.StatusServiceUnavailable, "DB_NOT_READY",
				"The akashic-server's database isn't fully wired yet. Retry shortly.")
		default:
			// Any other 4xx → 400; 5xx → 502.
			status := http.StatusBadGateway
			if ctlErr.HTTPStatus >= 400 && ctlErr.HTTPStatus < 500 {
				status = http.StatusBadRequest
			}
			writeError(w, status, "SERVER_ERROR",
				"Server error while "+context+". Please retry in a moment.")
		}
		return
	}

	// Network-level error (timeout, connection refused, TLS handshake
	// failure). Genuinely upstream issues; map to 502.
	writeError(w, http.StatusBadGateway, "UPSTREAM_UNREACHABLE",
		"Could not reach the Akashic server while "+context+". Please retry, or contact the deployment operator.")
}

// writeJSON writes a JSON-encoded value with the given status code.
// Sets Content-Type explicitly because Go's auto-detection sometimes
// guesses wrong on JSON-shaped bodies that lack the leading whitespace.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError is a thin wrapper for the {success:false, error:...}
// envelope format the FE expects.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"success": false,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// stringContains is a case-insensitive substring check; defined here
// for use in audit-related code (Step 4) without dragging in another
// package import.
func stringContains(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
