package admin_bff

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// ─── Phase 8c.2: user management ──────────────────────────────────
//
// Pure proxies to the control plane's /users + /users/<id>, with
// session-gating to admin/root and BFF-side self-protection
// (the control plane has no concept of "the calling user" — only
// the mTLS CN — so the BFF is the natural layer to enforce
// "you can't demote/delete yourself").
//
// The control plane runs the *cross-row* invariants (last-root) on
// its own; the BFF passes caller_user_id through so the control
// plane's domain-layer self-protection can also fire (defense in
// depth — we don't trust the BFF to be the only enforcement layer).

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	params := UserListParams{
		Limit:           limit,
		Offset:          offset,
		UserType:        q.Get("user_type"),
		IsDisabled:      parseTriBoolQuery(q.Get("is_disabled")),
		MissingIdentity: parseTriBoolQuery(q.Get("missing_identity")),
	}
	resp, err := s.controlClient.UserList(r.Context(), params)
	if err != nil {
		s.writeControlError(w, err, "listing users")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"users": resp.Users, "total": resp.Total},
	})
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusNotFound, "NOT_FOUND",
			"No route for this path.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.proxyGetUser(w, r, id)
	case http.MethodPatch:
		s.proxyPatchUser(w, r, id)
	case http.MethodDelete:
		s.proxyDeleteUser(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed,
			"METHOD_NOT_ALLOWED", "Only GET / PATCH / DELETE on /api/users/<id>.")
	}
}

func (s *Server) proxyGetUser(w http.ResponseWriter, r *http.Request, id string) {
	user, err := s.controlClient.UserGet(r.Context(), id)
	if err != nil {
		s.writeControlError(w, err, "fetching user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"user": user},
	})
}

func (s *Server) proxyPatchUser(w http.ResponseWriter, r *http.Request, id string) {
	var body UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Could not parse request body.")
		return
	}
	defer r.Body.Close()

	// Resolve the caller from session — overrides any caller_user_id
	// the FE may have set (don't trust client-supplied identity).
	callerID := s.callerUserIDFromSession(r)
	body.CallerUserID = callerID

	// BFF-side self-protection. Belt-and-braces alongside the control
	// plane's enforcement. Catches the case where someone calls the
	// BFF with a forged path; the BFF rejects before the control
	// plane ever sees it. Cheaper feedback for the FE.
	if callerID != "" && callerID == id {
		// Disabling self is allowed (recoverable by another admin);
		// only block role changes that would lock you out.
		if body.UserType != nil && *body.UserType != "" {
			writeError(w, http.StatusConflict, "SELF_DEMOTION",
				"You cannot change your own role from this surface. Ask another admin.")
			return
		}
	}

	user, err := s.controlClient.UserPatch(r.Context(), id, &body)
	if err != nil {
		s.writeControlError(w, err, "updating user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"user": user},
	})
}

func (s *Server) proxyDeleteUser(w http.ResponseWriter, r *http.Request, id string) {
	callerID := s.callerUserIDFromSession(r)
	if callerID != "" && callerID == id {
		writeError(w, http.StatusConflict, "SELF_DELETION",
			"You cannot delete your own account from this surface.")
		return
	}
	if err := s.controlClient.UserDelete(r.Context(), id, callerID); err != nil {
		s.writeControlError(w, err, "deleting user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"deleted": true},
	})
}

// callerUserIDFromSession extracts the operator's user_id from the
// admin-bff session. Returns "" if no session — the caller has
// already passed requireAdminSession at this point, so empty is
// only possible during a race where the session expired between
// the gate and here. Treated the same as "unknown" — the control
// plane will run its own invariants regardless.
func (s *Server) callerUserIDFromSession(r *http.Request) string {
	sid := readCookie(r, sessionCookieName)
	if sid == "" {
		return ""
	}
	sess, err := s.sessions.Touch(r.Context(), sid)
	if err != nil || sess == nil {
		return ""
	}
	return sess.UserID
}

// parseTriBoolQuery is the BFF-side mirror of the control plane's
// parseTriBool — kept here too so we can validate at the BFF
// boundary without an extra round-trip for invalid filter values.
func parseTriBoolQuery(s string) *bool {
	t, f := true, false
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return &t
	case "false", "0", "no":
		return &f
	}
	return nil
}

// ─── Phase 8c.3: server control panel ─────────────────────────────
//
// Six routes, all session-gated to admin/root, all proxied to the
// mTLS control plane via s.controlClient. The control plane already
// owns the state-machine logic (auth-server lifecycle, api-server
// lifecycle, graceful shutdown, config/TLS reload); these handlers
// are pure pass-through with the BFF's standard envelope.
//
// Why not a single dispatcher: each route maps to a different
// control-plane path and HTTP method, so a dispatcher would just
// be a switch statement with the route names duplicated. Six
// explicit handlers keep the routing table readable.

// handleAdminServerStatus is GET /api/admin/server/status — the
// snapshot the FE's Server page renders. Read-only, idempotent.
func (s *Server) handleAdminServerStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdminSession(w, r) {
		return
	}
	status, err := s.controlClient.StatusGet(r.Context())
	if err != nil {
		s.writeControlError(w, err, "fetching server status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    status,
	})
}

// proxyServerAction wraps the common "session-gate, post to
// control plane, write empty success or upstream error" flow used
// by every state-changing button on the Server page. `controlPath`
// is the control-plane relative URL; `actionName` is a short human
// phrase ("starting auth server") used in error messages.
func (s *Server) proxyServerAction(w http.ResponseWriter, r *http.Request, controlPath, actionName string) {
	if !s.requireAdminSession(w, r) {
		return
	}
	if err := s.controlClient.PostAction(r.Context(), controlPath); err != nil {
		s.writeControlError(w, err, actionName)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"ok": true},
	})
}

func (s *Server) handleAdminAuthStart(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/auth/start", "starting auth server")
}
func (s *Server) handleAdminAuthStop(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/auth/stop", "stopping auth server")
}
func (s *Server) handleAdminAuthRestart(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/auth/restart", "restarting auth server")
}

func (s *Server) handleAdminAPIStart(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/api/start", "starting API server")
}
func (s *Server) handleAdminAPIStop(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/api/stop", "stopping API server")
}
func (s *Server) handleAdminAPIRestart(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/api/restart", "restarting API server")
}

func (s *Server) handleAdminServerQuit(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/server/quit", "shutting down akashic")
}

func (s *Server) handleAdminConfigReload(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/config/reload", "reloading config")
}

func (s *Server) handleAdminTLSReload(w http.ResponseWriter, r *http.Request) {
	s.proxyServerAction(w, r, "/tls/reload", "reloading TLS certificates")
}

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
		switch r.Method {
		case http.MethodGet:
			s.getClient(w, r, id)
		case http.MethodPatch:
			s.patchClient(w, r, id)
		case http.MethodDelete:
			s.deleteClient(w, r, id)
		default:
			writeError(w, http.StatusMethodNotAllowed,
				"METHOD_NOT_ALLOWED",
				"Only GET, PATCH, DELETE on this path.")
		}
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

// getClient is GET /api/clients/<id> — Phase 8c.4. Read-only,
// returns the same wire shape the list endpoint emits so the FE
// can hydrate an edit form from a single response.
func (s *Server) getClient(w http.ResponseWriter, r *http.Request, id string) {
	client, err := s.controlClient.ClientGet(r.Context(), id)
	if err != nil {
		s.writeControlError(w, err, "fetching client")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"client": client},
	})
}

// patchClient is PATCH /api/clients/<id> — Phase 8c.4. Pure proxy
// to the control plane's PATCH; the operator-only fields
// (role_allowlist, require_pkce, is_tenant_portal) flow through
// when the FE form supplies them. Built-in rejection,
// VALIDATION_FAILED messages, etc. are mapped by the existing
// writeControlError table.
func (s *Server) patchClient(w http.ResponseWriter, r *http.Request, id string) {
	var body UpdateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Could not parse request body.")
		return
	}
	defer r.Body.Close()

	client, err := s.controlClient.ClientUpdate(r.Context(), id, &body)
	if err != nil {
		s.writeControlError(w, err, "updating client")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data":    map[string]any{"client": client},
	})
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
		// Phase 8c.3: state-machine errors from the auth/api lifecycle
		// endpoints. The control plane's message ("Auth server is already
		// running", "Cannot restart during transitional state", etc.) is
		// already user-facing-grade, so pass it through verbatim with the
		// upstream's 409 status preserved.
		case "AUTH_SERVER_ALREADY_RUNNING", "AUTH_SERVER_NOT_RUNNING",
			"AUTH_SERVER_STARTING", "AUTH_SERVER_STOPPING",
			"AUTH_SERVER_ERROR":
			writeError(w, http.StatusConflict, ctlErr.Code, ctlErr.Message)
		case "API_NOT_WIRED", "API_START_FAILED", "API_STOP_FAILED",
			"API_RESTART_FAILED":
			writeError(w, http.StatusConflict, ctlErr.Code, ctlErr.Message)
		case "CONFIG_RELOAD_FAILED", "TLS_RELOAD_FAILED":
			writeError(w, http.StatusInternalServerError, ctlErr.Code, ctlErr.Message)
		// Phase 8c.2: user-management invariant errors. Pass the
		// control-plane message through verbatim — it's already
		// user-facing-grade ("operation would leave the deployment
		// with no root users").
		case "USER_NOT_FOUND":
			writeError(w, http.StatusNotFound, ctlErr.Code, ctlErr.Message)
		case "LAST_ROOT", "SELF_DEMOTION", "SELF_DELETION":
			writeError(w, http.StatusConflict, ctlErr.Code, ctlErr.Message)
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
