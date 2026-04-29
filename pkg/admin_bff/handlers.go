package admin_bff

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

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
	// Session gate: must be logged in as admin or root.
	sid := readCookie(r, sessionCookieName)
	if sid == "" {
		writeError(w, http.StatusUnauthorized, "NOT_AUTHENTICATED",
			"You must be signed in to register OAuth clients.")
		return
	}
	sess, err := s.sessions.Touch(r.Context(), sid)
	if err != nil {
		clearCookie(w, sessionCookieName, r)
		writeError(w, http.StatusUnauthorized, "SESSION_EXPIRED",
			"Your session has expired. Please sign in again.")
		return
	}
	if sess.UserType != "admin" && sess.UserType != "root" {
		// Not a hard 403 with details — don't leak the existence of
		// admin-only endpoints to non-privileged users. They got past
		// session check but their role doesn't qualify.
		writeError(w, http.StatusForbidden, "INSUFFICIENT_ROLE",
			"Only admin or root users may register OAuth clients.")
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
