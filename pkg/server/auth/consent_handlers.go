package auth

import (
	"net/http"
	"net/url"
	"strings"

	"akashic/akashic/pkg/consent"
	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// /consent — Phase 7.
//
// GET /consent?return_to=<authorize URL>
//   Renders an approve-or-deny screen for the OAuth client named in
//   the return_to URL. The user must be logged in (we re-use the
//   same authSessionCookie /login established) — anonymous arrivals
//   bounce back through /login first.
//
// POST /consent/submit
//   Body: csrf_token, return_to, decision={approve,deny}
//   On approve: writes/upserts the consent row, then 302s to
//                return_to. /authorize re-evaluates the consent
//                gate; the stored row passes the subset check and
//                the flow proceeds to code mint.
//   On deny:    302s to the client's redirect_uri (extracted from
//                return_to) with ?error=access_denied per RFC 6749
//                §4.1.2.1. State is preserved.

// handleConsentPage serves GET /consent.
func (s *Server) handleConsentPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bootstrap gate. /consent runs in the middle of an OAuth flow
	// that should already have hit the bootstrap-blocked /login
	// page first, but a stale tab could land here mid-bootstrap;
	// surface the same friendly page in that case.
	if s.bootstrapBlocked(r.Context()) {
		s.renderBootstrapPending(w)
		return
	}

	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if returnTo == "" {
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid request",
			"This page can only be reached from an OAuth /authorize call.")
		return
	}

	// Pull the OAuth context out of the return_to URL so we can
	// display the client name + scopes. Anything malformed surfaces
	// as a 400 — we don't render a half-empty consent screen.
	authParams, err := url.ParseRequestURI(returnTo)
	if err != nil {
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid request", "return_to is not a parseable URL.")
		return
	}
	q := authParams.Query()
	clientID := q.Get("client_id")
	scope := q.Get("scope")
	if scope == "" {
		scope = "openid"
	}
	if clientID == "" {
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid request", "return_to is missing client_id.")
		return
	}

	// Session check. /consent only makes sense for an authenticated
	// user — handleAuthorize would have redirected us through /login
	// first if not, but a stale tab could still arrive here without
	// a session. Bounce back to /login (which then bounces back here
	// after auth).
	s.mu.RLock()
	sessionStore := s.sessionStore
	db := s.db
	s.mu.RUnlock()
	if sessionStore == nil || db == nil {
		s.renderConsentError(w, http.StatusServiceUnavailable,
			"Server not ready",
			"The auth server is not yet fully initialized. Retry shortly.")
		return
	}
	sid := readCookie(r, authSessionCookie)
	if sid == "" {
		s.redirectToLogin(w, r)
		return
	}
	if _, err := sessionStore.Touch(r.Context(), sid); err != nil {
		s.redirectToLogin(w, r)
		return
	}

	// Look up the client for display. We don't redirect-with-error
	// here because we don't yet have a validated redirect_uri; if
	// the client lookup fails, render a server-side error.
	var client models.ClientService
	err = db.WithContext(r.Context()).Where("client_id = ?", clientID).First(&client).Error
	if err == gorm.ErrRecordNotFound {
		s.renderConsentError(w, http.StatusBadRequest,
			"Unknown client", "The client_id is not registered.")
		return
	}
	if err != nil {
		s.logger.App.Error("consent: client lookup", zap.Error(err))
		s.renderConsentError(w, http.StatusInternalServerError,
			"Server error", "Could not load client metadata.")
		return
	}

	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "consent.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":   csrf,
		"ReturnTo":    returnTo,
		"ClientName":  client.Name,
		"ClientID":    client.ClientID,
		"HomepageURL": client.HomepageURL,
		"Description": client.Description,
		"Scopes":      humanScopes(scope),
		"RawScope":    scope,
	})
}

// handleConsentSubmit serves POST /consent/submit.
func (s *Server) handleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.bootstrapBlocked(r.Context()) {
		s.renderBootstrapPending(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid form", "Could not parse the form. Please retry.")
		return
	}
	if !s.verifyLoginCSRF(r) {
		s.renderConsentError(w, http.StatusForbidden,
			"Form expired", "Please reload the consent page and try again.")
		return
	}

	returnTo := safeReturnTo(r.PostForm.Get("return_to"))
	decision := r.PostForm.Get("decision")
	if returnTo == "" {
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid request",
			"return_to is missing.")
		return
	}

	// Parse the original /authorize params out of return_to so we
	// know what the user is approving and where to bounce on deny.
	authParams, err := url.ParseRequestURI(returnTo)
	if err != nil {
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid request", "return_to is not a parseable URL.")
		return
	}
	q := authParams.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	state := q.Get("state")
	scope := q.Get("scope")
	if scope == "" {
		scope = "openid"
	}

	switch decision {
	case "deny":
		// RFC 6749 §4.1.2.1 — bounce back to the client with
		// error=access_denied. We trust redirect_uri here only as
		// far as ParseRequestURI; the original /authorize call
		// already validated it against the client's allowlist. If
		// the user ended up on /consent, that validation passed.
		if redirectURI == "" {
			s.renderConsentError(w, http.StatusBadRequest,
				"Invalid request",
				"return_to is missing redirect_uri; cannot deliver the deny response.")
			return
		}
		ru, err := url.Parse(redirectURI)
		if err != nil {
			s.renderConsentError(w, http.StatusBadRequest,
				"Invalid request",
				"redirect_uri in return_to is malformed.")
			return
		}
		rq := ru.Query()
		rq.Set("error", "access_denied")
		rq.Set("error_description", "The user declined to grant the requested scopes.")
		if state != "" {
			rq.Set("state", state)
		}
		ru.RawQuery = rq.Encode()
		s.logger.Security.Info("consent denied",
			zap.String("client_id", clientID))
		http.Redirect(w, r, ru.String(), http.StatusFound)
		return

	case "approve":
		// Resolve the user from session. Same shape as /authorize.
		s.mu.RLock()
		sessionStore := s.sessionStore
		consentRepo := s.consentRepo
		s.mu.RUnlock()
		if sessionStore == nil {
			s.renderConsentError(w, http.StatusServiceUnavailable,
				"Server not ready",
				"The auth server is not yet fully initialized.")
			return
		}
		sid := readCookie(r, authSessionCookie)
		if sid == "" {
			s.redirectToLogin(w, r)
			return
		}
		sess, err := sessionStore.Touch(r.Context(), sid)
		if err != nil {
			s.redirectToLogin(w, r)
			return
		}
		userID, err := uuid.Parse(sess.UserID)
		if err != nil {
			s.renderConsentError(w, http.StatusInternalServerError,
				"Server error",
				"Session is in an inconsistent state.")
			return
		}
		if consentRepo == nil {
			// Without a repo we can't record the grant — but we
			// also can't have GOTTEN here without /authorize's
			// consent gate firing, which itself requires the repo
			// to NOT be nil (otherwise it fail-opens). Treat as
			// transient and surface a sharp error.
			s.renderConsentError(w, http.StatusServiceUnavailable,
				"Consent storage not ready",
				"The auth server's consent repository isn't wired.")
			return
		}

		// Synchronous write before the redirect so a fast browser
		// re-arriving at /authorize finds the row already present.
		// Without this, a tight loop could see no consent row yet
		// and bounce back to /consent again.
		if _, err := consentRepo.Upsert(r.Context(), userID, clientID, consent.NormalizeScopes(scope)); err != nil {
			s.logger.App.Error("consent upsert failed",
				zap.String("client_id", clientID),
				zap.String("user_id", sess.UserID), zap.Error(err))
			s.renderConsentError(w, http.StatusInternalServerError,
				"Server error", "Could not record your consent. Please retry.")
			return
		}
		s.logger.Security.Info("consent granted",
			zap.String("client_id", clientID),
			zap.String("user_id", sess.UserID),
			zap.String("scope", scope))
		http.Redirect(w, r, returnTo, http.StatusFound)
		return

	default:
		s.renderConsentError(w, http.StatusBadRequest,
			"Invalid decision",
			"decision must be 'approve' or 'deny'.")
		return
	}
}

// renderConsentError serves the shared error template with consent-
// flow context. Distinct from handleAuthorize's renderAuthorizeError
// only in name and import scope; could be unified later.
func (s *Server) renderConsentError(w http.ResponseWriter, status int, title, msg string) {
	renderTemplate(w, "error.html.tmpl", status, map[string]any{
		"Title":   title,
		"Message": msg,
		"Detail":  "",
	})
}

// humanScopes turns a space-separated scope string into a slice of
// {Code, Description} pairs for the template. Unknown scopes are
// shown by their code with no description — better than hiding them.
//
// Centralised here so the table can grow without touching the
// template; in a future cleanup the descriptions could come from a
// per-deployment config so operators localise.
func humanScopes(s string) []scopeRow {
	desc := map[string]string{
		"openid":  "Sign you in (your account ID).",
		"profile": "Your basic profile (display name, username).",
		"email":   "Your email address.",
		"address": "Your address, when present in the directory.",
		"phone":   "Your phone number, when present in the directory.",
	}
	out := []scopeRow{}
	for _, tok := range strings.Fields(s) {
		out = append(out, scopeRow{Code: tok, Description: desc[tok]})
	}
	return out
}

type scopeRow struct {
	Code        string
	Description string
}
