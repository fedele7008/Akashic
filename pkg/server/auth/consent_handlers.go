package auth

import (
	"net/http"
	"net/url"
	"strings"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"

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

	// Phase C: split the requested scope set into required (locked
	// in the consent UI) and optional (user-toggleable). The client
	// row's RequiredScopes is the authority for the split. Legacy
	// rows (empty RequiredScopes) fall back to "everything in
	// AllowedScopes is required" for backward compat — same fallback
	// `/authorize` and `oauth.EffectiveRequiredScopes` use.
	effRequired := oauth.EffectiveRequiredScopes(client.RequiredScopes, client.AllowedScopes)
	requestedSet := oauth.ParseScopeSet(scope)
	requiredSet := oauth.ParseScopeSet(effRequired)
	optionalSet := oauth.ParseScopeSet(client.OptionalScopes)

	requiredRows := []scopeRow{}
	optionalRows := []scopeRow{}
	for _, t := range requestedSet.Tokens() {
		row := scopeRow{Code: t, Description: humanScopeDescription(t)}
		if requiredSet.Contains(t) {
			requiredRows = append(requiredRows, row)
		} else if optionalSet.Contains(t) {
			optionalRows = append(optionalRows, row)
		} else {
			// Scope is requested AND in client.AllowedScopes but
			// neither required nor optional. Shouldn't happen given
			// the AllowedScopes invariant (= union), but defensively
			// treat as optional so the user can opt in or not.
			optionalRows = append(optionalRows, row)
		}
	}

	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "consent.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":      csrf,
		"ReturnTo":       returnTo,
		"ClientName":     client.Name,
		"ClientID":       client.ClientID,
		"HomepageURL":    client.HomepageURL,
		"Description":    client.Description,
		"RequiredScopes": requiredRows,
		"OptionalScopes": optionalRows,
		"RawScope":       scope,
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
		db := s.db
		s.mu.RUnlock()
		if sessionStore == nil || db == nil {
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

		// Phase C: granted scope = required ∪ user-checked optionals.
		// Required scopes are non-toggleable in the form so they
		// always come back as part of the granted set. User-toggled
		// optionals come in as `optional_scope` form values (one per
		// checked checkbox). Anything outside the original requested
		// set is ignored (defensive — the form shouldn't produce it).
		var client models.ClientService
		if err := db.WithContext(r.Context()).
			Where("client_id = ?", clientID).First(&client).Error; err != nil {
			s.logger.App.Error("consent submit: client lookup", zap.Error(err))
			s.renderConsentError(w, http.StatusInternalServerError,
				"Server error", "Could not load client metadata.")
			return
		}
		effRequired := oauth.EffectiveRequiredScopes(client.RequiredScopes, client.AllowedScopes)
		requestedSet := oauth.ParseScopeSet(scope)
		requiredSet := oauth.ParseScopeSet(effRequired)
		grantedTokens := []string{}
		for _, t := range requiredSet.Tokens() {
			if requestedSet.Contains(t) {
				grantedTokens = append(grantedTokens, t)
			}
		}
		// User's checked optionals — only include those that are in
		// the client's optional set AND in the request.
		optionalSet := oauth.ParseScopeSet(client.OptionalScopes)
		seen := map[string]bool{}
		for _, t := range grantedTokens {
			seen[t] = true
		}
		for _, picked := range r.PostForm["optional_scope"] {
			t := strings.TrimSpace(picked)
			if t == "" || seen[t] {
				continue
			}
			if optionalSet.Contains(t) && requestedSet.Contains(t) {
				grantedTokens = append(grantedTokens, t)
				seen[t] = true
			}
		}
		grantedScope := oauth.ParseScopeSet(strings.Join(grantedTokens, " ")).String()

		// Synchronous write before the redirect so a fast browser
		// re-arriving at /authorize finds the row already present.
		if _, err := consentRepo.Upsert(r.Context(), userID, clientID, grantedScope); err != nil {
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
			zap.String("requested_scope", scope),
			zap.String("granted_scope", grantedScope))

		// Phase C: rewrite the return_to URL's `scope` parameter to
		// reflect the user's granted set. /authorize will re-evaluate
		// consent against this narrower scope, find the upserted row
		// covers it, and mint a code with that scope. Without this
		// rewrite, /authorize would see the original (pre-narrow)
		// scope and bounce back to /consent in a loop.
		newQ := authParams.Query()
		newQ.Set("scope", grantedScope)
		authParams.RawQuery = newQ.Encode()
		http.Redirect(w, r, authParams.String(), http.StatusFound)
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

// humanScopeDescription returns a human-readable description for a
// single OAuth scope token, or empty string if the scope is
// unknown. Used by the consent handler to populate scope rows for
// the template. Could grow into a per-deployment config so
// operators localise; for now hardcoded.
func humanScopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Sign you in (your account ID)."
	case "profile":
		return "Your basic profile (display name, username)."
	case "email":
		return "Your email address."
	case "address":
		return "Your address, when present in the directory."
	case "phone":
		return "Your phone number, when present in the directory."
	case "offline_access":
		return "Stay signed in via this app even when you're not actively using it."
	}
	return ""
}

type scopeRow struct {
	Code        string
	Description string
}
