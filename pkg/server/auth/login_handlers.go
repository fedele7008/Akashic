package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"akashic/akashic/pkg/mfa"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/userregistration"

	"go.uber.org/zap"
)

// Login UI handlers + helpers. Two pages, two handlers:
//   GET /login          → render the form
//   POST /login/submit  → validate CSRF + creds, set session, redirect
//
// Plus the CSRF cookie infrastructure shared by both, and a small
// rate-limit helper specific to /login/submit.

const (
	// loginCSRFCookie holds a random value the form echoes back in
	// a hidden field. Protects /login/submit against cross-origin
	// form posts (an attacker can't read the cookie value, so they
	// can't put a matching value in their forged form).
	//
	// Distinct from the admin-bff's CSRF cookie because they're on
	// different origins (auth.* vs admin.*) and cookies are
	// origin-scoped.
	loginCSRFCookie = "akashic_login_csrf"

	// authSessionCookie identifies the auth-server session created
	// after a successful /login/submit. Survives across multiple
	// /authorize requests so the user doesn't re-enter credentials
	// for every OAuth client they visit (the SSO experience).
	authSessionCookie = "akashic_auth_session"

	// csrfTokenLen is the byte length of the CSRF random value
	// before hex-encoding. 32 → 64-char hex string, plenty.
	csrfTokenLen = 32
)

// handleLoginPage serves GET /login.
//
// Query params:
//   - return_to: the URL to redirect to after successful login.
//     Typically a /authorize URL with all its OAuth params attached.
//     Must be same-origin; absolute external URLs are rejected to
//     prevent open-redirect.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.bootstrapBlocked(r.Context()) {
		s.renderBootstrapPending(w)
		return
	}

	csrf := s.ensureLoginCSRF(w, r)
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	cancelTo := cancelTargetFromReturnTo(returnTo)
	// Pre-fill the username field from a `?username=` query param —
	// set by the /signup/submit redirect after successful sign-up so
	// the user only has to type their password to finish the flow.
	prefillUsername := strings.TrimSpace(r.URL.Query().Get("username"))

	// Phase 9c: surface a banner for the post-reset case
	// ("?notice=password_reset"). Non-strict input — unknown
	// notice values render no banner. Centralised here so every
	// notice that the reset/verify flow might pass through the
	// login redirect lands on a single switch.
	notice := loginNoticeText(r.URL.Query().Get("notice"))

	renderTemplate(w, "login.html.tmpl", http.StatusOK, s.loginTemplateData(returnTo, map[string]any{
		"CSRFToken": csrf,
		"ReturnTo":  returnTo,
		"CancelURL": cancelTo,
		"Username":  prefillUsername,
		"Error":     "",
		"Notice":    notice,
	}))
}

// loginNoticeText maps known `?notice=` codes to a user-facing
// banner string. Unknown codes return empty (no banner). Phase 9c
// adds "password_reset"; Phase 9d will add "temp_password_set"
// for the admin-temp-reset flow.
func loginNoticeText(code string) string {
	switch code {
	case "password_reset":
		return "Your password has been reset. Sign in with your new password to continue."
	}
	return ""
}

// loginTemplateData augments the per-call template data with the
// shared, dynamically-derived fields that every render of
// login.html.tmpl needs.
//
// returnTo (caller-validated via safeReturnTo) is woven into the
// "Create account" link so the /login → /signup → /login round-trip
// preserves OAuth context.
func (s *Server) loginTemplateData(returnTo string, extra map[string]any) map[string]any {
	extra["SignUpHref"] = signUpHref(returnTo)
	// Phase 9c: render a "Forgot password?" link when the mailer
	// is configured; otherwise the link still appears but reads
	// "Need help signing in?" and lands on the contact-admin
	// stub. Visible-but-degraded keeps the flow discoverable.
	extra["ForgotPasswordEnabled"] = s.MailerConfigured()
	return extra
}

// signUpHref returns the URL the /login page's "Create account"
// link points at — always the auth-server-hosted /signup, with
// `return_to` (when present) appended so a successful sign-up can
// resume the OAuth flow that brought the user here.
//
// returnTo is expected to be a safe (relative, same-origin) value
// from safeReturnTo. The receiving /signup handler validates it
// again on its own form submit.
func signUpHref(returnTo string) string {
	const path = "/signup"
	if returnTo == "" {
		return path
	}
	q := url.Values{}
	q.Set("return_to", returnTo)
	return path + "?" + q.Encode()
}

// renderBootstrapPending renders a friendly 503 explaining that the
// deployment hasn't been bootstrapped yet, so end-user sign-in is
// disabled. Used by both the login GET and POST handlers.
func (s *Server) renderBootstrapPending(w http.ResponseWriter) {
	renderTemplate(w, "error.html.tmpl", http.StatusServiceUnavailable, map[string]any{
		"Title":   "Setup not yet complete",
		"Message": "This Akashic deployment is still being set up by its operator. Sign-in becomes available once bootstrap is finished.",
		"Detail":  "Operators: complete bootstrap via the CLI or admin BFF, then refresh.",
	})
}

// handleLoginSubmit processes POST /login/submit.
//
// Steps:
//   1. Validate CSRF token (cookie value == form field value)
//   2. Rate-limit per source IP (5/min)
//   3. Authenticate against LDAP via pkg/auth.Service
//   4. Create auth-server session, set cookie
//   5. Redirect to return_to (or a default landing page)
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Bootstrap gate. Catches stale form submissions that crossed the
	// network just before the operator finished bootstrap (and direct
	// hits that bypass the GET render).
	if s.bootstrapBlocked(r.Context()) {
		s.renderBootstrapPending(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderLoginError(w, r, "Invalid form submission.", "")
		return
	}

	// CSRF check (shared with /signup/submit)
	if !s.verifyLoginCSRF(r) {
		s.logger.Security.Warn("login CSRF check failed",
			zap.String("remote_ip", clientIP(r)))
		s.renderLoginError(w, r, "Session expired. Please reload and try again.", "")
		return
	}

	// Rate limit (per source IP, 5/min). Done AFTER CSRF check so
	// abusive submissions still pay the (cheap) CSRF cost first.
	ip := clientIP(r)
	if !s.loginRateLimitAllow(ip) {
		s.logger.Security.Warn("login rate limit hit", zap.String("remote_ip", ip))
		s.renderLoginError(w, r, "Too many login attempts. Please wait and try again.", r.PostForm.Get("username"))
		return
	}

	username := strings.TrimSpace(r.PostForm.Get("username"))
	// Normalise the tag portion of uid-style input to uppercase
	// so logs / audit / displays use the canonical stored form
	// regardless of what the user typed. No-op for emails or
	// untagged uids (no `#` to find).
	username = userregistration.NormalizeUIDInput(username)
	password := r.PostForm.Get("password")
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))

	if username == "" || password == "" {
		s.renderLoginError(w, r, "Username and password are required.", username)
		return
	}

	// Authenticate via the existing LDAP-bind service.
	s.mu.RLock()
	authSvc := s.authService
	sessionStore := s.sessionStore
	s.mu.RUnlock()
	if authSvc == nil || sessionStore == nil {
		s.logger.App.Error("login attempted before auth/oauth deps wired")
		s.renderLoginError(w, r, "Server is not yet ready. Please try again in a moment.", username)
		return
	}

	result, err := authSvc.Authenticate(r.Context(), username, password)
	if err != nil {
		// Don't distinguish "wrong password" from "user not found"
		// in the error message — that information leak would help
		// attackers enumerate usernames.
		if errors.Is(err, models.ErrInvalidCredentials) {
			s.renderLoginError(w, r, "Invalid username or password.", username)
			return
		}
		s.logger.App.Error("authenticate error", zap.Error(err))
		s.renderLoginError(w, r, "Authentication system error. Please try again.", username)
		return
	}

	// Build the session payload. user_type comes from the user's
	// PG row, which the deprovisioning service keeps current.
	user := result.User
	sess := &oauth.AuthSession{
		UserID:   user.ID.String(),
		LDAPDN:   user.LdapDN,
		Username: deriveUsernameFromDN(user.LdapDN),
		Email:    "", // /userinfo will fill this from LDAP if email scope granted
		UserType: string(user.UserType),
		IP:       ip,
		// Phase 9d: an admin may have flagged this user for forced
		// password reset (POST /users/<id>/reset-password). Carry
		// the flag onto the session so the post-login redirect
		// lands on /forced-password-reset instead of returnTo /
		// /authorize / the signed-in landing page; every other
		// gated endpoint re-checks and bounces back here.
		ResetRequired: user.PasswordResetRequired,
	}
	if result.LDAPInfo != nil {
		sess.Username = result.LDAPInfo.Username
		sess.Email = result.LDAPInfo.Email
	}

	sid, err := sessionStore.Create(r.Context(), sess)
	if err != nil {
		s.logger.App.Error("create auth session", zap.Error(err))
		s.renderLoginError(w, r, "Could not start a session. Please retry.", username)
		return
	}

	// Defense against session fixation: the CSRF cookie's value
	// becomes "stale" after login (a different value's at this
	// origin would be in a fresh tab anyway, but explicit clear is
	// belt-and-suspenders). Set a fresh CSRF cookie so subsequent
	// /authorize visits (which don't need CSRF anyway, since they
	// only have side effects after another /login) don't pick up a
	// stale cookie.
	s.clearLoginCSRF(w)

	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookie,
		Value:    sid,
		Path:     "/",
		Secure:   isHTTPS(r),
		HttpOnly: true,
		// Lax (not Strict) so the OAuth redirect flow works: a
		// /authorize → /login → /login/submit → /authorize chain
		// counts as "navigation" but the final redirect to the
		// client's redirect_uri is "cross-site" from the browser's
		// perspective. Strict would block the cookie on that hop.
		SameSite: http.SameSiteLaxMode,
	})

	s.logger.Security.Info("login success",
		zap.String("user_id", user.ID.String()),
		zap.String("username", sess.Username),
		zap.String("user_type", sess.UserType),
		zap.String("ip", ip))

	// Phase 9d: if an admin flagged this user for a forced reset,
	// the partial session has ResetRequired=true. Skip both the
	// returnTo redirect and the signed-in landing — every gated
	// endpoint would just bounce here anyway. Preserve returnTo
	// across the reset so the user lands back on the original
	// destination after picking a new password.
	if sess.ResetRequired {
		http.Redirect(w, r, forcedResetURLWithReturnTo(returnTo, ""), http.StatusSeeOther)
		return
	}

	// Phase 9f: MFA gate. After password verification, before
	// finalising the login, check whether MFA is required (per-user
	// opt-in OR per-client require_mfa, OR'd at this point). If
	// required AND the request has no valid trusted-device cookie,
	// flip the session into MFAPending state and route to the
	// challenge page. The original returnTo is stamped on the
	// session so the post-MFA finalise lands the user on the
	// correct destination.
	//
	// Order vs forced-reset: forced-reset comes first (above)
	// because the user's password has been admin-rotated and we
	// want them on a fresh password before the MFA prompt. The
	// forced-reset handler then re-runs this gate after the rotate.
	s.mu.RLock()
	mfaSvc := s.mfaSvc
	s.mu.RUnlock()
	if mfaSvc != nil {
		clientID := extractClientIDFromReturnTo(returnTo)
		need, err := mfaSvc.IsRequired(r.Context(), user, clientID)
		if err != nil {
			s.logger.App.Warn("login: mfa IsRequired errored; allowing through",
				zap.String("user_id", user.ID.String()), zap.Error(err))
		}
		if need {
			// Trusted-device short-circuit: matching cookie skips
			// the prompt and lets the regular finalise continue.
			cookieVal := readCookie(r, mfa.CookieName)
			trusted := false
			if cookieVal != "" {
				ok, terr := mfaSvc.IsTrustedDevice(r.Context(), user.ID, cookieVal)
				if terr != nil {
					s.logger.App.Warn("login: mfa IsTrustedDevice errored",
						zap.Error(terr))
				}
				trusted = ok
			}
			if !trusted {
				if err := s.startMFAChallenge(r.Context(), w, r, sess, sid, user, returnTo, clientID); err != nil {
					s.logger.App.Error("login: startMFAChallenge",
						zap.String("user_id", user.ID.String()), zap.Error(err))
					s.renderLoginError(w, r,
						"We couldn't send your verification code. Please retry.",
						username)
					return
				}
				return
			}
			s.logger.Security.Info("mfa: trusted-device cookie short-circuited prompt",
				zap.String("user_id", user.ID.String()))
		}
	}

	// returnTo is empty when the user landed on /login directly
	// (typed the URL, used a saved bookmark, etc.) rather than via
	// an OAuth /authorize redirect. The auth server is purely an
	// IdP — it has no first-class home page to send them to — so
	// render a minimal "you're signed in" landing instead of
	// redirecting to "/" (which would 404, since no GET / route is
	// registered).
	if returnTo == "" {
		s.renderSignedInLanding(w, sess.Username)
		return
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// renderSignedInLanding shows the user a small confirmation page
// after a direct /login that wasn't part of an OAuth flow. Reuses
// error.html.tmpl's fields (Title/Message/Detail) — semantically
// it's an info screen, not an error, but the template's structure
// (a card with title + body) is fine for both, and avoiding a new
// template keeps the surface small. The 200 status reflects that
// this is a normal, successful landing.
func (s *Server) renderSignedInLanding(w http.ResponseWriter, username string) {
	greeting := "You're signed in."
	if username != "" {
		greeting = "Signed in as " + username + "."
	}
	renderTemplate(w, "error.html.tmpl", http.StatusOK, map[string]any{
		"Title":   "Signed in",
		"Message": greeting,
		"Detail":  "Open the app you wanted to use, or close this tab. Your session stays active for single sign-on.",
	})
}

// handleLogout clears the session cookie and removes the session
// from Redis. Idempotent — calling on an already-logged-out request
// just clears the cookie and redirects.
//
// Phase 7: implements OIDC RP-Initiated Logout. A relying party (the
// admin-bff in our case) initiates logout by navigating the browser
// here with `?post_logout_redirect_uri=<URL>`. We:
//
//   1. Delete the auth-server session (Redis row + cookie).
//   2. If post_logout_redirect_uri is supplied AND its origin matches
//      a registered client's redirect_uri origin, redirect there.
//   3. Otherwise fall back to the local /login page.
//
// The origin allowlist (rather than letting any URL through) prevents
// open-redirect: an attacker can't craft a /logout link that bounces
// the user to a phishing site of their choice — only origins that
// have a legitimate registered client are accepted.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sid := readCookie(r, authSessionCookie); sid != "" && s.sessionStore != nil {
		_ = s.sessionStore.Delete(r.Context(), sid)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookie,
		Value:    "",
		Path:     "/",
		Secure:   isHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // delete
	})

	// post_logout_redirect_uri (RP-Initiated Logout, OIDC §6.4.4).
	// Empty = stay on the IdP and show /login.
	postLogout := r.URL.Query().Get("post_logout_redirect_uri")
	if postLogout != "" && s.postLogoutOriginAllowed(r.Context(), postLogout) {
		http.Redirect(w, r, postLogout, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// postLogoutOriginAllowed checks whether the supplied URL's origin
// matches the origin of any registered client's redirect_uri. We
// don't require an exact-string match (as we do for OAuth redirect
// URIs) because the post-logout target is typically the client's
// home page or sign-in landing, not the OAuth callback path.
//
// Origin = scheme + host + port. Compared verbatim — no wildcards.
func (s *Server) postLogoutOriginAllowed(ctx context.Context, raw string) bool {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return false
	}
	targetOrigin := target.Scheme + "://" + target.Host

	s.mu.RLock()
	db := s.db
	s.mu.RUnlock()
	if db == nil {
		return false
	}

	// Pull every redirect_uri from every client_services row. For a
	// dev deployment with one or two built-in clients this is cheap.
	// In production this will want a small cache; deferred until we
	// have measurable load.
	var rows []models.ClientService
	if err := db.WithContext(ctx).Select("redirect_uris").Find(&rows).Error; err != nil {
		return false
	}
	for _, row := range rows {
		for _, uri := range strings.Split(row.RedirectURIs, ",") {
			u, err := url.Parse(strings.TrimSpace(uri))
			if err != nil || u.Scheme == "" || u.Host == "" {
				continue
			}
			if u.Scheme+"://"+u.Host == targetOrigin {
				return true
			}
		}
	}
	return false
}

// renderLoginError re-renders the login form with an error message
// and the username pre-filled (so the user doesn't lose their typed
// username when fixing a typo'd password).
//
// The CSRF token is also re-issued — the previous one is still valid
// for this session, but issuing fresh prevents some replay-style
// concerns and matches the "form regenerates on every render" model.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, msg, username string) {
	csrf := s.ensureLoginCSRF(w, r)
	returnTo := ""
	if r.PostForm != nil {
		returnTo = safeReturnTo(r.PostForm.Get("return_to"))
	}
	renderTemplate(w, "login.html.tmpl", http.StatusOK, s.loginTemplateData(returnTo, map[string]any{
		"CSRFToken": csrf,
		"ReturnTo":  returnTo,
		"CancelURL": cancelTargetFromReturnTo(returnTo),
		"Username":  username,
		"Error":     msg,
	}))
}

// ─── CSRF cookie helpers ───────────────────────────────────────────

// verifyLoginCSRF runs the double-submit-cookie check on a POST
// request. Returns true when the cookie value matches the form
// field value (constant-time compare); false on any mismatch or
// missing value. Shared by /login/submit and /signup/submit.
//
// On false the caller is expected to log a security warning AND
// re-render the originating form with a "session expired" error
// (renderLoginError / renderSignupError handle the second part).
func (s *Server) verifyLoginCSRF(r *http.Request) bool {
	cookieVal := readCookie(r, loginCSRFCookie)
	formVal := r.PostForm.Get("csrf_token")
	if cookieVal == "" || formVal == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieVal), []byte(formVal)) == 1
}

// ensureLoginCSRF returns the current CSRF token, setting a fresh
// cookie if none exists. Same double-submit-cookie pattern admin-bff
// uses, just a different cookie name.
func (s *Server) ensureLoginCSRF(w http.ResponseWriter, r *http.Request) string {
	if existing := readCookie(r, loginCSRFCookie); existing != "" {
		return existing
	}
	buf := make([]byte, csrfTokenLen)
	if _, err := rand.Read(buf); err != nil {
		// rand.Read shouldn't fail; fall back to a static value
		// rather than crashing the page. If it ever does fail,
		// CSRF protection is degraded but the page still loads.
		return "x"
	}
	val := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     loginCSRFCookie,
		Value:    val,
		Path:     "/",
		Secure:   isHTTPS(r),
		HttpOnly: false, // form needs to read it (echo into hidden field)
		SameSite: http.SameSiteStrictMode,
	})
	return val
}

func (s *Server) clearLoginCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginCSRFCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// readCookie returns the named cookie's value or "" if absent.
func readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// isHTTPS detects whether the original request was HTTPS, even when
// the auth server is fronted by a TLS-terminating proxy. Same logic
// as admin-bff's helper of the same name.
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// clientIP picks the source IP for rate-limiting / audit logging.
// Honors X-Forwarded-For only when present; otherwise falls back to
// RemoteAddr. (Production trust-chain validation is the proxy's
// responsibility; the auth server runs behind nginx-proxy which
// scopes X-Forwarded-For to its own upstream.)
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Leftmost entry is the original client.
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	// Strip port from RemoteAddr (host:port form).
	if i := strings.LastIndex(r.RemoteAddr, ":"); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}

// cancelTargetFromReturnTo derives a "go back to where you came
// from" URL for the login page's Cancel link.
//
// The auth server doesn't know which OAuth client started the flow,
// but the `return_to` param is typically a /authorize URL whose
// `redirect_uri` query value points at the client. The origin of that
// redirect_uri is, by definition, a public URL the user's browser
// can reach — and is the right "home" for that client.
//
// Returns "" when no safe target can be derived (no return_to, not
// an /authorize URL, missing/malformed redirect_uri). The template
// hides the Cancel link when the value is empty.
//
// Security: only http(s) schemes are accepted. The redirect_uri
// itself is implicitly trusted in this codepath because the OAuth
// client registration enforces an allowlist before we ever render
// /login — but we still scheme-check defensively.
func cancelTargetFromReturnTo(returnTo string) string {
	if returnTo == "" {
		return ""
	}
	// return_to is a relative URL like "/authorize?client_id=...&redirect_uri=...".
	parsed, err := url.Parse(returnTo)
	if err != nil {
		return ""
	}
	redirectURI := parsed.Query().Get("redirect_uri")
	if redirectURI == "" {
		return ""
	}
	ru, err := url.Parse(redirectURI)
	if err != nil || ru.Host == "" {
		return ""
	}
	if ru.Scheme != "http" && ru.Scheme != "https" {
		return ""
	}
	// Origin only — the callback path itself is not a useful
	// destination for a "Cancel and go home" affordance.
	return ru.Scheme + "://" + ru.Host + "/"
}

// safeReturnTo validates a return_to URL is same-origin (relative
// path or absolute path within this server). Rejects anything that
// looks like an external redirect — open-redirect prevention.
func safeReturnTo(raw string) string {
	if raw == "" {
		return ""
	}
	// Relative path is fine
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return raw
	}
	// Absolute URL: reject (we don't want to redirect to external
	// hosts, ever — that's an open-redirect and a phishing aid).
	// Even an absolute URL whose host matches our own is dropped
	// because it's not necessary; same-origin can always be expressed
	// as a relative path.
	u, err := url.Parse(raw)
	if err != nil || u.Host != "" {
		return ""
	}
	return raw
}

// deriveUsernameFromDN extracts the leftmost "uid=" RDN value from
// an LDAP DN. Used as a fallback when LDAPInfo isn't populated
// (shouldn't happen but defensive).
func deriveUsernameFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}
	first := parts[0]
	if eq := strings.Index(first, "="); eq > 0 {
		return strings.TrimSpace(first[eq+1:])
	}
	return first
}
