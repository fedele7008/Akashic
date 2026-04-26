package admin_bff

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// OAuth-flow handlers on the BFF side.
//
// Three browser-facing endpoints + one FE-facing JSON endpoint:
//
//   GET  /login           Begins the flow: generates state + PKCE
//                         verifier, persists them to a short-lived
//                         pre-session cookie, redirects to the auth
//                         server's /authorize.
//
//   GET  /oauth/callback  Receives ?code=&state= from auth server.
//                         Verifies state, exchanges code → tokens at
//                         /token, verifies the ID token, enforces
//                         the role allowlist (root/admin), creates
//                         a real BFF session, sets the session
//                         cookie, redirects to /.
//
//   POST /logout          Clears the BFF session cookie + Redis row,
//                         returns JSON. The FE also clears any local
//                         state and reloads.
//
//   GET  /api/session     FE polls this to render the right shell.
//                         200 with user info when logged in, 401
//                         when not.

const (
	sessionCookieName = "akashic_admin_session"

	// Pre-session cookie set during /login, read in /oauth/callback,
	// then deleted. Holds state + PKCE verifier so the callback can
	// match them. Expires fast (5 min) so a stale tab can't be
	// resurrected long after the user moved on.
	preSessionCookieName = "akashic_admin_oauth_pre"
	preSessionMaxAge     = 5 * 60 // seconds
)

// preSession is what we serialize into the pre-session cookie
// (encrypted by the cookie middleware? No -- we sign it instead with
// the BFF's HMAC secret in the Phase 7 follow-up. For now we keep it
// in plaintext; the values are random + bound to one browser, and
// the cookie is HttpOnly+SameSite=Lax+Secure so the attack surface
// is small. Hardening to signed/encrypted form is a follow-up).
type preSession struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	IssuedAt int64  `json:"iat"`
}

// ─── /login ─────────────────────────────────────────────────────────

// handleLogin starts the OAuth flow. We don't do any DB or LDAP
// lookups here -- the entire decision tree (logged-in vs. not,
// existing session vs. fresh) is delegated to the auth server's
// /authorize. Our job is just to set the PKCE/state binding and
// redirect.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.oauth == nil {
		writeError(w, http.StatusServiceUnavailable, "OAUTH_NOT_CONFIGURED",
			"Login is not yet configured on this BFF.")
		return
	}

	// If the caller already has a valid session, short-circuit to /.
	// This makes /login a safe button to surface in the UI -- clicking
	// it when already logged in just lands you on the dashboard.
	if sid := readCookie(r, sessionCookieName); sid != "" {
		if _, err := s.sessions.Get(r.Context(), sid); err == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	state, err := generateState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "Could not start login.")
		return
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "Could not start login.")
		return
	}

	pre := preSession{State: state, Verifier: verifier, IssuedAt: time.Now().Unix()}
	encoded, err := encodePreSession(pre)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "Could not encode pre-session.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     preSessionCookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   preSessionMaxAge,
		Secure:   isHTTPS(r),
		HttpOnly: true,
		// Lax (not Strict) is required: when the auth-server redirects
		// the browser back to /oauth/callback, that's a top-level
		// navigation cross-site from the browser's perspective. Strict
		// would drop the cookie and the callback couldn't read state.
		SameSite: http.SameSiteLaxMode,
	})

	s.auditLog(r, "oauth_login_initiated", map[string]any{
		"outcome": "redirect",
	})

	http.Redirect(w, r, s.oauth.authorizeURL(state, challenge), http.StatusFound)
}

// ─── /oauth/callback ────────────────────────────────────────────────

// handleOAuthCallback receives ?code=&state= from the auth server.
//
// Order of checks (this order matters -- we must validate state
// before doing anything network-side, both for security and to avoid
// burning a code on a forged callback):
//
//   1. error= param present? Surface it; don't exchange.
//   2. Pre-session cookie present?
//   3. state matches pre-session?
//   4. Code exchange at /token
//   5. ID token verification (signature + iss + aud + exp)
//   6. Role check (user_type ∈ {root, admin})
//   7. Create BFF session, set cookie, redirect to /.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.oauth == nil {
		writeError(w, http.StatusServiceUnavailable, "OAUTH_NOT_CONFIGURED",
			"Login is not yet configured on this BFF.")
		return
	}

	q := r.URL.Query()

	// (1) Auth-server-side error → render and stop. Don't try to
	// exchange a code that the auth server already said is bad.
	if errCode := q.Get("error"); errCode != "" {
		s.auditLog(r, "oauth_callback_error", map[string]any{
			"outcome":            "fail",
			"control_error_code": errCode,
		})
		writeError(w, http.StatusBadRequest, "AUTH_FAILED",
			"Login was rejected: "+q.Get("error_description"))
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Callback is missing required parameters.")
		return
	}

	// (2) + (3) State binding via pre-session cookie.
	pre, err := readPreSessionCookie(r)
	if err != nil {
		s.auditLog(r, "oauth_callback_error", map[string]any{
			"outcome":            "fail",
			"control_error_code": "PRE_SESSION_MISSING",
		})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"Login session has expired or was opened in a different browser. Please try again.")
		return
	}
	// Constant-time comparison (defends against timing oracles even
	// though state is random; cheap defense in depth).
	if subtle.ConstantTimeCompare([]byte(state), []byte(pre.State)) != 1 {
		s.auditLog(r, "oauth_callback_error", map[string]any{
			"outcome":            "fail",
			"control_error_code": "STATE_MISMATCH",
		})
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST",
			"State mismatch. Please retry login.")
		return
	}
	// State validated -- delete the pre-session cookie so a replay
	// can't reuse it.
	clearCookie(w, preSessionCookieName, r)

	// (4) Code exchange.
	tokens, err := s.oauth.exchangeCode(r.Context(), code, pre.Verifier)
	if err != nil {
		s.auditLog(r, "oauth_callback_error", map[string]any{
			"outcome":            "fail",
			"control_error_code": "TOKEN_EXCHANGE_FAILED",
		})
		writeError(w, http.StatusBadGateway, "TOKEN_EXCHANGE_FAILED",
			"Could not exchange code for tokens. Please retry.")
		return
	}
	if tokens.IDToken == "" {
		writeError(w, http.StatusBadGateway, "TOKEN_EXCHANGE_FAILED",
			"Auth server did not return an ID token.")
		return
	}

	// (5) Verify ID token (sig + iss + aud + exp). nonce check is
	// disabled here because we don't currently send a nonce on
	// /authorize -- adding nonce is a small future hardening item.
	claims, err := s.oauth.verifyIDToken(r.Context(), tokens.IDToken, "")
	if err != nil {
		// Print the underlying error to stderr so an operator can
		// distinguish "JWKS unreachable" from "iss mismatch" from
		// "exp in the past" without re-deriving each one. The audit
		// stream still gets the redacted code so we don't leak token
		// internals to the security log; stderr stays human-only.
		fmt.Fprintf(os.Stderr, "admin-bff: id token verify failed: %v\n", err)
		s.auditLog(r, "oauth_callback_error", map[string]any{
			"outcome":            "fail",
			"control_error_code": "ID_TOKEN_INVALID",
		})
		writeError(w, http.StatusBadGateway, "ID_TOKEN_INVALID",
			"ID token verification failed.")
		return
	}

	// (6) Role check. The auth server will issue tokens to *anyone*
	// who can authenticate; the BFF decides who is allowed past the
	// admin door. Failing here is the correct behavior for a non-admin
	// user attempting to sign in to admin.akashic.<domain>.
	if !slices.Contains(s.cfg.OAuthAllowedRoles, claims.UserType) {
		s.auditLog(r, "admin_login_denied_role", map[string]any{
			"outcome":  "fail",
			"username": claims.PreferredUsername,
		})
		writeError(w, http.StatusForbidden, "ACCESS_DENIED",
			"Your account does not have permission to access the admin console.")
		return
	}

	// (7) Create BFF session.
	sess := &Session{
		UserID:        claims.Subject,
		UserType:      claims.UserType,
		Username:      claims.PreferredUsername,
		Email:         claims.Email,
		AccessToken:   tokens.AccessToken,
		IDToken:       tokens.IDToken,
		AccessExpires: time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).UTC(),
		IP:            s.resolveAuditIP(r),
	}
	sid, err := s.sessions.Create(r.Context(), sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL",
			"Could not establish session. Please retry.")
		return
	}

	// Cookie. SameSite=Lax for compat with future OAuth redirects
	// initiated by other clients on this BFF (Phase 8+); Strict would
	// also work today but Lax keeps the door open without sacrificing
	// meaningful security (CSRF is enforced by separate token).
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sid,
		Path:     "/",
		MaxAge:   int(s.cfg.OAuthSessionAbsolute.Seconds()),
		Secure:   isHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	s.auditLog(r, "admin_login_succeeded", map[string]any{
		"outcome":  "success",
		"username": claims.PreferredUsername,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// ─── /logout ────────────────────────────────────────────────────────

// handleLogout invalidates the BFF session AND returns the auth
// server's RP-Initiated Logout URL so the FE can navigate the browser
// there next. Without that second hop, the auth-server's session
// cookie survives, and the next "Sign in" click silently re-uses the
// existing IdP session — i.e., re-logs-in the user without a credential
// prompt. Explicit logout has to end both sessions.
//
// Response shape:
//   {
//     "success": true,
//     "data": {
//       "logged_out":      true,
//       "auth_logout_url": "https://auth.example.com/logout?post_logout_redirect_uri=https://admin.example.com/"
//     }
//   }
//
// The FE reads `auth_logout_url`, navigates window.location there,
// and the auth-server clears its cookie + redirects back to the post-
// logout URI (validated server-side against registered clients).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sid := readCookie(r, sessionCookieName)
	if sid != "" {
		_ = s.sessions.Delete(r.Context(), sid)
	}
	clearCookie(w, sessionCookieName, r)

	s.auditLog(r, "admin_logout", map[string]any{
		"outcome": "success",
	})

	// Build the RP-Initiated Logout URL. Use the PUBLIC issuer (not
	// the internal back-channel URL) because the BROWSER has to
	// navigate there. post_logout_redirect_uri is the home page of
	// the admin surface, derived from OAuthRedirectURI (just stripping
	// the /oauth/callback path off the end keeps it in lockstep with
	// however the operator configured the BFF).
	authLogoutURL := ""
	if s.oauth != nil {
		postLogoutTarget := postLogoutTargetFromRedirectURI(s.cfg.OAuthRedirectURI)
		authLogoutURL = s.oauth.issuer + "/logout?post_logout_redirect_uri=" +
			urlQueryEscape(postLogoutTarget)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data": map[string]any{
			"logged_out":      true,
			"auth_logout_url": authLogoutURL,
		},
	})
}

// postLogoutTargetFromRedirectURI returns the home-page URL of the
// admin surface, derived from the OAuth redirect_uri by trimming the
// /oauth/callback suffix. We could make this its own config knob, but
// the redirect_uri already pins the admin's host+scheme exactly where
// we want the user to land post-logout, so we'd just be duplicating
// configuration.
func postLogoutTargetFromRedirectURI(redirectURI string) string {
	const suffix = "/oauth/callback"
	if strings.HasSuffix(redirectURI, suffix) {
		return strings.TrimSuffix(redirectURI, suffix) + "/"
	}
	return redirectURI
}

// urlQueryEscape is the smallest possible wrapper around net/url's
// QueryEscape — pulled out to avoid an additional import in this file
// when only one call site needs it.
func urlQueryEscape(s string) string {
	// %-encode reserved chars per RFC 3986. Equivalent to
	// url.QueryEscape but written inline to keep the import surface
	// of oauth_handlers.go small.
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' ||
			c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// ─── /api/session ───────────────────────────────────────────────────

// handleSessionInfo is the FE's primary "am I logged in?" endpoint.
// On hit, returns shallow user info (no tokens; the FE doesn't need
// them and shouldn't have access to them). On miss, returns 401 with
// a code the FE switches on to show the login button.
func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request) {
	sid := readCookie(r, sessionCookieName)
	if sid == "" {
		writeError(w, http.StatusUnauthorized, "NOT_AUTHENTICATED",
			"No active session.")
		return
	}
	sess, err := s.sessions.Touch(r.Context(), sid)
	if err != nil {
		// Drop the stale cookie so the FE doesn't keep sending it.
		clearCookie(w, sessionCookieName, r)
		writeError(w, http.StatusUnauthorized, "SESSION_EXPIRED",
			"Session has expired. Please log in again.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"data": map[string]any{
			"user_id":    sess.UserID,
			"user_type":  sess.UserType,
			"username":   sess.Username,
			"email":      sess.Email,
			"issued_at":  sess.IssuedAt.UTC().Format(time.RFC3339),
			"expires_at": sess.IssuedAt.Add(s.cfg.OAuthSessionAbsolute).UTC().Format(time.RFC3339),
		},
	})
}

// ─── helpers ────────────────────────────────────────────────────────

// readCookie returns the named cookie's value, or "" if absent.
// Mirrors auth-server's same helper -- duplicated rather than
// imported to keep the BFF free of pkg/server/auth deps.
func readCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// clearCookie sets an expired Max-Age=-1 cookie. The Secure attribute
// must match what we used to set the cookie or Chrome silently
// ignores the deletion.
func clearCookie(w http.ResponseWriter, name string, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   isHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// encodePreSession serializes the pre-session payload to a base64url
// string suitable for a cookie value. We use the JSON form rather
// than a packed binary form because the payload is tiny and the
// debug-friendliness of human-readable cookies during development
// is worth more than the few bytes saved.
func encodePreSession(p preSession) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// readPreSessionCookie decodes and validates the pre-session cookie.
// Returns an error if missing, malformed, or expired.
func readPreSessionCookie(r *http.Request) (*preSession, error) {
	raw := readCookie(r, preSessionCookieName)
	if raw == "" {
		return nil, errPreSessionMissing
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, errPreSessionMalformed
	}
	var p preSession
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, errPreSessionMalformed
	}
	if time.Now().Unix()-p.IssuedAt > preSessionMaxAge {
		return nil, errPreSessionExpired
	}
	return &p, nil
}

// Compile-time guard against accidental unused imports.
var (
	errPreSessionMissing   = newPreSessionErr("pre-session cookie missing")
	errPreSessionMalformed = newPreSessionErr("pre-session cookie malformed")
	errPreSessionExpired   = newPreSessionErr("pre-session cookie expired")
)

type preSessionErr struct{ msg string }

func (e *preSessionErr) Error() string         { return e.msg }
func newPreSessionErr(s string) *preSessionErr { return &preSessionErr{msg: s} }

