package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"akashic/akashic/pkg/mfa"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /login/mfa — Phase 9f.
//
// Routes:
//
//	GET  /login/mfa             code-entry form. Gated by an
//	                            MFAPending partial session cookie.
//	POST /login/mfa/submit      validate code, finalise login,
//	                            optionally mint trusted-device cookie.
//
// Lifecycle:
//
//   /login/submit verifies the password, mints a partial session
//   with MFAPending=true (via startMFAChallenge below), sends a
//   code email, and 302s here. The user enters the code; on match
//   we clear MFAPending, rotate the session id (defence against
//   partial-session-cookie leaks), optionally mint a trusted-device
//   cookie, and redirect to PendingReturnTo.
//
// On code mismatch: re-render with the error. The store handles
// attempt counting / auto-consume on cap; once the code is dead,
// the user falls back to /login.

// startMFAChallenge mints a partial-session-MFA-pending state for
// the just-password-verified user, dispatches the email code, and
// 302s to /login/mfa. Caller must have already created `sess` and
// `sid` (via SessionStore.Create); we update the session in-place
// to add the MFAPending flag + pending fields.
func (s *Server) startMFAChallenge(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	sess *oauth.AuthSession,
	sid string,
	user *models.User,
	returnTo string,
	clientID string,
) error {
	s.mu.RLock()
	mfaSvc := s.mfaSvc
	sessionStore := s.sessionStore
	s.mu.RUnlock()
	if mfaSvc == nil || sessionStore == nil {
		return errors.New("mfa: dependencies not wired")
	}

	// Email + display name. The session was just minted with these
	// fields populated from result.LDAPInfo in /login/submit; we
	// fall back to the LDAP DN's uid when display-name is empty.
	emailAddr := sess.Email
	displayName := sess.Username
	if displayName == "" {
		displayName = deriveUsernameFromDN(user.LdapDN)
	}
	if emailAddr == "" {
		// No email on the LDAP entry — we can't deliver a code.
		// Surface as an error to the caller; /login/submit's error
		// path will tell the user to contact admin.
		return errors.New("mfa: no email address on LDAP entry")
	}

	// Stamp the partial-session fields and persist.
	sess.MFAPending = true
	sess.PendingClientID = clientID
	sess.PendingReturnTo = returnTo
	if err := sessionStore.Replace(ctx, sid, sess); err != nil {
		return err
	}

	// Issue + email the code. Failure here means the user never
	// sees a code — we don't try to recover with a degraded path
	// because lockout-by-degradation is worse than a clear error.
	if err := mfaSvc.IssueCode(ctx, user, sid, emailAddr, displayName); err != nil {
		return err
	}

	http.Redirect(w, r, mfaURLWithReturnTo(returnTo), http.StatusSeeOther)
	return nil
}

func (s *Server) handleLoginMFAPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, sid, ok := s.requirePartialSession(w, r)
	if !ok {
		return
	}
	if !sess.MFAPending {
		// User wandered here outside the MFA flow (e.g., a stale
		// bookmark). Send them to returnTo or the signed-in
		// landing rather than rendering an empty challenge.
		s.redirectToReturnToOrLanding(w, r, sess, safeReturnTo(r.URL.Query().Get("return_to")))
		return
	}
	_ = sid
	csrf := s.ensureLoginCSRF(w, r)
	pol := s.passwordPolicy(r.Context()) // unrelated; just for consistency reading policy
	_ = pol
	maxDays := s.mfaTrustedMaxDays(r.Context())
	renderTemplate(w, "login_mfa.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":         csrf,
		"Email":             sess.Email,
		"ExpiresInMinutes":  10,
		"MaxTrustedDays":    maxDays,
		"DefaultTrustedDays": maxDays, // pre-fill with the ceiling
		"ReturnTo":          sess.PendingReturnTo,
	})
}

func (s *Server) handleLoginMFASubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, sid, ok := s.requirePartialSession(w, r)
	if !ok {
		return
	}
	if !sess.MFAPending {
		s.redirectToReturnToOrLanding(w, r, sess, safeReturnTo(r.URL.Query().Get("return_to")))
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderMFAError(w, r, sess, "Could not parse form. Please retry.")
		return
	}
	if !s.verifyLoginCSRF(r) {
		s.renderMFAError(w, r, sess, "Form expired. Please reload and try again.")
		return
	}

	code := strings.TrimSpace(r.PostForm.Get("code"))
	rememberStr := r.PostForm.Get("remember_device")
	rememberDays := 0
	if rememberStr != "" {
		if n, err := strconv.Atoi(rememberStr); err == nil && n > 0 {
			rememberDays = n
		}
	}

	s.mu.RLock()
	mfaSvc := s.mfaSvc
	sessionStore := s.sessionStore
	s.mu.RUnlock()
	if mfaSvc == nil || sessionStore == nil {
		s.renderMFAError(w, r, sess, "Server error. Please retry.")
		return
	}

	if err := mfaSvc.VerifyCode(r.Context(), sid, code); err != nil {
		s.logger.Security.Warn("mfa: code verify failed",
			zap.String("user_id", sess.UserID), zap.Error(err))
		s.renderMFAError(w, r, sess, "Invalid or expired code. Please try again.")
		return
	}

	// Code accepted. Build the upgraded session: clear the partial-
	// session flag and the pending fields, then rotate the sid so a
	// leaked partial cookie can't ride into a fully-authenticated
	// session. Mirrors the Phase 9d forced-reset upgrade.
	upgraded := *sess
	upgraded.MFAPending = false
	upgraded.PendingClientID = ""
	upgraded.PendingReturnTo = ""

	_ = sessionStore.Delete(r.Context(), sid)
	newSID, err := sessionStore.Create(r.Context(), &upgraded)
	if err != nil {
		s.logger.App.Error("mfa: session rotation failed", zap.Error(err))
		s.clearAuthSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookie,
		Value:    newSID,
		Path:     "/",
		Secure:   isHTTPS(r),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Optional trusted-device cookie. Only mint when the user
	// explicitly opted in (rememberDays > 0). The service clamps
	// to the policy ceiling and sets ExpiresAt accordingly; the
	// cookie's Max-Age must match so the browser drops it at the
	// same moment.
	if rememberDays > 0 {
		userID, perr := uuid.Parse(sess.UserID)
		if perr == nil {
			label := bestEffortDeviceLabel(r.UserAgent())
			cookieVal, derr := mfaSvc.RememberDevice(r.Context(), userID, rememberDays, label)
			if derr != nil {
				s.logger.App.Warn("mfa: RememberDevice failed; continuing without trusted cookie",
					zap.Error(derr))
			} else {
				maxAgeSec := rememberDays * 24 * 60 * 60
				if maxDays := s.mfaTrustedMaxDays(r.Context()); rememberDays > maxDays {
					maxAgeSec = maxDays * 24 * 60 * 60
				}
				http.SetCookie(w, &http.Cookie{
					Name:     mfa.CookieName,
					Value:    cookieVal,
					Path:     "/",
					Secure:   isHTTPS(r),
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					MaxAge:   maxAgeSec,
				})
			}
		}
	}

	s.logger.Security.Info("mfa: code accepted",
		zap.String("user_id", sess.UserID),
		zap.Bool("remember_device", rememberDays > 0))

	s.redirectToReturnToOrLanding(w, r, &upgraded, sess.PendingReturnTo)
}

// renderMFAError re-renders the challenge page with a flash error
// banner. Preserves the partial-session state (no upgrade) so the
// user can try again.
func (s *Server) renderMFAError(w http.ResponseWriter, r *http.Request, sess *oauth.AuthSession, msg string) {
	csrf := s.ensureLoginCSRF(w, r)
	maxDays := s.mfaTrustedMaxDays(r.Context())
	renderTemplate(w, "login_mfa.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":          csrf,
		"Email":              sess.Email,
		"ExpiresInMinutes":   10,
		"MaxTrustedDays":     maxDays,
		"DefaultTrustedDays": maxDays,
		"ReturnTo":           sess.PendingReturnTo,
		"Error":              msg,
	})
}

// mfaTrustedMaxDays reads the policy's MFA trusted-device ceiling.
// Falls back to a hard-coded default on read failure so the
// challenge page renders rather than 500-ing.
func (s *Server) mfaTrustedMaxDays(ctx context.Context) int {
	s.mu.RLock()
	pol := s.policySvc
	s.mu.RUnlock()
	if pol == nil {
		return 30
	}
	row, err := pol.Get(ctx)
	if err != nil || row == nil {
		return 30
	}
	if row.MFATrustedDeviceMaxDays > 0 {
		return row.MFATrustedDeviceMaxDays
	}
	return 30
}

// mfaURLWithReturnTo builds the redirect target for /login/submit's
// MFA-required branch. Notice is reserved for future use.
func mfaURLWithReturnTo(returnTo string) string {
	q := url.Values{}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	if len(q) == 0 {
		return "/login/mfa"
	}
	return "/login/mfa?" + q.Encode()
}

// extractClientIDFromReturnTo pulls the OAuth `client_id` query
// param out of a returnTo URL when the returnTo is an /authorize
// redirect. Returns "" for any URL shape that doesn't carry a
// client_id (direct logins, /profile, etc.).
//
// Used to feed the MFA gate's per-client require_mfa lookup at
// /login/submit time, before the user has been pushed back to
// /authorize.
func extractClientIDFromReturnTo(returnTo string) string {
	if returnTo == "" {
		return ""
	}
	u, err := url.Parse(returnTo)
	if err != nil {
		return ""
	}
	return u.Query().Get("client_id")
}

// bestEffortDeviceLabel parses a User-Agent into a short
// human-readable label ("Chrome on macOS"). Cheap regex-style
// substring matching — no full UA parser dependency. Used as the
// trusted-device row's Label so the user can identify which row
// to revoke later.
func bestEffortDeviceLabel(ua string) string {
	if ua == "" {
		return "Unknown device"
	}
	browser := "Browser"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		browser = "Safari"
	}
	os := "Unknown OS"
	switch {
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	case strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	}
	return browser + " on " + os + " · " + time.Now().UTC().Format("2006-01-02")
}
