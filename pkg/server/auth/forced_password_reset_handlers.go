package auth

import (
	"errors"
	"net/http"
	"net/url"

	"akashic/akashic/pkg/mfa"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /forced-password-reset — Phase 9d. The terminal step of the
// "admin issued a temporary password" flow.
//
// Lifecycle:
//
//  1. Admin POSTs /users/<id>/reset-password (control plane). The
//     handler stamps User.PasswordResetRequired = true and replaces
//     the LDAP userPassword with a freshly-generated temp password.
//  2. User signs in at /login/submit with the temp password. The
//     auth-server attaches ResetRequired=true to the partial session
//     and 302s to /forced-password-reset (instead of returnTo).
//  3. Every gated endpoint (/authorize today; future endpoints
//     follow the same pattern) re-checks sess.ResetRequired and
//     bounces back here.
//  4. User submits /forced-password-reset/submit. We validate the
//     new password against the live tenant policy, replace the LDAP
//     entry, clear User.PasswordResetRequired, clear sess.ResetRequired,
//     rotate the session ID (defense against partial-session-cookie
//     leak), and revoke every live RT.
//  5. User lands back on returnTo (or the signed-in landing) with a
//     fully-authenticated session.
//
// The flow is deliberately separate from /forgot-password/reset
// even though the post-LDAP work is identical: forgot-password is
// gated by a Redis "ready cookie" minted only after a verified
// 6-digit code, whereas this flow is gated by an existing partial
// session. Sharing one POST endpoint would mean threading "which
// authorization channel got us here" through the body, which is
// more bookkeeping for less clarity.

func (s *Server) handleForcedPasswordResetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, sid, ok := s.requirePartialSession(w, r)
	if !ok {
		return
	}
	// If the user already cleared the gate (e.g., they hit the back
	// button after a successful reset and the session is now full),
	// send them on to returnTo instead of re-prompting.
	if !sess.ResetRequired {
		s.redirectToReturnToOrLanding(w, r, sess, safeReturnTo(r.URL.Query().Get("return_to")))
		return
	}
	_ = sid // GET path only reads sess; sid is needed by the POST sibling.
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	policy := s.passwordPolicy(r.Context())
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forced_password_reset.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":  csrf,
		"MinLength":  policy.MinLength,
		"PolicyHint": passwordPolicyHint(policy),
		"ReturnTo":   returnTo,
	})
}

func (s *Server) handleForcedPasswordResetSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, sid, ok := s.requirePartialSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderForcedResetError(w, r, "", "Could not parse form. Please retry.")
		return
	}
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))
	if !s.verifyLoginCSRF(r) {
		s.renderForcedResetError(w, r, returnTo, "Form expired. Please reload and try again.")
		return
	}

	// Defense-in-depth: if somebody got here without ResetRequired
	// (e.g., a stale tab), don't accept a password change through
	// this endpoint — they should use the in-profile change-password
	// surface instead. Send them to returnTo so they don't loop.
	if !sess.ResetRequired {
		s.redirectToReturnToOrLanding(w, r, sess, returnTo)
		return
	}

	password := r.PostForm.Get("password")
	confirm := r.PostForm.Get("password_confirm")
	if password == "" || confirm == "" {
		s.renderForcedResetError(w, r, returnTo, "Both password fields are required.")
		return
	}
	if password != confirm {
		s.renderForcedResetError(w, r, returnTo, "Passwords don't match.")
		return
	}
	policy := s.passwordPolicy(r.Context())
	if err := policy.Validate(password); err != nil {
		s.renderForcedResetError(w, r, returnTo, err.Error())
		return
	}

	s.mu.RLock()
	ldapClient := s.authService.LDAPClient()
	userRepo := s.authService.UserRepository()
	rtRepo := s.refreshTokenRepo
	sessionStore := s.sessionStore
	s.mu.RUnlock()
	if ldapClient == nil || userRepo == nil || sessionStore == nil {
		s.renderForcedResetError(w, r, returnTo,
			"The server isn't ready. Try again in a moment.")
		return
	}

	userID, err := uuid.Parse(sess.UserID)
	if err != nil {
		// Should be unreachable — sessions only carry valid UUIDs.
		// Treat as a hard reset of state: kill the session and bounce
		// to /login.
		_ = sessionStore.Delete(r.Context(), sid)
		s.clearAuthSessionCookie(w)
		http.Redirect(w, r, loginURLWithReturnTo(returnTo, ""), http.StatusSeeOther)
		return
	}

	user, err := userRepo.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			_ = sessionStore.Delete(r.Context(), sid)
			s.clearAuthSessionCookie(w)
			http.Redirect(w, r, loginURLWithReturnTo(returnTo, ""), http.StatusSeeOther)
			return
		}
		s.logger.App.Error("forced-reset: user lookup",
			zap.String("user_id", userID.String()), zap.Error(err))
		s.renderForcedResetError(w, r, returnTo, "Server error. Please retry.")
		return
	}

	// LDAP first — if this fails, none of the gate-clearing happens.
	if err := ldapClient.ResetPasswordAsAdmin(user.LdapDN, password); err != nil {
		s.logger.Security.Error("forced-reset: LDAP modify failed",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN), zap.Error(err))
		s.renderForcedResetError(w, r, returnTo,
			"Could not update your password. Please retry.")
		return
	}

	// Clear the user-level gate. Best-effort: a failure here would
	// re-trigger the forced-reset on the next sign-in, which is
	// harmless (just annoying). The audit log captures the
	// inconsistency for operator follow-up.
	if err := userRepo.SetPasswordResetRequired(r.Context(), user.ID, false); err != nil {
		s.logger.App.Warn("forced-reset: failed to clear password_reset_required flag",
			zap.String("user_id", user.ID.String()), zap.Error(err))
	}

	// Revoke all live RTs. Same rationale as the forgot-password
	// flow: an attacker with an exfiltrated RT shouldn't survive a
	// password reset of the underlying account.
	if rtRepo != nil {
		if n, err := rtRepo.RevokeAllForUser(r.Context(), user.ID, "forced_password_reset"); err != nil {
			s.logger.App.Warn("forced-reset: RT revoke failed",
				zap.String("user_id", user.ID.String()), zap.Error(err))
		} else if n > 0 {
			s.logger.Security.Info("forced-reset: refresh tokens revoked",
				zap.String("user_id", user.ID.String()),
				zap.Int64("revoked", n))
		}
	}

	// Rotate the session ID. Defense against partial-session cookie
	// leak: the old SID may have been observed by something between
	// /login/submit and here (browser extension, shared screen, etc.);
	// rotating ensures that even if it leaks now, it can't be replayed
	// against the upgraded session.
	upgraded := *sess
	upgraded.ResetRequired = false
	_ = sessionStore.Delete(r.Context(), sid)
	newSID, err := sessionStore.Create(r.Context(), &upgraded)
	if err != nil {
		s.logger.App.Error("forced-reset: session rotation failed", zap.Error(err))
		// The user's password is already changed; they can sign in
		// again on the next request. Send them to /login with a
		// success notice.
		s.clearAuthSessionCookie(w)
		http.Redirect(w, r, loginURLWithReturnTo(returnTo, "password_reset"),
			http.StatusSeeOther)
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

	s.logger.Security.Info("forced-reset: completed",
		zap.String("user_id", user.ID.String()))

	// Phase 9f: re-evaluate MFA on the freshly-rotated session.
	// The just-completed reset gives the user a known-good password;
	// MFA's job (proving "this is the actual user") still applies
	// to the new session and should fire if the account opts in or
	// the intended client requires it.
	s.mu.RLock()
	mfaSvc := s.mfaSvc
	s.mu.RUnlock()
	if mfaSvc != nil {
		clientID := extractClientIDFromReturnTo(returnTo)
		need, mErr := mfaSvc.IsRequired(r.Context(), user, clientID)
		if mErr != nil {
			s.logger.App.Warn("forced-reset: mfa IsRequired errored; allowing through",
				zap.Error(mErr))
		}
		if need {
			cookieVal := readCookie(r, mfa.CookieName)
			trusted := false
			if cookieVal != "" {
				ok, _ := mfaSvc.IsTrustedDevice(r.Context(), user.ID, cookieVal)
				trusted = ok
			}
			if !trusted {
				if err := s.startMFAChallenge(r.Context(), w, r, &upgraded, newSID, user, returnTo, clientID); err != nil {
					s.logger.App.Error("forced-reset: startMFAChallenge",
						zap.Error(err))
					// Soft-fail: continue without MFA rather than
					// leaving the user stuck post-reset. The
					// admin's audit log captures the inconsistency.
				} else {
					return
				}
			}
		}
	}

	s.redirectToReturnToOrLanding(w, r, &upgraded, returnTo)
}

// requirePartialSession loads the auth session by cookie and returns
// it. Returns false (after writing the redirect) when no usable
// session exists — caller should return immediately.
//
// "Partial" only in the calling-convention sense — the function is
// happy to return a fully-authenticated session too. The caller
// decides what to do with sess.ResetRequired (the GET branch
// re-prompts on true / forwards on false; the POST branch processes
// on true / forwards on false).
func (s *Server) requirePartialSession(w http.ResponseWriter, r *http.Request) (*oauth.AuthSession, string, bool) {
	s.mu.RLock()
	sessionStore := s.sessionStore
	s.mu.RUnlock()
	if sessionStore == nil {
		http.Error(w, "session store not ready", http.StatusServiceUnavailable)
		return nil, "", false
	}
	sid := readCookie(r, authSessionCookie)
	if sid == "" {
		s.redirectToLogin(w, r)
		return nil, "", false
	}
	sess, err := sessionStore.Get(r.Context(), sid)
	if err != nil {
		s.redirectToLogin(w, r)
		return nil, "", false
	}
	return sess, sid, true
}

// clearAuthSessionCookie removes the auth-session cookie. Used when
// the underlying session is gone (rotation failure / user record
// missing) to keep the browser's state in sync with Redis.
func (s *Server) clearAuthSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// redirectToReturnToOrLanding picks the best post-completion
// destination: the OAuth/portal returnTo when present, otherwise
// the IdP's "you're signed in" landing.
func (s *Server) redirectToReturnToOrLanding(w http.ResponseWriter, r *http.Request, sess *oauth.AuthSession, returnTo string) {
	if returnTo != "" {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
		return
	}
	s.renderSignedInLanding(w, sess.Username)
}

func (s *Server) renderForcedResetError(w http.ResponseWriter, r *http.Request, returnTo, msg string) {
	policy := s.passwordPolicy(r.Context())
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forced_password_reset.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":  csrf,
		"Error":      msg,
		"MinLength":  policy.MinLength,
		"PolicyHint": passwordPolicyHint(policy),
		"ReturnTo":   returnTo,
	})
}

// forcedResetURLWithReturnTo builds the redirect target used by
// /login/submit and /authorize to deflect a ResetRequired session
// onto the reset page. Notice is reserved for future use (e.g.,
// "your password expired" wording variants) — empty today.
func forcedResetURLWithReturnTo(returnTo, notice string) string {
	q := url.Values{}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	if notice != "" {
		q.Set("notice", notice)
	}
	if len(q) == 0 {
		return "/forced-password-reset"
	}
	return "/forced-password-reset?" + q.Encode()
}

