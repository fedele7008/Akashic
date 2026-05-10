package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"akashic/akashic/pkg/email"
	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"

	"go.uber.org/zap"
)

// /forgot-password — Phase 9c. 6-digit numeric code emailed to
// the user's address; 15-min window; 5 wrong attempts → consumed.
//
// Routes:
//   GET  /forgot-password                   email form
//   POST /forgot-password/submit            issue code, redirect to /verify
//   GET  /forgot-password/sent              "we sent a code" interstitial
//   GET  /forgot-password/verify            code form
//   POST /forgot-password/verify/submit     validate code, set ready cookie
//   GET  /forgot-password/reset             new-password form (gated by cookie)
//   POST /forgot-password/reset/submit      update LDAP, revoke RTs, redirect to /login
//
// Conditional: when the mailer isn't configured, all of these
// render a "contact administrator" stub instead — no part of the
// flow can usefully complete without email.
//
// Info-leak prevention: every email-existence-revealing branch
// (no LDAP user for the address, rate-limited, etc.) lands on the
// same /sent interstitial as a successful submit. Attackers can't
// enumerate registered emails by watching response shapes.

const resetReadyCookieName = "akashic_pwr_ready"

func (s *Server) handleForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if !s.MailerConfigured() {
		s.renderForgotPasswordUnavailable(w, returnTo)
		return
	}
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forgot_password.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken": csrf,
		"Email":     r.URL.Query().Get("email"),
		"ReturnTo":  returnTo,
	})
}

func (s *Server) handleForgotPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderForgotPasswordError(w, r, "", "", "Could not parse form. Please retry.")
		return
	}
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))
	if !s.MailerConfigured() {
		s.renderForgotPasswordUnavailable(w, returnTo)
		return
	}
	if !s.verifyLoginCSRF(r) {
		s.renderForgotPasswordError(w, r, r.PostForm.Get("email"), returnTo,
			"Form expired. Please reload and try again.")
		return
	}
	email := strings.TrimSpace(r.PostForm.Get("email"))
	if email == "" {
		s.renderForgotPasswordError(w, r, "", returnTo, "Email is required.")
		return
	}

	// Issue the code (best-effort; silent on every failure mode
	// per info-leak-prevention rules) and redirect straight to
	// the code-entry page with a "code sent" notice banner. The
	// notice value is identical regardless of whether the email
	// matched a real account — preserves the info-leak posture
	// while removing the prior interstitial step.
	s.tryIssueResetCode(r.Context(), email)
	q := url.Values{}
	q.Set("email", email)
	q.Set("notice", "code_sent")
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	http.Redirect(w, r, "/forgot-password/verify?"+q.Encode(), http.StatusSeeOther)
}

// tryIssueResetCode does the actual code issuance + email send.
// Errors are logged but NOT surfaced to the user — the
// info-leak-prevention rule means the user-facing path looks
// identical regardless of whether the email exists / mailer
// failed / rate limit fired.
func (s *Server) tryIssueResetCode(ctx context.Context, emailAddr string) {
	s.mu.RLock()
	ldapClient := s.authService.LDAPClient()
	userRepo := s.authService.UserRepository()
	store := s.passwordResetStore
	emailSvc := s.emailSvc
	s.mu.RUnlock()
	if ldapClient == nil || userRepo == nil || store == nil || emailSvc == nil {
		return
	}

	// Lookup DN by email (LDAP). Missing → silently no-op.
	dn, err := ldapClient.LookupDNByEmail(emailAddr)
	if err != nil || dn == "" {
		return
	}
	user, err := userRepo.GetUserByLdapDN(ctx, dn)
	if err != nil {
		return
	}

	// LDAP user info for the email template's "Hi <name>" line.
	displayName := emailAddr
	if at := strings.IndexByte(emailAddr, '@'); at > 0 {
		displayName = emailAddr[:at]
	}
	if info, err := ldapClient.GetUserByDN(dn); err == nil && info != nil && info.DisplayName != "" {
		displayName = info.DisplayName
	}

	rawCode, err := store.Create(ctx, user.ID, emailAddr)
	if errors.Is(err, email.ErrResetRateLimited) {
		s.logger.Security.Warn("forgot-password: rate-limited",
			zap.String("email", emailAddr))
		return
	}
	if err != nil {
		s.logger.App.Error("forgot-password: store.Create",
			zap.String("email", emailAddr), zap.Error(err))
		return
	}

	msg, err := mailer.Render("password_reset_code", map[string]any{
		"TenantName":       "Akashic",
		"DisplayName":      displayName,
		"Code":             rawCode,
		"ExpiresInMinutes": int(email.ResetCodeLifetime.Minutes()),
	})
	if err != nil {
		s.logger.App.Error("forgot-password: render template", zap.Error(err))
		return
	}
	msg.To = emailAddr
	if err := emailSvc.Send(ctx, msg); err != nil {
		s.logger.App.Warn("forgot-password: email send failed",
			zap.String("email", emailAddr), zap.Error(err))
		return
	}
	s.logger.Security.Info("forgot-password: code emailed",
		zap.String("user_id", user.ID.String()),
		zap.String("email", emailAddr))
}

func (s *Server) handleForgotPasswordVerifyPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if !s.MailerConfigured() {
		s.renderForgotPasswordUnavailable(w, returnTo)
		return
	}
	emailAddr := strings.TrimSpace(r.URL.Query().Get("email"))
	if emailAddr == "" {
		// No email in query → kick back to /forgot-password,
		// preserving return_to so the user lands somewhere useful
		// after the eventual successful reset.
		dest := "/forgot-password"
		if returnTo != "" {
			dest = "/forgot-password?return_to=" + url.QueryEscape(returnTo)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	// `notice=code_sent` lands here from /submit and from the
	// resend form. Map to a one-line banner; unknown notices
	// render nothing.
	notice := ""
	if r.URL.Query().Get("notice") == "code_sent" {
		notice = "We've sent a 6-digit code. It expires in 15 minutes; check spam if it doesn't appear within a minute or two."
	}
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forgot_password_verify.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken": csrf,
		"Email":     emailAddr,
		"ReturnTo":  returnTo,
		"Notice":    notice,
	})
}

func (s *Server) handleForgotPasswordVerifySubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.MailerConfigured() {
		s.renderForgotPasswordUnavailable(w, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderVerifyError(w, r, "", "", "Could not parse form. Please retry.")
		return
	}
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))
	if !s.verifyLoginCSRF(r) {
		s.renderVerifyError(w, r, r.PostForm.Get("email"), returnTo,
			"Form expired. Please reload and try again.")
		return
	}
	emailAddr := strings.TrimSpace(r.PostForm.Get("email"))
	code := strings.TrimSpace(r.PostForm.Get("code"))
	if emailAddr == "" || code == "" {
		s.renderVerifyError(w, r, emailAddr, returnTo, "Email and code are both required.")
		return
	}

	s.mu.RLock()
	ldapClient := s.authService.LDAPClient()
	userRepo := s.authService.UserRepository()
	store := s.passwordResetStore
	s.mu.RUnlock()
	if ldapClient == nil || userRepo == nil || store == nil {
		s.renderVerifyError(w, r, emailAddr, returnTo, "The reset service isn't ready. Try again in a moment.")
		return
	}

	// Resolve user from email. Same email→DN→user lookup.
	dn, err := ldapClient.LookupDNByEmail(emailAddr)
	if err != nil || dn == "" {
		// Don't say "no such email" — info-leak. Use the same
		// generic message we use for wrong-code.
		s.renderVerifyError(w, r, emailAddr, returnTo, "Invalid or expired code. Try again, or request a new one.")
		return
	}
	user, err := userRepo.GetUserByLdapDN(r.Context(), dn)
	if err != nil {
		s.renderVerifyError(w, r, emailAddr, returnTo, "Invalid or expired code. Try again, or request a new one.")
		return
	}

	if err := store.Verify(r.Context(), user.ID, code); err != nil {
		s.renderVerifyError(w, r, emailAddr, returnTo, "Invalid or expired code. Try again, or request a new one.")
		return
	}

	// Code matched. Mint a ready-cookie scoped to /reset and
	// store its hash → user-id in Redis (5 min TTL). The user's
	// next click on "Set new password" carries this cookie; the
	// reset handler validates it.
	cookieValue, err := store.StartReadyToken(r.Context(), user.ID)
	if err != nil {
		s.logger.App.Error("forgot-password: StartReadyToken", zap.Error(err))
		s.renderVerifyError(w, r, emailAddr, returnTo, "Server error. Please retry.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     resetReadyCookieName,
		Value:    cookieValue,
		Path:     "/forgot-password/reset",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(email.ResetReadyLifetime.Seconds()),
	})
	dest := "/forgot-password/reset"
	if returnTo != "" {
		dest += "?return_to=" + url.QueryEscape(returnTo)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (s *Server) handleForgotPasswordResetPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))
	if !s.MailerConfigured() {
		s.renderForgotPasswordUnavailable(w, returnTo)
		return
	}
	if !s.hasResetReadyCookie(r) {
		dest := "/forgot-password"
		if returnTo != "" {
			dest = "/forgot-password?return_to=" + url.QueryEscape(returnTo)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}
	policy := s.passwordPolicy(r.Context())
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forgot_password_reset.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":  csrf,
		"MinLength":  policy.MinLength,
		"PolicyHint": passwordPolicyHint(policy),
		"ReturnTo":   returnTo,
	})
}

func (s *Server) handleForgotPasswordResetSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.MailerConfigured() {
		s.renderForgotPasswordUnavailable(w, "")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.renderResetError(w, r, "", "Could not parse form. Please retry.")
		return
	}
	returnTo := safeReturnTo(r.PostForm.Get("return_to"))
	if !s.verifyLoginCSRF(r) {
		s.renderResetError(w, r, returnTo, "Form expired. Please reload and try again.")
		return
	}
	cookie, _ := r.Cookie(resetReadyCookieName)
	if cookie == nil || cookie.Value == "" {
		dest := "/forgot-password"
		if returnTo != "" {
			dest = "/forgot-password?return_to=" + url.QueryEscape(returnTo)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	s.mu.RLock()
	store := s.passwordResetStore
	ldapClient := s.authService.LDAPClient()
	userRepo := s.authService.UserRepository()
	rtRepo := s.refreshTokenRepo
	s.mu.RUnlock()
	if store == nil || ldapClient == nil || userRepo == nil {
		s.renderResetError(w, r, returnTo, "The reset service isn't ready. Try again in a moment.")
		return
	}

	// Atomic consume of the ready cookie. Cookie is dead after
	// this call regardless of outcome.
	userID, err := store.ConsumeReadyToken(r.Context(), cookie.Value)
	if err != nil {
		s.clearReadyCookie(w)
		dest := "/forgot-password"
		if returnTo != "" {
			dest = "/forgot-password?return_to=" + url.QueryEscape(returnTo)
		}
		http.Redirect(w, r, dest, http.StatusSeeOther)
		return
	}

	password := r.PostForm.Get("password")
	confirm := r.PostForm.Get("password_confirm")
	if password == "" || confirm == "" {
		s.renderResetError(w, r, returnTo, "Both password fields are required.")
		return
	}
	if password != confirm {
		s.renderResetError(w, r, returnTo, "Passwords don't match.")
		return
	}
	policy := s.passwordPolicy(r.Context())
	if err := policy.Validate(password); err != nil {
		s.renderResetError(w, r, returnTo, err.Error())
		return
	}

	user, err := userRepo.GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			s.clearReadyCookie(w)
			http.Redirect(w, r, loginURLWithReturnTo(returnTo, ""), http.StatusSeeOther)
			return
		}
		s.logger.App.Error("forgot-password: user lookup",
			zap.String("user_id", userID.String()), zap.Error(err))
		s.renderResetError(w, r, returnTo, "Server error. Please retry.")
		return
	}

	// Update LDAP (admin-context modify, no old-password check).
	if err := ldapClient.ResetPasswordAsAdmin(user.LdapDN, password); err != nil {
		s.logger.Security.Error("forgot-password: LDAP modify failed",
			zap.String("user_id", user.ID.String()),
			zap.String("ldap_dn", user.LdapDN), zap.Error(err))
		s.renderResetError(w, r, returnTo, "Could not update your password. Please retry.")
		return
	}

	// Force re-auth on third-party clients: revoke all RTs.
	if rtRepo != nil {
		if n, err := rtRepo.RevokeAllForUser(r.Context(), user.ID, "password_reset"); err != nil {
			s.logger.App.Warn("forgot-password: RT revoke failed",
				zap.String("user_id", user.ID.String()), zap.Error(err))
		} else if n > 0 {
			s.logger.Security.Info("forgot-password: refresh tokens revoked",
				zap.String("user_id", user.ID.String()),
				zap.Int64("revoked", n))
		}
	}

	s.logger.Security.Info("password reset via forgot-password",
		zap.String("user_id", user.ID.String()))

	// Clear the ready cookie + redirect to login with a banner.
	// Preserves return_to so a user mid-OAuth-flow lands back on
	// the right place after signing in with the new password.
	s.clearReadyCookie(w)
	http.Redirect(w, r, loginURLWithReturnTo(returnTo, "password_reset"), http.StatusSeeOther)
}

// loginURLWithReturnTo builds a /login URL preserving an optional
// return_to and an optional notice code. Both args may be empty.
func loginURLWithReturnTo(returnTo, notice string) string {
	q := url.Values{}
	if returnTo != "" {
		q.Set("return_to", returnTo)
	}
	if notice != "" {
		q.Set("notice", notice)
	}
	if len(q) == 0 {
		return "/login"
	}
	return "/login?" + q.Encode()
}

// ─── helpers ────────────────────────────────────────────────────

func (s *Server) hasResetReadyCookie(r *http.Request) bool {
	c, err := r.Cookie(resetReadyCookieName)
	return err == nil && c != nil && c.Value != ""
}

func (s *Server) clearReadyCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     resetReadyCookieName,
		Value:    "",
		Path:     "/forgot-password/reset",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (s *Server) renderForgotPasswordUnavailable(w http.ResponseWriter, returnTo string) {
	renderTemplate(w, "forgot_password_unavailable.html.tmpl", http.StatusOK, map[string]any{
		"ReturnTo": returnTo,
	})
}

func (s *Server) renderForgotPasswordError(w http.ResponseWriter, r *http.Request, emailVal, returnTo, msg string) {
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forgot_password.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken": csrf,
		"Email":     emailVal,
		"ReturnTo":  returnTo,
		"Error":     msg,
	})
}

func (s *Server) renderVerifyError(w http.ResponseWriter, r *http.Request, emailVal, returnTo, msg string) {
	csrf := s.ensureLoginCSRF(w, r)
	// On error, deliberately drop the prior "code sent" notice so
	// we don't show "we sent a code" + "wrong code" together —
	// the error message is what the user needs to act on.
	renderTemplate(w, "forgot_password_verify.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken": csrf,
		"Email":     emailVal,
		"ReturnTo":  returnTo,
		"Error":     msg,
	})
}

func (s *Server) renderResetError(w http.ResponseWriter, r *http.Request, returnTo, msg string) {
	policy := s.passwordPolicy(r.Context())
	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "forgot_password_reset.html.tmpl", http.StatusOK, map[string]any{
		"CSRFToken":  csrf,
		"Error":      msg,
		"MinLength":  policy.MinLength,
		"PolicyHint": passwordPolicyHint(policy),
		"ReturnTo":   returnTo,
	})
}


