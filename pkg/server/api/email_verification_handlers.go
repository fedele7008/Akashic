package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /users/me/send-verification-email — Phase 9b.
//
// Bearer-authenticated. Sends a fresh verification email to the
// caller's CURRENT email address (looked up from LDAP, since
// User.Email lives in LDAP not PG). Supersedes any prior
// outstanding token. Rate limited (the api-server's own middleware
// stack already throttles bearer-auth requests).
//
// Refuses with `EMAIL_NOT_AVAILABLE` when the mailer is in nop
// mode. Refuses with `ALREADY_VERIFIED` when the user is already
// verified (no point burning a token).
//
// Method: POST. Body: empty (the bearer's `sub` identifies the
// user; nothing else to ask).

func (s *Server) handleSendVerificationEmail(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}
	s.mu.RLock()
	emailSvc := s.emailSvc
	verStore := s.emailVerificationStore
	s.mu.RUnlock()
	verifyBase := ""
	if emailSvc != nil {
		verifyBase = emailSvc.VerifyURLBase(r.Context())
	}
	if emailSvc == nil || !emailSvc.IsConfigured() {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("EMAIL_NOT_AVAILABLE",
				"this deployment doesn't have an email service configured; "+
					"contact your administrator if you need to verify your email", nil))
		return
	}
	if verStore == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY",
				"verification store not yet wired", nil))
		return
	}

	// Look up the user (PG). Email comes from LDAP.
	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("USER_NOT_FOUND", "no such user", nil))
			return
		}
		s.logger.App.Error("sendVerification: user lookup", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load user", nil))
		return
	}
	if user.EmailVerified {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("ALREADY_VERIFIED",
				"your email is already verified", nil))
		return
	}

	// Pull email from LDAP.
	if s.ldapClient == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY", "ldap client not yet wired", nil))
		return
	}
	info, err := s.ldapClient.GetUserByDN(user.LdapDN)
	if err != nil || info == nil {
		s.logger.App.Error("sendVerification: ldap lookup",
			zap.String("user_id", uid.String()),
			zap.String("ldap_dn", user.LdapDN),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not read your email from the directory", nil))
		return
	}
	email := strings.TrimSpace(info.Email)
	if email == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("NO_EMAIL_ON_FILE",
				"your account has no email address; contact your administrator", nil))
		return
	}

	displayName := strings.TrimSpace(info.DisplayName)
	if displayName == "" {
		// Fall back to the email's local part.
		if at := strings.IndexByte(email, '@'); at > 0 {
			displayName = email[:at]
		} else {
			displayName = "there"
		}
	}

	if err := s.sendVerificationEmail(r.Context(), uid, email, displayName, verifyBase); err != nil {
		if errors.Is(err, mailer.ErrNotConfigured) {
			// Race: mailer was reconfigured to nop between the gate
			// at top of handler and the actual send. Surface as the
			// same EMAIL_NOT_AVAILABLE so the client UX is uniform.
			response.WriteJSON(w, http.StatusServiceUnavailable,
				response.Fail("EMAIL_NOT_AVAILABLE",
					"email service not configured", nil))
			return
		}
		s.logger.App.Error("sendVerification: mail send",
			zap.String("user_id", uid.String()),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("SEND_FAILED",
				"could not send verification email; please try again later", nil))
		return
	}

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"sent":  true,
		"email": email,
	}))
}

// sendVerificationEmail is the api-server's local copy of the
// auth-server's send helper. Same logic, different field source —
// the api-server holds its own mailer + repo + verify-URL state
// (set in akashic core context), so callers don't have to reach
// across servers. We accept this small duplication over a shared
// helper module because it keeps the two surfaces independently
// testable + nil-tolerant.
func (s *Server) sendVerificationEmail(
	ctx context.Context,
	userID uuid.UUID,
	email, displayName, verifyBase string,
) error {
	s.mu.RLock()
	emailSvc := s.emailSvc
	store := s.emailVerificationStore
	s.mu.RUnlock()
	if emailSvc == nil || !emailSvc.IsConfigured() {
		return mailer.ErrNotConfigured
	}
	if store == nil {
		return errors.New("email-verification store not wired")
	}
	if verifyBase == "" {
		return errors.New("verify_url_base not configured")
	}
	rawToken, err := store.Create(ctx, userID, email)
	if err != nil {
		return err
	}
	verifyURL := strings.TrimRight(verifyBase, "/") + "/verify-email?token=" + url.QueryEscape(rawToken)
	msg, err := mailer.Render("verification", map[string]any{
		"TenantName":     "Akashic",
		"DisplayName":    displayName,
		"VerifyURL":      verifyURL,
		"ExpiresInHours": 24,
	})
	if err != nil {
		return err
	}
	msg.To = email
	if err := emailSvc.Send(ctx, msg); err != nil {
		return err
	}
	s.logger.Security.Info("verification email sent (resend)",
		zap.String("user_id", userID.String()),
		zap.String("email", email))
	return nil
}
