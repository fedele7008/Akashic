package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"akashic/akashic/pkg/email"
	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /verify-email — Phase 9b.
//
// Single endpoint:
//   GET /verify-email?token=<raw>
//     Consumes the token (atomically marking the row used), flips
//     `users.email_verified` to true, renders a success or error
//     template. Always GET — clicking a link in an email becomes a
//     GET, and the handler is idempotent enough that the
//     non-CSRF-protected method is safe (the token IS the proof).
//
// Failure modes (all surface the same generic error to the user
// to avoid leaking which exact failure mode triggered):
//   - missing/empty token
//   - token not found in DB
//   - token already consumed
//   - token expired
//   - token superseded by a newer one (used_at non-nil from
//     supersede-on-resend)
//
// Emitted from two places:
//   - signup-time send (best-effort; signup succeeds even if the
//     email send fails)
//   - resend (api-server `/users/me/send-verification-email`)
//
// Both call `SendVerificationEmail()` below, which centralises
// the mint + render + send sequence.

// handleVerifyEmail serves GET /verify-email.
func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	store := s.emailVerificationStore
	db := s.db
	s.mu.RUnlock()
	if store == nil || db == nil {
		s.renderVerifyEmailError(w, http.StatusServiceUnavailable,
			"Server not ready",
			"The verification service isn't ready yet. Please try the link again in a moment.")
		return
	}

	rawToken := strings.TrimSpace(r.URL.Query().Get("token"))
	data, err := store.Consume(r.Context(), rawToken)
	if errors.Is(err, email.ErrVerificationInvalid) {
		s.renderVerifyEmailError(w, http.StatusOK,
			"Verification link expired or already used",
			"This verification link is no longer valid. It may have expired (links last 24 hours), been used already, or been replaced by a newer one.")
		return
	}
	if err != nil {
		s.logger.App.Error("verify-email: consume", zap.Error(err))
		s.renderVerifyEmailError(w, http.StatusInternalServerError,
			"Server error",
			"Something went wrong while verifying your email. Please try the link again.")
		return
	}

	// Token is valid. Flip the user's `email_verified` flag.
	// The Redis token stored the email it was sent TO; if the
	// user's CURRENT email differs (changed mid-verification), we
	// still flip the flag — the action verifies the user's claim
	// about the address that was emailed, regardless of subsequent
	// email-change events. Phase 9c (email-change re-verification)
	// is what re-resets the flag on email change.
	now := time.Now().UTC()
	updates := map[string]any{
		"email_verified":    true,
		"email_verified_at": &now,
	}
	if err := db.WithContext(r.Context()).Model(&models.User{}).
		Where("id = ?", data.UserID).
		Updates(updates).Error; err != nil {
		s.logger.App.Error("verify-email: user update",
			zap.String("user_id", data.UserID.String()),
			zap.Error(err))
		s.renderVerifyEmailError(w, http.StatusInternalServerError,
			"Server error",
			"We verified your link but couldn't update your account. Please contact your administrator.")
		return
	}

	s.logger.Security.Info("email verified",
		zap.String("user_id", data.UserID.String()),
		zap.String("email", data.Email))

	// Look up display name AND current MFA state for the success
	// page. We need user.MFAEnabled to decide whether to render the
	// "Enable MFA" inline toggle — already-on accounts shouldn't be
	// prompted (the prompt is enable-only, and showing it on an
	// already-on account is just confusing UX).
	var u models.User
	displayName := ""
	mfaAlreadyOn := false
	if err := db.WithContext(r.Context()).Where("id = ?", data.UserID).First(&u).Error; err == nil {
		mfaAlreadyOn = u.MFAEnabled
		// User row doesn't carry display_name (it's in LDAP); fall
		// back to the email's local part for a friendly greeting.
		if at := strings.IndexByte(data.Email, '@'); at > 0 {
			displayName = data.Email[:at]
		}
	}

	// Phase 9f follow-up: mint an enable-only setup token when the
	// user is a candidate for inline MFA enablement (mailer
	// configured AND MFA currently off). The plaintext is embedded
	// as a hidden form field on the success page; the user clicks
	// "Enable MFA" → POST /verify-email/enable-mfa consumes the
	// token and flips users.mfa_enabled to true. Token TTL is 5
	// minutes, single-use. Already-on accounts skip the prompt
	// entirely — this token MUST NOT exist as a downgrade vector.
	mailerOn := s.MailerConfigured()
	var setupToken string
	s.mu.RLock()
	setupStore := s.mfaSetupTokens
	s.mu.RUnlock()
	if mailerOn && !mfaAlreadyOn && setupStore != nil {
		tok, terr := setupStore.Create(r.Context(), data.UserID)
		if terr != nil {
			// Best-effort: a token-mint failure shouldn't block the
			// verified-email confirmation. Just suppress the inline
			// toggle and fall through to the plain success page.
			s.logger.App.Warn("verify-email: mint mfa setup token failed",
				zap.String("user_id", data.UserID.String()), zap.Error(terr))
		} else {
			setupToken = tok
		}
	}

	csrf := s.ensureLoginCSRF(w, r)
	renderTemplate(w, "verify_email_result.html.tmpl", http.StatusOK, map[string]any{
		"Title":            "Email verified",
		"Success":          true,
		"DisplayName":      displayName,
		"MailerConfigured": mailerOn,
		// MFASetupToken is non-empty only when the inline-enable
		// toggle should render. Template branches on it.
		"MFASetupToken": setupToken,
		"CSRFToken":     csrf,
	})
}

// renderVerifyEmailError renders the verify-email result template
// with a failure shape. We deliberately don't distinguish the
// underlying cause to the user — every "this link doesn't work"
// case lands on the same screen with the same advice (sign in,
// request a new link from your profile).
func (s *Server) renderVerifyEmailError(w http.ResponseWriter, status int, title, msg string) {
	renderTemplate(w, "verify_email_result.html.tmpl", status, map[string]any{
		"Title":   title,
		"Success": false,
		"Message": msg,
	})
}

// handleVerifyEmailEnableMFA serves POST /verify-email/enable-mfa.
// Phase 9f follow-up. Consumes a one-shot MFA setup token (minted
// during the verify-email success path) and enables MFA for the
// bound user.
//
// Direction-of-change is **enable-only** by design: the form has no
// way to send "disable", and the handler ignores any field that
// could be interpreted as such. The token grants only the narrow
// authority to flip mfa_enabled from false to true; using it to
// disable would be a downgrade attack vector if the verification
// email channel were compromised.
//
// Failure modes:
//   - Token invalid/expired → render a "link expired" page; user
//     can manage MFA from their profile after signing in.
//   - Mailer no longer configured → ignore; the toggle is a no-op
//     security-wise (eligibility silently bypasses), so flipping
//     the bit anyway is fine for "intent survives mailer state."
func (s *Server) handleVerifyEmailEnableMFA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	store := s.mfaSetupTokens
	db := s.db
	s.mu.RUnlock()
	if store == nil || db == nil {
		s.renderVerifyEmailError(w, http.StatusServiceUnavailable,
			"Server not ready",
			"The MFA setup service isn't ready yet. Please retry in a moment.")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.renderVerifyEmailError(w, http.StatusBadRequest,
			"Form error",
			"Could not parse the form. Please try the verification link again.")
		return
	}
	if !s.verifyLoginCSRF(r) {
		s.renderVerifyEmailError(w, http.StatusOK,
			"Form expired",
			"This form has expired. Sign in to your account to enable MFA from your profile.")
		return
	}

	token := strings.TrimSpace(r.PostForm.Get("setup_token"))
	userID, err := store.Consume(r.Context(), token)
	if errors.Is(err, email.ErrMFASetupTokenInvalid) {
		s.renderVerifyEmailError(w, http.StatusOK,
			"MFA setup link expired",
			"This MFA setup window has expired. Sign in to your account and enable MFA from your profile's Two-factor authentication section.")
		return
	}
	if err != nil {
		s.logger.App.Error("verify-email/enable-mfa: consume token",
			zap.Error(err))
		s.renderVerifyEmailError(w, http.StatusInternalServerError,
			"Server error",
			"Something went wrong while enabling MFA. Please try from your profile after signing in.")
		return
	}

	// Atomic-flip-on. We don't gate on the current value: if the
	// user's MFA is already on (race with the user-side widget),
	// the UPDATE is a no-op and the success page renders the same.
	now := time.Now().UTC()
	if err := db.WithContext(r.Context()).Model(&models.User{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"mfa_enabled":    true,
			"mfa_enabled_at": &now,
		}).Error; err != nil {
		s.logger.App.Error("verify-email/enable-mfa: db update",
			zap.String("user_id", userID.String()), zap.Error(err))
		s.renderVerifyEmailError(w, http.StatusInternalServerError,
			"Server error",
			"We accepted your setup request but couldn't enable MFA. Please try from your profile after signing in.")
		return
	}

	s.logger.Security.Info("mfa enabled via post-verify token",
		zap.String("user_id", userID.String()))

	// Render the same template with a different banner — MFA-enabled
	// confirmation, no setup-token (already consumed). The user
	// can still hit Sign in to finish landing on their portal.
	renderTemplate(w, "verify_email_result.html.tmpl", http.StatusOK, map[string]any{
		"Title":       "MFA enabled",
		"Success":     true,
		"MFAEnabled":  true,
		"DisplayName": "",
	})
}

// SendVerificationEmail mints a fresh verification token (super-
// seding any prior un-used token for the user) and sends the
// verification email via the configured mailer. Returns the
// underlying error so the caller can decide whether the failure
// is fatal to its flow:
//
//   - signup: best-effort. Logs + continues. The user can resend
//     from the profile banner.
//   - resend: hard-fail. Caller surfaces a typed error to the
//     widget so the user sees a clear "try again later" message.
//
// When the mailer is in nop mode (`mailer.IsConfigured() == false`),
// returns `mailer.ErrNotConfigured` without writing a token row —
// no point storing tokens we can't deliver.
//
// Tenant name in templates: today we use "Akashic" as a fallback
// because we don't have a per-tenant display name field. Phase 9+
// could grow `TenantPolicy.TenantDisplayName` for white-labelling.
func (s *Server) SendVerificationEmail(
	ctx context.Context,
	userID uuid.UUID,
	email, displayName string,
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
	verifyBase := emailSvc.VerifyURLBase(ctx)
	if verifyBase == "" {
		return errors.New("verify_url_base not configured")
	}

	rawToken, err := store.Create(ctx, userID, email)
	if err != nil {
		return err
	}

	// Build the click-target URL. We URL-encode the token even
	// though base64url is already URL-safe, defensive against any
	// future token format change.
	verifyURL := strings.TrimRight(verifyBase, "/") + "/verify-email?token=" + url.QueryEscape(rawToken)

	if displayName == "" {
		displayName = "there"
	}

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
		// Mark the token unused-still so the operator can examine
		// it for debugging — it'll be superseded on the next send.
		// We deliberately don't roll back the row to avoid a race
		// where Send retries.
		return err
	}

	s.logger.Security.Info("verification email sent",
		zap.String("user_id", userID.String()),
		zap.String("email", email))
	return nil
}

// MailerConfigured is the auth-server's view on whether email is
// available. Exposed for the rare cross-surface reader that holds
// an *auth.Server (e.g., template helpers deciding whether to
// render an email-related link).
func (s *Server) MailerConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.emailSvc != nil && s.emailSvc.IsConfigured()
}
