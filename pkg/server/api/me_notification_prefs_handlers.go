package api

import (
	"encoding/json"
	"net/http"

	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /users/me/notification-preferences — Phase 9g.
//
//   GET   → state snapshot
//   POST  → patch the two toggles
//
// First-party only (toggle changes are account-state mutations, not
// suitable for third-party bearers). When the mailer isn't
// configured we still let the toggles flip — the *intent* survives;
// the send path silently skips at runtime — and the snapshot
// surfaces `mailer_configured` so the widget can render a
// "configured but inactive" hint.

type notificationPrefsView struct {
	LoginEnabled     bool `json:"login_enabled"`
	ApprovalEnabled  bool `json:"approval_enabled"`
	MailerConfigured bool `json:"mailer_configured"`
}

type patchNotificationPrefsRequest struct {
	LoginEnabled    *bool `json:"login_enabled,omitempty"`
	ApprovalEnabled *bool `json:"approval_enabled,omitempty"`
}

// handleMyNotificationPrefs dispatches GET vs POST on
// /users/me/notification-preferences.
func (s *Server) handleMyNotificationPrefs(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	switch r.Method {
	case http.MethodGet:
		s.getMyNotificationPrefs(w, r, uid)
	case http.MethodPost:
		s.patchMyNotificationPrefs(w, r, uid)
	default:
		writeBearerError(w, http.StatusMethodNotAllowed,
			"method_not_allowed",
			"GET or POST only on /users/me/notification-preferences")
	}
}

func (s *Server) getMyNotificationPrefs(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
	s.mu.RLock()
	userRepo := s.userRepo
	emailSvc := s.emailSvc
	s.mu.RUnlock()
	if userRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE", "user repo not yet wired", nil))
		return
	}
	user, err := userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		s.logger.App.Error("notification-prefs: user lookup failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load user", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(notificationPrefsView{
		LoginEnabled:     user.LoginNotificationsEnabled,
		ApprovalEnabled:  user.ApprovalNotificationsEnabled,
		MailerConfigured: emailSvc != nil && emailSvc.IsConfigured(),
	}))
}

func (s *Server) patchMyNotificationPrefs(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
	s.mu.RLock()
	userRepo := s.userRepo
	s.mu.RUnlock()
	if userRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE", "user repo not yet wired", nil))
		return
	}
	var body patchNotificationPrefsRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()
	if body.LoginEnabled == nil && body.ApprovalEnabled == nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"at least one of login_enabled / approval_enabled must be supplied", nil))
		return
	}
	if err := userRepo.SetNotificationPreferences(r.Context(), uid,
		body.LoginEnabled, body.ApprovalEnabled); err != nil {
		s.logger.App.Error("notification-prefs: update failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update preferences", nil))
		return
	}
	s.logger.Security.Info("notification preferences updated",
		zap.String("user_id", uid.String()),
		zap.Any("login_enabled", body.LoginEnabled),
		zap.Any("approval_enabled", body.ApprovalEnabled))
	// Return the fresh state so the widget can sync without another
	// GET round trip.
	s.getMyNotificationPrefs(w, r, uid)
}
