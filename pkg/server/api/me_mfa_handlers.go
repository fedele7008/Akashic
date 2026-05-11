package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /users/me/mfa — Phase 9f. User-facing MFA management surface,
// driven by the <akashic-mfa-settings> widget.
//
//   GET    /users/me/mfa                                    state snapshot
//   POST   /users/me/mfa                                    toggle enable/disable
//   POST   /users/me/mfa/trusted-devices/<id>/revoke        revoke a single device
//
// All first-party only — toggling MFA is an account-takeover-grade
// control surface, so a third-party bearer token must not drive it.

// mfaSettingsView is the wire shape returned by GET /users/me/mfa.
type mfaSettingsView struct {
	// Enabled mirrors users.mfa_enabled. Exposed even when the
	// mailer is off so the widget can show "MFA configured but
	// inactive — configure email to re-activate" rather than
	// pretending the user toggled it off.
	Enabled bool `json:"enabled"`
	// MailerConfigured tells the widget whether to render the
	// toggle as interactive vs. greyed-off. Drawn from the api-
	// server's email.Service IsConfigured(). When false, the
	// MFA gate is silently bypassed at login regardless of
	// `Enabled` (see pkg/mfa.IsRequired).
	MailerConfigured bool `json:"mailer_configured"`
	// MaxTrustedDays surfaces the policy ceiling so the widget
	// can show "remember this device for up to N days" copy.
	MaxTrustedDays int `json:"max_trusted_days"`
	// Devices is the user's trusted-device history (any state).
	// Newest first. The widget filters/sorts client-side.
	Devices []trustedDeviceView `json:"devices"`
}

type trustedDeviceView struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	IssuedAt   string  `json:"issued_at"`
	ExpiresAt  string  `json:"expires_at"`
	LastUsedAt string  `json:"last_used_at"`
	RevokedAt  *string `json:"revoked_at,omitempty"`
	// Active is a derived convenience for the widget: true iff
	// not revoked AND not expired.
	Active bool `json:"active"`
}

// handleGetMyMFA is GET-only on /users/me/mfa.
func (s *Server) handleGetMyMFA(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "GET only", nil))
		return
	}
	s.mu.RLock()
	mfaSvc := s.mfaSvc
	userRepo := s.userRepo
	policySvc := s.policySvc
	emailSvc := s.emailSvc
	s.mu.RUnlock()
	if mfaSvc == nil || userRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE", "mfa service not yet wired", nil))
		return
	}

	user, err := userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		s.logger.App.Error("getMyMFA: user lookup failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load user", nil))
		return
	}

	rows, err := mfaSvc.ListDevices(r.Context(), uid)
	if err != nil {
		s.logger.App.Error("getMyMFA: list devices failed",
			zap.String("user_id", uid.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list trusted devices", nil))
		return
	}

	maxDays := 30
	if policySvc != nil {
		if pol, perr := policySvc.Get(r.Context()); perr == nil && pol.MFATrustedDeviceMaxDays > 0 {
			maxDays = pol.MFATrustedDeviceMaxDays
		}
	}
	mailerOn := emailSvc != nil && emailSvc.IsConfigured()

	views := make([]trustedDeviceView, 0, len(rows))
	now := time.Now().UTC()
	for _, row := range rows {
		v := trustedDeviceView{
			ID:         row.ID.String(),
			Label:      row.Label,
			IssuedAt:   row.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
			ExpiresAt:  row.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
			LastUsedAt: row.LastUsedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Active:     row.RevokedAt == nil && row.ExpiresAt.After(now),
		}
		if row.RevokedAt != nil {
			ts := row.RevokedAt.UTC().Format("2006-01-02T15:04:05Z")
			v.RevokedAt = &ts
		}
		views = append(views, v)
	}

	response.WriteJSON(w, http.StatusOK, response.Success(mfaSettingsView{
		Enabled:          user.MFAEnabled,
		MailerConfigured: mailerOn,
		MaxTrustedDays:   maxDays,
		Devices:          views,
	}))
}

// patchMyMFARequest is the body for POST /users/me/mfa.
type patchMyMFARequest struct {
	Enabled bool `json:"enabled"`
}

// handlePatchMyMFA toggles `users.mfa_enabled`. Refuses to enable
// when the mailer isn't configured — surfacing a clear error
// (`MFA_REQUIRES_MAILER`) prevents a stuck state where the toggle
// is on but no codes can be delivered.
func (s *Server) handlePatchMyMFA(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "POST only", nil))
		return
	}
	s.mu.RLock()
	userRepo := s.userRepo
	emailSvc := s.emailSvc
	s.mu.RUnlock()
	if userRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE", "user repo not yet wired", nil))
		return
	}

	var body patchMyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	if body.Enabled {
		if emailSvc == nil || !emailSvc.IsConfigured() {
			response.WriteJSON(w, http.StatusConflict,
				response.Fail("MFA_REQUIRES_MAILER",
					"email is not configured for this deployment; "+
						"MFA can't be enabled until an admin sets up email", nil))
			return
		}
	}

	if err := userRepo.SetMFAEnabled(r.Context(), uid, body.Enabled); err != nil {
		s.logger.App.Error("patchMyMFA: SetMFAEnabled",
			zap.String("user_id", uid.String()),
			zap.Bool("enabled", body.Enabled),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update MFA setting", nil))
		return
	}
	s.logger.Security.Info("mfa: setting toggled",
		zap.String("user_id", uid.String()),
		zap.Bool("enabled", body.Enabled))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"enabled": body.Enabled,
	}))
}

// handleRevokeMyTrustedDevice handles POST
// /users/me/mfa/trusted-devices/<id>/revoke.
func (s *Server) handleRevokeMyTrustedDevice(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "POST only", nil))
		return
	}
	s.mu.RLock()
	mfaSvc := s.mfaSvc
	s.mu.RUnlock()
	if mfaSvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE", "mfa service not yet wired", nil))
		return
	}

	// Path: /users/me/mfa/trusted-devices/<id>/revoke
	rest := strings.TrimPrefix(r.URL.Path, "/users/me/mfa/trusted-devices/")
	rest = strings.TrimSuffix(rest, "/revoke")
	idStr := strings.TrimSuffix(rest, "/")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"device id must be a valid uuid", nil))
		return
	}
	if err := mfaSvc.RevokeDevice(r.Context(), uid, deviceID); err != nil {
		if errors.Is(err, repository.ErrTrustedDeviceNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("DEVICE_NOT_FOUND",
					"trusted device not found, already revoked, or expired", nil))
			return
		}
		s.logger.App.Error("revokeMyTrustedDevice: revoke failed",
			zap.String("user_id", uid.String()),
			zap.String("device_id", deviceID.String()),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not revoke device", nil))
		return
	}
	s.logger.Security.Info("mfa: trusted device revoked",
		zap.String("user_id", uid.String()),
		zap.String("device_id", deviceID.String()))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"revoked": true,
	}))
}

