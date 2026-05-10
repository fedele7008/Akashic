package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"akashic/akashic/pkg/email"
	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// /email-config — Phase 9 (revised). DB-backed mailer settings.
//
//   GET   /email-config       → fetch current config (key MASKED)
//   PATCH /email-config       → update fields; service.Reload runs after
//   POST  /email-config/test  → send a test email to a caller-supplied address
//
// Operator-scoped (mTLS gate). The admin BFF proxies these so the
// admin web's "Email" page can render the form + run a test send.
//
// Secret handling: the SendGrid API key is plaintext at rest. GET
// returns a masked placeholder ("••••••••" when set, "" otherwise)
// so the value never crosses the wire on read; PATCH accepts a
// plaintext key (caller knows what they typed). When PATCH omits
// the key field, the stored value is preserved — operators can
// edit other fields without re-typing the key.

const maskedKeyPlaceholder = "••••••••"

// adminEmailConfigView is the wire shape for GET /email-config.
// Mirrors models.EmailConfig but with the API key masked. We keep
// the boolean `sendgrid_api_key_set` so the admin UI can render
// "configured" vs "not configured" without needing to compare
// against the placeholder string.
type adminEmailConfigView struct {
	Provider           string `json:"provider"`
	FromAddress        string `json:"from_address"`
	FromName           string `json:"from_name"`
	SendGridAPIKey     string `json:"sendgrid_api_key"`
	SendGridAPIKeySet  bool   `json:"sendgrid_api_key_set"`
	VerifyURLBase      string `json:"verify_url_base"`
	UpdatedAt          string `json:"updated_at"`
	UpdatedBy          string `json:"updated_by,omitempty"`
	IsConfigured       bool   `json:"is_configured"`
}

func toEmailConfigView(c *models.EmailConfig, isConfigured bool) adminEmailConfigView {
	v := adminEmailConfigView{
		Provider:          c.Provider,
		FromAddress:       c.FromAddress,
		FromName:          c.FromName,
		VerifyURLBase:     c.VerifyURLBase,
		SendGridAPIKeySet: c.HasSendGridKey(),
		UpdatedAt:         c.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		IsConfigured:      isConfigured,
	}
	if c.HasSendGridKey() {
		v.SendGridAPIKey = maskedKeyPlaceholder
	}
	if c.UpdatedBy != nil {
		v.UpdatedBy = c.UpdatedBy.String()
	}
	return v
}

func (s *Server) handleAdminEmailConfig(w http.ResponseWriter, r *http.Request) {
	if s.emailService == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"email-config service not yet wired", nil))
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.adminGetEmailConfig(w, r)
	case http.MethodPatch:
		s.adminPatchEmailConfig(w, r)
	default:
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"GET or PATCH only on /email-config", nil))
	}
}

func (s *Server) adminGetEmailConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.emailService.Get(r.Context())
	if err != nil {
		s.logger.App.Error("adminGetEmailConfig: get failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load email config", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"email_config": toEmailConfigView(cfg, s.emailService.IsConfigured()),
	}))
}

// adminPatchEmailConfigRequest is the wire body for PATCH.
// Pointer fields preserve "leave unchanged" / "set to empty".
//
// Special key handling: when the caller sends the masked
// placeholder string ("••••••••") as the API key, we treat it as
// "leave unchanged" — that's what GET returned, and the admin web
// echoes it back unedited if the operator only changed other
// fields. Without this, every PATCH that didn't re-type the key
// would clobber it with the mask string.
type adminPatchEmailConfigRequest struct {
	Provider       *string `json:"provider,omitempty"`
	FromAddress    *string `json:"from_address,omitempty"`
	FromName       *string `json:"from_name,omitempty"`
	SendGridAPIKey *string `json:"sendgrid_api_key,omitempty"`
	VerifyURLBase  *string `json:"verify_url_base,omitempty"`
	CallerUserID   string  `json:"caller_user_id,omitempty"`
}

func (s *Server) adminPatchEmailConfig(w http.ResponseWriter, r *http.Request) {
	var req adminPatchEmailConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	// Treat the masked placeholder as "leave key unchanged" so
	// admins editing other fields don't accidentally clobber the
	// stored API key with the mask string.
	if req.SendGridAPIKey != nil && *req.SendGridAPIKey == maskedKeyPlaceholder {
		req.SendGridAPIKey = nil
	}

	params := email.UpdateParams{
		Provider:       req.Provider,
		FromAddress:    req.FromAddress,
		FromName:       req.FromName,
		SendGridAPIKey: req.SendGridAPIKey,
		VerifyURLBase:  req.VerifyURLBase,
	}
	if req.CallerUserID != "" {
		callerID, err := uuid.Parse(req.CallerUserID)
		if err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("INVALID_REQUEST",
					"caller_user_id must be a valid uuid", nil))
			return
		}
		params.CallerID = callerID
	}

	updated, err := s.emailService.Update(r.Context(), params)
	if errors.Is(err, email.ErrInvalidConfig) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED", err.Error(), nil))
		return
	}
	if err != nil {
		s.logger.App.Error("adminPatchEmailConfig: update failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update email config", nil))
		return
	}

	s.logger.Security.Info("email config updated",
		zap.String("caller_user_id", req.CallerUserID),
		zap.Strings("changed_fields", changedEmailConfigFields(req)))

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"email_config": toEmailConfigView(updated, s.emailService.IsConfigured()),
	}))
}

// adminTestEmailRequest is POST /email-config/test body.
type adminTestEmailRequest struct {
	To string `json:"to"`
}

// handleAdminTestEmail sends a one-off test email. The caller
// supplies a recipient (typically the admin's own address); we
// fire a small "Akashic test email" message and return whether
// the send succeeded. Lets operators verify the config without
// going through a full signup-and-verify dance.
func (s *Server) handleAdminTestEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"POST only", nil))
		return
	}
	if s.emailService == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"email-config service not yet wired", nil))
		return
	}
	var req adminTestEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()
	to := strings.TrimSpace(req.To)
	if to == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"`to` is required", nil))
		return
	}
	if !s.emailService.IsConfigured() {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("EMAIL_NOT_CONFIGURED",
				"no email provider configured; save a valid config first", nil))
		return
	}

	msg := mailer.Message{
		To:      to,
		Subject: "Akashic test email",
		Text: "This is a test email from Akashic.\n\n" +
			"If you received this, your outbound-email config is working.\n\n" +
			"— Akashic",
		HTML: `<!DOCTYPE html>
<html><body style="font-family:system-ui,sans-serif;padding:24px;">
<h2 style="margin:0 0 12px 0;">Akashic test email</h2>
<p>This is a test email from Akashic.</p>
<p>If you received this, your outbound-email config is working.</p>
<p style="color:#888;font-size:0.875rem;">— Akashic</p>
</body></html>`,
	}
	if err := s.emailService.Send(r.Context(), msg); err != nil {
		s.logger.App.Warn("test email send failed",
			zap.String("to", to), zap.Error(err))
		response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
			"sent":  false,
			"error": err.Error(),
		}))
		return
	}
	s.logger.Security.Info("test email sent",
		zap.String("to", to))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"sent": true,
		"to":   to,
	}))
}

func changedEmailConfigFields(req adminPatchEmailConfigRequest) []string {
	out := []string{}
	if req.Provider != nil {
		out = append(out, "provider")
	}
	if req.FromAddress != nil {
		out = append(out, "from_address")
	}
	if req.FromName != nil {
		out = append(out, "from_name")
	}
	if req.SendGridAPIKey != nil {
		out = append(out, "sendgrid_api_key")
	}
	if req.VerifyURLBase != nil {
		out = append(out, "verify_url_base")
	}
	return out
}
