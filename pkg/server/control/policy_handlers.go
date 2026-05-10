package control

import (
	"encoding/json"
	"errors"
	"net/http"

	"akashic/akashic/pkg/policy"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Operator-side tenant-policy CRUD — Phase 8c.6.
//
// Surface:
//   GET   /policy        → fetch the singleton row
//   PATCH /policy        → update; body fields are partial (omitted = leave unchanged)
//
// caller_user_id flows in from the BFF's session-aware proxy so
// the audit `updated_by` column gets populated. CLI calls omit it
// (the CLI has no per-user identity tied to the static client cert).

// handleAdminPolicy dispatches GET / PATCH on /policy.
func (s *Server) handleAdminPolicy(w http.ResponseWriter, r *http.Request) {
	if s.policySvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"policy service not yet wired", nil))
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.adminGetPolicy(w, r)
	case http.MethodPatch:
		s.adminPatchPolicy(w, r)
	default:
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"GET or PATCH only on /policy", nil))
	}
}

func (s *Server) adminGetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.policySvc.Get(r.Context())
	if err != nil {
		s.logger.App.Error("adminGetPolicy: get failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load policy", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"policy": p,
	}))
}

// adminPatchPolicyRequest is the wire body for PATCH /policy.
// Pointer fields preserve the "leave unchanged" / "set to false"
// distinction the policy.Service.Update method needs.
type adminPatchPolicyRequest struct {
	PasswordMinLength              *int    `json:"password_min_length,omitempty"`
	PasswordRequireUppercase       *bool   `json:"password_require_uppercase,omitempty"`
	PasswordRequireNumber          *bool   `json:"password_require_number,omitempty"`
	PasswordRequireSpecial         *bool   `json:"password_require_special,omitempty"`
	SignupEnabled                  *bool   `json:"signup_enabled,omitempty"`
	UIDChangeCooldownDays          *int    `json:"uid_change_cooldown_days,omitempty"`
	AccessTokenTTLSeconds          *int    `json:"access_token_ttl_seconds,omitempty"`
	RefreshTokenSlidingTTLSeconds  *int    `json:"refresh_token_sliding_ttl_seconds,omitempty"`
	RefreshTokenAbsoluteTTLSeconds *int    `json:"refresh_token_absolute_ttl_seconds,omitempty"`
	AllowedClientScopes            *string `json:"allowed_client_scopes,omitempty"`
	CallerUserID                   string  `json:"caller_user_id,omitempty"`
}

func (s *Server) adminPatchPolicy(w http.ResponseWriter, r *http.Request) {
	var req adminPatchPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	params := policy.UpdateParams{
		PasswordMinLength:              req.PasswordMinLength,
		PasswordRequireUppercase:       req.PasswordRequireUppercase,
		PasswordRequireNumber:          req.PasswordRequireNumber,
		PasswordRequireSpecial:         req.PasswordRequireSpecial,
		SignupEnabled:                  req.SignupEnabled,
		UIDChangeCooldownDays:          req.UIDChangeCooldownDays,
		AccessTokenTTLSeconds:          req.AccessTokenTTLSeconds,
		RefreshTokenSlidingTTLSeconds:  req.RefreshTokenSlidingTTLSeconds,
		RefreshTokenAbsoluteTTLSeconds: req.RefreshTokenAbsoluteTTLSeconds,
		AllowedClientScopes:            req.AllowedClientScopes,
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

	updated, err := s.policySvc.Update(r.Context(), params)
	if errors.Is(err, policy.ErrInvalidPolicy) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED", err.Error(), nil))
		return
	}
	if err != nil {
		s.logger.App.Error("adminPatchPolicy: update failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update policy", nil))
		return
	}

	s.logger.Security.Info("tenant policy updated",
		zap.String("caller_user_id", req.CallerUserID),
		zap.Any("changed_fields", changedPolicyFields(req)))

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"policy": updated,
	}))
}

func changedPolicyFields(req adminPatchPolicyRequest) []string {
	out := []string{}
	if req.PasswordMinLength != nil {
		out = append(out, "password_min_length")
	}
	if req.PasswordRequireUppercase != nil {
		out = append(out, "password_require_uppercase")
	}
	if req.PasswordRequireNumber != nil {
		out = append(out, "password_require_number")
	}
	if req.PasswordRequireSpecial != nil {
		out = append(out, "password_require_special")
	}
	if req.SignupEnabled != nil {
		out = append(out, "signup_enabled")
	}
	if req.UIDChangeCooldownDays != nil {
		out = append(out, "uid_change_cooldown_days")
	}
	if req.AccessTokenTTLSeconds != nil {
		out = append(out, "access_token_ttl_seconds")
	}
	if req.RefreshTokenSlidingTTLSeconds != nil {
		out = append(out, "refresh_token_sliding_ttl_seconds")
	}
	if req.RefreshTokenAbsoluteTTLSeconds != nil {
		out = append(out, "refresh_token_absolute_ttl_seconds")
	}
	if req.AllowedClientScopes != nil {
		out = append(out, "allowed_client_scopes")
	}
	return out
}
