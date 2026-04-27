package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 8 user-management endpoints — moved off the control plane
// to here in the three-server refactor.
//
// Routing model:
//   - PUBLIC   POST /users/register, GET /users/forgot-password-help
//                  (no token required — handler explicitly wrapped in
//                  requirePublic; bearer middleware skipped)
//   - BEARER   GET / PATCH /users/me, POST /users/me/password
//                  (token's `sub` claim identifies the user; no
//                  on-behalf-of header needed)
//
// The BEARER endpoints' user identity comes directly from the access
// token's `sub` claim. The portal forwards the access token; akashic
// trusts the token because it verified the signature against its own
// keystore. No "on-behalf-of" header trust delegation, no mTLS
// — this is the standard OAuth resource-server pattern.

// ─── POST /users/register ──────────────────────────────────────────

type registerUserRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
}

type registerUserResponse struct {
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		LdapDN   string `json:"ldap_dn"`
	} `json:"user"`
}

// handleRegisterUser is POST /users/register — public, unauthenticated.
// Always creates a user_type=user account; root + admin accounts come
// via separate paths (bootstrap and admin-promotion respectively, the
// latter being a Phase 8 control-plane endpoint TBD).
func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}
	if s.userRepo == nil || s.ldapClient == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY",
				"user-management dependencies not initialized", nil))
		return
	}

	var req registerUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Username == "" || req.Email == "" || req.Password == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"username, email, and password are required", nil))
		return
	}
	if !looksLikeEmail(req.Email) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"email is not a valid email address", nil))
		return
	}

	policy := auth.DefaultPasswordPolicy()
	if err := policy.Validate(req.Password); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("PASSWORD_POLICY_VIOLATION", err.Error(), nil))
		return
	}

	exists, err := s.ldapClient.UserExists(req.Username)
	if err != nil {
		s.logger.App.Error("register: LDAP UserExists failed",
			zap.String("username", req.Username), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not check username availability", nil))
		return
	}
	if exists {
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("USERNAME_TAKEN",
				"that username is already in use", nil))
		return
	}

	createReq := &models.CreateUserRequest{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		UserType:    models.UserTypeUser,
		DisplayName: req.DisplayName,
	}
	user, err := s.userRepo.CreateUser(r.Context(), createReq, req.Password)
	if err != nil {
		s.logger.App.Error("register: CreateUser failed",
			zap.String("username", req.Username), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create user", nil))
		return
	}

	s.logger.Security.Info("user registered (self-service)",
		zap.String("user_id", user.ID.String()),
		zap.String("username", req.Username),
		zap.String("ldap_dn", user.LdapDN))

	var resp registerUserResponse
	resp.User.ID = user.ID.String()
	resp.User.Username = req.Username
	resp.User.Email = req.Email
	resp.User.LdapDN = user.LdapDN
	response.WriteJSON(w, http.StatusCreated, response.Success(resp))
}

// ─── GET /users/me ─────────────────────────────────────────────────

type meResponse struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	Email         string  `json:"email"`
	DisplayName   string  `json:"display_name"`
	UserType      string  `json:"user_type"`
	EmailVerified bool    `json:"email_verified"`
	LastLoginAt   *string `json:"last_login_at,omitempty"`
	CreatedAt     string  `json:"created_at"`
}

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET is allowed", nil))
		return
	}
	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("USER_NOT_FOUND", "no such user", nil))
			return
		}
		s.logger.App.Error("getMe: db lookup", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load user", nil))
		return
	}
	ldapInfo, err := s.ldapClient.GetUserByDN(user.LdapDN)
	if err != nil {
		s.logger.App.Error("getMe: LDAP lookup",
			zap.String("dn", user.LdapDN), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load LDAP info", nil))
		return
	}

	resp := meResponse{
		ID:            user.ID.String(),
		Username:      ldapInfo.Username,
		Email:         ldapInfo.Email,
		DisplayName:   ldapInfo.DisplayName,
		UserType:      string(user.UserType),
		EmailVerified: user.EmailVerified,
		CreatedAt:     user.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if user.LastLoginAt != nil {
		s := user.LastLoginAt.UTC().Format("2006-01-02T15:04:05Z")
		resp.LastLoginAt = &s
	}
	response.WriteJSON(w, http.StatusOK, response.Success(resp))
}

// ─── PATCH /users/me ───────────────────────────────────────────────

type patchMeRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Email       *string `json:"email,omitempty"`
}

func (s *Server) handlePatchMe(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPatch {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only PATCH is allowed", nil))
		return
	}
	var req patchMeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	if req.DisplayName == nil && req.Email == nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"at least one of display_name or email must be provided", nil))
		return
	}
	if req.Email != nil && !looksLikeEmail(*req.Email) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"email is not a valid email address", nil))
		return
	}

	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("USER_NOT_FOUND", "no such user", nil))
		return
	}

	if err := s.ldapModifyUser(r.Context(), user.LdapDN, req); err != nil {
		s.logger.App.Error("patchMe: LDAP modify",
			zap.String("dn", user.LdapDN), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update LDAP attributes", nil))
		return
	}
	s.logger.Security.Info("user profile updated",
		zap.String("user_id", uid.String()),
		zap.Bool("display_name_changed", req.DisplayName != nil),
		zap.Bool("email_changed", req.Email != nil))
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"updated": true}))
}

func (s *Server) ldapModifyUser(_ context.Context, dn string, req patchMeRequest) error {
	mods := ldap.NewModifyRequest(dn, nil)
	added := false
	if req.DisplayName != nil {
		mods.Replace("cn", []string{*req.DisplayName})
		added = true
	}
	if req.Email != nil {
		mods.Replace("mail", []string{*req.Email})
		added = true
	}
	if !added {
		return nil
	}
	return s.ldapClient.RawModify(mods)
}

// ─── POST /users/me/password ───────────────────────────────────────

type passwordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}
	var req passwordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	if req.OldPassword == "" || req.NewPassword == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"old_password and new_password are required", nil))
		return
	}
	policy := auth.DefaultPasswordPolicy()
	if err := policy.Validate(req.NewPassword); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("PASSWORD_POLICY_VIOLATION", err.Error(), nil))
		return
	}

	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("USER_NOT_FOUND", "no such user", nil))
		return
	}

	if err := s.ldapClient.ChangePassword(user.LdapDN, req.OldPassword, req.NewPassword); err != nil {
		if strings.Contains(err.Error(), "invalid current password") {
			response.WriteJSON(w, http.StatusUnauthorized,
				response.Fail("INVALID_CREDENTIALS",
					"current password is incorrect", nil))
			return
		}
		s.logger.App.Error("changePassword: LDAP failure",
			zap.String("dn", user.LdapDN), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not change password", nil))
		return
	}
	s.logger.Security.Info("user password changed",
		zap.String("user_id", uid.String()))
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"updated": true}))
}

// ─── GET /users/forgot-password-help ───────────────────────────────

func (s *Server) handleForgotPasswordHelp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET is allowed", nil))
		return
	}
	cfg := s.config.GetConfig()
	contact := cfg.Portal.SupportContact
	if contact == "" {
		contact = "your administrator (operator has not configured a support contact)"
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"phase":           8,
		"self_service":    false,
		"support_contact": contact,
		"message":         "Password reset is not yet self-service. Contact " + contact + " to reset your password.",
	}))
}

// ─── helpers ───────────────────────────────────────────────────────

func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	right := s[at+1:]
	return strings.Contains(right, ".")
}
