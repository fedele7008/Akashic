package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 8 user-management endpoints. All gated by mTLS — the
// requireClientIdentity middleware in routes.go restricts them to
// callers presenting a portal-client cert (CN portal.akashic.local)
// or admin-bff (for future admin-side overrides).
//
// "Per-user" endpoints take an `X-Akashic-On-Behalf-Of` header that
// identifies the end user the request acts upon. The portal sets this
// after verifying its own session cookie. Akashic trusts the header
// because the *portal* is mTLS-authenticated and on the allowlist —
// same trust model as Phase 7's bootstrap-create-root (the BFF was
// trusted to forward bootstrap submissions verbatim). A compromised
// portal can act as any user; that's the same blast radius as a
// compromised admin-bff. Tightening this further (e.g. via per-user
// JWTs threaded through every call) is a Phase 9+ refinement.

// onBehalfOfHeader is the canonical name. The portal SHOULD only set
// this on requests where it has just verified the user's session
// cookie; akashic does no verification beyond UUID-format checking.
const onBehalfOfHeader = "X-Akashic-On-Behalf-Of"

// requireOnBehalfOf wraps a handler that needs to know "which user is
// this request about." Reads X-Akashic-On-Behalf-Of, validates it as
// a UUID, and stashes it in the request context for the handler. On
// missing/invalid header, returns 400 BAD_ON_BEHALF_OF immediately.
func requireOnBehalfOf(next func(http.ResponseWriter, *http.Request, uuid.UUID)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get(onBehalfOfHeader))
		if raw == "" {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("BAD_ON_BEHALF_OF",
					onBehalfOfHeader+" header is required",
					nil))
			return
		}
		uid, err := uuid.Parse(raw)
		if err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("BAD_ON_BEHALF_OF",
					onBehalfOfHeader+" is not a valid UUID",
					nil))
			return
		}
		next(w, r, uid)
	}
}

// requireUserDeps is a lightweight gate that returns 503 if the user
// repository / LDAP client haven't been wired in yet. Keeps the new
// Phase 8 handlers safe to register even on a partially-initialized
// control server (during a phased boot).
func (s *Server) requireUserDeps(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.userRepo == nil || s.ldapClient == nil {
			response.WriteJSON(w, http.StatusServiceUnavailable,
				response.Fail("USER_DEPS_NOT_READY",
					"user-management dependencies not initialized",
					nil))
			return
		}
		next(w, r)
	}
}

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

// handleRegisterUser is POST /users/register. Phase 8 self-service
// signup. Always creates a user_type=user account; root and admin
// accounts are created via separate paths (bootstrap and admin-bff
// promotion respectively).
//
// Validation:
//   - username, email, password are required
//   - password must satisfy DefaultPasswordPolicy
//   - email must look like an email (cheap regex; LDAP accepts what
//     it accepts, no need to over-validate here)
//   - username must not already exist in LDAP
//
// The created user's email_verified flag stays false in Phase 8 —
// Phase 9 wires the verification flow that sets it true.
func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}

	var req registerUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body",
				nil))
		return
	}
	defer r.Body.Close()

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)

	if req.Username == "" || req.Email == "" || req.Password == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"username, email, and password are required",
				nil))
		return
	}
	if !looksLikeEmail(req.Email) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"email is not a valid email address",
				nil))
		return
	}

	policy := auth.DefaultPasswordPolicy()
	if err := policy.Validate(req.Password); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("PASSWORD_POLICY_VIOLATION", err.Error(), nil))
		return
	}

	// Username uniqueness check (against LDAP, the source of truth).
	exists, err := s.ldapClient.UserExists(req.Username)
	if err != nil {
		s.logger.App.Error("register: LDAP UserExists failed",
			zap.String("username", req.Username),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not check username availability", nil))
		return
	}
	if exists {
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("USERNAME_TAKEN",
				"that username is already in use",
				nil))
		return
	}

	createReq := &models.CreateUserRequest{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		UserType:    models.UserTypeUser, // Phase 8: self-service is always plain user
		DisplayName: req.DisplayName,
	}
	user, err := s.userRepo.CreateUser(r.Context(), createReq, req.Password)
	if err != nil {
		s.logger.App.Error("register: CreateUser failed",
			zap.String("username", req.Username),
			zap.Error(err))
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

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
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

func (s *Server) handlePatchMe(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
	if r.Method != http.MethodPatch {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only PATCH is allowed", nil))
		return
	}

	var req patchMeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	if req.DisplayName == nil && req.Email == nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"at least one of display_name or email must be provided",
				nil))
		return
	}
	if req.Email != nil && !looksLikeEmail(*req.Email) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"email is not a valid email address",
				nil))
		return
	}

	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("USER_NOT_FOUND", "no such user", nil))
		return
	}

	// Update LDAP attributes (cn for display_name, mail for email).
	// Both writes happen via a single LDAP Modify request when both
	// are supplied — atomic per-entry so we can't end up with the
	// cn updated but mail rolled back.
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

// ldapModifyUser issues a single LDAP Modify-Replace on the named
// attributes. Used by handlePatchMe; broken out so it can grow more
// fields without bloating the handler.
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

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}

	var req passwordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
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
		// Surface "wrong old password" specifically; everything else
		// is a server-side problem.
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

// handleForgotPasswordHelp is a Phase 8 stub that returns operator-
// configured contact info for users who need a password reset.
// Phase 9 replaces this with a real token-based reset flow once
// email infrastructure lands.
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

// looksLikeEmail does the cheapest possible "is this an email"
// validation: contains '@', has at least one char on each side, and
// the right side has a '.'. The LDAP server's schema is the real
// authority on what a valid email looks like; this just stops the
// most obvious typos before they get there.
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	right := s[at+1:]
	if !strings.Contains(right, ".") {
		return false
	}
	return true
}

// _ keeps fmt imported even when no error path uses it directly;
// users_handlers.go logs via zap, but format-string assistance is
// kept available for future expansion. Remove if/when unused.
var _ = fmt.Sprintf
