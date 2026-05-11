package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"
	"akashic/akashic/pkg/usermanagement"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Operator-side user-management endpoints — Phase 8c.2. Mirrors the
// shape of clients_handlers.go: mTLS-gated, requireBootstrapComplete,
// thin handlers over the pkg/usermanagement domain package.
//
// Surface:
//   GET    /users[?limit=&offset=&user_type=&is_disabled=&missing_identity=]
//   GET    /users/<id>
//   PATCH  /users/<id>           body: {user_type?, is_disabled?, caller_user_id?}
//   DELETE /users/<id>?caller_user_id=<uuid>
//
// caller_user_id flows in from the BFF's session-aware proxy so the
// domain layer can run self-protection checks (no demoting / deleting
// yourself). The CLI omits it (uuid.Nil) — CLI has no concept of
// "self" tied to a row.

// userView is the wire shape one user. Mirrors models.User but
// with stable JSON keys, a deterministic timestamp format, and an
// email field joined in from LDAP. Email is the primary identity
// post-Phase-7.5 (the email-uniqueness fix), so the admin Users
// page renders it as the column-1 identity rather than the LDAP
// uid.
type userView struct {
	ID                   string  `json:"id"`
	LdapDN               string  `json:"ldap_dn"`
	Email                string  `json:"email,omitempty"`
	UserType             string  `json:"user_type"`
	IsDisabled           bool    `json:"is_disabled"`
	DisabledAt           string  `json:"disabled_at,omitempty"`
	DisabledBy           string  `json:"disabled_by,omitempty"`
	MissingIdentity      bool    `json:"missing_identity"`
	MissingIdentitySince string  `json:"missing_identity_since,omitempty"`
	EmailVerified        bool    `json:"email_verified"`
	// Phase 9e v2: signed offset on the tenant's default_max_clients.
	// 0 = use the tenant default exactly; positive grants extra
	// slots; negative tightens.
	ClientCountOffset int `json:"client_count_offset"`
	// Phase 9f: per-user MFA opt-in flag.
	MFAEnabled  bool    `json:"mfa_enabled"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// toUserView converts the PG row to the wire shape. `email` is
// supplied by the caller — typically from a per-row LDAP lookup —
// because the PG row alone doesn't carry email (LDAP is the source
// of truth). Pass "" when LDAP is unreachable or the entry is
// missing; the FE falls back to the uid extracted from the DN.
func toUserView(u *models.User, email string) userView {
	v := userView{
		ID:                u.ID.String(),
		LdapDN:            u.LdapDN,
		Email:             email,
		UserType:          string(u.UserType),
		IsDisabled:        u.IsDisabled,
		MissingIdentity:   u.MissingIdentity,
		EmailVerified:     u.EmailVerified,
		ClientCountOffset: u.ClientCountOffset,
		MFAEnabled:        u.MFAEnabled,
		CreatedAt:         u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:         u.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if u.DisabledAt != nil {
		v.DisabledAt = u.DisabledAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if u.DisabledBy != nil {
		v.DisabledBy = u.DisabledBy.String()
	}
	if u.MissingIdentitySince != nil {
		v.MissingIdentitySince = u.MissingIdentitySince.UTC().Format("2006-01-02T15:04:05Z")
	}
	if u.LastLoginAt != nil {
		s := u.LastLoginAt.UTC().Format("2006-01-02T15:04:05Z")
		v.LastLoginAt = &s
	}
	return v
}

// lookupEmail returns the LDAP `mail` attribute for a user's DN,
// or "" on any failure (LDAP unreachable, entry missing, attribute
// unset). Doesn't propagate errors because the calling code path
// (admin Users list/get) shouldn't fail just because email join
// missed — the row stays renderable with extracted-uid fallback.
func (s *Server) lookupEmail(dn string) string {
	if s.ldapClient == nil || dn == "" {
		return ""
	}
	info, err := s.ldapClient.GetUserByDN(dn)
	if err != nil || info == nil {
		return ""
	}
	return info.Email
}

// handleAdminUsers dispatches `/users` (collection-level):
//
//	GET → list with pagination + filters
//
// Per-id ops live on `/users/` with handleAdminUserByID.
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if s.userRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY", "user repository not yet wired", nil))
		return
	}
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "GET only on /users", nil))
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	params := usermanagement.ListParams{
		Limit:           limit,
		Offset:          offset,
		UserType:        models.UserType(q.Get("user_type")),
		IsDisabled:      parseTriBool(q.Get("is_disabled")),
		MissingIdentity: parseTriBool(q.Get("missing_identity")),
	}
	res, err := usermanagement.List(r.Context(), usermanagement.Deps{
		UserRepo: s.userRepo,
		LDAP:     s.ldapClient,
	}, params)
	if err != nil {
		s.logger.App.Error("handleAdminUsers: list failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list users", nil))
		return
	}
	// Per-row LDAP fetch for email. Bounded by the page size (50
	// default, max 200) so this is at most 200 LDAP queries per
	// page render — acceptable for an operator UI. If we ever
	// outgrow that, swap in a single ListUsers + map-by-DN.
	views := make([]userView, 0, len(res.Users))
	for _, u := range res.Users {
		views = append(views, toUserView(u, s.lookupEmail(u.LdapDN)))
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"users": views,
		"total": res.Total,
	}))
}

// handleAdminUserByID dispatches `/users/<id>` for GET/PATCH/DELETE.
func (s *Server) handleAdminUserByID(w http.ResponseWriter, r *http.Request) {
	if s.userRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY", "user repository not yet wired", nil))
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/users/")
	if rest == "" {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
		return
	}
	// Split id + optional action: `/users/<id>` or `/users/<id>/<action>`.
	idStr := rest
	action := ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		idStr = rest[:i]
		action = strings.TrimSuffix(rest[i+1:], "/")
	}
	userID, err := uuid.Parse(idStr)
	if err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "user id is not a valid uuid", nil))
		return
	}

	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			s.adminGetUser(w, r, userID)
		case http.MethodPatch:
			s.adminPatchUser(w, r, userID)
		case http.MethodDelete:
			s.adminDeleteUser(w, r, userID)
		default:
			response.WriteJSON(w, response.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"GET / PATCH / DELETE only on /users/<id>", nil))
		}
	case "reset-password":
		// Phase 9d: admin-issued temporary-password reset.
		if r.Method != http.MethodPost {
			response.WriteJSON(w, response.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"POST only on /users/<id>/reset-password", nil))
			return
		}
		s.adminResetUserPassword(w, r, userID)
	default:
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND",
				"unknown action; recognised: 'reset-password'", nil))
	}
}

func (s *Server) adminGetUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	user, err := usermanagement.Get(r.Context(),
		usermanagement.Deps{UserRepo: s.userRepo, LDAP: s.ldapClient}, id)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("USER_NOT_FOUND", "no user with that id", nil))
			return
		}
		s.logger.App.Error("adminGetUser: get failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not fetch user", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"user": toUserView(user, s.lookupEmail(user.LdapDN)),
	}))
}

// adminPatchUserRequest is the body for PATCH /users/<id>. Pointer
// fields distinguish "leave unchanged" (omitted) from "set to zero"
// (explicit zero). caller_user_id is the operator's user_id from
// the BFF session — required for self-protection invariants.
type adminPatchUserRequest struct {
	UserType   *string `json:"user_type,omitempty"`
	IsDisabled *bool   `json:"is_disabled,omitempty"`
	// Phase 9e v2: signed offset applied to the tenant policy's
	// default_max_clients to compute this user's effective cap.
	ClientCountOffset *int `json:"client_count_offset,omitempty"`
	// Phase 9f: per-user MFA opt-in toggle. Admin can enable on
	// behalf of a user; the handler enforces the same
	// no-mailer-no-MFA gate the user-side widget uses so an
	// admin can't accidentally lock a user out by enabling MFA
	// without a configured mailer.
	MFAEnabled   *bool  `json:"mfa_enabled,omitempty"`
	CallerUserID string `json:"caller_user_id,omitempty"`
}

func (s *Server) adminPatchUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var req adminPatchUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse body", nil))
		return
	}
	defer r.Body.Close()

	// Refuse MFA-enable when no mailer is configured. Same guard the
	// user-side /users/me/mfa endpoint applies; surfacing it here
	// keeps an admin from accidentally locking a user out by
	// flipping the bit through this surface.
	if req.MFAEnabled != nil && *req.MFAEnabled {
		if s.emailService == nil || !s.emailService.IsConfigured() {
			response.WriteJSON(w, http.StatusConflict,
				response.Fail("MFA_REQUIRES_MAILER",
					"email is not configured for this deployment; "+
						"MFA can't be enabled until email is set up", nil))
			return
		}
	}

	params := usermanagement.UpdateParams{
		IsDisabled:        req.IsDisabled,
		ClientCountOffset: req.ClientCountOffset,
		MFAEnabled:        req.MFAEnabled,
	}
	if req.UserType != nil {
		ut := models.UserType(*req.UserType)
		if !ut.IsValid() {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("VALIDATION_FAILED",
					"user_type must be one of: root, admin, user", nil))
			return
		}
		params.UserType = &ut
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

	user, err := usermanagement.Update(r.Context(),
		usermanagement.Deps{UserRepo: s.userRepo, LDAP: s.ldapClient},
		id, params)
	switch {
	case errors.Is(err, models.ErrUserNotFound):
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("USER_NOT_FOUND", "no user with that id", nil))
		return
	case errors.Is(err, usermanagement.ErrLastRoot):
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("LAST_ROOT", err.Error(), nil))
		return
	case errors.Is(err, usermanagement.ErrSelfDemotion):
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("SELF_DEMOTION", err.Error(), nil))
		return
	case err != nil:
		s.logger.App.Error("adminPatchUser: update failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update user", nil))
		return
	}

	s.logger.Security.Info("user updated via admin API",
		zap.String("user_id", id.String()),
		zap.String("caller_user_id", req.CallerUserID),
		zap.Any("changed_fields", changedFields(req)))

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"user": toUserView(user, s.lookupEmail(user.LdapDN)),
	}))
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var callerID uuid.UUID
	if s := r.URL.Query().Get("caller_user_id"); s != "" {
		c, err := uuid.Parse(s)
		if err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("INVALID_REQUEST",
					"caller_user_id must be a valid uuid", nil))
			return
		}
		callerID = c
	}

	err := usermanagement.Delete(r.Context(),
		usermanagement.Deps{UserRepo: s.userRepo, LDAP: s.ldapClient},
		id, callerID)
	switch {
	case errors.Is(err, models.ErrUserNotFound):
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("USER_NOT_FOUND", "no user with that id", nil))
		return
	case errors.Is(err, usermanagement.ErrLastRoot):
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("LAST_ROOT", err.Error(), nil))
		return
	case errors.Is(err, usermanagement.ErrSelfDeletion):
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("SELF_DELETION", err.Error(), nil))
		return
	case err != nil:
		s.logger.App.Error("adminDeleteUser: delete failed", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not delete user", nil))
		return
	}

	s.logger.Security.Warn("user deleted via admin API",
		zap.String("user_id", id.String()),
		zap.String("caller_user_id", callerID.String()))

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"deleted": true,
	}))
}

// adminResetUserPasswordRequest is the body for
// POST /users/<id>/reset-password. CallerUserID is the admin's
// PG-level user_id, threaded in by the BFF's session-aware proxy
// so the security audit log can attribute the action; CLI callers
// omit it (uuid.Nil — the audit row will read "system" for caller).
type adminResetUserPasswordRequest struct {
	CallerUserID string `json:"caller_user_id,omitempty"`
}

// adminResetUserPassword executes the Phase 9d "admin issues a
// temporary password" flow. The lifecycle is:
//
//  1. Generate a strong 24-char password (auth.GenerateTempPassword,
//     no ambiguous chars, all four character classes guaranteed).
//  2. Validate it against the live tenant password policy. The
//     generator is engineered to satisfy any reasonable policy; the
//     check is a defense-in-depth in case a custom-policy deployment
//     ever requires something we don't produce.
//  3. Replace the LDAP userPassword via admin bind (no old-password
//     check — admin authority).
//  4. Flip User.PasswordResetRequired = true so the next /login is
//     intercepted into a forced-reset flow instead of issuing a
//     normal session.
//  5. Revoke every live RT chain for the user — without this, an
//     attacker who already exfiltrated an RT could keep refreshing
//     sessions even after the password change.
//  6. If the mailer is configured, render and send the temp_password
//     email; respond `{sent: true, email: <address>}` without the
//     plaintext.
//     If the mailer is NOT configured, respond `{sent: false,
//     temp_password: <plaintext>}` so the operator can deliver it
//     out-of-band. The plaintext is only ever in this single
//     response — never persisted.
//
// Self-protection: an admin can reset their own password through
// this endpoint. We don't block self-reset — it's a legitimate use
// case ("I'm about to leave my desk, generate me a temp password
// and email it to me"). Disabled accounts are blocked to avoid the
// "reset, then can't sign in" trap.
func (s *Server) adminResetUserPassword(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	if s.userRepo == nil || s.ldapClient == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DEPENDENCIES_NOT_READY",
				"user repo or LDAP client not yet wired", nil))
		return
	}

	var req adminResetUserPasswordRequest
	// Empty body is valid (CLI), so a JSON parse error on a non-empty
	// body is the only thing we surface; ignore EOF.
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("INVALID_REQUEST", "could not parse body", nil))
			return
		}
	}
	defer r.Body.Close()

	var callerID uuid.UUID
	if req.CallerUserID != "" {
		c, err := uuid.Parse(req.CallerUserID)
		if err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("INVALID_REQUEST",
					"caller_user_id must be a valid uuid", nil))
			return
		}
		callerID = c
	}

	ctx := r.Context()

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("USER_NOT_FOUND", "no user with that id", nil))
			return
		}
		s.logger.App.Error("adminResetUserPassword: GetUserByID failed",
			zap.String("user_id", userID.String()), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not fetch user", nil))
		return
	}
	if user.IsDisabled {
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("USER_DISABLED",
				"cannot reset password for a disabled user; enable the account first", nil))
		return
	}
	if user.LdapDN == "" {
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("NO_LDAP_DN",
				"user has no LDAP DN; identity is missing or partially provisioned", nil))
		return
	}

	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		s.logger.App.Error("adminResetUserPassword: GenerateTempPassword failed",
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not generate temporary password", nil))
		return
	}

	// Defense-in-depth policy validate. The generator is designed to
	// satisfy any reasonable policy, but a custom-policy deployment
	// could in theory require characters we don't produce — fail
	// fast with a clear error rather than silently shipping a
	// password the user can't actually change to (the forced-reset
	// page validates the same policy).
	if s.policySvc != nil {
		pol, perr := s.policySvc.PasswordPolicy(ctx)
		if perr != nil {
			s.logger.App.Warn("adminResetUserPassword: password policy fetch failed; "+
				"proceeding with generator-only validity",
				zap.Error(perr))
		} else if pol != nil {
			if verr := pol.Validate(tempPassword); verr != nil {
				s.logger.App.Error("adminResetUserPassword: generated temp password "+
					"failed policy validation — generator/policy mismatch",
					zap.Error(verr))
				response.WriteJSON(w, http.StatusInternalServerError,
					response.Fail("POLICY_MISMATCH",
						"generated temporary password does not satisfy current "+
							"password policy; loosen the policy or contact maintainers",
						nil))
				return
			}
		}
	}

	// LDAP first — if this fails, nothing else changes. Order
	// matters: a flipped PasswordResetRequired without a working
	// new password would lock the user out at the next sign-in.
	if err := s.ldapClient.ResetPasswordAsAdmin(user.LdapDN, tempPassword); err != nil {
		s.logger.Security.Error("adminResetUserPassword: LDAP modify failed",
			zap.String("user_id", userID.String()),
			zap.String("user_dn", user.LdapDN),
			zap.String("caller_user_id", callerID.String()),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("LDAP_ERROR",
				"could not update password in directory", nil))
		return
	}

	// Flip the gate. If this fails after LDAP succeeded, the user's
	// password is now the temp one but their next /login won't be
	// forced through the reset page — they'll get a normal session
	// with the temp password as their permanent password. We still
	// attempt the RT revocation and the email; the audit log captures
	// the inconsistency for operator follow-up.
	if err := s.userRepo.SetPasswordResetRequired(ctx, userID, true); err != nil {
		s.logger.Security.Error("adminResetUserPassword: failed to set "+
			"password_reset_required flag (LDAP password already changed)",
			zap.String("user_id", userID.String()),
			zap.Error(err))
		// Fall through — the password change is the load-bearing
		// part; the gate-flip is the UX nicety. Operator should
		// retry or set the flag manually if needed.
	}

	// Kill all live RTs. Soft-failure: log and continue. The reset
	// is still useful even if revocation fails — the new password
	// is in effect, the gate is flipped, and existing access tokens
	// expire on their own short TTL.
	if s.refreshTokenRepo != nil {
		if n, rerr := s.refreshTokenRepo.RevokeAllForUser(ctx, userID,
			"admin_password_reset"); rerr != nil {
			s.logger.Security.Warn("adminResetUserPassword: RT revocation failed; "+
				"existing refresh tokens may remain valid until their natural TTL",
				zap.String("user_id", userID.String()),
				zap.Error(rerr))
		} else {
			s.logger.Security.Info("adminResetUserPassword: refresh tokens revoked",
				zap.String("user_id", userID.String()),
				zap.Int64("count", n))
		}
	} else {
		s.logger.App.Warn("adminResetUserPassword: refreshTokenRepo not wired; " +
			"skipping refresh-token revocation")
	}

	// Audit before deciding the response shape — the action happened
	// regardless of whether the email goes out.
	s.logger.Security.Warn("admin temporary password reset",
		zap.String("user_id", userID.String()),
		zap.String("user_dn", user.LdapDN),
		zap.String("caller_user_id", callerID.String()))

	// Decide delivery channel.
	emailAddr := s.lookupEmail(user.LdapDN)
	mailerReady := s.emailService != nil && s.emailService.IsConfigured()

	if mailerReady && emailAddr != "" {
		if err := s.sendTempPasswordEmail(ctx, emailAddr, user.LdapDN, tempPassword); err != nil {
			// Fall through to the "show plaintext to admin" branch.
			// Better to give the operator the password in the response
			// than to leave the user locked out with no recovery path.
			s.logger.App.Warn("adminResetUserPassword: email send failed; "+
				"returning plaintext to caller as fallback",
				zap.String("user_id", userID.String()),
				zap.Error(err))
			response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
				"sent":          false,
				"email":         emailAddr,
				"temp_password": tempPassword,
				"reason":        "email_send_failed",
			}))
			return
		}
		response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
			"sent":  true,
			"email": emailAddr,
		}))
		return
	}

	// Mailer not configured (or no email on the LDAP entry). Return
	// the plaintext exactly once so the admin can deliver it out-of-
	// band. The UI is expected to render this in a confirmation modal
	// and not persist it anywhere.
	reason := "mailer_not_configured"
	if mailerReady && emailAddr == "" {
		reason = "no_email_on_ldap_entry"
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"sent":          false,
		"email":         emailAddr, // may be empty
		"temp_password": tempPassword,
		"reason":        reason,
	}))
}

// sendTempPasswordEmail renders and dispatches the temp_password
// template via the cached mailer. Errors propagate so the caller
// can decide whether to fall back to returning the plaintext.
//
// `userDN` is used only to resolve a display name from LDAP for the
// "Hi <name>," greeting; on lookup failure we fall back to the
// local-part of the email, mirroring the forgot-password flow.
func (s *Server) sendTempPasswordEmail(ctx context.Context, emailAddr, userDN, tempPassword string) error {
	displayName := emailAddr
	if at := strings.IndexByte(emailAddr, '@'); at > 0 {
		displayName = emailAddr[:at]
	}
	if s.ldapClient != nil {
		if info, err := s.ldapClient.GetUserByDN(userDN); err == nil &&
			info != nil && info.DisplayName != "" {
			displayName = info.DisplayName
		}
	}

	loginURL := ""
	if s.emailService != nil {
		// VerifyURLBase is the externally-reachable URL prefix; the
		// auth-server's login page lives at <base>/login. (We reuse
		// VerifyURLBase here rather than adding a separate
		// LoginURLBase column — both emails resolve to the same
		// public host.)
		if base := s.emailService.VerifyURLBase(ctx); base != "" {
			loginURL = strings.TrimRight(base, "/") + "/login"
		}
	}

	msg, err := mailer.Render("temp_password", map[string]any{
		"TenantName":   "Akashic",
		"DisplayName":  displayName,
		"TempPassword": tempPassword,
		"LoginURL":     loginURL,
	})
	if err != nil {
		return err
	}
	msg.To = emailAddr
	return s.emailService.Send(ctx, msg)
}

// parseTriBool returns nil for "" (filter not set), &true for
// "true"/"1"/"yes", &false for "false"/"0"/"no". Any other string
// is treated as nil (no filter) so a typo doesn't accidentally
// hide rows.
func parseTriBool(s string) *bool {
	t, f := true, false
	switch strings.ToLower(s) {
	case "true", "1", "yes":
		return &t
	case "false", "0", "no":
		return &f
	}
	return nil
}

// changedFields summarises which top-level keys the PATCH supplied
// for the security log. Keeping this in one place avoids each
// branch building its own bag of fields.
func changedFields(req adminPatchUserRequest) []string {
	out := []string{}
	if req.UserType != nil {
		out = append(out, "user_type="+*req.UserType)
	}
	if req.IsDisabled != nil {
		out = append(out, "is_disabled="+strconv.FormatBool(*req.IsDisabled))
	}
	if req.ClientCountOffset != nil {
		out = append(out, "client_count_offset="+strconv.Itoa(*req.ClientCountOffset))
	}
	if req.MFAEnabled != nil {
		out = append(out, "mfa_enabled="+strconv.FormatBool(*req.MFAEnabled))
	}
	return out
}
