package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

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
// with stable JSON keys + a deterministic timestamp format.
type userView struct {
	ID                   string  `json:"id"`
	LdapDN               string  `json:"ldap_dn"`
	UserType             string  `json:"user_type"`
	IsDisabled           bool    `json:"is_disabled"`
	DisabledAt           string  `json:"disabled_at,omitempty"`
	DisabledBy           string  `json:"disabled_by,omitempty"`
	MissingIdentity      bool    `json:"missing_identity"`
	MissingIdentitySince string  `json:"missing_identity_since,omitempty"`
	EmailVerified        bool    `json:"email_verified"`
	LastLoginAt          *string `json:"last_login_at,omitempty"`
	CreatedAt            string  `json:"created_at"`
	UpdatedAt            string  `json:"updated_at"`
}

func toUserView(u *models.User) userView {
	v := userView{
		ID:              u.ID.String(),
		LdapDN:          u.LdapDN,
		UserType:        string(u.UserType),
		IsDisabled:      u.IsDisabled,
		MissingIdentity: u.MissingIdentity,
		EmailVerified:   u.EmailVerified,
		CreatedAt:       u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:       u.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
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
	views := make([]userView, 0, len(res.Users))
	for _, u := range res.Users {
		views = append(views, toUserView(u))
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
	idStr := strings.TrimPrefix(r.URL.Path, "/users/")
	if idStr == "" || strings.Contains(idStr, "/") {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
		return
	}
	userID, err := uuid.Parse(idStr)
	if err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "user id is not a valid uuid", nil))
		return
	}

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
		"user": toUserView(user),
	}))
}

// adminPatchUserRequest is the body for PATCH /users/<id>. Pointer
// fields distinguish "leave unchanged" (omitted) from "set to false"
// (explicit false). caller_user_id is the operator's user_id from
// the BFF session — required for self-protection invariants.
type adminPatchUserRequest struct {
	UserType     *string `json:"user_type,omitempty"`
	IsDisabled   *bool   `json:"is_disabled,omitempty"`
	CallerUserID string  `json:"caller_user_id,omitempty"`
}

func (s *Server) adminPatchUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	var req adminPatchUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse body", nil))
		return
	}
	defer r.Body.Close()

	params := usermanagement.UpdateParams{IsDisabled: req.IsDisabled}
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
		"user": toUserView(user),
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
	return out
}
