package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"
	"akashic/akashic/pkg/userregistration"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// PATCH /users/me/uid — Phase 9 prerequisite (B-2 of the
// uid-rotation milestone).
//
// Body:
//
//	{ "username"?: "<new id-base>", "tag"?: "<NEW>" }
//
// At least one of `username` or `tag` must be supplied.
// Defaults for the other field:
//   - missing `username` → keeps the user's CURRENT id-base
//     (extracted from the leftmost RDN of their current DN).
//     This preserves a user-chosen id like `bob` even when the
//     user's email's local part is something else like `alice`.
//   - missing `tag` → auto-generated 4-char base36 with collision
//     retry. Same flow as registration.
//
// Cooldown: enforced via `policy.UIDChangeCooldownDays` against
// `User.LastUIDChangedAt`. 0 disables. Nil-LastUIDChangedAt
// (never rotated) always passes.
//
// Atomicity: LDAP modrdn first, PG update second, best-effort
// LDAP rollback if PG fails. See the package design note in
// the doc comment of api/users_handlers.go for the rationale.

type changeUIDRequest struct {
	Username string `json:"username,omitempty"`
	Tag      string `json:"tag,omitempty"`
}

func (s *Server) handleChangeUID(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPatch {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only PATCH is allowed", nil))
		return
	}
	if s.userRepo == nil || s.ldapClient == nil || s.policySvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY",
				"uid-change dependencies not initialized", nil))
		return
	}

	// Load the user row so we have current DN + LastUIDChangedAt.
	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("USER_NOT_FOUND", "no such user", nil))
			return
		}
		s.logger.App.Error("changeUID: db lookup", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load user", nil))
		return
	}

	// Cooldown check. Read the policy fresh per call so operator
	// edits to UIDChangeCooldownDays take effect immediately.
	policy, err := s.policySvc.Get(r.Context())
	if err != nil {
		s.logger.App.Error("changeUID: policy lookup", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load policy", nil))
		return
	}
	if policy.UIDChangeCooldownDays > 0 && user.LastUIDChangedAt != nil {
		nextAllowed := user.LastUIDChangedAt.Add(
			time.Duration(policy.UIDChangeCooldownDays) * 24 * time.Hour)
		if time.Now().Before(nextAllowed) {
			response.WriteJSON(w, http.StatusConflict,
				response.Fail("UID_CHANGE_COOLDOWN_ACTIVE",
					"id rotation is rate-limited; try again later",
					map[string]any{
						"next_allowed_at":   nextAllowed.UTC().Format(time.RFC3339),
						"cooldown_days":     policy.UIDChangeCooldownDays,
						"last_changed_at":   user.LastUIDChangedAt.UTC().Format(time.RFC3339),
					}))
			return
		}
	}

	var req changeUIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()
	req.Username = strings.TrimSpace(req.Username)
	req.Tag = strings.TrimSpace(req.Tag)
	if req.Username == "" && req.Tag == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"supply at least one of `username` or `tag`", nil))
		return
	}

	// Resolve current uid + id-base from the existing DN. When the
	// caller didn't supply a username, we keep their existing id-
	// base (rather than re-deriving from email, which would change
	// id-base for users with custom names).
	currentUID := uidFromDN(user.LdapDN)
	currentIDBase := currentUID
	if hash := strings.IndexByte(currentUID, '#'); hash >= 0 {
		currentIDBase = currentUID[:hash]
	}
	suppliedID := req.Username
	if suppliedID == "" {
		suppliedID = currentIDBase
	}

	// Email is needed only as a fallback for ResolveUID when its
	// suppliedID is empty — which we've ruled out above, but pass
	// it along for completeness. Best-effort lookup; resolveUID
	// will accept "" if the LDAP entry is briefly unreachable.
	var email string
	if info, err := s.ldapClient.GetUserByDN(user.LdapDN); err == nil && info != nil {
		email = info.Email
	}

	newUID, err := userregistration.ResolveUID(s.ldapClient, email, suppliedID, req.Tag, currentUID)
	switch {
	case errors.Is(err, userregistration.ErrIDInvalid):
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("ID_INVALID",
				"id must be 2-32 chars (letters/digits/dots/hyphens/underscores)", nil))
		return
	case errors.Is(err, userregistration.ErrTagInvalid):
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("TAG_INVALID",
				"tag must be exactly 4 chars (0-9, A-Z)", nil))
		return
	case errors.Is(err, userregistration.ErrUIDTaken):
		response.WriteJSON(w, http.StatusConflict,
			response.Fail("UID_TAKEN",
				"that id+tag combination is already taken", nil))
		return
	case errors.Is(err, userregistration.ErrUsernameUnavailable):
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("USERNAME_UNAVAILABLE",
				"could not generate a unique uid; please retry or supply an explicit tag", nil))
		return
	case err != nil:
		s.logger.App.Error("changeUID: ResolveUID", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not resolve new uid", nil))
		return
	}

	// No-op short-circuit: the resolved uid matches the user's
	// current uid. Don't burn the cooldown for a no-change call.
	if newUID == currentUID {
		response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
			"changed":   false,
			"uid":       currentUID,
			"ldap_dn":   user.LdapDN,
		}))
		return
	}

	// LDAP rename first. If this fails, we haven't touched PG yet
	// — return cleanly.
	newDN, err := s.ldapClient.RenameUser(user.LdapDN, newUID)
	if err != nil {
		s.logger.App.Error("changeUID: LDAP modrdn",
			zap.String("old_dn", user.LdapDN),
			zap.String("new_uid", newUID), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not rename LDAP entry", nil))
		return
	}

	// PG update. If this fails after LDAP succeeded, attempt to
	// roll the LDAP rename back to keep the two stores consistent.
	if err := s.userRepo.UpdateLdapDNAndMarkUIDChanged(r.Context(), uid, newDN); err != nil {
		s.logger.App.Error("changeUID: PG update after LDAP rename",
			zap.String("user_id", uid.String()),
			zap.String("new_dn", newDN), zap.Error(err))
		// Best-effort rollback. If THIS fails too, log loudly —
		// the operator will need to fix manually (rare).
		if _, rbErr := s.ldapClient.RenameUser(newDN, currentUID); rbErr != nil {
			s.logger.Security.Error(
				"changeUID: LDAP rollback failed; PG and LDAP now diverge",
				zap.String("user_id", uid.String()),
				zap.String("ldap_dn_should_be", user.LdapDN),
				zap.String("ldap_dn_currently", newDN),
				zap.Error(rbErr))
		}
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL",
				"could not persist uid change; rolled back LDAP rename", nil))
		return
	}

	s.logger.Security.Info("user changed uid",
		zap.String("user_id", uid.String()),
		zap.String("old_uid", currentUID),
		zap.String("new_uid", newUID))

	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"changed":              true,
		"uid":                  newUID,
		"ldap_dn":              newDN,
		"last_uid_changed_at":  time.Now().UTC().Format(time.RFC3339),
	}))
}
