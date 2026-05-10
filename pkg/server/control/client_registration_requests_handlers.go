package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"akashic/akashic/pkg/clientregistration"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase 9e: client-registration qualification — admin reviewer surface.
//
//   GET  /client-registration-requests                       list (?status=)
//   GET  /client-registration-requests/<id>                  fetch one
//   POST /client-registration-requests/<id>/approve          approve
//   POST /client-registration-requests/<id>/reject           reject
//
// Operator-scoped (mTLS gate). The admin BFF proxies these so the
// admin web's "Client registration requests" page can render the
// reviewer queue. Mirrors the scope-requests surface — see
// scope_requests_handlers.go for the longer rationale on the
// approve/reject body shape and side-effect ordering.

// adminClientRegRequestView is the wire shape one row. Mirrors
// models.ClientRegistrationRequest with stable JSON keys, RFC-3339
// timestamps, and a per-row LDAP join for `requester_email` /
// `requester_display_name` so the reviewer page can identify the
// user without a second round trip.
type adminClientRegRequestView struct {
	ID                   string  `json:"id"`
	UserID               string  `json:"user_id"`
	RequesterEmail       string  `json:"requester_email,omitempty"`
	RequesterDisplayName string  `json:"requester_display_name,omitempty"`
	Reason               string  `json:"reason"`
	// Phase 9e v2: proposed client params surfaced for the
	// reviewer's read.
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	HomepageURL    string `json:"homepage_url,omitempty"`
	ClientType     string `json:"client_type"`
	RedirectURIs   string `json:"redirect_uris"`
	RequiredScopes string `json:"required_scopes,omitempty"`
	OptionalScopes string `json:"optional_scopes,omitempty"`
	RequirePKCE    bool   `json:"require_pkce"`

	Status          string  `json:"status"`
	SubmittedAt     string  `json:"submitted_at"`
	ReviewedBy      *string `json:"reviewed_by,omitempty"`
	ReviewedAt      *string `json:"reviewed_at,omitempty"`
	DecisionNote    string  `json:"decision_note,omitempty"`
	CreatedClientID *string `json:"created_client_id,omitempty"`
}

func (s *Server) toClientRegRequestView(req *models.ClientRegistrationRequest) adminClientRegRequestView {
	v := adminClientRegRequestView{
		ID:              req.ID.String(),
		UserID:          req.UserID.String(),
		Reason:          req.Reason,
		Name:            req.Name,
		Description:     req.Description,
		HomepageURL:     req.HomepageURL,
		ClientType:      req.ClientType,
		RedirectURIs:    req.RedirectURIs,
		RequiredScopes:  req.RequiredScopes,
		OptionalScopes:  req.OptionalScopes,
		RequirePKCE:     req.RequirePKCE,
		Status:          req.Status,
		SubmittedAt:     req.SubmittedAt.UTC().Format("2006-01-02T15:04:05Z"),
		DecisionNote:    req.DecisionNote,
		CreatedClientID: req.CreatedClientID,
	}
	if req.ReviewedBy != nil {
		s := req.ReviewedBy.String()
		v.ReviewedBy = &s
	}
	if req.ReviewedAt != nil {
		s := req.ReviewedAt.UTC().Format("2006-01-02T15:04:05Z")
		v.ReviewedAt = &s
	}
	// Best-effort LDAP join. Same fail-soft pattern as the user-
	// list endpoint — empty fields when LDAP is unreachable; the
	// review page falls back to showing user_id only.
	v.RequesterEmail, v.RequesterDisplayName = s.lookupRequesterLDAP(req.UserID)
	return v
}

// lookupRequesterLDAP resolves a user UUID to their LDAP email +
// display name. Returns empty strings on any failure (no PG row,
// no LDAP entry, LDAP unreachable). Used by the per-row view so
// the reviewer can identify the requester at a glance.
func (s *Server) lookupRequesterLDAP(userID uuid.UUID) (email, displayName string) {
	if s.userRepo == nil || s.ldapClient == nil {
		return "", ""
	}
	user, err := s.userRepo.GetUserByID(context.Background(), userID)
	if err != nil || user == nil || user.LdapDN == "" {
		return "", ""
	}
	info, err := s.ldapClient.GetUserByDN(user.LdapDN)
	if err != nil || info == nil {
		return "", ""
	}
	return info.Email, info.DisplayName
}

func (s *Server) handleAdminClientRegistrationRequests(w http.ResponseWriter, r *http.Request) {
	if s.clientRegRequestRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"client-registration request repository not yet wired", nil))
		return
	}
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"GET only on /client-registration-requests", nil))
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	rows, err := s.clientRegRequestRepo.List(r.Context(), status, 200)
	if err != nil {
		s.logger.App.Error("listClientRegistrationRequests: repo", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list requests", nil))
		return
	}
	views := make([]adminClientRegRequestView, 0, len(rows))
	for _, row := range rows {
		views = append(views, s.toClientRegRequestView(row))
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"client_registration_requests": views,
	}))
}

// handleAdminClientRegistrationRequestByID dispatches
// `/client-registration-requests/<id>[/<action>]`.
func (s *Server) handleAdminClientRegistrationRequestByID(w http.ResponseWriter, r *http.Request) {
	if s.clientRegRequestRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"client-registration request repository not yet wired", nil))
		return
	}
	idStr, action := splitClientRegRequestPath(r.URL.Path)
	if idStr == "" {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"id must be a valid uuid", nil))
		return
	}
	switch action {
	case "":
		if r.Method != http.MethodGet {
			response.WriteJSON(w, http.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"GET only for /client-registration-requests/<id>", nil))
			return
		}
		row, err := s.clientRegRequestRepo.Get(r.Context(), id)
		if err != nil {
			s.writeClientRegRequestError(w, err, "fetch")
			return
		}
		response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
			"client_registration_request": s.toClientRegRequestView(row),
		}))
	case "approve":
		s.handleAdminApproveClientRegistrationRequest(w, r, id)
	case "reject":
		s.handleAdminRejectClientRegistrationRequest(w, r, id)
	default:
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND",
				"unknown action; use 'approve' or 'reject'", nil))
	}
}

// adminApproveClientRegRequest is the body for the approve action.
// Phase 9e v2: approval is "as proposed" — the reviewer doesn't
// edit client params at approval time; they accept or reject. To
// alter params, reject with a note and the user resubmits.
type adminApproveClientRegRequest struct {
	ReviewerUserID string `json:"reviewer_user_id"`
	DecisionNote   string `json:"decision_note,omitempty"`
}

func (s *Server) handleAdminApproveClientRegistrationRequest(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "POST only", nil))
		return
	}
	if s.clientRegSvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE",
				"client-registration service not yet wired", nil))
		return
	}
	var body adminApproveClientRegRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()
	reviewerID, err := uuid.Parse(strings.TrimSpace(body.ReviewerUserID))
	if err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"reviewer_user_id must be a valid uuid", nil))
		return
	}

	// Pre-fetch the row so we can look up the requester for the
	// approval-email recipient. The service's transition is still
	// atomic — this read is just for the email metadata.
	pre, err := s.clientRegRequestRepo.Get(r.Context(), id)
	if err != nil {
		s.writeClientRegRequestError(w, err, "approve")
		return
	}
	email, displayName := s.lookupRequesterLDAP(pre.UserID)

	row, err := s.clientRegSvc.Approve(r.Context(), clientregistration.ApproveParams{
		RequestID:            id,
		ReviewerID:           reviewerID,
		DecisionNote:         body.DecisionNote,
		RequesterEmail:       email,
		RequesterDisplayName: displayName,
	})
	if errors.Is(err, clientregistration.ErrInvalidRequest) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED", err.Error(), nil))
		return
	}
	if err != nil {
		s.writeClientRegRequestError(w, err, "approve")
		return
	}
	createdClientID := ""
	if row.CreatedClientID != nil {
		createdClientID = *row.CreatedClientID
	}
	s.logger.Security.Info("client-registration request approved",
		zap.String("id", row.ID.String()),
		zap.String("user_id", row.UserID.String()),
		zap.String("reviewer", reviewerID.String()),
		zap.String("created_client_id", createdClientID))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"client_registration_request": s.toClientRegRequestView(row),
	}))
}

// adminRejectClientRegRequest is the body for the reject action.
type adminRejectClientRegRequest struct {
	ReviewerUserID string `json:"reviewer_user_id"`
	DecisionNote   string `json:"decision_note,omitempty"`
}

func (s *Server) handleAdminRejectClientRegistrationRequest(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "POST only", nil))
		return
	}
	if s.clientRegSvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("SERVICE_UNAVAILABLE",
				"client-registration service not yet wired", nil))
		return
	}
	var body adminRejectClientRegRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()
	reviewerID, err := uuid.Parse(strings.TrimSpace(body.ReviewerUserID))
	if err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"reviewer_user_id must be a valid uuid", nil))
		return
	}
	pre, err := s.clientRegRequestRepo.Get(r.Context(), id)
	if err != nil {
		s.writeClientRegRequestError(w, err, "reject")
		return
	}
	email, displayName := s.lookupRequesterLDAP(pre.UserID)

	row, err := s.clientRegSvc.Reject(r.Context(), clientregistration.RejectParams{
		RequestID:            id,
		ReviewerID:           reviewerID,
		DecisionNote:         body.DecisionNote,
		RequesterEmail:       email,
		RequesterDisplayName: displayName,
	})
	if err != nil {
		s.writeClientRegRequestError(w, err, "reject")
		return
	}
	s.logger.Security.Info("client-registration request rejected",
		zap.String("id", row.ID.String()),
		zap.String("user_id", row.UserID.String()),
		zap.String("reviewer", reviewerID.String()))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"client_registration_request": s.toClientRegRequestView(row),
	}))
}

func (s *Server) writeClientRegRequestError(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, repository.ErrClientRegRequestNotFound) {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("REQUEST_NOT_FOUND",
				"client-registration request not found or no longer pending", nil))
		return
	}
	s.logger.App.Error("client-registration request "+op, zap.Error(err))
	response.WriteJSON(w, http.StatusInternalServerError,
		response.Fail("INTERNAL", "could not "+op+" request", nil))
}

// splitClientRegRequestPath parses
// `/client-registration-requests/<id>[/<action>]`.
func splitClientRegRequestPath(p string) (id, action string) {
	const prefix = "/client-registration-requests/"
	if !strings.HasPrefix(p, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(p, prefix)
	rest = strings.TrimSuffix(rest, "/")
	if rest == "" {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 2)
	id = parts[0]
	if len(parts) == 2 {
		action = parts[1]
	}
	return id, action
}
