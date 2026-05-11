package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"akashic/akashic/pkg/mailer"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Phase B: special-scope approval-workflow surface.
//
//   GET  /scope-requests                  → list (?status=pending|approved|rejected)
//   POST /scope-requests                  → submit a new pending request
//   POST /scope-requests/<id>/approve     → approve a pending request
//   POST /scope-requests/<id>/reject      → reject a pending request
//   GET  /scope-requests/<id>             → fetch a single request
//
// Operator-scoped (mTLS gate). The admin BFF proxies these so the
// admin web's "Scope requests" page can render them.

func (s *Server) handleAdminScopeRequests(w http.ResponseWriter, r *http.Request) {
	if s.scopeRequestRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"scope-request repository not yet wired", nil))
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleAdminListScopeRequests(w, r)
	case http.MethodPost:
		s.handleAdminCreateScopeRequest(w, r)
	default:
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"GET or POST only on /scope-requests", nil))
	}
}

type adminScopeRequestView struct {
	ID                                     string  `json:"id"`
	ClientID                               string  `json:"client_id"`
	Scope                                  string  `json:"scope"`
	Reason                                 string  `json:"reason"`
	ProposedAccessTokenTTLSeconds          *int    `json:"proposed_access_token_ttl_seconds,omitempty"`
	ProposedRefreshTokenSlidingTTLSeconds  *int    `json:"proposed_refresh_token_sliding_ttl_seconds,omitempty"`
	ProposedRefreshTokenAbsoluteTTLSeconds *int    `json:"proposed_refresh_token_absolute_ttl_seconds,omitempty"`
	Status                                 string  `json:"status"`
	SubmittedBy                            *string `json:"submitted_by,omitempty"`
	SubmittedAt                            string  `json:"submitted_at"`
	ReviewedBy                             *string `json:"reviewed_by,omitempty"`
	ReviewedAt                             *string `json:"reviewed_at,omitempty"`
	DecisionNote                           string  `json:"decision_note,omitempty"`
}

func toScopeRequestView(req *models.OAuthScopeRequest) adminScopeRequestView {
	v := adminScopeRequestView{
		ID:                                     req.ID.String(),
		ClientID:                               req.ClientID,
		Scope:                                  req.Scope,
		Reason:                                 req.Reason,
		ProposedAccessTokenTTLSeconds:          req.ProposedAccessTokenTTLSeconds,
		ProposedRefreshTokenSlidingTTLSeconds:  req.ProposedRefreshTokenSlidingTTLSeconds,
		ProposedRefreshTokenAbsoluteTTLSeconds: req.ProposedRefreshTokenAbsoluteTTLSeconds,
		Status:                                 req.Status,
		SubmittedAt:                            req.SubmittedAt.UTC().Format("2006-01-02T15:04:05Z"),
		DecisionNote:                           req.DecisionNote,
	}
	if req.SubmittedBy != nil {
		s := req.SubmittedBy.String()
		v.SubmittedBy = &s
	}
	if req.ReviewedBy != nil {
		s := req.ReviewedBy.String()
		v.ReviewedBy = &s
	}
	if req.ReviewedAt != nil {
		s := req.ReviewedAt.UTC().Format("2006-01-02T15:04:05Z")
		v.ReviewedAt = &s
	}
	return v
}

func (s *Server) handleAdminListScopeRequests(w http.ResponseWriter, r *http.Request) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	rows, err := s.scopeRequestRepo.List(r.Context(), status, 200)
	if err != nil {
		s.logger.App.Error("listScopeRequests: repo", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list scope requests", nil))
		return
	}
	views := make([]adminScopeRequestView, 0, len(rows))
	for _, row := range rows {
		views = append(views, toScopeRequestView(row))
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"scope_requests": views,
	}))
}

type adminCreateScopeRequest struct {
	ClientID                               string `json:"client_id"`
	Scope                                  string `json:"scope"`
	Reason                                 string `json:"reason"`
	ProposedAccessTokenTTLSeconds          *int   `json:"proposed_access_token_ttl_seconds,omitempty"`
	ProposedRefreshTokenSlidingTTLSeconds  *int   `json:"proposed_refresh_token_sliding_ttl_seconds,omitempty"`
	ProposedRefreshTokenAbsoluteTTLSeconds *int   `json:"proposed_refresh_token_absolute_ttl_seconds,omitempty"`
	SubmittedBy                            string `json:"submitted_by,omitempty"` // uuid string; optional
}

func (s *Server) handleAdminCreateScopeRequest(w http.ResponseWriter, r *http.Request) {
	var req adminCreateScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	req.ClientID = strings.TrimSpace(req.ClientID)
	req.Scope = strings.TrimSpace(req.Scope)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.ClientID == "" || req.Scope == "" || req.Reason == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"client_id, scope, and reason are all required", nil))
		return
	}
	if !oauth.IsSpecialScope(req.Scope) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"only special scopes (e.g. offline_access) require approval; non-special scopes are set directly via PATCH /clients/<id>", nil))
		return
	}

	// Verify the client actually exists. A request bound to a
	// missing client is a useless audit row.
	var c models.ClientService
	if err := s.db.WithContext(r.Context()).Where("client_id = ?", req.ClientID).First(&c).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			response.WriteJSON(w, http.StatusNotFound,
				response.Fail("CLIENT_NOT_FOUND", "no such client_id", nil))
			return
		}
		s.logger.App.Error("createScopeRequest: client lookup", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load client", nil))
		return
	}

	row := &models.OAuthScopeRequest{
		ClientID:                               req.ClientID,
		Scope:                                  req.Scope,
		Reason:                                 req.Reason,
		ProposedAccessTokenTTLSeconds:          req.ProposedAccessTokenTTLSeconds,
		ProposedRefreshTokenSlidingTTLSeconds:  req.ProposedRefreshTokenSlidingTTLSeconds,
		ProposedRefreshTokenAbsoluteTTLSeconds: req.ProposedRefreshTokenAbsoluteTTLSeconds,
	}
	if req.SubmittedBy != "" {
		uid, err := uuid.Parse(req.SubmittedBy)
		if err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("VALIDATION_FAILED",
					"submitted_by must be a valid uuid", nil))
			return
		}
		row.SubmittedBy = &uid
	}

	if err := s.scopeRequestRepo.Create(r.Context(), row); err != nil {
		if errors.Is(err, repository.ErrScopeRequestExists) {
			response.WriteJSON(w, http.StatusConflict,
				response.Fail("SCOPE_REQUEST_EXISTS",
					"a pending request for this client+scope already exists; edit or wait for review", nil))
			return
		}
		s.logger.App.Error("createScopeRequest: repo", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create scope request", nil))
		return
	}

	s.logger.Security.Info("scope request submitted",
		zap.String("id", row.ID.String()),
		zap.String("client_id", row.ClientID),
		zap.String("scope", row.Scope))

	response.WriteJSON(w, http.StatusCreated, response.Success(map[string]any{
		"scope_request": toScopeRequestView(row),
	}))
}

// handleAdminScopeRequestByID dispatches `/scope-requests/<id>[/<action>]`:
//
//	GET  /scope-requests/<id>             → fetch
//	POST /scope-requests/<id>/approve     → approve
//	POST /scope-requests/<id>/reject      → reject
func (s *Server) handleAdminScopeRequestByID(w http.ResponseWriter, r *http.Request) {
	if s.scopeRequestRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"scope-request repository not yet wired", nil))
		return
	}
	idStr, action := splitScopeRequestPath(r.URL.Path)
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
					"GET only for /scope-requests/<id>", nil))
			return
		}
		row, err := s.scopeRequestRepo.Get(r.Context(), id)
		if err != nil {
			s.writeScopeRequestError(w, err, "fetch")
			return
		}
		response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
			"scope_request": toScopeRequestView(row),
		}))
	case "approve":
		s.handleAdminApproveScopeRequest(w, r, id)
	case "reject":
		s.handleAdminRejectScopeRequest(w, r, id)
	default:
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND",
				"unknown action; use 'approve' or 'reject'", nil))
	}
}

type adminReviewScopeRequest struct {
	ReviewerUserID string `json:"reviewer_user_id"`
	DecisionNote   string `json:"decision_note,omitempty"`
}

func (s *Server) handleAdminApproveScopeRequest(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"POST only", nil))
		return
	}
	var body adminReviewScopeRequest
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

	// Move row to approved. Atomic compare-and-swap inside the
	// repo; concurrent reviews collapse to one winner.
	row, err := s.scopeRequestRepo.ApprovePending(r.Context(), id, reviewerID, body.DecisionNote)
	if err != nil {
		s.writeScopeRequestError(w, err, "approve")
		return
	}

	// Apply approval side-effects: add the scope to the client's
	// OptionalScopes (unless already present) AND apply any
	// proposed TTL overrides clamped to the tenant ceiling.
	if err := s.applyApprovalToClient(r.Context(), row); err != nil {
		// We've already flipped the row to approved. Rollback by
		// re-rejecting would be racy + confusing. Better to log
		// loudly and surface the underlying error so the operator
		// can fix the client row manually if needed.
		s.logger.Security.Error("scope approval: client mutation failed; row already approved",
			zap.String("scope_request_id", row.ID.String()),
			zap.String("client_id", row.ClientID),
			zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL",
				"approval recorded but client mutation failed; check logs", nil))
		return
	}

	s.logger.Security.Info("scope request approved",
		zap.String("id", row.ID.String()),
		zap.String("client_id", row.ClientID),
		zap.String("scope", row.Scope),
		zap.String("reviewer", reviewerID.String()))
	// Phase 9g: ping the submitter (if known) about the approval.
	s.sendScopeRequestNotification(r.Context(), row, "scope_request_approved")
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"scope_request": toScopeRequestView(row),
	}))
}

func (s *Server) handleAdminRejectScopeRequest(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"POST only", nil))
		return
	}
	var body adminReviewScopeRequest
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
	row, err := s.scopeRequestRepo.RejectPending(r.Context(), id, reviewerID, body.DecisionNote)
	if err != nil {
		s.writeScopeRequestError(w, err, "reject")
		return
	}
	s.logger.Security.Info("scope request rejected",
		zap.String("id", row.ID.String()),
		zap.String("client_id", row.ClientID),
		zap.String("scope", row.Scope),
		zap.String("reviewer", reviewerID.String()))
	// Phase 9g: ping the submitter (if known) about the rejection.
	s.sendScopeRequestNotification(r.Context(), row, "scope_request_rejected")
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"scope_request": toScopeRequestView(row),
	}))
}

// sendScopeRequestNotification fires the approval/rejection email
// for the submitter (when SubmittedBy is non-nil and the user opted
// in to approval notifications). Phase 9g. Best-effort: a send
// failure never affects the state-transition contract.
//
// Five preconditions for delivery:
//
//	1. SubmittedBy is non-nil (operator-side submissions skip).
//	2. Mailer is configured.
//	3. User row resolvable + has an LDAP email.
//	4. User opted in (approval_notifications_enabled).
//	5. Client name resolvable (used in the email body).
//
// Any failure silently drops the send; the audit log carries the
// approval/rejection itself.
func (s *Server) sendScopeRequestNotification(ctx context.Context, row *models.OAuthScopeRequest, template string) {
	if row.SubmittedBy == nil {
		return
	}
	if s.emailService == nil || !s.emailService.IsConfigured() {
		return
	}
	if s.userRepo == nil || s.ldapClient == nil || s.db == nil {
		return
	}
	user, err := s.userRepo.GetUserByID(ctx, *row.SubmittedBy)
	if err != nil || user == nil {
		return
	}
	if !user.ApprovalNotificationsEnabled {
		s.logger.App.Info("scope-request: submitter opted out of notifications",
			zap.String("user_id", user.ID.String()),
			zap.String("template", template))
		return
	}
	info, err := s.ldapClient.GetUserByDN(user.LdapDN)
	if err != nil || info == nil || info.Email == "" {
		return
	}

	// Resolve client name for the email body. Best-effort.
	var c models.ClientService
	clientName := row.ClientID
	if err := s.db.WithContext(ctx).
		Select("name").Where("client_id = ?", row.ClientID).
		First(&c).Error; err == nil && c.Name != "" {
		clientName = c.Name
	}

	displayName := info.DisplayName
	if displayName == "" {
		displayName = info.Email
		if at := strings.IndexByte(displayName, '@'); at > 0 {
			displayName = displayName[:at]
		}
	}
	loginURL := ""
	if base := s.emailService.VerifyURLBase(ctx); base != "" {
		loginURL = strings.TrimRight(base, "/") + "/login"
	}
	msg, err := mailer.Render(template, map[string]any{
		"TenantName":   "Akashic",
		"DisplayName":  displayName,
		"Scope":        row.Scope,
		"ClientName":   clientName,
		"DecisionNote": row.DecisionNote,
		"LoginURL":     loginURL,
	})
	if err != nil {
		s.logger.App.Warn("scope-request: render notification failed",
			zap.String("template", template), zap.Error(err))
		return
	}
	msg.To = info.Email
	if err := s.emailService.Send(ctx, msg); err != nil {
		s.logger.App.Warn("scope-request: send notification failed",
			zap.String("template", template),
			zap.String("to", info.Email), zap.Error(err))
		return
	}
}

// applyApprovalToClient is the side-effect bundle that runs after a
// scope-request row flips to `approved`. Two effects:
//
//  1. Add the scope to the client's `OptionalScopes` (unless it's
//     already in required or optional). Optional is the default
//     bucket on approval — the client owner / operator can promote
//     to required later via the regular Edit form. AllowedScopes
//     is rebuilt as the union.
//  2. If the request supplied any TTL proposals, apply them as
//     per-client overrides — clamped to the tenant ceiling so an
//     unreasonable ask gets quietly trimmed rather than rejected.
//
// All mutations run in a single transaction so a partial apply
// can't leave the client row in a half-approved state.
func (s *Server) applyApprovalToClient(ctx context.Context, row *models.OAuthScopeRequest) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var c models.ClientService
		if err := tx.Where("client_id = ?", row.ClientID).First(&c).Error; err != nil {
			return err
		}
		// Add the scope to OptionalScopes unless it's already present
		// in required or optional. If the operator had already wired
		// the scope (via a direct PATCH that bypassed the normal
		// gate, e.g., via a previous approval), don't double-add.
		updates := map[string]any{}
		reqSet := oauth.ParseScopeSet(c.RequiredScopes)
		optSet := oauth.ParseScopeSet(c.OptionalScopes)
		if !reqSet.Contains(row.Scope) && !optSet.Contains(row.Scope) {
			newOpt := oauth.UnionScopes(c.OptionalScopes, row.Scope)
			updates["optional_scopes"] = newOpt
			updates["allowed_scopes"] = oauth.UnionScopes(c.RequiredScopes, newOpt)
		}

		// TTL overrides — clamp to tenant ceiling.
		var pol models.TenantPolicy
		if err := tx.Where("id = ?", 1).First(&pol).Error; err != nil {
			return err
		}
		if v := row.ProposedAccessTokenTTLSeconds; v != nil {
			capped := *v
			if capped > pol.AccessTokenTTLSeconds {
				capped = pol.AccessTokenTTLSeconds
			}
			updates["access_token_ttl_seconds_override"] = capped
		}
		if v := row.ProposedRefreshTokenSlidingTTLSeconds; v != nil {
			capped := *v
			if capped > pol.RefreshTokenSlidingTTLSeconds {
				capped = pol.RefreshTokenSlidingTTLSeconds
			}
			updates["refresh_token_sliding_ttl_seconds_override"] = capped
		}
		if v := row.ProposedRefreshTokenAbsoluteTTLSeconds; v != nil {
			capped := *v
			if capped > pol.RefreshTokenAbsoluteTTLSeconds {
				capped = pol.RefreshTokenAbsoluteTTLSeconds
			}
			updates["refresh_token_absolute_ttl_seconds_override"] = capped
		}

		if len(updates) == 0 {
			return nil
		}
		return tx.Model(&c).Updates(updates).Error
	})
}

// writeScopeRequestError maps repository errors to HTTP responses.
// Centralised so the three call sites (Get/Approve/Reject) all
// respond consistently.
func (s *Server) writeScopeRequestError(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, repository.ErrScopeRequestNotFound) {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("SCOPE_REQUEST_NOT_FOUND",
				"scope request not found or no longer pending", nil))
		return
	}
	s.logger.App.Error("scope request "+op, zap.Error(err))
	response.WriteJSON(w, http.StatusInternalServerError,
		response.Fail("INTERNAL", "could not "+op+" scope request", nil))
}

// splitScopeRequestPath parses `/scope-requests/<id>[/<action>]`.
// Returns ("", "") for paths that don't match the prefix.
func splitScopeRequestPath(p string) (id, action string) {
	const prefix = "/scope-requests/"
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
