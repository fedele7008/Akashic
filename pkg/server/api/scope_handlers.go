package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Phase B portal-side scope-policy endpoints. These complement the
// existing /clients endpoints with two pieces the `<akashic-clients>`
// widget needs:
//
//   GET  /allowed-client-scopes
//        Public read. Returns the tenant's `allowed_client_scopes`
//        + the special-scope list. Widget renders the per-scope
//        tristate selector against this set.
//
//   GET  /clients/<id>/scope-requests
//        Bearer + owner-scoped. Returns the request history for
//        the client, so the widget shows pending/approved/rejected
//        status under the "Special scopes" section.
//
//   POST /clients/<id>/scope-requests
//        Bearer + owner-scoped. Creates a pending request. The
//        admin web's Scope-requests page is where review happens.
//
// The submission step lives on the api-server (developer surface)
// rather than the admin BFF (operator surface) because client
// owners — third-party developers integrating against this tenant
// — are the ones with knowledge of WHY they need a special scope.
// The admin web's role is purely review.

// allowedClientScopesResponse is the body of GET /allowed-client-scopes.
// Public, cached lightly client-side.
type allowedClientScopesResponse struct {
	// AllowedClientScopes is the space-separated tenant ceiling.
	// Widget tokenizes + filters out specials before rendering the
	// regular ScopeMatrix.
	AllowedClientScopes string `json:"allowed_client_scopes"`
	// SpecialScopes is the list of scopes that require admin
	// approval via the request workflow. Widget renders these in
	// a separate "Special scopes" section with the request form.
	SpecialScopes []string `json:"special_scopes"`
}

// handleAllowedClientScopes serves GET /allowed-client-scopes.
// Public endpoint — same gating as /users/password-policy
// (requirePublic). The information is non-sensitive: knowing what
// scopes a tenant supports is the same as parsing the discovery
// doc, which is also public.
func (s *Server) handleAllowedClientScopes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET is allowed", nil))
		return
	}
	if s.policySvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY", "policy service not yet wired", nil))
		return
	}
	pol, err := s.policySvc.Get(r.Context())
	if err != nil {
		s.logger.App.Error("allowedClientScopes: read policy", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not read tenant policy", nil))
		return
	}
	specials := []string{}
	for k := range oauth.SpecialScopes {
		specials = append(specials, k)
	}
	response.WriteJSON(w, http.StatusOK, response.Success(allowedClientScopesResponse{
		AllowedClientScopes: pol.AllowedClientScopes,
		SpecialScopes:       specials,
	}))
}

// scopeRequestView is the wire shape returned by both list and
// submit. Same field set as the admin BFF's ScopeRequestView.
type scopeRequestView struct {
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

func toScopeRequestView(r *models.OAuthScopeRequest) scopeRequestView {
	v := scopeRequestView{
		ID:                                     r.ID.String(),
		ClientID:                               r.ClientID,
		Scope:                                  r.Scope,
		Reason:                                 r.Reason,
		ProposedAccessTokenTTLSeconds:          r.ProposedAccessTokenTTLSeconds,
		ProposedRefreshTokenSlidingTTLSeconds:  r.ProposedRefreshTokenSlidingTTLSeconds,
		ProposedRefreshTokenAbsoluteTTLSeconds: r.ProposedRefreshTokenAbsoluteTTLSeconds,
		Status:                                 r.Status,
		SubmittedAt:                            r.SubmittedAt.UTC().Format("2006-01-02T15:04:05Z"),
		DecisionNote:                           r.DecisionNote,
	}
	if r.SubmittedBy != nil {
		s := r.SubmittedBy.String()
		v.SubmittedBy = &s
	}
	if r.ReviewedBy != nil {
		s := r.ReviewedBy.String()
		v.ReviewedBy = &s
	}
	if r.ReviewedAt != nil {
		s := r.ReviewedAt.UTC().Format("2006-01-02T15:04:05Z")
		v.ReviewedAt = &s
	}
	return v
}

// handleClientScopeRequests dispatches GET / POST on
// `/clients/<id>/scope-requests`. The id is parsed by the caller
// (handleClientByID) and passed via the clientCtx pattern that
// already exists for /clients/<id>/* paths.
func (s *Server) handleClientScopeRequests(w http.ResponseWriter, r *http.Request, ctx *clientCtx) {
	if s.scopeRequestRepo == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY",
				"scope-request repository not yet wired", nil))
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listClientScopeRequests(w, r, ctx)
	case http.MethodPost:
		s.submitClientScopeRequest(w, r, ctx)
	default:
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET or POST is allowed", nil))
	}
}

func (s *Server) listClientScopeRequests(w http.ResponseWriter, r *http.Request, ctx *clientCtx) {
	rows, err := s.scopeRequestRepo.ListByClient(r.Context(), ctx.client.ClientID)
	if err != nil {
		s.logger.App.Error("listClientScopeRequests", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list scope requests", nil))
		return
	}
	views := make([]scopeRequestView, 0, len(rows))
	for _, row := range rows {
		views = append(views, toScopeRequestView(row))
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"scope_requests": views,
	}))
}

type submitScopeRequestRequest struct {
	Scope                                  string `json:"scope"`
	Reason                                 string `json:"reason"`
	ProposedAccessTokenTTLSeconds          *int   `json:"proposed_access_token_ttl_seconds,omitempty"`
	ProposedRefreshTokenSlidingTTLSeconds  *int   `json:"proposed_refresh_token_sliding_ttl_seconds,omitempty"`
	ProposedRefreshTokenAbsoluteTTLSeconds *int   `json:"proposed_refresh_token_absolute_ttl_seconds,omitempty"`
}

func (s *Server) submitClientScopeRequest(w http.ResponseWriter, r *http.Request, ctx *clientCtx) {
	var req submitScopeRequestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	req.Scope = strings.TrimSpace(req.Scope)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Scope == "" || req.Reason == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"scope and reason are both required", nil))
		return
	}
	if !oauth.IsSpecialScope(req.Scope) {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"only special scopes (e.g. offline_access) require approval; non-special scopes are set directly via PATCH /clients/<id>", nil))
		return
	}

	row := &models.OAuthScopeRequest{
		ClientID:                               ctx.client.ClientID,
		Scope:                                  req.Scope,
		Reason:                                 req.Reason,
		ProposedAccessTokenTTLSeconds:          req.ProposedAccessTokenTTLSeconds,
		ProposedRefreshTokenSlidingTTLSeconds:  req.ProposedRefreshTokenSlidingTTLSeconds,
		ProposedRefreshTokenAbsoluteTTLSeconds: req.ProposedRefreshTokenAbsoluteTTLSeconds,
	}
	// Stamp the submitter from the bearer's `sub` claim so audit
	// history shows which developer (not just which client)
	// requested the scope.
	submitter := ctx.requesterID
	if submitter != uuid.Nil {
		row.SubmittedBy = &submitter
	}

	if err := s.scopeRequestRepo.Create(r.Context(), row); err != nil {
		if errors.Is(err, repository.ErrScopeRequestExists) {
			response.WriteJSON(w, http.StatusConflict,
				response.Fail("SCOPE_REQUEST_EXISTS",
					"a pending request for this scope already exists; wait for review or contact the operator", nil))
			return
		}
		s.logger.App.Error("submitClientScopeRequest: repo", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create scope request", nil))
		return
	}

	s.logger.Security.Info("scope request submitted via portal",
		zap.String("id", row.ID.String()),
		zap.String("client_id", row.ClientID),
		zap.String("scope", row.Scope),
		zap.String("submitted_by", ctx.requesterID.String()))

	response.WriteJSON(w, http.StatusCreated, response.Success(map[string]any{
		"scope_request": toScopeRequestView(row),
	}))
}
