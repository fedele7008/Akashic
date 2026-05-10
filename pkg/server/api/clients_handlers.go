package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/clientservice"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Phase 8 OAuth-client management endpoints. Bearer-token authenticated
// (the requester's identity comes from the access token's `sub` claim).
// Built-in clients are read-only via this surface; admin overrides
// (force-edit any client) live on the control plane under /admin/clients.

// ─── shared types ──────────────────────────────────────────────────

type clientView struct {
	ClientID    string `json:"client_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	HomepageURL string `json:"homepage_url,omitempty"`
	// ClientType is the operator-facing label derived from Public:
	//   "WEB"  → confidential client (server-side, holds
	//            client_secret). Maps to BFF/Backend-for-Frontend
	//            in architectural terms; the operator-facing label
	//            is "WEB" to match how Auth0/Okta/Cognito name this
	//            shape on their create-client forms.
	//   "SPA"  → public client (PKCE-only, no shared secret).
	//            Browser-only or native apps with no server-side
	//            secret storage.
	//
	// Footgun: "WEB" doesn't mean "anything that runs in a browser"
	// — a SPA also runs in a browser. The clarifying question is
	// "does the app have a server you control that can store
	// secrets?" Yes → WEB. No → SPA.
	//
	// Surfaced alongside the protocol-correct `public` bool so UI
	// code (admin-bff, <akashic-clients> widget) can render either.
	ClientType     string  `json:"client_type"`
	Public         bool    `json:"public"`
	RedirectURIs   string  `json:"redirect_uris"`
	AllowedScopes  string  `json:"allowed_scopes"`
	RequiredScopes string  `json:"required_scopes"`
	OptionalScopes string  `json:"optional_scopes"`
	AuthTypes      string  `json:"auth_types"`
	BuiltIn        bool    `json:"built_in"`
	RoleAllowlist  string  `json:"role_allowlist,omitempty"`
	RequirePKCE    bool    `json:"require_pkce"`
	IsTenantPortal bool    `json:"is_tenant_portal"`
	OwnerUserID    *string `json:"owner_user_id,omitempty"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
}

// Canonical wire labels for client_type. Always uppercase on the
// way out; case-insensitive on the way in (see parseClientType).
const (
	clientTypeWeb = "WEB" // confidential, server-side (a.k.a. BFF)
	clientTypeSPA = "SPA" // public, browser/native (PKCE-only)
)

func clientTypeLabel(public bool) string {
	if public {
		return clientTypeSPA
	}
	return clientTypeWeb
}

func toClientView(c *models.ClientService) clientView {
	v := clientView{
		ClientID:       c.ClientID,
		Name:           c.Name,
		Description:    c.Description,
		HomepageURL:    c.HomepageURL,
		ClientType:     clientTypeLabel(c.Public),
		Public:         c.Public,
		RedirectURIs:   c.RedirectURIs,
		AllowedScopes:  c.AllowedScopes,
		RequiredScopes: c.RequiredScopes,
		OptionalScopes: c.OptionalScopes,
		AuthTypes:      c.AuthTypes,
		BuiltIn:        c.BuiltIn,
		RoleAllowlist:  c.RoleAllowlist,
		RequirePKCE:    c.RequirePKCE,
		IsTenantPortal: c.IsTenantPortal,
		CreatedAt:      c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:      c.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if c.OwnerUserID != nil {
		s := c.OwnerUserID.String()
		v.OwnerUserID = &s
	}
	return v
}

type clientCtx struct {
	requesterID uuid.UUID
	requester   *models.User
	client      *models.ClientService
}

func (s *Server) canManage(ctx *clientCtx) bool {
	if ctx.requester.UserType == models.UserTypeAdmin ||
		ctx.requester.UserType == models.UserTypeRoot {
		return true
	}
	if ctx.client.OwnerUserID != nil && *ctx.client.OwnerUserID == ctx.requesterID {
		return true
	}
	return false
}

func (s *Server) loadClientCtx(w http.ResponseWriter, r *http.Request, uid uuid.UUID, clientID string) (*clientCtx, bool) {
	user, err := s.userRepo.GetUserByID(r.Context(), uid)
	if err != nil {
		response.WriteJSON(w, http.StatusUnauthorized,
			response.Fail("USER_NOT_FOUND",
				"requester user does not exist", nil))
		return nil, false
	}
	var c models.ClientService
	res := s.db.WithContext(r.Context()).Where("client_id = ?", clientID).First(&c)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("CLIENT_NOT_FOUND",
				"no such client_id", nil))
		return nil, false
	}
	if res.Error != nil {
		s.logger.App.Error("loadClientCtx: db lookup",
			zap.String("client_id", clientID), zap.Error(res.Error))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load client", nil))
		return nil, false
	}
	return &clientCtx{requesterID: uid, requester: user, client: &c}, true
}

// ─── GET /clients/mine ─────────────────────────────────────────────

func (s *Server) handleListMyClients(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodGet {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET is allowed", nil))
		return
	}
	var rows []models.ClientService
	if err := s.db.WithContext(r.Context()).
		Where("owner_user_id = ?", uid).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		s.logger.App.Error("listMyClients: db", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load clients", nil))
		return
	}
	views := make([]clientView, 0, len(rows))
	for i := range rows {
		views = append(views, toClientView(&rows[i]))
	}
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"clients": views}))
}

// ─── POST /clients ─────────────────────────────────────────────────

type createClientRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	HomepageURL string `json:"homepage_url,omitempty"`
	// ClientType is required:
	//   "WEB" — confidential / server-side (a.k.a. BFF). The app has
	//           a backend that can hold a client_secret; PKCE is
	//           configurable (default on, recommended).
	//   "SPA" — public / browser-only or native. No secure secret
	//           storage; PKCE is required (forced on by the model
	//           regardless of what the operator sends).
	// Case-insensitive on input; canonical "WEB"/"SPA" on output.
	// Determines whether a client_secret is provisioned and whether
	// RequirePKCE is operator-configurable.
	ClientType   string `json:"client_type"`
	RedirectURIs string `json:"redirect_uris"`
	// RequirePKCE applies only to WEB clients (operator-configurable
	// per OAuth 2.1 best-practice; default true). Ignored for SPA
	// clients (which always require PKCE — the field is forced true
	// by the model's BeforeCreate hook regardless).
	//
	// Pointer (*bool) so we can distinguish "operator omitted the
	// field" (→ default true) from "operator explicitly set false."
	RequirePKCE   *bool  `json:"require_pkce,omitempty"`
	AllowedScopes string `json:"allowed_scopes"`
	// Phase A scope split. Either may be empty; when both are
	// empty AND `allowed_scopes` is empty too, defaults to
	// required = "openid profile email". Mixing legacy
	// `allowed_scopes` with the split fields is rejected.
	// Special scopes (e.g. `offline_access`) are rejected at
	// create time — they require the scope-request workflow.
	RequiredScopes string `json:"required_scopes,omitempty"`
	OptionalScopes string `json:"optional_scopes,omitempty"`
}

type createClientResponse struct {
	Client clientView `json:"client"`
	// ClientSecret is the plaintext client_secret, returned ONCE at
	// creation time so the operator can copy it into their WEB
	// app's secret store. Never persisted in plaintext server-side.
	//
	// Empty string for SPA (public) clients — they have no secret
	// to share. The omitempty here helps callers JSON-decode into a
	// "secret may be absent" shape without special-casing.
	ClientSecret string `json:"client_secret,omitempty"`
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	req.Name = strings.TrimSpace(req.Name)
	req.RedirectURIs = strings.TrimSpace(req.RedirectURIs)
	// Case-insensitive on input — operators will type "web", "WEB",
	// "Web", etc. Normalise to canonical uppercase before dispatch.
	req.ClientType = strings.ToUpper(strings.TrimSpace(req.ClientType))
	if req.Name == "" || req.RedirectURIs == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"name and redirect_uris are required", nil))
		return
	}
	var public bool
	switch req.ClientType {
	case clientTypeWeb:
		public = false
	case clientTypeSPA:
		public = true
	case "":
		// Validation message reads as the disambiguating question
		// rather than a list of magic strings — most operators
		// pause on "WEB vs SPA" and the answer to "do you have a
		// server you control?" is what they actually need to pick.
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"client_type is required: 'WEB' (server-side app that can hold a client_secret) or 'SPA' (browser/native app, PKCE-only)", nil))
		return
	default:
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"client_type must be 'WEB' or 'SPA'", nil))
		return
	}
	// Phase A: resolve required/optional scopes. Three accepted
	// caller shapes (mixing them is rejected):
	//   1. (legacy) allowed_scopes only       → required = allowed
	//   2. required_scopes / optional_scopes  → use as given
	//   3. nothing                            → required = "openid profile email"
	if req.AllowedScopes != "" && (req.RequiredScopes != "" || req.OptionalScopes != "") {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"send either allowed_scopes (legacy) OR required_scopes/optional_scopes — not both", nil))
		return
	}
	required := req.RequiredScopes
	optional := req.OptionalScopes
	if required == "" && optional == "" {
		if req.AllowedScopes != "" {
			required = req.AllowedScopes
		} else {
			required = "openid profile email"
		}
	}
	required = oauth.ParseScopeSet(required).String()
	optional = oauth.ParseScopeSet(optional).String()

	// Special scopes can't be set at create time — they need an
	// approved scope-request, which requires the client to exist
	// first. Surface the workflow.
	for _, t := range oauth.ParseScopes(required + " " + optional) {
		if oauth.IsSpecialScope(t) {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("SPECIAL_SCOPE_REQUIRES_REQUEST",
					"scope '"+t+"' requires admin approval — register the client first, then submit a scope request", nil))
			return
		}
	}
	// Validate against tenant ceiling.
	if s.policySvc == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_READY", "policy service not yet wired", nil))
		return
	}
	policyRow, err := s.policySvc.Get(r.Context())
	if err != nil {
		s.logger.App.Error("createClient: read policy", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not read tenant policy", nil))
		return
	}
	if err := oauth.ValidateClientScopeSplit(required, optional, policyRow.AllowedClientScopes); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED", err.Error(), nil))
		return
	}
	allowed := oauth.UnionScopes(required, optional)

	// Decide on PKCE: SPA always-true (model invariant); BFF
	// operator-configurable, default true.
	requirePKCE := true
	if !public && req.RequirePKCE != nil {
		requirePKCE = *req.RequirePKCE
	}

	// Phase 9e v2: qualification + routing. The eligibility service
	// composes the verified-email gate and the per-user cap into
	// `Eligible`; `ApprovalRequired` is a separate dimension
	// signalling that this endpoint is the wrong route — the user
	// must POST through /client-registration-requests instead so
	// the registration goes through the approval workflow. Fail-
	// soft when the service isn't wired (preserves the pre-9e
	// free-for-all if an operator backs out the wiring).
	s.mu.RLock()
	clientRegSvc := s.clientRegSvc
	s.mu.RUnlock()
	if clientRegSvc != nil {
		elig, eErr := clientRegSvc.CheckEligibility(r.Context(), uid)
		if eErr != nil {
			s.logger.App.Error("createClient: eligibility check failed",
				zap.String("user_id", uid.String()), zap.Error(eErr))
			response.WriteJSON(w, http.StatusInternalServerError,
				response.Fail("INTERNAL", "could not check eligibility", nil))
			return
		}
		if !elig.Eligible {
			code := "NOT_ELIGIBLE"
			msg := "you are not eligible to register clients at this time"
			if len(elig.Missing) > 0 {
				switch elig.Missing[0] {
				case "email_verified":
					code = "EMAIL_NOT_VERIFIED"
					msg = "your email must be verified before you can register OAuth clients"
				case "cap_reached":
					code = "CAP_REACHED"
					msg = "you have reached your client-registration cap; delete an existing client or contact your administrator for a higher cap"
				}
			}
			response.WriteJSON(w, http.StatusForbidden,
				response.Fail(code, msg, map[string]any{
					"missing":               elig.Missing,
					"effective_max_clients": elig.EffectiveMaxClients,
					"current_client_count":  elig.CurrentClientCount,
					"pending_request_count": elig.PendingRequestCount,
				}))
			return
		}
		if elig.ApprovalRequired {
			response.WriteJSON(w, http.StatusForbidden,
				response.Fail("APPROVAL_REQUIRED",
					"this tenant requires admin approval; submit through "+
						"POST /client-registration-requests instead", nil))
			return
		}
	}

	owner := uid
	result, err := clientservice.Create(r.Context(), s.db.DB, clientservice.CreateParams{
		Name:           req.Name,
		Description:    req.Description,
		HomepageURL:    req.HomepageURL,
		Public:         public,
		RequirePKCE:    requirePKCE,
		RedirectURIs:   req.RedirectURIs,
		AllowedScopes:  allowed,
		RequiredScopes: required,
		OptionalScopes: optional,
		OwnerUserID:    &owner,
	})
	if err != nil {
		s.logger.App.Error("createClient: clientservice.Create", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create client", nil))
		return
	}
	s.logger.Security.Info("oauth client created",
		zap.String("client_id", result.Client.ClientID),
		zap.String("owner_user_id", uid.String()),
		zap.String("name", req.Name),
		zap.String("client_type", req.ClientType),
		zap.Bool("require_pkce", requirePKCE))
	response.WriteJSON(w, http.StatusCreated, response.Success(createClientResponse{
		Client:       toClientView(result.Client),
		ClientSecret: result.Secret,
	}))
}

// ─── /clients/:id (+ /clients/:id/rotate-secret) dispatcher ────────

func extractClientID(path string) (id, action string) {
	const prefix = "/clients/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(path, prefix)
	if rest == "" || rest == "mine" {
		return "", ""
	}
	parts := strings.SplitN(rest, "/", 2)
	id = parts[0]
	if len(parts) == 2 {
		action = parts[1]
	}
	return id, action
}

func (s *Server) handleClientByID(w http.ResponseWriter, r *http.Request, uid uuid.UUID, _ *oauth.AccessTokenClaims) {
	clientID, action := extractClientID(r.URL.Path)
	if clientID == "" {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
		return
	}
	ctx, ok := s.loadClientCtx(w, r, uid, clientID)
	if !ok {
		return
	}
	if !s.canManage(ctx) {
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("NOT_OWNER",
				"you do not own this client", nil))
		return
	}

	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			s.handleGetClient(w, r, ctx)
		case http.MethodPatch:
			s.handlePatchClient(w, r, ctx)
		case http.MethodDelete:
			s.handleDeleteClient(w, r, ctx)
		default:
			response.WriteJSON(w, http.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"only GET, PATCH, DELETE are allowed", nil))
		}
	case "rotate-secret":
		if r.Method != http.MethodPost {
			response.WriteJSON(w, http.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"only POST is allowed on rotate-secret", nil))
			return
		}
		s.handleRotateSecret(w, r, ctx)
	case "scope-requests":
		// /clients/<id>/scope-requests — owner-scoped GET (list)
		// + POST (submit). Special-scope approval workflow.
		s.handleClientScopeRequests(w, r, ctx)
	default:
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
	}
}

func (s *Server) handleGetClient(w http.ResponseWriter, _ *http.Request, ctx *clientCtx) {
	response.WriteJSON(w, http.StatusOK, response.Success(toClientView(ctx.client)))
}

type patchClientRequest struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	HomepageURL   *string `json:"homepage_url,omitempty"`
	RedirectURIs  *string `json:"redirect_uris,omitempty"`
	AllowedScopes *string `json:"allowed_scopes,omitempty"`
	// Phase A: required/optional scope split. Same accept rules as
	// the create path — mixing legacy `allowed_scopes` with split
	// fields is rejected. Special scopes here go through the gate:
	// allowed iff an approved `oauth_scope_requests` row exists.
	RequiredScopes *string `json:"required_scopes,omitempty"`
	OptionalScopes *string `json:"optional_scopes,omitempty"`
}

func (s *Server) handlePatchClient(w http.ResponseWriter, r *http.Request, ctx *clientCtx) {
	if ctx.client.BuiltIn {
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("BUILTIN_IMMUTABLE",
				"built-in clients cannot be edited via the portal API", nil))
		return
	}
	var req patchClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST", "could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	updates := map[string]any{}
	if req.Name != nil {
		updates["name"] = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.HomepageURL != nil {
		updates["homepage_url"] = *req.HomepageURL
	}
	if req.RedirectURIs != nil {
		updates["redirect_uris"] = strings.TrimSpace(*req.RedirectURIs)
	}
	// Scope handling — three caller shapes (legacy, split, none).
	// Mirrors the control plane's adminPatchClient logic so the
	// same invariants apply on the developer-side surface.
	scopeMode1 := req.AllowedScopes != nil
	scopeMode2 := req.RequiredScopes != nil || req.OptionalScopes != nil
	if scopeMode1 && scopeMode2 {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"send either allowed_scopes (legacy) OR required_scopes/optional_scopes — not both", nil))
		return
	}
	if scopeMode1 || scopeMode2 {
		if s.policySvc == nil {
			response.WriteJSON(w, http.StatusServiceUnavailable,
				response.Fail("API_NOT_READY", "policy service not yet wired", nil))
			return
		}
		policyRow, err := s.policySvc.Get(r.Context())
		if err != nil {
			s.logger.App.Error("patchClient: read policy", zap.Error(err))
			response.WriteJSON(w, http.StatusInternalServerError,
				response.Fail("INTERNAL", "could not read tenant policy", nil))
			return
		}
		var newRequired, newOptional string
		if scopeMode1 {
			newRequired = oauth.ParseScopeSet(*req.AllowedScopes).String()
			newOptional = ""
		} else {
			if req.RequiredScopes != nil {
				newRequired = oauth.ParseScopeSet(*req.RequiredScopes).String()
			} else {
				newRequired = ctx.client.RequiredScopes
			}
			if req.OptionalScopes != nil {
				newOptional = oauth.ParseScopeSet(*req.OptionalScopes).String()
			} else {
				newOptional = ctx.client.OptionalScopes
			}
		}
		// Special-scope gate: allowed iff approved.
		for _, t := range oauth.ParseScopes(newRequired + " " + newOptional) {
			if !oauth.IsSpecialScope(t) {
				continue
			}
			if s.scopeRequestRepo == nil {
				response.WriteJSON(w, http.StatusServiceUnavailable,
					response.Fail("API_NOT_READY",
						"scope-request repository not yet wired", nil))
				return
			}
			has, err := s.scopeRequestRepo.HasApproved(r.Context(), ctx.client.ClientID, t)
			if err != nil {
				s.logger.App.Error("patchClient: HasApproved", zap.Error(err))
				response.WriteJSON(w, http.StatusInternalServerError,
					response.Fail("INTERNAL", "could not check scope approvals", nil))
				return
			}
			if !has {
				response.WriteJSON(w, http.StatusBadRequest,
					response.Fail("SPECIAL_SCOPE_REQUIRES_REQUEST",
						"scope '"+t+"' requires an approved scope-request for this client", nil))
				return
			}
		}
		if err := oauth.ValidateClientScopeSplit(newRequired, newOptional, policyRow.AllowedClientScopes); err != nil {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("VALIDATION_FAILED", err.Error(), nil))
			return
		}
		updates["required_scopes"] = newRequired
		updates["optional_scopes"] = newOptional
		updates["allowed_scopes"] = oauth.UnionScopes(newRequired, newOptional)
	}
	if len(updates) == 0 {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"at least one editable field must be provided", nil))
		return
	}
	if err := s.db.WithContext(r.Context()).Model(ctx.client).
		Updates(updates).Error; err != nil {
		s.logger.App.Error("patchClient: db", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update client", nil))
		return
	}
	s.logger.Security.Info("oauth client updated",
		zap.String("client_id", ctx.client.ClientID),
		zap.String("owner_user_id", ctx.requesterID.String()))

	var fresh models.ClientService
	if err := s.db.WithContext(r.Context()).
		Where("client_id = ?", ctx.client.ClientID).First(&fresh).Error; err == nil {
		response.WriteJSON(w, http.StatusOK, response.Success(toClientView(&fresh)))
		return
	}
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"updated": true}))
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request, ctx *clientCtx) {
	if ctx.client.BuiltIn {
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("BUILTIN_IMMUTABLE",
				"built-in clients cannot be deleted via the portal API", nil))
		return
	}
	if err := s.db.WithContext(r.Context()).Delete(ctx.client).Error; err != nil {
		s.logger.App.Error("deleteClient: db", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not delete client", nil))
		return
	}
	s.logger.Security.Info("oauth client deleted",
		zap.String("client_id", ctx.client.ClientID),
		zap.String("owner_user_id", ctx.requesterID.String()))
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"deleted": true}))
}

func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request, ctx *clientCtx) {
	secret, err := clientservice.RotateSecret(r.Context(), s.db.DB, ctx.client)
	switch {
	case errors.Is(err, clientservice.ErrBuiltInImmutable):
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("BUILTIN_IMMUTABLE",
				"built-in clients' secrets are managed by the server itself", nil))
		return
	case errors.Is(err, clientservice.ErrPublicClientNoSecret):
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("PUBLIC_CLIENT_NO_SECRET",
				"public (SPA) clients have no client_secret; PKCE replaces it on every authorization", nil))
		return
	case err != nil:
		s.logger.App.Error("rotateSecret", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not rotate secret", nil))
		return
	}
	s.logger.Security.Info("oauth client secret rotated",
		zap.String("client_id", ctx.client.ClientID),
		zap.String("owner_user_id", ctx.requesterID.String()))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"client_id":     ctx.client.ClientID,
		"client_secret": secret,
	}))
}
