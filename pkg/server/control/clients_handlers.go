package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"akashic/akashic/pkg/clientservice"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Operator-side client management endpoints.
//
// These mirror parts of the API-server's bearer-authenticated /clients
// surface (pkg/server/api/clients_handlers.go) but on the mTLS-gated
// control plane — for use by the akashic-cli during the post-bootstrap
// "register your tenant portal" initialization step described in the
// clients-registration roadmap.
//
// Distinguishing characteristics from the API-server side:
//   - Auth is mTLS (operator's CLI cert), not bearer token. Anyone with
//     a valid client cert reaching this endpoint is treated as operator-
//     level. There is no per-user owner check — OwnerUserID stays NULL.
//   - Built-in clients are still off-limits (no admin override here).
//   - Logs go to the security channel like other operator-driven writes.
//
// TODO: refactor the WEB/SPA branching, secret generation, and bcrypt
// hashing into a shared pkg/clientservice package so this and the
// API-server handlers share business logic. Today they're duplicated
// — small enough to live with for one stage.

// Canonical wire labels for client_type, mirrored from
// pkg/server/api/clients_handlers.go. Always uppercase on the way
// out; case-insensitive on the way in. Footgun documented over
// there too: WEB ≠ "anything browser-facing" — the disambiguating
// question is "does the app have a server you control that can
// store secrets?"
const (
	adminClientTypeWeb = "WEB"
	adminClientTypeSPA = "SPA"
)

type adminCreateClientRequest struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	HomepageURL   string `json:"homepage_url,omitempty"`
	ClientType    string `json:"client_type"`
	RedirectURIs  string `json:"redirect_uris"`
	AllowedScopes string `json:"allowed_scopes,omitempty"`
	// RequirePKCE: WEB clients only — operator-configurable, default
	// true. Pointer (*bool) so we can distinguish "operator omitted"
	// (→ default true) from "operator explicitly set false". Forced
	// true for SPA regardless.
	RequirePKCE *bool `json:"require_pkce,omitempty"`
	// IsTenantPortal flags this client as operator-owned (first-
	// party). Any number of rows may carry the flag — a deployment
	// that ships multiple first-party apps (mail, calendar, drive)
	// will flag each one. Operator-only on this control-plane
	// surface; the api-server's bearer-auth /clients endpoint
	// ignores it on input.
	IsTenantPortal bool `json:"is_tenant_portal,omitempty"`
}

type adminClientView struct {
	ClientID       string `json:"client_id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	HomepageURL    string `json:"homepage_url,omitempty"`
	ClientType     string `json:"client_type"`
	Public         bool   `json:"public"`
	RedirectURIs   string `json:"redirect_uris"`
	AllowedScopes  string `json:"allowed_scopes"`
	AuthTypes      string `json:"auth_types"`
	BuiltIn        bool   `json:"built_in"`
	RequirePKCE    bool   `json:"require_pkce"`
	IsTenantPortal bool   `json:"is_tenant_portal"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

type adminCreateClientResponse struct {
	Client adminClientView `json:"client"`
	// ClientSecret is the plaintext, returned ONCE on creation for
	// WEB clients. Empty string for SPA. The operator MUST capture
	// this value now — only its bcrypt hash is persisted.
	ClientSecret string `json:"client_secret,omitempty"`
}

func toAdminClientView(c *models.ClientService) adminClientView {
	label := adminClientTypeWeb
	if c.Public {
		label = adminClientTypeSPA
	}
	return adminClientView{
		ClientID:       c.ClientID,
		Name:           c.Name,
		Description:    c.Description,
		HomepageURL:    c.HomepageURL,
		ClientType:     label,
		Public:         c.Public,
		RedirectURIs:   c.RedirectURIs,
		AllowedScopes:  c.AllowedScopes,
		AuthTypes:      c.AuthTypes,
		BuiltIn:        c.BuiltIn,
		RequirePKCE:    c.RequirePKCE,
		IsTenantPortal: c.IsTenantPortal,
		CreatedAt:      c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      c.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// handleAdminClients dispatches `/clients` (collection-level):
//   GET  → list every registered client (built-in + tenant)
//   POST → create a new client (calls handleAdminCreateClient)
//
// Per-id operations (DELETE, rotate-secret) live on `/clients/`
// (trailing slash) and are dispatched by handleAdminClientByID.
func (s *Server) handleAdminClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleAdminListClients(w, r)
	case http.MethodPost:
		s.handleAdminCreateClient(w, r)
	default:
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only GET or POST is allowed", nil))
	}
}

// handleAdminListClients implements GET /clients. Returns every
// registered client_service row (built-ins + operator-/tenant-
// registered) — the control plane is operator-level via mTLS, so
// there's no per-owner scoping like the api-server's /clients/mine.
func (s *Server) handleAdminListClients(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"the control server has no database handle yet", nil))
		return
	}
	var rows []models.ClientService
	if err := s.db.WithContext(r.Context()).
		Order("built_in DESC, created_at DESC").
		Find(&rows).Error; err != nil {
		s.logger.App.Error("adminListClients: db query", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not list clients", nil))
		return
	}
	views := make([]adminClientView, 0, len(rows))
	for i := range rows {
		views = append(views, toAdminClientView(&rows[i]))
	}
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"clients": views}))
}

// handleAdminClientByID dispatches `/clients/<id>[/<action>]`:
//   DELETE /clients/:id                → delete (rejects built-ins)
//   POST   /clients/:id/rotate-secret  → rotate (rejects built-ins, public)
//
// extractClientID is the same helper the api-server uses; we reach
// across packages rather than duplicate the parser.
func (s *Server) handleAdminClientByID(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"the control server has no database handle yet", nil))
		return
	}
	clientID, action := splitClientPath(r.URL.Path)
	if clientID == "" {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
		return
	}

	var existing models.ClientService
	res := s.db.WithContext(r.Context()).
		Where("client_id = ?", clientID).First(&existing)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("CLIENT_NOT_FOUND", "no such client_id", nil))
		return
	}
	if res.Error != nil {
		s.logger.App.Error("adminClientByID: db lookup",
			zap.String("client_id", clientID), zap.Error(res.Error))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not load client", nil))
		return
	}

	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			s.handleAdminGetClient(w, r, &existing)
		case http.MethodPatch:
			s.handleAdminPatchClient(w, r, &existing)
		case http.MethodDelete:
			s.handleAdminDeleteClient(w, r, &existing)
		default:
			response.WriteJSON(w, http.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"only GET, PATCH, DELETE are allowed on this path", nil))
		}
	case "rotate-secret":
		if r.Method != http.MethodPost {
			response.WriteJSON(w, http.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"only POST is allowed on rotate-secret", nil))
			return
		}
		s.handleAdminRotateSecret(w, r, &existing)
	default:
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
	}
}

// splitClientPath parses `/clients/<id>[/<action>]`. Mirrors the
// api-server's `extractClientID`; duplicated rather than imported
// to keep `pkg/server/control` free of `pkg/server/api` dependencies
// (the surfaces are intentionally independent).
func splitClientPath(path string) (id, action string) {
	const prefix = "/clients/"
	if !strings.HasPrefix(path, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(path, prefix)
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

// handleAdminDeleteClient implements DELETE /clients/:id. Built-ins
// are rejected — they're server-managed via EnsureBuiltInClients;
// deleting them here would leave the spec list disagreeing with the
// DB until the next boot. Tenant-registered clients are removed.
// handleAdminGetClient implements GET /clients/<id>. Read-only;
// returns the same view shape the list endpoint emits.
func (s *Server) handleAdminGetClient(w http.ResponseWriter, _ *http.Request, c *models.ClientService) {
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"client": toAdminClientView(c)}))
}

// adminPatchClientRequest is the body for PATCH /clients/<id>.
// Pointer fields preserve "leave unchanged" (omitted) vs. "set to
// empty/false" (explicit). Operator-only fields (role_allowlist,
// require_pkce, is_tenant_portal) live here that the api-server's
// bearer-auth PATCH refuses on input.
type adminPatchClientRequest struct {
	Name           *string `json:"name,omitempty"`
	Description    *string `json:"description,omitempty"`
	HomepageURL    *string `json:"homepage_url,omitempty"`
	RedirectURIs   *string `json:"redirect_uris,omitempty"`
	AllowedScopes  *string `json:"allowed_scopes,omitempty"`
	RoleAllowlist  *string `json:"role_allowlist,omitempty"`
	RequirePKCE    *bool   `json:"require_pkce,omitempty"`
	IsTenantPortal *bool   `json:"is_tenant_portal,omitempty"`
}

// handleAdminPatchClient implements PATCH /clients/<id>. Operator-
// scoped (mTLS); editable superset includes the three operator-only
// fields the api-server refuses (role_allowlist, require_pkce,
// is_tenant_portal). Built-ins reject all PATCH the same way they
// reject delete and rotate.
//
// SPA + require_pkce=false is rejected with VALIDATION_FAILED —
// public clients have no shared secret, so disabling PKCE removes
// their only credential mechanism. Same invariant the create path
// enforces.
func (s *Server) handleAdminPatchClient(w http.ResponseWriter, r *http.Request, c *models.ClientService) {
	if c.BuiltIn {
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("BUILTIN_IMMUTABLE",
				"built-in clients are server-managed and cannot be edited", nil))
		return
	}
	var req adminPatchClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	updates := map[string]any{}
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("VALIDATION_FAILED",
					"name cannot be empty", nil))
			return
		}
		updates["name"] = trimmed
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.HomepageURL != nil {
		updates["homepage_url"] = strings.TrimSpace(*req.HomepageURL)
	}
	if req.RedirectURIs != nil {
		trimmed := strings.TrimSpace(*req.RedirectURIs)
		if trimmed == "" {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("VALIDATION_FAILED",
					"redirect_uris cannot be empty", nil))
			return
		}
		updates["redirect_uris"] = trimmed
	}
	if req.AllowedScopes != nil {
		updates["allowed_scopes"] = strings.TrimSpace(*req.AllowedScopes)
	}
	if req.RoleAllowlist != nil {
		updates["role_allowlist"] = strings.TrimSpace(*req.RoleAllowlist)
	}
	if req.RequirePKCE != nil {
		// SPA must keep PKCE on — disabling it removes the only
		// credential mechanism a public client has. Reject sharply
		// rather than silently accepting and breaking the next
		// authorization flow.
		if c.Public && !*req.RequirePKCE {
			response.WriteJSON(w, http.StatusBadRequest,
				response.Fail("VALIDATION_FAILED",
					"PKCE cannot be disabled for SPA / public clients", nil))
			return
		}
		updates["require_pkce"] = *req.RequirePKCE
	}
	if req.IsTenantPortal != nil {
		updates["is_tenant_portal"] = *req.IsTenantPortal
	}
	if len(updates) == 0 {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"at least one editable field must be provided", nil))
		return
	}

	if err := s.db.WithContext(r.Context()).Model(c).Updates(updates).Error; err != nil {
		s.logger.App.Error("adminPatchClient: db",
			zap.String("client_id", c.ClientID), zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not update client", nil))
		return
	}

	// Reload to capture server-side normalization (TrimSpace,
	// updated_at, etc.) so the view we return matches what's now
	// in the DB rather than the request shape.
	var fresh models.ClientService
	if err := s.db.WithContext(r.Context()).
		Where("client_id = ?", c.ClientID).First(&fresh).Error; err != nil {
		s.logger.App.Warn("adminPatchClient: reload after update",
			zap.String("client_id", c.ClientID), zap.Error(err))
		response.WriteJSON(w, http.StatusOK,
			response.Success(map[string]any{"updated": true}))
		return
	}

	s.logger.Security.Info("oauth client updated via control plane",
		zap.String("client_id", c.ClientID),
		zap.Any("changed_fields", changedClientFields(req)))

	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"client": toAdminClientView(&fresh)}))
}

// changedClientFields summarises the PATCH for the security log —
// keeps the audit line precise without dumping the whole struct.
func changedClientFields(req adminPatchClientRequest) []string {
	out := []string{}
	if req.Name != nil {
		out = append(out, "name")
	}
	if req.Description != nil {
		out = append(out, "description")
	}
	if req.HomepageURL != nil {
		out = append(out, "homepage_url")
	}
	if req.RedirectURIs != nil {
		out = append(out, "redirect_uris")
	}
	if req.AllowedScopes != nil {
		out = append(out, "allowed_scopes")
	}
	if req.RoleAllowlist != nil {
		out = append(out, "role_allowlist")
	}
	if req.RequirePKCE != nil {
		out = append(out, "require_pkce")
	}
	if req.IsTenantPortal != nil {
		out = append(out, "is_tenant_portal")
	}
	return out
}

func (s *Server) handleAdminDeleteClient(w http.ResponseWriter, r *http.Request, c *models.ClientService) {
	if c.BuiltIn {
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("BUILTIN_IMMUTABLE",
				"built-in clients are managed by the server itself; toggle AKASHIC_OAUTH_ADMIN_BFF_ENABLED to remove the admin built-in",
				nil))
		return
	}
	if err := s.db.WithContext(r.Context()).Delete(c).Error; err != nil {
		s.logger.App.Error("adminDeleteClient: db", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not delete client", nil))
		return
	}
	s.logger.Security.Info("oauth client deleted via control plane",
		zap.String("client_id", c.ClientID),
		zap.String("name", c.Name))
	response.WriteJSON(w, http.StatusOK,
		response.Success(map[string]any{"deleted": true}))
}

// handleAdminRotateSecret implements POST /clients/:id/rotate-secret.
// Rejected for built-ins (server-managed) and public/SPA clients
// (have no shared secret — PKCE replaces it).
func (s *Server) handleAdminRotateSecret(w http.ResponseWriter, r *http.Request, c *models.ClientService) {
	secret, err := clientservice.RotateSecret(r.Context(), s.db, c)
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
		s.logger.App.Error("adminRotateSecret", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not rotate secret", nil))
		return
	}
	s.logger.Security.Info("oauth client secret rotated via control plane",
		zap.String("client_id", c.ClientID))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"client_id":     c.ClientID,
		"client_secret": secret,
	}))
}

// handleAdminCreateClient implements POST /clients on the control plane.
// mTLS-gated by the surrounding middleware chain (only operator certs
// reach this point).
func (s *Server) handleAdminCreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed,
				"only POST is allowed", nil))
		return
	}
	if s.db == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("DB_NOT_READY",
				"the control server has no database handle yet", nil))
		return
	}

	var req adminCreateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("INVALID_REQUEST",
				"could not parse request body", nil))
		return
	}
	defer r.Body.Close()

	req.Name = strings.TrimSpace(req.Name)
	req.RedirectURIs = strings.TrimSpace(req.RedirectURIs)
	req.ClientType = strings.ToUpper(strings.TrimSpace(req.ClientType))
	if req.Name == "" || req.RedirectURIs == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"name and redirect_uris are required", nil))
		return
	}

	var public bool
	switch req.ClientType {
	case adminClientTypeWeb:
		public = false
	case adminClientTypeSPA:
		public = true
	case "":
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

	if req.AllowedScopes == "" {
		req.AllowedScopes = "openid profile email"
	}

	requirePKCE := true
	if !public && req.RequirePKCE != nil {
		requirePKCE = *req.RequirePKCE
	}

	// OwnerUserID stays nil — operator-created clients have no
	// per-user owner. The api-server's canManage() check (admin/root
	// user_type can manage anything) still allows later UI-driven
	// edits by an authenticated operator.
	result, err := clientservice.Create(r.Context(), s.db, clientservice.CreateParams{
		Name:           req.Name,
		Description:    req.Description,
		HomepageURL:    req.HomepageURL,
		Public:         public,
		RequirePKCE:    requirePKCE,
		RedirectURIs:   req.RedirectURIs,
		AllowedScopes:  req.AllowedScopes,
		OwnerUserID:    nil,
		IsTenantPortal: req.IsTenantPortal,
	})
	if err != nil {
		s.logger.App.Error("adminCreateClient: clientservice.Create", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create client", nil))
		return
	}

	s.logger.Security.Info("oauth client created via control plane",
		zap.String("client_id", result.Client.ClientID),
		zap.String("name", req.Name),
		zap.String("client_type", req.ClientType),
		zap.Bool("require_pkce", requirePKCE))

	response.WriteJSON(w, http.StatusCreated, response.Success(adminCreateClientResponse{
		Client:       toAdminClientView(result.Client),
		ClientSecret: result.Secret,
	}))
}
