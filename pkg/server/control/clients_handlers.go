package control

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Phase 8 OAuth-client management endpoints. Same gating model as
// users_handlers.go: mTLS + portal-client CN, plus an
// X-Akashic-On-Behalf-Of header that names the user the request acts
// for. Authorization is enforced per-row: the requester must own the
// client, OR be an admin/root.
//
// Built-in clients (BuiltIn=true) are READ-ONLY through these
// endpoints — they're managed by EnsureBuiltInClients on every
// startup and the portal must not edit them. Attempts to PATCH /
// DELETE / rotate-secret on a built-in return 403 BUILTIN_IMMUTABLE.

// ─── shared types ──────────────────────────────────────────────────

type clientView struct {
	ClientID      string  `json:"client_id"`
	Name          string  `json:"name"`
	Description   string  `json:"description,omitempty"`
	HomepageURL   string  `json:"homepage_url,omitempty"`
	RedirectURIs  string  `json:"redirect_uris"`
	AllowedScopes string  `json:"allowed_scopes"`
	AuthTypes     string  `json:"auth_types"`
	BuiltIn       bool    `json:"built_in"`
	RoleAllowlist string  `json:"role_allowlist,omitempty"`
	RequirePKCE   bool    `json:"require_pkce"`
	OwnerUserID   *string `json:"owner_user_id,omitempty"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

func toClientView(c *models.ClientService) clientView {
	v := clientView{
		ClientID:      c.ClientID,
		Name:          c.Name,
		Description:   c.Description,
		HomepageURL:   c.HomepageURL,
		RedirectURIs:  c.RedirectURIs,
		AllowedScopes: c.AllowedScopes,
		AuthTypes:     c.AuthTypes,
		BuiltIn:       c.BuiltIn,
		RoleAllowlist: c.RoleAllowlist,
		RequirePKCE:   c.RequirePKCE,
		CreatedAt:     c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     c.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if c.OwnerUserID != nil {
		s := c.OwnerUserID.String()
		v.OwnerUserID = &s
	}
	return v
}

// canManage returns true iff the requester is allowed to read AND
// write the given client. Owner OR admin/root is allowed.
//
// Read-only access (e.g. for /clients/:id GET as a non-owner) is
// not currently supported — Phase 8's portal exposes only the
// requester's own clients. If a "browse all clients" admin view
// lands later, this check should split into canRead / canWrite.
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

// clientCtx bundles the resolved requester + client row for the
// per-client handlers. Cuts down on repeated DB lookups and lets
// canManage be a one-liner.
type clientCtx struct {
	requesterID uuid.UUID
	requester   *models.User
	client      *models.ClientService
}

// loadClientCtx fetches the requester (by uid) and the named client
// (by client_id from the path). Returns either the loaded ctx or a
// completed HTTP error response (caller checks `ok`).
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

func (s *Server) handleListMyClients(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
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
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	HomepageURL   string `json:"homepage_url,omitempty"`
	RedirectURIs  string `json:"redirect_uris"`  // CSV, exact-match
	AllowedScopes string `json:"allowed_scopes"` // space-separated
}

type createClientResponse struct {
	Client       clientView `json:"client"`
	ClientSecret string     `json:"client_secret"` // SHOWN ONCE
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
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
	if req.Name == "" || req.RedirectURIs == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail("VALIDATION_FAILED",
				"name and redirect_uris are required", nil))
		return
	}
	if req.AllowedScopes == "" {
		req.AllowedScopes = "openid profile email"
	}

	// Phase 8: client_id is auto-generated. We use a short random
	// slug — readable, unique, easy to type. Format: "tc-<10 hex>"
	// for "tenant client." Built-ins use human-meaningful IDs
	// (akashic-admin, akashic-portal); user-registered clients get
	// random IDs to avoid name collisions and squatting.
	clientID, err := generateClientID()
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not generate client_id", nil))
		return
	}

	// Generate the client secret — shown ONCE in the response, never
	// retrievable again. 32 random bytes, base64url-encoded.
	secret, err := generateClientSecret()
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not generate client secret", nil))
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not hash secret", nil))
		return
	}

	owner := uid
	row := models.ClientService{
		ClientID:         clientID,
		ClientSecretHash: string(hash),
		Name:             req.Name,
		Description:      req.Description,
		HomepageURL:      req.HomepageURL,
		RedirectURIs:     req.RedirectURIs,
		AllowedScopes:    req.AllowedScopes,
		// Phase 8 only enables authorization_code+PKCE — match Phase 7's policy
		AuthTypes:   string(models.AuthTypeAuthorizationCode),
		BuiltIn:     false,
		RequirePKCE: true,
		OwnerUserID: &owner,
	}
	if err := s.db.WithContext(r.Context()).Create(&row).Error; err != nil {
		s.logger.App.Error("createClient: db insert", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create client", nil))
		return
	}

	s.logger.Security.Info("oauth client created",
		zap.String("client_id", clientID),
		zap.String("owner_user_id", uid.String()),
		zap.String("name", req.Name))

	response.WriteJSON(w, http.StatusCreated, response.Success(createClientResponse{
		Client:       toClientView(&row),
		ClientSecret: secret,
	}))
}

// ─── GET / PATCH / DELETE /clients/:id  +  POST /clients/:id/rotate-secret ─

// Path parsing: routes register a single handler on /clients/ that
// dispatches based on the path tail. We avoid an HTTP router because
// the rest of the control plane uses plain ServeMux; staying
// consistent matters more than the slightly cleaner routing a real
// router would give us.

// extractClientID returns the client_id from a path like
// "/clients/<id>" or "/clients/<id>/rotate-secret". Returns "" if
// the path doesn't fit either pattern.
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

func (s *Server) handleClientByID(w http.ResponseWriter, r *http.Request, uid uuid.UUID) {
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
					"only GET, PATCH, DELETE are allowed on this resource", nil))
		}
	case "rotate-secret":
		if r.Method != http.MethodPost {
			response.WriteJSON(w, http.StatusMethodNotAllowed,
				response.Fail(response.ErrMethodNotAllowed,
					"only POST is allowed on rotate-secret", nil))
			return
		}
		s.handleRotateSecret(w, r, ctx)
	default:
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("NOT_FOUND", "no route for this path", nil))
	}
}

func (s *Server) handleGetClient(w http.ResponseWriter, _ *http.Request, ctx *clientCtx) {
	response.WriteJSON(w, http.StatusOK,
		response.Success(toClientView(ctx.client)))
}

type patchClientRequest struct {
	Name          *string `json:"name,omitempty"`
	Description   *string `json:"description,omitempty"`
	HomepageURL   *string `json:"homepage_url,omitempty"`
	RedirectURIs  *string `json:"redirect_uris,omitempty"`
	AllowedScopes *string `json:"allowed_scopes,omitempty"`
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
	if req.AllowedScopes != nil {
		updates["allowed_scopes"] = strings.TrimSpace(*req.AllowedScopes)
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

	// Re-load to return the post-update view
	var fresh models.ClientService
	if err := s.db.WithContext(r.Context()).
		Where("client_id = ?", ctx.client.ClientID).First(&fresh).Error; err == nil {
		response.WriteJSON(w, http.StatusOK,
			response.Success(toClientView(&fresh)))
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
	if ctx.client.BuiltIn {
		response.WriteJSON(w, http.StatusForbidden,
			response.Fail("BUILTIN_IMMUTABLE",
				"built-in clients' secrets are managed by the server itself, not the portal", nil))
		return
	}
	secret, err := generateClientSecret()
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not generate secret", nil))
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not hash secret", nil))
		return
	}
	if err := s.db.WithContext(r.Context()).Model(ctx.client).
		Update("client_secret_hash", string(hash)).Error; err != nil {
		s.logger.App.Error("rotateSecret: db", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not rotate secret", nil))
		return
	}
	s.logger.Security.Info("oauth client secret rotated",
		zap.String("client_id", ctx.client.ClientID),
		zap.String("owner_user_id", ctx.requesterID.String()))
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"client_id":     ctx.client.ClientID,
		"client_secret": secret, // SHOWN ONCE
	}))
}

// ─── helpers ───────────────────────────────────────────────────────

// generateClientID returns a new tenant-client identifier of the form
// "tc-<10 hex chars>". Hex over base64 because the identifier shows
// up in URLs/configs/CLI args; alphanum+dash is friendlier than
// base64 there.
func generateClientID() (string, error) {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const hex = "0123456789abcdef"
	out := make([]byte, len(buf)*2)
	for i, b := range buf {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0f]
	}
	return "tc-" + string(out), nil
}

// generateClientSecret returns a 32-byte random value, base64url-
// encoded (~43 chars). Used as a one-time password the developer
// captures at registration / rotation time.
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
