package control

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
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
}

type adminClientView struct {
	ClientID      string `json:"client_id"`
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	HomepageURL   string `json:"homepage_url,omitempty"`
	ClientType    string `json:"client_type"`
	Public        bool   `json:"public"`
	RedirectURIs  string `json:"redirect_uris"`
	AllowedScopes string `json:"allowed_scopes"`
	AuthTypes     string `json:"auth_types"`
	BuiltIn       bool   `json:"built_in"`
	RequirePKCE   bool   `json:"require_pkce"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
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
		ClientID:      c.ClientID,
		Name:          c.Name,
		Description:   c.Description,
		HomepageURL:   c.HomepageURL,
		ClientType:    label,
		Public:        c.Public,
		RedirectURIs:  c.RedirectURIs,
		AllowedScopes: c.AllowedScopes,
		AuthTypes:     c.AuthTypes,
		BuiltIn:       c.BuiltIn,
		RequirePKCE:   c.RequirePKCE,
		CreatedAt:     c.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     c.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
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

	clientID, err := generateAdminClientID()
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not generate client_id", nil))
		return
	}
	var (
		secret string
		hash   string
	)
	if !public {
		secret, err = generateAdminClientSecret()
		if err != nil {
			response.WriteJSON(w, http.StatusInternalServerError,
				response.Fail("INTERNAL", "could not generate client secret", nil))
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if err != nil {
			response.WriteJSON(w, http.StatusInternalServerError,
				response.Fail("INTERNAL", "could not hash secret", nil))
			return
		}
		hash = string(h)
	}

	row := models.ClientService{
		ClientID:         clientID,
		ClientSecretHash: hash,
		Name:             req.Name,
		Description:      req.Description,
		HomepageURL:      req.HomepageURL,
		RedirectURIs:     req.RedirectURIs,
		AllowedScopes:    req.AllowedScopes,
		AuthTypes:        string(models.AuthTypeAuthorizationCode),
		BuiltIn:          false,
		Public:           public,
		RequirePKCE:      requirePKCE,
		// OwnerUserID stays NULL — operator-created clients have no
		// per-user owner. The /clients API-server canManage() check
		// (admin/root user_type can manage anything) still allows
		// later UI-driven edits by an authenticated operator.
		OwnerUserID: nil,
	}
	if err := s.db.WithContext(r.Context()).Create(&row).Error; err != nil {
		s.logger.App.Error("adminCreateClient: db insert", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("INTERNAL", "could not create client", nil))
		return
	}

	s.logger.Security.Info("oauth client created via control plane",
		zap.String("client_id", clientID),
		zap.String("name", req.Name),
		zap.String("client_type", req.ClientType),
		zap.Bool("require_pkce", requirePKCE))

	response.WriteJSON(w, http.StatusCreated, response.Success(adminCreateClientResponse{
		Client:       toAdminClientView(&row),
		ClientSecret: secret,
	}))
}

// generateAdminClientID produces a `tc-` (tenant-client) prefixed
// 10-hex-char ID. Mirrors the API-server's generateClientID — same
// shape so operators reading the DB can't tell at a glance which
// surface a row was created through.
func generateAdminClientID() (string, error) {
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

// generateAdminClientSecret produces a 32-byte base64url secret.
// Same entropy + format as the API-server side.
func generateAdminClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
