package control

import (
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// clientIP extracts the source IP from an http.Request. RemoteAddr is in
// "host:port" form; we split off the port for human-readable audit logs.
// Falls back to the raw RemoteAddr if parsing fails.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Middleware: Require bootstrap mode to be active
func (s *Server) requireBootstrapMode(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.bootstrapMgr == nil {
			response.WriteJSON(w, response.StatusInternalServerError,
				response.Fail(response.ErrInternalServer, "Bootstrap manager not initialized", nil))
			return
		}

		needs, err := s.bootstrapMgr.NeedsBootstrap(r.Context())
		if err != nil {
			response.WriteJSON(w, response.StatusInternalServerError,
				response.Fail(response.ErrInternalServer, "Failed to check bootstrap status", map[string]any{
					"error": err.Error(),
				}))
			return
		}

		if !needs {
			response.WriteJSON(w, http.StatusForbidden,
				response.Fail("BOOTSTRAP_COMPLETE", "Bootstrap already completed", nil))
			return
		}

		next(w, r)
	}
}

// Middleware: Require client cert with one of the listed Common Names.
// This replaces the prior requireCLI helper which trusted the User-Agent
// header (trivially spoofable). Phase 4 made mTLS mandatory on the control
// plane, so every request reaching this middleware already carries a
// verified peer certificate signed by pki-mtls-akashic-ctrl. The CN is the
// stable, RFC-grade identity we should authorize against.
//
// allowedCNs lists the Common Names permitted to call the wrapped handler.
// Typical values: "cli.akashic.local" (akashic-cli), "bff.akashic.local"
// (admin BFF, when added in Phase 6).
//
// Failure modes:
//   - No TLS or no peer cert        → 403 MTLS_REQUIRED
//   - Peer cert CN not in allowlist → 403 CLIENT_NOT_ALLOWED (CN included
//                                       in error details for diagnostic use)
func requireClientIdentity(allowedCNs ...string) func(http.HandlerFunc) http.HandlerFunc {
	allowed := make(map[string]bool, len(allowedCNs))
	for _, cn := range allowedCNs {
		allowed[cn] = true
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				response.WriteJSON(w, http.StatusForbidden,
					response.Fail("MTLS_REQUIRED", "client certificate required for this endpoint", nil))
				return
			}
			cn := r.TLS.PeerCertificates[0].Subject.CommonName
			if !allowed[cn] {
				response.WriteJSON(w, http.StatusForbidden,
					response.Fail("CLIENT_NOT_ALLOWED", "this endpoint is not authorized for the presented client certificate", map[string]any{
						"presented_cn": cn,
						"allowed_cns":  allowedCNs,
					}))
				return
			}
			next(w, r)
		}
	}
}

// GET /bootstrap/status
// Returns the current bootstrap status
func (s *Server) handleBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling bootstrap status request")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		return
	}

	if s.bootstrapMgr == nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrInternalServer, "Bootstrap manager not initialized", nil))
		return
	}

	status, err := s.bootstrapMgr.GetBootstrapStatus(r.Context())
	if err != nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrInternalServer, "Failed to get bootstrap status", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to get bootstrap status", zap.Error(err))
		return
	}

	response.WriteJSON(w, response.StatusOK, response.Success(status))
}

// GET /bootstrap/token (CLI only)
// Returns the current bootstrap token
func (s *Server) handleGetBootstrapToken(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling get bootstrap token request (CLI)")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		return
	}

	token, err := s.bootstrapMgr.GetToken(r.Context())
	if err != nil {
		response.WriteJSON(w, http.StatusNotFound,
			response.Fail("TOKEN_NOT_FOUND", "Bootstrap token not found or expired", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Debug("Bootstrap token not found or expired")
		return
	}

	// Get TTL
	ttl, _ := s.bootstrapMgr.GetTokenTTL(r.Context())

	s.logger.Security.Info("Bootstrap token retrieved via CLI")

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"token":            token,
		"ttl_seconds":      int(ttl.Seconds()),
		"expires_in_human": ttl.String(),
	}))
}

// POST /bootstrap/token/regenerate (CLI only)
// Regenerates the bootstrap token. Accepts ?force=true to overwrite an
// existing valid token (otherwise returns 409 if one is already live).
func (s *Server) handleRegenerateToken(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling regenerate bootstrap token request (CLI)")

	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		return
	}

	// `?force=true` (or `?force=1`) opts in to overwriting a still-valid token
	force := false
	switch r.URL.Query().Get("force") {
	case "true", "1", "yes":
		force = true
	}

	token, err := s.bootstrapMgr.RegenerateToken(r.Context(), force)
	if err != nil {
		// "already exists" is a conflict, not a server error
		if strings.Contains(err.Error(), "already exists") {
			response.WriteJSON(w, http.StatusConflict,
				response.Fail("TOKEN_ALREADY_EXISTS", err.Error(), map[string]any{
					"hint": "pass ?force=true to overwrite the existing token",
				}))
			return
		}
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrInternalServer, "Failed to regenerate token", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to regenerate bootstrap token", zap.Error(err))
		return
	}

	s.logger.Security.Warn("Bootstrap token regenerated via CLI - old token invalidated",
		zap.Bool("forced", force))

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"token":   token,
		"forced":  force,
		"message": "Token regenerated successfully - old token is now invalid",
	}))
}

// POST /bootstrap/root
// Creates the root user account
func (s *Server) handleCreateRootUser(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling create root user request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		return
	}

	var req struct {
		Token    string `json:"token"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail(response.ErrInvalidRequest, "Invalid request body", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Debug("Invalid request body for root user creation", zap.Error(err))
		return
	}

	// Validate request fields
	if req.Token == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail(response.ErrInvalidRequest, "Bootstrap token is required", nil))
		return
	}
	if req.Username == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail(response.ErrInvalidRequest, "Username is required", nil))
		return
	}
	if req.Email == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail(response.ErrInvalidRequest, "Email is required", nil))
		return
	}
	if req.Password == "" {
		response.WriteJSON(w, http.StatusBadRequest,
			response.Fail(response.ErrInvalidRequest, "Password is required", nil))
		return
	}

	// Capture audit context: who is calling, from where? The mTLS layer
	// (Phase 4) guarantees PeerCertificates is present and verified for any
	// request reaching this handler.
	clientCN := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	attempt := &bootstrap.AttemptContext{
		ClientCN: clientCN,
		RemoteIP: clientIP(r),
	}

	// Create root user via bootstrap manager
	user, err := s.bootstrapMgr.CreateRootUser(r.Context(), req.Token, &models.CreateUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
		UserType: models.UserTypeRoot, // Will be enforced by manager
	}, attempt)

	if err != nil {
		s.logger.Security.Warn("Failed root user creation attempt",
			zap.String("username", req.Username),
			zap.String("email", req.Email),
			zap.Error(err))

		// Determine appropriate error response
		statusCode := http.StatusBadRequest
		errorCode := "ROOT_CREATION_FAILED"

		// Check for specific error types
		if strings.Contains(err.Error(), "invalid or expired token") {
			statusCode = http.StatusUnauthorized
			errorCode = "INVALID_TOKEN"
		} else if strings.Contains(err.Error(), "bootstrap already completed") {
			statusCode = http.StatusConflict
			errorCode = "BOOTSTRAP_COMPLETE"
		} else if strings.Contains(err.Error(), "password policy") {
			errorCode = "PASSWORD_POLICY_VIOLATION"
		} else if strings.Contains(err.Error(), "validation failed") {
			errorCode = "VALIDATION_FAILED"
		}

		response.WriteJSON(w, statusCode,
			response.Fail(errorCode, err.Error(), nil))
		return
	}

	s.logger.Security.Info("Root user created successfully via control API",
		zap.String("user_id", user.ID.String()),
		zap.String("ldap_dn", user.LdapDN),
		zap.String("username", req.Username),
		zap.String("email", req.Email))

	// Return user info (without password hash)
	response.WriteJSON(w, http.StatusCreated, response.Success(map[string]any{
		"user": map[string]any{
			"uid":        user.ID,
			"ldap_dn":    user.LdapDN,
			"username":   req.Username,
			"email":      req.Email,
			"user_type":  user.UserType,
			"created_at": user.CreatedAt,
		},
		"message": "Root user created successfully - bootstrap complete. NOTE: User must exist in LDAP.",
	}))
}
