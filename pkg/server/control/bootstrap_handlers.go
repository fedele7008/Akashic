package control

import (
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/server/response"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

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

// Middleware: Require CLI user-agent (for token fetch/regenerate endpoints)
func requireCLI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if !strings.Contains(ua, "akashic-cli/") {
			response.WriteJSON(w, http.StatusForbidden,
				response.Fail("CLI_ONLY", "This endpoint is only accessible via akashic-cli", map[string]any{
					"user_agent": ua,
				}))
			return
		}
		next(w, r)
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
// Regenerates the bootstrap token
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

	token, err := s.bootstrapMgr.RegenerateToken(r.Context())
	if err != nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrInternalServer, "Failed to regenerate token", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to regenerate bootstrap token", zap.Error(err))
		return
	}

	s.logger.Security.Warn("Bootstrap token regenerated via CLI - old token invalidated")

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"token":   token,
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

	// Create root user via bootstrap manager
	user, err := s.bootstrapMgr.CreateRootUser(r.Context(), req.Token, &models.CreateUserRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
		UserType: models.UserTypeRoot, // Will be enforced by manager
	})

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
		zap.String("username", user.Username),
		zap.String("email", user.Email))

	// Return user info (without password hash)
	response.WriteJSON(w, http.StatusCreated, response.Success(map[string]any{
		"user": map[string]any{
			"id":         user.ID,
			"username":   user.Username,
			"email":      user.Email,
			"user_type":  user.UserType,
			"is_active":  user.IsActive,
			"created_at": user.CreatedAt,
		},
		"message": "Root user created successfully - bootstrap complete",
	}))
}
