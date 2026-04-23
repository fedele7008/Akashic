package control

import (
	"akashic/akashic/pkg/server/response"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// handleHealth returns the control plane health status
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling health request")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"status": "healthy",
	}))
}

// handleStatus returns detailed server status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling status request")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	authStatus := s.stateManager.GetStatus()

	controlStatus := map[string]any{
		"state":   "running",
		"address": s.GetAddress(),
	}

	status := map[string]any{
		"control_server": controlStatus,
		"auth_server":    authStatus,
		"uptime":         s.GetUptime().String(),
		"pid":            s.GetPID(),
	}

	response.WriteJSON(w, response.StatusOK, response.Success(status))
}

// handleConfig returns the sanitized configuration
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling configuration request")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	cfg := s.config.GetConfig()
	sanitized := SanitizeConfig(cfg)

	response.WriteJSON(w, response.StatusOK, response.Success(sanitized))
}

// handleConfigReload reloads the configuration
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling configuration reload request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	s.logger.App.Info("Reloading configuration")

	if err := s.config.LoadConfig(); err != nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrConfigReloadFailed, "Failed to reload configuration", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to reload configuration", zap.Error(err))
		return
	}

	s.logger.App.Info("Configuration reloaded successfully")

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"message": "Configuration reloaded successfully",
	}))
}

// handleAuthStart starts the auth server
func (s *Server) handleAuthStart(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling authorization server start request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	currentState := s.stateManager.GetState()

	if currentState == StateRunning {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerRunning, "Auth server is already running", nil))
		s.logger.App.Debug("CTRL: auth server is already running")
		return
	}

	if currentState == StateStarting {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerStarting, "Auth server is already starting", nil))
		s.logger.App.Debug("CTRL: auth server is already starting")
		return
	}

	if currentState == StateStopping {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerStopping, "Auth server is currently stopping", nil))
		s.logger.App.Debug("CTRL: auth server is currently stopping")
		return
	}

	if err := s.stateManager.Start(s.ctx); err != nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrAuthServerError, "Failed to start auth server", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to start auth server", zap.Error(err))
		return
	}

	s.logger.App.Info("Auth server started successfully", zap.String("address", s.stateManager.authServer.GetAddress()))

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"message": "Auth server started successfully",
		"status":  s.stateManager.GetStatus(),
	}))
}

// handleAuthStop stops the auth server
func (s *Server) handleAuthStop(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling authorization server stop request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	currentState := s.stateManager.GetState()

	if currentState == StateStopped {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerNotRunning, "Auth server is already stopped", nil))
		s.logger.App.Debug("CTRL: auth server is already stopped")
		return
	}

	if currentState == StateStarting {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerStarting, "Auth server is starting, cannot stop yet", nil))
		s.logger.App.Debug("CTRL: auth server is starting, cannot stop yet")
		return
	}

	if currentState == StateStopping {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerStopping, "Auth server is already stopping", nil))
		s.logger.App.Debug("CTRL: auth server is already stopping")
		return
	}

	uptime := s.stateManager.GetStatus()["uptime"].(string)
	address := s.stateManager.authServer.GetAddress()
	if err := s.stateManager.Stop(); err != nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrAuthServerError, "Failed to stop auth server", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to stop auth server", zap.Error(err))
		return
	}

	s.logger.App.Info("Auth server stopped successfully", zap.String("address", address), zap.String("runtime", uptime))

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"message": "Auth server stopped successfully",
		"status":  s.stateManager.GetStatus(),
	}))
}

// handleAuthRestart restarts the auth server
func (s *Server) handleAuthRestart(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling authorization server restart request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	currentState := s.stateManager.GetState()

	if currentState == StateStarting || currentState == StateStopping {
		response.WriteJSON(w, response.StatusConflict,
			response.Fail(response.ErrAuthServerError, "Cannot restart during transitional state", map[string]any{
				"current_state": currentState.String(),
			}))
		s.logger.App.Debug("CTRL: cannot restart during transitional state")
		return
	}

	if err := s.stateManager.Restart(s.ctx); err != nil {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrAuthServerError, "Failed to restart auth server", map[string]any{
				"error": err.Error(),
			}))
		s.logger.App.Error("Failed to restart auth server", zap.Error(err))
		return
	}

	s.logger.App.Info("Auth server restarted successfully", zap.String("address", s.stateManager.authServer.GetAddress()))

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"message": "Auth server restarted successfully",
		"status":  s.stateManager.GetStatus(),
	}))
}

// handleServerQuit triggers a graceful shutdown of the entire application
func (s *Server) handleServerQuit(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling akashic shutdown request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("CTRL: received invalid method: %s", r.Method))
		return
	}

	s.logger.App.Info("Shutdown requested via control API")

	// Send response before triggering shutdown
	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"message": "Shutdown initiated",
	}))

	// Trigger shutdown after a brief delay to ensure response is sent
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.logger.App.Info("Triggering application shutdown")
		if s.shutdownFn != nil {
			s.shutdownFn()
		} else {
			s.logger.App.Fatal("No shutdown function provided, exiting immediately")
		}
	}()
}

// handleTLSReload re-reads the cert/key files for both the control and
// auth servers. Safe to retry on error -- the previous cert stays active
// when a reload fails (e.g. Vault Agent is mid-rotation).
//
// Only the leaf certs are reloaded. If the underlying CA bundle rotates
// (rare), restart the process instead.
func (s *Server) handleTLSReload(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("CTRL: Handling TLS reload request")
	if r.Method != http.MethodPost {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodPost},
				"received_method": r.Method,
			}))
		return
	}

	s.logger.App.Info("Reloading TLS certificates")

	results := map[string]any{}
	var failures []string

	if s.certReloader != nil {
		if err := s.ReloadCert(); err != nil {
			failures = append(failures, fmt.Sprintf("control: %v", err))
			results["control"] = map[string]any{"reloaded": false, "error": err.Error()}
		} else {
			results["control"] = map[string]any{"reloaded": true}
		}
	} else {
		results["control"] = map[string]any{"reloaded": false, "reason": "TLS not enabled"}
	}

	if authServer := s.stateManager.GetAuthServer(); authServer != nil {
		if err := authServer.ReloadCert(); err != nil {
			// Don't treat "TLS not enabled" as a hard failure; just report it.
			results["auth"] = map[string]any{"reloaded": false, "error": err.Error()}
		} else {
			results["auth"] = map[string]any{"reloaded": true}
		}
	}

	if len(failures) > 0 {
		response.WriteJSON(w, response.StatusInternalServerError,
			response.Fail(response.ErrTLSReloadFailed, "one or more reloads failed", results))
		s.logger.App.Error("TLS reload had failures", zap.Any("results", results))
		return
	}

	s.logger.App.Info("TLS certificates reloaded", zap.Any("results", results))
	response.WriteJSON(w, response.StatusOK, response.Success(results))
}
