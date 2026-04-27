package control

import (
	"net/http"

	"akashic/akashic/pkg/server/response"

	"go.uber.org/zap"
)

// API server lifecycle handlers — mirror the auth-server lifecycle
// handlers (handleAuthStart, handleAuthStop, handleAuthRestart) but
// targeted at the Phase 8 API server (port 8082).
//
// Each handler:
//   1. Verifies the request method (POST only)
//   2. Verifies the API state manager is wired (SetAPIServer called)
//   3. Delegates to APIStateManager.Start/Stop/Restart
//   4. Reports the new status

func (s *Server) handleAPIStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "only POST is allowed", nil))
		return
	}
	if s.apiStateManager == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_WIRED", "API server is not wired into the control plane", nil))
		return
	}
	if err := s.apiStateManager.Start(s.ctx); err != nil {
		s.logger.App.Error("Failed to start API server", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("API_START_FAILED", err.Error(), nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"message": "API server started",
		"status":  s.apiStateManager.GetStatus(),
	}))
}

func (s *Server) handleAPIStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "only POST is allowed", nil))
		return
	}
	if s.apiStateManager == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_WIRED", "API server is not wired into the control plane", nil))
		return
	}
	if err := s.apiStateManager.Stop(); err != nil {
		s.logger.App.Error("Failed to stop API server", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("API_STOP_FAILED", err.Error(), nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"message": "API server stopped",
		"status":  s.apiStateManager.GetStatus(),
	}))
}

func (s *Server) handleAPIRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "only POST is allowed", nil))
		return
	}
	if s.apiStateManager == nil {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("API_NOT_WIRED", "API server is not wired into the control plane", nil))
		return
	}
	if err := s.apiStateManager.Restart(s.ctx); err != nil {
		s.logger.App.Error("Failed to restart API server", zap.Error(err))
		response.WriteJSON(w, http.StatusInternalServerError,
			response.Fail("API_RESTART_FAILED", err.Error(), nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"message": "API server restarted",
		"status":  s.apiStateManager.GetStatus(),
	}))
}
