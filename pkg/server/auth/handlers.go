package auth

import (
	"akashic/akashic/pkg/server/response"
	"fmt"
	"net/http"
)

// handleHealth returns the health status of the auth server
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("AUTH: Handling health request")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("AUTH: received invalid method: %s", r.Method))
		return
	}

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"status": "healthy",
	}))
}

// handleReady returns the readiness status of the auth server
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	s.logger.App.Debug("AUTH: Handling ready request")
	if r.Method != http.MethodGet {
		response.WriteJSON(w, response.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, fmt.Sprintf("%s method not allowed", r.Method), map[string]any{
				"allowed_methods": []string{http.MethodGet},
				"received_method": r.Method,
			}))
		s.logger.App.Debug(fmt.Sprintf("AUTH: received invalid method: %s", r.Method))
		return
	}

	// TODO: For now, always ready if server is running; In the future, this will check database connections, etc.
	checks := map[string]string{
		"server": "ok",
	}

	response.WriteJSON(w, response.StatusOK, response.Success(map[string]any{
		"ready":  true,
		"checks": checks,
	}))
}
