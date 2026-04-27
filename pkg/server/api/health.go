package api

import (
	"net/http"

	"akashic/akashic/pkg/server/response"
)

// handleHealth is the liveness probe. Returns 200 unconditionally —
// "this process is running and accepting requests." Used by docker
// for container-health and any future orchestrator's liveness check.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"service": "akashic-api",
		"status":  "healthy",
	}))
}

// handleReady is the readiness probe. Returns 200 only when the
// keystore is wired (so bearer-token verification will work) and
// the userRepo is wired (so handlers can do their job). Returns 503
// otherwise — orchestrators should not route traffic here yet.
//
// Distinct from /health because "alive but not yet ready" is a real
// state during akashic-server startup: the API server's listener is
// up before SetDeps fires.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	ready := s.keyStore != nil && s.userRepo != nil && s.ldapClient != nil && s.db != nil
	s.mu.RUnlock()
	if !ready {
		response.WriteJSON(w, http.StatusServiceUnavailable,
			response.Fail("NOT_READY", "API server dependencies not yet wired", nil))
		return
	}
	response.WriteJSON(w, http.StatusOK, response.Success(map[string]any{
		"service": "akashic-api",
		"status":  "ready",
	}))
}
