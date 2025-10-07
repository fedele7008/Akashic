package control

import (
	"net/http"
)

// registerRoutes sets up the control server routes
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health and status
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)

	// Configuration
	mux.HandleFunc("/config", s.handleConfig)
	mux.HandleFunc("/config/reload", s.handleConfigReload)

	// Auth server control
	mux.HandleFunc("/auth/start", s.handleAuthStart)
	mux.HandleFunc("/auth/stop", s.handleAuthStop)
	mux.HandleFunc("/auth/restart", s.handleAuthRestart)

	// Server control
	mux.HandleFunc("/server/quit", s.handleServerQuit)

	// Bootstrap routes (only active when bootstrap needed)
	mux.HandleFunc("/bootstrap/status", s.handleBootstrapStatus)
	mux.HandleFunc("/bootstrap/token", requireCLI(s.requireBootstrapMode(s.handleGetBootstrapToken)))
	mux.HandleFunc("/bootstrap/token/regenerate", requireCLI(s.requireBootstrapMode(s.handleRegenerateToken)))
	mux.HandleFunc("/bootstrap/root", s.requireBootstrapMode(s.handleCreateRootUser))
}
