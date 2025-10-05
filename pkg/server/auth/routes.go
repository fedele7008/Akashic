package auth

import (
	"net/http"
)

// registerRoutes sets up the auth server routes
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)
}
