package auth

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Server represents the Auth Server (OAuth/OIDC endpoints)
type Server struct {
	config *config.ConfigManager
	server *http.Server
	logger *logging.Logger
	mu     sync.RWMutex
	state  ServerState
}

// ServerState represents the current state of the server
type ServerState int

const (
	_ ServerState = iota
	StateStopped
	StateRunning
)

const (
	AuthServerReadTimeout             = 15 * time.Second
	AuthServerWriteTimeout            = 15 * time.Second
	AuthServerIdleTimeout             = 60 * time.Second
	AuthServerGracefulShutdownTimeout = 10 * time.Second
)

// New creates a new Auth Server instance
func New(configManager *config.ConfigManager, logger *logging.Logger) *Server {
	return &Server{
		config: configManager,
		logger: logger,
		state:  StateStopped,
	}
}

// Start starts the auth server
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.state == StateRunning {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := s.GetAddress()

	// Pre-bind listener to detect port conflicts immediately
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to bind to %s: %v", addr, err)
	}

	mux := http.NewServeMux()

	// Register routes
	s.registerRoutes(mux)

	s.server = &http.Server{
		Handler:      mux,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
		ReadTimeout:  AuthServerReadTimeout,
		WriteTimeout: AuthServerWriteTimeout,
		IdleTimeout:  AuthServerIdleTimeout,
	}

	s.state = StateRunning
	s.mu.Unlock()

	s.logger.App.Info("Auth server starting", zap.String("address", addr))

	// Start server in goroutine with pre-bound listener
	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.App.Error("Auth server error", zap.Error(err))
			s.mu.Lock()
			s.state = StateStopped
			s.mu.Unlock()
		}
	}()

	s.logger.App.Info("Auth server started successfully", zap.String("address", addr))
	return nil
}

// Stop stops the auth server gracefully
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateRunning || s.server == nil {
		return fmt.Errorf("server not running")
	}

	s.logger.App.Info("Stopping auth server")

	ctx, cancel := context.WithTimeout(context.Background(), AuthServerGracefulShutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.App.Error("Error during auth server shutdown", zap.Error(err))
		return err
	}

	s.state = StateStopped
	s.server = nil

	s.logger.App.Info("Auth server stopped")
	return nil
}

// GetState returns the current state of the server
func (s *Server) GetState() ServerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// IsRunning returns true if the server is running
func (s *Server) IsRunning() bool {
	return s.GetState() == StateRunning
}

// GetAddress returns the server address
func (s *Server) GetAddress() string {
	return fmt.Sprintf("%s:%d", s.config.GetConfig().Server.Auth.Host, s.config.GetConfig().Server.Auth.Port)
}
