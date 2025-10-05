package control

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/server/auth"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// Server represents the Control Server (management API)
type Server struct {
	ctx          context.Context
	server       *http.Server
	logger       *logging.Logger
	stateManager *StateManager
	config       *config.ConfigManager
	startedAt    time.Time
	shutdownFn   context.CancelFunc // Function to trigger app shutdown
}

const (
	CtrlServerReadTimeout             = 15 * time.Second
	CtrlServerWriteTimeout            = 15 * time.Second
	CtrlServerIdleTimeout             = 60 * time.Second
	CtrlServerGracefulShutdownTimeout = 10 * time.Second
)

// New creates a new Control Server instance
func New(ctx context.Context, authServer *auth.Server, config *config.ConfigManager, logger *logging.Logger, shutdownFn context.CancelFunc) *Server {
	return &Server{
		ctx:          ctx,
		logger:       logger,
		stateManager: NewStateManager(authServer, logger),
		config:       config,
		shutdownFn:   shutdownFn,
		startedAt:    time.Now(),
	}
}

// Start starts the control server
func (s *Server) Start() error {
	if s.server != nil {
		return fmt.Errorf("server already running")
	}

	addr := s.GetAddress()

	// Pre-bind listener to detect port conflicts immediately
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %v", addr, err)
	}

	mux := http.NewServeMux()

	// Register routes
	s.registerRoutes(mux)

	s.server = &http.Server{
		Handler:      mux,
		BaseContext:  func(_ net.Listener) context.Context { return s.ctx },
		ReadTimeout:  CtrlServerReadTimeout,
		WriteTimeout: CtrlServerWriteTimeout,
		IdleTimeout:  CtrlServerIdleTimeout,
	}

	s.logger.App.Info("Control server starting", zap.String("address", addr))

	// Start server in goroutine with pre-bound listener
	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.App.Error("Control server error", zap.Error(err))
		}
	}()

	s.logger.App.Info("Control server started successfully", zap.String("address", addr))
	return nil
}

// Stop stops the control server gracefully
func (s *Server) Stop() error {
	if s.server == nil {
		return fmt.Errorf("server not running")
	}

	s.logger.App.Info("Stopping control server")

	ctx, cancel := context.WithTimeout(context.Background(), CtrlServerGracefulShutdownTimeout)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.App.Error("Error during control server shutdown", zap.Error(err))
		return err
	}

	s.server = nil

	s.logger.App.Info("Control server stopped")
	return nil
}

// GetStateManager returns the state manager
func (s *Server) GetStateManager() *StateManager {
	return s.stateManager
}

// GetAddress returns the server address
func (s *Server) GetAddress() string {
	return fmt.Sprintf("%s:%d", s.config.GetConfig().Server.Control.Host, s.config.GetConfig().Server.Control.Port)
}

// GetUptime returns the server uptime
func (s *Server) GetUptime() time.Duration {
	return time.Since(s.startedAt)
}

// GetPID returns the process ID
func (s *Server) GetPID() int {
	return os.Getpid()
}
