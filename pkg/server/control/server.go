package control

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/server/auth"
	"context"
	"crypto/x509"
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

	// Build middleware chain
	handler := s.buildMiddlewareChain(mux)

	s.server = &http.Server{
		Handler:      handler,
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

// buildMiddlewareChain builds the middleware chain for the control server
func (s *Server) buildMiddlewareChain(handler http.Handler) http.Handler {
	cfg := s.config.GetConfig()
	mwCfg := cfg.Middleware.Control

	// Build IP allowlist config
	var ipAllowlistConfig *middleware.IPAllowlistConfig
	if mwCfg.IPAllowlist.Enabled {
		ipAllowlistConfig = &middleware.IPAllowlistConfig{
			AllowedIPs:    mwCfg.IPAllowlist.AllowedIPs,
			AllowLoopback: mwCfg.IPAllowlist.AllowLoopback,
			TrustProxy:    mwCfg.IPAllowlist.TrustProxy,
		}
	}

	// Build mTLS config
	var mtlsConfig *middleware.MTLSConfig
	if cfg.Server.Control.TLS.Enabled && cfg.Server.Control.TLS.ClientAuthRequired {
		// Load CA certificate pool if CA file is specified
		var caPool *x509.CertPool
		if cfg.Server.Control.TLS.CAFile != "" {
			// Note: In production, load the CA file here
			// For now, we'll use nil which means no verification
			// This will be implemented when TLS is fully set up
			caPool = nil
		}

		mtlsConfig = &middleware.MTLSConfig{
			RequireClientCert:        true,
			TrustedCAs:               caPool,
			AllowLoopbackWithoutCert: true,
			ExtractDN:                true,
		}
	}

	// Build CORS config
	var corsConfig *middleware.CORSConfig
	if mwCfg.CORS.Enabled {
		corsConfig = &middleware.CORSConfig{
			AllowedOrigins:   mwCfg.CORS.AllowedOrigins,
			AllowedMethods:   mwCfg.CORS.AllowedMethods,
			AllowedHeaders:   mwCfg.CORS.AllowedHeaders,
			ExposedHeaders:   mwCfg.CORS.ExposedHeaders,
			AllowCredentials: mwCfg.CORS.AllowCredentials,
			MaxAge:           mwCfg.CORS.MaxAge,
		}
	}

	// Build rate limit config
	var rateLimitConfig *middleware.RateLimitConfig
	if mwCfg.RateLimit.Enabled {
		rateLimitConfig = &middleware.RateLimitConfig{
			RequestsPerWindow: mwCfg.RateLimit.RequestsPerWindow,
			Window:            mwCfg.RateLimit.WindowDuration,
			KeyFunc:           nil, // Use default (IP-based)
			SkipFunc:          nil,
		}
	}

	// Build size limit config
	sizeLimitConfig := &middleware.SizeLimitConfig{
		MaxBytes: mwCfg.MaxRequestSizeBytes,
		SkipFunc: nil,
	}

	// Build timeout config
	timeoutConfig := &middleware.TimeoutConfig{
		Timeout:  mwCfg.RequestTimeout,
		Message:  "Request Timeout",
		SkipFunc: nil,
	}

	// Build the middleware chain
	chain := middleware.ControlServerChain(
		s.logger,
		ipAllowlistConfig,
		mtlsConfig,
		corsConfig,
		rateLimitConfig,
		sizeLimitConfig,
		timeoutConfig,
	)

	return chain.Apply(handler)
}
