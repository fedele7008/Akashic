package auth

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/pki"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Server represents the Auth Server (OAuth/OIDC endpoints)
type Server struct {
	config       *config.ConfigManager
	server       *http.Server
	logger       *logging.Logger
	certReloader *pki.CertReloader
	mu           sync.RWMutex
	state        ServerState
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

	// Build middleware chain
	handler := s.buildMiddlewareChain(mux)

	s.server = &http.Server{
		Handler:      handler,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
		ReadTimeout:  AuthServerReadTimeout,
		WriteTimeout: AuthServerWriteTimeout,
		IdleTimeout:  AuthServerIdleTimeout,
	}

	s.state = StateRunning
	s.mu.Unlock()

	// Configure TLS if enabled
	tlsCfg := s.config.GetConfig().Server.Auth.TLS
	var listener net.Listener
	if tlsCfg.Enabled {
		tlsConfig, reloader, err := pki.NewServerTLSConfig(pki.ServerTLSOptions{
			CertFile:           tlsCfg.CertFile,
			KeyFile:            tlsCfg.KeyFile,
			CAFile:             tlsCfg.CAFile,
			ClientAuthRequired: tlsCfg.ClientAuthRequired,
		}, s.logger.App)
		if err != nil {
			s.mu.Lock()
			s.state = StateStopped
			s.mu.Unlock()
			return fmt.Errorf("failed to configure TLS: %v", err)
		}
		s.certReloader = reloader
		reloader.Start(ctx)
		listener = tls.NewListener(ln, tlsConfig)
		s.logger.App.Info("Auth server TLS enabled", zap.String("address", addr))
	} else {
		listener = ln
	}

	s.logger.App.Info("Auth server starting", zap.String("address", addr))

	// Start server in goroutine with pre-bound listener
	go func() {
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
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

// buildMiddlewareChain builds the middleware chain for the auth server
func (s *Server) buildMiddlewareChain(handler http.Handler) http.Handler {
	cfg := s.config.GetConfig()
	mwCfg := cfg.Middleware.Auth

	// Build security headers config
	securityHeadersConfig := &middleware.SecurityHeadersConfig{
		XFrameOptions:         middleware.XFrameOptions(mwCfg.SecurityHeaders.XFrameOptions),
		XSSProtection:         middleware.XSSProtectionPolicy(mwCfg.SecurityHeaders.XSSProtection),
		HSTSMaxAge:            mwCfg.SecurityHeaders.HSTSMaxAge,
		HSTSIncludeSubDomains: mwCfg.SecurityHeaders.HSTSIncludeSubDomains,
		HSTSPreload:           mwCfg.SecurityHeaders.HSTSPreload,
		ContentSecurityPolicy: mwCfg.SecurityHeaders.ContentSecurityPolicy,
		RemoveServerHeader:    mwCfg.SecurityHeaders.RemoveServerHeader,
		CustomHeaders:         make(map[string]string),
	}

	// Build logging config
	loggingConfig := &middleware.LoggingConfig{
		SkipPaths: make(map[string]bool),
	}
	for _, path := range mwCfg.Logging.SkipPaths {
		loggingConfig.SkipPaths[path] = true
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
	chain := middleware.AuthServerChain(
		s.logger,
		securityHeadersConfig,
		loggingConfig,
		corsConfig,
		rateLimitConfig,
		sizeLimitConfig,
		timeoutConfig,
	)

	return chain.Apply(handler)
}
