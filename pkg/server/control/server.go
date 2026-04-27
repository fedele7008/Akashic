package control

import (
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/database/akashic_postgres"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/auth"
	"context"
	"crypto/tls"
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
	ctx              context.Context
	server           *http.Server
	logger           *logging.Logger
	stateManager     *StateManager
	bootstrapMgr     *bootstrap.Manager // Bootstrap manager (set after initialization)
	config           *config.ConfigManager
	startedAt        time.Time
	shutdownFn       context.CancelFunc // Function to trigger app shutdown
	certReloader     *pki.Reloader
	bootstrapLimiter *middleware.InMemoryRateLimiter // per-CN rate limit for /bootstrap/* (Phase 5.1.2)

	// Phase 8: dependencies for the new user / client management
	// endpoints. Set via SetUserDeps after construction so the
	// control server's New() signature stays backward-compatible
	// with the existing bootstrap-only path. Same pattern auth.Server
	// uses for OAuth deps in Phase 7.
	userRepo   *repository.UserRepository
	ldapClient *ldap.Client
	db         *akashic_postgres.DB
}

// SetUserDeps wires the user-repository, LDAP client, and database
// handle into the control server. Called from pkg/akashic/core/context
// after those deps are initialized but before Start(). When unset
// (any caller using only bootstrap endpoints), the Phase 8 user /
// client routes return a clear 503 instead of NPE'ing.
func (s *Server) SetUserDeps(userRepo *repository.UserRepository, ldapClient *ldap.Client, db *akashic_postgres.DB) {
	s.userRepo = userRepo
	s.ldapClient = ldapClient
	s.db = db
}

const (
	CtrlServerReadTimeout             = 15 * time.Second
	CtrlServerWriteTimeout            = 15 * time.Second
	CtrlServerIdleTimeout             = 60 * time.Second
	CtrlServerGracefulShutdownTimeout = 10 * time.Second
)

// New creates a new Control Server instance
func New(ctx context.Context, authServer *auth.Server, bootstrapMgr *bootstrap.Manager, config *config.ConfigManager, logger *logging.Logger, shutdownFn context.CancelFunc) *Server {
	return &Server{
		ctx:              ctx,
		logger:           logger,
		stateManager:     NewStateManager(authServer, logger),
		bootstrapMgr:     bootstrapMgr,
		config:           config,
		shutdownFn:       shutdownFn,
		bootstrapLimiter: newBootstrapRateLimiter(),
		startedAt:    time.Now(),
	}
}

// Start starts the control server
func (s *Server) Start() error {
	if s.server != nil {
		return fmt.Errorf("server already running")
	}

	addr := s.GetAddress()
	cfg := s.config.GetConfig()
	tlsCfg := cfg.Server.Control.TLS

	// Pre-bind listener to detect port conflicts immediately
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %v", addr, err)
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.buildMiddlewareChain(mux)

	s.server = &http.Server{
		Handler:      handler,
		BaseContext:  func(_ net.Listener) context.Context { return s.ctx },
		ReadTimeout:  CtrlServerReadTimeout,
		WriteTimeout: CtrlServerWriteTimeout,
		IdleTimeout:  CtrlServerIdleTimeout,
	}

	// Install TLS + mTLS when enabled. The control plane is the server side
	// of a private mTLS relationship signed by pki-mtls-akashic-ctrl, so we
	// demand client certs issued by that CA.
	if tlsCfg.Enabled {
		reloader, rerr := pki.NewReloader("control-server", tlsCfg.CertFile, tlsCfg.KeyFile)
		if rerr != nil {
			ln.Close()
			return fmt.Errorf("control server TLS init: %v", rerr)
		}
		s.certReloader = reloader

		tlsc := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: reloader.GetCertificate,
		}
		if tlsCfg.ClientAuthRequired {
			tlsc.ClientAuth = tls.RequireAndVerifyClientCert
			if tlsCfg.CAFile != "" {
				pool, cerr := pki.LoadCAPool(tlsCfg.CAFile)
				if cerr != nil {
					ln.Close()
					return fmt.Errorf("control server mTLS CA load: %v", cerr)
				}
				tlsc.ClientCAs = pool
			}
		}
		s.server.TLSConfig = tlsc
	}

	s.logger.App.Info("Control server starting",
		zap.String("address", addr),
		zap.Bool("tls", tlsCfg.Enabled),
		zap.Bool("mtls", tlsCfg.Enabled && tlsCfg.ClientAuthRequired),
	)

	go func() {
		var serveErr error
		if tlsCfg.Enabled {
			serveErr = s.server.ServeTLS(ln, "", "")
		} else {
			serveErr = s.server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			s.logger.App.Error("Control server error", zap.Error(serveErr))
		}
	}()

	s.logger.App.Info("Control server started successfully", zap.String("address", addr))
	return nil
}

// ReloadCert re-reads the control server's cert/key from disk. When mTLS is
// enabled, ClientCAs is intentionally NOT reloaded here because the trust
// root itself shouldn't be changing on a leaf-cert rotation -- if the CA
// bundle rotates, restart the process or extend this to re-read CAFile.
func (s *Server) ReloadCert() error {
	if s.certReloader == nil {
		return fmt.Errorf("control server has no cert reloader (TLS not enabled)")
	}
	return s.certReloader.Reload()
}

// CertReloader exposes the underlying reloader so the optional in-process
// cert-watcher (see pkg/pki/cert_watcher.go) can subscribe to it. Returns
// nil when TLS is disabled.
func (s *Server) CertReloader() *pki.Reloader {
	return s.certReloader
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

	// Build IP allowlist config
	var ipAllowlistConfig *middleware.IPAllowlistConfig
	if mwCfg.IPAllowlist.Enabled {
		ipAllowlistConfig = &middleware.IPAllowlistConfig{
			AllowedIPs:    mwCfg.IPAllowlist.AllowedIPs,
			AllowLoopback: mwCfg.IPAllowlist.AllowLoopback,
			TrustProxy:    mwCfg.IPAllowlist.TrustProxy,
		}
	}

	// Build mTLS middleware config. Actual cert verification is enforced by
	// the TLS listener above (ClientAuth = RequireAndVerifyClientCert);
	// this middleware layer is for DN extraction and audit logging.
	var mtlsConfig *middleware.MTLSConfig
	if cfg.Server.Control.TLS.Enabled && cfg.Server.Control.TLS.ClientAuthRequired {
		var caPool *x509.CertPool
		if cfg.Server.Control.TLS.CAFile != "" {
			if pool, cerr := pki.LoadCAPool(cfg.Server.Control.TLS.CAFile); cerr == nil {
				caPool = pool
			} else {
				s.logger.App.Warn("control mTLS middleware: CA pool load failed, DN extraction only",
					zap.Error(cerr))
			}
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
		securityHeadersConfig,
		loggingConfig,
		ipAllowlistConfig,
		mtlsConfig,
		corsConfig,
		rateLimitConfig,
		sizeLimitConfig,
		timeoutConfig,
	)

	return chain.Apply(handler)
}
