package control

import (
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/email"
	"akashic/akashic/pkg/policy"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/api"
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
	"gorm.io/gorm"
)

// Server represents the Control Server (management API)
type Server struct {
	ctx              context.Context
	server           *http.Server
	logger           *logging.Logger
	stateManager     *StateManager
	apiStateManager  *APIStateManager // Phase 8: lifecycle of the API server
	bootstrapMgr     *bootstrap.Manager // Bootstrap manager (set after initialization)
	config           *config.ConfigManager
	startedAt        time.Time
	shutdownFn       context.CancelFunc // Function to trigger app shutdown
	certReloader     *pki.Reloader
	bootstrapLimiter *middleware.InMemoryRateLimiter // per-CN rate limit for /bootstrap/* (Phase 5.1.2)

	// db is the GORM handle to the akashic_postgres database, wired
	// in by SetDB() after initialization. Used by the operator-side
	// client management endpoints (Stage 2 of the clients-registration
	// roadmap) to upsert into the same `client_services` table the
	// API-server's bearer-authenticated handlers write to.
	//
	// Why a direct *gorm.DB rather than a manager type: the control
	// plane is mTLS-gated already; there's no per-user auth to thread
	// through, no audit-log fields to populate, no rate limit to apply
	// per requester. A thin handler that calls the DB directly is
	// clearer than a wrapped manager that adds no value.
	db *gorm.DB

	// ldapClient is the same LDAP client the auth path uses, wired in
	// by SetLDAP() after initialization. Used by the setup-status
	// handler (Phase 8c.1) to surface "is LDAP reachable" on the
	// admin banner. Optional: handlers nil-check before use.
	ldapClient *ldap.Client

	// userRepo is wired in by SetUserRepo() and used by the
	// Phase 8c.2 user-management handlers (list / get / patch /
	// delete). Optional: handlers nil-check before use so the
	// control server still starts in degraded mode without it.
	userRepo *repository.UserRepository

	// policySvc backs the Phase 8c.6 GET/PATCH /policy endpoints.
	// Same nil-tolerant pattern as the other Set* fields.
	policySvc *policy.Service

	// scopeRequestRepo backs the Phase B special-scope approval
	// workflow: clients_handlers reads it to gate special scopes
	// against approval, and scope_requests_handlers exposes the
	// list/submit/approve/reject endpoints. Same nil-tolerant
	// pattern.
	scopeRequestRepo *repository.OAuthScopeRequestRepository

	// emailService backs the Phase 9 GET/PATCH /email-config and
	// POST /email-config/test endpoints. Same nil-tolerant pattern.
	emailService *email.Service

	// refreshTokenRepo lets the Phase 9d admin temp-password reset
	// kill all live RT chains for the target user — without it, an
	// attacker who already exfiltrated an RT could keep refreshing
	// sessions even after the admin "reset" their password. Same
	// nil-tolerant pattern: if not wired, the handler still completes
	// the LDAP password change and gate flip, but logs a warning that
	// existing RTs were not revoked.
	refreshTokenRepo *repository.OAuthRefreshTokenRepository
}

// SetDB wires the GORM handle into the control server. Called from
// pkg/akashic/core/context after the database connection is up but
// before the server starts. Optional — handlers that need DB access
// nil-check before use so the control server still starts in
// degraded mode without it.
func (s *Server) SetDB(db *gorm.DB) {
	s.db = db
}

// SetLDAP wires the LDAP client into the control server so the
// setup-status handler (Phase 8c.1) can probe "is LDAP reachable."
// Mirrors SetDB's nil-tolerant pattern: handlers nil-check before
// use so the control server still starts even if LDAP wiring is
// deferred or omitted.
func (s *Server) SetLDAP(client *ldap.Client) {
	s.ldapClient = client
}

// SetUserRepo wires the user repository into the control server so
// the Phase 8c.2 user-management handlers can list / patch / delete
// users. Same nil-tolerant pattern as SetDB / SetLDAP.
func (s *Server) SetUserRepo(repo *repository.UserRepository) {
	s.userRepo = repo
}

// SetPolicyService wires the DB-backed tenant-policy accessor for
// the Phase 8c.6 GET/PATCH /policy endpoints.
func (s *Server) SetPolicyService(p *policy.Service) {
	s.policySvc = p
}

// SetScopeRequestRepo wires the special-scope approval-workflow
// repository (Phase B). When nil, special-scope endpoints return
// 503 and the client-write path's special-scope gate fails closed
// — special scopes can't be set without it.
func (s *Server) SetScopeRequestRepo(r *repository.OAuthScopeRequestRepository) {
	s.scopeRequestRepo = r
}

// SetEmailService wires the DB-backed email-config service for the
// Phase 9 /email-config endpoints.
func (s *Server) SetEmailService(svc *email.Service) {
	s.emailService = svc
}

// SetRefreshTokenRepo wires the OAuth refresh-token repository so
// the Phase 9d admin temp-password reset can revoke every live RT
// chain for the target user as part of the reset operation.
func (s *Server) SetRefreshTokenRepo(repo *repository.OAuthRefreshTokenRepository) {
	s.refreshTokenRepo = repo
}

// SetAPIServer wires the API server's state manager into the control
// plane so /api/start, /api/stop, /api/restart endpoints can manage
// its lifecycle. Called from pkg/akashic/core/context after both
// servers are constructed.
func (s *Server) SetAPIServer(apiServer *api.Server) {
	s.apiStateManager = NewAPIStateManager(apiServer, s.logger)
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

// GetAPIStateManager returns the API server's state manager. Nil if
// SetAPIServer hasn't been called yet (the manager is created lazily
// in SetAPIServer rather than in New() because the api.Server itself
// is constructed after the control server).
func (s *Server) GetAPIStateManager() *APIStateManager {
	return s.apiStateManager
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
