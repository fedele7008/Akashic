package auth

import (
	authpkg "akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/database/akashic_redis"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/pki"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Server represents the Auth Server (OAuth/OIDC endpoints)
type Server struct {
	config       *config.ConfigManager
	server       *http.Server
	logger       *logging.Logger
	mu           sync.RWMutex
	state        ServerState
	certReloader *pki.Reloader

	// Phase 7 OAuth/OIDC dependencies. Wired in by SetOAuth*; nil
	// until akashic-server's Init wires them up. Handlers that need
	// these tolerate nil by returning 503 -- helps during partial
	// deploy / restart races.
	oauthKeyStore *oauth.KeyStore
	codeStore     *oauth.CodeStore
	sessionStore  *oauth.SessionStore
	authService   *authpkg.Service
	db            *gorm.DB
	redis         *akashic_redis.Client // for the rate-limit middleware

	// Phase 8: bootstrap-mode gate. When the deployment hasn't yet
	// minted a root user (NeedsBootstrap == true), /login and the
	// authorize endpoint refuse to serve end users — only the
	// operator's bootstrap path on the control plane works. Wired
	// in via SetBootstrapManager.
	bootstrapMgr *bootstrap.Manager
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

// New creates a new Auth Server instance.
//
// Templates are parsed at construction. Panics on template parse
// failure because a missing/broken template indicates a corrupt
// binary, not a runtime issue worth handling gracefully.
func New(configManager *config.ConfigManager, logger *logging.Logger) *Server {
	if err := initTemplates(); err != nil {
		panic("auth-server: " + err.Error())
	}
	return &Server{
		config: configManager,
		logger: logger,
		state:  StateStopped,
	}
}

// SetOAuthKeyStore wires the JWT signing-key store into the server.
// Called from akashic's Init() once the keystore is loaded. Goroutine-
// safe but typically only invoked once at startup.
func (s *Server) SetOAuthKeyStore(ks *oauth.KeyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oauthKeyStore = ks
}

// SetBootstrapManager wires the bootstrap manager so /login can
// short-circuit to a "system not yet ready" page when the operator
// hasn't completed bootstrap. Phase 8: nil is tolerated (handlers
// fail-open in that case so an init-race doesn't lock everyone out).
func (s *Server) SetBootstrapManager(m *bootstrap.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootstrapMgr = m
}

// bootstrapBlocked returns true iff the deployment is still in
// bootstrap mode (no root user yet). When the manager isn't wired
// or a check errors, returns false — fail-open here is the right
// trade-off because the alternative is a hard lockout during a
// transient DB hiccup.
func (s *Server) bootstrapBlocked(ctx context.Context) bool {
	s.mu.RLock()
	mgr := s.bootstrapMgr
	s.mu.RUnlock()
	if mgr == nil {
		return false
	}
	needs, err := mgr.NeedsBootstrap(ctx)
	if err != nil {
		s.logger.App.Warn("bootstrap-state check failed; allowing through",
			zap.Error(err))
		return false
	}
	return needs
}

// OAuthKeyStore returns the wired keystore (may be nil during init
// races). Handlers should treat nil as "OAuth not yet ready" → 503.
func (s *Server) OAuthKeyStore() *oauth.KeyStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oauthKeyStore
}

// SetOAuthDeps wires the rest of the OAuth dependency graph: code
// store, session store, auth service, DB. Done in one call rather
// than per-field setters because these are all-or-nothing — without
// any one of them, none of /authorize, /token, /login work.
func (s *Server) SetOAuthDeps(
	codes *oauth.CodeStore,
	sessions *oauth.SessionStore,
	authSvc *authpkg.Service,
	db *gorm.DB,
	redis *akashic_redis.Client,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codeStore = codes
	s.sessionStore = sessions
	s.authService = authSvc
	s.db = db
	s.redis = redis
}

// Start starts the auth server
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.state == StateRunning {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := s.GetAddress()
	tlsCfg := s.config.GetConfig().Server.Auth.TLS

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

	// If TLS is enabled, install a cert reloader. The GetCertificate callback
	// is re-read on every handshake, so rotation swaps in the new cert with
	// zero listener restarts.
	if tlsCfg.Enabled {
		reloader, rerr := pki.NewReloader("auth-server", tlsCfg.CertFile, tlsCfg.KeyFile)
		if rerr != nil {
			ln.Close()
			s.mu.Unlock()
			return fmt.Errorf("auth server TLS init: %v", rerr)
		}
		s.certReloader = reloader
		s.server.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: reloader.GetCertificate,
		}
	}

	s.state = StateRunning
	s.mu.Unlock()

	s.logger.App.Info("Auth server starting",
		zap.String("address", addr),
		zap.Bool("tls", tlsCfg.Enabled),
	)

	go func() {
		var serveErr error
		if tlsCfg.Enabled {
			// cert/key args are empty because we source them from TLSConfig.GetCertificate
			serveErr = s.server.ServeTLS(ln, "", "")
		} else {
			serveErr = s.server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			s.logger.App.Error("Auth server error", zap.Error(serveErr))
			s.mu.Lock()
			s.state = StateStopped
			s.mu.Unlock()
		}
	}()

	s.logger.App.Info("Auth server started successfully", zap.String("address", addr))
	return nil
}

// ReloadCert re-reads the auth server's cert/key from disk. Safe to call
// while the server is handling traffic; returns an error if the new files
// don't parse (e.g. rotation in progress) so the caller can retry.
func (s *Server) ReloadCert() error {
	s.mu.RLock()
	r := s.certReloader
	s.mu.RUnlock()
	if r == nil {
		return fmt.Errorf("auth server has no cert reloader (TLS not enabled)")
	}
	return r.Reload()
}

// CertReloader exposes the underlying reloader so the optional in-process
// cert-watcher (see pkg/pki/cert_watcher.go) can subscribe to it. Returns
// nil before Start() completes, or when TLS is disabled.
func (s *Server) CertReloader() *pki.Reloader {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certReloader
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
