// Package api implements the Akashic OAuth Resource Server — the
// third listener in the three-server architecture.
//
// The trust-axis split, in one table:
//
//   pkg/server/auth     OIDC IdP (8080)    public + session-cookie
//   pkg/server/api      Resource API (8082) bearer-token (Phase 8)
//   pkg/server/control  Admin plane (8081)  mTLS (admin-bff/CLI)
//
// This server hosts all bearer-token-authenticated end-user-facing
// resource APIs: /users/me, /users/me/password, /clients/*, plus the
// unauthenticated public endpoints that were previously on the
// control plane (/users/register, /users/forgot-password-help).
//
// The portal's API routes call this server with
// `Authorization: Bearer <access_token>` headers, where the access
// token comes from the user's OAuth login. Token verification uses
// the same in-process keystore the auth server uses to mint tokens
// — local crypto check, no cross-server call.
package api

import (
	authpkg "akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/database/akashic_postgres"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/middleware"
	"akashic/akashic/pkg/email"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/policy"
	"akashic/akashic/pkg/repository"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ServerState mirrors auth.ServerState — same lifecycle model so the
// control-plane state-machine code can manage both servers uniformly.
type ServerState int

const (
	_ ServerState = iota
	StateStopped
	StateRunning
)

const (
	APIServerReadTimeout             = 15 * time.Second
	APIServerWriteTimeout            = 15 * time.Second
	APIServerIdleTimeout             = 60 * time.Second
	APIServerGracefulShutdownTimeout = 10 * time.Second
)

// Server represents the Akashic API (resource) Server.
type Server struct {
	config       *config.ConfigManager
	server       *http.Server
	logger       *logging.Logger
	mu           sync.RWMutex
	state        ServerState
	certReloader *pki.Reloader

	// Phase 8 deps. Set via SetDeps after construction so the lifecycle
	// stays decoupled from when these get initialized — same pattern
	// as the auth server's SetOAuthDeps.
	keyStore   *oauth.KeyStore
	userRepo   *repository.UserRepository
	ldapClient *ldap.Client
	authSvc    *authpkg.Service
	db         *akashic_postgres.DB

	// Phase 8: bootstrap-mode gate. When the deployment hasn't yet
	// minted a root user, /users/register refuses signup so the
	// operator's setup runs first. Wired in via SetBootstrapManager;
	// nil is tolerated (handlers fail-open during init races).
	bootstrapMgr *bootstrap.Manager

	// Phase 8c.6: tenant-policy service. DB-backed live read for
	// password rules (used by signup, password-policy hint, password-
	// change) and the SignupEnabled gate. Same fail-open posture as
	// the bootstrap gate: nil → permissive defaults.
	policySvc *policy.Service

	// Phase 7.5: consent repository for the bearer-authenticated
	// /users/me/consents surface — list + revoke. Same repo handle
	// the auth-server uses for /authorize gating; co-locating the
	// reads/writes here keeps audit trails consistent.
	consentRepo *repository.OAuthConsentRepository

	// Phase B portal-side scope-request workflow. Read by client
	// write paths (gate special scopes against approval); read +
	// written by `/clients/<id>/scope-requests` for owner-side
	// submission and status display.
	scopeRequestRepo *repository.OAuthScopeRequestRepository

	// Phase 9 (revised): DB-backed email-config service. Replaces
	// the prior static mailer + verify-URL fields. Same shape as
	// the auth-server side — see pkg/server/auth/server.go for
	// the longer rationale.
	emailSvc *email.Service

	// Phase 9b: email-verification repo. Read+written by the
	// resend endpoint.
	emailVerificationRepo *repository.EmailVerificationRepository
}

// New constructs a Server. Lifecycle: New → SetDeps → Start.
func New(configManager *config.ConfigManager, logger *logging.Logger) *Server {
	return &Server{
		config: configManager,
		logger: logger,
		state:  StateStopped,
	}
}

// SetDeps wires the runtime dependencies. Done in one shot rather
// than per-field setters because none of the API endpoints work
// without all of these (authoritative crypto via keystore, identity
// store via userRepo + LDAP, postgres for client_services).
func (s *Server) SetDeps(
	keyStore *oauth.KeyStore,
	userRepo *repository.UserRepository,
	ldapClient *ldap.Client,
	authSvc *authpkg.Service,
	db *akashic_postgres.DB,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyStore = keyStore
	s.userRepo = userRepo
	s.ldapClient = ldapClient
	s.authSvc = authSvc
	s.db = db
}

// SetPolicyService wires the DB-backed tenant-policy accessor.
// Phase 8c.6. Same fail-open posture as SetBootstrapManager.
func (s *Server) SetPolicyService(p *policy.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policySvc = p
}

// SetConsentRepo wires the OAuth consent repository. Used by the
// Phase 7.5 /users/me/consents handlers (list + revoke).
func (s *Server) SetConsentRepo(r *repository.OAuthConsentRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consentRepo = r
}

// SetScopeRequestRepo wires the special-scope approval-workflow
// repository. Used by the api-server's `/clients/<id>/scope-requests`
// list + submit endpoints (owner-scoped) and by the client write
// paths' special-scope gate.
func (s *Server) SetScopeRequestRepo(r *repository.OAuthScopeRequestRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scopeRequestRepo = r
}

// SetEmailService wires the DB-backed email config service
// (Phase 9 revised). Implements `mailer.Mailer` and exposes
// `VerifyURLBase` for live reads.
func (s *Server) SetEmailService(svc *email.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailSvc = svc
}

// SetEmailVerificationRepo wires the email-verification repo
// (Phase 9b). Required for `/users/me/send-verification-email`.
func (s *Server) SetEmailVerificationRepo(r *repository.EmailVerificationRepository) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailVerificationRepo = r
}

// SetBootstrapManager wires the bootstrap-state checker so signup
// can short-circuit before bootstrap completes. Same fail-open
// semantics as the auth server: nil manager or error → don't
// block.
func (s *Server) SetBootstrapManager(m *bootstrap.Manager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bootstrapMgr = m
}

// bootstrapBlocked returns true iff the deployment is still in
// bootstrap mode. Mirrors the auth server's helper of the same name.
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

// Start begins serving on the configured address. Mirrors the auth
// server's Start — pre-bind listener for fast port-conflict detection,
// optional TLS via cert reloader, goroutine-blocked Serve.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.state == StateRunning {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}

	addr := s.GetAddress()
	tlsCfg := s.config.GetConfig().Server.API.TLS

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to bind to %s: %v", addr, err)
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)
	handler := s.buildMiddlewareChain(mux)

	s.server = &http.Server{
		Handler:      handler,
		BaseContext:  func(_ net.Listener) context.Context { return ctx },
		ReadTimeout:  APIServerReadTimeout,
		WriteTimeout: APIServerWriteTimeout,
		IdleTimeout:  APIServerIdleTimeout,
	}

	if tlsCfg.Enabled {
		reloader, rerr := pki.NewReloader("api-server", tlsCfg.CertFile, tlsCfg.KeyFile)
		if rerr != nil {
			ln.Close()
			s.mu.Unlock()
			return fmt.Errorf("api server TLS init: %v", rerr)
		}
		s.certReloader = reloader
		s.server.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: reloader.GetCertificate,
		}
	}

	s.state = StateRunning
	s.mu.Unlock()

	s.logger.App.Info("API server starting",
		zap.String("address", addr),
		zap.Bool("tls", tlsCfg.Enabled),
	)

	go func() {
		var serveErr error
		if tlsCfg.Enabled {
			serveErr = s.server.ServeTLS(ln, "", "")
		} else {
			serveErr = s.server.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			s.logger.App.Error("API server error", zap.Error(serveErr))
			s.mu.Lock()
			s.state = StateStopped
			s.mu.Unlock()
		}
	}()

	s.logger.App.Info("API server started successfully", zap.String("address", addr))
	return nil
}

// Stop gracefully shuts down the API server.
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateRunning || s.server == nil {
		return fmt.Errorf("server not running")
	}

	s.logger.App.Info("Stopping API server")
	ctx, cancel := context.WithTimeout(context.Background(), APIServerGracefulShutdownTimeout)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		s.logger.App.Error("Error during API server shutdown", zap.Error(err))
		return err
	}
	s.state = StateStopped
	s.server = nil
	s.logger.App.Info("API server stopped")
	return nil
}

// ReloadCert re-reads the API server's cert/key from disk. Same
// pattern as the auth server.
func (s *Server) ReloadCert() error {
	s.mu.RLock()
	r := s.certReloader
	s.mu.RUnlock()
	if r == nil {
		return fmt.Errorf("api server has no cert reloader (TLS not enabled)")
	}
	return r.Reload()
}

// CertReloader exposes the underlying reloader for the optional
// in-process cert-watcher. Returns nil before Start() or with TLS off.
func (s *Server) CertReloader() *pki.Reloader {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certReloader
}

func (s *Server) GetState() ServerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *Server) IsRunning() bool {
	return s.GetState() == StateRunning
}

func (s *Server) GetAddress() string {
	cfg := s.config.GetConfig().Server.API
	return fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
}

// buildMiddlewareChain wraps the routed handler with per-request
// middleware:
//   - Recovery (always)
//   - CORS for tenant origins (Phase 8b — widgets running on
//     `<tenant>` cross-origin to `api.<tenant>` need preflight
//     responses + Access-Control-Allow-Origin echoes).
//
// CORS allowlist comes from `AKASHIC_PORTAL_TENANT_ORIGINS`. Empty
// list = no origin echoed = browsers refuse to deliver responses to
// JS on cross-origin pages, which is the safe default. Bearer-token
// callers from server-to-server contexts (the BFF in the sample
// portal, third-party SSO Clients) don't need CORS — they don't run
// in browsers — so this is purely additive, never restrictive for
// existing flows.
func (s *Server) buildMiddlewareChain(handler http.Handler) http.Handler {
	// Apply CORS first (outermost) so preflights short-circuit before
	// hitting the bearer middleware.
	wrapped := s.tenantCORS()(handler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.App.Error("API server panic",
					zap.Any("panic", rec),
					zap.String("path", r.URL.Path),
				)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		wrapped.ServeHTTP(w, r)
	})
}

// tenantCORS builds CORS middleware seeded from
// `AKASHIC_PORTAL_TENANT_ORIGINS`. Permits cross-origin requests
// from the operator-allowlisted tenant product origins to ALL
// api-server routes (bearer-protected and public alike — preflights
// don't carry the bearer so we can't decide allowance per-route at
// the CORS layer).
func (s *Server) tenantCORS() middleware.Middleware {
	origins := splitTenantOrigins(s.config.GetConfig().Portal.TenantOrigins)
	return middleware.CORS(&middleware.CORSConfig{
		AllowedOrigins: origins,
		AllowedMethods: []string{
			"GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS",
		},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Akashic-CSRF"},
		AllowCredentials: true,
		MaxAge:           600,
	})
}
