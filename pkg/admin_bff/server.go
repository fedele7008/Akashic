package admin_bff

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
)

// Server owns the BFF's HTTP listener, the mTLS client to the control
// plane, and the request lifecycle. Construct via NewServer; run via
// Run (blocks until SIGTERM/SIGINT).
type Server struct {
	cfg              *Config
	srv              *http.Server
	controlClient    *ControlClient
	rateLimiter      *rateLimiter
	bootstrapLimiter *rateLimiter // narrower bucket for /api/bootstrap/create-root
	audit            *AuditWriter
	feAssets         fs.FS // embedded FE; nil = no FE served (API-only mode)

	// Phase 7 additions: OAuth client + Redis-backed sessions. nil
	// when the corresponding init wasn't reachable (e.g., Redis is
	// down). Handlers that depend on these check + return 503.
	oauth    *oauthClient
	sessions *sessionStore
	rdb      *redis.Client

	mu     sync.Mutex
	closed bool
}

// NewServer constructs a Server with config loaded from env, the mTLS
// control-plane client wired up, and (Step 4) all middleware ready.
//
// feAssets is the embedded FE filesystem, typically passed in by main.go
// from a //go:embed directive. Pass nil to run in API-only mode (the
// SPA fallback returns 404 instead of index.html).
//
// Returns an error if the BFF can't reach a usable initial state --
// e.g., the bff-client cert isn't on disk yet (Vault Agent hasn't
// rendered it). In production deployments compose's depends_on
// ordering should make that case rare; if it happens, the operator
// can simply wait and `docker compose restart admin-bff`.
func NewServer(feAssets fs.FS) (*Server, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	cc, err := NewControlClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("init control client: %w", err)
	}

	// Phase 7 wiring: OAuth client (talks to auth-server) + Redis +
	// session store. These run AFTER the control client because if
	// any of them is broken we want to surface that diagnostically
	// without losing the bootstrap ability -- the bootstrap surface
	// works without OAuth, useful for "log in" pre-conditions.
	//
	// Failure-mode policy: if Redis is unreachable, we abort startup.
	// Login is genuinely broken without it, and the operator should
	// notice now rather than after the first user clicks /login.
	rdb, err := newRedisClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("init redis: %w", err)
	}
	sess := newSessionStore(rdb, cfg.OAuthSessionIdle, cfg.OAuthSessionAbsolute)

	// OAuth client init. Failure here is non-fatal: the bootstrap
	// flow still works with the control client; we just won't be
	// able to log anyone in. This separation is deliberate -- e.g.,
	// during bootstrap-only deployments the operator may not have
	// rotated the akashic-admin secret yet, and forcing OAuth init
	// at that point would block bootstrap.
	oauthC, oauthErr := newOAuthClient(cfg)
	if oauthErr != nil {
		fmt.Fprintf(os.Stderr,
			"admin-bff: OAuth client init failed (login disabled): %v\n", oauthErr)
		oauthC = nil
	}

	// Two rate-limit buckets:
	//   - bootstrapLimiter: tight cap on /api/bootstrap/create-root,
	//     mirrors the control-plane per-CN limit (5/min)
	//   - rateLimiter: looser cap on idempotent reads (status, health)
	//     to keep abusive scanning out of the logs
	return &Server{
		cfg:              cfg,
		controlClient:    cc,
		bootstrapLimiter: newRateLimiter(cfg.BootstrapRateLimit, time.Minute, cfg.TrustedProxies),
		rateLimiter:      newRateLimiter(30, time.Minute, cfg.TrustedProxies),
		audit:            newAuditWriter(),
		feAssets:         feAssets,
		oauth:            oauthC,
		sessions:         sess,
		rdb:              rdb,
	}, nil
}

// Run starts the HTTP listener and blocks until SIGINT/SIGTERM. Returns
// nil on graceful shutdown, error if the listener fails or shutdown
// times out.
func (s *Server) Run() error {
	mux := s.buildMux()

	s.srv = &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // mitigate slowloris
		IdleTimeout:       60 * time.Second,
	}

	// Signal handler triggers graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	shutdownDone := make(chan error, 1)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "admin-bff: shutdown signal received")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- s.srv.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "admin-bff: listening on %s\n", s.cfg.ListenAddr)
	fmt.Fprintf(os.Stderr, "admin-bff: control plane = %s\n", s.cfg.ControlURL)
	if err := s.srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("listen: %w", err)
	}
	return <-shutdownDone
}

// buildMux assembles the HTTP routes with middleware layered as:
//
//   securityHeaders  ← outermost (response headers always set)
//     csrfMiddleware  ← validates state-changing requests
//       rateLimit      ← per-IP throttle, narrower for bootstrap
//         handler
//
// Health endpoint skips CSRF + rate limit because it's used by docker
// for liveness probing and shouldn't be subject to either.
//
// FE assets (when feAssets is non-nil) are served at "/" with SPA
// fallback: any non-API path that isn't a real file gets index.html.
func (s *Server) buildMux() http.Handler {
	mux := http.NewServeMux()

	// Liveness probe: minimal middleware, just headers.
	mux.HandleFunc("GET /api/health", s.handleHealth)

	// Bootstrap status: read-only, idempotent. CSRF middleware still
	// runs (sets the cookie if missing) but doesn't enforce match.
	// Rate-limited via the looser bucket.
	mux.HandleFunc("GET /api/bootstrap/status",
		s.csrfMiddleware(
			s.rateLimitMiddleware(s.rateLimiter, s.handleBootstrapStatus)))

	// Bootstrap create-root: state-changing. CSRF enforced; rate-
	// limited via the tight bucket (mirrors control-plane per-CN limit).
	mux.HandleFunc("POST /api/bootstrap/create-root",
		s.csrfMiddleware(
			s.rateLimitMiddleware(s.bootstrapLimiter, s.handleBootstrapCreateRoot)))

	// ─── Phase 7: OAuth flow ───────────────────────────────────────
	//
	// /login and /oauth/callback are GET endpoints reached via top-
	// level browser navigation (302 redirects), so they MUST NOT
	// require the X-Akashic-CSRF header (which only the FE's fetch
	// code knows how to set). The double-submit-cookie pattern still
	// runs underneath: csrfMiddleware sets the cookie on idempotent
	// methods and only enforces matching on POST/PUT/DELETE/PATCH.
	//
	// Rate limit: the looser bucket. Per-IP throttling on /login
	// matters less here than at the auth server's /login/submit;
	// the auth server is doing the heavy authentication work.
	mux.HandleFunc("GET /login",
		s.csrfMiddleware(
			s.rateLimitMiddleware(s.rateLimiter, s.handleLogin)))
	mux.HandleFunc("GET /oauth/callback",
		s.csrfMiddleware(
			s.rateLimitMiddleware(s.rateLimiter, s.handleOAuthCallback)))

	// /logout is POST: it changes server-side state (deletes the
	// Redis session), so CSRF enforcement applies — same protection
	// as bootstrap-create-root.
	mux.HandleFunc("POST /logout",
		s.csrfMiddleware(
			s.rateLimitMiddleware(s.rateLimiter, s.handleLogout)))

	// /api/session: GET, idempotent, reads the BFF session and
	// returns user info. The FE polls this on first load to decide
	// which shell view to render.
	mux.HandleFunc("GET /api/session",
		s.csrfMiddleware(
			s.rateLimitMiddleware(s.rateLimiter, s.handleSessionInfo)))

	// FE assets at "/", with SPA-fallback so client-side routes load
	// index.html. The CSRF middleware also wraps this so the cookie
	// gets set on initial page load (the FE then reads it for forms).
	if s.feAssets != nil {
		mux.Handle("/", s.csrfMiddleware(s.feHandler().ServeHTTP))
	}

	// Security headers wrap everything — set on every response.
	return s.securityHeadersMiddleware(mux)
}

// feHandler returns an http.Handler that serves the embedded FE.
// Path-not-found falls back to index.html (SPA-routing support).
func (s *Server) feHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.feAssets))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		// Try to open as a real file. If found, FileServer serves
		// with proper content-type / etag / range handling.
		if f, err := s.feAssets.Open(p); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		// SPA fallback: any non-existent path under "/" gets the React
		// shell, which then handles the route client-side.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}

// handleHealth is a liveness probe that doesn't reach the control plane.
// Used by docker / nginx for upstream health checks.
//
// Returning a small JSON envelope (rather than an empty 200) means an
// operator who curls this from a misconfigured proxy can immediately
// see whether they're reaching the BFF or some other service.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service": "admin-bff",
		"status":  "healthy",
	})
}
