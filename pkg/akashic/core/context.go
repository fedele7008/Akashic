package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	authpkg "akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/database/akashic_postgres"
	"akashic/akashic/pkg/database/akashic_redis"
	"akashic/akashic/pkg/ldap"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/models"
	"akashic/akashic/pkg/oauth"
	"akashic/akashic/pkg/policy"
	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/api"
	"akashic/akashic/pkg/server/auth"
	"akashic/akashic/pkg/server/control"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

// zapWatcherLogger adapts *zap.SugaredLogger to pki.WatcherLogger.
type zapWatcherLogger struct{ *zap.SugaredLogger }

func (z zapWatcherLogger) Infof(tpl string, args ...any)  { z.SugaredLogger.Infof(tpl, args...) }
func (z zapWatcherLogger) Warnf(tpl string, args ...any)  { z.SugaredLogger.Warnf(tpl, args...) }
func (z zapWatcherLogger) Errorf(tpl string, args ...any) { z.SugaredLogger.Errorf(tpl, args...) }

type AkashicApp struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	Config                *config.ConfigManager
	Logger                *logging.Logger
	DB                    *akashic_postgres.DB
	Redis                 *akashic_redis.Client
	LDAPClient            *ldap.Client
	DeprovisioningService *ldap.DeprovisioningService
	BootstrapMgr          *bootstrap.Manager
	AuthServer            *auth.Server
	APIServer             *api.Server // Phase 8: bearer-token resource server
	ControlServer         *control.Server
	OAuthKeyStore         *oauth.KeyStore // Phase 7: JWT signing keys
	PolicyService         *policy.Service // Phase 8c.6: DB-backed tenant policy
	closerFns             []func()
	verbose               bool
	bootstrapToken        string // Stored for console display
}

func NewAkashicApp() *AkashicApp {
	ctx, cancel := context.WithCancel(context.Background())
	return &AkashicApp{
		ctx:                   ctx,
		cancel:                cancel,
		Config:                nil,
		Logger:                nil,
		DB:                    nil,
		Redis:                 nil,
		LDAPClient:            nil,
		DeprovisioningService: nil,
		BootstrapMgr:          nil,
		AuthServer:            nil,
		ControlServer:         nil,
		closerFns:             make([]func(), 0),
		verbose:               false,
		bootstrapToken:        "",
	}
}

func (app *AkashicApp) Init(cmd *cobra.Command, args []string) error {
	var err error

	// Initialize configuration
	app.Config, err = config.NewConfigManager(cmd, app)
	if err != nil {
		return fmt.Errorf("failed to initialize configuration: %v", err)
	}

	cfg := app.Config.GetConfig()

	// Initialize logger
	var loggerClose func()
	app.Logger, loggerClose, err = logging.New(&cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}
	app.Logger.App.Info("logger created")
	app.AddCloser(loggerClose)

	// feed reconfigure function to config manager (for config reloading)
	app.Config.SetLoggerReconfigureFunction(app.Logger.Reconfigure)

	// Initialize PostgreSQL with GORM
	app.Logger.App.Info("Initializing database connections")
	app.DB, err = akashic_postgres.New(app.Config, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	app.AddCloser(func() {
		if err := app.DB.Close(); err != nil {
			app.Logger.App.Error("Error closing PostgreSQL connection", zap.Error(err))
		}
	})

	// Initialize Redis
	app.Redis, err = akashic_redis.New(app.Config, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}
	app.AddCloser(func() {
		if err := app.Redis.Close(); err != nil {
			app.Logger.App.Error("Error closing Redis connection", zap.Error(err))
		}
	})

	// Initialize LDAP client
	app.Logger.App.Info("Initializing LDAP client")
	app.LDAPClient = ldap.New(&cfg.LDAP, app.Logger)

	if err := app.LDAPClient.Connect(); err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %v", err)
	}
	app.AddCloser(func() {
		if err := app.LDAPClient.Close(); err != nil {
			app.Logger.App.Error("Error closing LDAP connection", zap.Error(err))
		}
	})

	// Test LDAP connection
	app.Logger.App.Info("Testing LDAP connection")
	if err := app.LDAPClient.TestConnection(); err != nil {
		return fmt.Errorf("LDAP connection test failed - Akashic cannot start without LDAP: %v", err)
	}
	app.Logger.App.Info("LDAP connection verified successfully")

	// Initialize LDAP directory structure (similar to GORM AutoMigrate)
	app.Logger.App.Info("Initializing LDAP directory structure")
	if err := app.LDAPClient.InitializeStructure(); err != nil {
		return fmt.Errorf("failed to initialize LDAP structure: %v", err)
	}

	// Initialize RBAC service
	app.Logger.App.Info("Initializing RBAC service")
	rbacService := ldap.NewRBACService(app.LDAPClient, app.Logger.App)

	// Run automatic database migrations with GORM
	if err := app.DB.AutoMigrate(); err != nil {
		return fmt.Errorf("failed to run auto-migration: %v", err)
	}

	// Phase 8c.6: tenant-policy service. Singleton row gets seeded
	// from YAML defaults on first run; subsequent edits go through
	// the admin web. After this point, callers (signup, register,
	// password-policy hint) read live from the DB instead of cfg.
	app.PolicyService = policy.NewService(app.DB.DB)
	if err := app.PolicyService.EnsureSingleton(app.ctx, &models.TenantPolicy{
		PasswordMinLength:        cfg.Bootstrap.Password.MinLength,
		PasswordRequireUppercase: cfg.Bootstrap.Password.RequireUppercase,
		PasswordRequireNumber:    cfg.Bootstrap.Password.RequireNumber,
		PasswordRequireSpecial:   cfg.Bootstrap.Password.RequireSpecial,
		SignupEnabled:            true,
		// Default 30-day cooldown between PATCH /users/me/uid calls
		// per user. Discourages rotation-as-impersonation. Operators
		// can tune from the Policy page.
		UIDChangeCooldownDays: 30,
	}); err != nil {
		return fmt.Errorf("seed tenant policy: %v", err)
	}

	// Initialize repositories
	bootstrapRepo := repository.NewBootstrapRepository(app.DB, app.Logger.App)
	userRepo := repository.NewUserRepository(app.DB, app.LDAPClient, app.Logger.App)
	// Phase 7: OAuth consent repo. Used by /authorize to gate the
	// consent prompt and by /consent/submit to write grant rows.
	consentRepo := repository.NewOAuthConsentRepository(app.DB.DB)

	// Initialize OAuth signing-key store (Phase 7).
	// On first-ever startup the directory is empty and we generate a
	// bootstrap RSA key. On subsequent starts we just load existing
	// keys. Auto-aging and rotation orchestration are deferred to a
	// later phase; for now keys live indefinitely until manually rotated.
	app.Logger.App.Info("Initializing OAuth signing-key store",
		zap.String("dir", cfg.OAuth.SigningKeyDir))
	// 0755 (not 0700) for traversal: the admin-bff (uid 10100,
	// non-root) needs to reach /keys/oauth/client-secrets/ to read
	// its own client secret. The signing-key files inside this dir
	// are still 0600 root:root, so non-root processes can list the
	// directory but cannot read the keys themselves.
	if err := os.MkdirAll(cfg.OAuth.SigningKeyDir, 0o755); err != nil {
		return fmt.Errorf("create OAuth signing-key dir: %v", err)
	}
	app.OAuthKeyStore, err = oauth.NewKeyStore(cfg.OAuth.SigningKeyDir)
	if err != nil {
		// Empty-dir error is expected on first run -- bootstrap a key
		if !app.OAuthKeyStore.HasAnyKeys() {
			app.Logger.App.Info("No OAuth signing keys yet; generating initial RSA-2048 keypair")
			// Need a working keystore to call GenerateInitial; if NewKeyStore
			// returned nil we have to construct one fresh.
			if app.OAuthKeyStore == nil {
				app.OAuthKeyStore, _ = oauth.NewKeyStore(cfg.OAuth.SigningKeyDir)
			}
			if app.OAuthKeyStore == nil {
				return fmt.Errorf("OAuth keystore init failed and bootstrap path unrecoverable")
			}
		} else {
			return fmt.Errorf("load OAuth signing keys: %v", err)
		}
	}
	if !app.OAuthKeyStore.HasAnyKeys() {
		if err := app.OAuthKeyStore.GenerateInitial(); err != nil {
			return fmt.Errorf("generate initial OAuth signing key: %v", err)
		}
		app.Logger.App.Info("OAuth signing key generated successfully")
	} else {
		active, _ := app.OAuthKeyStore.Active()
		if active != nil {
			app.Logger.App.Info("OAuth signing key loaded",
				zap.String("active_kid", active.KID),
				zap.Int("total_keys", len(app.OAuthKeyStore.All())))
		}
	}

	// Initialize bootstrap system
	tokenMgr := bootstrap.NewTokenManager(app.Redis, cfg.Bootstrap.TokenTTL, app.Logger.Security)
	passwordPolicy := &authpkg.PasswordPolicy{
		MinLength:        cfg.Bootstrap.Password.MinLength,
		RequireUppercase: cfg.Bootstrap.Password.RequireUppercase,
		RequireLowercase: true,
		RequireNumber:    cfg.Bootstrap.Password.RequireNumber,
		RequireSpecial:   cfg.Bootstrap.Password.RequireSpecial,
	}

	app.BootstrapMgr = bootstrap.NewManager(
		bootstrapRepo,
		userRepo,
		tokenMgr,
		passwordPolicy,
		rbacService,
		app.Logger.Security,
	)

	// Initialize deprovisioning service (BEFORE bootstrap check)
	// This ensures root user sync happens before we check bootstrap status
	app.Logger.App.Info("Initializing LDAP deprovisioning service")
	app.DeprovisioningService = ldap.NewDeprovisioningService(
		app.LDAPClient,
		rbacService,
		app.DB.DB, // Pass the underlying gorm.DB
		bootstrapRepo,
		app.Logger,
		&app.Config.GetConfig().LDAP.Deprovisioning,
	)

	// Run initial deprovisioning reconciliation to sync root users
	// This may auto-provision root users from LDAP or delete missing root users
	app.Logger.App.Info("Running initial LDAP reconciliation")
	if err := app.DeprovisioningService.Reconcile(); err != nil {
		app.Logger.App.Warn("Initial LDAP reconciliation failed",
			zap.Error(err))
		// Don't fail startup - continue but log the error
	}

	// NOW check if bootstrap is needed (after reconciliation)
	needsBootstrap, err := app.BootstrapMgr.NeedsBootstrap(app.ctx)
	if err != nil {
		return fmt.Errorf("failed to check bootstrap status: %v", err)
	}

	if needsBootstrap {
		app.Logger.App.Warn("Bootstrap required - no root user configured")
		app.Logger.Security.Warn("BOOTSTRAP MODE ACTIVE - Root user not configured")

		// Generate bootstrap token
		token, err := app.BootstrapMgr.InitializeBootstrap(app.ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize bootstrap: %v", err)
		}

		app.bootstrapToken = token
		app.Logger.Security.Info("Bootstrap token generated", zap.Duration("ttl", cfg.Bootstrap.TokenTTL))
	} else {
		app.Logger.App.Info("Bootstrap complete - root user configured")
	}

	// Create auth server (but don't start yet)
	app.AuthServer = auth.New(
		app.Config,
		app.Logger,
	)
	// Wire the OAuth signing-key store. The auth server's discovery
	// and JWKS handlers tolerate a nil keystore (return 503), but we
	// always set it here at startup time.
	app.AuthServer.SetOAuthKeyStore(app.OAuthKeyStore)

	// Construct OAuth-server-side primitives (Phase 7 Steps 4-7):
	//   - Code store (Redis-backed, 60s TTL)
	//   - Auth-server session store (Redis-backed, 30m idle / 8h abs)
	//   - Auth service (LDAP-bind + JIT provisioning, already in pkg/auth)
	codeStore := oauth.NewCodeStore(app.Redis.Client, cfg.OAuth.AuthCodeTTL)
	sessionStore := oauth.NewSessionStore(app.Redis.Client,
		cfg.OAuth.AuthSessionIdleTTL, cfg.OAuth.AuthSessionMaxTTL)
	authService := authpkg.NewService(app.LDAPClient, rbacService, userRepo, app.Logger)
	app.AuthServer.SetOAuthDeps(codeStore, sessionStore, authService, app.DB.DB, app.Redis)
	// Phase 8: gate /login on bootstrap completion. The auth server
	// short-circuits to a friendly "setup not yet complete" page
	// while NeedsBootstrap is true, so end users can't sneak in
	// before the operator has finished mint-the-root-user.
	app.AuthServer.SetBootstrapManager(app.BootstrapMgr)

	// Phase 8c.6: hand the auth server a live handle to the
	// DB-backed tenant-policy accessor.
	app.AuthServer.SetPolicyService(app.PolicyService)

	// Phase 7: hand the auth server the consent repo so /authorize
	// can decide whether to prompt and /consent/submit can record
	// approval.
	app.AuthServer.SetConsentRepo(consentRepo)

	// Built-in OAuth client registration. After Phase 8b's tenant-
	// client registration roadmap landed, akashic-admin is the only
	// server-managed built-in — every other client (tenant portals,
	// sub-services, samples) is operator-registered via
	// `akashic-cli clients create` or the admin web console.
	//
	// AdminBFFEnabled gates this single client. When false, the
	// akashic-admin row is REMOVED from client_services on boot
	// (EnsureBuiltInClients deletes any built_in row not in the
	// passed-in spec list), so admin-bff can no longer OAuth-login
	// — the deployment is in "minimal mode": CLI is the only
	// operator surface.
	var specs []oauth.BuiltInClientSpec
	if cfg.OAuth.AdminBFFEnabled {
		specs = append(specs, oauth.BuiltInClientSpec{
			ClientID:      "akashic-admin",
			Name:          "Akashic Admin Console",
			RedirectURIs:  cfg.OAuth.AdminRedirectURI,
			AllowedScopes: "openid profile email",
			AuthTypes:     string(models.AuthTypeAuthorizationCode),
			RoleAllowlist: "root,admin",
		})
	}
	app.Logger.App.Info("Ensuring built-in OAuth client services",
		zap.Bool("admin_bff_enabled", cfg.OAuth.AdminBFFEnabled))
	if err := oauth.EnsureBuiltInClients(app.ctx, app.DB.DB, cfg.OAuth.SigningKeyDir, specs); err != nil {
		return fmt.Errorf("ensure built-in OAuth clients: %v", err)
	}
	app.Logger.App.Info("Built-in OAuth client services ready")

	// Create the API server (but don't start yet). Phase 8: dedicated
	// bearer-authenticated resource server for /users/* and /clients/*.
	app.APIServer = api.New(app.Config, app.Logger)
	app.APIServer.SetDeps(app.OAuthKeyStore, userRepo, app.LDAPClient, authService, app.DB)
	// Phase 8: gate /users/register on bootstrap completion (mirrors
	// the auth server's /login gate). Direct API hits and portal-side
	// signups both block until operator setup is done.
	app.APIServer.SetBootstrapManager(app.BootstrapMgr)
	app.APIServer.SetPolicyService(app.PolicyService)
	// Phase 7.5: api-server's /users/me/consents uses the same
	// repo the auth-server uses for /authorize gating — single
	// source of truth for grant rows.
	app.APIServer.SetConsentRepo(consentRepo)

	// Create control server (but don't start yet)
	app.ControlServer = control.New(
		app.ctx,
		app.AuthServer,
		app.BootstrapMgr,
		app.Config,
		app.Logger,
		app.cancel, // Pass cancel function for shutdown
	)

	// Phase 8: wire the API server into the control plane so its
	// lifecycle endpoints (/api/start, /api/stop, /api/restart) can
	// manage it just like /auth/* manages the auth server.
	app.ControlServer.SetAPIServer(app.APIServer)

	// Phase 8b clients-registration roadmap: the control plane's
	// operator-side /clients endpoint needs DB access to upsert
	// into client_services. Same DB the API-server's bearer-auth
	// /clients writes to — single source of truth.
	app.ControlServer.SetDB(app.DB.DB)

	// Phase 8c.1: setup-status banner needs to probe LDAP health,
	// so wire the same client the auth path uses. Single LDAP
	// connection across the deployment — control's probe and
	// auth's bind share the pool.
	app.ControlServer.SetLDAP(app.LDAPClient)

	// Phase 8c.2: user-management handlers reuse the api-server's
	// userRepo so all writes go through the same audit-aware
	// methods (DisableUser populates disabled_by, etc.).
	app.ControlServer.SetUserRepo(userRepo)

	// Phase 8c.6: control-plane policy CRUD shares the singleton
	// service across all surfaces — operator edits via /policy
	// and any signup/register call read the same row.
	app.ControlServer.SetPolicyService(app.PolicyService)

	app.Logger.App.Info("Application initialized successfully")
	return nil
}

func (app *AkashicApp) AddCloser(closerFn func()) {
	if closerFn != nil {
		app.closerFns = append(app.closerFns, closerFn)
	}
}

// Close executes all registered closer functions in reverse order (LIFO)
func (app *AkashicApp) Close() error {
	var errors []error

	// Execute closers in reverse order (LIFO - Last In, First Out)
	for i := len(app.closerFns) - 1; i >= 0; i-- {
		func() {
			defer func() {
				if r := recover(); r != nil {
					if app.Logger != nil {
						app.Logger.App.Error("Panic during closer execution", zap.Any("panic", r))
					}
					errors = append(errors, fmt.Errorf("panic during closer execution: %v", r))
				}
			}()
			app.closerFns[i]()
		}()
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	return nil
}

func (app *AkashicApp) setupSignalHandlers() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sigCount := 0
		for sig := range c {
			sigCount++

			if sigCount == 1 {
				if app.Logger != nil {
					app.Logger.App.Info("Received shutdown signal, starting graceful shutdown...")
				}
				fmt.Fprintf(os.Stderr, "Received %s. Shutting down gracefully... (press Ctrl+C again to force quit)\n", sig.String())
				if app.cancel != nil {
					app.cancel()
				}
			} else {
				if app.Logger != nil {
					app.Logger.App.Warn("Received shutdown signal again, forcing application to exit")
				}
				fmt.Fprintf(os.Stderr, "Force quit! Exiting immediately.\n")
				os.Exit(1)
			}
		}
	}()
}

func (app *AkashicApp) PrintConfigYAML() {
	settings := app.Config.GetViper().AllSettings()
	b, err := yaml.Marshal(settings)
	if err != nil {
		fmt.Println("error marshaling settings:", err)
		return
	}
	fmt.Println(string(b))
}

func (app *AkashicApp) Run(cmd *cobra.Command, args []string) error {
	// Setup signal handlers for graceful shutdown
	app.setupSignalHandlers()

	// Start deprovisioning service
	app.Logger.App.Info("Starting LDAP deprovisioning service")
	if err := app.DeprovisioningService.Start(); err != nil {
		app.Logger.App.Warn("Failed to start deprovisioning service", zap.Error(err))
		// Don't fail - this is not critical for startup
	}

	// Register deprovisioning service cleanup
	app.AddCloser(func() {
		if err := app.DeprovisioningService.Stop(); err != nil {
			app.Logger.App.Error("Error stopping deprovisioning service", zap.Error(err))
		}
	})

	// Start control server (always starts)
	app.Logger.App.Info("Starting control server",
		zap.String("address", app.ControlServer.GetAddress()))

	if err := app.ControlServer.Start(); err != nil {
		return fmt.Errorf("failed to start control server: %v", err)
	}

	// Register control server cleanup
	app.AddCloser(func() {
		if err := app.ControlServer.Stop(); err != nil {
			app.Logger.App.Error("Error stopping control server", zap.Error(err))
		}
	})

	// Check --no-auto-start flag
	noAutoStart, err := config.GetFlagValue[bool](cmd, config.NoAutoStartFlag)
	if err != nil {
		app.Logger.App.Warn("Failed to read no-auto-start flag, defaulting to auto-start", zap.Error(err))
		noAutoStart = false
	}

	// Start auth server (unless --no-auto-start is set)
	if !noAutoStart {
		app.Logger.App.Info("Auto-starting auth server",
			zap.String("requested-address", app.AuthServer.GetAddress()))

		if err := app.ControlServer.GetStateManager().Start(app.ctx); err != nil {
			app.Logger.App.Error("Failed to auto-start auth server", zap.Error(err))
			// Don't fail - control server is still running, can start manually
		}

		// Phase 8: also auto-start the API (resource) server through its
		// state manager (same pattern as the auth server above). Going
		// through the manager — rather than calling app.APIServer.Start
		// directly — keeps the two state machines (api.Server.state and
		// APIStateManager.state) in lockstep, so a later POST /api/restart
		// sees the manager believing the server is running and follows
		// the Stop→Start path instead of jumping straight to Start.
		// Failure semantics match auth: non-fatal, recoverable via
		// POST /api/start.
		app.Logger.App.Info("Auto-starting API server",
			zap.String("requested-address", app.APIServer.GetAddress()))
		if err := app.ControlServer.GetAPIStateManager().Start(app.ctx); err != nil {
			app.Logger.App.Error("Failed to auto-start API server", zap.Error(err))
		}
	} else {
		app.Logger.App.Info("Auth + API server auto-start disabled (--no-auto-start flag)")
		app.Logger.App.Info("Use control API to start: POST http://localhost:8081/auth/start")
		app.Logger.App.Info("                          POST http://localhost:8081/api/start")
	}

	// Register server cleanups (LIFO — API stops before auth, both
	// before deps).
	app.AddCloser(func() {
		if app.AuthServer.IsRunning() {
			if err := app.AuthServer.Stop(); err != nil {
				app.Logger.App.Error("Error stopping auth server", zap.Error(err))
			}
		}
	})
	app.AddCloser(func() {
		if app.APIServer.IsRunning() {
			if err := app.APIServer.Stop(); err != nil {
				app.Logger.App.Error("Error stopping API server", zap.Error(err))
			}
		}
	})

	// Start the optional in-process cert watcher. It only watches the
	// reloaders that exist at this moment; if the auth server is restarted
	// later (via POST /auth/restart), the new reloader is picked up on the
	// next Vault Agent rotation only if POST /tls/reload is called in the
	// interim. For most operators this is fine because auth restarts are rare.
	if app.Config.GetConfig().PKI.CertWatcherEnabled {
		reloaders := collectReloaders(app.ControlServer, app.AuthServer)
		if len(reloaders) > 0 {
			debounce := app.Config.GetConfig().PKI.CertWatcherDebounce
			watcher, werr := pki.NewWatcher(reloaders, debounce, zapWatcherLogger{app.Logger.App.Sugar()})
			if werr != nil {
				app.Logger.App.Warn("cert watcher failed to start; continuing without hot-reload",
					zap.Error(werr))
			} else {
				watchCtx, cancelWatch := context.WithCancel(app.ctx)
				go watcher.Run(watchCtx)
				app.AddCloser(func() {
					cancelWatch()
					if err := watcher.Close(); err != nil {
						app.Logger.App.Warn("cert watcher close error", zap.Error(err))
					}
				})
				app.Logger.App.Info("cert watcher running",
					zap.Int("reloaders", len(reloaders)),
					zap.Duration("debounce", debounce))
			}
		} else {
			app.Logger.App.Info("cert watcher skipped (no TLS listeners have reloaders)")
		}
	} else {
		app.Logger.App.Info("cert watcher disabled via config")
	}

	cfg := app.Config.GetConfig()
	ctrlURL := accessURL(app.ControlServer.GetAddress(), cfg.Server.Control.TLS.Enabled)
	authURL := accessURL(app.AuthServer.GetAddress(), cfg.Server.Auth.TLS.Enabled)
	apiURL := accessURL(app.APIServer.GetAddress(), cfg.Server.API.TLS.Enabled)
	statusOf := func(running bool) string {
		if running {
			return "Running"
		}
		return "Stopped"
	}

	app.Logger.App.Info("Akashic server started successfully",
		zap.String("control_api", ctrlURL),
		zap.String("auth_api", authURL),
		zap.String("resource_api", apiURL),
		zap.Bool("auth_running", app.AuthServer.IsRunning()),
		zap.Bool("api_running", app.APIServer.IsRunning()))

	fmt.Printf("\n")
	fmt.Printf("=======================================================================\n")
	fmt.Printf("  Akashic Server Running (PID:%v)\n", app.ControlServer.GetPID())
	fmt.Printf("=======================================================================\n")
	fmt.Printf("  Control API:  %s   [%s]\n", ctrlURL, "mTLS")
	fmt.Printf("  Auth API:     %s   [%s]\n", authURL, statusOf(app.AuthServer.IsRunning()))
	fmt.Printf("  Resource API: %s   [%s, bearer]\n", apiURL, statusOf(app.APIServer.IsRunning()))
	fmt.Printf("=======================================================================\n")

	// Display bootstrap information if needed
	if app.bootstrapToken != "" {
		fmt.Printf("  !! BOOTSTRAP MODE ACTIVE !!\n")
		fmt.Printf("-----------------------------------------------------------------------\n")
		fmt.Printf("  Root user not configured. Please create one.\n")
		fmt.Printf("\n")
		fmt.Printf("  Bootstrap Token:\n")
		fmt.Printf("    %s\n", app.bootstrapToken)
		fmt.Printf("\n")
		fmt.Printf("  Methods:\n")
		fmt.Printf("  1. Web: Use BFF to submit token + credentials\n")
		fmt.Printf("  2. CLI: akashic-cli bootstrap create-root --help\n")
		fmt.Printf("\n")
		fmt.Printf("  Token expires in: %v\n", app.Config.GetConfig().Bootstrap.TokenTTL)
		fmt.Printf("=======================================================================\n")
	}

	fmt.Printf("  Press Ctrl+C to stop\n")
	fmt.Printf("=======================================================================\n\n")

	// Wait for shutdown signal
	<-app.ctx.Done()

	app.Logger.App.Info("Shutdown request received, starting graceful shutdown")

	// Execute all closers (LIFO order)
	if err := app.Close(); err != nil {
		// try to log via logger (if logger is not closed yet)
		app.Logger.App.Error("Errors during shutdown", zap.Error(err))
		// print to stderr in case logger is closed
		fmt.Fprintf(os.Stderr, "Error during shutdown: %v\n", err)
	}

	fmt.Println("Shutdown complete.")
	return nil
}
