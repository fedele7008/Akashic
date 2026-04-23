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
	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/repository"
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
	ControlServer         *control.Server
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

	// Initialize repositories
	bootstrapRepo := repository.NewBootstrapRepository(app.DB, app.Logger.App)
	userRepo := repository.NewUserRepository(app.DB, app.LDAPClient, app.Logger.App)

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

	// Create control server (but don't start yet)
	app.ControlServer = control.New(
		app.ctx,
		app.AuthServer,
		app.BootstrapMgr,
		app.Config,
		app.Logger,
		app.cancel, // Pass cancel function for shutdown
	)

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
	} else {
		app.Logger.App.Info("Auth server auto-start disabled (--no-auto-start flag)")
		app.Logger.App.Info("Use control API to start: POST http://localhost:8081/auth/start")
	}

	// Register auth server cleanup
	app.AddCloser(func() {
		if app.AuthServer.IsRunning() {
			if err := app.AuthServer.Stop(); err != nil {
				app.Logger.App.Error("Error stopping auth server", zap.Error(err))
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

	app.Logger.App.Info("Akashic server started successfully",
		zap.String("control_api", fmt.Sprintf("http://%s", app.ControlServer.GetAddress())),
		zap.String("auth_api", fmt.Sprintf("http://%s", app.AuthServer.GetAddress())),
		zap.Bool("auth_running", app.AuthServer.IsRunning()))

	fmt.Printf("\n")
	fmt.Printf("=======================================================================\n")
	fmt.Printf("  Akashic Server Running (PID:%v)\n", app.ControlServer.GetPID())
	fmt.Printf("=======================================================================\n")
	fmt.Printf("  Control API: http://%s\n", app.ControlServer.GetAddress())
	fmt.Printf("  Auth API:    http://%s\n", app.AuthServer.GetAddress())
	fmt.Printf("  Auth Status: %s\n", map[bool]string{true: "Running", false: "Stopped"}[app.AuthServer.IsRunning()])
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
