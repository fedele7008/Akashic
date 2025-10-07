package akashic

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	authpkg "akashic/akashic/pkg/auth"
	"akashic/akashic/pkg/bootstrap"
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/database/gormdb"
	"akashic/akashic/pkg/database/redis"
	"akashic/akashic/pkg/logging"
	"akashic/akashic/pkg/repository"
	"akashic/akashic/pkg/server/auth"
	"akashic/akashic/pkg/server/control"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

type AkashicApp struct {
	ctx            context.Context
	cancel         context.CancelFunc
	Config         *config.ConfigManager
	Logger         *logging.Logger
	DB             *gormdb.DB
	Redis          *redis.Client
	BootstrapMgr   *bootstrap.Manager
	AuthServer     *auth.Server
	ControlServer  *control.Server
	closerFns      []func()
	verbose        bool
	bootstrapToken string // Stored for console display
}

func NewAkashicApp() *AkashicApp {
	ctx, cancel := context.WithCancel(context.Background())
	return &AkashicApp{
		ctx:           ctx,
		cancel:        cancel,
		Config:        nil,
		Logger:        nil,
		AuthServer:    nil,
		ControlServer: nil,
		closerFns:     make([]func(), 0),
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
	app.AddCloser(loggerClose)

	// feed reconfigure function to config manager (for config reloading)
	app.Config.SetLoggerReconfigureFunction(app.Logger.Reconfigure)

	// Initialize PostgreSQL with GORM
	app.Logger.App.Info("Initializing database connections")
	app.DB, err = gormdb.New(&gormdb.Config{
		Host:            cfg.Database.Postgres.Host,
		Port:            cfg.Database.Postgres.Port,
		Database:        cfg.Database.Postgres.Database,
		Username:        cfg.Database.Postgres.Username,
		Password:        cfg.Database.Postgres.Password,
		SSLMode:         cfg.Database.Postgres.SSLMode,
		MaxConns:        cfg.Database.Postgres.MaxConnections,
		MaxIdleConns:    cfg.Database.Postgres.MaxIdleConnections,
		ConnLifetime:    cfg.Database.Postgres.ConnectionLifetime,
		ConnMaxIdleTime: 30 * time.Minute,
	}, app.Logger.App)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	app.AddCloser(func() {
		if err := app.DB.Close(); err != nil {
			app.Logger.App.Error("Error closing PostgreSQL connection", zap.Error(err))
		}
	})

	// Initialize Redis
	app.Redis, err = redis.New(&redis.Config{
		Host:         cfg.Database.Redis.Host,
		Port:         cfg.Database.Redis.Port,
		Password:     cfg.Database.Redis.Password,
		DB:           cfg.Database.Redis.DB,
		PoolSize:     cfg.Database.Redis.PoolSize,
		MinIdleConns: 2,
		MaxRetries:   3,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}, app.Logger.App)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	app.AddCloser(func() {
		if err := app.Redis.Close(); err != nil {
			app.Logger.App.Error("Error closing Redis connection", zap.Error(err))
		}
	})

	// Run automatic database migrations with GORM
	app.Logger.App.Info("Running automatic database migrations")
	if err := app.DB.AutoMigrate(); err != nil {
		return fmt.Errorf("failed to run auto-migration: %w", err)
	}

	// Initialize repositories
	bootstrapRepo := repository.NewBootstrapRepository(app.DB, app.Logger.App)
	userRepo := repository.NewUserRepository(app.DB, app.Logger.App)

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
		app.Logger.Security,
	)

	// Check if bootstrap is needed
	needsBootstrap, err := app.BootstrapMgr.NeedsBootstrap(app.ctx)
	if err != nil {
		return fmt.Errorf("failed to check bootstrap status: %w", err)
	}

	if needsBootstrap {
		app.Logger.App.Warn("Bootstrap required - no root user configured")
		app.Logger.Security.Warn("BOOTSTRAP MODE ACTIVE - Root user not configured")

		// Generate bootstrap token
		token, err := app.BootstrapMgr.InitializeBootstrap(app.ctx)
		if err != nil {
			return fmt.Errorf("failed to initialize bootstrap: %w", err)
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
		app.Config,
		app.Logger,
		app.cancel, // Pass cancel function for shutdown
	)

	// Set bootstrap manager on control server
	app.ControlServer.SetBootstrapManager(app.BootstrapMgr)

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

	app.Logger.App.Info("Akashic server started successfully",
		zap.String("control_api", fmt.Sprintf("http://%s", app.ControlServer.GetAddress())),
		zap.String("auth_api", fmt.Sprintf("http://%s", app.AuthServer.GetAddress())),
		zap.Bool("auth_running", app.AuthServer.IsRunning()))

	fmt.Printf("\n")
	fmt.Printf("=================================================\n")
	fmt.Printf("  Akashic Server Running (PID:%v)\n", app.ControlServer.GetPID())
	fmt.Printf("=================================================\n")
	fmt.Printf("  Control API: http://%s\n", app.ControlServer.GetAddress())
	fmt.Printf("  Auth API:    http://%s\n", app.AuthServer.GetAddress())
	fmt.Printf("  Auth Status: %s\n", map[bool]string{true: "Running", false: "Stopped"}[app.AuthServer.IsRunning()])
	fmt.Printf("=================================================\n")

	// Display bootstrap information if needed
	if app.bootstrapToken != "" {
		fmt.Printf("\n")
		fmt.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
		fmt.Printf("  BOOTSTRAP MODE ACTIVE\n")
		fmt.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
		fmt.Printf("\n")
		fmt.Printf("  Root user not configured. Please create one.\n")
		fmt.Printf("\n")
		fmt.Printf("  Bootstrap Token:\n")
		fmt.Printf("  %s\n", app.bootstrapToken)
		fmt.Printf("\n")
		fmt.Printf("  Methods:\n")
		fmt.Printf("  1. Web: Use BFF to submit token + credentials\n")
		fmt.Printf("  2. CLI: akashic bootstrap create-root\n")
		fmt.Printf("\n")
		fmt.Printf("  Token expires in: %v\n", app.Config.GetConfig().Bootstrap.TokenTTL)
		fmt.Printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
		fmt.Printf("\n")
	}

	fmt.Printf("  Press Ctrl+C to stop\n")
	fmt.Printf("=================================================\n\n")

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
