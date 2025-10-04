package akashic

import (
	"akashic/akashic/pkg/config"
	"akashic/akashic/pkg/logging"
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

type AkashicApp struct {
	ctx       context.Context
	cancel    context.CancelFunc
	Config    *config.ConfigManager
	Logger    *logging.Logger
	closerFns []func()
	verbose   bool
}

func NewAkashicApp() *AkashicApp {
	ctx, cancel := context.WithCancel(context.Background())
	return &AkashicApp{
		ctx:       ctx,
		cancel:    cancel,
		Config:    nil,
		Logger:    nil,
		closerFns: make([]func(), 0),
	}
}

func (app *AkashicApp) Init(cmd *cobra.Command, args []string) error {
	var err error

	app.Config, err = config.NewConfigManager(cmd, app)
	if err != nil {
		return fmt.Errorf("failed to initialize configuration: %v", err)
	}

	cfg := app.Config.GetConfig()
	var loggerClose func()
	app.Logger, loggerClose, err = logging.New(&cfg.Logging)
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}

	app.AddCloser(loggerClose)

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
	// THIS SHOULD RUN THE SERVER BUT FOR NOW JUST PRINT CONFIGURATION FOR TESTING PURPOSES
	fmt.Println("Configuration values:")
	app.PrintConfigYAML()

	app.setupSignalHandlers()

	app.Logger.App.Info("Server simulation started")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-app.ctx.Done():
			app.Logger.App.Info("Shutdown signal received, stopping server")
			if err := app.Close(); err != nil {
				app.VerbosePrintlnf("Error during shutdown: %v", err)
			}
			fmt.Println("Graceful shutdown complete.")
			return nil
		case <-ticker.C:
			app.Logger.App.Debug("Server tick")
			fmt.Printf("Application running... (press Ctrl+C to exit)\n")
		}
	}
}
