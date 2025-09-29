package akashic

import (
	"akashic/akashic/pkg/logging"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
)

var configPaths = []string{
	".",                      // current directory
	"./config",               // directory above current directory
	"./configs",              // directory above current directory
	"$HOME/.akashic",         // user-specific config directory
	"$HOME/.config/akashic",  // user-specific config directory
	"/etc/akashic",           // system-wide directory
	"/usr/local/etc/akashic", // another common system-wide directory
}

type AkashicApp struct {
	ctx    context.Context
	cancel context.CancelFunc
	Config *viper.Viper
	Logger *logging.Logger
}

func NewAkashicApp() *AkashicApp {
	ctx, cancel := context.WithCancel(context.Background())
	return &AkashicApp{
		ctx:    ctx,
		cancel: cancel,
		Config: viper.New(),
		Logger: nil,
	}
}

func (app *AkashicApp) Context() context.Context {
	return app.ctx
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
					app.Logger.App.Info("Received shutdown signal, starting graceful shutdown...", zap.String("signal", sig.String()))
				}
				fmt.Fprintf(os.Stderr, "\nReceived %s. Shutting down gracefully... (press Ctrl+C again to force quit)\n", sig.String())
				app.Shutdown()
			} else {
				if app.Logger != nil {
					app.Logger.App.Warn("Received shutdown signal again, forcing application to exit", zap.String("signal", sig.String()))
				}
				fmt.Fprintf(os.Stderr, "\nForce quit! Exiting immediately.\n")
				os.Exit(1)
			}
		}
	}()
}

func (app *AkashicApp) Shutdown() {
	if app.cancel != nil {
		app.cancel()
	}
}

func (app *AkashicApp) Init(cmd *cobra.Command, args []string) error {
	// parse verbose flag
	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return fmt.Errorf("failed to parse verbose flag: %s", err)
	}
	if verbose {
		fmt.Fprintln(os.Stderr, "Verbose logging enabled")
	}

	// handle viper environment variables
	app.Config.SetEnvPrefix("AKASHIC")
	app.Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	app.Config.AutomaticEnv()

	// handle config file
	configFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return fmt.Errorf("failed to parse config flag: %s", err)
	}

	if configFile != "" {
		app.Config.SetConfigFile(configFile)
	} else {
		app.Config.SetConfigName("config")
		app.Config.SetConfigType("yaml")

		homeDir, err := os.UserHomeDir()
		if err != nil {
			if verbose {
				fmt.Fprintln(os.Stderr, "Failed to get user home directory, skipping user-specific config paths")
			}
			homeDir = ""
		}
		for _, path := range configPaths {
			if homeDir == "" && strings.Contains(path, "$HOME") {
				continue
			}
			path = strings.ReplaceAll(path, "$HOME", homeDir)
			app.Config.AddConfigPath(path)
		}
	}

	if err := app.Config.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// config file not found in default paths, proceed with defaults and environment variables
			if verbose {
				fmt.Fprintln(os.Stderr, "No config file found, using defaults and environment variables")
			}
		} else if configFile != "" {
			// if some unknown error occurred, but config file was specified, it's likely user's error. Halt and report.
			if verbose {
				fmt.Fprintln(os.Stderr, "failed to read config file:", configFile)
			}
			return err
		} else {
			// if some unknown error occurred, but config file was not specified, it's internal error. Warn and proceed.
			if verbose {
				fmt.Fprintf(os.Stderr, "Something when wrong: %v; using defaults and environment variables\n", err)
			}
		}
	} else {
		if verbose {
			fmt.Printf("Using config file: %s\n", app.Config.ConfigFileUsed())
		}
	}

	// bind flags to viper
	app.Config.BindPFlag("server.auth.host", cmd.Flags().Lookup("host"))
	app.Config.BindPFlag("server.auth.port", cmd.Flags().Lookup("port"))

	// set default values
	app.Config.SetDefault("server.auth.host", "0.0.0.0")
	app.Config.SetDefault("server.auth.port", 8080)

	return nil
}

func PrintSettingsYAML(v *viper.Viper) {
	settings := v.AllSettings()
	b, err := yaml.Marshal(settings)
	if err != nil {
		fmt.Println("error marshaling settings:", err)
		return
	}
	fmt.Println(string(b))
}

func (app *AkashicApp) Run(cmd *cobra.Command, args []string) error {
	// THIS SHOULD RUN THE SERVER BUT FOR NOW JUST PRINT CONFIGURATION FOR TESTING PURPOSES
	// print all config values in viper in json format
	fmt.Println("Configuration values:")
	PrintSettingsYAML(app.Config)

	app.setupSignalHandlers()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-app.Context().Done():
			time.Sleep(2 * time.Second) // simulate cleanup work
			fmt.Println("Graceful shutdown complete.")
			return nil
		case <-ticker.C:
			fmt.Printf("Application running... (press Ctrl+C to exit)\n")
		}
	}
}
