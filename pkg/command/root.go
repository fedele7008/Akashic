package command

import (
	"akashic/akashic/pkg/common"
	"akashic/akashic/pkg/config"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	branch, commit, err := common.GetGitInfo()
	if err != nil {
		return nil
	}

	var configFile string
	var environment string
	var outputFormat string

	rootCmd := &cobra.Command{
		Use:     "akashic",
		Short:   fmt.Sprintf(fmtRootCmdShort, fmt.Sprintf("%s (%s)", branch, commit)),
		Long:    fmt.Sprintf(fmtRootCmdLong, fmt.Sprintf("%s (%s)", branch, commit)),
		Version: branch,
		RunE: func(cmd *cobra.Command, args []string) error {
			return displayConfiguration(configFile, environment, outputFormat)
		},
	}

	// Configuration flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file name (without extension)")
	rootCmd.PersistentFlags().StringVarP(&environment, "env", "e", "development", "environment (development, staging, production)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "pretty", "output format (pretty, json, yaml)")

	rootCmd.Flags().BoolP("version", "v", false, "show version")
	rootCmd.AddCommand(NewConfigCommand())
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	return rootCmd
}

func displayConfiguration(configFile, environment, outputFormat string) error {
	fmt.Printf("=== Akashic Configuration ===\n")
	fmt.Printf("Environment: %s\n", environment)

	// Create configuration manager
	var manager *config.ViperManager
	var err error

	if configFile != "" {
		fmt.Printf("Config file: %s\n", configFile)
		manager, err = config.NewViperManager(configFile,
			config.WithViperEnvironment(environment),
			config.WithViperHotReload(false),
		)
	} else {
		fmt.Printf("Config file: using defaults and environment variables\n")
		manager, err = config.NewViperManager("config",
			config.WithViperEnvironment(environment),
			config.WithViperHotReload(false),
		)
	}

	if err != nil {
		return fmt.Errorf("failed to create config manager: %w", err)
	}
	defer manager.Close()

	fmt.Printf("Output format: %s\n", outputFormat)
	fmt.Println()

	switch strings.ToLower(outputFormat) {
	case "json":
		return displayConfigAsJSON(manager)
	case "yaml":
		return displayConfigAsYAML(manager)
	default:
		return displayConfigPretty(manager)
	}
}

func displayConfigPretty(manager *config.ViperManager) error {
	cfg := manager.GetConfig()

	fmt.Println("🔧 Server Configuration:")
	authHost := cfg.Server.Auth.Host.GetOrDefault()
	authPort := cfg.Server.Auth.Port.GetOrDefault()
	controlHost := cfg.Server.Control.Host.GetOrDefault()
	controlPort := cfg.Server.Control.Port.GetOrDefault()
	tlsEnabled := cfg.Server.Control.TLS.Enabled.GetOrDefault()

	fmt.Printf("  Auth Server:    %s:%d (OAuth/OIDC endpoints)\n", authHost, authPort)
	fmt.Printf("  Control Server: %s:%d (mTLS: %v)\n", controlHost, controlPort, tlsEnabled)

	if tlsEnabled {
		certFile := cfg.Server.Control.TLS.CertFile.GetOrDefault()
		keyFile := cfg.Server.Control.TLS.KeyFile.GetOrDefault()
		caFile := cfg.Server.Control.TLS.CAFile.GetOrDefault()
		clientAuth := cfg.Server.Control.TLS.ClientAuthRequired.GetOrDefault()
		fmt.Printf("    Certificate: %s\n", certFile)
		fmt.Printf("    Private Key: %s\n", keyFile)
		fmt.Printf("    CA File:     %s\n", caFile)
		fmt.Printf("    Client Auth: %v\n", clientAuth)
	}

	fmt.Println()
	fmt.Println("💾 Database Configuration:")
	pgHost := cfg.Database.Postgres.Host.GetOrDefault()
	pgPort := cfg.Database.Postgres.Port.GetOrDefault()
	pgDB := cfg.Database.Postgres.Database.GetOrDefault()
	pgUser := cfg.Database.Postgres.Username.GetOrDefault()
	redisHost := cfg.Database.Redis.Host.GetOrDefault()
	redisPort := cfg.Database.Redis.Port.GetOrDefault()

	fmt.Printf("  PostgreSQL: %s:%d/%s (user: %s)\n", pgHost, pgPort, pgDB, pgUser)
	fmt.Printf("  Redis:      %s:%d\n", redisHost, redisPort)

	fmt.Println()
	fmt.Println("🍪 Session Configuration:")
	sessionTimeout := cfg.Session.Timeout.GetOrDefault()
	secureCookies := cfg.Session.SecureCookies.GetOrDefault()
	sameSite := cfg.Session.SameSite.GetOrDefault()
	cookieName := cfg.Session.CookieName.GetOrDefault()

	fmt.Printf("  Timeout:        %v\n", sessionTimeout)
	fmt.Printf("  Secure Cookies: %v\n", secureCookies)
	fmt.Printf("  SameSite:       %s\n", sameSite)
	fmt.Printf("  Cookie Name:    %s\n", cookieName)

	fmt.Println()
	fmt.Println("📝 Logging Configuration:")
	serviceName, _ := cfg.Logging.Service.Get()
	env, _ := cfg.Logging.Env.Get()
	fmt.Printf("  Service: %s\n", serviceName)
	fmt.Printf("  Environment: %s\n", env)

	fmt.Println()
	fmt.Println("🚀 Deployment Configuration:")
	deployEnv := cfg.Deployment.Environment.GetOrDefault()
	debug := cfg.Deployment.Debug.GetOrDefault()
	fmt.Printf("  Environment: %s\n", deployEnv)
	fmt.Printf("  Debug Mode:  %v\n", debug)

	return nil
}

func displayConfigAsJSON(manager *config.ViperManager) error {
	allSettings := manager.GetAllSettings()
	jsonData, err := json.MarshalIndent(allSettings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config to JSON: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

func displayConfigAsYAML(manager *config.ViperManager) error {
	// For now, we'll use the viper's built-in functionality
	fmt.Println("YAML output not yet implemented - showing JSON instead:")
	return displayConfigAsJSON(manager)
}

func NewConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management commands",
		Long:  "Commands for managing Akashic configuration",
	}

	cmd.AddCommand(NewConfigShowCommand())
	cmd.AddCommand(NewConfigValidateCommand())

	return cmd
}

func NewConfigShowCommand() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		Long:  "Display the current configuration with all resolved values",
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, _ := cmd.Root().PersistentFlags().GetString("config")
			environment, _ := cmd.Root().PersistentFlags().GetString("env")
			return displayConfiguration(configFile, environment, outputFormat)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "pretty", "output format (pretty, json, yaml)")

	return cmd
}

func NewConfigValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration",
		Long:  "Validate the current configuration for errors",
		RunE: func(cmd *cobra.Command, args []string) error {
			configFile, _ := cmd.Root().PersistentFlags().GetString("config")
			environment, _ := cmd.Root().PersistentFlags().GetString("env")

			var manager *config.ViperManager
			var err error

			if configFile != "" {
				manager, err = config.NewViperManager(configFile,
					config.WithViperEnvironment(environment),
					config.WithViperHotReload(false),
				)
			} else {
				manager, err = config.NewViperManager("config",
					config.WithViperEnvironment(environment),
					config.WithViperHotReload(false),
				)
			}

			if err != nil {
				fmt.Printf("❌ Configuration validation failed: %v\n", err)
				return err
			}
			defer manager.Close()

			fmt.Printf("✅ Configuration is valid!\n")
			return nil
		},
	}

	return cmd
}
