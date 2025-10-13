package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// configCmd represents the config command group
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
	Long:  `Commands for viewing and reloading the Akashic server configuration.`,
}

// configViewCmd represents the config view command
var configViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View current configuration",
	Long:  `View the current Akashic server configuration.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Get(ctx, "/config")
		if err != nil {
			return fmt.Errorf("failed to get configuration: %v", err)
		}

		var config ConfigResponse
		if err := json.Unmarshal(resp.Data, &config); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		format, _ := cmd.Flags().GetString("format")

		fmt.Println("Current Configuration:")
		fmt.Println("======================")
		fmt.Println()

		switch format {
		case "json":
			prettyJSON, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to format config as JSON: %v", err)
			}
			fmt.Println(string(prettyJSON))

		case "yaml":
			yamlData, err := yaml.Marshal(config)
			if err != nil {
				return fmt.Errorf("failed to format config as YAML: %v", err)
			}
			fmt.Println(string(yamlData))

		default:
			return fmt.Errorf("unsupported format: %s (use 'json' or 'yaml')", format)
		}

		return nil
	},
}

// configReloadCmd represents the config reload command
var configReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration from file",
	Long: `Reload the Akashic server configuration from the config file.

This allows you to apply configuration changes without restarting the server.

The config file is re-read, validated, and applied to running components.
Components that support hot-reload (like the logger) will be reconfigured.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.Post(ctx, "/config/reload", nil)
		if err != nil {
			return fmt.Errorf("failed to reload configuration: %v", err)
		}

		fmt.Println("✓ Configuration reloaded successfully.")
		fmt.Println()
		fmt.Println("Changes have been applied to running components.")
		fmt.Println("Some settings may require a server restart to take full effect.")

		return nil
	},
}

// configValidateCmd represents the config validate command
var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long: `Validate the configuration file without applying changes.

This checks the config file for syntax errors and invalid values.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.Post(ctx, "/config/validate", nil)
		if err != nil {
			return fmt.Errorf("configuration validation failed: %v", err)
		}

		fmt.Println("✓ Configuration is valid.")

		return nil
	},
}

func init() {
	// Add subcommands to config
	configCmd.AddCommand(configViewCmd)
	configCmd.AddCommand(configReloadCmd)
	configCmd.AddCommand(configValidateCmd)

	// Flags for view command
	configViewCmd.Flags().StringP("format", "f", "yaml", "Output format: json or yaml")
}
