package main

import (
	"fmt"

	akashiccli "akashic/akashic/pkg/akashic-cli"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	controlURL string
	verbose    bool

	// Shared client instance
	client *akashiccli.Client
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "akashic-cli",
	Short: "Akashic CLI - Administrative tool for Akashic server",
	Long: `akashic-cli is a command-line tool for managing the Akashic server.

It connects to the Akashic control plane API (default: http://localhost:8081)
and allows you to perform administrative tasks such as:

- Bootstrap root user creation
- User management (create, list, disable, enable)
- Server control (start, stop, restart, status)
- Configuration management (view, reload)

Examples:
  # Check bootstrap status
  akashic-cli bootstrap status

  # Create root user (during bootstrap)
  akashic-cli bootstrap create-root --token <token> --username root --email root@example.com

  # Create an admin user
  akashic-cli user create --username admin --email admin@example.com --type admin

  # List all users
  akashic-cli user list

  # Check server status
  akashic-cli server status

  # Restart auth server
  akashic-cli server restart`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Initialize client for all commands
		client = akashiccli.NewClient(controlURL, verbose)
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&controlURL, "url", "http://localhost:8081",
		"Akashic control plane URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"Enable verbose output (shows HTTP requests/responses)")

	// Add command groups
	rootCmd.AddCommand(bootstrapCmd)
	rootCmd.AddCommand(userCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of akashic-cli",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("akashic-cli v0.0.2")
	},
}
