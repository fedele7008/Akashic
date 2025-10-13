package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// serverCmd represents the server command group
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Server control commands",
	Long:  `Commands for controlling the Akashic server (start, stop, restart, status, shutdown).`,
}

// serverStatusCmd represents the server status command
var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Get server status",
	Long:  `Get the current status of both the control server and auth server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Get(ctx, "/status")
		if err != nil {
			return fmt.Errorf("failed to get server status: %v", err)
		}

		var status ServerStatusResponse
		if err := json.Unmarshal(resp.Data, &status); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		fmt.Println("Akashic Status:")
		fmt.Println("==============")
		fmt.Printf("PID:            %d\n", status.PID)
		fmt.Printf("Uptime:         %v\n", status.Uptime)
		fmt.Println("Services:")
		fmt.Println("- Control Server:")
		fmt.Printf("    Address:    %s\n", status.ControlServer.Address)
		fmt.Printf("    State:      %s\n", status.ControlServer.State)
		fmt.Println("- Auth Server:")
		fmt.Printf("    Address:    %s\n", status.AuthServer.Address)
		fmt.Printf("    State:      %s\n", status.AuthServer.State)
		fmt.Printf("    Started at: %v\n", status.AuthServer.StartedAt)
		fmt.Printf("    Uptime:     %v\n", status.AuthServer.Uptime)

		return nil
	},
}

// serverStartCmd represents the server start command
var serverStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the auth server",
	Long:  `Start the auth server if it's not already running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.Post(ctx, "/auth/start", nil)
		if err != nil {
			return fmt.Errorf("failed to start auth server: %v", err)
		}

		fmt.Println("✓ Auth server started successfully.")

		return nil
	},
}

// serverStopCmd represents the server stop command
var serverStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the auth server",
	Long:  `Stop the auth server gracefully.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.Post(ctx, "/auth/stop", nil)
		if err != nil {
			return fmt.Errorf("failed to stop auth server: %v", err)
		}

		fmt.Println("✓ Auth server stopped successfully.")

		return nil
	},
}

// serverRestartCmd represents the server restart command
var serverRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart the auth server",
	Long:  `Restart the auth server (stop then start).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.Post(ctx, "/auth/restart", nil)
		if err != nil {
			return fmt.Errorf("failed to restart auth server: %v", err)
		}

		fmt.Println("✓ Auth server restarted successfully.")

		return nil
	},
}

// serverShutdownCmd represents the server shutdown command
var serverShutdownCmd = &cobra.Command{
	Use:   "shutdown",
	Short: "Shutdown the entire Akashic server",
	Long: `Gracefully shutdown both the auth server and control server.

WARNING: This will stop the entire Akashic server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Require confirmation
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			fmt.Println("WARNING: This will shutdown the entire Akashic server.")
			fmt.Println("To confirm, use --confirm flag.")
			return fmt.Errorf("shutdown not confirmed")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := client.Post(ctx, "/server/quit", nil)
		if err != nil {
			return fmt.Errorf("failed to shutdown server: %v", err)
		}

		fmt.Println("✓ Akashic server shutdown initiated.")

		return nil
	},
}

// serverHealthCmd represents the server health command
var serverHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check server health",
	Long:  `Check the health status of the Akashic server and its dependencies.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Get(ctx, "/health")
		if err != nil {
			return fmt.Errorf("failed to get health status: %v", err)
		}

		// Pretty print the health response
		var healthData map[string]any
		if err := json.Unmarshal(resp.Data, &healthData); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		fmt.Println("Server Health:")
		fmt.Println("==============")
		fmt.Println("Control Server:", healthData["status"])

		return nil
	},
}

func init() {
	// Add subcommands to server
	serverCmd.AddCommand(serverStatusCmd)
	serverCmd.AddCommand(serverStartCmd)
	serverCmd.AddCommand(serverStopCmd)
	serverCmd.AddCommand(serverRestartCmd)
	serverCmd.AddCommand(serverShutdownCmd)
	serverCmd.AddCommand(serverHealthCmd)

	// Flags for shutdown command
	serverShutdownCmd.Flags().Bool("confirm", false, "Confirm shutdown")
}
