package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall"
	"time"

	akashiccli "akashic/akashic/pkg/akashic-cli"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// bootstrapCmd represents the bootstrap command group
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Bootstrap-related commands",
	Long:  `Commands for managing the Akashic bootstrap process (initial root user creation).`,
}

// bootstrapStatusCmd represents the bootstrap status command
var bootstrapStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check bootstrap status",
	Long:  `Check whether the Akashic server needs bootstrapping (root user creation).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Get(ctx, "/bootstrap/status")
		if err != nil {
			return fmt.Errorf("failed to get bootstrap status: %v", err)
		}

		var status akashiccli.BootstrapStatusResponse
		if err := json.Unmarshal(resp.Data, &status); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		fmt.Println("Bootstrap Status:")
		fmt.Println("=================")
		fmt.Printf("Needs Bootstrap: %v\n", status.NeedsBootstrap)
		fmt.Printf("Is Complete:     %v\n", status.IsComplete)
		fmt.Printf("Created At:      %s\n", status.CreatedAt.Format(time.RFC3339))

		if status.IsComplete {
			if status.CompletedAt != nil {
				fmt.Printf("Completed At:    %s\n", status.CompletedAt.Format(time.RFC3339))
			}
			if status.RootUserID != nil {
				fmt.Printf("Root User ID:    %s\n", *status.RootUserID)
			}
		} else {
			fmt.Printf("\nBootstrap Token:\n")
			fmt.Printf("  Exists:        %v\n", status.TokenExists)
			if status.TokenExists {
				ttlMinutes := status.TokenTTLSeconds / 60
				ttlSeconds := status.TokenTTLSeconds % 60
				fmt.Printf("  TTL Remaining: %dm%ds\n", ttlMinutes, ttlSeconds)
			}
		}

		return nil
	},
}

// bootstrapCreateRootCmd represents the create-root command
var bootstrapCreateRootCmd = &cobra.Command{
	Use:   "create-root",
	Short: "Create the root user during bootstrap",
	Long: `Create the root user using a bootstrap token.

The bootstrap token is displayed when the server starts in bootstrap mode.
You can also check for the token using 'akashic-cli bootstrap status'.

The password must meet the following requirements:
  - Minimum 12 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character

Example:
  akashic-cli bootstrap create-root \
    --token abc123... \
    --username root \
    --email root@example.com \
    --password "SecurePass123!"

Interactive mode (prompts for password):
  akashic-cli bootstrap create-root \
    --token abc123... \
    --username root \
    --email root@example.com`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		username, _ := cmd.Flags().GetString("username")
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")

		// Validate required flags
		if token == "" {
			return fmt.Errorf("--token is required")
		}
		if username == "" {
			return fmt.Errorf("--username is required")
		}
		if email == "" {
			return fmt.Errorf("--email is required")
		}

		// If password not provided, prompt for it securely
		if password == "" {
			fmt.Print("Enter password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println() // Print newline after password input
			if err != nil {
				return fmt.Errorf("failed to read password: %v", err)
			}
			password = string(passwordBytes)

			if password == "" {
				return fmt.Errorf("password cannot be empty")
			}

			// Confirm password
			fmt.Print("Confirm password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			if err != nil {
				return fmt.Errorf("failed to read password confirmation: %v", err)
			}

			if password != string(confirmBytes) {
				return fmt.Errorf("passwords do not match")
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req := akashiccli.CreateRootRequest{
			Token:    token,
			Username: username,
			Email:    email,
			Password: password,
		}

		resp, err := client.Post(ctx, "/bootstrap/root", req)
		if err != nil {
			return fmt.Errorf("failed to create root user: %v", err)
		}

		var user akashiccli.RootUserCreateResponse
		if err := json.Unmarshal(resp.Data, &user); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		fmt.Println("✓ Root user created successfully!")
		fmt.Println()
		fmt.Printf("User ID:   %s\n", user.User.ID)
		fmt.Printf("Username:  %s\n", user.User.Username)
		fmt.Printf("Email:     %s\n", user.User.Email)
		fmt.Printf("User Type: %s\n", user.User.UserType)
		fmt.Printf("Created:   %s\n", user.User.CreatedAt.Format(time.RFC3339))
		fmt.Println()
		fmt.Printf("%s\n", user.Message)

		return nil
	},
}

func init() {
	// Add subcommands to bootstrap
	bootstrapCmd.AddCommand(bootstrapStatusCmd)
	bootstrapCmd.AddCommand(bootstrapCreateRootCmd)

	// Flags for create-root command
	bootstrapCreateRootCmd.Flags().StringP("token", "t", "", "Bootstrap token (required)")
	bootstrapCreateRootCmd.Flags().StringP("username", "u", "", "Root username (required)")
	bootstrapCreateRootCmd.Flags().StringP("email", "e", "", "Root email (required)")
	bootstrapCreateRootCmd.Flags().StringP("password", "p", "", "Root password (if not provided, will prompt securely)")
}
