package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// userCmd represents the user command group
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User management commands",
	Long:  `Commands for managing Akashic users (create, list, disable, enable, delete).`,
}

// userListCmd represents the user list command
var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users",
	Long:  `List all users in the Akashic system with their details.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")

		path := fmt.Sprintf("/users?limit=%d&offset=%d", limit, offset)
		resp, err := client.Get(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to list users: %v", err)
		}

		var users []UserResponse
		if err := json.Unmarshal(resp.Data, &users); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		if len(users) == 0 {
			fmt.Println("No users found.")
			return nil
		}

		// Print table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "ID\tUSERNAME\tEMAIL\tTYPE\tDISABLED\tCREATED")
		fmt.Fprintln(w, "────────────────────────────────────\t────────\t────────────────\t─────\t────────\t───────────────────")
		for _, user := range users {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\n",
				user.ID[:8]+"...",
				user.Username,
				user.Email,
				user.UserType,
				user.IsDisabled,
				user.CreatedAt.Format("2006-01-02 15:04"))
		}
		w.Flush()

		fmt.Printf("\nTotal: %d users\n", len(users))

		return nil
	},
}

// userGetCmd represents the user get command
var userGetCmd = &cobra.Command{
	Use:   "get [user-id or username]",
	Short: "Get user details",
	Long:  `Get detailed information about a specific user by ID or username.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		identifier := args[0]
		path := fmt.Sprintf("/users/%s", identifier)

		resp, err := client.Get(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to get user: %v", err)
		}

		var user UserResponse
		if err := json.Unmarshal(resp.Data, &user); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		fmt.Println("User Details:")
		fmt.Println("=============")
		fmt.Printf("ID:         %s\n", user.ID)
		fmt.Printf("Username:   %s\n", user.Username)
		fmt.Printf("Email:      %s\n", user.Email)
		fmt.Printf("Type:       %s\n", user.UserType)
		fmt.Printf("Disabled:   %v\n", user.IsDisabled)
		if user.DisabledAt != nil {
			fmt.Printf("Disabled At: %s\n", user.DisabledAt.Format(time.RFC3339))
		}
		if user.DisabledBy != nil {
			fmt.Printf("Disabled By: %s\n", *user.DisabledBy)
		}
		fmt.Printf("Created At: %s\n", user.CreatedAt.Format(time.RFC3339))
		fmt.Printf("Updated At: %s\n", user.UpdatedAt.Format(time.RFC3339))

		return nil
	},
}

// userCreateCmd represents the user create command
var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Long: `Create a new user in the Akashic system.

User types:
  - admin: Full administrative access (can manage users, configuration)
  - user:  Regular user (limited access)

Note: Root users can only be created during bootstrap.

Example:
  akashic-cli user create \
    --username alice \
    --email alice@example.com \
    --type admin \
    --password "SecurePass123!"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		username, _ := cmd.Flags().GetString("username")
		email, _ := cmd.Flags().GetString("email")
		userType, _ := cmd.Flags().GetString("type")
		password, _ := cmd.Flags().GetString("password")

		// Validate required flags
		if username == "" {
			return fmt.Errorf("--username is required")
		}
		if email == "" {
			return fmt.Errorf("--email is required")
		}
		if userType == "" {
			return fmt.Errorf("--type is required (admin or user)")
		}

		// Validate user type
		if userType != "admin" && userType != "user" {
			return fmt.Errorf("invalid user type: %s (must be 'admin' or 'user')", userType)
		}

		// If password not provided, prompt for it securely
		if password == "" {
			fmt.Print("Enter password: ")
			passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
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

		req := CreateUserRequest{
			Username: username,
			Email:    email,
			Password: password,
			UserType: userType,
		}

		resp, err := client.Post(ctx, "/users", req)
		if err != nil {
			return fmt.Errorf("failed to create user: %v", err)
		}

		var user UserResponse
		if err := json.Unmarshal(resp.Data, &user); err != nil {
			return fmt.Errorf("failed to parse response: %v", err)
		}

		fmt.Println("✓ User created successfully!")
		fmt.Println()
		fmt.Printf("User ID:   %s\n", user.ID)
		fmt.Printf("Username:  %s\n", user.Username)
		fmt.Printf("Email:     %s\n", user.Email)
		fmt.Printf("User Type: %s\n", user.UserType)
		fmt.Printf("Created:   %s\n", user.CreatedAt.Format(time.RFC3339))

		return nil
	},
}

// userDisableCmd represents the user disable command
var userDisableCmd = &cobra.Command{
	Use:   "disable [user-id or username]",
	Short: "Disable a user account",
	Long: `Disable a user account, preventing them from logging in.

The account can be re-enabled later using 'user enable'.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		identifier := args[0]
		path := fmt.Sprintf("/users/%s/disable", identifier)

		_, err := client.Post(ctx, path, nil)
		if err != nil {
			return fmt.Errorf("failed to disable user: %v", err)
		}

		fmt.Printf("✓ User '%s' disabled successfully.\n", identifier)

		return nil
	},
}

// userEnableCmd represents the user enable command
var userEnableCmd = &cobra.Command{
	Use:   "enable [user-id or username]",
	Short: "Enable a disabled user account",
	Long:  `Enable a previously disabled user account, allowing them to log in again.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		identifier := args[0]
		path := fmt.Sprintf("/users/%s/enable", identifier)

		_, err := client.Post(ctx, path, nil)
		if err != nil {
			return fmt.Errorf("failed to enable user: %v", err)
		}

		fmt.Printf("✓ User '%s' enabled successfully.\n", identifier)

		return nil
	},
}

// userDeleteCmd represents the user delete command
var userDeleteCmd = &cobra.Command{
	Use:   "delete [user-id or username]",
	Short: "Delete a user account (DANGEROUS)",
	Long: `Permanently delete a user account.

WARNING: This action cannot be undone. The user's data will be permanently removed.

Note: Root users cannot be deleted, only disabled.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		identifier := args[0]

		// Require confirmation
		confirm, _ := cmd.Flags().GetBool("confirm")
		if !confirm {
			fmt.Printf("WARNING: This will permanently delete user '%s'.\n", identifier)
			fmt.Println("To confirm, use --confirm flag.")
			return fmt.Errorf("deletion not confirmed")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		path := fmt.Sprintf("/users/%s", identifier)
		_, err := client.Delete(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to delete user: %v", err)
		}

		fmt.Printf("✓ User '%s' deleted successfully.\n", identifier)

		return nil
	},
}

func init() {
	// Add subcommands to user
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userGetCmd)
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userDisableCmd)
	userCmd.AddCommand(userEnableCmd)
	userCmd.AddCommand(userDeleteCmd)

	// Flags for list command
	userListCmd.Flags().Int("limit", 100, "Maximum number of users to return")
	userListCmd.Flags().Int("offset", 0, "Offset for pagination")

	// Flags for create command
	userCreateCmd.Flags().StringP("username", "u", "", "Username (required)")
	userCreateCmd.Flags().StringP("email", "e", "", "Email address (required)")
	userCreateCmd.Flags().StringP("type", "t", "", "User type: admin or user (required)")
	userCreateCmd.Flags().StringP("password", "p", "", "Password (if not provided, will prompt securely)")

	// Flags for delete command
	userDeleteCmd.Flags().Bool("confirm", false, "Confirm deletion")
}
