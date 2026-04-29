package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewBootstrapCreateRootCmd implements `akashic-cli bootstrap create-root`.
//
// The ergonomic version: with just --username and --email, the CLI auto-
// fetches the bootstrap token from the server (saving the operator a
// copy-paste step) and prompts interactively for the password (no echo,
// twice for confirmation). Power users can pass --token / --password-stdin
// for scripted invocations.
func NewBootstrapCreateRootCmd(ctx *core.CliContext) *cobra.Command {
	var (
		username      string
		email         string
		password      string
		passwordStdin bool
		token         string
	)

	cmd := &cobra.Command{
		Use:   "create-root",
		Short: "Create the root user (one-time bootstrap action)",
		Long: `Create the very first root user for a fresh Akashic deployment.

The bootstrap token is auto-fetched from the server unless --token is given.
The password is prompted interactively unless --password-stdin or --password
is given.

After this command succeeds, the bootstrap endpoints are permanently closed
on the server. Further admin-user creation goes through the regular admin
plane.`,
		Example: `# Interactive — easiest path
  akashic-cli bootstrap create-root --username admin --email admin@example.com

# Scripted — pipe password from stdin
  echo 'StrongP@ssword!' | akashic-cli bootstrap create-root \
      --username admin --email admin@example.com --password-stdin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if username == "" {
				return cliErr(ExitValidation, fmt.Errorf("--username is required"))
			}
			if email == "" {
				return cliErr(ExitValidation, fmt.Errorf("--email is required"))
			}

			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			// Resolve token: explicit --token wins, otherwise fetch.
			if token == "" {
				resp, body, err := client.SendRequest(http.MethodGet, "/bootstrap/token", nil)
				if err != nil {
					return cliErr(ExitNetworkError, err)
				}
				// Walk likely failure cases in priority order so the user
				// gets the most actionable message rather than a raw 4xx.
				if resp.StatusCode == http.StatusForbidden {
					if code, _ := extractServerErrorCode(body); code == "BOOTSTRAP_COMPLETE" {
						fmt.Println("Bootstrap is already complete; nothing to do.")
						return nil
					}
				}
				if resp.StatusCode == http.StatusNotFound {
					return cliErr(ExitInvalidToken,
						fmt.Errorf("no active bootstrap token; the server may not be in bootstrap mode "+
							"(check `akashic-cli bootstrap status`)"))
				}
				if resp.StatusCode != http.StatusOK {
					return cliErr(ExitServerError,
						fmt.Errorf("fetch token: server returned %d: %s", resp.StatusCode, string(body)))
				}
				var env struct {
					Data struct {
						Token string `json:"token"`
					} `json:"data"`
				}
				if err := json.Unmarshal(body, &env); err != nil {
					return cliErr(ExitServerError, fmt.Errorf("malformed token response: %w", err))
				}
				token = env.Data.Token
			}

			// Resolve password: --password (literal, NOT recommended) wins;
			// otherwise --password-stdin reads one line; otherwise interactive
			// prompt with confirmation.
			if password == "" {
				pw, err := core.PromptPassword(core.PromptPasswordOpts{
					Prompt:        "Password: ",
					ConfirmPrompt: "Confirm:  ",
					StdinSource:   passwordStdin,
				})
				if err != nil {
					return cliErr(ExitValidation, err)
				}
				password = pw
			}

			// Submit to the server.
			payload := map[string]any{
				"token":    token,
				"username": username,
				"email":    email,
				"password": password,
			}
			resp, body, err := client.SendRequest(http.MethodPost, "/bootstrap/root", payload)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}

			// Map known server error codes to specific exit codes so shell
			// scripts can branch on failure type.
			if resp.StatusCode == http.StatusTooManyRequests {
				return cliErr(ExitRateLimit, fmt.Errorf("server: rate-limited; %s", extractServerMessage(body)))
			}
			if resp.StatusCode != http.StatusCreated {
				if errCode, msg := extractServerErrorCode(body); errCode != "" {
					switch errCode {
					case "INVALID_TOKEN":
						return cliErr(ExitInvalidToken, fmt.Errorf("%s", msg))
					case "PASSWORD_POLICY_VIOLATION", "VALIDATION_FAILED":
						return cliErr(ExitValidation, fmt.Errorf("%s", msg))
					case "BOOTSTRAP_COMPLETE":
						// Already done -- treat as success-equivalent: the
						// system is in the desired state; print and exit 0.
						fmt.Println("Bootstrap is already complete; nothing to do.")
						return nil
					case "MTLS_REQUIRED", "CLIENT_NOT_ALLOWED":
						return cliErr(ExitConfigError, fmt.Errorf("%s", msg))
					}
				}
				return cliErr(ExitServerError,
					fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
			}

			// Success: print the created-user summary.
			var env struct {
				Data struct {
					User map[string]any `json:"user"`
				} `json:"data"`
			}
			_ = json.Unmarshal(body, &env)
			fmt.Println("✓ Root user created successfully")
			for _, key := range []string{"uid", "username", "email", "ldap_dn", "user_type", "created_at"} {
				if v, ok := env.Data.User[key]; ok {
					fmt.Printf("  %-10s %v\n", key+":", v)
				}
			}
			// Post-bootstrap initialization hint. Bootstrap by itself
			// only creates the root user; the deployment isn't usable
			// until at least one OAuth client is registered (the
			// tenant's primary portal). Print the exact command so
			// the operator doesn't have to tab-discover the args.
			fmt.Println()
			fmt.Println("Next step: register your tenant portal as an OAuth client.")
			fmt.Println()
			fmt.Println("  WEB (server-side / BFF — gets a client_secret):")
			fmt.Println("    akashic-cli clients create --type WEB \\")
			fmt.Println("        --name \"My Portal\" \\")
			fmt.Println("        --redirect-uri https://<your-portal-domain>/api/auth/callback")
			fmt.Println()
			fmt.Println("  SPA (browser/native — PKCE-only, no secret):")
			fmt.Println("    akashic-cli clients create --type SPA \\")
			fmt.Println("        --name \"My SPA\" \\")
			fmt.Println("        --redirect-uri https://<your-spa-domain>/callback")
			fmt.Println()
			fmt.Println("  Or via the admin web console at https://admin.<your-domain>/")
			fmt.Println()
			fmt.Println("  Tip: pass --save-credentials-to <path> to drop the issued")
			fmt.Println("  client_id+client_secret into a JSON file (used by in-stack")
			fmt.Println("  samples to read credentials at runtime).")
			return nil
		},
	}

	cmd.Flags().StringVar(&username, "username", "", "username for the new root user (required)")
	cmd.Flags().StringVar(&email, "email", "", "email for the new root user (required)")
	cmd.Flags().StringVar(&password, "password", "",
		"password (NOT recommended -- exposed via shell history; prefer interactive or --password-stdin)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read password from stdin (for scripted invocations)")
	cmd.Flags().StringVar(&token, "token", "", "explicit bootstrap token (default: fetched from server)")
	return cmd
}

// extractServerErrorCode pulls {error: {code, message}} out of the
// standard error envelope.
func extractServerErrorCode(body []byte) (code, message string) {
	var env struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "", strings.TrimSpace(string(body))
	}
	return env.Error.Code, env.Error.Message
}

// extractServerMessage pulls just the message out of the error envelope.
func extractServerMessage(body []byte) string {
	_, msg := extractServerErrorCode(body)
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}
	return msg
}
