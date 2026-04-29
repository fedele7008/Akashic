package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewClientsRotateSecretCmd implements
// `akashic-cli clients rotate-secret <client_id>`.
//
// Calls POST /clients/<id>/rotate-secret on the control plane and
// prints the freshly-issued plaintext secret in the same shown-once
// box format as `clients create`. Old secret is immediately
// invalid — tokens already issued for the client_id remain valid
// until expiry, but new /token calls with the old secret get 401.
func NewClientsRotateSecretCmd(ctx *core.CliContext) *cobra.Command {
	var saveCredentialsTo string

	cmd := &cobra.Command{
		Use:   "rotate-secret <client_id>",
		Short: "Rotate a confidential (WEB) client's secret",
		Long: `Issue a fresh client_secret for an existing WEB client and
invalidate the old one.

Rejected for:
  - Built-in clients (server-managed; secrets rotate via container restart)
  - Public/SPA clients (no shared secret to rotate; PKCE replaces it)

The new plaintext secret is printed ONCE; copy it immediately into
your portal's secret store. If lost, run rotate-secret again to
replace it.`,
		Example: `# Print the new secret to stdout
  akashic-cli clients rotate-secret tc-abc1234567

# Update an in-stack sample's credentials file in one step
  akashic-cli clients rotate-secret tc-abc1234567 \
      --save-credentials-to .secrets/sample/nextjs.json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID := strings.TrimSpace(args[0])
			if clientID == "" {
				return cliErr(ExitValidation, fmt.Errorf("client_id is required"))
			}

			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			resp, body, err := client.SendRequest(http.MethodPost,
				"/clients/"+clientID+"/rotate-secret", nil)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode != http.StatusOK {
				if errCode, msg := extractServerErrorCode(body); errCode != "" {
					switch errCode {
					case "CLIENT_NOT_FOUND":
						return cliErr(ExitValidation,
							fmt.Errorf("no client with id %q", clientID))
					case "BUILTIN_IMMUTABLE", "PUBLIC_CLIENT_NO_SECRET":
						return cliErr(ExitValidation, fmt.Errorf("%s", msg))
					case "BOOTSTRAP_INCOMPLETE":
						return cliErr(ExitValidation,
							fmt.Errorf("bootstrap is not yet complete; run `akashic-cli bootstrap create-root` first"))
					case "MTLS_REQUIRED", "CLIENT_NOT_ALLOWED":
						return cliErr(ExitConfigError, fmt.Errorf("%s", msg))
					}
				}
				return cliErr(ExitServerError,
					fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
			}

			var env struct {
				Data struct {
					ClientID     string `json:"client_id"`
					ClientSecret string `json:"client_secret"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				return cliErr(ExitServerError, fmt.Errorf("malformed response: %w", err))
			}

			fmt.Println("✓ Client secret rotated successfully")
			fmt.Printf("  client_id:     %s\n", env.Data.ClientID)
			fmt.Println()
			fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
			fmt.Println("  │  new client_secret (shown ONCE — copy it now):              │")
			fmt.Println("  ├─────────────────────────────────────────────────────────────┤")
			fmt.Printf("  │  %-58s │\n", env.Data.ClientSecret)
			fmt.Println("  └─────────────────────────────────────────────────────────────┘")
			fmt.Println()
			fmt.Println("  Old secret is invalid as of now. Update your portal's")
			fmt.Println("  secret store before its next OAuth flow.")

			if saveCredentialsTo != "" {
				if err := writeCredentialsFile(saveCredentialsTo, env.Data.ClientID, env.Data.ClientSecret); err != nil {
					return cliErr(ExitServerError,
						fmt.Errorf("write credentials file: %w", err))
				}
				fmt.Println()
				fmt.Printf("  Credentials JSON written to: %s\n", saveCredentialsTo)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&saveCredentialsTo, "save-credentials-to", "",
		"path to write the rotated credentials as JSON (mode 0600). Used by in-stack samples.")
	return cmd
}
