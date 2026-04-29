package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewClientsDeleteCmd implements `akashic-cli clients delete <id>`.
//
// Calls DELETE /clients/<id> on the control plane. Built-ins are
// rejected server-side; tenant-registered rows are removed.
//
// Confirmation prompt by default (operator must type the client_id
// to proceed) — `--yes` skips it for scripted use.
func NewClientsDeleteCmd(ctx *core.CliContext) *cobra.Command {
	var skipConfirm bool

	cmd := &cobra.Command{
		Use:   "delete <client_id>",
		Short: "Delete an OAuth client by client_id",
		Long: `Delete a registered OAuth client.

Built-in clients (currently just akashic-admin if AKASHIC_OAUTH_ADMIN_BFF_ENABLED=true)
cannot be deleted via this command — toggle the env var instead.
Tenant-registered clients are removed permanently; any tokens minted
for that client_id will fail next /authorize.`,
		Example: `# Confirmation prompt
  akashic-cli clients delete tc-abc1234567

# Scripted (skip confirm)
  akashic-cli clients delete tc-abc1234567 --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID := strings.TrimSpace(args[0])
			if clientID == "" {
				return cliErr(ExitValidation, fmt.Errorf("client_id is required"))
			}

			if !skipConfirm {
				fmt.Printf("About to delete client %q. Type the client_id to confirm: ", clientID)
				reader := bufio.NewReader(os.Stdin)
				typed, _ := reader.ReadString('\n')
				if strings.TrimSpace(typed) != clientID {
					return cliErr(ExitValidation,
						fmt.Errorf("confirmation mismatch — aborted"))
				}
			}

			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			resp, body, err := client.SendRequest(http.MethodDelete, "/clients/"+clientID, nil)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode != http.StatusOK {
				if errCode, msg := extractServerErrorCode(body); errCode != "" {
					switch errCode {
					case "CLIENT_NOT_FOUND":
						return cliErr(ExitValidation,
							fmt.Errorf("no client with id %q", clientID))
					case "BUILTIN_IMMUTABLE":
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

			fmt.Printf("✓ Client %s deleted.\n", clientID)
			return nil
		},
	}

	cmd.Flags().BoolVar(&skipConfirm, "yes", false,
		"skip the type-the-id confirmation prompt (for scripted use)")
	return cmd
}
