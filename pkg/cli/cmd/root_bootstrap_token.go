package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewBootstrapTokenCmd implements `akashic-cli bootstrap token` with two modes:
//
//   - Default (GET):                 fetch the current token
//   - With --regenerate (POST):      rotate the token
//   - With --regenerate --force:     overwrite an existing valid token
func NewBootstrapTokenCmd(ctx *core.CliContext) *cobra.Command {
	var regenerate bool
	var force bool

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Get or regenerate the bootstrap token",
		Long: `Fetch the current bootstrap token, or rotate it.

Without flags: GET /bootstrap/token — prints the current token + its TTL.
With --regenerate: POST /bootstrap/token/regenerate — issues a new token.
With --regenerate --force: overwrites an existing valid token (the server
otherwise refuses to clobber a still-live token without explicit consent).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			if regenerate {
				path := "/bootstrap/token/regenerate"
				if force {
					path += "?force=true"
				}
				resp, body, err := client.SendRequest(http.MethodPost, path, nil)
				if err != nil {
					return cliErr(ExitNetworkError, err)
				}
				if resp.StatusCode == http.StatusForbidden {
					if code, _ := extractServerErrorCode(body); code == "BOOTSTRAP_COMPLETE" {
						fmt.Println("Bootstrap is already complete; token regeneration is not applicable.")
						return nil
					}
				}
				if resp.StatusCode == http.StatusConflict {
					return cliErr(ExitInvalidToken,
						fmt.Errorf("a valid token already exists; pass --force to overwrite"))
				}
				if resp.StatusCode != http.StatusOK {
					return cliErr(ExitServerError,
						fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
				}
				printTokenResponse(body, "Token regenerated")
				return nil
			}

			resp, body, err := client.SendRequest(http.MethodGet, "/bootstrap/token", nil)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode == http.StatusForbidden {
				if code, _ := extractServerErrorCode(body); code == "BOOTSTRAP_COMPLETE" {
					fmt.Println("Bootstrap is already complete; no token exists.")
					return nil
				}
			}
			if resp.StatusCode == http.StatusNotFound {
				return cliErr(ExitInvalidToken,
					fmt.Errorf("no active bootstrap token; is the server in bootstrap mode? "+
						"(check `akashic-cli bootstrap status`)"))
			}
			if resp.StatusCode != http.StatusOK {
				return cliErr(ExitServerError,
					fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
			}
			printTokenResponse(body, "Bootstrap token")
			return nil
		},
	}
	cmd.Flags().BoolVar(&regenerate, "regenerate", false, "rotate the token (POST instead of GET)")
	cmd.Flags().BoolVar(&force, "force", false, "with --regenerate: overwrite an existing valid token")
	return cmd
}

// printTokenResponse extracts token + TTL fields from the standard
// {success, data: {token, ttl_seconds}} envelope and prints them.
func printTokenResponse(body []byte, header string) {
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		fmt.Println(string(body))
		return
	}
	fmt.Println(header + ":")
	if v, ok := env.Data["token"].(string); ok {
		fmt.Printf("  token: %s\n", v)
	}
	if v, ok := env.Data["ttl_seconds"]; ok {
		if secs, ok := v.(float64); ok {
			fmt.Printf("  ttl:   %ds (%s)\n", int(secs), humanDuration(int(secs)))
		}
	}
	if v, ok := env.Data["forced"].(bool); ok && v {
		fmt.Printf("  (forced overwrite)\n")
	}
}
