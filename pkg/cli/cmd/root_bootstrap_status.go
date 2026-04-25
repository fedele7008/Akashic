package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewBootstrapStatusCmd implements `akashic-cli bootstrap status`.
// GET /bootstrap/status — reachable in both modes (the endpoint itself
// answers "are you in bootstrap mode?"), so we don't pre-filter on state.
func NewBootstrapStatusCmd(ctx *core.CliContext) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current bootstrap status",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			client, name, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}
			resp, body, err := client.SendRequest(http.MethodGet, "/bootstrap/status", nil)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode != http.StatusOK {
				return cliErr(ExitServerError,
					fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
			}

			var env struct {
				Success bool                   `json:"success"`
				Data    map[string]any         `json:"data"`
				Error   map[string]any         `json:"error"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				return cliErr(ExitServerError, fmt.Errorf("malformed server response: %w", err))
			}

			fmt.Printf("Bootstrap status (profile %q):\n", name)
			if v, ok := env.Data["is_complete"].(bool); ok {
				fmt.Printf("  is_complete: %v\n", v)
			}
			if v, ok := env.Data["completed_at"]; ok {
				fmt.Printf("  completed_at: %v\n", v)
			}
			if v, ok := env.Data["root_user_id"]; ok {
				fmt.Printf("  root_user_id: %v\n", v)
			}
			if v, ok := env.Data["token_exists"]; ok {
				fmt.Printf("  token_exists: %v\n", v)
			}
			if v, ok := env.Data["token_ttl_seconds"]; ok {
				if secs, ok := v.(float64); ok {
					fmt.Printf("  token_ttl: %ds (%s)\n", int(secs), humanDuration(int(secs)))
				}
			}
			return nil
		},
	}
}

// cliErr wraps an error with a structured exit code so the shell can
// branch on failure type. Returned via cobra's RunE; the root cmd's
// SilenceUsage/SilenceErrors are toggled on (set up below).
func cliErr(code int, err error) error {
	return &exitError{code: code, err: err}
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }

// HandleExitError extracts the structured exit code from a returned error.
// Called from main() to map the error to os.Exit(N).
func HandleExitError(err error) {
	if err == nil {
		return
	}
	if ex, ok := err.(*exitError); ok {
		fmt.Fprintln(os.Stderr, "Error:", ex.err)
		os.Exit(ex.code)
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}

// humanDuration formats a positive seconds value as Xh Ym Zs, dropping
// zero leading components.
func humanDuration(seconds int) string {
	if seconds <= 0 {
		return "0s"
	}
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// Exit codes used by the bootstrap command family. Distinct codes let
// shell scripts branch on failure type without parsing error text.
const (
	ExitOK              = 0
	_                   = 1 // reserved for "generic" cobra failures
	ExitInvalidToken    = 2
	ExitValidation      = 3
	ExitRateLimit       = 4
	ExitConfigError     = 5
	ExitNetworkError    = 6
	ExitServerError     = 7
)
