package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewClientsUpdateCmd implements `akashic-cli clients update <id>`.
//
// Operator-side PATCH /clients/<id> on the control plane.
//
// Initial scope (Phase 9 prep): the per-client token-lifetime
// overrides. These are the testing knobs that let an operator make
// the OAuth refresh-token flow exercise its rotation + replay-
// detection logic in seconds rather than days.
//
// Use case:
//
//	akashic-cli clients update myapp \
//	    --access-token-ttl 30s \
//	    --refresh-sliding-ttl 90s \
//	    --refresh-absolute-ttl 5m
//
// Then exercise /token + /token (refresh_token) at <30s intervals
// and watch the rotation chain land + the absolute window expire.
//
// Clearing an override (revert to inheriting the tenant policy
// ceiling): pass `--clear-access-token-ttl` etc. The set and
// clear forms of the same field are mutually exclusive.
//
// Other client fields (name, redirect_uris, etc.) are NOT YET
// surfaced through this command — use the admin web UI for those.
// We can add `--name`, `--redirect-uri`, ... when there's demand;
// for the testing use case the TTL knobs are what matters.
func NewClientsUpdateCmd(ctx *core.CliContext) *cobra.Command {
	var (
		accessTTL          string
		refreshSlidingTTL  string
		refreshAbsoluteTTL string
		clearAccessTTL     bool
		clearSlidingTTL    bool
		clearAbsoluteTTL   bool
	)

	cmd := &cobra.Command{
		Use:   "update <client-id>",
		Short: "Update an OAuth client's settings (currently: per-client token TTL overrides)",
		Long: `Update settings on a registered OAuth client.

Phase 9 prep: per-client token-lifetime overrides. These are bounded
by the tenant policy's ceilings — passing a value greater than the
ceiling is rejected at the server. Pass durations as Go duration
strings (e.g. 30s, 5m, 2h, 24h).

The "clear" flags revert the corresponding override to NULL, making
the client inherit the tenant ceiling again. Set and clear on the
same field in the same command are mutually exclusive.`,
		Example: `# Aggressive testing: 30-second access tokens, 90-second sliding
# refresh window, 5-minute absolute chain — exercise the full
# rotation + replay-detection dance in under 6 minutes.
  akashic-cli clients update myapp \
      --access-token-ttl 30s \
      --refresh-sliding-ttl 90s \
      --refresh-absolute-ttl 5m

# Revert the access-token override; let it inherit the tenant ceiling.
  akashic-cli clients update myapp --clear-access-token-ttl`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientID := strings.TrimSpace(args[0])
			if clientID == "" {
				return cliErr(ExitValidation, fmt.Errorf("client-id is required"))
			}

			// Parse duration flags into seconds. Empty string means
			// "flag not supplied"; we send only the fields the user
			// actually touched so the server's PATCH semantics
			// preserve untouched values.
			payload := map[string]any{}

			if accessTTL != "" && clearAccessTTL {
				return cliErr(ExitValidation,
					fmt.Errorf("--access-token-ttl and --clear-access-token-ttl are mutually exclusive"))
			}
			if refreshSlidingTTL != "" && clearSlidingTTL {
				return cliErr(ExitValidation,
					fmt.Errorf("--refresh-sliding-ttl and --clear-refresh-sliding-ttl are mutually exclusive"))
			}
			if refreshAbsoluteTTL != "" && clearAbsoluteTTL {
				return cliErr(ExitValidation,
					fmt.Errorf("--refresh-absolute-ttl and --clear-refresh-absolute-ttl are mutually exclusive"))
			}

			if accessTTL != "" {
				secs, err := parseTTLToSeconds(accessTTL, "--access-token-ttl")
				if err != nil {
					return err
				}
				payload["access_token_ttl_seconds_override"] = secs
			}
			if clearAccessTTL {
				payload["clear_access_token_ttl_override"] = true
			}
			if refreshSlidingTTL != "" {
				secs, err := parseTTLToSeconds(refreshSlidingTTL, "--refresh-sliding-ttl")
				if err != nil {
					return err
				}
				payload["refresh_token_sliding_ttl_seconds_override"] = secs
			}
			if clearSlidingTTL {
				payload["clear_refresh_token_sliding_ttl_override"] = true
			}
			if refreshAbsoluteTTL != "" {
				secs, err := parseTTLToSeconds(refreshAbsoluteTTL, "--refresh-absolute-ttl")
				if err != nil {
					return err
				}
				payload["refresh_token_absolute_ttl_seconds_override"] = secs
			}
			if clearAbsoluteTTL {
				payload["clear_refresh_token_absolute_ttl_override"] = true
			}

			if len(payload) == 0 {
				return cliErr(ExitValidation,
					fmt.Errorf("supply at least one of --access-token-ttl, --refresh-sliding-ttl, --refresh-absolute-ttl, --clear-access-token-ttl, --clear-refresh-sliding-ttl, --clear-refresh-absolute-ttl"))
			}

			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			resp, body, err := client.SendRequest(http.MethodPatch, "/clients/"+clientID, payload)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode != http.StatusOK {
				if errCode, msg := extractServerErrorCode(body); errCode != "" {
					switch errCode {
					case "VALIDATION_FAILED":
						return cliErr(ExitValidation, fmt.Errorf("%s", msg))
					case "CLIENT_NOT_FOUND":
						return cliErr(ExitValidation, fmt.Errorf("no such client_id: %s", clientID))
					case "BUILTIN_IMMUTABLE":
						return cliErr(ExitValidation,
							fmt.Errorf("built-in clients are server-managed and cannot be edited via the API"))
					}
				}
				return cliErr(ExitServerError,
					fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
			}

			var env struct {
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				return cliErr(ExitServerError, fmt.Errorf("malformed response: %w", err))
			}

			fmt.Println("✓ Client updated")
			fmt.Printf("  client_id:                %v\n", env.Data["client_id"])
			fmt.Printf("  access_ttl_override:      %v\n",
				renderOptionalSeconds(env.Data["access_token_ttl_seconds_override"]))
			fmt.Printf("  refresh_sliding_override: %v\n",
				renderOptionalSeconds(env.Data["refresh_token_sliding_ttl_seconds_override"]))
			fmt.Printf("  refresh_absolute_override:%v\n",
				renderOptionalSeconds(env.Data["refresh_token_absolute_ttl_seconds_override"]))
			return nil
		},
	}

	cmd.Flags().StringVar(&accessTTL, "access-token-ttl", "",
		"per-client access-token TTL override (e.g. 30s, 5m, 1h). Capped by tenant ceiling.")
	cmd.Flags().StringVar(&refreshSlidingTTL, "refresh-sliding-ttl", "",
		"per-client refresh-token sliding TTL override (e.g. 90s, 30m, 7d).")
	cmd.Flags().StringVar(&refreshAbsoluteTTL, "refresh-absolute-ttl", "",
		"per-client refresh-token absolute (chain) TTL override (e.g. 5m, 6h, 30d).")
	cmd.Flags().BoolVar(&clearAccessTTL, "clear-access-token-ttl", false,
		"clear the access-token TTL override (revert to tenant ceiling)")
	cmd.Flags().BoolVar(&clearSlidingTTL, "clear-refresh-sliding-ttl", false,
		"clear the refresh-token sliding TTL override (revert to tenant ceiling)")
	cmd.Flags().BoolVar(&clearAbsoluteTTL, "clear-refresh-absolute-ttl", false,
		"clear the refresh-token absolute TTL override (revert to tenant ceiling)")
	return cmd
}

// parseTTLToSeconds parses a Go duration string (30s, 5m, 1h, etc.)
// into integer seconds. Rejects negative or zero durations with a
// CLI-friendly error rather than hitting the server validator —
// catches the typo at the user's terminal.
func parseTTLToSeconds(raw, flagName string) (int, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, cliErr(ExitValidation,
			fmt.Errorf("%s: invalid duration %q (try 30s, 5m, 1h)", flagName, raw))
	}
	if d <= 0 {
		return 0, cliErr(ExitValidation,
			fmt.Errorf("%s: duration must be positive, got %s", flagName, d))
	}
	secs := int(d / time.Second)
	if secs == 0 {
		// Sub-second values round to zero — disallow.
		return 0, cliErr(ExitValidation,
			fmt.Errorf("%s: minimum resolution is 1 second; got %s", flagName, d))
	}
	return secs, nil
}

// renderOptionalSeconds prints a TTL-override field for human eyes:
// nil/missing renders as "<inherited>", a number renders as the
// decimal seconds + the duration form for legibility.
func renderOptionalSeconds(v any) string {
	if v == nil {
		return "<inherited from tenant ceiling>"
	}
	// JSON numbers come back as float64; coerce.
	var secs int
	switch n := v.(type) {
	case float64:
		secs = int(n)
	case int:
		secs = n
	default:
		return fmt.Sprintf("%v", v)
	}
	return fmt.Sprintf("%d seconds (%s)", secs, time.Duration(secs)*time.Second)
}
