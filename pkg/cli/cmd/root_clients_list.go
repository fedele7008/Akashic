package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewClientsListCmd implements `akashic-cli clients list`.
//
// Calls GET /clients on the control plane (mTLS-gated, operator-level)
// and prints a tabular summary. Includes both built-in and tenant-
// registered clients — the control plane returns the full row set,
// since the operator is who needs the complete picture.
func NewClientsListCmd(ctx *core.CliContext) *cobra.Command {
	var jsonOut bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered OAuth clients",
		Long: `List every OAuth client registered with this Akashic deployment.

Includes server-managed built-ins (currently just akashic-admin if
AKASHIC_OAUTH_ADMIN_BFF_ENABLED=true) and operator-/tenant-registered
clients (everything created via this CLI or the admin web).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			resp, body, err := client.SendRequest(http.MethodGet, "/clients", nil)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode != http.StatusOK {
				if errCode, msg := extractServerErrorCode(body); errCode != "" {
					switch errCode {
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
					Clients []map[string]any `json:"clients"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				return cliErr(ExitServerError, fmt.Errorf("malformed response: %w", err))
			}

			if jsonOut {
				// Pass-through JSON for scripting. Re-encode to get
				// stable indentation rather than streaming the raw
				// envelope (which would include the success flag and
				// be awkward to | jq).
				out, _ := json.MarshalIndent(env.Data.Clients, "", "  ")
				fmt.Println(string(out))
				return nil
			}

			if len(env.Data.Clients) == 0 {
				fmt.Println("No clients registered.")
				return nil
			}

			// Stable column ordering: built-ins first (lexicographic),
			// then tenant clients (lexicographic). Matches the
			// server's `ORDER BY built_in DESC, created_at DESC` but
			// re-sorted by client_id for human readability since the
			// CLI list is for inspection, not most-recent-first.
			sort.SliceStable(env.Data.Clients, func(i, j int) bool {
				bi, _ := env.Data.Clients[i]["built_in"].(bool)
				bj, _ := env.Data.Clients[j]["built_in"].(bool)
				if bi != bj {
					return bi
				}
				return asString(env.Data.Clients[i]["client_id"]) <
					asString(env.Data.Clients[j]["client_id"])
			})

			// Compute column widths for alignment. Plain text is
			// fine here — operators pipe to less/grep more often
			// than they parse it; --json exists for structured.
			cols := []string{"client_id", "client_type", "name", "built_in", "is_tenant_portal", "redirect_uris"}
			widths := make(map[string]int, len(cols))
			for _, c := range cols {
				widths[c] = len(c)
			}
			for _, row := range env.Data.Clients {
				for _, c := range cols {
					if w := len(asString(row[c])); w > widths[c] {
						widths[c] = w
					}
				}
			}
			// Cap redirect_uris column to keep the line readable;
			// truncate with ellipsis. Operator can --json for full.
			if widths["redirect_uris"] > 60 {
				widths["redirect_uris"] = 60
			}

			// Header.
			parts := make([]string, len(cols))
			for i, c := range cols {
				parts[i] = padRight(c, widths[c])
			}
			fmt.Println(strings.Join(parts, "  "))
			for i, c := range cols {
				parts[i] = strings.Repeat("─", widths[c])
			}
			fmt.Println(strings.Join(parts, "  "))

			// Rows.
			for _, row := range env.Data.Clients {
				vals := make([]string, len(cols))
				for i, c := range cols {
					v := asString(row[c])
					if c == "redirect_uris" && len(v) > widths["redirect_uris"] {
						v = v[:widths["redirect_uris"]-1] + "…"
					}
					vals[i] = padRight(v, widths[c])
				}
				fmt.Println(strings.Join(vals, "  "))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false,
		"output the raw client list as indented JSON (script-friendly)")
	return cmd
}

// asString coerces a JSON-decoded value to its display form.
// `built_in: true` → "true", absent fields → "", nil → "".
func asString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return fmt.Sprintf("%v", v)
}

func padRight(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}
