package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewClientsCreateCmd implements `akashic-cli clients create`.
//
// Posts to the control plane's /clients endpoint. Returns the new
// client's ID and (for WEB clients) the plaintext client_secret —
// shown ONCE because only its bcrypt hash persists on the server.
//
// Designed to also serve as the "post-bootstrap initialization step"
// described in the clients-registration roadmap: the operator runs
// this once after `bootstrap create-root` to register their tenant's
// primary portal.
func NewClientsCreateCmd(ctx *core.CliContext) *cobra.Command {
	var (
		name              string
		clientType        string
		redirectURI       string
		description       string
		homepageURL       string
		noPKCE            bool
		saveCredentialsTo string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Register a new OAuth client (WEB or SPA)",
		Long: `Register a new OAuth client_service in Akashic.

The --type flag is required and must be one of:
  WEB — confidential, server-side. Returns a client_secret you MUST
        capture immediately (only its bcrypt hash is stored). PKCE is
        optional but recommended; pass --no-pkce to disable.
  SPA — public, browser-only or native. No secret returned; PKCE is
        required (--no-pkce is rejected for SPA).

After this command succeeds, the printed client_id (and, for WEB,
client_secret) should be configured into the application that will use
it for OAuth flows. For your tenant's primary portal, this is typically
done via the portal's environment configuration.`,
		Example: `# Tenant portal with backend (BFF)
  akashic-cli clients create --type WEB \
      --name "Acme Portal" \
      --redirect-uri https://acme.com/api/auth/callback

# SPA / public client (PKCE forced on)
  akashic-cli clients create --type SPA \
      --name "Acme SPA" \
      --redirect-uri https://acme.com/callback`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate locally before round-tripping to the server,
			// so common mistakes get a sharp message rather than a
			// raw 400 from the control plane.
			if name == "" {
				return cliErr(ExitValidation, fmt.Errorf("--name is required"))
			}
			if redirectURI == "" {
				return cliErr(ExitValidation, fmt.Errorf("--redirect-uri is required"))
			}
			ct := strings.ToUpper(strings.TrimSpace(clientType))
			switch ct {
			case "WEB", "SPA":
				// ok
			case "":
				return cliErr(ExitValidation,
					fmt.Errorf("--type is required: WEB (server-side, gets a client_secret) or SPA (browser/native, PKCE-only)"))
			default:
				return cliErr(ExitValidation,
					fmt.Errorf("--type must be WEB or SPA, got %q", clientType))
			}
			if ct == "SPA" && noPKCE {
				return cliErr(ExitValidation,
					fmt.Errorf("--no-pkce is incompatible with --type SPA: public clients MUST use PKCE"))
			}

			profile, _ := cmd.Flags().GetString("profile")
			client, _, err := core.NewAkashicControlClient(ctx, profile)
			if err != nil {
				return cliErr(ExitConfigError, err)
			}

			payload := map[string]any{
				"name":          name,
				"client_type":   ct,
				"redirect_uris": redirectURI,
			}
			if description != "" {
				payload["description"] = description
			}
			if homepageURL != "" {
				payload["homepage_url"] = homepageURL
			}
			// Only send require_pkce when WEB + operator explicitly
			// disabled it. SPA always-true is enforced server-side
			// regardless of what we send; omitting keeps the request
			// minimal and the server log of operator intent honest.
			if ct == "WEB" && noPKCE {
				falseVal := false
				payload["require_pkce"] = &falseVal
			}

			resp, body, err := client.SendRequest(http.MethodPost, "/clients", payload)
			if err != nil {
				return cliErr(ExitNetworkError, err)
			}
			if resp.StatusCode != http.StatusCreated {
				if errCode, msg := extractServerErrorCode(body); errCode != "" {
					switch errCode {
					case "VALIDATION_FAILED":
						return cliErr(ExitValidation, fmt.Errorf("%s", msg))
					case "DB_NOT_READY":
						return cliErr(ExitServerError,
							fmt.Errorf("server: database not yet ready; retry shortly"))
					case "MTLS_REQUIRED", "CLIENT_NOT_ALLOWED":
						return cliErr(ExitConfigError, fmt.Errorf("%s", msg))
					}
				}
				return cliErr(ExitServerError,
					fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body)))
			}

			// Success: print a useful summary. WEB gets a "save the
			// secret NOW" warning since this is the only chance.
			var env struct {
				Data struct {
					Client       map[string]any `json:"client"`
					ClientSecret string         `json:"client_secret"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				return cliErr(ExitServerError, fmt.Errorf("malformed response: %w", err))
			}

			fmt.Println("✓ OAuth client registered successfully")
			for _, key := range []string{"client_id", "name", "client_type", "redirect_uris", "require_pkce", "public", "created_at"} {
				if v, ok := env.Data.Client[key]; ok {
					fmt.Printf("  %-15s %v\n", key+":", v)
				}
			}
			if env.Data.ClientSecret != "" {
				fmt.Println()
				fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
				fmt.Println("  │  client_secret (shown ONCE — copy it now):                  │")
				fmt.Println("  ├─────────────────────────────────────────────────────────────┤")
				fmt.Printf("  │  %-58s │\n", env.Data.ClientSecret)
				fmt.Println("  └─────────────────────────────────────────────────────────────┘")
				fmt.Println()
				fmt.Println("  Only its bcrypt hash is persisted server-side. You cannot")
				fmt.Println("  recover this secret later — if lost, rotate via the API.")
			} else {
				fmt.Println()
				fmt.Println("  No client_secret — this is a public (SPA) client.")
				fmt.Println("  PKCE replaces the shared secret on every authorization.")
			}

			// Optional: write credentials to a file for sample-style
			// dynamic credential consumption. Real-tenant deployments
			// generally DON'T use this — they hardcode the printed
			// secret into their portal's .env or secrets manager and
			// move on. This flag exists for the in-stack-samples case
			// where the sample container is already running when the
			// operator generates credentials, and we need a path the
			// sample can read at first-OAuth-request time.
			//
			// File contents: minimal JSON `{client_id, client_secret}`.
			// Atomic write (.tmp + rename) so a partially-written file
			// is never visible to a reader. Mode 0600 so adjacent
			// processes on the host can't slurp it.
			if saveCredentialsTo != "" {
				clientID, _ := env.Data.Client["client_id"].(string)
				if clientID == "" {
					return cliErr(ExitServerError,
						fmt.Errorf("server response missing client_id; cannot write credentials file"))
				}
				if err := writeCredentialsFile(saveCredentialsTo, clientID, env.Data.ClientSecret); err != nil {
					return cliErr(ExitServerError,
						fmt.Errorf("write credentials file: %w", err))
				}
				fmt.Println()
				fmt.Printf("  Credentials JSON written to: %s\n", saveCredentialsTo)
				fmt.Println("  Sample-side OAuth code reads this file at request time;")
				fmt.Println("  no container restart needed — next /authorize will pick it up.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "human-readable client name (required)")
	cmd.Flags().StringVar(&clientType, "type", "",
		"client type: WEB (server-side, gets client_secret) or SPA (browser/native, PKCE-only) (required)")
	cmd.Flags().StringVar(&redirectURI, "redirect-uri", "",
		"OAuth redirect_uri (required; comma-separate multiple values)")
	cmd.Flags().StringVar(&description, "description", "", "free-form description shown on consent screens")
	cmd.Flags().StringVar(&homepageURL, "homepage-url", "", "client's homepage shown on consent screens")
	cmd.Flags().BoolVar(&noPKCE, "no-pkce", false,
		"WEB clients only: disable the PKCE requirement (default: required). Rejected for SPA.")
	cmd.Flags().StringVar(&saveCredentialsTo, "save-credentials-to", "",
		"path to write the client_id+client_secret as JSON (mode 0600). Used by in-stack samples that read credentials at runtime; real-tenant deployments typically hardcode the printed secret into .env instead.")
	return cmd
}

// writeCredentialsFile atomically writes a minimal credentials JSON to
// path. Creates the parent directory if needed (mode 0700 — secrets
// directory). The file itself is mode 0600.
//
// JSON shape: `{"client_id": "...", "client_secret": "..."}`. Other
// metadata (redirect_uri, name) lives in the same /clients response
// the operator already sees printed; not duplicated into the file.
func writeCredentialsFile(path, clientID, clientSecret string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}
	body, err := json.MarshalIndent(map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
