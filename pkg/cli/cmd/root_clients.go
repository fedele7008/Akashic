package cmd

import (
	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// NewClientsCmd is the parent of `akashic-cli clients ...`. Subcommands
// talk to the control plane's operator-side `/clients` endpoint(s) using
// the active configure profile (or --profile <name>).
//
// This is the operator surface for OAuth client management — used both
// for the post-bootstrap "register your tenant portal" initialization
// step and for ad-hoc admin client management thereafter. The parallel
// surface for tenant developers (registering their own integrations
// via the <akashic-clients> widget) is the API server's bearer-
// authenticated /clients API; both write to the same client_services
// table.
func NewClientsCmd(ctx *core.CliContext) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clients",
		Short: "Manage OAuth client registrations (operator-side)",
		Long: `Manage OAuth client registrations on the Akashic control plane.

Use this command after bootstrap to register your tenant's primary portal
("first-hand portal") with Akashic. The choice of WEB vs SPA determines
whether the resulting client is confidential (has a client_secret) or
public (PKCE-only):

  WEB — confidential, server-side. The tenant's portal has a backend
        (BFF/Backend-for-Frontend) that can hold a client_secret in a
        secure store. PKCE is supported and recommended but optional;
        the secret + bcrypt verification is the credential.
  SPA — public, browser/native. The tenant's portal runs entirely in
        the browser (or native client) with no secure place to keep a
        secret. PKCE is REQUIRED and replaces the missing shared secret.

Don't read "WEB" as "anything browser-facing" — a SPA also runs in a
browser. The disambiguating question is "does the app have a server you
control that can store secrets?" Yes → WEB. No → SPA.

A profile (added via 'akashic-cli configure add') is required so the CLI
knows where to connect and how to authenticate over mTLS.`,
		Example: `# Register a server-side portal (BFF) — gets a client_secret back
  akashic-cli clients create --type WEB \
      --name "Acme Portal" \
      --redirect-uri https://acme.com/api/auth/callback

# Register a browser-only SPA — no secret, PKCE forced on
  akashic-cli clients create --type SPA \
      --name "Acme SPA" \
      --redirect-uri https://acme.com/callback`,
	}
	cmd.PersistentFlags().String("profile", "", "configure profile to use (default: active)")
	cmd.AddCommand(NewClientsCreateCmd(ctx))
	cmd.AddCommand(NewClientsListCmd(ctx))
	cmd.AddCommand(NewClientsDeleteCmd(ctx))
	cmd.AddCommand(NewClientsRotateSecretCmd(ctx))
	return cmd
}
