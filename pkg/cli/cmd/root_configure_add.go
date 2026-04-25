package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"akashic/akashic/pkg/cli/core"

	"github.com/spf13/cobra"
)

// removeIfExists deletes a path if it exists, ignoring "not found" errors.
// Used before creating a symlink at a path that may currently be a regular
// file from a previous `configure add` (without --link).
func removeIfExists(path string) error {
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// symlinkAbs creates a symlink from `link` → `target`, resolving target
// to an absolute path so the link doesn't break when CWD changes.
func symlinkAbs(target, link string) error {
	abs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		return err
	}
	return os.Symlink(abs, link)
}

// NewConfigureAddCmd implements `akashic-cli configure add`.
//
// Adds (or overwrites) a named profile, copying the supplied cert files
// into ~/.akashic/certs/<name>/ for stable storage. The default behavior
// COPIES the certs (so moving the project tree later doesn't break the
// CLI); --link symlinks instead, useful if operators want the CLI to
// always pick up the latest cert from a Vault-Agent-managed location.
//
// On first add, the new profile is automatically set as active.
func NewConfigureAddCmd(ctx *core.CliContext) *cobra.Command {
	var (
		name       string
		controlURL string
		caCert     string
		clientCert string
		clientKey  string
		link       bool
		setActive  bool
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new connection profile",
		Long: `Add a new connection profile to ~/.akashic/config.yaml.

The supplied cert files are copied into ~/.akashic/certs/<name>/ with
strict permissions (key=0600, certs=0644). If --link is passed, symlinks
are created instead -- useful when the source files are managed by Vault
Agent and you want the CLI to pick up rotations automatically.`,
		Example: `# First-time setup, becomes active profile
  akashic-cli configure add \
      --name default \
      --control-url https://127.0.0.1:8081 \
      --ca-cert ./certs/akashic/mtls-ca.crt \
      --client-cert ./certs/akashic-cli/akashic-ctrl-client.crt \
      --client-key ./certs/akashic-cli/akashic-ctrl-client.key

# Add a second profile (does NOT become active unless --set-active)
  akashic-cli configure add --name prod --control-url https://akashic.example.com:8081 ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if controlURL == "" {
				return fmt.Errorf("--control-url is required")
			}
			for _, p := range []struct {
				flag, val, label string
			}{
				{"--ca-cert", caCert, "CA cert"},
				{"--client-cert", clientCert, "client cert"},
				{"--client-key", clientKey, "client key"},
			} {
				if p.val == "" {
					return fmt.Errorf("%s is required", p.flag)
				}
			}

			// Expand ~ in user-supplied paths.
			caCert, _ = core.ExpandHome(caCert)
			clientCert, _ = core.ExpandHome(clientCert)
			clientKey, _ = core.ExpandHome(clientKey)

			cfg, err := core.LoadProfileConfig()
			if err != nil {
				return err
			}

			certDir, err := core.ProfileCertsDir(name)
			if err != nil {
				return err
			}

			dstCA := filepath.Join(certDir, "ca.crt")
			dstCert := filepath.Join(certDir, "client.crt")
			dstKey := filepath.Join(certDir, "client.key")

			if link {
				// Symlink: make the destination point at the source.
				// Useful when Vault Agent rotates the source in place.
				for _, l := range [][2]string{
					{caCert, dstCA},
					{clientCert, dstCert},
					{clientKey, dstKey},
				} {
					_ = removeIfExists(l[1])
					if err := symlinkAbs(l[0], l[1]); err != nil {
						return fmt.Errorf("symlink %s -> %s: %w", l[1], l[0], err)
					}
				}
			} else {
				if err := core.CopyFileSecure(caCert, dstCA, 0o644); err != nil {
					return fmt.Errorf("copy CA cert: %w", err)
				}
				if err := core.CopyFileSecure(clientCert, dstCert, 0o644); err != nil {
					return fmt.Errorf("copy client cert: %w", err)
				}
				if err := core.CopyFileSecure(clientKey, dstKey, 0o600); err != nil {
					return fmt.Errorf("copy client key: %w", err)
				}
			}

			cfg.Profiles[name] = &core.Profile{
				ControlURL:     controlURL,
				CACertPath:     dstCA,
				ClientCertPath: dstCert,
				ClientKeyPath:  dstKey,
			}
			// First-ever profile auto-activates; subsequent profiles only
			// become active when --set-active is passed.
			if cfg.ActiveProfile == "" || setActive {
				cfg.ActiveProfile = name
			}
			if err := core.SaveProfileConfig(cfg); err != nil {
				return err
			}

			fmt.Printf("✓ Profile %q saved\n", name)
			fmt.Printf("  control_url: %s\n", controlURL)
			fmt.Printf("  ca_cert:     %s\n", dstCA)
			fmt.Printf("  client_cert: %s\n", dstCert)
			fmt.Printf("  client_key:  %s\n", dstKey)
			if cfg.ActiveProfile == name {
				fmt.Printf("  (active profile)\n")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "profile name (required)")
	cmd.Flags().StringVar(&controlURL, "control-url", "", "control plane URL, e.g. https://127.0.0.1:8081 (required)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "", "path to mTLS CA cert (required)")
	cmd.Flags().StringVar(&clientCert, "client-cert", "", "path to mTLS client cert (required)")
	cmd.Flags().StringVar(&clientKey, "client-key", "", "path to mTLS client private key (required)")
	cmd.Flags().BoolVar(&link, "link", false, "symlink the cert files instead of copying (track source rotation)")
	cmd.Flags().BoolVar(&setActive, "set-active", false, "make this the active profile (default: only on first add)")
	return cmd
}
