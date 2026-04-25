// Package admin_bff is the Go BFF that fronts the React admin UI on
// admin.akashic.<domain>. It terminates browser requests, talks to the
// control plane over mTLS using the bff-client cert (CN bff.akashic.local),
// and serves the embedded React app.
//
// Phase 6 scope: bootstrap-only. No login flow, no admin dashboard, no
// session store. Those land in Phase 7.
package admin_bff

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds runtime settings for the admin-bff process.
//
// Loaded via Viper with prefix AKASHIC_BFF_; unknown keys are ignored so
// operators can sprinkle other env vars in the same shell without
// causing startup failures. Defaults assume container-mode paths
// (/certs/...); host-run is fine too with explicit overrides.
type Config struct {
	// ListenAddr is the host:port the BFF binds to. Inside the docker
	// network this is ":8082" (all interfaces in the container's netns,
	// which Docker's port-forwarding can then reach). For host-run dev
	// you'd typically use "127.0.0.1:8082".
	ListenAddr string

	// ControlURL is the Akashic control plane base URL. Inside the
	// docker network it's reached via the network alias.
	ControlURL string

	// BFF mTLS material. The cert/key is rotated by Vault Agent in
	// place; the cert reloader (Step 2) picks up rotations without
	// restarting the BFF.
	BFFCertFile string
	BFFKeyFile  string
	BFFCAFile   string

	// CertWatcherEnabled toggles the in-process fsnotify watcher.
	// When false, rotation requires a process restart -- still
	// works, just not zero-downtime.
	CertWatcherEnabled bool

	// CertWatcherDebounce is the settle delay after the last cert/key
	// event before reloading. Mirrors the Akashic server's setting
	// (Phase 4) and exists for the same reason: Vault Agent writes
	// cert and key sequentially, so we wait for both to settle.
	CertWatcherDebounce time.Duration

	// TrustedProxies is a list of CIDR ranges from which the BFF will
	// honor X-Forwarded-For. Anything else is ignored and the BFF
	// uses the socket peer IP for rate limiting / audit logging.
	//
	// Default "172.0.0.0/8" covers the docker-network range -- the
	// docker proxy is the only thing that legitimately forwards into
	// the BFF, so the docker-network supernet is the right scope.
	// In a non-default docker network setup, override accordingly.
	TrustedProxies []string

	// BootstrapRateLimit is the per-source-IP attempts/minute cap on
	// /api/bootstrap/create-root. 5 mirrors the control plane's
	// per-CN rate limit so the user-visible behavior aligns.
	BootstrapRateLimit int

	// RequestTimeout caps the duration of the BFF's outbound call to
	// the control plane. Bootstrap is a single, blocking action; if
	// it takes longer than this, something has gone wrong upstream.
	RequestTimeout time.Duration
}

const envPrefix = "AKASHIC_BFF"

// LoadConfig reads BFF config from environment variables, applying
// defaults for any missing values. Returns a usable *Config or an
// error if a required field is empty after defaulting.
func LoadConfig() (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Defaults — viper.SetDefault is the lowest-precedence layer, so
	// any AKASHIC_BFF_* env var overrides without further action.
	v.SetDefault("listen_addr", ":8082")
	v.SetDefault("control_url", "https://akashic.akashic.local:8081")
	v.SetDefault("bff_cert_file", "/certs/bff/akashic-ctrl-client.crt")
	v.SetDefault("bff_key_file", "/certs/bff/akashic-ctrl-client.key")
	v.SetDefault("bff_ca_file", "/certs/bff/mtls-ca.crt")
	v.SetDefault("cert_watcher_enabled", true)
	v.SetDefault("cert_watcher_debounce", "500ms")
	v.SetDefault("trusted_proxies", "172.0.0.0/8")
	v.SetDefault("bootstrap_rate_limit", 5)
	v.SetDefault("request_timeout", "10s")

	cfg := &Config{
		ListenAddr:          v.GetString("listen_addr"),
		ControlURL:          v.GetString("control_url"),
		BFFCertFile:         v.GetString("bff_cert_file"),
		BFFKeyFile:          v.GetString("bff_key_file"),
		BFFCAFile:           v.GetString("bff_ca_file"),
		CertWatcherEnabled:  v.GetBool("cert_watcher_enabled"),
		CertWatcherDebounce: v.GetDuration("cert_watcher_debounce"),
		// trusted_proxies is comma-separated when supplied via env
		TrustedProxies:     splitCSV(v.GetString("trusted_proxies")),
		BootstrapRateLimit: v.GetInt("bootstrap_rate_limit"),
		RequestTimeout:     v.GetDuration("request_timeout"),
	}

	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen_addr is required")
	}
	if cfg.ControlURL == "" {
		return nil, fmt.Errorf("control_url is required")
	}
	return cfg, nil
}

// splitCSV splits a comma-separated string and trims whitespace.
// Empty values are dropped so "a, , b" → ["a", "b"].
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
