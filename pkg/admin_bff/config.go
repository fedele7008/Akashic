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

	// ─── Phase 7: OAuth client + Redis-backed sessions ────────────
	//
	// The BFF acts as an OAuth 2.1 client to the auth server. It
	// initiates flows (/login → /authorize), receives callbacks
	// (/oauth/callback), and translates a successful flow into a
	// browser session. The session lives in Redis so that the BFF
	// can restart without invalidating logged-in users.

	// OAuthIssuer is the auth server's PUBLIC base URL. Used both to
	// build /authorize redirects (browser-facing) and to validate the
	// iss claim on returned ID tokens. Must NOT have a trailing slash;
	// the code trims it but keep configs clean.
	OAuthIssuer string

	// OAuthInternalURL is the BACK-CHANNEL base URL the BFF dials
	// when calling /token and /jwks.json. Optional; falls back to
	// OAuthIssuer when empty (single-URL deployment). The standard
	// docker-compose setup overrides this to the docker-network alias
	// (https://auth.akashic.local:8080) so the BFF doesn't have to
	// round-trip through the public reverse proxy for server-to-
	// server traffic. The auth-server's TLS cert SAN list includes
	// auth.akashic.local, so cert verification still succeeds.
	OAuthInternalURL string

	// OAuthClientID is the client_services row that this BFF presents
	// itself as. Phase 7 default: "akashic-admin". Must exist as a
	// built-in row in the database, with redirect_uri matching
	// OAuthRedirectURI exactly.
	OAuthClientID string

	// OAuthClientSecretFile is the path on disk to the plaintext
	// client secret. Akashic-server writes this on startup (see
	// pkg/oauth/builtin.go) -- the BFF reads it once at init.
	OAuthClientSecretFile string

	// OAuthRedirectURI is the absolute URL the auth server redirects
	// the browser to after /authorize. Must match the registered
	// redirect_uri on the client_services row exactly.
	OAuthRedirectURI string

	// OAuthScopes is the space-separated scope set we request.
	// "openid profile email" is the standard OIDC trio; we read all
	// three claims off the ID token for the user-info display.
	OAuthScopes string

	// OAuthCAFile is the CA bundle the BFF trusts when calling the
	// auth server (/token, /jwks.json). Distinct from BFFCAFile
	// (which is the mTLS CA used for the control plane) -- the auth
	// server's TLS cert is signed by a different intermediate.
	OAuthCAFile string

	// OAuthAllowedRoles is the user_type allowlist for admin login.
	// Anyone authenticating as a role NOT in this list gets a 403
	// at /oauth/callback and never has a session created.
	OAuthAllowedRoles []string

	// OAuthSessionIdle / OAuthSessionAbsolute are the BFF session
	// TTLs. Idle is refreshed on each authenticated request; absolute
	// is the hard ceiling. See pkg/admin_bff/session.go for details.
	OAuthSessionIdle     time.Duration
	OAuthSessionAbsolute time.Duration

	// ─── Redis (BFF session store) ────────────────────────────────

	// RedisAddr is host:port of the Redis used for BFF sessions.
	// In docker, "redis.akashic.local:6379"; for host-run dev,
	// "localhost:6379".
	RedisAddr string

	// RedisPassword is the Redis AUTH password. Empty disables AUTH.
	RedisPassword string

	// RedisDB is the Redis logical database the BFF uses. Default 1
	// to keep the BFF's keyspace cleanly separated from the auth
	// server's (DB 0).
	RedisDB int

	// RedisTLSCAFile, when non-empty, enables TLS on the Redis
	// connection and configures verification against this CA bundle.
	// Vault-Agent renders this in production; in dev it's the same
	// cert the akashic-server uses.
	RedisTLSCAFile     string
	RedisTLSServerName string // override SNI; default = host of RedisAddr

	// ─── Phase 8c.5: external tool links ──────────────────────────
	//
	// Operator-configured URLs to internal admin / debugging tools
	// (Grafana, Adminer, RedisInsight, Vault UI, phpLDAPadmin).
	// Surfaced on the admin web's "Tools" page as a card grid.
	//
	// Empty = the corresponding card does NOT render — keeps the
	// production case "no broken cards for tools we didn't deploy."
	// Each tool has a hardcoded label + icon on the FE; only the
	// URL is operator-set, since labels and icons aren't usefully
	// configurable for a fixed catalog of well-known tools.
	ToolsGrafanaURL      string
	ToolsAdminerURL      string
	ToolsRedisInsightURL string
	ToolsVaultURL        string
	ToolsPhpLDAPAdminURL string
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

	// Phase 7: OAuth + sessions. These defaults assume the
	// docker-compose `app` profile + the standard akashic-admin
	// built-in client. Operators running differently override via env.
	// Issuer URL: must MATCH auth-server's AKASHIC_OAUTH_ISSUER
	// exactly (otherwise iss-claim verification on returned ID
	// tokens fails). Defaults to the no-port form because we route
	// auth.* through nginx-proxy on the browser-facing TLS port.
	v.SetDefault("oauth_issuer", "https://auth.akashic.local")
	// Internal URL: where the BFF dials for /token and /jwks. Default
	// is the docker-network alias on the auth-server's TLS port
	// (which is in the cert's SAN list). Empty = use issuer.
	v.SetDefault("oauth_internal_url", "https://auth.akashic.local:8080")
	v.SetDefault("oauth_client_id", "akashic-admin")
	v.SetDefault("oauth_client_secret_file", "/keys/oauth/client-secrets/akashic-admin.txt")
	v.SetDefault("oauth_redirect_uri", "https://admin.akashic.local/oauth/callback")
	v.SetDefault("oauth_scopes", "openid profile email")
	v.SetDefault("oauth_ca_file", "/certs/akashic/auth-ca.crt")
	v.SetDefault("oauth_allowed_roles", "root,admin")
	v.SetDefault("oauth_session_idle", "30m")
	v.SetDefault("oauth_session_absolute", "8h")

	v.SetDefault("redis_addr", "redis.akashic.local:6379")
	v.SetDefault("redis_password", "")
	v.SetDefault("redis_db", 1)
	v.SetDefault("redis_tls_ca_file", "/certs/redis/ca.crt")
	v.SetDefault("redis_tls_server_name", "redis.akashic.local")

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

		OAuthIssuer:           v.GetString("oauth_issuer"),
		OAuthInternalURL:      v.GetString("oauth_internal_url"),
		OAuthClientID:         v.GetString("oauth_client_id"),
		OAuthClientSecretFile: v.GetString("oauth_client_secret_file"),
		OAuthRedirectURI:      v.GetString("oauth_redirect_uri"),
		OAuthScopes:           v.GetString("oauth_scopes"),
		OAuthCAFile:           v.GetString("oauth_ca_file"),
		OAuthAllowedRoles:     splitCSV(v.GetString("oauth_allowed_roles")),
		OAuthSessionIdle:      v.GetDuration("oauth_session_idle"),
		OAuthSessionAbsolute:  v.GetDuration("oauth_session_absolute"),

		RedisAddr:          v.GetString("redis_addr"),
		RedisPassword:      v.GetString("redis_password"),
		RedisDB:            v.GetInt("redis_db"),
		RedisTLSCAFile:     v.GetString("redis_tls_ca_file"),
		RedisTLSServerName: v.GetString("redis_tls_server_name"),

		// Phase 8c.5: tool links. Defaults are empty by design —
		// operators set only the tools they actually deployed, so
		// production deployments don't render broken cards for
		// missing services.
		ToolsGrafanaURL:      v.GetString("tools_grafana_url"),
		ToolsAdminerURL:      v.GetString("tools_adminer_url"),
		ToolsRedisInsightURL: v.GetString("tools_redisinsight_url"),
		ToolsVaultURL:        v.GetString("tools_vault_url"),
		ToolsPhpLDAPAdminURL: v.GetString("tools_phpldapadmin_url"),
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
