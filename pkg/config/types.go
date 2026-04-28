package config

import (
	"errors"
	"fmt"
	"maps"
	"time"
)

// Environment specifies the runtime environment
type Environment string

const (
	// EnvDevelopment: Development environment with debug features
	EnvDevelopment Environment = "development"
	// EnvStaging: Staging environment for testing
	EnvStaging Environment = "staging"
	// EnvProduction: Production environment
	EnvProduction Environment = "production"
)

func (e Environment) String() string {
	return string(e)
}

// FileMode specifies how log files should be handled
type FileMode int

const (
	FileAppend FileMode = iota
	FileTruncate
	FileRolling
)

func ParseFileMode(s string) (FileMode, error) {
	switch s {
	case "append":
		return FileAppend, nil
	case "truncate":
		return FileTruncate, nil
	case "rolling":
		return FileRolling, nil
	default:
		return FileMode(-1), fmt.Errorf("unknown file mode: %s", s)
	}
}

func (f FileMode) String() string {
	return map[FileMode]string{
		FileAppend:   "append",
		FileTruncate: "truncate",
		FileRolling:  "rolling",
	}[f]
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (f *FileMode) UnmarshalText(text []byte) error {
	mode, err := ParseFileMode(string(text))
	if err != nil {
		return err
	}
	*f = mode
	return nil
}

// SinkType specifies the output destination type
type SinkType int

const (
	SinkStdout SinkType = iota
	SinkStderr
	SinkFile
	SinkLoki
)

func ParseSinkType(s string) (SinkType, error) {
	switch s {
	case "stdout":
		return SinkStdout, nil
	case "stderr":
		return SinkStderr, nil
	case "file":
		return SinkFile, nil
	case "loki":
		return SinkLoki, nil
	default:
		return -1, fmt.Errorf("unknown sink type: %s", s)
	}
}

func (s SinkType) String() string {
	return map[SinkType]string{
		SinkStdout: "stdout",
		SinkStderr: "stderr",
		SinkFile:   "file",
		SinkLoki:   "loki",
	}[s]
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (s *SinkType) UnmarshalText(text []byte) error {
	sinkType, err := ParseSinkType(string(text))
	if err != nil {
		return err
	}
	*s = sinkType
	return nil
}

// Level specifies the log level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func ParseLevel(s string) (Level, error) {
	switch s {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "fatal":
		return LevelFatal, nil
	default:
		return LevelFatal, fmt.Errorf("unknown log level: %s", s)
	}
}

func (l Level) String() string {
	return map[Level]string{
		LevelDebug: "debug",
		LevelInfo:  "info",
		LevelWarn:  "warn",
		LevelError: "error",
		LevelFatal: "fatal",
	}[l]
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (l *Level) UnmarshalText(text []byte) error {
	level, err := ParseLevel(string(text))
	if err != nil {
		return err
	}
	*l = level
	return nil
}

// Format specifies the log format
type Format int

const (
	FormatText Format = iota
	FormatJSON
)

func ParseFormat(s string) (Format, error) {
	switch s {
	case "text":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	default:
		return FormatText, fmt.Errorf("unknown sink format: %s", s)
	}
}

func (f Format) String() string {
	return map[Format]string{
		FormatText: "text",
		FormatJSON: "json",
	}[f]
}

// UnmarshalText implements the encoding.TextUnmarshaler interface
func (f *Format) UnmarshalText(text []byte) error {
	format, err := ParseFormat(string(text))
	if err != nil {
		return err
	}
	*f = format
	return nil
}

// Channel specifies the log channel
type Channel int

const (
	ChannelApp Channel = iota
	ChannelSecurity
	ChannelAudit
)

var channelName = map[Channel]string{
	ChannelApp:      "app",
	ChannelSecurity: "security",
	ChannelAudit:    "audit",
}

func (ch Channel) String() string {
	str := channelName[ch]
	if str == "" {
		return "unknown"
	}
	return str
}

// StaticLabel represents key-value labels for Loki
type StaticLabel map[string]string

// SinkConfig defines a single log output destination
type SinkConfig struct {
	// Common fields
	Type    SinkType `mapstructure:"type" yaml:"type"`
	Enabled bool     `mapstructure:"enabled" yaml:"enabled"`
	Level   Level    `mapstructure:"level" yaml:"level"`
	Format  Format   `mapstructure:"format" yaml:"format"` // ignored in loki sink

	// File sink specific fields
	FilePath   string   `mapstructure:"file_path" yaml:"file_path"`
	FileMode   FileMode `mapstructure:"file_mode" yaml:"file_mode"`
	MaxSizeMB  int      `mapstructure:"max_size_mb" yaml:"max_size_mb"`
	MaxBackups int      `mapstructure:"max_backups" yaml:"max_backups"`

	// Loki sink specific fields
	LokiURL            string      `mapstructure:"loki_url" yaml:"loki_url"`
	BasicAuthUser      string      `mapstructure:"basic_auth_user" yaml:"basic_auth_user"`
	BasicAuthPass      string      `mapstructure:"basic_auth_pass" yaml:"basic_auth_pass"`
	LokiLabels         StaticLabel `mapstructure:"loki_labels" yaml:"loki_labels"`
	BatchSize          int         `mapstructure:"batch_size" yaml:"batch_size"`
	BatchFlushPeriodMs int         `mapstructure:"batch_flush_period_ms" yaml:"batch_flush_period_ms"`
	RetryMaxCount      int         `mapstructure:"retry_max_count" yaml:"retry_max_count"`
	RetryMinBackoffMs  int         `mapstructure:"retry_min_backoff_ms" yaml:"retry_min_backoff_ms"`
	RetryMaxBackoffMs  int         `mapstructure:"retry_max_backoff_ms" yaml:"retry_max_backoff_ms"`
	Compress           bool        `mapstructure:"compress" yaml:"compress"`
	BreakerMaxRetries  int         `mapstructure:"breaker_max_retries" yaml:"breaker_max_retries"`
	BreakerCooldownMs  int         `mapstructure:"breaker_cooldown_ms" yaml:"breaker_cooldown_ms"`
	ClientTimeoutMs    int         `mapstructure:"client_timeout_ms" yaml:"client_timeout_ms"`
}

// EncoderConfig defines JSON encoder configuration
type EncoderConfig struct {
	TimestampKey  string `mapstructure:"timestamp_key" yaml:"timestamp_key"`
	TimeFormatKey string `mapstructure:"time_format" yaml:"time_format"`
	LevelKey      string `mapstructure:"level_key" yaml:"level_key"`
	NameKey       string `mapstructure:"name_key" yaml:"name_key"`
	CallerKey     string `mapstructure:"caller_key" yaml:"caller_key"`
	MessageKey    string `mapstructure:"message_key" yaml:"message_key"`
	StacktraceKey string `mapstructure:"stacktrace_key" yaml:"stacktrace_key"`
}

// ChannelConfig defines configuration for a logging channel
type ChannelConfig struct {
	Enabled         bool         `mapstructure:"enabled" yaml:"enabled"`
	ShowCaller      bool         `mapstructure:"show_caller" yaml:"show_caller"`
	ShowStacktrace  bool         `mapstructure:"show_stacktrace" yaml:"show_stacktrace"`
	StacktraceLevel Level        `mapstructure:"stacktrace_level" yaml:"stacktrace_level"`
	Sinks           []SinkConfig `mapstructure:"sinks" yaml:"sinks"`
}

// LoggingConfig defines the complete logging configuration
type LoggingConfig struct {
	ServiceName      string         `mapstructure:"service_name" yaml:"service_name"`
	Environment      string         `mapstructure:"environment" yaml:"environment"`
	EncoderConfig    EncoderConfig  `mapstructure:"encoder" yaml:"encoder"`
	App              ChannelConfig  `mapstructure:"app" yaml:"app"`
	Security         ChannelConfig  `mapstructure:"security" yaml:"security"`
	Audit            ChannelConfig  `mapstructure:"audit" yaml:"audit"`
	ForceAuditAppend bool           `mapstructure:"force_audit_append" yaml:"force_audit_append"`
	LokiTLS          LokiTLSConfig  `mapstructure:"loki_tls" yaml:"loki_tls"`
}

// Root configuration
type Config struct {
	// Server configuration for API endpoints
	Server ServerConfig `mapstructure:"server" yaml:"server"`
	// Database connections (PostgreSQL and Redis)
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`
	// Session management settings
	Session SessionConfig `mapstructure:"session" yaml:"session"`
	// Logging configuration (multi-sink system)
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`
	// Middleware configuration for both servers
	Middleware MiddlewareConfig `mapstructure:"middleware" yaml:"middleware"`
	// General deployment settings
	Deployment DeploymentConfig `mapstructure:"deployment" yaml:"deployment"`
	// Bootstrap configuration for initial setup
	Bootstrap BootstrapConfig `mapstructure:"bootstrap" yaml:"bootstrap"`
	// LDAP server configuration
	LDAP LDAPConfig `mapstructure:"ldap" yaml:"ldap"`
	// PKI / cert-rotation configuration (Phase 4)
	PKI PKIConfig `mapstructure:"pki" yaml:"pki"`
	// OAuth/OIDC server configuration (Phase 7)
	OAuth OAuthConfig `mapstructure:"oauth" yaml:"oauth"`
	// Tenant-portal configuration (Phase 8)
	Portal PortalConfig `mapstructure:"portal" yaml:"portal"`
}

// PortalConfig holds Phase 8 settings for the public portal.
// All fields are operator-supplied; Akashic itself just exposes them
// via control-plane endpoints the portal calls (e.g.,
// /users/forgot-password-help reads SupportContact).
type PortalConfig struct {
	// SupportContact is the email or URL the portal's "forgot
	// password" page tells users to contact for a manual reset
	// (Phase 8 doesn't have email-driven self-service reset; that's
	// Phase 9). If empty, the help page surfaces a generic
	// "contact your administrator" message.
	SupportContact string `mapstructure:"support_contact" yaml:"support_contact"`

	// TenantOrigins is a comma-separated CORS allowlist for tenant
	// product origins that may embed Akashic widgets. Used by:
	//   - auth-server's POST /session/token (bearer-exchange endpoint)
	//   - api-server's bearer-protected resource endpoints
	//
	// Set as a single string (e.g. "https://acme.com,https://www.acme.com")
	// for viper compatibility with env vars; consumers split by ","
	// at use time. Helper: pkg/server/cors.ParseOrigins(cfg.Portal.TenantOrigins).
	//
	// Cross-origin requests from these origins are honoured with
	// `Access-Control-Allow-Origin: <origin>` (echoed) and
	// `Access-Control-Allow-Credentials: true`. Origins not on this
	// list see no Access-Control-Allow-Origin header — the browser
	// then refuses to deliver the response to its JS, blocking
	// widget integrations from unauthorized sites.
	//
	// Empty = no widget origins permitted (default; widgets still
	// load as <script> tags but their fetch calls are blocked by
	// CORS, which is the safe default).
	//
	// Future (post-Phase-8b, when client_services registration is
	// fully self-service): each registered tenant Client may
	// contribute its own origins, dynamically extending this list.
	TenantOrigins string `mapstructure:"tenant_origins" yaml:"tenant_origins"`
}

// OAuthConfig configures the OAuth 2.1 / OIDC authorization server.
type OAuthConfig struct {
	// Issuer is the base URL of the auth server, used as the JWT
	// `iss` claim and in the discovery doc. MUST match the URL
	// clients are configured to redirect through.
	Issuer string `mapstructure:"issuer" yaml:"issuer"`

	// SigningKeyDir is the filesystem path holding RSA signing keys
	// (one <kid>.json file per key). Phase 7 stores keys here; a
	// future phase may move them to Vault KV.
	SigningKeyDir string `mapstructure:"signing_key_dir" yaml:"signing_key_dir"`

	// AccessTokenTTL is how long an access token is valid. 15 min
	// default — short enough that revocation isn't critical, long
	// enough to avoid re-auth on every API call.
	AccessTokenTTL time.Duration `mapstructure:"access_token_ttl" yaml:"access_token_ttl"`

	// IDTokenTTL is how long an OIDC ID token is valid. Typically
	// matches AccessTokenTTL.
	IDTokenTTL time.Duration `mapstructure:"id_token_ttl" yaml:"id_token_ttl"`

	// AuthCodeTTL is how long an authorization code is valid. RFC
	// 6749 §4.1.2 recommends ≤10 minutes; we go shorter (60s) to
	// limit the interception window.
	AuthCodeTTL time.Duration `mapstructure:"auth_code_ttl" yaml:"auth_code_ttl"`

	// AdminRedirectURI is the redirect_uri the akashic-admin built-in
	// client is registered with. Must match exactly what admin-bff
	// sends on /authorize.
	AdminRedirectURI string `mapstructure:"admin_redirect_uri" yaml:"admin_redirect_uri"`

	// PortalRedirectURI is the redirect_uri the akashic-portal built-in
	// client is registered with (Phase 8). Must match exactly what the
	// portal sends on /authorize. Public surface — user-scoped (no
	// role restriction), unlike AdminRedirectURI.
	PortalRedirectURI string `mapstructure:"portal_redirect_uri" yaml:"portal_redirect_uri"`

	// AuthSessionIdleTTL is how long an auth-server session can be
	// idle before requiring re-login. Refreshed on every visit to
	// /authorize within the absolute TTL.
	AuthSessionIdleTTL time.Duration `mapstructure:"auth_session_idle_ttl" yaml:"auth_session_idle_ttl"`

	// AuthSessionMaxTTL is the absolute lifetime of an auth-server
	// session. Cannot be extended past this even with active use.
	AuthSessionMaxTTL time.Duration `mapstructure:"auth_session_max_ttl" yaml:"auth_session_max_ttl"`
}

// PKIConfig controls the in-process PKI / cert-rotation subsystem (Phase 4)
type PKIConfig struct {
	// CertWatcherEnabled enables an in-process fsnotify watcher that calls
	// the reloader when cert/key files change on disk. Safe to disable --
	// rotation still works via POST /tls/reload or process restart.
	CertWatcherEnabled bool `mapstructure:"cert_watcher_enabled" yaml:"cert_watcher_enabled"`

	// CertWatcherDebounce is the settle delay after the last cert/key
	// event before reloading, to avoid reading a new cert paired with
	// an old key while Vault Agent finishes writing both files.
	CertWatcherDebounce time.Duration `mapstructure:"cert_watcher_debounce" yaml:"cert_watcher_debounce"`
}

// LokiTLSConfig describes how the Loki HTTP client trusts the loki-proxy.
type LokiTLSConfig struct {
	// Enabled signals that the Loki URL is expected to be https and we
	// must verify against CACertPath. Mirrors AKASHIC_LOKI_PROXY_TLS.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// CACertPath is the path to the trust bundle that signs the loki-proxy cert.
	CACertPath string `mapstructure:"ca_cert" yaml:"ca_cert"`
	// ServerName overrides the SNI/verify hostname (default: loki.akashic.local).
	ServerName string `mapstructure:"server_name" yaml:"server_name"`
	// SkipVerify bypasses cert verification (dev only, INSECURE).
	SkipVerify bool `mapstructure:"skip_verify" yaml:"skip_verify"`
}

// ServerConfig contains basic server settings
type ServerConfig struct {
	// Auth server configuration for OAuth/OIDC endpoints
	Auth AuthServerConfig `mapstructure:"auth" yaml:"auth"`
	// Control server configuration for control plane management via mTLS
	Control ControlServerConfig `mapstructure:"control" yaml:"control"`
	// API server configuration for end-user resource APIs (Phase 8).
	// Bearer-token authenticated (OAuth resource server). Hosts user
	// self-service (/users/register, /users/me) and developer
	// self-service (/clients/*) endpoints.
	API APIServerConfig `mapstructure:"api" yaml:"api"`
}

// APIServerConfig defines settings for the API (resource) server
// — the OAuth-resource-server surface introduced in Phase 8.
//
// Authentication on this server is OAuth bearer tokens, NOT mTLS.
// The portal/BFF gets an access token during the user's OAuth login
// and forwards it as `Authorization: Bearer <token>` on every API
// call. The bearer middleware verifies the token's signature via the
// shared OAuth keystore (same in-process keystore the auth server
// uses to mint tokens), so token validation is a local crypto check
// — no cross-server call.
type APIServerConfig struct {
	// Host address to bind the API server (e.g., "0.0.0.0").
	Host string `mapstructure:"host" yaml:"host"`
	// Port number for the API server (typically 8082).
	Port int `mapstructure:"port" yaml:"port"`
	// TLS settings — same shape as the auth server's. No mTLS on this
	// listener (it's bearer-token authenticated, not cert-authenticated).
	TLS APITLSConfig `mapstructure:"tls" yaml:"tls"`
}

// APITLSConfig is the API-server-specific TLS block. Same shape as
// AuthTLSConfig — no mTLS on this listener.
type APITLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
}

// AuthServerConfig defines OAuth/OIDC authentication server settings
type AuthServerConfig struct {
	// Host address to bind the server (e.g., "0.0.0.0", "localhost")
	Host string `mapstructure:"host" yaml:"host"`
	// Port number for the auth server (typically 8080)
	Port int `mapstructure:"port" yaml:"port"`
	// TLS serves OAuth/OIDC endpoints over HTTPS when Enabled. Unlike the
	// control server, the auth server never requires client certs.
	TLS AuthTLSConfig `mapstructure:"tls" yaml:"tls"`
}

// AuthTLSConfig is the auth-server-specific TLS block. Simpler than
// ControlServerConfig.TLS because there is no mTLS on this listener.
type AuthTLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
}

// ControlServerConfig defines control plane management server settings
type ControlServerConfig struct {
	// Host address to bind the control server (e.g., "127.0.0.1" for localhost only)
	Host string `mapstructure:"host" yaml:"host"`
	// Port number for the control server (typically 8081)
	Port int `mapstructure:"port" yaml:"port"`
	// TLS configuration for mTLS with self-signed certificates
	TLS TLSConfig `mapstructure:"tls" yaml:"tls"`
}

// TLSConfig defines TLS/mTLS settings for the control server
type TLSConfig struct {
	// Enabled controls whether TLS is enabled (should always be true for control server)
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// CertFile path to the server certificate file (self-signed)
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	// KeyFile path to the server private key file
	KeyFile string `mapstructure:"key_file" yaml:"key_file"`
	// CAFile path to the Certificate Authority file for client verification
	CAFile string `mapstructure:"ca_file" yaml:"ca_file"`
	// ClientAuthRequired enforces mutual TLS (client certificates required)
	ClientAuthRequired bool `mapstructure:"client_auth_required" yaml:"client_auth_required"`
}

// DatabaseConfig contains database connection settings
type DatabaseConfig struct {
	// PostgreSQL configuration for persistent data
	Postgres PostgresConfig `mapstructure:"postgres" yaml:"postgres"`
	// Redis configuration for sessions and caching
	Redis RedisConfig `mapstructure:"redis" yaml:"redis"`
}

// PostgresConfig defines PostgreSQL connection settings
type PostgresConfig struct {
	// Host address of the PostgreSQL server
	Host string `mapstructure:"host" yaml:"host"`
	// Port number (typically 5432)
	Port int `mapstructure:"port" yaml:"port"`
	// Database name
	Database string `mapstructure:"database" yaml:"database"`
	// Username for authentication
	Username string `mapstructure:"username" yaml:"username"`
	// Password for authentication (use environment variables)
	Password string `mapstructure:"password" yaml:"password"`
	// SSLMode for connection security (disable, require, verify-ca, verify-full).
	// Used when TLS.Enabled is true; ignored otherwise (sslmode=disable is forced).
	SSLMode string `mapstructure:"ssl_mode" yaml:"ssl_mode"`
	// MaxConnections for connection pool
	MaxConnections int `mapstructure:"max_connections" yaml:"max_connections"`
	// MaxIdleConnections for connection pool
	MaxIdleConnections int `mapstructure:"max_idle_connections" yaml:"max_idle_connections"`
	// ConnectionLifetime for connection reuse
	ConnectionLifetime time.Duration `mapstructure:"connection_lifetime" yaml:"connection_lifetime"`
	// TLS holds the master toggle + CA bundle path (AKASHIC_DATABASE_POSTGRES_TLS_ENABLED)
	TLS PostgresTLSConfig `mapstructure:"tls" yaml:"tls"`
}

// PostgresTLSConfig is the Phase 4 master toggle for Postgres TLS, mirroring
// AKASHIC_POSTGRES_TLS=on|off from the docker-compose side.
type PostgresTLSConfig struct {
	// Enabled toggles whether the DSN uses TLS at all. When false we force
	// sslmode=disable regardless of the SSLMode field above.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// CACertPath is the trust bundle used to verify the postgres server cert.
	CACertPath string `mapstructure:"ca_cert" yaml:"ca_cert"`
	// ServerName overrides the hostname verified against the server cert CN/SAN.
	ServerName string `mapstructure:"server_name" yaml:"server_name"`
}

// RedisConfig defines Redis connection settings
type RedisConfig struct {
	// Host address of Redis server
	Host string `mapstructure:"host" yaml:"host"`
	// Port number (typically 6379)
	Port int `mapstructure:"port" yaml:"port"`
	// Password for authentication (optional)
	Password string `mapstructure:"password" yaml:"password"`
	// DB number to select (0-15, typically 0)
	DB int `mapstructure:"db" yaml:"db"`
	// PoolSize for connection pool
	PoolSize int `mapstructure:"pool_size" yaml:"pool_size"`
	// SessionTTL for session storage
	SessionTTL time.Duration `mapstructure:"session_ttl" yaml:"session_ttl"`
	// CacheTTL for general caching
	CacheTTL time.Duration `mapstructure:"cache_ttl" yaml:"cache_ttl"`
	// TLS holds the master toggle + CA bundle path (AKASHIC_DATABASE_REDIS_TLS_ENABLED)
	TLS RedisTLSConfig `mapstructure:"tls" yaml:"tls"`
}

// RedisTLSConfig mirrors AKASHIC_REDIS_TLS=on|off. When enabled, go-redis
// dials TLS and verifies against CACertPath.
type RedisTLSConfig struct {
	// Enabled toggles whether the redis client dials TLS.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// CACertPath is the trust bundle used to verify the redis server cert.
	CACertPath string `mapstructure:"ca_cert" yaml:"ca_cert"`
	// ServerName overrides the SNI / verify hostname.
	ServerName string `mapstructure:"server_name" yaml:"server_name"`
	// SkipVerify bypasses cert verification (dev only, INSECURE).
	SkipVerify bool `mapstructure:"skip_verify" yaml:"skip_verify"`
}

// SessionConfig contains basic session management settings
type SessionConfig struct {
	// Timeout for session expiration
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
	// SecureCookies enforces secure flag on cookies
	SecureCookies bool `mapstructure:"secure_cookies" yaml:"secure_cookies"`
	// SameSite cookie attribute (Strict, Lax, None)
	SameSite string `mapstructure:"same_site" yaml:"same_site"`
	// CookieName for session cookies
	CookieName string `mapstructure:"cookie_name" yaml:"cookie_name"`
	// CookiePath for session cookies
	CookiePath string `mapstructure:"cookie_path" yaml:"cookie_path"`
}

// DeploymentConfig defines basic deployment settings
type DeploymentConfig struct {
	// Environment (development, staging, production)
	Environment Environment `mapstructure:"environment" yaml:"environment"`
}

// BootstrapConfig contains bootstrap system configuration
type BootstrapConfig struct {
	// TokenTTL is the time-to-live for bootstrap tokens (default: 1h)
	TokenTTL time.Duration `mapstructure:"token_ttl" yaml:"token_ttl"`
	// Password policy configuration
	Password PasswordPolicyConfig `mapstructure:"password" yaml:"password"`
}

// PasswordPolicyConfig defines password strength requirements
type PasswordPolicyConfig struct {
	// MinLength is the minimum password length (default: 12)
	MinLength int `mapstructure:"min_length" yaml:"min_length"`
	// RequireUppercase requires at least one uppercase letter
	RequireUppercase bool `mapstructure:"require_uppercase" yaml:"require_uppercase"`
	// RequireNumber requires at least one number
	RequireNumber bool `mapstructure:"require_number" yaml:"require_number"`
	// RequireSpecial requires at least one special character
	RequireSpecial bool `mapstructure:"require_special" yaml:"require_special"`
}

// LDAPConfig contains unified LDAP server configuration
// Works for both embedded (Docker) and external LDAP servers
type LDAPConfig struct {
	// Host is the LDAP server address
	// Embedded: "ldap" (Docker service name)
	// External: "ldap.company.com" or IP address
	Host string `mapstructure:"host" yaml:"host"`

	// Port is the LDAP port number (default: 389, LDAPS: 636)
	Port int `mapstructure:"port" yaml:"port"`

	// BaseDN is the base distinguished name for the LDAP directory
	BaseDN string `mapstructure:"base_dn" yaml:"base_dn"`

	// BindDN is the DN to bind as for authentication
	// Example: "cn=admin,dc=akashic,dc=local"
	BindDN string `mapstructure:"bind_dn" yaml:"bind_dn"`

	// BindPassword is the password for the bind DN
	BindPassword string `mapstructure:"bind_password" yaml:"bind_password"`

	// UseTLS enables TLS/LDAPS connection (AKASHIC_LDAP_TLS=on|off)
	UseTLS bool `mapstructure:"use_tls" yaml:"use_tls"`

	// TLSSkipVerify skips TLS certificate verification (insecure - dev only)
	TLSSkipVerify bool `mapstructure:"tls_skip_verify" yaml:"tls_skip_verify"`

	// TLSCACertPath is the trust bundle used when UseTLS is true and TLSSkipVerify
	// is false. Empty = use system root CAs.
	TLSCACertPath string `mapstructure:"tls_ca_cert" yaml:"tls_ca_cert"`

	// TLSMode selects how TLS is negotiated: "ldaps" (dial ldaps:// on the LDAPS port),
	// "starttls" (dial ldap:// then upgrade), or "plain" (no TLS). Empty lets the
	// client infer from Port by comparing against StartTLSPort / LDAPSPort below.
	TLSMode string `mapstructure:"tls_mode" yaml:"tls_mode"`

	// StartTLSPort names the port on which the server offers StartTLS (i.e. plain
	// LDAP that can be upgraded to TLS via the StartTLS operation). When Port
	// matches this value and TLSMode is empty, the client infers "starttls".
	// Default: 389 (IANA-assigned standard LDAP port).
	StartTLSPort int `mapstructure:"starttls_port" yaml:"starttls_port"`

	// LDAPSPort names the port on which the server offers LDAPS (implicit TLS from
	// byte 0). When Port matches this value and TLSMode is empty, the client
	// infers "ldaps". Default: 636 (IANA-assigned standard LDAPS port).
	LDAPSPort int `mapstructure:"ldaps_port" yaml:"ldaps_port"`

	// UserSearchBase is the base DN for user searches
	// Example: "ou=users,dc=akashic,dc=local"
	UserSearchBase string `mapstructure:"user_search_base" yaml:"user_search_base"`

	// UserSearchFilter is the LDAP filter for finding users by their
	// canonical username (uid). Used for existence checks and lookups
	// where the caller is specifying a username explicitly — bootstrap
	// "is this uid taken?", JIT provisioning by DN, etc. Stays uid-only
	// to avoid false positives where someone's email happens to match
	// another user's uid.
	//
	// Use {username} as placeholder. Example: "(uid={username})"
	UserSearchFilter string `mapstructure:"user_search_filter" yaml:"user_search_filter"`

	// UserLoginFilter is the LDAP filter applied when a user types
	// their identifier into the login form. Distinct from
	// UserSearchFilter so login can be more permissive (accept either
	// uid or mail) without affecting username-existence semantics.
	//
	// Use {login} as placeholder. Default ORs uid + mail so users can
	// sign in with whichever they remember.
	UserLoginFilter string `mapstructure:"user_login_filter" yaml:"user_login_filter"`

	// UserObjectClass is the object class for user entries
	// Example: "inetOrgPerson"
	UserObjectClass string `mapstructure:"user_object_class" yaml:"user_object_class"`

	// UsernameAttr is the LDAP attribute for username
	// Example: "uid"
	UsernameAttr string `mapstructure:"username_attr" yaml:"username_attr"`

	// EmailAttr is the LDAP attribute for email
	// Example: "mail"
	EmailAttr string `mapstructure:"email_attr" yaml:"email_attr"`

	// DisplayNameAttr is the LDAP attribute for display name
	// Example: "cn"
	DisplayNameAttr string `mapstructure:"display_name_attr" yaml:"display_name_attr"`

	// RBAC contains role-based access control configuration
	RBAC LDAPRBACConfig `mapstructure:"rbac" yaml:"rbac"`

	// Deprovisioning contains user deprovisioning configuration
	Deprovisioning LDAPDeprovisioningConfig `mapstructure:"deprovisioning" yaml:"deprovisioning"`
}

// LDAPRBACConfig contains LDAP group-based RBAC configuration
type LDAPRBACConfig struct {
	// RootGroup is the LDAP group DN for root users
	// Example: "cn=akashic-root,ou=groups,dc=akashic,dc=local"
	RootGroup string `mapstructure:"root_group" yaml:"root_group"`

	// AdminGroup is the LDAP group DN for admin users
	// Example: "cn=akashic-admins,ou=groups,dc=akashic,dc=local"
	AdminGroup string `mapstructure:"admin_group" yaml:"admin_group"`

	// UserGroup is the LDAP group DN for regular users (optional - can be empty)
	// Example: "cn=akashic-users,ou=groups,dc=akashic,dc=local"
	UserGroup string `mapstructure:"user_group" yaml:"user_group"`

	// DefaultType is the default user type when no group membership found
	// Valid values: "user", "admin", "root" (typically should be "user")
	DefaultType string `mapstructure:"default_type" yaml:"default_type"`
}

// LDAPDeprovisioningConfig contains differential deprovisioning thresholds
type LDAPDeprovisioningConfig struct {
	// Enabled enables the deprovisioning service
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// SyncInterval is how often to check for missing LDAP entries
	SyncInterval time.Duration `mapstructure:"sync_interval" yaml:"sync_interval"`

	// RootDeletionThreshold is time before deleting root user when LDAP entry missing
	// Root accounts are critical, so this should be very short (e.g., 0s for immediate)
	RootDeletionThreshold time.Duration `mapstructure:"root_deletion_threshold" yaml:"root_deletion_threshold"`

	// AdminDeletionThreshold is time before deleting admin user when LDAP entry missing
	// Example: "720h" (30 days)
	AdminDeletionThreshold time.Duration `mapstructure:"admin_deletion_threshold" yaml:"admin_deletion_threshold"`

	// UserDeletionThreshold is time before deleting regular user when LDAP entry missing
	// Example: "2160h" (90 days)
	UserDeletionThreshold time.Duration `mapstructure:"user_deletion_threshold" yaml:"user_deletion_threshold"`
}

// MiddlewareConfig contains middleware configuration for both servers
type MiddlewareConfig struct {
	// Auth server middleware configuration
	Auth AuthMiddlewareConfig `mapstructure:"auth" yaml:"auth"`
	// Control server middleware configuration
	Control ControlMiddlewareConfig `mapstructure:"control" yaml:"control"`
}

// AuthMiddlewareConfig defines middleware settings for the Auth Server
type AuthMiddlewareConfig struct {
	// Security headers configuration
	SecurityHeaders SecurityHeadersMiddlewareConfig `mapstructure:"security_headers" yaml:"security_headers"`
	// CORS configuration
	CORS CORSMiddlewareConfig `mapstructure:"cors" yaml:"cors"`
	// Rate limiting configuration
	RateLimit RateLimitMiddlewareConfig `mapstructure:"rate_limit" yaml:"rate_limit"`
	// Logging configuration
	Logging LoggingMiddlewareConfig `mapstructure:"logging" yaml:"logging"`
	// Request size limit in bytes (default: 5MB)
	MaxRequestSizeBytes int64 `mapstructure:"max_request_size_bytes" yaml:"max_request_size_bytes"`
	// Request timeout duration
	RequestTimeout time.Duration `mapstructure:"request_timeout" yaml:"request_timeout"`
}

// ControlMiddlewareConfig defines middleware settings for the Control Server
type ControlMiddlewareConfig struct {
	// Security headers configuration
	SecurityHeaders SecurityHeadersMiddlewareConfig `mapstructure:"security_headers" yaml:"security_headers"`
	// IP allowlist for access control
	IPAllowlist IPAllowlistMiddlewareConfig `mapstructure:"ip_allowlist" yaml:"ip_allowlist"`
	// CORS configuration
	CORS CORSMiddlewareConfig `mapstructure:"cors" yaml:"cors"`
	// Rate limiting configuration
	RateLimit RateLimitMiddlewareConfig `mapstructure:"rate_limit" yaml:"rate_limit"`
	// Logging configuration
	Logging LoggingMiddlewareConfig `mapstructure:"logging" yaml:"logging"`
	// Request size limit in bytes (default: 1MB)
	MaxRequestSizeBytes int64 `mapstructure:"max_request_size_bytes" yaml:"max_request_size_bytes"`
	// Request timeout duration
	RequestTimeout time.Duration `mapstructure:"request_timeout" yaml:"request_timeout"`
}

// CORSMiddlewareConfig defines CORS settings
type CORSMiddlewareConfig struct {
	// Enabled determines if CORS is enabled
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// AllowedOrigins is a list of allowed origins (use ["*"] for all)
	AllowedOrigins []string `mapstructure:"allowed_origins" yaml:"allowed_origins"`
	// AllowedMethods is a list of allowed HTTP methods
	AllowedMethods []string `mapstructure:"allowed_methods" yaml:"allowed_methods"`
	// AllowedHeaders is a list of allowed request headers
	AllowedHeaders []string `mapstructure:"allowed_headers" yaml:"allowed_headers"`
	// ExposedHeaders is a list of headers exposed to the client
	ExposedHeaders []string `mapstructure:"exposed_headers" yaml:"exposed_headers"`
	// AllowCredentials indicates whether credentials are allowed
	AllowCredentials bool `mapstructure:"allow_credentials" yaml:"allow_credentials"`
	// MaxAge is the preflight cache duration in seconds
	MaxAge int `mapstructure:"max_age" yaml:"max_age"`
}

// RateLimitMiddlewareConfig defines rate limiting settings
type RateLimitMiddlewareConfig struct {
	// Enabled determines if rate limiting is enabled
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// RequestsPerWindow is the max number of requests allowed in the time window
	RequestsPerWindow int `mapstructure:"requests_per_window" yaml:"requests_per_window"`
	// WindowDuration is the time window for rate limiting
	WindowDuration time.Duration `mapstructure:"window_duration" yaml:"window_duration"`
}

// IPAllowlistMiddlewareConfig defines IP allowlist settings
type IPAllowlistMiddlewareConfig struct {
	// Enabled determines if IP allowlisting is enabled
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`
	// AllowedIPs is a list of allowed IP addresses or CIDR ranges
	AllowedIPs []string `mapstructure:"allowed_ips" yaml:"allowed_ips"`
	// AllowLoopback determines if loopback addresses are always allowed
	AllowLoopback bool `mapstructure:"allow_loopback" yaml:"allow_loopback"`
	// TrustProxy determines if X-Forwarded-For header should be used
	TrustProxy bool `mapstructure:"trust_proxy" yaml:"trust_proxy"`
}

// SecurityHeadersMiddlewareConfig defines security headers settings
type SecurityHeadersMiddlewareConfig struct {
	// XFrameOptions defines the X-Frame-Options policy (DENY, SAMEORIGIN)
	XFrameOptions string `mapstructure:"x_frame_options" yaml:"x_frame_options"`
	// XSSProtection defines the X-XSS-Protection policy (0, 1, 1; mode=block)
	XSSProtection string `mapstructure:"x_xss_protection" yaml:"x_xss_protection"`
	// HSTSMaxAge is the max-age for HSTS header in seconds (0 disables)
	HSTSMaxAge int `mapstructure:"hsts_max_age" yaml:"hsts_max_age"`
	// HSTSIncludeSubDomains determines if HSTS applies to subdomains
	HSTSIncludeSubDomains bool `mapstructure:"hsts_include_subdomains" yaml:"hsts_include_subdomains"`
	// HSTSPreload determines if HSTS preload directive is included
	HSTSPreload bool `mapstructure:"hsts_preload" yaml:"hsts_preload"`
	// ContentSecurityPolicy defines the CSP header value (empty disables)
	ContentSecurityPolicy string `mapstructure:"content_security_policy" yaml:"content_security_policy"`
	// RemoveServerHeader determines if Server header should be removed
	RemoveServerHeader bool `mapstructure:"remove_server_header" yaml:"remove_server_header"`
}

// LoggingMiddlewareConfig defines logging middleware settings
type LoggingMiddlewareConfig struct {
	// SkipPaths are paths to skip logging (e.g., /health for high-frequency checks)
	SkipPaths []string `mapstructure:"skip_paths" yaml:"skip_paths"`
}

// ValidateLoggingConfig validates the logging configuration
func ValidateLoggingConfig(cfg *LoggingConfig) error {
	var errs []error
	joinErrs := func(errs []error) error {
		return errors.Join(append([]error{errors.New("logging config is not valid")}, errs...)...)
	}

	if cfg == nil {
		errs = append(errs, errors.New("logging config is nil"))
		return joinErrs(errs)
	}

	if cfg.ServiceName == "" {
		errs = append(errs, errors.New("service_name is required"))
	}

	if cfg.Environment == "" {
		errs = append(errs, errors.New("environment is required"))
	}

	channels := map[string]*ChannelConfig{
		ChannelApp.String():      &cfg.App,
		ChannelSecurity.String(): &cfg.Security,
		ChannelAudit.String():    &cfg.Audit,
	}

	for chName, ch := range channels {
		for i := range ch.Sinks {
			sink := &ch.Sinks[i]

			if sink.Type == SinkFile && sink.FilePath == "" {
				errs = append(errs, fmt.Errorf("%s.sinks.file_path is required for file sink", chName))
			}

			if sink.Type == SinkLoki && sink.LokiURL == "" {
				errs = append(errs, fmt.Errorf("%s.sinks.loki_url is required for loki sink", chName))
			}
		}
	}

	if len(errs) > 0 {
		return joinErrs(errs)
	}
	return nil
}

// Clone creates a deep copy of the logging configuration
func (cfg *LoggingConfig) Clone() *LoggingConfig {
	newCfg := &LoggingConfig{}
	*newCfg = *cfg

	// Deep copy channels with their sinks
	channels := []*ChannelConfig{&newCfg.App, &newCfg.Security, &newCfg.Audit}
	originalChannels := []*ChannelConfig{&cfg.App, &cfg.Security, &cfg.Audit}

	for i, ch := range channels {
		originalCh := originalChannels[i]
		ch.Sinks = make([]SinkConfig, len(originalCh.Sinks))
		for j, sink := range originalCh.Sinks {
			ch.Sinks[j] = sink
			// Deep copy LokiLabels map
			if sink.LokiLabels != nil {
				ch.Sinks[j].LokiLabels = maps.Clone(sink.LokiLabels)
			}
		}
	}

	return newCfg
}
