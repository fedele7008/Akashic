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
	ServiceName      string        `mapstructure:"service_name" yaml:"service_name"`
	Environment      string        `mapstructure:"environment" yaml:"environment"`
	EncoderConfig    EncoderConfig `mapstructure:"encoder" yaml:"encoder"`
	App              ChannelConfig `mapstructure:"app" yaml:"app"`
	Security         ChannelConfig `mapstructure:"security" yaml:"security"`
	Audit            ChannelConfig `mapstructure:"audit" yaml:"audit"`
	ForceAuditAppend bool          `mapstructure:"force_audit_append" yaml:"force_audit_append"`
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
}

// ServerConfig contains basic server settings
type ServerConfig struct {
	// Auth server configuration for OAuth/OIDC endpoints
	Auth AuthServerConfig `mapstructure:"auth" yaml:"auth"`
	// Control server configuration for control plane management via mTLS
	Control ControlServerConfig `mapstructure:"control" yaml:"control"`
}

// AuthServerConfig defines OAuth/OIDC authentication server settings
type AuthServerConfig struct {
	// Host address to bind the server (e.g., "0.0.0.0", "localhost")
	Host string `mapstructure:"host" yaml:"host"`
	// Port number for the auth server (typically 8080)
	Port int `mapstructure:"port" yaml:"port"`
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
	// SSLMode for connection security (disable, require, verify-ca, verify-full)
	SSLMode string `mapstructure:"ssl_mode" yaml:"ssl_mode"`
	// MaxConnections for connection pool
	MaxConnections int `mapstructure:"max_connections" yaml:"max_connections"`
	// MaxIdleConnections for connection pool
	MaxIdleConnections int `mapstructure:"max_idle_connections" yaml:"max_idle_connections"`
	// ConnectionLifetime for connection reuse
	ConnectionLifetime time.Duration `mapstructure:"connection_lifetime" yaml:"connection_lifetime"`
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

	// UseTLS enables TLS/LDAPS connection
	UseTLS bool `mapstructure:"use_tls" yaml:"use_tls"`

	// TLSSkipVerify skips TLS certificate verification (insecure - dev only)
	TLSSkipVerify bool `mapstructure:"tls_skip_verify" yaml:"tls_skip_verify"`

	// UserSearchBase is the base DN for user searches
	// Example: "ou=users,dc=akashic,dc=local"
	UserSearchBase string `mapstructure:"user_search_base" yaml:"user_search_base"`

	// UserSearchFilter is the LDAP filter for finding users
	// Use {username} as placeholder. Example: "(uid={username})"
	UserSearchFilter string `mapstructure:"user_search_filter" yaml:"user_search_filter"`

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
