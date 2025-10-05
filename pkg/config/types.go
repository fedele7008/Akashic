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
	// General deployment settings
	Deployment DeploymentConfig `mapstructure:"deployment" yaml:"deployment"`
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
