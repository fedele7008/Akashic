package config

import (
	"akashic/akashic/pkg/common"
	"akashic/akashic/pkg/logging"
	"time"
)

type Optional[T any] = common.Nullable[T]
type Required[T any] = common.Nullable[T]

func SetOptional[T any](val ...T) Optional[T] {
	switch len(val) {
	case 0:
		return common.EmptyNullable[T]()
	case 1:
		return common.MakeNullable[T](val[0])
	default:
		return common.EmptyNullable[T]()
	}
}

func SetRequired[T any](val T) Required[T] {
	return common.MakeNullable(val)
}

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

// Root configuration
type Config struct {
	// Server configuration for API endpoints
	Server ServerConfig `mapstructure:"server" yaml:"server"`
	// Database connections (PostgreSQL and Redis)
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`
	// Session management settings
	Session SessionConfig `mapstructure:"session" yaml:"session"`
	// Logging configuration (multi-sink system)
	Logging logging.Config `mapstructure:"logging" yaml:"logging"`
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
	Host Required[string] `mapstructure:"host" yaml:"host"`
	// Port number for the auth server (typically 8080)
	Port Required[int] `mapstructure:"port" yaml:"port"`
}

// ControlServerConfig defines control plane management server settings
type ControlServerConfig struct {
	// Host address to bind the control server (e.g., "127.0.0.1" for localhost only)
	Host Required[string] `mapstructure:"host" yaml:"host"`
	// Port number for the control server (typically 8081)
	Port Required[int] `mapstructure:"port" yaml:"port"`
	// TLS configuration for mTLS with self-signed certificates
	TLS TLSConfig `mapstructure:"tls" yaml:"tls"`
}

// TLSConfig defines TLS/mTLS settings for the control server
type TLSConfig struct {
	// Enabled controls whether TLS is enabled (should always be true for control server)
	Enabled Required[bool] `mapstructure:"enabled" yaml:"enabled"`
	// CertFile path to the server certificate file (self-signed)
	CertFile Required[string] `mapstructure:"cert_file" yaml:"cert_file"`
	// KeyFile path to the server private key file
	KeyFile Required[string] `mapstructure:"key_file" yaml:"key_file"`
	// CAFile path to the Certificate Authority file for client verification
	CAFile Required[string] `mapstructure:"ca_file" yaml:"ca_file"`
	// ClientAuthRequired enforces mutual TLS (client certificates required)
	ClientAuthRequired Optional[bool] `mapstructure:"client_auth_required" yaml:"client_auth_required"`
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
	Host Required[string] `mapstructure:"host" yaml:"host"`
	// Port number (typically 5432)
	Port Required[int] `mapstructure:"port" yaml:"port"`
	// Database name
	Database Required[string] `mapstructure:"database" yaml:"database"`
	// Username for authentication
	Username Required[string] `mapstructure:"username" yaml:"username"`
	// Password for authentication (use environment variables)
	Password Required[string] `mapstructure:"password" yaml:"password"`
	// SSLMode for connection security (disable, require, verify-ca, verify-full)
	SSLMode Optional[string] `mapstructure:"ssl_mode" yaml:"ssl_mode"`
	// MaxConnections for connection pool
	MaxConnections Optional[int] `mapstructure:"max_connections" yaml:"max_connections"`
	// MaxIdleConnections for connection pool
	MaxIdleConnections Optional[int] `mapstructure:"max_idle_connections" yaml:"max_idle_connections"`
	// ConnectionLifetime for connection reuse
	ConnectionLifetime Optional[time.Duration] `mapstructure:"connection_lifetime" yaml:"connection_lifetime"`
}

// RedisConfig defines Redis connection settings
type RedisConfig struct {
	// Host address of Redis server
	Host Required[string] `mapstructure:"host" yaml:"host"`
	// Port number (typically 6379)
	Port Required[int] `mapstructure:"port" yaml:"port"`
	// Password for authentication (optional)
	Password Optional[string] `mapstructure:"password" yaml:"password"`
	// DB number to select (0-15, typically 0)
	DB Optional[int] `mapstructure:"db" yaml:"db"`
	// PoolSize for connection pool
	PoolSize Optional[int] `mapstructure:"pool_size" yaml:"pool_size"`
	// SessionTTL for session storage
	SessionTTL Optional[time.Duration] `mapstructure:"session_ttl" yaml:"session_ttl"`
	// CacheTTL for general caching
	CacheTTL Optional[time.Duration] `mapstructure:"cache_ttl" yaml:"cache_ttl"`
}

// SessionConfig contains basic session management settings
type SessionConfig struct {
	// Timeout for session expiration
	Timeout Optional[time.Duration] `mapstructure:"timeout" yaml:"timeout"`
	// SecureCookies enforces secure flag on cookies
	SecureCookies Optional[bool] `mapstructure:"secure_cookies" yaml:"secure_cookies"`
	// SameSite cookie attribute (Strict, Lax, None)
	SameSite Optional[string] `mapstructure:"same_site" yaml:"same_site"`
	// CookieName for session cookies
	CookieName Optional[string] `mapstructure:"cookie_name" yaml:"cookie_name"`
	// CookiePath for session cookies
	CookiePath Optional[string] `mapstructure:"cookie_path" yaml:"cookie_path"`
}

// DeploymentConfig defines basic deployment settings
type DeploymentConfig struct {
	// Environment (development, staging, production)
	Environment Required[Environment] `mapstructure:"environment" yaml:"environment"`
	// Debug enables debug features
	Debug Optional[bool] `mapstructure:"debug" yaml:"debug"`
}
