package config

import (
	"akashic/akashic/pkg/logging"
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

// Root configuration
type Config struct {
	// Server configuration for API endpoints
	Server ServerConfig `mapstructure:"server" yaml:"server"`
	// Database connections (PostgreSQL and Redis)
	Database DatabaseConfig `mapstructure:"database" yaml:"database"`
	// Session management settings
	Session SessionConfig `mapstructure:"session" yaml:"session"`
	// Logging configuration (multi-sink system) - handled separately in postProcessConfig
	Logging logging.Config `mapstructure:"-" yaml:"-"`
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
