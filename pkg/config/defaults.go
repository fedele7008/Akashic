package config

import "time"

// Default values for simplified configuration

const (
	// Server defaults
	DefaultAuthHost = "0.0.0.0"
	DefaultAuthPort = 8080

	// Control server defaults
	DefaultControlHost         = "127.0.0.1"
	DefaultControlPort         = 8081
	DefaultTLSEnabled          = true
	DefaultClientAuthRequired  = true
	DefaultCertFile            = "./certs/server.crt"
	DefaultKeyFile             = "./certs/server.key"
	DefaultCAFile              = "./certs/ca.crt"

	// Database defaults
	DefaultPostgresSSLMode            = "require"
	DefaultPostgresMaxConnections     = 100
	DefaultPostgresMaxIdleConnections = 10
	DefaultPostgresConnectionLifetime = 1 * time.Hour

	DefaultRedisDB         = 0
	DefaultRedisPoolSize   = 10
	DefaultRedisSessionTTL = 24 * time.Hour
	DefaultRedisCacheTTL   = 1 * time.Hour

	// Session defaults
	DefaultSessionTimeout   = 30 * time.Minute
	DefaultSecureCookies    = true
	DefaultSameSite         = "Strict"
	DefaultCookieName       = "akashic_session"
	DefaultCookiePath       = "/"

	// Deployment defaults
	DefaultEnvironment = EnvDevelopment
	DefaultDebug       = true
)

// FillDefaults fills in default values for optional configuration fields
func (c *Config) FillDefaults() error {
	// Server defaults
	c.Server.Auth.Host = c.Server.Auth.Host.IfNullSet(DefaultAuthHost)
	c.Server.Auth.Port = c.Server.Auth.Port.IfNullSet(DefaultAuthPort)

	// Control server defaults
	c.Server.Control.Host = c.Server.Control.Host.IfNullSet(DefaultControlHost)
	c.Server.Control.Port = c.Server.Control.Port.IfNullSet(DefaultControlPort)
	c.Server.Control.TLS.Enabled = c.Server.Control.TLS.Enabled.IfNullSet(DefaultTLSEnabled)
	c.Server.Control.TLS.CertFile = c.Server.Control.TLS.CertFile.IfNullSet(DefaultCertFile)
	c.Server.Control.TLS.KeyFile = c.Server.Control.TLS.KeyFile.IfNullSet(DefaultKeyFile)
	c.Server.Control.TLS.CAFile = c.Server.Control.TLS.CAFile.IfNullSet(DefaultCAFile)
	c.Server.Control.TLS.ClientAuthRequired = c.Server.Control.TLS.ClientAuthRequired.IfNullSet(DefaultClientAuthRequired)

	// Database defaults
	c.Database.Postgres.SSLMode = c.Database.Postgres.SSLMode.IfNullSet(DefaultPostgresSSLMode)
	c.Database.Postgres.MaxConnections = c.Database.Postgres.MaxConnections.IfNullSet(DefaultPostgresMaxConnections)
	c.Database.Postgres.MaxIdleConnections = c.Database.Postgres.MaxIdleConnections.IfNullSet(DefaultPostgresMaxIdleConnections)
	c.Database.Postgres.ConnectionLifetime = c.Database.Postgres.ConnectionLifetime.IfNullSet(DefaultPostgresConnectionLifetime)

	c.Database.Redis.DB = c.Database.Redis.DB.IfNullSet(DefaultRedisDB)
	c.Database.Redis.PoolSize = c.Database.Redis.PoolSize.IfNullSet(DefaultRedisPoolSize)
	c.Database.Redis.SessionTTL = c.Database.Redis.SessionTTL.IfNullSet(DefaultRedisSessionTTL)
	c.Database.Redis.CacheTTL = c.Database.Redis.CacheTTL.IfNullSet(DefaultRedisCacheTTL)

	// Session defaults
	c.Session.Timeout = c.Session.Timeout.IfNullSet(DefaultSessionTimeout)
	c.Session.SecureCookies = c.Session.SecureCookies.IfNullSet(DefaultSecureCookies)
	c.Session.SameSite = c.Session.SameSite.IfNullSet(DefaultSameSite)
	c.Session.CookieName = c.Session.CookieName.IfNullSet(DefaultCookieName)
	c.Session.CookiePath = c.Session.CookiePath.IfNullSet(DefaultCookiePath)

	// Logging defaults - use the logging package's FillDefaults method
	if err := c.Logging.FillDefaults(); err != nil {
		return err
	}

	// Deployment defaults
	c.Deployment.Environment = c.Deployment.Environment.IfNullSet(DefaultEnvironment)
	c.Deployment.Debug = c.Deployment.Debug.IfNullSet(DefaultDebug)

	return nil
}