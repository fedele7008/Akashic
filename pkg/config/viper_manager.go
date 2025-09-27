package config

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"akashic/akashic/pkg/logging"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// ViperManager handles configuration using Viper library
type ViperManager struct {
	viper            *viper.Viper
	config           *Config
	configMutex      sync.RWMutex
	listeners        map[string][]ChangeListener
	listenersMutex   sync.RWMutex
	logger           *logging.Logger
	environment      string
	hotReloadEnabled bool
}

type ViperManagerOption func(*ViperManager)

func WithViperLogger(logger *logging.Logger) ViperManagerOption {
	return func(m *ViperManager) {
		m.logger = logger
	}
}

func WithViperEnvironment(env string) ViperManagerOption {
	return func(m *ViperManager) {
		m.environment = env
	}
}

func WithViperHotReload(enabled bool) ViperManagerOption {
	return func(m *ViperManager) {
		m.hotReloadEnabled = enabled
	}
}

// NewViperManager creates a new configuration manager using Viper
func NewViperManager(configName string, opts ...ViperManagerOption) (*ViperManager, error) {
	v := viper.New()

	m := &ViperManager{
		viper:            v,
		listeners:        make(map[string][]ChangeListener),
		environment:      string(EnvDevelopment),
		hotReloadEnabled: true,
	}

	for _, opt := range opts {
		opt(m)
	}

	// Configure viper
	m.setupViper(configName)

	// Load configuration
	if err := m.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load initial configuration: %w", err)
	}

	// Setup hot reload if enabled
	if m.hotReloadEnabled {
		m.setupHotReload()
	}

	return m, nil
}

func (m *ViperManager) setupViper(configName string) {
	// Set config name (without extension)
	if configName != "" {
		m.viper.SetConfigName(configName)
	} else {
		m.viper.SetConfigName("config")
	}

	// Set config type
	m.viper.SetConfigType("yaml")

	// Add config paths
	m.viper.AddConfigPath(".")
	m.viper.AddConfigPath("./configs")
	m.viper.AddConfigPath("/etc/akashic")

	// Environment variable settings
	m.viper.SetEnvPrefix("AKASHIC")
	m.viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	m.viper.AutomaticEnv()

	// Set defaults
	m.setDefaults()
}

func (m *ViperManager) setDefaults() {
	// Server defaults
	m.viper.SetDefault("server.auth.host", DefaultAuthHost)
	m.viper.SetDefault("server.auth.port", DefaultAuthPort)
	m.viper.SetDefault("server.control.host", DefaultControlHost)
	m.viper.SetDefault("server.control.port", DefaultControlPort)
	m.viper.SetDefault("server.control.tls.enabled", DefaultTLSEnabled)
	m.viper.SetDefault("server.control.tls.cert_file", DefaultCertFile)
	m.viper.SetDefault("server.control.tls.key_file", DefaultKeyFile)
	m.viper.SetDefault("server.control.tls.ca_file", DefaultCAFile)
	m.viper.SetDefault("server.control.tls.client_auth_required", DefaultClientAuthRequired)

	// Database defaults
	m.viper.SetDefault("database.postgres.host", "localhost")
	m.viper.SetDefault("database.postgres.port", 5432)
	m.viper.SetDefault("database.postgres.database", "akashic")
	m.viper.SetDefault("database.postgres.username", "akashic_user")
	m.viper.SetDefault("database.postgres.password", "${POSTGRES_PASSWORD}")
	m.viper.SetDefault("database.postgres.ssl_mode", DefaultPostgresSSLMode)
	m.viper.SetDefault("database.postgres.max_connections", DefaultPostgresMaxConnections)
	m.viper.SetDefault("database.postgres.max_idle_connections", DefaultPostgresMaxIdleConnections)
	m.viper.SetDefault("database.postgres.connection_lifetime", DefaultPostgresConnectionLifetime)

	m.viper.SetDefault("database.redis.host", "localhost")
	m.viper.SetDefault("database.redis.port", 6379)
	m.viper.SetDefault("database.redis.password", "${REDIS_PASSWORD}")
	m.viper.SetDefault("database.redis.db", DefaultRedisDB)
	m.viper.SetDefault("database.redis.pool_size", DefaultRedisPoolSize)
	m.viper.SetDefault("database.redis.session_ttl", DefaultRedisSessionTTL)
	m.viper.SetDefault("database.redis.cache_ttl", DefaultRedisCacheTTL)

	// Session defaults
	m.viper.SetDefault("session.timeout", DefaultSessionTimeout)
	m.viper.SetDefault("session.secure_cookies", DefaultSecureCookies)
	m.viper.SetDefault("session.same_site", DefaultSameSite)
	m.viper.SetDefault("session.cookie_name", DefaultCookieName)
	m.viper.SetDefault("session.cookie_path", DefaultCookiePath)

	// Logging defaults
	m.viper.SetDefault("logging.service_name", "akashic")
	m.viper.SetDefault("logging.env", m.environment)

	// Deployment defaults
	m.viper.SetDefault("deployment.environment", m.environment)
	m.viper.SetDefault("deployment.debug", DefaultDebug)
}

func (m *ViperManager) LoadConfig() error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()

	// Try to read config file
	if err := m.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults
		m.logInfo("No config file found, using defaults and environment variables")
	} else {
		m.logInfo("Config file loaded", "file", m.viper.ConfigFileUsed())
	}

	// Create config struct and fill it from viper values
	config := &Config{}
	if err := m.applyEnvironmentAndDefaults(config); err != nil {
		return fmt.Errorf("failed to apply environment and defaults: %w", err)
	}

	// Validate configuration
	if err := m.validateViperConfig(config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	oldConfig := m.config
	m.config = config

	// Notify listeners of config change
	if oldConfig != nil {
		m.notifyConfigChange(oldConfig, m.config)
	}

	return nil
}

func (m *ViperManager) applyEnvironmentAndDefaults(config *Config) error {
	// Server configuration
	config.Server.Auth.Host = SetRequired(m.viper.GetString("server.auth.host"))
	config.Server.Auth.Port = SetRequired(m.viper.GetInt("server.auth.port"))

	config.Server.Control.Host = SetRequired(m.viper.GetString("server.control.host"))
	config.Server.Control.Port = SetRequired(m.viper.GetInt("server.control.port"))
	config.Server.Control.TLS.Enabled = SetRequired(m.viper.GetBool("server.control.tls.enabled"))
	config.Server.Control.TLS.CertFile = SetRequired(m.viper.GetString("server.control.tls.cert_file"))
	config.Server.Control.TLS.KeyFile = SetRequired(m.viper.GetString("server.control.tls.key_file"))
	config.Server.Control.TLS.CAFile = SetRequired(m.viper.GetString("server.control.tls.ca_file"))
	config.Server.Control.TLS.ClientAuthRequired = SetOptional(m.viper.GetBool("server.control.tls.client_auth_required"))

	// Database configuration
	config.Database.Postgres.Host = SetRequired(m.viper.GetString("database.postgres.host"))
	config.Database.Postgres.Port = SetRequired(m.viper.GetInt("database.postgres.port"))
	config.Database.Postgres.Database = SetRequired(m.viper.GetString("database.postgres.database"))
	config.Database.Postgres.Username = SetRequired(m.viper.GetString("database.postgres.username"))
	config.Database.Postgres.Password = SetRequired(m.viper.GetString("database.postgres.password"))
	config.Database.Postgres.SSLMode = SetOptional(m.viper.GetString("database.postgres.ssl_mode"))
	config.Database.Postgres.MaxConnections = SetOptional(m.viper.GetInt("database.postgres.max_connections"))
	config.Database.Postgres.MaxIdleConnections = SetOptional(m.viper.GetInt("database.postgres.max_idle_connections"))
	config.Database.Postgres.ConnectionLifetime = SetOptional(m.viper.GetDuration("database.postgres.connection_lifetime"))

	config.Database.Redis.Host = SetRequired(m.viper.GetString("database.redis.host"))
	config.Database.Redis.Port = SetRequired(m.viper.GetInt("database.redis.port"))
	config.Database.Redis.Password = SetOptional(m.viper.GetString("database.redis.password"))
	config.Database.Redis.DB = SetOptional(m.viper.GetInt("database.redis.db"))
	config.Database.Redis.PoolSize = SetOptional(m.viper.GetInt("database.redis.pool_size"))
	config.Database.Redis.SessionTTL = SetOptional(m.viper.GetDuration("database.redis.session_ttl"))
	config.Database.Redis.CacheTTL = SetOptional(m.viper.GetDuration("database.redis.cache_ttl"))

	// Session configuration
	config.Session.Timeout = SetOptional(m.viper.GetDuration("session.timeout"))
	config.Session.SecureCookies = SetOptional(m.viper.GetBool("session.secure_cookies"))
	config.Session.SameSite = SetOptional(m.viper.GetString("session.same_site"))
	config.Session.CookieName = SetOptional(m.viper.GetString("session.cookie_name"))
	config.Session.CookiePath = SetOptional(m.viper.GetString("session.cookie_path"))

	// Logging configuration - create a default logging config
	config.Logging = *logging.GetConfig(
		m.viper.GetString("logging.service_name"),
		m.viper.GetString("logging.env"),
	)

	// Deployment configuration
	config.Deployment.Environment = SetRequired(Environment(m.viper.GetString("deployment.environment")))
	config.Deployment.Debug = SetOptional(m.viper.GetBool("deployment.debug"))

	return nil
}

func (m *ViperManager) validateViperConfig(config *Config) error {
	// Use the existing validation logic
	validator := NewValidator()

	// Validate server config
	if host := config.Server.Auth.Host.GetOrDefault(); host == "" {
		validator.AddError("server.auth.host", "auth server host is required")
	}
	if port := config.Server.Auth.Port.GetOrDefault(); port <= 0 || port > 65535 {
		validator.AddError("server.auth.port", "invalid auth server port")
	}

	if host := config.Server.Control.Host.GetOrDefault(); host == "" {
		validator.AddError("server.control.host", "control server host is required")
	}
	if port := config.Server.Control.Port.GetOrDefault(); port <= 0 || port > 65535 {
		validator.AddError("server.control.port", "invalid control server port")
	}

	// Validate database config
	if host := config.Database.Postgres.Host.GetOrDefault(); host == "" {
		validator.AddError("database.postgres.host", "PostgreSQL host is required")
	}
	if db := config.Database.Postgres.Database.GetOrDefault(); db == "" {
		validator.AddError("database.postgres.database", "PostgreSQL database name is required")
	}

	if host := config.Database.Redis.Host.GetOrDefault(); host == "" {
		validator.AddError("database.redis.host", "Redis host is required")
	}

	return validator.Error()
}

func (m *ViperManager) setupHotReload() {
	m.viper.WatchConfig()
	m.viper.OnConfigChange(func(e fsnotify.Event) {
		m.logInfo("Config file changed, reloading...")
		if err := m.LoadConfig(); err != nil {
			m.logError("Failed to reload configuration", "error", err)
		}
	})
}

func (m *ViperManager) GetConfig() *Config {
	m.configMutex.RLock()
	defer m.configMutex.RUnlock()
	return m.config
}

func (m *ViperManager) GetViper() *viper.Viper {
	return m.viper
}

func (m *ViperManager) AddListener(component string, listener ChangeListener) {
	m.listenersMutex.Lock()
	defer m.listenersMutex.Unlock()

	if m.listeners[component] == nil {
		m.listeners[component] = []ChangeListener{}
	}
	m.listeners[component] = append(m.listeners[component], listener)
}

func (m *ViperManager) notifyConfigChange(oldConfig, newConfig *Config) {
	m.listenersMutex.RLock()
	defer m.listenersMutex.RUnlock()

	event := ChangeEvent{
		Type:      ChangeTypeReload,
		Component: "config",
		Key:       "full_reload",
		Timestamp: time.Now(),
	}

	for component, listeners := range m.listeners {
		for _, listener := range listeners {
			go func(comp string, l ChangeListener) {
				if err := l(event); err != nil {
					m.logError("Config change listener failed", "component", comp, "error", err)
				}
			}(component, listener)
		}
	}
}

func (m *ViperManager) Close() error {
	// Viper doesn't need explicit cleanup
	return nil
}

// Helper methods for logging
func (m *ViperManager) logInfo(msg string, args ...interface{}) {
	if m.logger != nil {
		fields := m.formatLogArgs(args...)
		m.logger.App.Info(msg, fields...)
	}
}

func (m *ViperManager) logError(msg string, args ...interface{}) {
	if m.logger != nil {
		fields := m.formatLogArgs(args...)
		m.logger.App.Error(msg, fields...)
	}
}

func (m *ViperManager) formatLogArgs(args ...interface{}) []zap.Field {
	fields := make([]zap.Field, 0, len(args)/2)

	for i := 0; i < len(args)-1; i += 2 {
		if key, ok := args[i].(string); ok {
			value := args[i+1]
			switch v := value.(type) {
			case string:
				fields = append(fields, zap.String(key, v))
			case int:
				fields = append(fields, zap.Int(key, v))
			case int64:
				fields = append(fields, zap.Int64(key, v))
			case float64:
				fields = append(fields, zap.Float64(key, v))
			case bool:
				fields = append(fields, zap.Bool(key, v))
			case error:
				fields = append(fields, zap.Error(v))
			case time.Duration:
				fields = append(fields, zap.Duration(key, v))
			default:
				fields = append(fields, zap.Any(key, v))
			}
		}
	}

	return fields
}

// GetAllSettings returns all configuration settings as a map
func (m *ViperManager) GetAllSettings() map[string]interface{} {
	return m.viper.AllSettings()
}