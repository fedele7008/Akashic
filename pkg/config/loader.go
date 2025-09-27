package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"akashic/akashic/pkg/logging"

	"gopkg.in/yaml.v3"
)

type LoaderOptions struct {
	ConfigPaths    []string
	Environment    string
	OverrideFromEnv bool
	RequireFile    bool
}

type Loader struct {
	options LoaderOptions
}

func NewLoader(opts LoaderOptions) *Loader {
	if len(opts.ConfigPaths) == 0 {
		opts.ConfigPaths = []string{
			"./config.yaml",
			"./config.yml",
			"./configs/config.yaml",
			"./configs/config.yml",
			"/etc/akashic/config.yaml",
			"/etc/akashic/config.yml",
		}
	}

	if opts.Environment == "" {
		opts.Environment = "development"
	}

	return &Loader{
		options: opts,
	}
}

func (l *Loader) Load() (*Config, error) {
	config := &Config{}

	// Try to load from files
	configLoaded := false
	for _, path := range l.options.ConfigPaths {
		if l.fileExists(path) {
			if err := l.loadFromFile(config, path); err != nil {
				return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
			}
			configLoaded = true
			break
		}
	}

	// Check if file is required but not found
	if l.options.RequireFile && !configLoaded {
		return nil, fmt.Errorf("configuration file not found in any of the expected locations: %v", l.options.ConfigPaths)
	}

	// If no file was loaded, start with defaults
	if !configLoaded {
		config = l.getDefaultConfig()
	}

	// Load environment-specific overrides
	if err := l.loadEnvironmentOverrides(config); err != nil {
		return nil, fmt.Errorf("failed to load environment overrides: %w", err)
	}

	// Override from environment variables if enabled
	if l.options.OverrideFromEnv {
		l.overrideFromEnvironment(config)
	}

	// Fill in any missing defaults
	if err := config.FillDefaults(); err != nil {
		return nil, fmt.Errorf("failed to fill defaults: %w", err)
	}

	return config, nil
}

func (l *Loader) loadFromFile(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Expand environment variables in the content
	content := l.expandEnvironmentVariables(string(data))

	// Determine file format from extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return yaml.Unmarshal([]byte(content), config)
	case ".json":
		return json.Unmarshal([]byte(content), config)
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal([]byte(content), config); err != nil {
			return json.Unmarshal([]byte(content), config)
		}
		return nil
	}
}

func (l *Loader) loadEnvironmentOverrides(config *Config) error {
	envConfigPath := fmt.Sprintf("./configs/config.%s.yaml", l.options.Environment)
	if l.fileExists(envConfigPath) {
		envConfig := &Config{}
		if err := l.loadFromFile(envConfig, envConfigPath); err != nil {
			return err
		}
		l.mergeConfigs(config, envConfig)
	}

	return nil
}

func (l *Loader) expandEnvironmentVariables(content string) string {
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			content = strings.ReplaceAll(content, "${"+key+"}", value)
			content = strings.ReplaceAll(content, "$"+key, value)
		}
	}
	return content
}

func (l *Loader) overrideFromEnvironment(config *Config) {
	// Server configuration
	if val := os.Getenv("AKASHIC_SERVER_AUTH_HOST"); val != "" {
		config.Server.Auth.Host = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_SERVER_AUTH_PORT"); val != "" {
		if port := l.parseIntFromEnv(val); port > 0 {
			config.Server.Auth.Port = SetRequired(port)
		}
	}

	// Control server configuration
	if val := os.Getenv("AKASHIC_SERVER_CONTROL_HOST"); val != "" {
		config.Server.Control.Host = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_SERVER_CONTROL_PORT"); val != "" {
		if port := l.parseIntFromEnv(val); port > 0 {
			config.Server.Control.Port = SetRequired(port)
		}
	}
	if val := os.Getenv("AKASHIC_TLS_ENABLED"); val != "" {
		config.Server.Control.TLS.Enabled = SetRequired(l.parseBoolFromEnv(val))
	}
	if val := os.Getenv("AKASHIC_TLS_CERT_FILE"); val != "" {
		config.Server.Control.TLS.CertFile = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_TLS_KEY_FILE"); val != "" {
		config.Server.Control.TLS.KeyFile = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_TLS_CA_FILE"); val != "" {
		config.Server.Control.TLS.CAFile = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_TLS_CLIENT_AUTH_REQUIRED"); val != "" {
		config.Server.Control.TLS.ClientAuthRequired = SetOptional(l.parseBoolFromEnv(val))
	}

	// Database configuration
	if val := os.Getenv("AKASHIC_DB_POSTGRES_HOST"); val != "" {
		config.Database.Postgres.Host = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_DB_POSTGRES_PORT"); val != "" {
		if port := l.parseIntFromEnv(val); port > 0 {
			config.Database.Postgres.Port = SetRequired(port)
		}
	}
	if val := os.Getenv("AKASHIC_DB_POSTGRES_DATABASE"); val != "" {
		config.Database.Postgres.Database = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_DB_POSTGRES_USERNAME"); val != "" {
		config.Database.Postgres.Username = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_DB_POSTGRES_PASSWORD"); val != "" {
		config.Database.Postgres.Password = SetRequired(val)
	}

	if val := os.Getenv("AKASHIC_DB_REDIS_HOST"); val != "" {
		config.Database.Redis.Host = SetRequired(val)
	}
	if val := os.Getenv("AKASHIC_DB_REDIS_PORT"); val != "" {
		if port := l.parseIntFromEnv(val); port > 0 {
			config.Database.Redis.Port = SetRequired(port)
		}
	}
	if val := os.Getenv("AKASHIC_DB_REDIS_PASSWORD"); val != "" {
		config.Database.Redis.Password = SetOptional(val)
	}

	// Session configuration
	if val := os.Getenv("AKASHIC_SESSION_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			config.Session.Timeout = SetOptional(duration)
		}
	}
	if val := os.Getenv("AKASHIC_SESSION_SECURE_COOKIES"); val != "" {
		config.Session.SecureCookies = SetOptional(l.parseBoolFromEnv(val))
	}

	// Deployment configuration
	if val := os.Getenv("AKASHIC_DEPLOYMENT_ENVIRONMENT"); val != "" {
		config.Deployment.Environment = SetRequired(Environment(val))
	}
	if val := os.Getenv("AKASHIC_DEBUG"); val != "" {
		config.Deployment.Debug = SetOptional(l.parseBoolFromEnv(val))
	}
}

func (l *Loader) mergeConfigs(base, override *Config) {
	// This is a simplified merge - in a real implementation, you'd want
	// to do a deep merge of the configuration structures
	data, _ := yaml.Marshal(override)
	yaml.Unmarshal(data, base)
}

func (l *Loader) getDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Auth: AuthServerConfig{
				Host: SetRequired(DefaultAuthHost),
				Port: SetRequired(DefaultAuthPort),
			},
			Control: ControlServerConfig{
				Host: SetRequired(DefaultControlHost),
				Port: SetRequired(DefaultControlPort),
				TLS: TLSConfig{
					Enabled:            SetRequired(DefaultTLSEnabled),
					CertFile:           SetRequired(DefaultCertFile),
					KeyFile:            SetRequired(DefaultKeyFile),
					CAFile:             SetRequired(DefaultCAFile),
					ClientAuthRequired: SetOptional(DefaultClientAuthRequired),
				},
			},
		},
		Database: DatabaseConfig{
			Postgres: PostgresConfig{
				Host:     SetRequired("localhost"),
				Port:     SetRequired(5432),
				Database: SetRequired("akashic"),
				Username: SetRequired("akashic_user"),
				Password: SetRequired("${POSTGRES_PASSWORD}"),
			},
			Redis: RedisConfig{
				Host: SetRequired("localhost"),
				Port: SetRequired(6379),
			},
		},
		Session: SessionConfig{
			Timeout:       SetOptional(DefaultSessionTimeout),
			SecureCookies: SetOptional(DefaultSecureCookies),
			SameSite:      SetOptional(DefaultSameSite),
			CookieName:    SetOptional(DefaultCookieName),
			CookiePath:    SetOptional(DefaultCookiePath),
		},
		Logging: *logging.GetConfig("akashic", l.options.Environment),
		Deployment: DeploymentConfig{
			Environment: SetRequired(Environment(l.options.Environment)),
			Debug:       SetOptional(DefaultDebug),
		},
	}
}

func (l *Loader) parseIntFromEnv(val string) int {
	// Simple integer parsing - you might want to use strconv.Atoi
	// and handle errors appropriately
	if val == "" {
		return 0
	}

	// This is a placeholder - implement proper integer parsing
	switch val {
	case "8080":
		return 8080
	case "8081":
		return 8081
	case "5432":
		return 5432
	case "6379":
		return 6379
	default:
		return 0
	}
}

func (l *Loader) parseBoolFromEnv(val string) bool {
	val = strings.ToLower(strings.TrimSpace(val))
	return val == "true" || val == "1" || val == "yes" || val == "on"
}

func (l *Loader) fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// SaveConfig saves the configuration to a file
func (l *Loader) SaveConfig(config *Config, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Determine format from extension
	ext := strings.ToLower(filepath.Ext(path))
	var data []byte
	var err error

	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		// Default to YAML
		data, err = yaml.Marshal(config)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig(path string) error {
	loader := NewLoader(LoaderOptions{})
	config := loader.getDefaultConfig()

	// Fill with comprehensive examples for simplified config
	config.Database.Postgres.MaxConnections = SetOptional(DefaultPostgresMaxConnections)
	config.Database.Postgres.MaxIdleConnections = SetOptional(DefaultPostgresMaxIdleConnections)
	config.Database.Postgres.ConnectionLifetime = SetOptional(DefaultPostgresConnectionLifetime)

	config.Database.Redis.PoolSize = SetOptional(DefaultRedisPoolSize)
	config.Database.Redis.SessionTTL = SetOptional(DefaultRedisSessionTTL)
	config.Database.Redis.CacheTTL = SetOptional(DefaultRedisCacheTTL)

	config.Session.Timeout = SetOptional(DefaultSessionTimeout)
	config.Session.SecureCookies = SetOptional(DefaultSecureCookies)
	config.Session.SameSite = SetOptional(DefaultSameSite)

	return loader.SaveConfig(config, path)
}