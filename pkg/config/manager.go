package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"akashic/akashic/pkg/logging"

	"go.uber.org/zap"

	"gopkg.in/yaml.v3"
)

type ChangeEvent struct {
	Type      ChangeType  `json:"type"`
	Component string      `json:"component"`
	Key       string      `json:"key"`
	OldValue  interface{} `json:"old_value,omitempty"`
	NewValue  interface{} `json:"new_value,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

type ChangeType string

const (
	ChangeTypeCreate ChangeType = "create"
	ChangeTypeUpdate ChangeType = "update"
	ChangeTypeDelete ChangeType = "delete"
	ChangeTypeReload ChangeType = "reload"
)

type ChangeListener func(event ChangeEvent) error

type Manager struct {
	config           *Config
	configPath       string
	configMutex      sync.RWMutex
	listeners        map[string][]ChangeListener
	listenersMutex   sync.RWMutex
	watchContext     context.Context
	watchCancel      context.CancelFunc
	logger           *logging.Logger
	environment      string
	hotReloadEnabled bool
}

type ManagerOption func(*Manager)

func WithLogger(logger *logging.Logger) ManagerOption {
	return func(m *Manager) {
		m.logger = logger
	}
}

func WithEnvironment(env string) ManagerOption {
	return func(m *Manager) {
		m.environment = env
	}
}

func WithHotReload(enabled bool) ManagerOption {
	return func(m *Manager) {
		m.hotReloadEnabled = enabled
	}
}

func NewManager(configPath string, opts ...ManagerOption) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		configPath:       configPath,
		listeners:        make(map[string][]ChangeListener),
		watchContext:     ctx,
		watchCancel:      cancel,
		environment:      string(EnvDevelopment),
		hotReloadEnabled: true,
	}

	for _, opt := range opts {
		opt(m)
	}

	if err := m.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load initial configuration: %w", err)
	}

	if m.hotReloadEnabled {
		go m.watchConfigFile()
	}

	return m, nil
}

func (m *Manager) LoadConfig() error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()

	config, err := m.loadConfigFromFile()
	if err != nil {
		return err
	}

	oldConfig := m.config
	m.config = config

	if err := m.config.FillDefaults(); err != nil {
		return fmt.Errorf("failed to fill defaults: %w", err)
	}

	if err := m.validateConfig(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	if oldConfig != nil {
		m.notifyConfigChange(oldConfig, m.config)
	}

	return nil
}

func (m *Manager) loadConfigFromFile() (*Config, error) {
	if m.configPath == "" {
		return m.getDefaultConfig(), nil
	}

	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		m.logInfo("Configuration file not found, using defaults", "path", m.configPath)
		return m.getDefaultConfig(), nil
	}

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	data = m.expandEnvironmentVariables(data)

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

func (m *Manager) expandEnvironmentVariables(data []byte) []byte {
	content := string(data)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := parts[0]
			value := parts[1]
			content = strings.ReplaceAll(content, "${"+key+"}", value)
			content = strings.ReplaceAll(content, "$"+key, value)
		}
	}
	return []byte(content)
}

func (m *Manager) getDefaultConfig() *Config {
	config := &Config{
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
				Host:     SetRequired("localhost"),
				Port:     SetRequired(6379),
				Password: SetOptional("${REDIS_PASSWORD}"),
			},
		},
		Session: SessionConfig{
			Timeout:       SetOptional(DefaultSessionTimeout),
			SecureCookies: SetOptional(DefaultSecureCookies),
			SameSite:      SetOptional(DefaultSameSite),
			CookieName:    SetOptional(DefaultCookieName),
			CookiePath:    SetOptional(DefaultCookiePath),
		},
		Logging: *logging.GetConfig("akashic", m.environment),
		Deployment: DeploymentConfig{
			Environment: SetRequired(Environment(m.environment)),
			Debug:       SetOptional(DefaultDebug),
		},
	}

	return config
}

func (m *Manager) validateConfig() error {
	var errs []error

	// Validate required fields
	if _, ok := m.config.Server.Auth.Host.Get(); !ok {
		errs = append(errs, errors.New("server.auth.host is required"))
	}
	if _, ok := m.config.Server.Auth.Port.Get(); !ok {
		errs = append(errs, errors.New("server.auth.port is required"))
	}

	// Validate database connection settings
	if _, ok := m.config.Database.Postgres.Host.Get(); !ok {
		errs = append(errs, errors.New("database.postgres.host is required"))
	}
	if _, ok := m.config.Database.Postgres.Database.Get(); !ok {
		errs = append(errs, errors.New("database.postgres.database is required"))
	}
	if _, ok := m.config.Database.Redis.Host.Get(); !ok {
		errs = append(errs, errors.New("database.redis.host is required"))
	}

	// Validate deployment environment
	if env, ok := m.config.Deployment.Environment.Get(); ok {
		validEnvs := []Environment{EnvDevelopment, EnvStaging, EnvProduction}
		found := false
		for _, validEnv := range validEnvs {
			if env == validEnv {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, errors.New("deployment.environment must be development, staging, or production"))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (m *Manager) GetConfig() *Config {
	m.configMutex.RLock()
	defer m.configMutex.RUnlock()
	return m.config
}

func (m *Manager) UpdateConfig(updates map[string]interface{}) error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()

	oldConfig := m.cloneConfig(m.config)

	if err := m.applyUpdates(updates); err != nil {
		return fmt.Errorf("failed to apply updates: %w", err)
	}

	if err := m.validateConfig(); err != nil {
		m.config = oldConfig
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	m.notifyConfigChange(oldConfig, m.config)

	if m.configPath != "" {
		if err := m.saveConfigToFile(); err != nil {
			m.logError("Failed to save configuration to file", "error", err)
		}
	}

	return nil
}

func (m *Manager) applyUpdates(updates map[string]interface{}) error {
	for key, value := range updates {
		if err := m.setConfigValue(key, value); err != nil {
			return fmt.Errorf("failed to set config value %s: %w", key, err)
		}
	}
	return nil
}

func (m *Manager) setConfigValue(key string, value interface{}) error {
	parts := strings.Split(key, ".")
	if len(parts) < 2 {
		return fmt.Errorf("invalid config key format: %s", key)
	}

	switch parts[0] {
	case "server":
		return m.setServerConfig(parts[1:], value)
	case "database":
		return m.setDatabaseConfig(parts[1:], value)
	case "session":
		return m.setSessionConfig(parts[1:], value)
	case "deployment":
		return m.setDeploymentConfig(parts[1:], value)
	default:
		return fmt.Errorf("unknown config section: %s", parts[0])
	}
}

func (m *Manager) setServerConfig(parts []string, value interface{}) error {
	if len(parts) < 2 {
		return fmt.Errorf("invalid server config path")
	}

	switch parts[0] {
	case "auth":
		switch parts[1] {
		case "host":
			if str, ok := value.(string); ok {
				m.config.Server.Auth.Host = SetRequired(str)
			}
		case "port":
			if port, ok := value.(int); ok {
				m.config.Server.Auth.Port = SetRequired(port)
			}
		}
	case "control":
		switch parts[1] {
		case "host":
			if str, ok := value.(string); ok {
				m.config.Server.Control.Host = SetRequired(str)
			}
		case "port":
			if port, ok := value.(int); ok {
				m.config.Server.Control.Port = SetRequired(port)
			}
		}
	}

	return nil
}

func (m *Manager) setDatabaseConfig(parts []string, value interface{}) error {
	// Implementation for database config updates
	return nil
}

func (m *Manager) setSessionConfig(parts []string, value interface{}) error {
	// Implementation for session config updates
	return nil
}

func (m *Manager) setDeploymentConfig(parts []string, value interface{}) error {
	// Implementation for deployment config updates
	return nil
}

func (m *Manager) saveConfigToFile() error {
	data, err := yaml.Marshal(m.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func (m *Manager) cloneConfig(config *Config) *Config {
	data, _ := yaml.Marshal(config)
	var cloned Config
	yaml.Unmarshal(data, &cloned)
	return &cloned
}

func (m *Manager) AddListener(component string, listener ChangeListener) {
	m.listenersMutex.Lock()
	defer m.listenersMutex.Unlock()

	if m.listeners[component] == nil {
		m.listeners[component] = []ChangeListener{}
	}
	m.listeners[component] = append(m.listeners[component], listener)
}

func (m *Manager) RemoveListener(component string, listener ChangeListener) {
	m.listenersMutex.Lock()
	defer m.listenersMutex.Unlock()

	listeners := m.listeners[component]
	for i, l := range listeners {
		if &l == &listener {
			m.listeners[component] = append(listeners[:i], listeners[i+1:]...)
			break
		}
	}
}

func (m *Manager) notifyConfigChange(oldConfig, newConfig *Config) {
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

func (m *Manager) watchConfigFile() {
	if m.configPath == "" {
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastModTime time.Time
	if stat, err := os.Stat(m.configPath); err == nil {
		lastModTime = stat.ModTime()
	}

	for {
		select {
		case <-m.watchContext.Done():
			return
		case <-ticker.C:
			if stat, err := os.Stat(m.configPath); err == nil {
				if stat.ModTime().After(lastModTime) {
					lastModTime = stat.ModTime()
					m.logInfo("Configuration file changed, reloading")
					if err := m.LoadConfig(); err != nil {
						m.logError("Failed to reload configuration", "error", err)
					}
				}
			}
		}
	}
}

func (m *Manager) Close() error {
	m.watchCancel()
	return nil
}

// Helper methods for logging
func (m *Manager) logInfo(msg string, args ...interface{}) {
	if m.logger != nil {
		m.logger.App.Info(msg, m.formatLogArgs(args...)...)
	}
}

func (m *Manager) logWarn(msg string, args ...interface{}) {
	if m.logger != nil {
		m.logger.App.Warn(msg, m.formatLogArgs(args...)...)
	}
}

func (m *Manager) logError(msg string, args ...interface{}) {
	if m.logger != nil {
		m.logger.App.Error(msg, m.formatLogArgs(args...)...)
	}
}

func (m *Manager) formatLogArgs(args ...interface{}) []zap.Field {
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
