package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"akashic/akashic/pkg/common"

	"github.com/joho/godotenv"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const EnvVarPrefix = "AKASHIC"

var configPaths = []string{
	".",                      // current directory
	"./config",               // config subdirectory
	"./configs",              // configs subdirectory
	"$HOME/.akashic",         // user-specific config directory
	"$HOME/.config/akashic",  // user-specific config directory
	"/etc/akashic",           // system-wide directory
	"/usr/local/etc/akashic", // another common system-wide directory
}

type ConfigManager struct {
	viper               *viper.Viper
	config              *Config
	configMutex         sync.RWMutex
	cmd                 *cobra.Command
	IAkashic            common.AkashicApp
	loggerReconfigureFn func(cfg *LoggingConfig) error
}

func NewConfigManager(cmd *cobra.Command, app common.AkashicApp) (*ConfigManager, error) {
	// Parse verbose flag
	verbose, err := GetFlagValue[bool](cmd, VerboseFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verbose flag: %v", err)
	}
	app.SetVerbose(verbose)

	// Create viper instance
	v := viper.New()

	// Create manager
	m := &ConfigManager{
		viper:    v,
		cmd:      cmd,
		IAkashic: app,
	}

	m.verbosePrintlnf("Verbose logging enabled")

	// Load .env file if it exists
	if err := godotenv.Load(); err == nil {
		m.verbosePrintlnf("Loaded environment variables from .env file")
	} else if !os.IsNotExist(err) {
		// Only return error if it's not a "file not found" error
		return nil, fmt.Errorf("failed to load .env file: %v", err)
	}

	// Set defaults before loading config
	setDefaults(v)

	// Setup environment variables
	v.SetEnvPrefix(EnvVarPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Bind flags to viper
	if err := BindPFlags(cmd, v); err != nil {
		return nil, fmt.Errorf("failed to bind command-line flags: %v", err)
	}

	// Load and unmarshal configuration
	if err := m.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	return m, nil
}

func (m *ConfigManager) readConfigWithEnvExpansion() error {
	// try to read normally to find the config file
	if err := m.viper.ReadInConfig(); err != nil {
		return err
	}

	configFile := m.viper.ConfigFileUsed()
	if configFile == "" {
		return nil // No config file found, nothing to expand
	}

	m.verbosePrintlnf("Using config file: %s", configFile)

	// Read the raw config file content
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	// Expand environment variables in the raw content
	expandedContent := os.ExpandEnv(string(data))

	// Check if any variables were expanded
	if expandedContent != string(data) {
		m.verbosePrintlnf("Expanded environment variables in config file")

		// Determine config type from file extension
		configType := strings.TrimPrefix(filepath.Ext(configFile), ".")
		if configType == "" {
			configType = DefaultConfigFileType
		}

		// Read the expanded content into Viper
		m.viper.SetConfigType(configType)
		return m.viper.ReadConfig(strings.NewReader(expandedContent))
	}

	return nil
}

// stringToLoggingEnumHookFunc returns a decode hook that converts strings to our logging enum types
func stringToLoggingEnumHookFunc() mapstructure.DecodeHookFunc {
	return func(f, t reflect.Type, data any) (any, error) {
		// Only process if source is string and target is one of our enum types
		if f.Kind() != reflect.String {
			return data, nil
		}

		str := data.(string)

		// Check target type and convert accordingly
		switch t {
		case reflect.TypeOf(SinkType(0)):
			return ParseSinkType(str)
		case reflect.TypeOf(Level(0)):
			return ParseLevel(str)
		case reflect.TypeOf(Format(0)):
			return ParseFormat(str)
		case reflect.TypeOf(FileMode(0)):
			return ParseFileMode(str)
		default:
			return data, nil
		}
	}
}

// stringToDurationHookFunc returns a decode hook that converts strings to time.Duration
func stringToDurationHookFunc() mapstructure.DecodeHookFunc {
	return func(f, t reflect.Type, data any) (any, error) {
		// Only process if source is string and target is time.Duration
		if f.Kind() != reflect.String || t != reflect.TypeOf(time.Duration(0)) {
			return data, nil
		}

		str := data.(string)
		return time.ParseDuration(str)
	}
}

func (m *ConfigManager) LoadConfig() error {

	// Parse config file flag
	configFile, err := GetFlagValue[string](m.cmd, ConfigFlag)
	if err != nil {
		return fmt.Errorf("failed to parse config flag: %v", err)
	}

	// Setup config file paths
	if configFile != "" {
		m.viper.SetConfigFile(configFile)
		m.verbosePrintlnf("Using config file: %s", configFile)
	} else {
		m.viper.SetConfigName(DefaultConfigFileName)
		m.viper.SetConfigType(DefaultConfigFileType)

		// Handle environment variable expansion in config paths
		for _, path := range configPaths {
			expandedPath := os.ExpandEnv(path)
			// Skip paths that still contain unexpanded variables (e.g., $HOME not set)
			if strings.Contains(expandedPath, "$") {
				m.verbosePrintlnf("Skipping config path with unexpanded variables: %s", path)
				continue
			}
			m.viper.AddConfigPath(expandedPath)
		}
	}

	// Try to read config file with environment variable expansion
	if err := m.readConfigWithEnvExpansion(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found - this is OK, we'll use defaults and env vars
			m.verbosePrintlnf("No config file found, using defaults and environment variables")
		} else if configFile != "" {
			// Config file specified but error reading it - report error
			m.verbosePrintlnf("Failed to read config file:", configFile)
			return fmt.Errorf("failed to read config file %s: %v", configFile, err)
		} else {
			// Unknown error with default paths - warn but continue
			m.verbosePrintlnf("Config file error: %v; using defaults and environment variables", err)
		}
	}

	m.configMutex.Lock()
	defer m.configMutex.Unlock()

	// Create config struct and unmarshal from viper with custom decode hooks
	config := &Config{}

	// Configure mapstructure with custom decode hooks for our enum types and time.Duration
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToLoggingEnumHookFunc(),
			stringToDurationHookFunc(),
		),
		Metadata:   nil,
		Result:     config,
		ZeroFields: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create decoder: %v", err)
	}

	if err := decoder.Decode(m.viper.AllSettings()); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %v", err)
	}

	// Apply any post-unmarshaling fixes (e.g., logging config setup)
	if err := m.postProcessConfig(config); err != nil {
		return fmt.Errorf("failed to post-process configuration: %v", err)
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return err
	}

	m.config = config

	// if logger reconfigure function is set, call it
	if m.loggerReconfigureFn != nil {
		if err := m.loggerReconfigureFn(&m.config.Logging); err != nil {
			return fmt.Errorf("failed to reconfigure logger: %v", err)
		}
	}

	return nil
}

// postProcessConfig handles any configuration setup that needs to happen after unmarshaling
func (m *ConfigManager) postProcessConfig(config *Config) error {
	// Validate logging configuration
	if err := ValidateLoggingConfig(&config.Logging); err != nil {
		return fmt.Errorf("logging configuration validation failed: %v", err)
	}

	// Set environment from deployment config if not explicitly set
	if config.Logging.Environment == "" {
		config.Logging.Environment = config.Deployment.Environment.String()
	}

	return nil
}

func validateConfig(config *Config) error {
	// Basic validation
	if config.Server.Auth.Host == "" {
		return fmt.Errorf("missing config: server.auth.host is required")
	}
	if config.Server.Auth.Port <= 0 || config.Server.Auth.Port > 65535 {
		return fmt.Errorf("missing config: server.auth.port must be between 1 and 65535")
	}
	if config.Server.Control.Host == "" {
		return fmt.Errorf("missing config: server.control.host is required")
	}
	if config.Server.Control.Port <= 0 || config.Server.Control.Port > 65535 {
		return fmt.Errorf("missing config: server.control.port must be between 1 and 65535")
	}

	// Database validation
	if config.Database.Postgres.Host == "" {
		return fmt.Errorf("missing config: database.postgres.host is required")
	}
	if config.Database.Postgres.Database == "" {
		return fmt.Errorf("missing config: database.postgres.database is required")
	}
	if config.Database.Postgres.Username == "" {
		return fmt.Errorf("missing config: database.postgres.username is required")
	}
	if config.Database.Postgres.Password == "" {
		return fmt.Errorf("missing config: database.postgres.password is required")
	}

	if config.Database.Redis.Host == "" {
		return fmt.Errorf("missing config: database.redis.host is required")
	}

	return nil
}

func (m *ConfigManager) GetConfig() *Config {
	m.configMutex.RLock()
	defer m.configMutex.RUnlock()
	return m.config
}

func (m *ConfigManager) GetViper() *viper.Viper {
	return m.viper
}

func (m *ConfigManager) GetAllSettings() map[string]any {
	return m.viper.AllSettings()
}

func (m *ConfigManager) verbosePrintlnf(format string, args ...any) {
	if m.IAkashic != nil {
		m.IAkashic.VerbosePrintlnf(format, args...)
	}
}

func (m *ConfigManager) SetLoggerReconfigureFunction(f func(cfg *LoggingConfig) error) {
	m.loggerReconfigureFn = f
}
