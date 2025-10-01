package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"akashic/akashic/pkg/logging"

	"github.com/joho/godotenv"
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
	viper       *viper.Viper
	config      *Config
	configMutex sync.RWMutex
	logger      *logging.Logger
	verbose     bool
}

func NewConfigManager(cmd *cobra.Command) (*ConfigManager, error) {
	// Parse verbose flag
	verbose, err := GetFlagValue[bool](cmd, VerboseFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to parse verbose flag: %v", err)
	}

	// Create viper instance
	v := viper.New()

	// Create manager
	m := &ConfigManager{
		viper:   v,
		verbose: verbose,
	}

	m.VerbosePrintlnf("Verbose logging enabled")

	// Load .env file if it exists
	if err := godotenv.Load(); err == nil {
		m.VerbosePrintlnf("Loaded environment variables from .env file")
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

	// Parse config file flag
	configFile, err := GetFlagValue[string](cmd, ConfigFlag)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config flag: %v", err)
	}

	// Setup config file paths
	if configFile != "" {
		v.SetConfigFile(configFile)
		m.VerbosePrintlnf("Using config file: %s", configFile)
	} else {
		v.SetConfigName(DefaultConfigFileName)
		v.SetConfigType(DefaultConfigFileType)

		// Handle environment variable expansion in config paths
		for _, path := range configPaths {
			expandedPath := os.ExpandEnv(path)
			// Skip paths that still contain unexpanded variables (e.g., $HOME not set)
			if strings.Contains(expandedPath, "$") {
				m.VerbosePrintlnf("Skipping config path with unexpanded variables: %s", path)
				continue
			}
			v.AddConfigPath(expandedPath)
		}
	}

	// Try to read config file with environment variable expansion
	if err := m.readConfigWithEnvExpansion(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found - this is OK, we'll use defaults and env vars
			m.VerbosePrintlnf("No config file found, using defaults and environment variables")
		} else if configFile != "" {
			// Config file specified but error reading it - report error
			m.VerbosePrintlnf("Failed to read config file:", configFile)
			return nil, fmt.Errorf("failed to read config file %s: %v", configFile, err)
		} else {
			// Unknown error with default paths - warn but continue
			m.VerbosePrintlnf("Config file error: %v; using defaults and environment variables", err)
		}
	}

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

	m.VerbosePrintlnf("Using config file: %s", configFile)

	// Read the raw config file content
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	// Expand environment variables in the raw content
	expandedContent := os.ExpandEnv(string(data))

	// Check if any variables were expanded
	if expandedContent != string(data) {
		m.VerbosePrintlnf("Expanded environment variables in config file")

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

func (m *ConfigManager) LoadConfig() error {
	m.configMutex.Lock()
	defer m.configMutex.Unlock()

	// Create config struct and unmarshal from viper
	config := &Config{}
	if err := m.viper.Unmarshal(config); err != nil {
		return fmt.Errorf("failed to unmarshal configuration: %v", err)
	}

	// Apply any post-unmarshaling fixes (e.g., logging config setup)
	if err := m.postProcessConfig(config); err != nil {
		return fmt.Errorf("failed to post-process configuration: %v", err)
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return fmt.Errorf("configuration validation failed: %v", err)
	}

	m.config = config
	return nil
}

// postProcessConfig handles any configuration setup that needs to happen after unmarshaling
func (m *ConfigManager) postProcessConfig(config *Config) error {
	// Setup logging configuration using the logging package
	// Note: logging package uses its own nullable type system, so we create it separately
	serviceName := m.GetViper().GetString("logging.service_name")
	env := config.Deployment.Environment.String()

	logConfig := logging.GetConfig(serviceName, env)
	if logConfig == nil {
		return fmt.Errorf("failed to create logging configuration")
	}
	logConfig.EncoderConfig = logging.EncoderConfig{
		TimestampKey:  logging.SetOptional(m.viper.GetString("logging.encoder.timestamp_key")),
		TimeFormatKey: logging.SetOptional(m.viper.GetString("logging.encoder.time_format")),
		LevelKey:      logging.SetOptional(m.viper.GetString("logging.encoder.level_key")),
		NameKey:       logging.SetOptional(m.viper.GetString("logging.encoder.name_key")),
		CallerKey:     logging.SetOptional(m.viper.GetString("logging.encoder.caller_key")),
		MessageKey:    logging.SetOptional(m.viper.GetString("logging.encoder.message_key")),
		StacktraceKey: logging.SetOptional(m.viper.GetString("logging.encoder.stacktrace_key")),
	}
	logConfig.App.Enabled = logging.SetOptional(m.viper.GetBool("logging.app.enabled"))
	logConfig.App.ShowCaller = logging.SetOptional(m.viper.GetBool("logging.app.show_caller"))
	logConfig.App.ShowStacktrace = logging.SetOptional(m.viper.GetBool("logging.app.show_stacktrace"))
	stacktraceLv, err := logging.ParseLevel(m.viper.GetString("logging.app.stacktrace_level"))
	if err == nil {
		logConfig.App.StacktraceLevel = logging.SetOptional(stacktraceLv)
	}

	logConfig.Security.Enabled = logging.SetOptional(m.viper.GetBool("logging.security.enabled"))
	logConfig.Security.ShowCaller = logging.SetOptional(m.viper.GetBool("logging.security.show_caller"))
	logConfig.Security.ShowStacktrace = logging.SetOptional(m.viper.GetBool("logging.security.show_stacktrace"))
	stacktraceLv, err = logging.ParseLevel(m.viper.GetString("logging.security.stacktrace_level"))
	if err == nil {
		logConfig.Security.StacktraceLevel = logging.SetOptional(stacktraceLv)
	}

	logConfig.Audit.Enabled = logging.SetOptional(m.viper.GetBool("logging.audit.enabled"))
	logConfig.Audit.ShowCaller = logging.SetOptional(m.viper.GetBool("logging.audit.show_caller"))
	logConfig.Audit.ShowStacktrace = logging.SetOptional(m.viper.GetBool("logging.audit.show_stacktrace"))
	stacktraceLv, err = logging.ParseLevel(m.viper.GetString("logging.audit.stacktrace_level"))
	if err == nil {
		logConfig.Audit.StacktraceLevel = logging.SetOptional(stacktraceLv)
	}

	appSinkConfigs := m.viper.Get("logging.app.sinks")
	if appSinkConfigs != nil {
		if sinksList, ok := appSinkConfigs.([]interface{}); ok {
			for _, sinkCfg := range sinksList {
				if sinkMap, ok := sinkCfg.(map[string]interface{}); ok {
					// Safe type assertions with nil checks
					sinkTypeStr, ok := sinkMap["type"].(string)
					if !ok {
						m.VerbosePrintlnf("invalid or missing app sink type")
						continue
					}

					sinkEnabled, ok := sinkMap["enabled"].(bool)
					if !ok {
						m.VerbosePrintlnf("invalid or missing app sink enabled flag")
						continue
					}

					sinkLevelStr, ok := sinkMap["level"].(string)
					if !ok {
						m.VerbosePrintlnf("invalid or missing app sink level")
						continue
					}

					sinkFormatStr, ok := sinkMap["format"].(string)
					if !ok {
						sinkFormatStr = "json" // default format for sinks without explicit format
					}

					sinkType, err := logging.ParseSinkType(sinkTypeStr)
					if err != nil {
						m.VerbosePrintlnf("invalid app sink type: %v", err)
						continue
					}

					sinkFormat, err := logging.ParseFormat(sinkFormatStr)
					if err != nil {
						m.VerbosePrintlnf("invalid app sink format: %v", err)
						continue
					}

					sinkLevel, err := logging.ParseLevel(sinkLevelStr)
					if err != nil {
						m.VerbosePrintlnf("invalid app sink level: %v", err)
						continue
					}

					inSinkCfg := &logging.SinkConfig{
						Type:    logging.SetRequired(sinkType),
						Enabled: logging.SetRequired(sinkEnabled),
						Level:   logging.SetOptional(sinkLevel),
						Format:  logging.SetOptional(sinkFormat),
					}

					if sinkType == logging.SinkFile {
						if filePath, ok := sinkMap["file_path"].(string); ok {
							inSinkCfg.FilePath = logging.SetRequired(filePath)
						} else {
							m.VerbosePrintlnf("invalid or missing file_path for file sink")
							continue
						}

						if fileModeStr, ok := sinkMap["file_mode"].(string); ok {
							fileMode, err := logging.ParseFileMode(fileModeStr)
							if err != nil {
								m.VerbosePrintlnf("invalid app sink file mode: %v", err)
								continue
							}
							inSinkCfg.FileMode = logging.SetOptional(fileMode)
						}

						if maxSizeMB, ok := sinkMap["max_size_mb"].(int); ok {
							inSinkCfg.MaxSizeMB = logging.SetOptional(maxSizeMB)
						}

						if maxBackups, ok := sinkMap["max_backups"].(int); ok {
							inSinkCfg.MaxBackups = logging.SetOptional(maxBackups)
						}
					} else if sinkType == logging.SinkLoki {
						if lokiURL, ok := sinkMap["loki_url"].(string); ok {
							inSinkCfg.LokiURL = logging.SetRequired(lokiURL)
						} else {
							m.VerbosePrintlnf("invalid or missing loki_url for loki sink")
							continue
						}

						if basicAuthUser, ok := sinkMap["basic_auth_user"].(string); ok {
							inSinkCfg.BasicAuthUser = logging.SetOptional(basicAuthUser)
						}

						if basicAuthPass, ok := sinkMap["basic_auth_pass"].(string); ok {
							inSinkCfg.BasicAuthPass = logging.SetOptional(basicAuthPass)
						}

						if batchSize, ok := sinkMap["batch_size"].(int); ok {
							inSinkCfg.BatchSize = logging.SetOptional(batchSize)
						}

						if batchFlushPeriodMs, ok := sinkMap["batch_flush_period_ms"].(int); ok {
							inSinkCfg.BatchFlushPeriodMs = logging.SetOptional(batchFlushPeriodMs)
						}

						if retryMaxCount, ok := sinkMap["retry_max_count"].(int); ok {
							inSinkCfg.RetryMaxCount = logging.SetOptional(retryMaxCount)
						}

						if retryMinBackoffMs, ok := sinkMap["retry_min_backoff_ms"].(int); ok {
							inSinkCfg.RetryMinBackoffMs = logging.SetOptional(retryMinBackoffMs)
						}

						if retryMaxBackoffMs, ok := sinkMap["retry_max_backoff_ms"].(int); ok {
							inSinkCfg.RetryMaxBackoffMs = logging.SetOptional(retryMaxBackoffMs)
						}

						if compress, ok := sinkMap["compress"].(bool); ok {
							inSinkCfg.Compress = logging.SetOptional(compress)
						}

						if breakerMaxRetries, ok := sinkMap["breaker_max_retries"].(int); ok {
							inSinkCfg.BreakerMaxRetries = logging.SetOptional(breakerMaxRetries)
						}

						if breakerCooldownMs, ok := sinkMap["breaker_cooldown_ms"].(int); ok {
							inSinkCfg.BreakerCooldownMs = logging.SetOptional(breakerCooldownMs)
						}

						if clientTimeoutMs, ok := sinkMap["client_timeout_ms"].(int); ok {
							inSinkCfg.ClientTimeoutMs = logging.SetOptional(clientTimeoutMs)
						}
					}

					err = logConfig.RegisterSink(logging.ChannelApp, inSinkCfg)
					if err != nil {
						m.VerbosePrintlnf("failed to register app sink: %v", err)
						return err
					}
				}
			}
		}
	}

	config.Logging = *logConfig
	return nil
}

func validateConfig(config *Config) error {
	// Basic validation
	if config.Server.Auth.Host == "" {
		return fmt.Errorf("server.auth.host is required")
	}
	if config.Server.Auth.Port <= 0 || config.Server.Auth.Port > 65535 {
		return fmt.Errorf("server.auth.port must be between 1 and 65535")
	}
	if config.Server.Control.Host == "" {
		return fmt.Errorf("server.control.host is required")
	}
	if config.Server.Control.Port <= 0 || config.Server.Control.Port > 65535 {
		return fmt.Errorf("server.control.port must be between 1 and 65535")
	}

	// Database validation
	if config.Database.Postgres.Host == "" {
		return fmt.Errorf("database.postgres.host is required")
	}
	if config.Database.Postgres.Database == "" {
		return fmt.Errorf("database.postgres.database is required")
	}
	if config.Database.Postgres.Username == "" {
		return fmt.Errorf("database.postgres.username is required")
	}
	if config.Database.Postgres.Password == "" {
		return fmt.Errorf("database.postgres.password is required")
	}

	if config.Database.Redis.Host == "" {
		return fmt.Errorf("database.redis.host is required")
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

func (m *ConfigManager) SetLogger(logger *logging.Logger) {
	m.logger = logger
	if logger != nil {
		m.logger.App.Info("Logger injected into configuration manager")
	}
}

func (m *ConfigManager) GetAllSettings() map[string]interface{} {
	return m.viper.AllSettings()
}
