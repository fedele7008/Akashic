package logging

import (
	"akashic/akashic/pkg/common"
	"errors"
	"fmt"
	"maps"
	"os"
	"time"
)

/***** type aliases *****/

type Optional[T any] = common.Nullable[T]

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

type Required[T any] = common.Nullable[T]

func SetRequired[T any](val T) Required[T] {
	return common.MakeNullable[T](val)
}

/***** type definitions *****/

type FileMode int

const (
	FileAppend FileMode = iota
	FileTruncate
	FileRolling
)

type SinkType int

const (
	SinkStdout SinkType = iota
	SinkStderr
	SinkFile
	SinkLoki
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

type Format int

const (
	FormatText Format = iota
	FormatJSON
)

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

type StaticLabel map[string]string

/***** configuration definition *****/

type SinkConfig struct {
	// Common fields
	Type    Required[SinkType] `mapstructure:"type"`
	Enabled Required[bool]     `mapstructure:"enabled"`
	Level   Optional[Level]    `mapstructure:"level"`
	Format  Optional[Format]   `mapstructure:"format"` // ignored in loki sink

	// file sink specific fields
	FilePath   Required[string]   `mapstructure:"file_path"`
	FileMode   Optional[FileMode] `mapstructure:"file_mode"`
	MaxSizeMB  Optional[int]      `mapstructure:"max_size_mb"`
	MaxBackups Optional[int]      `mapstructure:"max_backups"`

	// loki sink specific fields
	LokiURL            Required[string]      `mapstructure:"loki_url"`
	BasicAuthUser      Optional[string]      `mapstructure:"basic_auth_user"`
	BasicAuthPass      Optional[string]      `mapstructure:"basic_auth_pass"`
	LokiLabels         Optional[StaticLabel] `mapstructure:"loki_labels"`
	BatchSize          Optional[int]         `mapstructure:"batch_size"`
	BatchFlushPeriodMs Optional[int]         `mapstructure:"batch_flush_period_ms"`
	RetryMaxCount      Optional[int]         `mapstructure:"retry_max_count"`
	RetryMinBackoffMs  Optional[int]         `mapstructure:"retry_min_backoff_ms"`
	RetryMaxBackoffMs  Optional[int]         `mapstructure:"retry_max_backoff_ms"`
	Compress           Optional[bool]        `mapstructure:"compress"`
	BreakerMaxRetries  Optional[int]         `mapstructure:"breaker_max_retries"`
	BreakerCooldownMs  Optional[int]         `mapstructure:"breaker_cooldown_ms"`
	ClientTimeoutMs    Optional[int]         `mapstructure:"client_timeout_ms"`
}

// EncoderConfig json encoder config
type EncoderConfig struct {
	TimestampKey  Optional[string]
	TimeFormatKey Optional[string]
	LevelKey      Optional[string]
	NameKey       Optional[string]
	CallerKey     Optional[string]
	MessageKey    Optional[string]
	StacktraceKey Optional[string]
}

type ChannelConfig struct {
	Enabled         Optional[bool]  `mapstructure:"enabled"`
	ShowCaller      Optional[bool]  `mapstructure:"show_caller"`
	ShowStacktrace  Optional[bool]  `mapstructure:"show_stacktrace"`
	StacktraceLevel Optional[Level] `mapstructure:"stacktrace_level"`
	Sinks           []SinkConfig    `mapstructure:"sinks"`
}

type Config struct {
	Service          Required[string] `mapstructure:"service_name"`
	Env              Required[string] `mapstructure:"env"`
	EncoderConfig    EncoderConfig    `mapstructure:"encoder_config"`
	App              ChannelConfig    `mapstructure:"channel"`
	Security         ChannelConfig    `mapstructure:"security"`
	Audit            ChannelConfig    `mapstructure:"audit"`
	ForceAuditAppend Optional[bool]   `mapstructure:"force_audit_append"`
}

/***** Default values *****/

// Default values for SinkConfig
const (
	DefaultLevel                     = LevelInfo
	DefaultFormat                    = FormatJSON
	DefaultFileMode                  = FileRolling
	DefaultMaxSizeMB          int    = 100
	DefaultMaxBackups         int    = 3
	DefaultBasicAuthUser      string = ""
	DefaultBasicAuthPass      string = ""
	DefaultBatchSize          int    = 100
	DefaultBatchFlushPeriodMs int    = 1000
	DefaultRetryMaxCount      int    = 5
	DefaultRetryMinBackoffMs  int    = 200
	DefaultRetryMaxBackoffMs  int    = 2000
	DefaultCompress           bool   = true
	DefaultBreakerMaxRetries  int    = 1
	DefaultBreakerCooldownMs  int    = 5000
	DefaultClientTimeoutMs    int    = 10000
)

var (
	DefaultStaticLabel = StaticLabel{}
)

// Default values for ChannelConfig
const (
	DefaultChannelEnabled  bool = true
	DefaultShowCaller      bool = true
	DefaultShowStacktrace  bool = true
	DefaultStacktraceLevel      = LevelError
)

// Default values for EncoderConfig
const (
	DefaultTimestampKey  = "timestamp"
	DefaultTimeFormat    = time.UnixDate
	DefaultLogLevelKey   = "level"
	DefaultNameKey       = "logging"
	DefaultCallerKey     = "caller"
	DefaultMessageKey    = "message"
	DefaultStacktraceKey = "stacktrace"
)

// Default values for Config
const (
	DefaultForceAuditAppend bool = true
)

/* helper function */

// validates whether if the cfg has all of its required fields properly defined
func (cfg *Config) ValidateLoggerConfig() error {
	var errs []error
	joinErrs := func(errs []error) error {
		return errors.Join(append([]error{errors.New("logging config is not valid")}, errs...)...)
	}

	if cfg == nil {
		errs = append(errs, errors.New("logging config is nil"))
		return joinErrs(errs)
	}
	strVal, strOk := cfg.Service.Get()
	if !strOk || strVal == "" {
		errs = append(errs, errors.New("config.service_name is required field"))
	}
	strVal, strOk = cfg.Env.Get()
	if !strOk || strVal == "" {
		errs = append(errs, errors.New("config.env is required field"))
	}
	channels := map[string]*ChannelConfig{
		ChannelApp.String():      &cfg.App,
		ChannelSecurity.String(): &cfg.Security,
		ChannelAudit.String():    &cfg.Audit,
	}
	for chName, ch := range channels {
		for i := range ch.Sinks {
			sink := &ch.Sinks[i]
			sinkTypeVal, sinkTypeOk := sink.Type.Get()
			if !sinkTypeOk {
				errs = append(errs, fmt.Errorf("config.%s.sinks.type is required field", chName))
			}
			_, boolOk := sink.Enabled.Get()
			if !boolOk {
				errs = append(errs, fmt.Errorf("config.%s.sinks.enabled is required field", chName))
			}

			if sinkTypeOk && sinkTypeVal == SinkFile {
				strVal, strOk = sink.FilePath.Get()
				if !strOk || strVal == "" {
					errs = append(errs, fmt.Errorf("config.%s.sinks.file_path is required field for file sink", chName))
				}
			}

			if sinkTypeOk && sinkTypeVal == SinkLoki {
				strVal, strOk = sink.LokiURL.Get()
				if !strOk || strVal == "" {
					errs = append(errs, fmt.Errorf("config.%s.sinks.loki_url is required field for loki sink", chName))
				}
			}
		}
	}
	if len(errs) > 0 {
		return joinErrs(errs)
	}
	return nil
}

// fill any of undefined optional values into default values
func (cfg *Config) FillDefaults() error {
	if cfg == nil {
		return errors.New("logging config is nil")
	}

	if err := cfg.ValidateLoggerConfig(); err != nil {
		return err
	}

	// config setup
	cfg.ForceAuditAppend = cfg.ForceAuditAppend.IfNullSet(DefaultForceAuditAppend)

	// encoder config setup
	cfg.EncoderConfig.TimestampKey = cfg.EncoderConfig.TimestampKey.IfNullSet(DefaultTimestampKey)
	cfg.EncoderConfig.TimeFormatKey = cfg.EncoderConfig.TimeFormatKey.IfNullSet(DefaultTimeFormat)
	cfg.EncoderConfig.LevelKey = cfg.EncoderConfig.LevelKey.IfNullSet(DefaultLogLevelKey)
	cfg.EncoderConfig.NameKey = cfg.EncoderConfig.NameKey.IfNullSet(DefaultNameKey)
	cfg.EncoderConfig.CallerKey = cfg.EncoderConfig.CallerKey.IfNullSet(DefaultCallerKey)
	cfg.EncoderConfig.MessageKey = cfg.EncoderConfig.MessageKey.IfNullSet(DefaultMessageKey)
	cfg.EncoderConfig.StacktraceKey = cfg.EncoderConfig.StacktraceKey.IfNullSet(DefaultStacktraceKey)

	channels := map[string]*ChannelConfig{
		ChannelApp.String():      &cfg.App,
		ChannelSecurity.String(): &cfg.Security,
		ChannelAudit.String():    &cfg.Audit,
	}
	for _, ch := range channels {
		// channel setups
		ch.Enabled = ch.Enabled.IfNullSet(DefaultChannelEnabled)
		ch.ShowCaller = ch.ShowCaller.IfNullSet(DefaultShowCaller)
		ch.ShowStacktrace = ch.ShowStacktrace.IfNullSet(DefaultShowStacktrace)
		ch.StacktraceLevel = ch.StacktraceLevel.IfNullSet(DefaultStacktraceLevel)

		for i := range ch.Sinks {
			sink := &ch.Sinks[i]
			sink.Level = sink.Level.IfNullSet(DefaultLevel)
			sink.Format = sink.Format.IfNullSet(DefaultFormat)

			if sType, ok := sink.Type.Get(); ok && sType == SinkFile {
				sink.FileMode = sink.FileMode.IfNullSet(DefaultFileMode)
				sink.MaxSizeMB = sink.MaxSizeMB.IfNullSet(DefaultMaxSizeMB)
				sink.MaxBackups = sink.MaxBackups.IfNullSet(DefaultMaxBackups)
			}

			if sType, ok := sink.Type.Get(); ok && sType == SinkLoki {
				sink.BasicAuthUser = sink.BasicAuthUser.IfNullSet(DefaultBasicAuthUser)
				sink.BasicAuthPass = sink.BasicAuthPass.IfNullSet(DefaultBasicAuthPass)
				sink.LokiLabels = sink.LokiLabels.IfNullSet(maps.Clone(DefaultStaticLabel))
				sink.BatchSize = sink.BatchSize.IfNullSet(DefaultBatchSize)
				sink.BatchFlushPeriodMs = sink.BatchFlushPeriodMs.IfNullSet(DefaultBatchFlushPeriodMs)
				sink.RetryMaxCount = sink.RetryMaxCount.IfNullSet(DefaultRetryMaxCount)
				sink.RetryMinBackoffMs = sink.RetryMinBackoffMs.IfNullSet(DefaultRetryMinBackoffMs)
				sink.RetryMaxBackoffMs = sink.RetryMaxBackoffMs.IfNullSet(DefaultRetryMaxBackoffMs)
				sink.Compress = sink.Compress.IfNullSet(DefaultCompress)
				sink.BreakerMaxRetries = sink.BreakerMaxRetries.IfNullSet(DefaultBreakerMaxRetries)
				sink.BreakerCooldownMs = sink.BreakerCooldownMs.IfNullSet(DefaultBreakerCooldownMs)
				sink.ClientTimeoutMs = sink.ClientTimeoutMs.IfNullSet(DefaultClientTimeoutMs)
			}
		}
	}
	return nil
}

// deep copy the sink config
func (cfg *SinkConfig) Clone() *SinkConfig {
	newSinkConfig := &SinkConfig{}
	*newSinkConfig = *cfg
	newSinkConfig.LokiLabels = newSinkConfig.LokiLabels.Set(maps.Clone(cfg.LokiLabels.IfValidGet(maps.Clone(DefaultStaticLabel))))
	return newSinkConfig
}

// deep copy the entire config
func (cfg *Config) Clone() *Config {
	newCfg := &Config{}
	*newCfg = *cfg

	channels := map[string][2]*ChannelConfig{
		ChannelApp.String():      {&cfg.App, &newCfg.App},
		ChannelSecurity.String(): {&cfg.Security, &newCfg.Security},
		ChannelAudit.String():    {&cfg.Audit, &newCfg.Audit},
	}
	for _, ch := range channels {
		oldCh := ch[0]
		newCh := ch[1]

		// re-create reference valued fields
		newCh.Sinks = []SinkConfig{}

		// for each sink, deep copy into new channel's sink
		for i := range oldCh.Sinks {
			sinkOriginal := &oldCh.Sinks[i]
			newSink := sinkOriginal.Clone()
			newCh.Sinks = append(newCh.Sinks, *newSink)
		}
	}
	return newCfg
}

// get base config which no sink is registered and all optional values are undefined
func GetBaseConfig(service, env string) *Config {
	cfg := &Config{
		Service: SetRequired(service),
		Env:     SetRequired(env),
	}
	return cfg
}

// get config which no sink is registered and all optional fields are default values
func GetConfig(service, env string) *Config {
	cfg := GetBaseConfig(service, env)
	if err := cfg.FillDefaults(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Something went wrong while filling default config: %s\n", err)
		return nil
	}
	return cfg
}

func (cfg *Config) RegisterSink(ch Channel, sinkConfig *SinkConfig) error {
	var channel *ChannelConfig
	switch ch {
	case ChannelApp:
		channel = &cfg.App
	case ChannelSecurity:
		channel = &cfg.Security
	case ChannelAudit:
		channel = &cfg.Audit
	default:
		return fmt.Errorf("unknown channel: %s", ch.String())
	}
	channel.Sinks = append(channel.Sinks, *sinkConfig.Clone())
	return nil
}
