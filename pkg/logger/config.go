package logger

import "akashic/akashic/pkg/common"

type FileMode string

const (
	FileAppend      FileMode = "append"
	FileTruncate    FileMode = "truncate"
	FileRolling     FileMode = "rolling"
	DefaultFileMode          = FileRolling
)

type SinkType string

const (
	SinkStdout SinkType = "stdout"
	SinkStderr SinkType = "stderr"
	SinkFile   SinkType = "file"
	SinkLoki   SinkType = "loki"
)

type Level string

const (
	LevelDebug   Level = "debug"
	LevelInfo    Level = "info"
	LevelWarn    Level = "warn"
	LevelError   Level = "error"
	LevelFatal   Level = "fatal"
	DefaultLevel       = LevelInfo
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

type StaticLabel map[string]string

var DefaultStaticLabel = StaticLabel{}

const (
	DefaultMaxSizeMB          int  = 100
	DefaultMaxBackups         int  = 3
	DefaultBatchSize          int  = 100
	DefaultBatchFlushPeriodMs int  = 1000
	DefaultRetryMaxCount      int  = 5
	DefaultRetryMinBackoffMs  int  = 200
	DefaultRetryMaxBackoffMs  int  = 2000
	DefaultClientTimeoutSec   int  = 10
	DefaultCompress           bool = true
)

type SinkConfig struct {
	// Common fields
	Type    SinkType `mapstructure:"type"`    // required
	Enabled bool     `mapstructure:"enabled"` // required
	Level   Level    `mapstructure:"level"`   // optional (default: LevelInfo)
	Format  Format   `mapstructure:"format"`  // required; ignored in loki sink

	// file/json specific fields
	FilePath   string   `mapstructure:"file_path"`   // required
	FileMode   FileMode `mapstructure:"file_mode"`   // optional (default: FileRolling)
	MaxSizeMB  int      `mapstructure:"max_size_mb"` // optional (default: DefaultMaxSizeMB); rolling files only
	MaxBackups int      `mapstructure:"max_backups"` // optional (default: DefaultMaxBackups; min: 1); rolling files only

	// loki specific fields
	LokiURL            string                `mapstructure:"loki_url"`              // required
	BasicAuthUser      string                `mapstructure:"basic_auth_user"`       // required
	BasicAuthPass      string                `mapstructure:"basic_auth_pass"`       // required
	LokiLabels         StaticLabel           `mapstructure:"loki_labels"`           // optional (default: DefaultStaticLabel)
	BatchSize          int                   `mapstructure:"batch_size"`            // optional (default: DefaultBatchSize)
	BatchFlushPeriodMs int                   `mapstructure:"batch_flush_period_ms"` // optional (default: DefaultBatchFlushPeriodMs)
	RetryMaxCount      common.Nullable[int]  `mapstructure:"retry_max_count"`       // optional (default: DefaultRetryMaxCount)
	RetryMinBackoffMs  int                   `mapstructure:"retry_min_backoff_ms"`  // optional (default: DefaultRetryMinBackoffMs)
	RetryMaxBackoffMs  int                   `mapstructure:"retry_max_backoff_ms"`  // optional (default: DefaultRetryMaxBackoffMs)
	Compress           common.Nullable[bool] `mapstructure:"compress"`              // optional (default: DefaultCompress)
}

type Channel string

const (
	AppChannel      = "app"
	SecurityChannel = "security"
	AuditChannel    = "audit"
)

type ChannelConfig struct {
	Enabled bool         `mapstructure:"enabled"` // required
	Sinks   []SinkConfig `mapstructure:"sinks"`   // required
}

const DefaultForceAuditAppend bool = true

type Config struct {
	Service          string        `mapstructure:"service_name"`       // required
	Env              string        `mapstructure:"env"`                // required
	App              ChannelConfig `mapstructure:"channel"`            // required
	Security         ChannelConfig `mapstructure:"security"`           // required
	Audit            ChannelConfig `mapstructure:"audit"`              // required
	ForceAuditAppend bool          `mapstructure:"force_audit_append"` // optional (default: DefaultForceAuditAppend)
}

// json encoding key values
const (
	TimestampKey  = "timestamp"
	LogLevelKey   = "level"
	NameKey       = "logger"
	CallerKey     = "caller"
	MessageKey    = "message"
	StacktraceKey = "stacktrace"
)
