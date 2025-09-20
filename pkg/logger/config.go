package logger

import (
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

type FileMode string

const (
	FileAppend   FileMode = "append"
	FileTruncate FileMode = "truncate"
	FileRolling  FileMode = "rolling"
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
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelFatal Level = "fatal"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

type SinkConfig struct {
	// Common fields
	Type    SinkType `mapstructure:"type"`
	Enabled bool     `mapstructure:"enabled"`
	Level   Level    `mapstructure:"level"`
	Format  Format   `mapstructure:"format"` // ignored in loki sink

	// file/json specific fields
	FilePath   string   `mapstructure:"file_path"`
	FileMode   FileMode `mapstructure:"file_mode"`
	MaxSizeMB  int      `mapstructure:"max_size_mb"` // rolling files only
	MaxBackups int      `mapstructure:"max_backups"` // rolling files only

	// loki specific fields
	LokiURL            string            `mapstructure:"loki_url"`
	BasicAuthUser      string            `mapstructure:"basic_auth_user"`
	BasicAuthPass      string            `mapstructure:"basic_auth_pass"`
	LokiLabels         map[string]string `mapstructure:"loki_labels"`
	BatchSize          int               `mapstructure:"batch_size"`
	BatchFlushPeriodMs int               `mapstructure:"batch_flush_period_ms"`
	RetryMaxCount      int               `mapstructure:"retry_max_count"`
	RetryMinBackoffMs  int               `mapstructure:"retry_min_backoff_ms"`
	RetryMaxBackoffMs  int               `mapstructure:"retry_max_backoff_ms"`
	Compress           bool              `mapstructure:"compress"`
}

type ChannelConfig struct {
	Enabled bool         `mapstructure:"enabled"`
	Sinks   []SinkConfig `mapstructure:"sinks"`
}

type Channel string

const (
	AppChannel      = "app"
	SecurityChannel = "security"
	AuditChannel    = "audit"
)

type Config struct {
	Service          string        `mapstructure:"service_name"`
	Env              string        `mapstructure:"env"`
	App              ChannelConfig `mapstructure:"channel"`
	Security         ChannelConfig `mapstructure:"security"`
	Audit            ChannelConfig `mapstructure:"audit"`
	ForceAuditAppend bool          `mapstructure:"force_audit_append"`
}

const (
	DefaultMaxSizeMB  = 10
	DefaultMaxBackups = 3
)

var ErrFileWriterNotInitialized = errors.New("file writer not initialized")

type FileWriter struct {
	mu   sync.Mutex
	path string
	file *os.File
}

type AppendingFileWriter struct {
	FileWriter
}
type TruncatedFileWriter struct {
	FileWriter
}
type RollingFileWriter struct {
	FileWriter
	size       int64
	maxSize    int64
	maxBackups int
}

const (
	DefaultBatchSize          int = 100
	DefaultBatchFlushPeriodMs int = 1000
	DefaultRetryMaxCount      int = 5
	DefaultRetryMinBackoffMs  int = 200
	DefaultRetryMaxBackoffMs  int = 2000
	DefaultClientTimeoutSec   int = 10
)

type LokiWriter struct {
	url         string
	user        string
	pass        string
	fixedLabels map[string]string

	batchSize        int
	batchFlushPeriod time.Duration
	retryMaxCount    int
	retryMinBackoff  time.Duration
	retryMaxBackoff  time.Duration
	compress         bool

	mu     sync.Mutex
	buf    map[string][][2]string // buf[streamKey] = [..., [timestamp, line], ...]
	timer  *time.Timer
	quit   chan struct{}
	wg     sync.WaitGroup
	client *http.Client
}

type Logger struct {
	App      *zap.Logger
	Security *zap.Logger
	Audit    *zap.Logger
}
