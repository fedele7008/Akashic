package logger

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	App      *zap.Logger
	Security *zap.Logger
	Audit    *zap.Logger
}

func consoleEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:       TimestampKey,
		LevelKey:      LogLevelKey,
		NameKey:       NameKey,
		CallerKey:     CallerKey,
		MessageKey:    MessageKey,
		StacktraceKey: StacktraceKey,
		LineEnding:    zapcore.DefaultLineEnding,
		EncodeLevel:   zapcore.CapitalLevelEncoder,
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(t.UTC().Format(time.UnixDate))
		},
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		ConsoleSeparator: " ",
	}
}

func jsonEncoderConfig() zapcore.EncoderConfig {
	c := consoleEncoderConfig()
	c.EncodeLevel = zapcore.LowercaseLevelEncoder
	return c
}

func openTextFileSink(sinkCfg SinkConfig) (io.Writer, io.Closer, error) {
	if sinkCfg.FilePath == "" {
		return nil, nil, fmt.Errorf("SinkConfig config missing file_path")
	}
	if err := os.MkdirAll(filepath.Dir(sinkCfg.FilePath), 0o755); err != nil {
		return nil, nil, err
	}
	switch sinkCfg.FileMode {
	case FileAppend:
		w, err := NewAppendingFileWriter(sinkCfg.FilePath)
		return w, w, err
	case FileTruncate:
		w, err := NewTruncatedFileWriter(sinkCfg.FilePath)
		return w, w, err
	case FileRolling:
		w, err := NewRollingFileWriter(sinkCfg.FilePath, sinkCfg.MaxSizeMB, sinkCfg.MaxBackups)
		return w, w, err
	default:
		return nil, nil, fmt.Errorf("unknown file mode: %s", sinkCfg.FileMode)
	}
}

func levelToEnabler(level Level) zapcore.LevelEnabler {
	switch level {
	case LevelDebug:
		return zap.DebugLevel
	case LevelInfo:
		return zap.InfoLevel
	case LevelWarn:
		return zap.WarnLevel
	case LevelError:
		return zap.ErrorLevel
	case LevelFatal:
		return zap.FatalLevel
	default:
		return zap.InfoLevel
	}
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

func buildChannelCore(channel string, cfg *Config, chCfg ChannelConfig, consoleEnc, jsonEnc zapcore.Encoder) (zapcore.Core, []io.Closer, error) {
	if !chCfg.Enabled || len(chCfg.Sinks) == 0 {
		core := zapcore.NewCore(consoleEnc, zapcore.AddSync(os.Stdout), zap.InfoLevel)
		return core, nil, nil
	}
	var cores []zapcore.Core
	var closers []io.Closer

	for _, sink := range chCfg.Sinks {
		if !sink.Enabled {
			continue
		}
		enabler := levelToEnabler(sink.Level)

		switch sink.Type {
		case SinkStdout:
			switch sink.Format {
			case FormatText:
				cores = append(cores, zapcore.NewCore(consoleEnc, zapcore.AddSync(os.Stdout), enabler))
			case FormatJSON:
				cores = append(cores, zapcore.NewCore(jsonEnc, zapcore.AddSync(os.Stdout), enabler))
			default:
				return nil, nil, fmt.Errorf("%s: unknown format: %s", channel, sink.Format)
			}
		case SinkStderr:
			switch sink.Format {
			case FormatText:
				cores = append(cores, zapcore.NewCore(consoleEnc, zapcore.AddSync(os.Stderr), enabler))
			case FormatJSON:
				cores = append(cores, zapcore.NewCore(jsonEnc, zapcore.AddSync(os.Stderr), enabler))
			default:
				return nil, nil, fmt.Errorf("%s: unknown format: %s", channel, sink.Format)
			}
		case SinkFile:
			if sink.FilePath == "" {
				return nil, nil, fmt.Errorf("%s: SinkConfig config missing file_path", channel)
			}
			sinkConfigCopy := sink
			if channel == AuditChannel && cfg.ForceAuditAppend {
				sinkConfigCopy.FileMode = FileAppend
			}
			writer, closer, err := openTextFileSink(sinkConfigCopy)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: file sink: %w", channel, err)
			}
			if closer != nil {
				closers = append(closers, closer)
			}
			switch sink.Format {
			case FormatText:
				cores = append(cores, zapcore.NewCore(consoleEnc, zapcore.AddSync(writer), enabler))
			case FormatJSON:
				cores = append(cores, zapcore.NewCore(jsonEnc, zapcore.AddSync(writer), enabler))
			default:
				return nil, nil, fmt.Errorf("%s: unknown format: %s", channel, sink.Format)
			}
		case SinkLoki:
			labels := map[string]string{
				"service_name": cfg.Service,
				"env":          cfg.Env,
				"channel":      channel,
			}
			maps.Copy(labels, sink.LokiLabels)
			lokiWriter, err := NewLokiWriter(&sink, labels)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: loki sink: %w", channel, err)
			}
			closers = append(closers, closerFunc(lokiWriter.Close))
			cores = append(cores, zapcore.NewCore(jsonEnc, zapcore.AddSync(lokiWriter), enabler))
		default:
			return nil, nil, fmt.Errorf("%s: unknown sink type: %s", channel, sink.Type)
		}
	}

	if len(cores) == 0 {
		cores = append(cores, zapcore.NewCore(consoleEnc, zapcore.AddSync(os.Stdout), zap.InfoLevel))
	}
	return zapcore.NewTee(cores...), closers, nil
}

func New(cfg *Config) (logger *Logger, closeFn func(), err error) {
	consoleEnc := zapcore.NewConsoleEncoder(consoleEncoderConfig())
	jsonEnc := zapcore.NewJSONEncoder(jsonEncoderConfig())

	appCore, appCloser, err := buildChannelCore(AppChannel, cfg, cfg.App, consoleEnc, jsonEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("app channel: %w", err)
	}
	securityCore, securityCloser, err := buildChannelCore(SecurityChannel, cfg, cfg.Security, consoleEnc, jsonEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("security channel: %w", err)
	}
	auditCore, auditCloser, err := buildChannelCore(AuditChannel, cfg, cfg.Audit, consoleEnc, jsonEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("audit channel: %w", err)
	}

	app := zap.New(appCore, zap.AddCaller(), zap.AddStacktrace(levelToEnabler(LevelError)))
	security := zap.New(securityCore)
	audit := zap.New(auditCore)

	closeFn = func() {
		_ = app.Sync()
		_ = security.Sync()
		_ = audit.Sync()
		for _, closer := range append(append(appCloser, securityCloser...), auditCloser...) {
			_ = closer.Close()
		}
	}
	return &Logger{
		App:      app,
		Security: security,
		Audit:    audit,
	}, closeFn, nil
}
