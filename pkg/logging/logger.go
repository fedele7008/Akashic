package logging

import (
	"akashic/akashic/pkg/common"
	"akashic/akashic/pkg/config"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	appOriginal      *zap.Logger
	securityOriginal *zap.Logger
	auditOriginal    *zap.Logger
	LoggerConfig     *config.LoggingConfig
	ServiceName      string
	ServiceEnv       string
	App              *zap.Logger
	Security         *zap.Logger
	Audit            *zap.Logger
	ForceAuditAppend bool
	closerFns        map[string][]io.Closer
}

func consoleEncoderConfig(encConfig *config.EncoderConfig) zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:       encConfig.TimestampKey,
		LevelKey:      encConfig.LevelKey,
		NameKey:       encConfig.NameKey,
		CallerKey:     encConfig.CallerKey,
		MessageKey:    encConfig.MessageKey,
		StacktraceKey: encConfig.StacktraceKey,
		LineEnding:    zapcore.DefaultLineEnding,
		EncodeLevel:   zapcore.CapitalLevelEncoder,
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(t.UTC().Format(encConfig.TimeFormatKey))
		},
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		ConsoleSeparator: " ",
	}
}

func jsonEncoderConfig(encConfig *config.EncoderConfig) zapcore.EncoderConfig {
	c := consoleEncoderConfig(encConfig)
	c.EncodeLevel = zapcore.LowercaseLevelEncoder
	return c
}

func openFileSink(sinkCfg *config.SinkConfig, isRebuild bool) (io.Writer, io.Closer, error) {
	if sinkCfg.FilePath == "" {
		return nil, nil, fmt.Errorf("SinkConfig config missing file_path")
	}
	if err := os.MkdirAll(filepath.Dir(sinkCfg.FilePath), 0o755); err != nil {
		return nil, nil, err
	}
	switch sinkCfg.FileMode {
	case config.FileAppend:
		w, err := NewAppendingFileWriter(sinkCfg.FilePath)
		return w, w, err
	case config.FileTruncate:
		if isRebuild {
			w, err := NewAppendingFileWriter(sinkCfg.FilePath)
			return w, w, err
		}
		w, err := NewTruncatedFileWriter(sinkCfg.FilePath)
		return w, w, err
	case config.FileRolling:
		w, err := NewRollingFileWriter(sinkCfg.FilePath, sinkCfg.MaxSizeMB, sinkCfg.MaxBackups)
		return w, w, err
	default:
		return nil, nil, fmt.Errorf("unknown file mode: %v", sinkCfg.FileMode)
	}
}

func levelToEnabler(level config.Level) zapcore.LevelEnabler {
	switch level {
	case config.LevelDebug:
		return zap.DebugLevel
	case config.LevelInfo:
		return zap.InfoLevel
	case config.LevelWarn:
		return zap.WarnLevel
	case config.LevelError:
		return zap.ErrorLevel
	case config.LevelFatal:
		return zap.FatalLevel
	default:
		return zap.InfoLevel
	}
}

func buildChannelCore(cfg *config.LoggingConfig, ch config.Channel, consoleEnc, jsonEnc *zapcore.Encoder, isRebuild bool) (zapcore.Core, []io.Closer, error) {
	// find channel config
	var chCfg *config.ChannelConfig
	switch ch {
	case config.ChannelApp:
		chCfg = &cfg.App
	case config.ChannelSecurity:
		chCfg = &cfg.Security
	case config.ChannelAudit:
		chCfg = &cfg.Audit
	default:
		return nil, nil, fmt.Errorf("unknown channel: %s", ch.String())
	}

	// if no sink is configured, return no-op core
	if len(chCfg.Sinks) == 0 {
		return zapcore.NewNopCore(), []io.Closer{}, nil
	}

	var cores = make([]zapcore.Core, 0)
	var closers = make([]io.Closer, 0)

	for i := range chCfg.Sinks {
		sinkCfg := &chCfg.Sinks[i]

		if !sinkCfg.Enabled {
			continue
		}
		enabler := levelToEnabler(sinkCfg.Level)

		switch sinkCfg.Type {
		case config.SinkStdout:
			var enc *zapcore.Encoder
			switch sinkCfg.Format {
			case config.FormatText:
				enc = consoleEnc
			case config.FormatJSON:
				enc = jsonEnc
			default:
				return nil, nil, fmt.Errorf("%s: unknown sink format: %v", ch.String(), sinkCfg.Format)
			}
			cores = append(cores, zapcore.NewCore(*enc, zapcore.AddSync(os.Stdout), enabler))
		case config.SinkStderr:
			var enc *zapcore.Encoder
			switch sinkCfg.Format {
			case config.FormatText:
				enc = consoleEnc
			case config.FormatJSON:
				enc = jsonEnc
			default:
				return nil, nil, fmt.Errorf("%s: unknown sink format: %v", ch.String(), sinkCfg.Format)
			}
			cores = append(cores, zapcore.NewCore(*enc, zapcore.AddSync(os.Stderr), enabler))
		case config.SinkFile:
			if sinkCfg.FilePath == "" {
				return nil, nil, fmt.Errorf("%s: invalid file path: %v", ch.String(), sinkCfg.FilePath)
			}
			if ch == config.ChannelAudit && cfg.ForceAuditAppend {
				sinkCfg.FileMode = config.FileAppend
			}
			writer, closer, err := openFileSink(sinkCfg, isRebuild)
			if err != nil {
				return nil, nil, err
			}
			if closer != nil {
				closers = append(closers, closer)
			}
			var enc *zapcore.Encoder
			switch sinkCfg.Format {
			case config.FormatText:
				enc = consoleEnc
			case config.FormatJSON:
				enc = jsonEnc
			default:
				return nil, nil, fmt.Errorf("%s: unknown sink format: %v", ch.String(), sinkCfg.Format)
			}
			cores = append(cores, zapcore.NewCore(*enc, zapcore.AddSync(writer), enabler))
		case config.SinkLoki:
			// configure must have stream keys for Loki api
			labels := map[string]string{
				"service_name": cfg.ServiceName,
				"env":          cfg.Environment,
				"channel":      ch.String(),
			}
			maps.Copy(labels, sinkCfg.LokiLabels)
			lokiWriter, err := NewLokiWriter(sinkCfg, labels)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %v", ch.String(), err)
			}
			closers = append(closers, lokiWriter)
			cores = append(cores, zapcore.NewCore(*jsonEnc, zapcore.AddSync(lokiWriter), enabler))
		default:
			return nil, nil, fmt.Errorf("%s: unknown sink type: %v", ch.String(), sinkCfg.Type)
		}
	}

	return zapcore.NewTee(cores...), closers, nil
}

func attachOptions(logger *zap.Logger, chCfg *config.ChannelConfig) *zap.Logger {
	var opts []zap.Option
	if chCfg.ShowCaller {
		opts = append(opts, zap.AddCaller())
	}
	if chCfg.ShowStacktrace {
		lv := levelToEnabler(chCfg.StacktraceLevel)
		opts = append(opts, zap.AddStacktrace(lv))
	}
	return logger.WithOptions(opts...)
}

func New(cfg *config.LoggingConfig) (logger *Logger, closeFn func(), err error) {
	// Configuration should be validated by the config manager before reaching here
	if err = config.ValidateLoggingConfig(cfg); err != nil {
		return nil, nil, err
	}

	logConfig := cfg.Clone()

	logger = &Logger{
		appOriginal:      nil,
		securityOriginal: nil,
		auditOriginal:    nil,
		LoggerConfig:     logConfig,
		ServiceName:      logConfig.ServiceName,
		ServiceEnv:       logConfig.Environment,
		App:              nil,
		Security:         nil,
		Audit:            nil,
		ForceAuditAppend: logConfig.ForceAuditAppend,
		closerFns:        make(map[string][]io.Closer),
	}
	consoleEnc := zapcore.NewConsoleEncoder(consoleEncoderConfig(&logger.LoggerConfig.EncoderConfig))
	jsonEnc := zapcore.NewJSONEncoder(jsonEncoderConfig(&logger.LoggerConfig.EncoderConfig))

	appCore, appCloser, err := buildChannelCore(logger.LoggerConfig, config.ChannelApp, &consoleEnc, &jsonEnc, false)
	if err != nil {
		return nil, nil, err
	}
	logger.closerFns[config.ChannelApp.String()] = appCloser

	securityCore, securityCloser, err := buildChannelCore(logger.LoggerConfig, config.ChannelSecurity, &consoleEnc, &jsonEnc, false)
	if err != nil {
		return nil, nil, err
	}
	logger.closerFns[config.ChannelSecurity.String()] = securityCloser

	auditCore, auditCloser, err := buildChannelCore(logger.LoggerConfig, config.ChannelAudit, &consoleEnc, &jsonEnc, false)
	if err != nil {
		return nil, nil, err
	}
	logger.closerFns[config.ChannelAudit.String()] = auditCloser

	logger.appOriginal = zap.New(appCore)
	logger.securityOriginal = zap.New(securityCore)
	logger.auditOriginal = zap.New(auditCore)

	logger.App = common.Ternary(logger.LoggerConfig.App.Enabled,
		attachOptions(logger.appOriginal, &logger.LoggerConfig.App), zap.NewNop())
	logger.Security = common.Ternary(logger.LoggerConfig.Security.Enabled,
		attachOptions(logger.securityOriginal, &logger.LoggerConfig.Security), zap.NewNop())
	logger.Audit = common.Ternary(logger.LoggerConfig.Audit.Enabled,
		attachOptions(logger.auditOriginal, &logger.LoggerConfig.Audit), zap.NewNop())

	closeFn = func() {
		_ = logger.appOriginal.Sync()
		_ = logger.securityOriginal.Sync()
		_ = logger.auditOriginal.Sync()
		for _, closerList := range logger.closerFns {
			for _, closer := range closerList {
				closerErr := closer.Close()
				if closerErr != nil {
					_, _ = fmt.Fprintf(os.Stderr, "closer error: %v", closerErr)
				}
			}
		}
	}
	err = nil
	return
}

func (logger *Logger) Reconfigure(cfg *config.LoggingConfig) error {
	if err := config.ValidateLoggingConfig(cfg); err != nil {
		return err
	}
	oldConfig := logger.LoggerConfig
	newConfig := cfg.Clone()

	channelConfigs := map[config.Channel]*config.ChannelConfig{
		config.ChannelApp:      &oldConfig.App,
		config.ChannelSecurity: &oldConfig.Security,
		config.ChannelAudit:    &oldConfig.Audit,
	}
	newChannelConfigs := map[config.Channel]*config.ChannelConfig{
		config.ChannelApp:      &newConfig.App,
		config.ChannelSecurity: &newConfig.Security,
		config.ChannelAudit:    &newConfig.Audit,
	}
	rebuildRequired := map[config.Channel]bool{
		config.ChannelApp:      false,
		config.ChannelSecurity: false,
		config.ChannelAudit:    false,
	}
	if oldConfig.ServiceName != newConfig.ServiceName || oldConfig.Environment != newConfig.Environment {
		// Loki sink requires service and env values for labeling
		for ch, chCfg := range channelConfigs {
			for i := range chCfg.Sinks {
				sink := &chCfg.Sinks[i]
				if sink.Type == config.SinkLoki {
					rebuildRequired[ch] = true
				}
			}
		}
	}
	if oldConfig.EncoderConfig != newConfig.EncoderConfig {
		// encoder is applied for all channels, require to rebuild all
		rebuildRequired[config.ChannelApp] = true
		rebuildRequired[config.ChannelSecurity] = true
		rebuildRequired[config.ChannelAudit] = true
	}
	if oldConfig.ForceAuditAppend != newConfig.ForceAuditAppend {
		// force-audit-append option is only applicable for audit channel
		rebuildRequired[config.ChannelAudit] = true
	}
	for ch, oldChCfg := range channelConfigs {
		newChCfg := newChannelConfigs[ch]
		if !reflect.DeepEqual(oldChCfg.Sinks, newChCfg.Sinks) {
			rebuildRequired[ch] = true
		}
	}

	consoleEnc := zapcore.NewConsoleEncoder(consoleEncoderConfig(&newConfig.EncoderConfig))
	jsonEnc := zapcore.NewJSONEncoder(jsonEncoderConfig(&newConfig.EncoderConfig))
	for ch, re := range rebuildRequired {
		if !re {
			continue
		}
		core, closer, err := buildChannelCore(newConfig, ch, &consoleEnc, &jsonEnc, true)
		if err != nil {
			return err
		}
		var log *zap.Logger
		switch ch {
		case config.ChannelApp:
			log = logger.appOriginal
		case config.ChannelSecurity:
			log = logger.securityOriginal
		case config.ChannelAudit:
			log = logger.auditOriginal
		}
		if log != nil {
			_ = log.Sync()
		}
		for _, cl := range logger.closerFns[ch.String()] {
			err = cl.Close()
			if err != nil {
				return err
			}
		}
		logger.closerFns[ch.String()] = closer
		switch ch {
		case config.ChannelApp:
			logger.appOriginal = zap.New(core)
		case config.ChannelSecurity:
			logger.securityOriginal = zap.New(core)
		case config.ChannelAudit:
			logger.auditOriginal = zap.New(core)
		}
	}
	for ch, chCfg := range channelConfigs {
		newChCfg := newChannelConfigs[ch]
		if rebuildRequired[ch] ||
			chCfg.Enabled != newChCfg.Enabled ||
			chCfg.ShowCaller != newChCfg.ShowCaller ||
			chCfg.ShowStacktrace != newChCfg.ShowStacktrace ||
			chCfg.StacktraceLevel != newChCfg.StacktraceLevel {
			switch ch {
			case config.ChannelApp:
				logger.App = common.Ternary(newChCfg.Enabled,
					attachOptions(logger.appOriginal, newChCfg), zap.NewNop())
			case config.ChannelSecurity:
				logger.Security = common.Ternary(newChCfg.Enabled,
					attachOptions(logger.securityOriginal, newChCfg), zap.NewNop())
			case config.ChannelAudit:
				logger.Audit = common.Ternary(newChCfg.Enabled,
					attachOptions(logger.auditOriginal, newChCfg), zap.NewNop())
			}
		}
	}

	logger.LoggerConfig = newConfig

	return nil
}
