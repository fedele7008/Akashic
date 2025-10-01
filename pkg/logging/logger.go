package logging

import (
	"akashic/akashic/pkg/common"
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
	LoggerConfig     *Config
	ServiceName      string
	ServiceEnv       string
	App              *zap.Logger
	Security         *zap.Logger
	Audit            *zap.Logger
	ForceAuditAppend bool
	closerFns        map[Channel][]io.Closer
}

func consoleEncoderConfig(encConfig *EncoderConfig) zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:       encConfig.TimestampKey.GetOrDefault(),
		LevelKey:      encConfig.LevelKey.GetOrDefault(),
		NameKey:       encConfig.NameKey.GetOrDefault(),
		CallerKey:     encConfig.CallerKey.GetOrDefault(),
		MessageKey:    encConfig.MessageKey.GetOrDefault(),
		StacktraceKey: encConfig.StacktraceKey.GetOrDefault(),
		LineEnding:    zapcore.DefaultLineEnding,
		EncodeLevel:   zapcore.CapitalLevelEncoder,
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(t.UTC().Format(encConfig.TimeFormatKey.GetOrDefault()))
		},
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		ConsoleSeparator: " ",
	}
}

func jsonEncoderConfig(encConfig *EncoderConfig) zapcore.EncoderConfig {
	c := consoleEncoderConfig(encConfig)
	c.EncodeLevel = zapcore.LowercaseLevelEncoder
	return c
}

func openFileSink(sinkCfg *SinkConfig, isRebuild bool) (io.Writer, io.Closer, error) {
	if sinkCfg.FilePath.GetOrDefault() == "" {
		return nil, nil, fmt.Errorf("SinkConfig config missing file_path")
	}
	if err := os.MkdirAll(filepath.Dir(sinkCfg.FilePath.GetOrDefault()), 0o755); err != nil {
		return nil, nil, err
	}
	switch sinkCfg.FileMode.GetOrDefault() {
	case FileAppend:
		w, err := NewAppendingFileWriter(sinkCfg.FilePath.GetOrDefault())
		return w, w, err
	case FileTruncate:
		if isRebuild {
			w, err := NewAppendingFileWriter(sinkCfg.FilePath.GetOrDefault())
			return w, w, err
		}
		w, err := NewTruncatedFileWriter(sinkCfg.FilePath.GetOrDefault())
		return w, w, err
	case FileRolling:
		w, err := NewRollingFileWriter(sinkCfg.FilePath.GetOrDefault(), sinkCfg.MaxSizeMB.GetOrDefault(), sinkCfg.MaxBackups.GetOrDefault())
		return w, w, err
	default:
		return nil, nil, fmt.Errorf("unknown file mode: %v", sinkCfg.FileMode.GetOrDefault())
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

func buildChannelCore(cfg *Config, ch Channel, consoleEnc, jsonEnc *zapcore.Encoder, isRebuild bool) (zapcore.Core, []io.Closer, error) {
	// find channel config
	var chCfg *ChannelConfig
	switch ch {
	case ChannelApp:
		chCfg = &cfg.App
	case ChannelSecurity:
		chCfg = &cfg.Security
	case ChannelAudit:
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

		if !sinkCfg.Enabled.GetOrDefault() {
			continue
		}
		enabler := levelToEnabler(sinkCfg.Level.IfValidGet(DefaultLevel))

		switch sinkCfg.Type.GetOrDefault() {
		case SinkStdout:
			var enc *zapcore.Encoder
			switch sinkCfg.Format.GetOrDefault() {
			case FormatText:
				enc = consoleEnc
			case FormatJSON:
				enc = jsonEnc
			default:
				return nil, nil, fmt.Errorf("%s: unknown sink format: %v", ch.String(), sinkCfg.Format.GetOrDefault())
			}
			cores = append(cores, zapcore.NewCore(*enc, zapcore.AddSync(os.Stdout), enabler))
		case SinkStderr:
			var enc *zapcore.Encoder
			switch sinkCfg.Format.GetOrDefault() {
			case FormatText:
				enc = consoleEnc
			case FormatJSON:
				enc = jsonEnc
			default:
				return nil, nil, fmt.Errorf("%s: unknown sink format: %v", ch.String(), sinkCfg.Format.GetOrDefault())
			}
			cores = append(cores, zapcore.NewCore(*enc, zapcore.AddSync(os.Stderr), enabler))
		case SinkFile:
			if sinkCfg.FilePath.GetOrDefault() == "" {
				return nil, nil, fmt.Errorf("%s: invalid file path: %v", ch.String(), sinkCfg.FilePath.GetOrDefault())
			}
			if ch == ChannelAudit && cfg.ForceAuditAppend.GetOrDefault() {
				appendModeOpt := SetOptional[FileMode](FileAppend)
				sinkCfg.FileMode = appendModeOpt
			}
			writer, closer, err := openFileSink(sinkCfg, isRebuild)
			if err != nil {
				return nil, nil, err
			}
			if closer != nil {
				closers = append(closers, closer)
			}
			var enc *zapcore.Encoder
			switch sinkCfg.Format.GetOrDefault() {
			case FormatText:
				enc = consoleEnc
			case FormatJSON:
				enc = jsonEnc
			default:
				return nil, nil, fmt.Errorf("%s: unknown sink format: %v", ch.String(), sinkCfg.Format.GetOrDefault())
			}
			cores = append(cores, zapcore.NewCore(*enc, zapcore.AddSync(writer), enabler))
		case SinkLoki:
			// configure must have stream keys for Loki api
			labels := map[string]string{
				"service_name": cfg.Service.GetOrDefault(),
				"env":          cfg.Env.GetOrDefault(),
				"channel":      ch.String(),
			}
			maps.Copy(labels, sinkCfg.LokiLabels.GetOrDefault())
			lokiWriter, err := NewLokiWriter(sinkCfg, labels)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", ch.String(), err)
			}
			closers = append(closers, lokiWriter)
			cores = append(cores, zapcore.NewCore(*jsonEnc, zapcore.AddSync(lokiWriter), enabler))
		default:
			return nil, nil, fmt.Errorf("%s: unknown sink type: %v", ch.String(), sinkCfg.Type.GetOrDefault())
		}
	}

	return zapcore.NewTee(cores...), closers, nil
}

func attachOptions(logger *zap.Logger, chCfg *ChannelConfig) *zap.Logger {
	var opts []zap.Option
	if chCfg.ShowCaller.GetOrDefault() {
		opts = append(opts, zap.AddCaller())
	}
	if chCfg.ShowStacktrace.GetOrDefault() {
		lv := levelToEnabler(chCfg.StacktraceLevel.IfValidGet(DefaultStacktraceLevel))
		opts = append(opts, zap.AddStacktrace(lv))
	}
	return logger.WithOptions(opts...)
}

func New(cfg *Config) (logger *Logger, closeFn func(), err error) {
	// try to fill any undefined optional values
	if err = cfg.FillDefaults(); err != nil {
		return nil, nil, err
	}

	config := cfg.Clone()

	logger = &Logger{
		appOriginal:      nil,
		securityOriginal: nil,
		auditOriginal:    nil,
		LoggerConfig:     config,
		ServiceName:      config.Service.GetOrDefault(),
		ServiceEnv:       config.Env.GetOrDefault(),
		App:              nil,
		Security:         nil,
		Audit:            nil,
		ForceAuditAppend: config.ForceAuditAppend.GetOrDefault(),
		closerFns:        make(map[Channel][]io.Closer),
	}
	consoleEnc := zapcore.NewConsoleEncoder(consoleEncoderConfig(&logger.LoggerConfig.EncoderConfig))
	jsonEnc := zapcore.NewJSONEncoder(jsonEncoderConfig(&logger.LoggerConfig.EncoderConfig))

	appCore, appCloser, err := buildChannelCore(logger.LoggerConfig, ChannelApp, &consoleEnc, &jsonEnc, false)
	if err != nil {
		return nil, nil, err
	}
	logger.closerFns[ChannelApp] = appCloser

	securityCore, securityCloser, err := buildChannelCore(logger.LoggerConfig, ChannelSecurity, &consoleEnc, &jsonEnc, false)
	if err != nil {
		return nil, nil, err
	}
	logger.closerFns[ChannelSecurity] = securityCloser

	auditCore, auditCloser, err := buildChannelCore(logger.LoggerConfig, ChannelAudit, &consoleEnc, &jsonEnc, false)
	if err != nil {
		return nil, nil, err
	}
	logger.closerFns[ChannelAudit] = auditCloser

	logger.appOriginal = zap.New(appCore)
	logger.securityOriginal = zap.New(securityCore)
	logger.auditOriginal = zap.New(auditCore)

	logger.App = common.Ternary(logger.LoggerConfig.App.Enabled.GetOrDefault(),
		attachOptions(logger.appOriginal, &logger.LoggerConfig.App), zap.NewNop())
	logger.Security = common.Ternary(logger.LoggerConfig.Security.Enabled.GetOrDefault(),
		attachOptions(logger.securityOriginal, &logger.LoggerConfig.Security), zap.NewNop())
	logger.Audit = common.Ternary(logger.LoggerConfig.Audit.Enabled.GetOrDefault(),
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

func (logger *Logger) Reconfigure(cfg *Config) error {
	if err := cfg.FillDefaults(); err != nil {
		return err
	}
	oldConfig := logger.LoggerConfig
	newConfig := cfg.Clone()

	channelConfigs := map[Channel]*ChannelConfig{
		ChannelApp:      &oldConfig.App,
		ChannelSecurity: &oldConfig.Security,
		ChannelAudit:    &oldConfig.Audit,
	}
	newChannelConfigs := map[Channel]*ChannelConfig{
		ChannelApp:      &newConfig.App,
		ChannelSecurity: &newConfig.Security,
		ChannelAudit:    &newConfig.Audit,
	}
	rebuildRequired := map[Channel]bool{
		ChannelApp:      false,
		ChannelSecurity: false,
		ChannelAudit:    false,
	}
	if oldConfig.Service != newConfig.Service || oldConfig.Env != newConfig.Env {
		// Loki sink requires service and env values for labeling
		for ch, chCfg := range channelConfigs {
			for i := range chCfg.Sinks {
				sink := &chCfg.Sinks[i]
				if sink.Type.GetOrDefault() == SinkLoki {
					rebuildRequired[ch] = true
				}
			}
		}
	}
	if oldConfig.EncoderConfig != newConfig.EncoderConfig {
		// encoder is applied for all channels, require to rebuild all
		rebuildRequired[ChannelApp] = true
		rebuildRequired[ChannelSecurity] = true
		rebuildRequired[ChannelAudit] = true
	}
	if oldConfig.ForceAuditAppend != newConfig.ForceAuditAppend {
		// force-audit-append option is only applicable for audit channel
		rebuildRequired[ChannelAudit] = true
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
		case ChannelApp:
			log = logger.appOriginal
		case ChannelSecurity:
			log = logger.securityOriginal
		case ChannelAudit:
			log = logger.auditOriginal
		}
		if log != nil {
			_ = log.Sync()
		}
		for _, cl := range logger.closerFns[ch] {
			err = cl.Close()
			if err != nil {
				return err
			}
		}
		logger.closerFns[ch] = closer
		switch ch {
		case ChannelApp:
			logger.appOriginal = zap.New(core)
		case ChannelSecurity:
			logger.securityOriginal = zap.New(core)
		case ChannelAudit:
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
			case ChannelApp:
				logger.App = common.Ternary(newChCfg.Enabled.GetOrDefault(),
					attachOptions(logger.appOriginal, newChCfg), zap.NewNop())
			case ChannelSecurity:
				logger.Security = common.Ternary(newChCfg.Enabled.GetOrDefault(),
					attachOptions(logger.securityOriginal, newChCfg), zap.NewNop())
			case ChannelAudit:
				logger.Audit = common.Ternary(newChCfg.Enabled.GetOrDefault(),
					attachOptions(logger.auditOriginal, newChCfg), zap.NewNop())
			}
		}
	}

	logger.LoggerConfig = newConfig

	return nil
}
