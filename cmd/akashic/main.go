package main

import (
	"akashic/akashic/pkg/logger"

	"go.uber.org/zap"
)

func main() {
	// TOOD: Make all config to have default values
	lokiUrl := "http://localhost:3100/loki/api/v1/push"
	logCfg := &logger.Config{
		Service: "akashic",
		Env:     "dev",
		App: logger.ChannelConfig{
			Enabled: true,
			Sinks: []logger.SinkConfig{
				logger.SinkConfig{
					Type:    logger.SinkStdout,
					Enabled: true,
					Level:   logger.LevelInfo,
					Format:  logger.FormatText,
				},
				logger.SinkConfig{
					Type:       logger.SinkFile,
					Enabled:    true,
					Level:      logger.LevelDebug,
					Format:     logger.FormatText,
					FilePath:   "logs/app.log",
					FileMode:   logger.FileRolling,
					MaxSizeMB:  100,
					MaxBackups: 3,
				},
				logger.SinkConfig{
					Type:     logger.SinkLoki,
					Enabled:  true,
					Level:    logger.LevelDebug,
					LokiURL:  lokiUrl,
					Compress: false,
				},
			},
		},
		Security: logger.ChannelConfig{
			Enabled: true,
			Sinks: []logger.SinkConfig{
				logger.SinkConfig{
					Type:    logger.SinkStdout,
					Enabled: true,
					Level:   logger.LevelInfo,
					Format:  logger.FormatText,
				},
				logger.SinkConfig{
					Type:       logger.SinkFile,
					Enabled:    true,
					Level:      logger.LevelDebug,
					Format:     logger.FormatText,
					FilePath:   "logs/security.log",
					FileMode:   logger.FileRolling,
					MaxSizeMB:  100,
					MaxBackups: 3,
				},
				logger.SinkConfig{
					Type:     logger.SinkLoki,
					Enabled:  true,
					Level:    logger.LevelDebug,
					LokiURL:  lokiUrl,
					Compress: true,
				},
			},
		},
		Audit: logger.ChannelConfig{
			Enabled: true,
			Sinks: []logger.SinkConfig{
				logger.SinkConfig{
					Type:    logger.SinkStdout,
					Enabled: true,
					Level:   logger.LevelInfo,
					Format:  logger.FormatText,
				},
				logger.SinkConfig{
					Type:       logger.SinkFile,
					Enabled:    true,
					Level:      logger.LevelDebug,
					Format:     logger.FormatText,
					FilePath:   "logs/audit.log",
					FileMode:   logger.FileRolling,
					MaxSizeMB:  100,
					MaxBackups: 3,
				},
				logger.SinkConfig{
					Type:     logger.SinkLoki,
					Enabled:  true,
					Level:    logger.LevelDebug,
					LokiURL:  lokiUrl,
					Compress: true,
				},
			},
		},
		ForceAuditAppend: true,
	}

	logger, loggerCloseFn, err := logger.New(logCfg)
	if err != nil {
		panic(err)
	}
	defer loggerCloseFn()

	logger.App.Debug("App debug log", zap.Int("some-key", 123))
	logger.App.Info("App info log", zap.String("some-key", "some-value"))
	logger.App.Warn("App warning log", zap.Error(err))
	logger.App.Error("App error log", zap.Int("some-key", 456))

	logger.Security.Debug("Security debug log", zap.Int("some-key", 123))
	logger.Security.Info("Security info log", zap.String("some-key", "some-value"))
	logger.Security.Warn("Security warning log", zap.Error(err))
	logger.Security.Error("Security error log", zap.Int("some-key", 456))

	logger.Audit.Debug("Audit debug log", zap.Int("some-key", 123))
	logger.Audit.Info("Audit info log", zap.String("some-key", "some-value"))
	logger.Audit.Warn("Audit warning log", zap.Error(err))
	logger.Audit.Error("Audit error log", zap.Int("some-key", 456))
}
