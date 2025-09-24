package main

import (
	"akashic/akashic/pkg/logging"
	"fmt"

	"go.uber.org/zap"
)

func main() {
	lokiUrl := "http://localhost:3100/loki/api/v1/push"
	logCfg := logging.GetConfig("akashic", "dev")
	if logCfg == nil {
		return
	}
	if err := logCfg.RegisterSink(logging.ChannelApp, &logging.SinkConfig{
		Type:    logging.SetRequired(logging.SinkStdout),
		Enabled: logging.SetRequired(true),
		Format:  logging.SetOptional(logging.FormatText),
	}); err != nil {
		fmt.Println(err)
	}
	if err := logCfg.RegisterSink(logging.ChannelApp, &logging.SinkConfig{
		Type:       logging.SetRequired(logging.SinkFile),
		Enabled:    logging.SetRequired(true),
		Level:      logging.SetOptional(logging.LevelDebug),
		Format:     logging.SetOptional(logging.FormatText),
		FilePath:   logging.SetRequired("logs/app.log"),
		FileMode:   logging.SetOptional(logging.FileTruncate),
		MaxSizeMB:  logging.SetOptional(1),
		MaxBackups: logging.SetOptional(1),
	}); err != nil {
		fmt.Println(err)
	}
	if err := logCfg.RegisterSink(logging.ChannelApp, &logging.SinkConfig{
		Type:    logging.SetRequired(logging.SinkLoki),
		Enabled: logging.SetRequired(true),
		Level:   logging.SetOptional(logging.LevelDebug),
		LokiURL: logging.SetRequired(lokiUrl),
	}); err != nil {
		fmt.Println(err)
	}
	logCfg.App.StacktraceLevel = logging.SetOptional(logging.LevelFatal)

	logger, loggerCloseFn, err := logging.New(logCfg)
	if err != nil {
		panic(err)
	}
	defer loggerCloseFn()

	for i := 0; i < 1; i++ {
		logger.App.Debug(fmt.Sprintf("App %v", i), zap.Int("some-key", 123))
		logger.App.Info(fmt.Sprintf("App %v", i), zap.String("some-key", "some-value"))
		logger.App.Error(fmt.Sprintf("App %v", i), zap.String("some-key", "some-value error"))

		logger.Security.Debug("Security debug log", zap.Int("some-key", 123))
		logger.Security.Info("Security info log", zap.String("some-key", "some-value"))

		logger.Audit.Debug("Audit debug log", zap.Int("some-key", 123))
		logger.Audit.Info("Audit info log", zap.String("some-key", "some-value"))
	}

	newLogCfg := logCfg.Clone()
	newLogCfg.Env = logging.SetRequired("Release")
	newLogCfg.App.Sinks[0].Enabled = logging.SetRequired(false)
	//newLogCfg.App.Sinks[0].Type = logging.SetRequired(logging.SinkStderr)
	if err = newLogCfg.RegisterSink(logging.ChannelAudit, &logging.SinkConfig{
		Type:    logging.SetRequired(logging.SinkStdout),
		Enabled: logging.SetRequired(true),
		Level:   logging.SetOptional(logging.LevelDebug),
		Format:  logging.SetOptional(logging.FormatText),
	}); err != nil {
		fmt.Println(err)
	}
	err = logger.Reconfigure(newLogCfg)
	if err != nil {
		fmt.Println(err)
	}
	for i := 0; i < 1; i++ {
		logger.App.Debug(fmt.Sprintf("App %v", i), zap.Int("some-key", 123))
		logger.App.Info(fmt.Sprintf("App %v", i), zap.String("some-key", "some-value"))
		logger.App.Error(fmt.Sprintf("App %v", i), zap.String("some-key", "some-value error"))

		logger.Security.Debug("Security debug log", zap.Int("some-key", 123))
		logger.Security.Info("Security info log", zap.String("some-key", "some-value"))

		logger.Audit.Debug("Audit debug log", zap.Int("some-key", 123))
		logger.Audit.Info("Audit info log", zap.String("some-key", "some-value"))
	}
}
