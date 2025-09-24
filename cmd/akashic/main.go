package main

import (
	"akashic/akashic/pkg/logging"
	"fmt"
	"time"

	"go.uber.org/zap"
)

func main() {
	// TODO: Make all config to have default values
	lokiUrl := "http://localhost:3100/loki/api/v1/push"
	//logCfg := &logging.Config{
	//	Service: "akashic",
	//	Env:     "dev",
	//	App: logging.ChannelConfig{
	//		Enabled: common.MakeNullable(true),
	//		Sinks: []logging.SinkConfig{
	//			{
	//				Type:   logging.SinkStdout,
	//				Level:  logging.LevelInfo,
	//				Format: logging.FormatText,
	//			},
	//			{
	//				Type:       logging.SinkFile,
	//				Level:      logging.LevelDebug,
	//				Format:     logging.FormatText,
	//				FilePath:   "logs/app.log",
	//				FileMode:   logging.FileRolling,
	//				MaxSizeMB:  100,
	//				MaxBackups: 3,
	//			},
	//			{
	//				Type:     logging.SinkLoki,
	//				Level:    logging.LevelDebug,
	//				LokiURL:  lokiUrl,
	//				Compress: common.MakeNullable(false),
	//			},
	//		},
	//	},
	//	Security: logging.ChannelConfig{
	//		Enabled: common.MakeNullable(true),
	//		Sinks: []logging.SinkConfig{
	//			{
	//				Type:   logging.SinkStdout,
	//				Level:  logging.LevelInfo,
	//				Format: logging.FormatText,
	//			},
	//			{
	//				Type:       logging.SinkFile,
	//				Level:      logging.LevelDebug,
	//				Format:     logging.FormatText,
	//				FilePath:   "logs/security.log",
	//				FileMode:   logging.FileRolling,
	//				MaxSizeMB:  1,
	//				MaxBackups: 1,
	//			},
	//			{
	//				Type:     logging.SinkLoki,
	//				Level:    logging.LevelDebug,
	//				LokiURL:  lokiUrl,
	//				Compress: common.MakeNullable(true),
	//			},
	//		},
	//	},
	//	Audit: logging.ChannelConfig{
	//		Enabled: common.MakeNullable(true),
	//		Sinks: []logging.SinkConfig{
	//			{
	//				Type:   logging.SinkStdout,
	//				Level:  logging.LevelInfo,
	//				Format: logging.FormatText,
	//			},
	//			{
	//				Type:       logging.SinkFile,
	//				Level:      logging.LevelDebug,
	//				Format:     logging.FormatText,
	//				FilePath:   "logs/audit.log",
	//				FileMode:   logging.FileRolling,
	//				MaxSizeMB:  100,
	//				MaxBackups: 3,
	//			},
	//			{
	//				Type:     logging.SinkLoki,
	//				Level:    logging.LevelDebug,
	//				LokiURL:  lokiUrl,
	//				Compress: common.MakeNullable(true),
	//			},
	//		},
	//	},
	//	ForceAuditAppend: common.MakeNullable(true),
	//}
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
		FileMode:   logging.SetOptional(logging.FileRolling),
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

	for i := 0; true; i++ {
		time.Sleep(500 * time.Millisecond)
		logger.App.Debug(fmt.Sprintf("App %v", i), zap.Int("some-key", 123))
		logger.App.Info(fmt.Sprintf("App %v", i), zap.String("some-key", "some-value"))
		logger.App.Error(fmt.Sprintf("App %v", i), zap.String("some-key", "some-value error"))

		//logging.Security.Debug("Security debug log", zap.Int("some-key", 123))
		//logging.Security.Info("Security info log", zap.String("some-key", "some-value"))
		//
		//logging.Audit.Debug("Audit debug log", zap.Int("some-key", 123))
		//logging.Audit.Info("Audit info log", zap.String("some-key", "some-value"))
	}
	// for {
	// 	time.Sleep(1 * time.Second)
	// }
}
