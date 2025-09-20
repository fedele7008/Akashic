package logger

import (
	"fmt"
	"strings"
)

type LogLevel int

const (
	Trace LogLevel = iota
	Debug
	Info
	Warn
	Error
	Fatal
)

func (lv LogLevel) String() string {
	switch lv {
	case Trace:
		return "TRACE"
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	default:
		return fmt.Sprintf("UNKNOWN(%v)", int(lv))
	}
}

func ParseLogLevel(lv string) (LogLevel, error) {
	switch strings.ToUpper(strings.TrimSpace(lv)) {
	case "TRACE":
		return Trace, nil
	case "DEBUG":
		return Debug, nil
	case "INFO":
		return Info, nil
	case "WARN":
		return Warn, nil
	case "ERROR":
		return Error, nil
	case "FATAL":
		return Fatal, nil
	default:
		return 0, fmt.Errorf("invalid log level: %s", lv)
	}
}
