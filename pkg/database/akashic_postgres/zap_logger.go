package akashic_postgres

import (
	"context"
	"errors"
	"time"

	"akashic/akashic/pkg/logging"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// zapGormLogger adapts GORM's logger.Interface to the project's zap
// logger so every GORM-emitted line lands in the same structured
// stream as the rest of the app — same timestamp format, levels,
// fields, sinks (stdout, file, Loki). Without this adapter GORM
// uses Go's stdlib log package and produces lines like:
//
//   2026/04/26 03:00:50 /path/to/file.go:86 record not found
//
// which look completely different from the project's zap output.
//
// The adapter routes:
//   - Info/Warn/Error → app channel at the matching zap level
//   - Trace (per-query) → app channel; SQL goes to debug, slow
//     queries to warn, errors to error. Slow-query threshold matches
//     GORM's default (200ms).
type zapGormLogger struct {
	z                 *logging.Logger
	level             logger.LogLevel
	slowThreshold     time.Duration
	ignoreNotFound    bool
}

// newZapGormLogger constructs a GORM-compatible logger that delegates
// to the supplied zap logger. level is GORM's verbosity threshold;
// queries below this level are silently dropped.
func newZapGormLogger(z *logging.Logger, level logger.LogLevel) *zapGormLogger {
	return &zapGormLogger{
		z:              z,
		level:          level,
		slowThreshold:  200 * time.Millisecond,
		// Don't propagate "record not found" as warnings — it's not
		// generally an error. Code paths that care about the error
		// already check for ErrRecordNotFound explicitly.
		ignoreNotFound: true,
	}
}

// LogMode implements logger.Interface. Returns a copy with the new
// log level so the caller can scope verbosity per session if needed
// (e.g. db.Session(&gorm.Session{Logger: l.LogMode(logger.Silent)})).
func (l *zapGormLogger) LogMode(level logger.LogLevel) logger.Interface {
	cp := *l
	cp.level = level
	return &cp
}

func (l *zapGormLogger) Info(ctx context.Context, msg string, args ...any) {
	if l.level < logger.Info {
		return
	}
	l.z.App.Sugar().Infof("[gorm] "+msg, args...)
}

func (l *zapGormLogger) Warn(ctx context.Context, msg string, args ...any) {
	if l.level < logger.Warn {
		return
	}
	l.z.App.Sugar().Warnf("[gorm] "+msg, args...)
}

func (l *zapGormLogger) Error(ctx context.Context, msg string, args ...any) {
	if l.level < logger.Error {
		return
	}
	l.z.App.Sugar().Errorf("[gorm] "+msg, args...)
}

// Trace is called once per query with timing + outcome. We split it
// into three branches:
//   - Error (other than ErrRecordNotFound when ignoreNotFound is true)
//     → app.Error with structured fields
//   - Slow (no error, but elapsed > slowThreshold)
//     → app.Warn — these are real performance signals
//   - Otherwise, at Info level only
//     → app.Debug — too chatty for Info; visible only when an
//       operator explicitly turns the level up.
func (l *zapGormLogger) Trace(
	ctx context.Context,
	begin time.Time,
	fc func() (sql string, rowsAffected int64),
	err error,
) {
	if l.level <= logger.Silent {
		return
	}

	elapsed := time.Since(begin)
	switch {
	case err != nil && l.level >= logger.Error &&
		!(l.ignoreNotFound && errors.Is(err, gorm.ErrRecordNotFound)):
		sql, rows := fc()
		l.z.App.Error("[gorm] query error",
			zap.Error(err),
			zap.Duration("elapsed", elapsed),
			zap.Int64("rows", rows),
			zap.String("sql", sql),
		)
	case elapsed > l.slowThreshold && l.slowThreshold > 0 && l.level >= logger.Warn:
		sql, rows := fc()
		l.z.App.Warn("[gorm] slow query",
			zap.Duration("elapsed", elapsed),
			zap.Duration("threshold", l.slowThreshold),
			zap.Int64("rows", rows),
			zap.String("sql", sql),
		)
	case l.level >= logger.Info:
		sql, rows := fc()
		l.z.App.Debug("[gorm] query",
			zap.Duration("elapsed", elapsed),
			zap.Int64("rows", rows),
			zap.String("sql", sql),
		)
	}
}
