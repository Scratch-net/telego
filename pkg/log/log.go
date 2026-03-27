// Package log provides structured logging using zerolog.
package log

import (
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// logger holds a pointer to the global logger for thread-safe access.
// We use atomic.Pointer instead of atomic.Value for type safety and to avoid
// the pointer-method-on-value issue with zerolog.Logger.
var logger atomic.Pointer[zerolog.Logger]

func init() {
	// Default to info level with console output
	l := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger().
		Level(zerolog.InfoLevel)
	logger.Store(&l)
}

// getLogger returns the current logger instance.
func getLogger() *zerolog.Logger {
	return logger.Load()
}

// SetLevel sets the global log level.
func SetLevel(level string) {
	l := *getLogger()
	switch level {
	case "trace":
		l = l.Level(zerolog.TraceLevel)
	case "debug":
		l = l.Level(zerolog.DebugLevel)
	case "info":
		l = l.Level(zerolog.InfoLevel)
	case "warn", "warning":
		l = l.Level(zerolog.WarnLevel)
	case "error":
		l = l.Level(zerolog.ErrorLevel)
	case "fatal":
		l = l.Level(zerolog.FatalLevel)
	case "disabled", "none":
		l = l.Level(zerolog.Disabled)
	default:
		l = l.Level(zerolog.InfoLevel)
	}
	logger.Store(&l)
}

// SetJSON switches to JSON output format.
func SetJSON() {
	l := getLogger()
	newL := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(l.GetLevel())
	logger.Store(&newL)
}

// Convenience functions
func Trace() *zerolog.Event { return getLogger().Trace() }
func Debug() *zerolog.Event { return getLogger().Debug() }
func Info() *zerolog.Event  { return getLogger().Info() }
func Warn() *zerolog.Event  { return getLogger().Warn() }
func Error() *zerolog.Event { return getLogger().Error() }
func Fatal() *zerolog.Event { return getLogger().Fatal() }
