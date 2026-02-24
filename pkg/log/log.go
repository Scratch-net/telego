// Package log provides structured logging using zerolog.
package log

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Logger is the global logger instance.
var Logger zerolog.Logger

func init() {
	// Default to info level with console output
	Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger().
		Level(zerolog.InfoLevel)
}

// SetLevel sets the global log level.
func SetLevel(level string) {
	switch level {
	case "trace":
		Logger = Logger.Level(zerolog.TraceLevel)
	case "debug":
		Logger = Logger.Level(zerolog.DebugLevel)
	case "info":
		Logger = Logger.Level(zerolog.InfoLevel)
	case "warn", "warning":
		Logger = Logger.Level(zerolog.WarnLevel)
	case "error":
		Logger = Logger.Level(zerolog.ErrorLevel)
	case "fatal":
		Logger = Logger.Level(zerolog.FatalLevel)
	case "disabled", "none":
		Logger = Logger.Level(zerolog.Disabled)
	default:
		Logger = Logger.Level(zerolog.InfoLevel)
	}
}

// SetJSON switches to JSON output format.
func SetJSON() {
	Logger = zerolog.New(os.Stderr).With().Timestamp().Logger().Level(Logger.GetLevel())
}

// Convenience functions
func Trace() *zerolog.Event { return Logger.Trace() }
func Debug() *zerolog.Event { return Logger.Debug() }
func Info() *zerolog.Event  { return Logger.Info() }
func Warn() *zerolog.Event  { return Logger.Warn() }
func Error() *zerolog.Event { return Logger.Error() }
func Fatal() *zerolog.Event { return Logger.Fatal() }
