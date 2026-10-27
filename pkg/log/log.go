// Package log provides structured logging using zerolog.
package log

import (
	"context"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// logger holds a pointer to the global logger for thread-safe access.
// We use atomic.Pointer instead of atomic.Value for type safety and to avoid
// the pointer-method-on-value issue with zerolog.Logger.
var logger atomic.Pointer[zerolog.Logger]

var (
	dropped atomic.Uint64
	output  = &formatWriter{
		raw:     os.Stderr,
		console: zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	}
	writer = newAsyncWriter(output, 4096, countDropped)
)

func countDropped(missed int) { dropped.Add(uint64(missed)) }

// formatWriter runs only on the consumer, after the JSON event has been queued.
// It deliberately implements only io.Writer: stderr belongs to the process.
type formatWriter struct {
	raw     io.Writer
	console zerolog.ConsoleWriter
	json    atomic.Bool
}

func (w *formatWriter) Write(p []byte) (int, error) {
	if w.json.Load() {
		return w.raw.Write(p)
	}
	return w.console.Write(p)
}

func init() {
	// Default to info level with console output
	l := zerolog.New(writer).
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
	output.json.Store(true)
}

// DroppedMessages returns the lifetime number of events dropped because the
// queue is full or shutdown has started. Producers update the count on rejection.
func DroppedMessages() uint64 { return dropped.Load() }

// Shutdown stops admitting events and drains the queue until ctx expires.
// A blocked sink can outlive the deadline; subsequent calls join the same drain.
func Shutdown(ctx context.Context) error { return writer.Shutdown(ctx) }

// Close drains the logger with the same bounded timeout used by Fatal.
func Close() error { return writer.Close() }

// Convenience functions
func Trace() *zerolog.Event { return getLogger().Trace() }
func Debug() *zerolog.Event { return getLogger().Debug() }
func Info() *zerolog.Event  { return getLogger().Info() }
func Warn() *zerolog.Event  { return getLogger().Warn() }
func Error() *zerolog.Event { return getLogger().Error() }
func Fatal() *zerolog.Event { return getLogger().Fatal() }
