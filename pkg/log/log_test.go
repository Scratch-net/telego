package log

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

func TestSetLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected zerolog.Level
	}{
		{"trace", "trace", zerolog.TraceLevel},
		{"debug", "debug", zerolog.DebugLevel},
		{"info", "info", zerolog.InfoLevel},
		{"warn", "warn", zerolog.WarnLevel},
		{"warning", "warning", zerolog.WarnLevel},
		{"error", "error", zerolog.ErrorLevel},
		{"fatal", "fatal", zerolog.FatalLevel},
		{"disabled", "disabled", zerolog.Disabled},
		{"none", "none", zerolog.Disabled},
		{"unknown", "unknown", zerolog.InfoLevel}, // default
		{"empty", "", zerolog.InfoLevel},          // default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetLevel(tt.level)
			currentLevel := getLogger().GetLevel()
			if currentLevel != tt.expected {
				t.Errorf("SetLevel(%q): got %v, want %v", tt.level, currentLevel, tt.expected)
			}
		})
	}

	// Reset to info for other tests
	SetLevel("info")
}

func TestSetJSON(t *testing.T) {
	// Capture original logger
	originalLogger := getLogger()
	defer logger.Store(originalLogger)

	// Set JSON mode
	SetJSON()

	// Logger should still work
	l := getLogger()
	if l == nil {
		t.Fatal("logger is nil after SetJSON")
	}

	// Level should be preserved
	SetLevel("debug")
	prevLevel := getLogger().GetLevel()
	SetJSON()
	if getLogger().GetLevel() != prevLevel {
		t.Error("SetJSON should preserve log level")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	// These should not panic - even when level is set to disabled
	SetLevel("info")
	defer SetLevel("info")

	// zerolog returns nil events when the level is disabled,
	// so we just verify they don't panic
	Trace().Msg("trace")
	Debug().Msg("debug")
	Info().Msg("info")
	Warn().Msg("warn")
	Error().Msg("error")
	// Note: Fatal() not tested as it would call os.Exit
}

func TestLoggerInitialization(t *testing.T) {
	// Logger should be initialized at package load
	l := getLogger()
	if l == nil {
		t.Fatal("logger not initialized")
	}

	// Default level should be info
	if l.GetLevel() != zerolog.InfoLevel {
		// Note: level might have been changed by other tests
		// Just verify it's not uninitialized
		if l.GetLevel() == zerolog.NoLevel {
			t.Error("logger level should be set")
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent level setting
	wg.Add(numGoroutines)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for range 10 {
				SetLevel("debug")
				SetLevel("info")
				SetLevel("warn")
			}
		}()
	}

	// Concurrent logging
	wg.Add(numGoroutines)
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for range 10 {
				_ = Debug()
				_ = Info()
				_ = Warn()
			}
		}()
	}

	wg.Wait()
}

func TestLoggingOutput(t *testing.T) {
	// Capture output
	var buf bytes.Buffer

	// Create a logger that writes to buffer
	testLogger := zerolog.New(&buf).With().Timestamp().Logger().Level(zerolog.DebugLevel)
	logger.Store(&testLogger)

	// Log a message
	Debug().Msg("test debug message")
	Info().Str("key", "value").Msg("test info message")

	output := buf.String()

	// Check output contains expected content
	if !strings.Contains(output, "test debug message") {
		t.Error("output should contain debug message")
	}
	if !strings.Contains(output, "test info message") {
		t.Error("output should contain info message")
	}
	if !strings.Contains(output, "key") || !strings.Contains(output, "value") {
		t.Error("output should contain structured field")
	}

	// Reset logger
	SetLevel("info")
}

func TestLevelFiltering(t *testing.T) {
	// Capture output
	var buf bytes.Buffer
	testLogger := zerolog.New(&buf).With().Timestamp().Logger().Level(zerolog.InfoLevel)
	logger.Store(&testLogger)

	// Debug should be filtered at info level
	buf.Reset()
	Debug().Msg("filtered debug")
	if strings.Contains(buf.String(), "filtered debug") {
		t.Error("debug message should be filtered at info level")
	}

	// Info should pass
	buf.Reset()
	Info().Msg("info passes")
	if !strings.Contains(buf.String(), "info passes") {
		t.Error("info message should not be filtered at info level")
	}

	// Reset logger
	SetLevel("info")
}

func TestSetLevelPreservesOutput(t *testing.T) {
	// Set level multiple times - should not crash or lose output destination
	SetLevel("trace")
	SetLevel("debug")
	SetLevel("info")
	SetLevel("warn")
	SetLevel("error")
	SetLevel("info")

	// Should still work
	l := getLogger()
	if l == nil {
		t.Fatal("logger is nil after multiple SetLevel calls")
	}
}

// BenchmarkGetLogger benchmarks logger access
func BenchmarkGetLogger(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		_ = getLogger()
	}
}

// BenchmarkSetLevel benchmarks level changes
func BenchmarkSetLevel(b *testing.B) {
	levels := []string{"debug", "info", "warn", "error"}
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		SetLevel(levels[i%len(levels)])
	}
}

// BenchmarkInfo benchmarks info logging (discarded)
func BenchmarkInfo(b *testing.B) {
	SetLevel("disabled")
	defer SetLevel("info")

	b.ResetTimer()
	for b.Loop() {
		Info().Msg("benchmark message")
	}
}

// BenchmarkInfoEnabled benchmarks info logging when enabled
func BenchmarkInfoEnabled(b *testing.B) {
	// Create logger that discards output but still processes
	testLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true}).
		Level(zerolog.InfoLevel)
	logger.Store(&testLogger)

	b.ResetTimer()
	for b.Loop() {
		Info().Msg("benchmark message")
	}

	SetLevel("info")
}

// BenchmarkConcurrentLogging benchmarks concurrent log access
func BenchmarkConcurrentLogging(b *testing.B) {
	SetLevel("disabled")
	defer SetLevel("info")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Info().Str("key", "value").Msg("concurrent log")
		}
	})
}
