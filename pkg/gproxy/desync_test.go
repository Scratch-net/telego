package gproxy

import (
	"sync"
	"testing"
)

func TestCheckFrameSize(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		wantFlag bool
	}{
		{"normal_small", 1000, false},
		{"normal_medium", 16384, false},
		{"at_limit", 64 * 1024, false},
		{"over_limit", 64*1024 + 1, true},
		{"way_over_limit", 1024 * 1024, true},
		{"zero", 0, false},
		{"negative", -1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckFrameSize(tt.size)
			if got != tt.wantFlag {
				t.Errorf("CheckFrameSize(%d) = %v, want %v", tt.size, got, tt.wantFlag)
			}
		})
	}
}

func TestDesyncDetector_Report(t *testing.T) {
	logger := &testLogger{}
	detector := NewDesyncDetector()
	ctx := NewConnContext()

	// First report should log
	logged := detector.Report(ctx, 100000, "c2dc", logger)
	if !logged {
		t.Error("first report should log")
	}
	if len(logger.warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(logger.warnings))
	}

	// Second immediate report should be deduplicated
	logged = detector.Report(ctx, 200000, "c2dc", logger)
	if logged {
		t.Error("immediate second report should be deduplicated")
	}
	if len(logger.warnings) != 1 {
		t.Errorf("expected still 1 warning, got %d", len(logger.warnings))
	}

	// Different direction should log
	logged = detector.Report(ctx, 150000, "dc2c", logger)
	if !logged {
		t.Error("different direction should log")
	}
	if len(logger.warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(logger.warnings))
	}
}

func TestDesyncDetector_DifferentConnections(t *testing.T) {
	logger := &testLogger{}
	detector := NewDesyncDetector()
	ctx1 := NewConnContext()
	ctx2 := NewConnContext()

	// Report for ctx1
	detector.Report(ctx1, 100000, "c2dc", logger)
	if len(logger.warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(logger.warnings))
	}

	// Report for ctx2 should also log (different connection)
	detector.Report(ctx2, 100000, "c2dc", logger)
	if len(logger.warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(logger.warnings))
	}
}

func TestDesyncDetector_Concurrent(t *testing.T) {
	detector := NewDesyncDetector()
	logger := &testLogger{}

	var wg sync.WaitGroup
	numGoroutines := 50
	reportsPerGoroutine := 10

	wg.Add(numGoroutines)
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			ctx := NewConnContext()
			for range reportsPerGoroutine {
				detector.Report(ctx, 100000, "c2dc", logger)
			}
		}(i)
	}

	wg.Wait()

	// Should have logged at least one per goroutine (first report)
	// But may have more due to timing (dedup window)
	if len(logger.warnings) < numGoroutines {
		t.Errorf("expected at least %d warnings, got %d", numGoroutines, len(logger.warnings))
	}
}

func TestDesyncDetector_DirectionKey(t *testing.T) {
	detector := NewDesyncDetector()
	logger := &testLogger{}
	ctx := NewConnContext()

	// Test c2dc direction
	logged := detector.Report(ctx, 100000, "c2dc", logger)
	if !logged {
		t.Error("c2dc should log first time")
	}

	// Test dc2c direction (should also log - different key)
	logged = detector.Report(ctx, 100000, "dc2c", logger)
	if !logged {
		t.Error("dc2c should log first time")
	}

	// Both c2dc and dc2c again should be deduplicated
	logged = detector.Report(ctx, 100000, "c2dc", logger)
	if logged {
		t.Error("c2dc should be deduplicated")
	}
	logged = detector.Report(ctx, 100000, "dc2c", logger)
	if logged {
		t.Error("dc2c should be deduplicated")
	}
}

func TestNewDesyncDetector(t *testing.T) {
	detector := NewDesyncDetector()
	if detector == nil {
		t.Fatal("NewDesyncDetector returned nil")
	}
	if detector.seen == nil {
		t.Error("seen map should be initialized")
	}
}

// testLogger implements Logger for testing
type testLogger struct {
	mu       sync.Mutex
	debugs   []string
	infos    []string
	warnings []string
	errors   []string
}

func (l *testLogger) Debug(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, format)
}

func (l *testLogger) Info(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, format)
}

func (l *testLogger) Warn(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, format)
}

func (l *testLogger) Error(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, format)
}

func (l *testLogger) DebugEnabled() bool {
	return true
}

// BenchmarkDesyncDetector_Report benchmarks the Report method
func BenchmarkDesyncDetector_Report(b *testing.B) {
	detector := NewDesyncDetector()
	logger := &testLogger{}
	ctx := NewConnContext()

	b.ResetTimer()
	for b.Loop() {
		detector.Report(ctx, 100000, "c2dc", logger)
	}
}

// BenchmarkDesyncDetector_ReportParallel benchmarks concurrent reporting
func BenchmarkDesyncDetector_ReportParallel(b *testing.B) {
	detector := NewDesyncDetector()
	logger := &testLogger{}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := NewConnContext()
		for pb.Next() {
			detector.Report(ctx, 100000, "c2dc", logger)
		}
	})
}

// BenchmarkCheckFrameSize benchmarks the frame size check
func BenchmarkCheckFrameSize(b *testing.B) {
	sizes := []int{1000, 16384, 65536, 100000}
	b.ResetTimer()
	for b.Loop() {
		for _, size := range sizes {
			CheckFrameSize(size)
		}
	}
}

// TestDesyncDetector_Cleanup tests that old entries are cleaned up
func TestDesyncDetector_Cleanup(t *testing.T) {
	detector := NewDesyncDetector()
	logger := &testLogger{}

	// Add many entries to trigger cleanup
	for range 1100 {
		ctx := NewConnContext()
		detector.Report(ctx, 100000, "c2dc", logger)
	}

	// The seen map should have been cleaned up
	// We can't easily test the exact cleanup behavior without modifying desyncDedupWindow
	// but we can verify the detector still works
	ctx := NewConnContext()
	logged := detector.Report(ctx, 100000, "c2dc", logger)
	if !logged {
		t.Error("should still log for new context after cleanup")
	}
}

// TestDesyncDetector_LogMessage verifies the log message format
func TestDesyncDetector_LogMessage(t *testing.T) {
	logger := &testLogger{}
	detector := NewDesyncDetector()
	ctx := NewConnContext()

	detector.Report(ctx, 100000, "c2dc", logger)

	if len(logger.warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(logger.warnings))
	}

	// Check the format string contains expected parts
	format := logger.warnings[0]
	expectedParts := []string{
		"desync detected",
		"frame size",
		"crypto state divergence",
	}
	for _, part := range expectedParts {
		found := false
		for _, w := range logger.warnings {
			if contains(w, part) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("warning should contain %q, got %q", part, format)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsSimple(s, substr)))
}

func containsSimple(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
