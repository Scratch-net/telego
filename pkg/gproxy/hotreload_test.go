package gproxy

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNewHotReloader(t *testing.T) {
	logger := &testLogger{}
	handler := &ProxyHandler{}

	hr := NewHotReloader(HotReloadConfig{
		ConfigPath: "/tmp/test.conf",
		LoadConfig: func() (*Config, string, error) {
			return &Config{}, "", nil
		},
		Handler:  handler,
		Logger:   logger,
		SetLogFn: func(level string) {},
	})

	if hr == nil {
		t.Fatal("NewHotReloader returned nil")
	}
	if hr.configPath != "/tmp/test.conf" {
		t.Errorf("configPath: got %s, want /tmp/test.conf", hr.configPath)
	}
	if hr.handler != handler {
		t.Error("handler not set correctly")
	}
	if hr.stopCh == nil {
		t.Error("stopCh not initialized")
	}
}

func TestHotReloader_StartStop(t *testing.T) {
	logger := &testLogger{}
	handler := &ProxyHandler{}

	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte("{}"), 0644)

	hr := NewHotReloader(HotReloadConfig{
		ConfigPath: configPath,
		LoadConfig: func() (*Config, string, error) {
			return &Config{IdleTimeout: time.Minute}, "", nil
		},
		Handler:  handler,
		Logger:   logger,
		SetLogFn: func(level string) {},
	})

	// Start should not block
	hr.Start()

	// Give goroutines time to start
	time.Sleep(50 * time.Millisecond)

	// Stop should complete
	done := make(chan struct{})
	go func() {
		hr.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Error("Stop() timed out")
	}
}

func TestHotReloader_FileWatch(t *testing.T) {
	// Skip if running in CI without fsnotify support
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{IdleTimeout: time.Minute}, logger)

	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	os.WriteFile(configPath, []byte("{}"), 0644)

	var reloadCount int
	var mu sync.Mutex

	hr := NewHotReloader(HotReloadConfig{
		ConfigPath: configPath,
		LoadConfig: func() (*Config, string, error) {
			mu.Lock()
			reloadCount++
			mu.Unlock()
			return &Config{IdleTimeout: 2 * time.Minute}, "debug", nil
		},
		Handler: handler,
		Logger:  logger,
		SetLogFn: func(level string) {
			// Log level set
		},
	})

	hr.Start()
	defer hr.Stop()

	// Give watcher time to initialize
	time.Sleep(100 * time.Millisecond)

	// Modify the config file
	os.WriteFile(configPath, []byte("{\"new\": true}"), 0644)

	// Wait for debounce + reload
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	count := reloadCount
	mu.Unlock()

	if count < 1 {
		t.Errorf("expected at least 1 reload, got %d", count)
	}
}

func TestHotReloader_Reload(t *testing.T) {
	logger := &testLogger{}
	cfg := &Config{IdleTimeout: time.Minute}
	handler := NewProxyHandler(cfg, logger)

	var logLevelSet string
	hr := NewHotReloader(HotReloadConfig{
		ConfigPath: "/tmp/test.conf",
		LoadConfig: func() (*Config, string, error) {
			return &Config{IdleTimeout: 5 * time.Minute}, "debug", nil
		},
		Handler: handler,
		Logger:  logger,
		SetLogFn: func(level string) {
			logLevelSet = level
		},
	})

	// Call reload directly
	hr.reload()

	// Check log level was set
	if logLevelSet != "debug" {
		t.Errorf("log level: got %s, want debug", logLevelSet)
	}

	// Check config was applied
	if handler.IdleTimeout() != 5*time.Minute {
		t.Errorf("idle timeout: got %v, want 5m", handler.IdleTimeout())
	}
}

func TestHotReloader_ReloadError(t *testing.T) {
	logger := &testLogger{}
	cfg := &Config{IdleTimeout: time.Minute}
	handler := NewProxyHandler(cfg, logger)

	hr := NewHotReloader(HotReloadConfig{
		ConfigPath: "/tmp/test.conf",
		LoadConfig: func() (*Config, string, error) {
			return nil, "", os.ErrNotExist
		},
		Handler:  handler,
		Logger:   logger,
		SetLogFn: func(level string) {},
	})

	// Reload should handle error gracefully
	hr.reload()

	// Original timeout should be unchanged
	if handler.IdleTimeout() != time.Minute {
		t.Errorf("idle timeout should be unchanged: got %v", handler.IdleTimeout())
	}

	// Should have logged a warning
	if len(logger.warnings) == 0 {
		t.Error("expected warning about reload failure")
	}
}

func TestHotReloader_WarnNonHotChanges(t *testing.T) {
	logger := &testLogger{}

	hr := &HotReloader{logger: logger}

	tests := []struct {
		name     string
		old      *Config
		new      *Config
		wantWarn bool
	}{
		{
			name:     "bind_addr_changed",
			old:      &Config{BindAddr: ":8080"},
			new:      &Config{BindAddr: ":9090"},
			wantWarn: true,
		},
		{
			name:     "secrets_count_changed",
			old:      &Config{Secrets: []Secret{{Name: "a"}}},
			new:      &Config{Secrets: []Secret{{Name: "a"}, {Name: "b"}}},
			wantWarn: true,
		},
		{
			name:     "mask_host_changed",
			old:      &Config{MaskHost: "old.com"},
			new:      &Config{MaskHost: "new.com"},
			wantWarn: true,
		},
		{
			name:     "proxy_protocol_changed",
			old:      &Config{ProxyProtocol: false},
			new:      &Config{ProxyProtocol: true},
			wantWarn: true,
		},
		{
			name:     "max_ips_per_user_changed",
			old:      &Config{MaxIPsPerUser: 10},
			new:      &Config{MaxIPsPerUser: 20},
			wantWarn: true,
		},
		{
			name:     "num_event_loop_changed",
			old:      &Config{NumEventLoop: 4},
			new:      &Config{NumEventLoop: 8},
			wantWarn: true,
		},
		{
			name:     "no_changes",
			old:      &Config{BindAddr: ":8080"},
			new:      &Config{BindAddr: ":8080"},
			wantWarn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.warnings = nil
			hr.warnNonHotChanges(tt.old, tt.new)
			hasWarn := len(logger.warnings) > 0
			if hasWarn != tt.wantWarn {
				t.Errorf("warnNonHotChanges(): got %v warnings, want warning=%v",
					len(logger.warnings), tt.wantWarn)
			}
		})
	}
}

func TestHotReloader_SecretChanges(t *testing.T) {
	logger := &testLogger{}
	hr := &HotReloader{logger: logger}

	// Same count, different content
	old := &Config{Secrets: []Secret{{Name: "user1", Key: []byte("key1")}}}
	new := &Config{Secrets: []Secret{{Name: "user1", Key: []byte("key2")}}}

	hr.warnNonHotChanges(old, new)

	if len(logger.warnings) == 0 {
		t.Error("expected warning when secret key changes")
	}
}

func TestHotReloader_NoWarnForHotFields(t *testing.T) {
	logger := &testLogger{}
	hr := &HotReloader{logger: logger}

	// Only IdleTimeout changed (hot field)
	old := &Config{
		BindAddr:    ":8080",
		IdleTimeout: time.Minute,
	}
	new := &Config{
		BindAddr:    ":8080",
		IdleTimeout: 5 * time.Minute,
	}

	hr.warnNonHotChanges(old, new)

	// Should not warn for hot field changes
	if len(logger.warnings) != 0 {
		t.Errorf("should not warn for hot field changes, got %d warnings", len(logger.warnings))
	}
}

func TestHotReloader_MaskPortChanged(t *testing.T) {
	logger := &testLogger{}
	hr := &HotReloader{logger: logger}

	old := &Config{MaskHost: "example.com", MaskPort: 443}
	new := &Config{MaskHost: "example.com", MaskPort: 8443}

	hr.warnNonHotChanges(old, new)

	if len(logger.warnings) == 0 {
		t.Error("expected warning when mask port changes")
	}
}

// BenchmarkHotReloader_Reload benchmarks the reload process
func BenchmarkHotReloader_Reload(b *testing.B) {
	logger := &testLogger{}
	cfg := &Config{IdleTimeout: time.Minute}
	handler := NewProxyHandler(cfg, logger)

	hr := NewHotReloader(HotReloadConfig{
		ConfigPath: "/tmp/test.conf",
		LoadConfig: func() (*Config, string, error) {
			return &Config{IdleTimeout: 5 * time.Minute}, "info", nil
		},
		Handler:  handler,
		Logger:   logger,
		SetLogFn: func(level string) {},
	})

	b.ResetTimer()
	for b.Loop() {
		hr.reload()
	}
}
