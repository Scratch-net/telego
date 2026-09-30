package gproxy

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitHotReload(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for config reload")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitHotReloadWatcher(t *testing.T, logger *testLogger) {
	t.Helper()
	waitHotReload(t, func() bool {
		logger.mu.Lock()
		defer logger.mu.Unlock()
		return slices.Contains(logger.debugs, "watching config file: %s")
	})
}

func TestHotReloaderAtomicReplacementAndSubsequentWrites(t *testing.T) {
	for _, relative := range []bool{false, true} {
		name := "absolute"
		if relative {
			name = "relative"
		}
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.toml")
			write := func(path, value string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(configPath, "1m")
			watchPath := configPath
			if relative {
				current, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				watchPath, err = filepath.Rel(current, configPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			logger := &testLogger{}
			handler := NewProxyHandler(&Config{IdleTimeout: time.Minute}, logger)
			var loads atomic.Int64
			reloader := NewHotReloader(HotReloadConfig{
				ConfigPath: watchPath, Handler: handler, Logger: logger,
				LoadConfig: func() (*Config, string, error) {
					loads.Add(1)
					data, err := os.ReadFile(configPath)
					if err != nil {
						return nil, "", err
					}
					timeout, err := time.ParseDuration(string(data))
					return &Config{IdleTimeout: timeout}, "", err
				},
			})
			reloader.Start()
			defer reloader.Stop()
			waitHotReloadWatcher(t, logger)

			write(configPath, "2m")
			waitHotReload(t, func() bool { return handler.IdleTimeout() == 2*time.Minute })
			replacement := configPath + ".new"
			write(replacement, "3m")
			if err := os.Rename(replacement, configPath); err != nil {
				t.Fatal(err)
			}
			waitHotReload(t, func() bool { return handler.IdleTimeout() == 3*time.Minute })
			write(configPath, "4m")
			waitHotReload(t, func() bool { return handler.IdleTimeout() == 4*time.Minute })

			before := loads.Load()
			write(configPath+".unrelated", "5m")
			time.Sleep(250 * time.Millisecond)
			if got := loads.Load(); got != before {
				t.Fatalf("unrelated file triggered %d config reloads", got-before)
			}
		})
	}
}

func TestHotReloaderRestartWarningPersistsUntilConfigReverted(t *testing.T) {
	logger := &testLogger{}
	active := &Config{
		IdleTimeout:         time.Minute,
		WebProxyFingerprint: "root",
		Secrets:             []Secret{{Name: "fixture", Key: []byte("original-fixture")}},
	}
	desired := &Config{
		IdleTimeout:         2 * time.Minute,
		WebProxyFingerprint: "path",
		Secrets:             []Secret{{Name: "fixture", Key: []byte("replacement-fixture")}},
	}
	handler := NewProxyHandler(active, logger)
	var logLevel string
	reloader := NewHotReloader(HotReloadConfig{
		Handler: handler, Logger: logger,
		LoadConfig: func() (*Config, string, error) { return desired, "debug", nil },
		SetLogFn:   func(value string) { logLevel = value },
	})
	for i := range 3 {
		desired.IdleTimeout = time.Duration(i+2) * time.Minute
		before := len(logger.warnings)
		reloader.reload()
		warnings := logger.warnings[before:]
		for _, want := range []string{
			"WEB proxy settings changed but require restart",
			"secrets changed but requires restart",
			"hot settings applied; restart required for other config changes",
		} {
			if !slices.Contains(warnings, want) {
				t.Fatalf("reload %d omitted restart warning %q", i+1, want)
			}
		}
		if slices.Contains(logger.infos, "config reloaded successfully") {
			t.Fatal("unapplied restart-only changes were reported as successful")
		}
		if handler.IdleTimeout() != desired.IdleTimeout || logLevel != "debug" {
			t.Fatal("restart-only changes prevented hot settings from applying")
		}
		if handler.config != active || active.WebProxyFingerprint != "root" {
			t.Fatal("reload changed the active restart-only configuration")
		}
	}

	restored := *active
	restored.IdleTimeout = 5 * time.Minute
	desired = &restored
	before := len(logger.warnings)
	reloader.reload()
	if len(logger.warnings) != before || logger.infos[len(logger.infos)-1] != "config reloaded successfully" {
		t.Fatal("reverting to active settings did not clear restart warning")
	}
	if handler.IdleTimeout() != 5*time.Minute {
		t.Fatal("reverted config did not apply hot settings")
	}
}

func TestHotReloaderSerializesConcurrentReloads(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{IdleTimeout: time.Minute}, logger)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var loads atomic.Int64
	reloader := NewHotReloader(HotReloadConfig{
		Handler: handler, Logger: logger,
		LoadConfig: func() (*Config, string, error) {
			number := loads.Add(1)
			entered <- struct{}{}
			if number == 1 {
				<-release
			}
			return &Config{IdleTimeout: time.Duration(number+1) * time.Minute}, "", nil
		},
	})
	done := make(chan struct{}, 2)
	go func() { reloader.reload(); done <- struct{}{} }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first reload did not start")
	}
	go func() { reloader.reload(); done <- struct{}{} }()
	select {
	case <-entered:
		t.Error("second loader ran before the first reload completed")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	for range 2 {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent reload did not finish")
		}
	}
	if loads.Load() != 2 || handler.IdleTimeout() != 3*time.Minute {
		t.Fatal("an older concurrent reload overwrote the newer settings")
	}
}

func TestHotReloaderStopWaitsForLoaderAndDiscardsResult(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{IdleTimeout: time.Minute}, logger)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	var loads atomic.Int64
	reloader := NewHotReloader(HotReloadConfig{
		ConfigPath: configPath, Handler: handler, Logger: logger,
		LoadConfig: func() (*Config, string, error) {
			loads.Add(1)
			entered <- struct{}{}
			<-release
			return &Config{IdleTimeout: 2 * time.Minute}, "", nil
		},
	})
	stop := sync.OnceFunc(reloader.Stop)
	reloader.Start()
	t.Cleanup(func() { unblock(); stop() })
	waitHotReloadWatcher(t, logger)
	if err := os.WriteFile(configPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("file reload did not enter loader")
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	<-reloader.stopCh
	select {
	case <-stopped:
		t.Error("Stop returned while the file loader was active")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not finish after loader returned")
	}
	if handler.IdleTimeout() != time.Minute {
		t.Fatal("stopped reloader applied the pending configuration")
	}
	reloader.reload()
	if loads.Load() != 1 {
		t.Fatal("stopped reloader started another load")
	}
}

func TestHotReloaderSymlinkAndTargetReplacement(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "original.toml")
	replacement := filepath.Join(t.TempDir(), "replacement.toml")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(target, "1m")
	write(replacement, "3m")
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.Symlink(target, configPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{IdleTimeout: time.Minute}, logger)
	var loads atomic.Int64
	reloader := NewHotReloader(HotReloadConfig{
		ConfigPath: configPath, Handler: handler, Logger: logger,
		LoadConfig: func() (*Config, string, error) {
			loads.Add(1)
			data, err := os.ReadFile(configPath)
			if err != nil {
				return nil, "", err
			}
			timeout, err := time.ParseDuration(string(data))
			return &Config{IdleTimeout: timeout}, "", err
		},
	})
	reloader.Start()
	defer reloader.Stop()
	waitHotReloadWatcher(t, logger)
	write(target, "2m")
	waitHotReload(t, func() bool { return handler.IdleTimeout() == 2*time.Minute })
	if err := os.Symlink(replacement, configPath+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(configPath+".new", configPath); err != nil {
		t.Fatal(err)
	}
	waitHotReload(t, func() bool { return handler.IdleTimeout() == 3*time.Minute })
	write(replacement, "4m")
	waitHotReload(t, func() bool { return handler.IdleTimeout() == 4*time.Minute })
	write(replacement+".new", "5m")
	if err := os.Rename(replacement+".new", replacement); err != nil {
		t.Fatal(err)
	}
	waitHotReload(t, func() bool { return handler.IdleTimeout() == 5*time.Minute })
	write(replacement, "6m")
	waitHotReload(t, func() bool { return handler.IdleTimeout() == 6*time.Minute })
	before := loads.Load()
	write(target, "7m")
	write(replacement+".unrelated", "8m")
	time.Sleep(250 * time.Millisecond)
	if loads.Load() != before {
		t.Fatal("retired target or unrelated sibling triggered a reload")
	}
}
