package gproxy

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// HotReloader watches a config file and reloads hot fields on change.
// Supports both file watching (fsnotify) and SIGHUP.
type HotReloader struct {
	configPath string
	loadConfig func() (*Config, string, error) // returns config, log level, error
	handler    *ProxyHandler
	logger     Logger
	setLogFn   func(level string) // callback to set log level

	mu         sync.Mutex // serializes file and signal reloads
	initialCfg *Config    // effective restart-only settings remain fixed until restart

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// HotReloadConfig contains configuration for the hot reloader.
type HotReloadConfig struct {
	ConfigPath string                          // Path to config file
	LoadConfig func() (*Config, string, error) // Config loader function
	Handler    *ProxyHandler
	Logger     Logger
	SetLogFn   func(level string) // Function to set log level
}

// NewHotReloader creates a new hot reloader.
func NewHotReloader(cfg HotReloadConfig) *HotReloader {
	var initialConfig *Config
	if cfg.Handler != nil {
		initialConfig = cfg.Handler.config
	}
	return &HotReloader{
		configPath: cfg.ConfigPath,
		loadConfig: cfg.LoadConfig,
		handler:    cfg.Handler,
		logger:     cfg.Logger,
		setLogFn:   cfg.SetLogFn,
		initialCfg: initialConfig,
		stopCh:     make(chan struct{}),
	}
}

// Start begins watching for config changes.
// Returns immediately; watching runs in background goroutines.
func (r *HotReloader) Start() {
	// SIGHUP handler
	r.wg.Go(r.watchSignal)

	// File watcher (best-effort, may fail on some systems)
	r.wg.Go(r.watchFile)
}

// Stop stops the hot reloader.
func (r *HotReloader) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

// watchSignal handles SIGHUP for manual reload trigger.
func (r *HotReloader) watchSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case <-sigCh:
			r.logger.Info("received SIGHUP, reloading config")
			r.reload()
		case <-r.stopCh:
			return
		}
	}
}

// watchFile uses fsnotify to watch for file changes.
func (r *HotReloader) watchFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		r.logger.Warn("file watcher unavailable: %v", err)
		return
	}
	defer watcher.Close()

	configPath, err := filepath.Abs(r.configPath)
	if err != nil {
		r.logger.Warn("failed to resolve config file path: %v", err)
		return
	}
	// Editors commonly replace the file atomically. Watching its parent keeps
	// the watch alive after replacement and also sees later writes to the file.
	configDir := filepath.Dir(configPath)
	if err := watcher.Add(configDir); err != nil {
		r.logger.Warn("failed to watch config file: %v", err)
		return
	}

	// A symlink target can be replaced in a different directory. Watch that
	// directory too, and move the watch if the config symlink changes targets.
	resolvedConfigDir, err := filepath.EvalSymlinks(configDir)
	if err != nil {
		r.logger.Warn("failed to resolve config directory: %v", err)
		return
	}
	var targetPath, targetDir string
	watchTargetParent := func() {
		resolved, err := filepath.EvalSymlinks(configPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				r.logger.Warn("failed to resolve config file target: %v", err)
			}
			// Keep the previous target watch across a delete/create interval.
			return
		}
		nextDir := filepath.Dir(resolved)
		if nextDir == resolvedConfigDir {
			// fsnotify reports names under the original directory watch path.
			resolved = filepath.Join(configDir, filepath.Base(resolved))
			nextDir = ""
		}
		if nextDir != targetDir {
			if nextDir != "" {
				if err := watcher.Add(nextDir); err != nil {
					r.logger.Warn("failed to watch config target directory: %v", err)
					return
				}
			}
			if targetDir != "" {
				_ = watcher.Remove(targetDir)
			}
			targetDir = nextDir
		}
		targetPath = resolved
	}
	watchTargetParent()

	// Retain direct file events for mount points and rearm after replacement.
	watchConfigFile := func() {
		_ = watcher.Remove(configPath)
		if err := watcher.Add(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			r.logger.Warn("failed to watch config file target: %v", err)
		}
	}
	watchConfigFile()
	r.logger.Debug("watching config file: %s", r.configPath)

	// Run debounced reloads on this goroutine so Stop waits for active reloads
	// and no timer callback can apply config after the watcher has exited.
	var debounceTimer *time.Timer
	var debounce <-chan time.Time
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			path := filepath.Clean(event.Name)
			if path != configPath && path != targetPath ||
				event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) == 0 {
				continue
			}

			if event.Op&(fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
				watchTargetParent()
				watchConfigFile()
			}

			// Wait 100ms after the last event, including an atomic replacement.
			if debounceTimer == nil {
				debounceTimer = time.NewTimer(100 * time.Millisecond)
			} else {
				debounceTimer.Reset(100 * time.Millisecond)
			}
			debounce = debounceTimer.C

		case <-debounce:
			debounce = nil
			r.logger.Info("config file changed, reloading")
			r.reload()

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			r.logger.Warn("file watcher error: %v", err)

		case <-r.stopCh:
			return
		}
	}
}

// reload loads the config and applies hot fields.
func (r *HotReloader) reload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.stopCh:
		return
	default:
	}
	newCfg, logLevel, err := r.loadConfig()
	if err != nil {
		r.logger.Warn("config reload failed: %v", err)
		return
	}

	select {
	case <-r.stopCh:
		return
	default:
	}

	// Apply log level (always hot-reloadable)
	if logLevel != "" && r.setLogFn != nil {
		r.setLogFn(logLevel)
		r.logger.Info("log level set to %s", logLevel)
	}

	// Warn about non-hot changes
	restartRequired := false
	if r.initialCfg != nil {
		restartRequired = r.warnNonHotChanges(r.initialCfg, newCfg)
	}

	// Apply hot config to handler
	r.handler.ApplyHotConfig(newCfg)
	if restartRequired {
		r.logger.Warn("hot settings applied; restart required for other config changes")
	} else {
		r.logger.Info("config reloaded successfully")
	}
}

// warnNonHotChanges logs warnings for config changes that require restart.
func (r *HotReloader) warnNonHotChanges(old, new *Config) bool {
	restartRequired := false
	if old.BindAddr != new.BindAddr {
		r.logger.Warn("bind address changed (%s -> %s) but requires restart", old.BindAddr, new.BindAddr)
		restartRequired = true
	}

	if len(old.Secrets) != len(new.Secrets) {
		r.logger.Warn("secrets count changed (%d -> %d) but requires restart", len(old.Secrets), len(new.Secrets))
		restartRequired = true
	} else {
		// Check if secrets changed
		for i := range old.Secrets {
			if i >= len(new.Secrets) {
				break
			}
			if old.Secrets[i].Name != new.Secrets[i].Name ||
				string(old.Secrets[i].Key) != string(new.Secrets[i].Key) {
				r.logger.Warn("secrets changed but requires restart")
				restartRequired = true
				break
			}
		}
	}

	if old.MaskHost != new.MaskHost || old.MaskPort != new.MaskPort {
		r.logger.Warn("TLS fronting settings changed but requires restart")
		restartRequired = true
	}

	if old.ProxyProtocol != new.ProxyProtocol {
		r.logger.Warn("proxy-protocol setting changed but requires restart")
		restartRequired = true
	}

	if old.InternalProxyProtocol != new.InternalProxyProtocol {
		r.logger.Warn("internal WEB PROXY protocol setting changed but requires restart")
		restartRequired = true
	}

	if old.WebProxyFingerprint != new.WebProxyFingerprint {
		r.logger.Warn("WEB proxy settings changed but require restart")
		restartRequired = true
	}
	if old.MiddleEndFingerprint != new.MiddleEndFingerprint {
		r.logger.Warn("Middle-End settings changed but require restart")
		restartRequired = true
	}

	if old.MaxConnections != new.MaxConnections {
		r.logger.Warn("max-connections changed (%d -> %d) but requires restart",
			old.MaxConnections, new.MaxConnections)
		restartRequired = true
	}

	if old.MaxIPsPerUser != new.MaxIPsPerUser {
		r.logger.Warn("max-ips-per-user changed (%d -> %d) but requires restart",
			old.MaxIPsPerUser, new.MaxIPsPerUser)
		restartRequired = true
	}

	if old.NumEventLoop != new.NumEventLoop {
		r.logger.Warn("num-event-loops changed but requires restart")
		restartRequired = true
	}
	return restartRequired
}
