package gproxy

import (
	"os"
	"os/signal"
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

	mu      sync.Mutex
	lastCfg *Config // last loaded config for comparison

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
		lastCfg:    initialConfig,
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

	if err := watcher.Add(r.configPath); err != nil {
		r.logger.Warn("failed to watch config file: %v", err)
		return
	}

	r.logger.Debug("watching config file: %s", r.configPath)

	// Debounce timer to avoid multiple reloads on rapid changes
	var debounceTimer *time.Timer

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// Only reload on write or create (editor may delete+create)
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Debounce: wait 100ms after last event before reloading
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(100*time.Millisecond, func() {
				r.logger.Info("config file changed, reloading")
				r.reload()
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			r.logger.Warn("file watcher error: %v", err)

		case <-r.stopCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		}
	}
}

// reload loads the config and applies hot fields.
func (r *HotReloader) reload() {
	newCfg, logLevel, err := r.loadConfig()
	if err != nil {
		r.logger.Warn("config reload failed: %v", err)
		return
	}

	r.mu.Lock()
	oldCfg := r.lastCfg
	r.lastCfg = newCfg
	r.mu.Unlock()

	// Apply log level (always hot-reloadable)
	if logLevel != "" && r.setLogFn != nil {
		r.setLogFn(logLevel)
		r.logger.Info("log level set to %s", logLevel)
	}

	// Warn about non-hot changes
	restartRequired := false
	if oldCfg != nil {
		restartRequired = r.warnNonHotChanges(oldCfg, newCfg)
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
