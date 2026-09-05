package gproxy

import (
	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/tlsfront"
	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// prepareFrontends runs before publishing the handler. Fronting pointers are
// immutable afterwards; their existing caches synchronize background refresh.
// The shared ME readiness consumer must not depend on the public listener.
func (h *ProxyHandler) prepareFrontends() {
	cfg := h.config
	if cfg.ClockSyncURL != "" {
		if offset, err := faketls.SyncClock(cfg.ClockSyncURL, 0); err != nil {
			h.logger.Warn("Clock sync from %s failed: %v (using local clock)", cfg.ClockSyncURL, err)
		} else {
			h.logger.Info("Clock sync from %s: offset %+ds applied", cfg.ClockSyncURL, offset)
		}
	}
	if cfg.MaskHost != "" && cfg.FetchRealCert {
		h.certFetcher = tlsfront.NewCertFetcher(cfg.CertRefreshHours, cfg.MaskHost)
		h.logger.Debug("Fetching TLS certificate from %s:%d (SNI: %s)...", cfg.CertHost, cfg.CertPort, cfg.MaskHost)
		cert, err := h.certFetcher.FetchCert(cfg.CertHost, cfg.CertPort)
		if err != nil {
			h.logger.Warn("Failed to fetch certificate: %v (will retry in background)", err)
		} else {
			h.logger.Debug("Certificate fetched: %d certs in chain", len(cert.Chain))
		}
		h.serverHelloFetcher = tlsfront.NewServerHelloFetcher(cfg.CertHost, cfg.CertPort)
		h.logger.Debug("Fetching real ServerHello from %s:%d for hybrid TLS mode...", cfg.CertHost, cfg.CertPort)
		if _, _, err := h.serverHelloFetcher.GetServerHelloTemplate(); err != nil {
			h.logger.Warn("Failed to fetch ServerHello template: %v (will retry)", err)
		} else {
			h.logger.Info("Hybrid TLS mode enabled: using real ServerHello from %s", cfg.CertHost)
		}
	}
	if h.middleEnd != nil {
		h.middleEnd.start()
	}
}

func (h *ProxyHandler) stopServing() error {
	if h.middleEnd != nil {
		h.middleEnd.stop()
	}
	return h.stopDCClient()
}

// runPublicEngine also owns cleanup when gnet fails before calling OnBoot or
// OnShutdown. Normal shutdown reaches the same idempotent cleanup methods.
func (h *ProxyHandler) runPublicEngine(events gnet.EventHandler, address string, options ...gnet.Option) error {
	defer func() {
		if err := h.stopServing(); err != nil {
			h.logger.Warn("failed to stop upstream gnet client: %v", err)
		}
	}()
	return gnet.Run(events, address, options...)
}
