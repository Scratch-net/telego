package gproxy

import (
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/scratch-net/telego/pkg/tlsfront"
)

// frontDomain is the runtime state of one extra cover domain. The fetchers
// are set before the handler is published and are immutable afterwards.
type frontDomain struct {
	TLSDomain
	spliceAddr         string
	certFetcher        *tlsfront.CertFetcher
	serverHelloFetcher *tlsfront.ServerHelloFetcher
}

func newFrontDomains(domains []TLSDomain) []*frontDomain {
	if len(domains) == 0 {
		return nil
	}
	result := make([]*frontDomain, 0, len(domains))
	for _, domain := range domains {
		result = append(result, &frontDomain{
			TLSDomain:  domain,
			spliceAddr: net.JoinHostPort(domain.SpliceHost, strconv.Itoa(domain.SplicePort)),
		})
	}
	return result
}

// domainFor returns the extra cover domain for host, ignoring case. It
// returns nil for MaskHost, an empty host and unknown hosts.
func (h *ProxyHandler) domainFor(host string) *frontDomain {
	if host == "" {
		return nil
	}
	for _, domain := range h.domains {
		if strings.EqualFold(domain.Host, host) {
			return domain
		}
	}
	return nil
}

// spliceToDomain sends a fallback whose SNI names an extra cover domain to
// that domain's splice target. It reports whether it set a target.
func (h *ProxyHandler) spliceToDomain(ctx *ConnContext, sni string) bool {
	domain := h.domainFor(sni)
	if domain == nil {
		return false
	}
	ctx.setSpliceTarget(domain.spliceAddr, domain.SpliceProxyProtocol)
	h.logger.Debug("[#%d] SNI %q is a cover domain, splicing to %s", ctx.id, sni, domain.spliceAddr)
	return true
}

// prepareDomains creates the certificate and ServerHello fetchers of every
// extra domain and runs the first fetch of each in parallel. A failed fetch
// is retried by the background refresh.
func (h *ProxyHandler) prepareDomains() {
	var wg sync.WaitGroup
	for _, domain := range h.domains {
		domain.certFetcher = tlsfront.NewCertFetcher(h.config.CertRefreshHours, domain.Host)
		domain.serverHelloFetcher = tlsfront.NewServerHelloFetcherSNI(domain.CertHost, domain.CertPort, domain.Host)
		wg.Go(func() {
			if _, err := domain.certFetcher.FetchCert(domain.CertHost, domain.CertPort); err != nil {
				h.logger.Warn("Failed to fetch certificate for %s from %s:%d: %v (will retry in background)",
					domain.Host, domain.CertHost, domain.CertPort, err)
			}
			if err := domain.serverHelloFetcher.Refresh(); err != nil {
				h.logger.Warn("Failed to fetch ServerHello template for %s from %s:%d: %v (will retry)",
					domain.Host, domain.CertHost, domain.CertPort, err)
			} else {
				h.logger.Info("Hybrid TLS mode enabled for %s: using real ServerHello from %s", domain.Host, domain.CertHost)
			}
		})
	}
	wg.Wait()
}

func (h *ProxyHandler) startDomainRefresh() {
	for _, domain := range h.domains {
		if domain.certFetcher != nil {
			domain.certFetcher.StartBackgroundRefresh(domain.CertHost, domain.CertPort)
		}
		if domain.serverHelloFetcher != nil {
			domain.serverHelloFetcher.StartBackgroundRefresh()
		}
	}
}

func (h *ProxyHandler) stopDomainRefresh() {
	for _, domain := range h.domains {
		if domain.certFetcher != nil {
			domain.certFetcher.StopBackgroundRefresh()
		}
		if domain.serverHelloFetcher != nil {
			domain.serverHelloFetcher.StopBackgroundRefresh()
		}
	}
}
