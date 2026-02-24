// Package tlsfront implements advanced TLS fronting with real certificate fetching.
// This makes the proxy indistinguishable from a real HTTPS server.
package tlsfront

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"
)

// CachedCert holds a fetched certificate with metadata.
type CachedCert struct {
	Chain     []*x509.Certificate
	RawChain  [][]byte // Raw DER-encoded certificates
	FetchedAt time.Time
	ExpiresAt time.Time
	Host      string
}

// IsExpired checks if the cached cert should be refreshed.
func (c *CachedCert) IsExpired() bool {
	// Refresh if within 1 hour of expiry or older than refresh interval
	return time.Now().After(c.ExpiresAt.Add(-time.Hour))
}

// GetRawCertChain returns the raw DER-encoded certificate chain.
func (c *CachedCert) GetRawCertChain() [][]byte {
	return c.RawChain
}

// CertFetcher fetches and caches real TLS certificates from mask hosts.
type CertFetcher struct {
	cache    map[string]*CachedCert
	mu       sync.RWMutex
	dialer   *net.Dialer
	timeout  time.Duration
	refreshH int // refresh interval in hours (with jitter)
}

// NewCertFetcher creates a new certificate fetcher.
func NewCertFetcher(refreshHours int) *CertFetcher {
	if refreshHours <= 0 {
		refreshHours = 5 // Default: refresh every 5 hours
	}
	return &CertFetcher{
		cache:    make(map[string]*CachedCert),
		dialer:   &net.Dialer{Timeout: 10 * time.Second},
		timeout:  10 * time.Second,
		refreshH: refreshHours,
	}
}

// FetchCert fetches a real certificate from the mask host.
// Uses cache if available and not expired.
func (f *CertFetcher) FetchCert(host string, port int) (*CachedCert, error) {
	key := fmt.Sprintf("%s:%d", host, port)

	// Check cache first
	f.mu.RLock()
	cached, ok := f.cache[key]
	f.mu.RUnlock()

	if ok && !cached.IsExpired() {
		return cached, nil
	}

	// Fetch new certificate
	cert, err := f.fetchFromHost(host, port)
	if err != nil {
		// Return stale cache on fetch error
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}

	// Update cache
	f.mu.Lock()
	f.cache[key] = cert
	f.mu.Unlock()

	return cert, nil
}

// fetchFromHost connects to the host and extracts its certificate.
func (f *CertFetcher) fetchFromHost(host string, port int) (*CachedCert, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// Connect with TLS
	conn, err := tls.DialWithDialer(f.dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // We just want to get the cert
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", addr, err)
	}
	defer conn.Close()

	// Get peer certificates
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates from %s", addr)
	}

	// Extract certificate chain (both parsed and raw)
	chain := make([]*x509.Certificate, len(state.PeerCertificates))
	rawChain := make([][]byte, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		chain[i] = cert
		rawChain[i] = cert.Raw
	}

	// Get the leaf certificate for expiry calculation
	leaf := state.PeerCertificates[0]

	// Calculate expiry with jitter to avoid synchronized refreshes
	jitterHours := time.Duration(f.refreshH) * time.Hour
	jitter := time.Duration(time.Now().UnixNano()%int64(time.Hour)) - 30*time.Minute
	refreshAt := time.Now().Add(jitterHours + jitter)

	// Don't exceed actual cert expiry
	if refreshAt.After(leaf.NotAfter) {
		refreshAt = leaf.NotAfter.Add(-time.Hour)
	}

	return &CachedCert{
		Chain:     chain,
		RawChain:  rawChain,
		FetchedAt: time.Now(),
		ExpiresAt: refreshAt,
		Host:      host,
	}, nil
}

// StartBackgroundRefresh starts a goroutine to refresh certificates before expiry.
func (f *CertFetcher) StartBackgroundRefresh(host string, port int) {
	go func() {
		// Initial fetch
		f.FetchCert(host, port)

		// Refresh periodically
		ticker := time.NewTicker(time.Duration(f.refreshH) * time.Hour / 2)
		defer ticker.Stop()

		for range ticker.C {
			f.FetchCert(host, port)
		}
	}()
}
