// Package tlsfront implements TLS fronting with real server responses.
package tlsfront

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// ServerHelloFetcher fetches and caches real ServerHello responses from mask hosts.
type ServerHelloFetcher struct {
	host    string
	port    int
	timeout time.Duration

	mu            sync.RWMutex
	cachedFull    []byte // Full response (ServerHello + ChangeCipherSpec + ApplicationData)
	randomOffset  int    // Offset of random field within cachedFull
	certRecordLen int    // Payload length of the backend's first ApplicationData (cert) record
	lastFetch     time.Time
	refreshPeriod time.Duration
}

// CertRecordLen returns the payload length of the mask backend's first
// ApplicationData (encrypted certificate) record from the last successful
// fetch, or 0 if not yet captured. Used to size our fake cert record to match.
func (f *ServerHelloFetcher) CertRecordLen() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.certRecordLen
}

// NewServerHelloFetcher creates a fetcher for the given mask host.
func NewServerHelloFetcher(host string, port int) *ServerHelloFetcher {
	return &ServerHelloFetcher{
		host:          host,
		port:          port,
		timeout:       10 * time.Second,
		refreshPeriod: 5 * time.Minute, // Refresh every 5 minutes to avoid stale fingerprints
	}
}

// TLS record types
const (
	recordTypeChangeCipherSpec = 0x14
	recordTypeHandshake        = 0x16
	recordTypeApplicationData  = 0x17
)

// TLS handshake types
const (
	handshakeTypeServerHello = 0x02
)

// GetServerHelloTemplate returns a cached ServerHello response template.
// The caller must patch the random field at the returned offset.
func (f *ServerHelloFetcher) GetServerHelloTemplate() (response []byte, randomOffset int, err error) {
	f.mu.RLock()
	if f.cachedFull != nil && time.Since(f.lastFetch) < f.refreshPeriod {
		// Return a copy to avoid races
		result := make([]byte, len(f.cachedFull))
		copy(result, f.cachedFull)
		offset := f.randomOffset
		f.mu.RUnlock()
		return result, offset, nil
	}
	f.mu.RUnlock()

	// Need to fetch fresh
	return f.fetchAndCache()
}

// fetchAndCache connects to the mask host and captures the ServerHello response.
func (f *ServerHelloFetcher) fetchAndCache() ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock
	if f.cachedFull != nil && time.Since(f.lastFetch) < f.refreshPeriod {
		result := make([]byte, len(f.cachedFull))
		copy(result, f.cachedFull)
		return result, f.randomOffset, nil
	}

	// Connect to mask host using raw TCP
	addr := net.JoinHostPort(f.host, fmt.Sprintf("%d", f.port))
	rawConn, err := net.DialTimeout("tcp", addr, f.timeout)
	if err != nil {
		return nil, 0, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	rawConn.SetDeadline(time.Now().Add(f.timeout))

	// Wrap in a recording connection to capture raw bytes from server
	recordingConn := &recordingConn{Conn: rawConn}

	// Use Go's TLS client to perform a real handshake
	// This generates a proper ClientHello that servers will accept
	tlsConn := tls.Client(recordingConn, &tls.Config{
		ServerName:         f.host,
		InsecureSkipVerify: true, // We just want to capture the ServerHello
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	})

	// Perform handshake - this will cause server to send ServerHello
	err = tlsConn.Handshake()
	tlsConn.Close()
	// Ignore handshake errors - we just need the ServerHello bytes
	// The handshake will "fail" because we're not actually negotiating

	// Get the captured server response
	response := recordingConn.GetServerData()
	if len(response) == 0 {
		return nil, 0, fmt.Errorf("no server response captured (handshake err: %v)", err)
	}

	// Parse to find ServerHello and random offset
	randomOffset, parseErr := findServerHelloRandomOffset(response)
	if parseErr != nil {
		return nil, 0, fmt.Errorf("parse ServerHello: %w", parseErr)
	}

	// Capture the size of the backend's first ApplicationData (encrypted cert
	// flight) record from the FULL response before truncating. Matching our
	// fake cert record to this removes the accept-vs-mask cert-record-size tell.
	certRecordLen := firstAppDataRecordLen(response)

	// Extract ONLY the first TLS record (ServerHello).
	// The full response may contain Certificate, ServerKeyExchange, etc.
	// which the Telegram client doesn't expect. We'll append synthetic
	// ChangeCipherSpec + ApplicationData in buildHybridServerHello.
	if len(response) >= 5 {
		firstRecordLen := 5 + int(binary.BigEndian.Uint16(response[3:5]))
		if firstRecordLen <= len(response) {
			response = response[:firstRecordLen]
		}
	}

	// Cache it
	f.cachedFull = make([]byte, len(response))
	copy(f.cachedFull, response)
	f.randomOffset = randomOffset
	f.certRecordLen = certRecordLen
	f.lastFetch = time.Now()

	// Return a copy
	result := make([]byte, len(response))
	copy(result, response)
	return result, randomOffset, nil
}

// recordingConn wraps a net.Conn and records all data received from the server.
type recordingConn struct {
	net.Conn
	mu         sync.Mutex
	serverData []byte
}

func (r *recordingConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.mu.Lock()
		r.serverData = append(r.serverData, b[:n]...)
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingConn) GetServerData() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]byte, len(r.serverData))
	copy(result, r.serverData)
	return result
}

// firstAppDataRecordLen walks the TLS record stream and returns the payload
// length of the first ApplicationData (0x17) record, or 0 if none is present.
func firstAppDataRecordLen(data []byte) int {
	pos := 0
	for pos+5 <= len(data) {
		recordLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
		if data[pos] == recordTypeApplicationData {
			return recordLen
		}
		pos += 5 + recordLen
	}
	return 0
}

// findServerHelloRandomOffset parses TLS records to find the random field offset.
// Returns the offset within the full response where the 32-byte random starts.
func findServerHelloRandomOffset(data []byte) (int, error) {
	if len(data) < 5 {
		return 0, errors.New("response too short")
	}

	// First record should be Handshake
	if data[0] != recordTypeHandshake {
		return 0, fmt.Errorf("expected Handshake record, got 0x%02x", data[0])
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return 0, errors.New("incomplete Handshake record")
	}

	// Parse handshake message (starts at offset 5)
	handshakeStart := 5
	if data[handshakeStart] != handshakeTypeServerHello {
		return 0, fmt.Errorf("expected ServerHello, got handshake type 0x%02x", data[handshakeStart])
	}

	// ServerHello structure:
	// handshake_type(1) + length(3) + version(2) + random(32) + ...
	// Random starts at: record_header(5) + handshake_type(1) + length(3) + version(2) = 11
	randomOffset := handshakeStart + 1 + 3 + 2 // = 11

	if len(data) < randomOffset+32 {
		return 0, errors.New("response too short for random field")
	}

	return randomOffset, nil
}

// StartBackgroundRefresh starts periodic refresh of the cached ServerHello.
func (f *ServerHelloFetcher) StartBackgroundRefresh() {
	go func() {
		// Initial fetch
		f.GetServerHelloTemplate()

		ticker := time.NewTicker(f.refreshPeriod)
		defer ticker.Stop()

		for range ticker.C {
			f.fetchAndCache()
		}
	}()
}
