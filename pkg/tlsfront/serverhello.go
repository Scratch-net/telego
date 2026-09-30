// Package tlsfront implements TLS fronting with real server responses.
package tlsfront

import (
	"bytes"
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

	refreshMu     sync.Mutex // Serialize network refreshes without blocking cache readers.
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
	maxCapturedServerData    = 64 << 10
)

// TLS 1.3 identifies HelloRetryRequest by this fixed ServerHello random.
// See RFC 8446, Section 4.1.3.
var helloRetryRequestRandom = [32]byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// GetServerHelloTemplate returns a cached ServerHello response template.
// The caller must patch the random field at the returned offset.
// It never performs network I/O, and retains the last good template on refresh failure.
func (f *ServerHelloFetcher) GetServerHelloTemplate() (response []byte, randomOffset int, err error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.cachedFull == nil {
		return nil, 0, errors.New("no cached ServerHello template")
	}
	return bytes.Clone(f.cachedFull), f.randomOffset, nil
}

// Refresh fetches an expired or missing template. Call it only during startup
// or in a background worker, never from a connection event loop.
func (f *ServerHelloFetcher) Refresh() error {
	f.refreshMu.Lock()
	defer f.refreshMu.Unlock()

	f.mu.RLock()
	fresh := f.cachedFull != nil && time.Since(f.lastFetch) < f.refreshPeriod
	f.mu.RUnlock()
	if fresh {
		return nil
	}

	// One deadline covers both connection establishment and the TLS handshake.
	addr := net.JoinHostPort(f.host, fmt.Sprintf("%d", f.port))
	deadline := time.Now().Add(f.timeout)
	dialer := net.Dialer{Deadline: deadline}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer rawConn.Close()

	if err := rawConn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set fetch deadline: %w", err)
	}

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
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("fetch ServerHello handshake: %w", err)
	}
	_ = tlsConn.Close()

	// Get the captured server response
	response := recordingConn.GetServerData()
	if len(response) == 0 {
		return errors.New("no server response captured")
	}

	// Parse to find ServerHello and random offset
	randomOffset, parseErr := findServerHelloRandomOffset(response)
	if parseErr != nil {
		return fmt.Errorf("parse ServerHello: %w", parseErr)
	}

	// Capture the size of the backend's first ApplicationData (encrypted cert
	// flight) record from the FULL response before truncating. Matching our
	// fake cert record to this removes the accept-vs-mask cert-record-size tell.
	certRecordLen := firstAppDataRecordLen(response)

	// Extract ONLY the first TLS record (ServerHello).
	// The full response may contain Certificate, ServerKeyExchange, etc.
	// which the Telegram client doesn't expect. We'll append synthetic
	// ChangeCipherSpec + ApplicationData in buildHybridServerHello.
	firstRecordLen := 5 + int(binary.BigEndian.Uint16(response[3:5]))
	response = response[:firstRecordLen]

	// Publish only a complete, validated template. Network work never holds mu.
	f.mu.Lock()
	f.cachedFull = bytes.Clone(response)
	f.randomOffset = randomOffset
	f.certRecordLen = certRecordLen
	f.lastFetch = time.Now()
	f.mu.Unlock()
	return nil
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
		captured := min(n, maxCapturedServerData-len(r.serverData))
		r.serverData = append(r.serverData, b[:captured]...)
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingConn) GetServerData() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.serverData)
}

// firstAppDataRecordLen walks the TLS record stream and returns the payload
// length of the first ApplicationData (0x17) record, or 0 if none is present.
func firstAppDataRecordLen(data []byte) int {
	pos := 0
	for pos+5 <= len(data) {
		recordLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
		if recordLen > len(data)-pos-5 {
			return 0
		}
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
	if recordLen < 4+2+32+1+2+1 || recordLen > 16384 || len(data) < 5+recordLen {
		return 0, errors.New("incomplete Handshake record")
	}
	data = data[:5+recordLen]

	// Parse handshake message (starts at offset 5)
	handshakeStart := 5
	if data[handshakeStart] != handshakeTypeServerHello {
		return 0, fmt.Errorf("expected ServerHello, got handshake type 0x%02x", data[handshakeStart])
	}
	messageLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if messageLen != recordLen-4 {
		return 0, errors.New("invalid ServerHello message length")
	}
	if data[1] != 3 || data[2] < 1 || data[2] > 3 || binary.BigEndian.Uint16(data[9:11]) != tls.VersionTLS12 {
		return 0, errors.New("invalid ServerHello version")
	}

	// ServerHello structure:
	// handshake_type(1) + length(3) + version(2) + random(32) + ...
	// Random starts at: record_header(5) + handshake_type(1) + length(3) + version(2) = 11
	randomOffset := handshakeStart + 1 + 3 + 2 // = 11
	if bytes.Equal(data[randomOffset:randomOffset+32], helloRetryRequestRandom[:]) {
		return 0, errors.New("HelloRetryRequest cannot be used as a ServerHello template")
	}

	// Check the session ID, cipher suite, compression, and extension framing.
	// Bytes in later TLS records must never satisfy bounds for this record.
	sessionLen := int(data[43])
	pos := 44 + sessionLen
	if sessionLen > 32 || pos+3 > len(data) {
		return 0, errors.New("invalid ServerHello session ID")
	}
	if data[pos+2] != 0 {
		return 0, errors.New("invalid ServerHello compression")
	}
	pos += 3
	if pos == len(data) {
		return randomOffset, nil // TLS 1.2 permits an absent extensions field.
	}
	if pos+2 > len(data) || int(binary.BigEndian.Uint16(data[pos:pos+2])) != len(data)-pos-2 {
		return 0, errors.New("invalid ServerHello extensions length")
	}
	pos += 2
	for pos < len(data) {
		if len(data)-pos < 4 {
			return 0, errors.New("incomplete ServerHello extension")
		}
		extensionLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if extensionLen > len(data)-pos {
			return 0, errors.New("incomplete ServerHello extension data")
		}
		pos += extensionLen
	}

	return randomOffset, nil
}

// StartBackgroundRefresh starts periodic refresh of the cached ServerHello.
func (f *ServerHelloFetcher) StartBackgroundRefresh() {
	go func() {
		// Initial fetch
		_ = f.Refresh()

		ticker := time.NewTicker(f.refreshPeriod)
		defer ticker.Stop()

		for range ticker.C {
			_ = f.Refresh()
		}
	}()
}
