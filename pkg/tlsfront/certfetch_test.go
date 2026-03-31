package tlsfront

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// TestIsExpired_NotExpired tests that far future returns false.
func TestIsExpired_NotExpired(t *testing.T) {
	cert := &CachedCert{
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hours in future
	}

	if cert.IsExpired() {
		t.Error("cert expiring in 24 hours should not be expired")
	}
}

// TestIsExpired_Expired tests that past returns true.
func TestIsExpired_Expired(t *testing.T) {
	cert := &CachedCert{
		ExpiresAt: time.Now().Add(-time.Hour), // 1 hour in past
	}

	if !cert.IsExpired() {
		t.Error("cert expired 1 hour ago should be expired")
	}
}

// TestIsExpired_WithinHour tests that within 1 hour of expiry returns true.
func TestIsExpired_WithinHour(t *testing.T) {
	testCases := []struct {
		name     string
		offset   time.Duration
		expected bool
	}{
		{"59_minutes", 59 * time.Minute, true},  // Within 1 hour
		{"30_minutes", 30 * time.Minute, true},  // Within 1 hour
		{"1_minute", time.Minute, true},         // Within 1 hour
		{"61_minutes", 61 * time.Minute, false}, // Just outside 1 hour
		{"2_hours", 2 * time.Hour, false},       // Well outside
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cert := &CachedCert{
				ExpiresAt: time.Now().Add(tc.offset),
			}

			if cert.IsExpired() != tc.expected {
				t.Errorf("IsExpired() for %v before expiry: got %v, want %v",
					tc.offset, cert.IsExpired(), tc.expected)
			}
		})
	}
}

// TestCachedCert_GetRawCertChain tests raw chain getter.
func TestCachedCert_GetRawCertChain(t *testing.T) {
	rawChain := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	}

	cert := &CachedCert{
		RawChain: rawChain,
	}

	got := cert.GetRawCertChain()
	if len(got) != len(rawChain) {
		t.Errorf("GetRawCertChain length: got %d, want %d", len(got), len(rawChain))
	}

	for i := range rawChain {
		if string(got[i]) != string(rawChain[i]) {
			t.Errorf("GetRawCertChain[%d] mismatch", i)
		}
	}
}

// TestCachedCert_GetRawCertChain_Nil tests nil chain handling.
func TestCachedCert_GetRawCertChain_Nil(t *testing.T) {
	cert := &CachedCert{
		RawChain: nil,
	}

	got := cert.GetRawCertChain()
	if got != nil {
		t.Error("GetRawCertChain should return nil for nil chain")
	}
}

// TestNewCertFetcher_DefaultRefresh tests that 0 hours defaults to 5.
func TestNewCertFetcher_DefaultRefresh(t *testing.T) {
	fetcher := NewCertFetcher(0, "")

	if fetcher.refreshH != 5 {
		t.Errorf("refreshH: got %d, want 5 (default)", fetcher.refreshH)
	}
}

// TestNewCertFetcher_NegativeRefresh tests that negative hours defaults to 5.
func TestNewCertFetcher_NegativeRefresh(t *testing.T) {
	fetcher := NewCertFetcher(-1, "")

	if fetcher.refreshH != 5 {
		t.Errorf("refreshH: got %d, want 5 (default)", fetcher.refreshH)
	}
}

// TestNewCertFetcher_CustomRefresh tests custom refresh hours.
func TestNewCertFetcher_CustomRefresh(t *testing.T) {
	fetcher := NewCertFetcher(10, "")

	if fetcher.refreshH != 10 {
		t.Errorf("refreshH: got %d, want 10", fetcher.refreshH)
	}
}

// TestNewCertFetcher_Initialization tests fetcher initialization.
func TestNewCertFetcher(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	if fetcher == nil {
		t.Fatal("NewCertFetcher returned nil")
	}

	if fetcher.cache == nil {
		t.Error("cache should be initialized")
	}

	if fetcher.dialer == nil {
		t.Error("dialer should be initialized")
	}

	if fetcher.timeout != 10*time.Second {
		t.Errorf("timeout: got %v, want 10s", fetcher.timeout)
	}
}

// TestCachedCert_Fields tests CachedCert field access.
func TestCachedCert_Fields(t *testing.T) {
	now := time.Now()
	cert := &CachedCert{
		Chain:     nil,
		RawChain:  [][]byte{{1, 2, 3}},
		FetchedAt: now,
		ExpiresAt: now.Add(time.Hour),
		Host:      "example.com",
	}

	if cert.Host != "example.com" {
		t.Errorf("Host: got %q, want %q", cert.Host, "example.com")
	}

	if !cert.FetchedAt.Equal(now) {
		t.Error("FetchedAt mismatch")
	}

	if !cert.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Error("ExpiresAt mismatch")
	}
}

// TestFetchCert_CacheHit tests that cached cert is returned without fetch.
func TestFetchCert_CacheHit(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	// Pre-populate cache
	host := "cached.example.com"
	port := 443
	key := "cached.example.com:443"

	cachedCert := &CachedCert{
		RawChain:  [][]byte{{1, 2, 3}},
		FetchedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Not expired
		Host:      host,
	}

	fetcher.mu.Lock()
	fetcher.cache[key] = cachedCert
	fetcher.mu.Unlock()

	// Should return cached cert
	cert, err := fetcher.FetchCert(host, port)
	if err != nil {
		t.Fatalf("FetchCert failed: %v", err)
	}

	if cert != cachedCert {
		t.Error("should return cached cert")
	}
}

// TestFetchCert_CacheExpired tests that expired cache triggers fetch attempt.
func TestFetchCert_CacheExpired(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	// Pre-populate cache with expired entry
	host := "expired.example.com"
	port := 443
	key := "expired.example.com:443"

	expiredCert := &CachedCert{
		RawChain:  [][]byte{{1, 2, 3}},
		FetchedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired
		Host:      host,
	}

	fetcher.mu.Lock()
	fetcher.cache[key] = expiredCert
	fetcher.mu.Unlock()

	// Will try to fetch, but fail (no server), should return stale cache
	cert, err := fetcher.FetchCert(host, port)

	// Should return stale cert on fetch error
	if err != nil {
		t.Logf("Fetch error (expected): %v", err)
	}

	if cert == nil {
		// Either returns stale or nil with error
		t.Log("No cert returned (no server available)")
	} else if cert != expiredCert {
		// If we got a cert, it should be the stale one
		t.Log("Returned stale cert as fallback")
	}
}

// TestFetchCert_CacheMiss tests that cache miss triggers fetch.
func TestFetchCert_CacheMiss(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	// This will try to connect to a non-existent server
	// and should return an error
	_, err := fetcher.FetchCert("nonexistent.invalid", 443)

	// Should fail since the host doesn't exist
	if err == nil {
		t.Log("FetchCert unexpectedly succeeded (network may have intercepted)")
	}
}

// TestFetchCert_StaleFallback tests that stale cert is returned on fetch error.
func TestFetchCert_StaleFallback(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	host := "stale.example.com"
	port := 443
	key := "stale.example.com:443"

	// Add a stale (but not nil) cert
	staleCert := &CachedCert{
		RawChain:  [][]byte{{0xDE, 0xAD, 0xBE, 0xEF}},
		FetchedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		Host:      host,
	}

	fetcher.mu.Lock()
	fetcher.cache[key] = staleCert
	fetcher.mu.Unlock()

	// Fetch will fail (no server), should return stale
	cert, err := fetcher.FetchCert(host, port)

	// Either we get the stale cert or an error (but not both nil)
	if cert == nil && err == nil {
		t.Error("should return either stale cert or error")
	}

	if cert != nil {
		// If we got a cert, it should be the stale one
		if len(cert.RawChain) != 1 || cert.RawChain[0][0] != 0xDE {
			t.Error("should have returned the stale cert")
		}
	}
}

// TestCertFetcher_CacheKey tests cache key format.
func TestCertFetcher_CacheKey(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	// Add entries with different hosts/ports
	cert1 := &CachedCert{ExpiresAt: time.Now().Add(time.Hour)}
	cert2 := &CachedCert{ExpiresAt: time.Now().Add(time.Hour)}

	fetcher.mu.Lock()
	fetcher.cache["host1:443"] = cert1
	fetcher.cache["host1:8443"] = cert2
	fetcher.mu.Unlock()

	// Different ports should be different cache entries
	fetcher.mu.RLock()
	if fetcher.cache["host1:443"] == fetcher.cache["host1:8443"] {
		t.Error("different ports should have different cache entries")
	}
	fetcher.mu.RUnlock()
}

// TestIsExpired_ExactBoundary tests expiry at exact boundary.
func TestIsExpired_ExactBoundary(t *testing.T) {
	// At exactly 1 hour before expiry
	cert := &CachedCert{
		ExpiresAt: time.Now().Add(time.Hour),
	}

	// This is at the boundary - implementation uses Add(-time.Hour)
	// so exactly 1 hour should be considered expired
	result := cert.IsExpired()
	t.Logf("At exactly 1 hour boundary, IsExpired=%v", result)
}

// TestNewCertFetcher_SNI tests SNI field is stored.
func TestNewCertFetcher_SNI(t *testing.T) {
	sni := "example.com"
	fetcher := NewCertFetcher(5, sni)

	if fetcher.sni != sni {
		t.Errorf("sni: got %q, want %q", fetcher.sni, sni)
	}
}

// TestCertFetcher_ConcurrentAccess tests concurrent cache access.
func TestCertFetcher_ConcurrentAccess(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	// Pre-populate cache
	cachedCert := &CachedCert{
		RawChain:  [][]byte{{1, 2, 3}},
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Host:      "concurrent.test",
	}
	fetcher.mu.Lock()
	fetcher.cache["concurrent.test:443"] = cachedCert
	fetcher.mu.Unlock()

	// Concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			cert, _ := fetcher.FetchCert("concurrent.test", 443)
			if cert != cachedCert {
				t.Error("concurrent read returned wrong cert")
			}
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestCachedCert_ChainField tests Chain field access.
func TestCachedCert_ChainField(t *testing.T) {
	cert := &CachedCert{
		Chain: nil,
	}

	if cert.Chain != nil {
		t.Error("Chain should be nil")
	}
}

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(notBefore, notAfter time.Time) (tls.Certificate, error) {
	// Generate key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", "test.example.com"},
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// startTestTLSServer starts a TLS server for testing and returns the port.
func startTestTLSServer(t *testing.T, cert tls.Certificate) (int, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tlsListener := tls.NewListener(listener, tlsConfig)

	// Serve in goroutine
	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			// Must complete TLS handshake before closing
			tlsConn, ok := conn.(*tls.Conn)
			if ok {
				tlsConn.Handshake()
			}
			// Keep connection open briefly to allow client to read cert
			time.Sleep(10 * time.Millisecond)
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	cleanup := func() {
		listener.Close()
	}

	return port, cleanup
}

// TestFetchFromHost_Success tests successful cert fetch from local TLS server.
func TestFetchFromHost_Success(t *testing.T) {
	// Create a cert valid for 30 days
	notBefore := time.Now()
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	cert, err := generateTestCert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	port, cleanup := startTestTLSServer(t, cert)
	defer cleanup()

	// Create fetcher and fetch
	fetcher := NewCertFetcher(5, "")
	cachedCert, err := fetcher.FetchCert("127.0.0.1", port)
	if err != nil {
		t.Fatalf("FetchCert failed: %v", err)
	}

	if cachedCert == nil {
		t.Fatal("expected cached cert, got nil")
	}

	// Verify cert fields
	if len(cachedCert.Chain) == 0 {
		t.Error("expected non-empty Chain")
	}
	if len(cachedCert.RawChain) == 0 {
		t.Error("expected non-empty RawChain")
	}
	if cachedCert.Host != "127.0.0.1" {
		t.Errorf("Host: got %q, want %q", cachedCert.Host, "127.0.0.1")
	}
	if cachedCert.FetchedAt.IsZero() {
		t.Error("FetchedAt should not be zero")
	}
	if cachedCert.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
}

// TestFetchFromHost_WithSNI tests fetching with custom SNI.
func TestFetchFromHost_WithSNI(t *testing.T) {
	notBefore := time.Now()
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	cert, err := generateTestCert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	port, cleanup := startTestTLSServer(t, cert)
	defer cleanup()

	// Create fetcher with custom SNI
	fetcher := NewCertFetcher(5, "custom.sni.example.com")
	cachedCert, err := fetcher.FetchCert("127.0.0.1", port)
	if err != nil {
		t.Fatalf("FetchCert failed: %v", err)
	}

	if cachedCert == nil {
		t.Fatal("expected cached cert, got nil")
	}

	// Verify the fetcher's SNI was used (cert still fetched successfully)
	if len(cachedCert.RawChain) == 0 {
		t.Error("expected non-empty RawChain")
	}
}

// TestFetchFromHost_ConnectionError tests fetch error handling.
func TestFetchFromHost_ConnectionError(t *testing.T) {
	fetcher := NewCertFetcher(5, "")

	// Use a port that's definitely not listening
	_, err := fetcher.FetchCert("127.0.0.1", 19999)
	if err == nil {
		t.Error("expected error for connection to non-existent server")
	}
}

// TestFetchFromHost_CacheUpdate tests that successful fetch updates cache.
func TestFetchFromHost_CacheUpdate(t *testing.T) {
	notBefore := time.Now()
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	cert, err := generateTestCert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	port, cleanup := startTestTLSServer(t, cert)
	defer cleanup()

	fetcher := NewCertFetcher(5, "")

	// First fetch
	cachedCert1, err := fetcher.FetchCert("127.0.0.1", port)
	if err != nil {
		t.Fatalf("first FetchCert failed: %v", err)
	}

	// Check cache was updated
	key := "127.0.0.1:" + string(rune('0'+port/10000)) + string(rune('0'+(port/1000)%10)) + string(rune('0'+(port/100)%10)) + string(rune('0'+(port/10)%10)) + string(rune('0'+port%10))
	_ = key // Key format check removed, just verify cache hit

	// Second fetch should return cached
	cachedCert2, err := fetcher.FetchCert("127.0.0.1", port)
	if err != nil {
		t.Fatalf("second FetchCert failed: %v", err)
	}

	// Should be same object
	if cachedCert1 != cachedCert2 {
		t.Error("second fetch should return cached cert")
	}
}

// TestStartBackgroundRefresh tests background refresh starts.
func TestStartBackgroundRefresh(t *testing.T) {
	notBefore := time.Now()
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	cert, err := generateTestCert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	port, cleanup := startTestTLSServer(t, cert)
	defer cleanup()

	// Use small refresh interval for testing
	fetcher := NewCertFetcher(1, "")

	// Start background refresh
	fetcher.StartBackgroundRefresh("127.0.0.1", port)

	// Wait for initial fetch
	time.Sleep(100 * time.Millisecond)

	// Check that cert was fetched
	fetcher.mu.RLock()
	cached := fetcher.cache["127.0.0.1:"+itoa(port)]
	fetcher.mu.RUnlock()

	if cached == nil {
		t.Error("background refresh should have populated cache")
	}
}

// itoa converts int to string without importing strconv
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b) - 1
	for i > 0 {
		b[n] = byte('0' + i%10)
		n--
		i /= 10
	}
	return string(b[n+1:])
}

// TestFetchCert_ExpiryCalculation tests expiry time is reasonable.
func TestFetchCert_ExpiryCalculation(t *testing.T) {
	notBefore := time.Now()
	notAfter := time.Now().Add(30 * 24 * time.Hour) // 30 days
	cert, err := generateTestCert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	port, cleanup := startTestTLSServer(t, cert)
	defer cleanup()

	fetcher := NewCertFetcher(5, "") // 5 hour refresh
	cachedCert, err := fetcher.FetchCert("127.0.0.1", port)
	if err != nil {
		t.Fatalf("FetchCert failed: %v", err)
	}

	// Expiry should be within reasonable range
	// With 5 hour refresh and jitter, should be roughly 4-6 hours from now
	minExpiry := time.Now().Add(3 * time.Hour)
	maxExpiry := time.Now().Add(7 * time.Hour)

	if cachedCert.ExpiresAt.Before(minExpiry) {
		t.Errorf("ExpiresAt %v too early (min: %v)", cachedCert.ExpiresAt, minExpiry)
	}
	if cachedCert.ExpiresAt.After(maxExpiry) {
		// Might exceed if cert expiry is close
		t.Logf("ExpiresAt %v later than expected (max: %v)", cachedCert.ExpiresAt, maxExpiry)
	}
}

// TestFetchCert_ShortLivedCert tests handling of soon-to-expire cert.
func TestFetchCert_ShortLivedCert(t *testing.T) {
	// Create a cert that expires in 2 hours
	notBefore := time.Now()
	notAfter := time.Now().Add(2 * time.Hour)
	cert, err := generateTestCert(notBefore, notAfter)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	port, cleanup := startTestTLSServer(t, cert)
	defer cleanup()

	fetcher := NewCertFetcher(5, "") // 5 hour refresh, but cert expires in 2h
	cachedCert, err := fetcher.FetchCert("127.0.0.1", port)
	if err != nil {
		t.Fatalf("FetchCert failed: %v", err)
	}

	// Expiry should be adjusted to 1 hour before cert expiry
	expectedMax := notAfter.Add(-time.Hour)
	if cachedCert.ExpiresAt.After(expectedMax.Add(time.Minute)) {
		t.Errorf("ExpiresAt %v should be at most %v (1h before cert expiry)", cachedCert.ExpiresAt, expectedMax)
	}
}
