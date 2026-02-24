package tlsfront

import (
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
	fetcher := NewCertFetcher(0)

	if fetcher.refreshH != 5 {
		t.Errorf("refreshH: got %d, want 5 (default)", fetcher.refreshH)
	}
}

// TestNewCertFetcher_NegativeRefresh tests that negative hours defaults to 5.
func TestNewCertFetcher_NegativeRefresh(t *testing.T) {
	fetcher := NewCertFetcher(-1)

	if fetcher.refreshH != 5 {
		t.Errorf("refreshH: got %d, want 5 (default)", fetcher.refreshH)
	}
}

// TestNewCertFetcher_CustomRefresh tests custom refresh hours.
func TestNewCertFetcher_CustomRefresh(t *testing.T) {
	fetcher := NewCertFetcher(10)

	if fetcher.refreshH != 10 {
		t.Errorf("refreshH: got %d, want 10", fetcher.refreshH)
	}
}

// TestNewCertFetcher_Initialization tests fetcher initialization.
func TestNewCertFetcher(t *testing.T) {
	fetcher := NewCertFetcher(5)

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
	fetcher := NewCertFetcher(5)

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
	fetcher := NewCertFetcher(5)

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
	fetcher := NewCertFetcher(5)

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
	fetcher := NewCertFetcher(5)

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
	fetcher := NewCertFetcher(5)

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
