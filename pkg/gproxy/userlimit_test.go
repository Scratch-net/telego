package gproxy

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestUserIPLimiter_UnlimitedConnectionsPerIP(t *testing.T) {
	l := NewUserIPLimiter(3, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip := net.ParseIP("192.168.1.1")

	// Same IP should allow unlimited connections
	var keys []string
	for i := range 100 {
		key, ok := l.TryAcquire(ip, secret, "test")
		if !ok {
			t.Fatalf("TryAcquire failed at iteration %d", i)
		}
		keys = append(keys, key)
	}

	// Release all
	for _, key := range keys {
		l.Release(key)
	}
}

func TestUserIPLimiter_MaxIPsPerUser(t *testing.T) {
	l := NewUserIPLimiter(3, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")
	ip4 := net.ParseIP("192.168.1.4")

	// First 3 IPs should succeed
	key1, ok := l.TryAcquire(ip1, secret, "test")
	if !ok {
		t.Fatal("IP1 should succeed")
	}
	key2, ok := l.TryAcquire(ip2, secret, "test")
	if !ok {
		t.Fatal("IP2 should succeed")
	}
	key3, ok := l.TryAcquire(ip3, secret, "test")
	if !ok {
		t.Fatal("IP3 should succeed")
	}

	// 4th IP should succeed (evicts IP1)
	key4, ok := l.TryAcquire(ip4, secret, "test")
	if !ok {
		t.Fatal("IP4 should succeed (evicting IP1)")
	}

	// IP1 should now be blocked
	_, ok = l.TryAcquire(ip1, secret, "test")
	if ok {
		t.Fatal("IP1 should be blocked after eviction")
	}

	// Release all
	l.Release(key1)
	l.Release(key2)
	l.Release(key3)
	l.Release(key4)
}

func TestUserIPLimiter_BlockedIPRejected(t *testing.T) {
	l := NewUserIPLimiter(2, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")

	// Fill up with IP1 and IP2
	l.TryAcquire(ip1, secret, "test")
	l.TryAcquire(ip2, secret, "test")

	// IP3 evicts IP1
	l.TryAcquire(ip3, secret, "test")

	// Multiple attempts from blocked IP1 should fail
	for i := range 5 {
		_, ok := l.TryAcquire(ip1, secret, "test")
		if ok {
			t.Fatalf("Blocked IP should be rejected (attempt %d)", i)
		}
	}
}

func TestUserIPLimiter_PerUserIsolation(t *testing.T) {
	l := NewUserIPLimiter(2, 5*time.Minute)
	defer l.Close()

	secret1 := []byte("0123456789abcdef")
	secret2 := []byte("fedcba9876543210")
	ip := net.ParseIP("192.168.1.1")

	// Same IP for different users should both succeed
	_, ok := l.TryAcquire(ip, secret1, "user1")
	if !ok {
		t.Fatal("User1 should succeed")
	}
	_, ok = l.TryAcquire(ip, secret2, "user2")
	if !ok {
		t.Fatal("User2 should succeed with same IP")
	}

	// Fill up user1's IP slots
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")
	l.TryAcquire(ip2, secret1, "user1")
	l.TryAcquire(ip3, secret1, "user1") // Evicts ip for user1

	// IP should be blocked for user1 but still work for user2
	_, ok = l.TryAcquire(ip, secret1, "user1")
	if ok {
		t.Fatal("IP should be blocked for user1")
	}
	_, ok = l.TryAcquire(ip, secret2, "user2")
	if !ok {
		t.Fatal("IP should still work for user2")
	}
}

func TestUserIPLimiter_StatsOnlyMode(t *testing.T) {
	l := NewUserIPLimiter(0, 5*time.Minute) // 0 = stats-only mode
	defer l.Close()

	if l == nil {
		t.Fatal("Limiter should not be nil in stats-only mode")
	}
	if l.LimitingEnabled() {
		t.Fatal("Limiting should be disabled in stats-only mode")
	}

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")

	// All IPs should succeed (no limiting)
	key1, ok := l.TryAcquire(ip1, secret, "test")
	if !ok {
		t.Fatal("IP1 should succeed in stats-only mode")
	}
	key2, ok := l.TryAcquire(ip2, secret, "test")
	if !ok {
		t.Fatal("IP2 should succeed in stats-only mode")
	}
	key3, ok := l.TryAcquire(ip3, secret, "test")
	if !ok {
		t.Fatal("IP3 should succeed in stats-only mode")
	}

	// Stats should be tracked
	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 user stat, got %d", len(stats))
	}
	if stats[0].ActiveIPs != 3 {
		t.Errorf("ActiveIPs = %d, want 3", stats[0].ActiveIPs)
	}
	if stats[0].BlockedIPs != 0 {
		t.Errorf("BlockedIPs = %d, want 0 (no blocking in stats-only)", stats[0].BlockedIPs)
	}

	l.Release(key1)
	l.Release(key2)
	l.Release(key3)
}

func TestUserIPLimiter_BlockExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = time.Minute
		l := NewUserIPLimiter(2, timeout)
		defer l.Close()
		secret := []byte("0123456789abcdef")
		ip1 := net.ParseIP("192.168.1.1")
		l.TryAcquire(ip1, secret, "test")
		l.TryAcquire(net.ParseIP("192.168.1.2"), secret, "test")
		l.TryAcquire(net.ParseIP("192.168.1.3"), secret, "test")
		if _, ok := l.TryAcquire(ip1, secret, "test"); ok {
			t.Fatal("evicted active IP was not blocked")
		}
		time.Sleep(timeout - time.Nanosecond)
		if got := l.Stats()[0].BlockedIPs; got != 1 {
			t.Fatalf("blocked IPs before deadline = %d, want 1", got)
		}
		time.Sleep(time.Nanosecond)
		if stats := l.Stats()[0]; stats.BlockedIPs != 0 || len(stats.BlockedIPList) != 0 {
			t.Fatal("stats retained an expired block")
		}
		if _, ok := l.TryAcquire(ip1, secret, "test"); !ok {
			t.Fatal("IP was rejected at its block deadline")
		}
	})
}

func TestUserIPLimiter_BlockTimeoutRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = time.Minute
		l := NewUserIPLimiter(1, timeout)
		defer l.Close()
		secret := []byte("0123456789abcdef")
		ip1 := net.ParseIP("192.168.1.1")
		l.TryAcquire(ip1, secret, "test")
		l.TryAcquire(net.ParseIP("192.168.1.2"), secret, "test")
		time.Sleep(timeout / 2)
		if _, ok := l.TryAcquire(ip1, secret, "test"); ok {
			t.Fatal("blocked retry was accepted")
		}
		time.Sleep(timeout / 2)
		if stats := l.Stats()[0]; stats.BlockedIPs != 1 || stats.BlockedTotal != 1 {
			t.Fatal("retry did not refresh the block or changed the eviction count")
		}
		time.Sleep(timeout/2 - time.Nanosecond)
		if got := l.Stats()[0].BlockedIPs; got != 1 {
			t.Fatalf("block expired before refreshed deadline: %d", got)
		}
		time.Sleep(time.Nanosecond)
		if _, ok := l.TryAcquire(ip1, secret, "test"); !ok {
			t.Fatal("block did not expire at its refreshed deadline")
		}
	})
}

func TestUserIPLimiter_BlockedCapacityAndRefreshOrder(t *testing.T) {
	l := NewUserIPLimiter(1, time.Hour)
	defer l.Close()
	secret := []byte("0123456789abcdef")
	for i := 1; i <= 12; i++ {
		if _, ok := l.TryAcquire(net.IPv4(192, 0, 2, byte(i)), secret, "test"); !ok {
			t.Fatal("new IP was rejected")
		}
	}
	if stats := l.Stats()[0]; stats.BlockedIPs != 10 || stats.BlockedIPList[0] != "192.0.2.2" {
		t.Fatalf("blocked capacity eviction is incorrect: %v", stats.BlockedIPList)
	}
	if _, ok := l.TryAcquire(net.ParseIP("192.0.2.2"), secret, "test"); ok {
		t.Fatal("oldest retained block was not enforced")
	}
	l.TryAcquire(net.ParseIP("192.0.2.13"), secret, "test")
	want := []string{"192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.10", "192.0.2.11", "192.0.2.2", "192.0.2.12"}
	if got := l.Stats()[0].BlockedIPList; !slices.Equal(got, want) {
		t.Fatalf("blocked order after refresh and eviction = %v, want %v", got, want)
	}
}

func TestUserIPLimiter_NonpositiveTTLAndClose(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				l := NewUserIPLimiter(1, ttl)
				secret := []byte("0123456789abcdef")
				ip1 := net.ParseIP("192.0.2.1")
				l.TryAcquire(ip1, secret, "test")
				l.TryAcquire(net.ParseIP("192.0.2.2"), secret, "test")
				time.Sleep(20 * 365 * 24 * time.Hour)
				if _, ok := l.TryAcquire(ip1, secret, "test"); ok {
					t.Fatal("nonpositive TTL must disable block expiration")
				}
				l.Close()
				l.Close()
				stats := l.Stats()[0]
				if stats.BlockedIPs != 0 || stats.TrackedIPs != 1 || stats.BlockedTotal != 1 {
					t.Fatal("Close must clear only blocked entries")
				}
			})
		})
	}
}

func TestUserIPLimiter_ConcurrentAccess(t *testing.T) {
	l := NewUserIPLimiter(10, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")

	var wg sync.WaitGroup
	for i := range 100 {
		n := i
		wg.Go(func() {
			ip := net.ParseIP(fmt.Sprintf("192.168.1.%d", n%10))
			for range 100 {
				key, ok := l.TryAcquire(ip, secret, "test")
				if ok {
					l.Release(key)
				}
			}
		})
	}
	wg.Wait()
}

func TestUserIPLimiter_TrafficCounters(t *testing.T) {
	l := NewUserIPLimiter(3, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip := net.ParseIP("192.168.1.1")

	// Acquire to create user state
	key, _ := l.TryAcquire(ip, secret, "test")
	defer l.Release(key)

	// Get traffic counters
	bytesIn, bytesOut := l.TrafficCounters(secret)
	if bytesIn == nil || bytesOut == nil {
		t.Fatal("Traffic counters should not be nil")
	}

	// Simulate traffic
	bytesIn.Add(1000)
	bytesOut.Add(2000)

	// Verify via Stats
	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 user stat, got %d", len(stats))
	}
	if stats[0].BytesIn != 1000 {
		t.Errorf("BytesIn = %d, want 1000", stats[0].BytesIn)
	}
	if stats[0].BytesOut != 2000 {
		t.Errorf("BytesOut = %d, want 2000", stats[0].BytesOut)
	}
}

func TestUserIPLimiter_Stats(t *testing.T) {
	l := NewUserIPLimiter(3, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	// Create some connections
	key1, _ := l.TryAcquire(ip1, secret, "testuser")
	key2, _ := l.TryAcquire(ip1, secret, "testuser")
	key3, _ := l.TryAcquire(ip2, secret, "testuser")

	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 user stat, got %d", len(stats))
	}

	s := stats[0]
	if s.SecretName != "testuser" {
		t.Errorf("SecretName = %q, want testuser", s.SecretName)
	}
	if s.ActiveIPs != 2 {
		t.Errorf("ActiveIPs = %d, want 2", s.ActiveIPs)
	}
	if s.Connections != 3 {
		t.Errorf("Connections = %d, want 3", s.Connections)
	}

	// Verify IP lists are populated
	if len(s.TrackedIPList) != 2 {
		t.Errorf("ActiveIPList len = %d, want 2", len(s.TrackedIPList))
	}
	if len(s.BlockedIPList) != 0 {
		t.Errorf("BlockedIPList len = %d, want 0", len(s.BlockedIPList))
	}

	l.Release(key1)
	l.Release(key2)
	l.Release(key3)
}

func TestUserIPLimiter_DisconnectedIPNotBlocked(t *testing.T) {
	// IPs that have closed all connections (count=0) should NOT be blocked when evicted
	l := NewUserIPLimiter(3, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")
	ip4 := net.ParseIP("192.168.1.4")

	// Connect IP1, IP2, IP3
	key1, _ := l.TryAcquire(ip1, secret, "test")
	key2, _ := l.TryAcquire(ip2, secret, "test")
	key3, _ := l.TryAcquire(ip3, secret, "test")

	// Disconnect IP1 (release all connections)
	l.Release(key1)

	// Connect IP4 - this evicts IP1 (oldest in LRU)
	key4, ok := l.TryAcquire(ip4, secret, "test")
	if !ok {
		t.Fatal("IP4 should succeed")
	}

	// IP1 should NOT be blocked because it had 0 connections when evicted
	// Use a fresh limiter check without reconnecting (to avoid cascading evictions)
	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 user stat, got %d", len(stats))
	}
	if stats[0].BlockedIPs != 0 {
		t.Errorf("BlockedIPs = %d, want 0 (disconnected IPs shouldn't be blocked)", stats[0].BlockedIPs)
	}

	// Now verify IP1 can reconnect (will evict IP2)
	_, ok = l.TryAcquire(ip1, secret, "test")
	if !ok {
		t.Fatal("IP1 should NOT be blocked - it had disconnected before eviction")
	}

	l.Release(key2)
	l.Release(key3)
	l.Release(key4)
}

func TestUserIPLimiter_ActiveIPBlocked(t *testing.T) {
	// IPs that still have active connections SHOULD be blocked when evicted
	l := NewUserIPLimiter(2, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")

	// Connect IP1 and IP2 (keep connections active)
	key1, _ := l.TryAcquire(ip1, secret, "test")
	key2, _ := l.TryAcquire(ip2, secret, "test")

	// Connect IP3 - this evicts IP1 which still has an active connection
	key3, ok := l.TryAcquire(ip3, secret, "test")
	if !ok {
		t.Fatal("IP3 should succeed")
	}

	// IP1 SHOULD be blocked because it had active connections when evicted
	_, ok = l.TryAcquire(ip1, secret, "test")
	if ok {
		t.Fatal("IP1 should be blocked - it had active connections when evicted")
	}

	// Verify IP1 is in blocked list
	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 user stat, got %d", len(stats))
	}
	if stats[0].BlockedIPs != 1 {
		t.Errorf("BlockedIPs = %d, want 1", stats[0].BlockedIPs)
	}

	l.Release(key1)
	l.Release(key2)
	l.Release(key3)
}

func TestUserIPLimiter_StatsWithBlockedIPs(t *testing.T) {
	l := NewUserIPLimiter(2, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	ip3 := net.ParseIP("192.168.1.3")

	// Fill up and cause eviction
	l.TryAcquire(ip1, secret, "testuser")
	l.TryAcquire(ip2, secret, "testuser")
	l.TryAcquire(ip3, secret, "testuser") // Evicts ip1

	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 user stat, got %d", len(stats))
	}

	s := stats[0]
	if len(s.TrackedIPList) != 2 {
		t.Errorf("ActiveIPList len = %d, want 2", len(s.TrackedIPList))
	}
	if len(s.BlockedIPList) != 1 {
		t.Errorf("BlockedIPList len = %d, want 1", len(s.BlockedIPList))
	}
	if s.BlockedIPList[0] != "192.168.1.1" {
		t.Errorf("BlockedIPList[0] = %q, want 192.168.1.1", s.BlockedIPList[0])
	}
}

func TestUserIPLimiter_TrackedVsActiveIPs(t *testing.T) {
	l := NewUserIPLimiter(10, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")

	// Connect both IPs
	key1, _ := l.TryAcquire(ip1, secret, "testuser")
	key2, _ := l.TryAcquire(ip2, secret, "testuser")

	// Both should be tracked and active
	stats := l.Stats()
	s := stats[0]
	if s.TrackedIPs != 2 {
		t.Errorf("TrackedIPs = %d, want 2", s.TrackedIPs)
	}
	if s.ActiveIPs != 2 {
		t.Errorf("ActiveIPs = %d, want 2", s.ActiveIPs)
	}

	// Release one IP
	l.Release(key1)

	// Should still be tracked (in LRU cache) but not active
	stats = l.Stats()
	s = stats[0]
	if s.TrackedIPs != 2 {
		t.Errorf("TrackedIPs after release = %d, want 2 (still in cache)", s.TrackedIPs)
	}
	if s.ActiveIPs != 1 {
		t.Errorf("ActiveIPs after release = %d, want 1", s.ActiveIPs)
	}

	// Release the other IP
	l.Release(key2)

	// Both should still be tracked, but neither active
	stats = l.Stats()
	s = stats[0]
	if s.TrackedIPs != 2 {
		t.Errorf("TrackedIPs after all release = %d, want 2 (still in cache)", s.TrackedIPs)
	}
	if s.ActiveIPs != 0 {
		t.Errorf("ActiveIPs after all release = %d, want 0", s.ActiveIPs)
	}
}

// Benchmarks

func BenchmarkUserIPLimiter_TryAcquire(b *testing.B) {
	l := NewUserIPLimiter(100, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	for b.Loop() {
		l.TryAcquire(ip, secret, "test")
	}
}

func BenchmarkUserIPLimiter_TryAcquireRelease(b *testing.B) {
	l := NewUserIPLimiter(100, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip := net.ParseIP("192.168.1.1")

	b.ResetTimer()
	for b.Loop() {
		key, _ := l.TryAcquire(ip, secret, "test")
		l.Release(key)
	}
}

func BenchmarkUserIPLimiter_Parallel(b *testing.B) {
	l := NewUserIPLimiter(100, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ip := net.ParseIP("192.168.1.1")
		for pb.Next() {
			key, ok := l.TryAcquire(ip, secret, "test")
			if ok {
				l.Release(key)
			}
		}
	})
}

func BenchmarkUserIPLimiter_MultipleIPs(b *testing.B) {
	l := NewUserIPLimiter(100, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ips := make([]net.IP, 10)
	for i := range ips {
		ips[i] = net.ParseIP(fmt.Sprintf("192.168.1.%d", i))
	}

	b.ResetTimer()
	i := 0
	for b.Loop() {
		ip := ips[i%len(ips)]
		key, ok := l.TryAcquire(ip, secret, "test")
		if ok {
			l.Release(key)
		}
		i++
	}
}
