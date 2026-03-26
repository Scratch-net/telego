package gproxy

import (
	"net"
	"sync"
	"testing"
)

func TestConnLimiter_Basic(t *testing.T) {
	l := NewConnLimiter(2)

	ip := net.ParseIP("192.168.1.1")
	secret := []byte("testsecret123456")

	// First connection should succeed
	key1, ok := l.TryAcquire(ip, secret)
	if !ok {
		t.Fatal("first connection should succeed")
	}
	if key1 == "" {
		t.Fatal("key should not be empty")
	}

	// Second connection should succeed
	key2, ok := l.TryAcquire(ip, secret)
	if !ok {
		t.Fatal("second connection should succeed")
	}

	// Third connection should fail (limit is 2)
	_, ok = l.TryAcquire(ip, secret)
	if ok {
		t.Fatal("third connection should fail")
	}

	// Release one
	l.Release(key1)

	// Now third should succeed
	key3, ok := l.TryAcquire(ip, secret)
	if !ok {
		t.Fatal("connection after release should succeed")
	}

	// Fourth should fail again
	_, ok = l.TryAcquire(ip, secret)
	if ok {
		t.Fatal("fourth connection should fail")
	}

	// Cleanup
	l.Release(key2)
	l.Release(key3)
}

func TestConnLimiter_DifferentIPs(t *testing.T) {
	l := NewConnLimiter(1)

	ip1 := net.ParseIP("192.168.1.1")
	ip2 := net.ParseIP("192.168.1.2")
	secret := []byte("testsecret123456")

	// First IP
	key1, ok := l.TryAcquire(ip1, secret)
	if !ok {
		t.Fatal("ip1 first connection should succeed")
	}

	// Second connection from same IP should fail
	_, ok = l.TryAcquire(ip1, secret)
	if ok {
		t.Fatal("ip1 second connection should fail")
	}

	// Different IP should succeed (separate limit)
	key2, ok := l.TryAcquire(ip2, secret)
	if !ok {
		t.Fatal("ip2 should have separate limit")
	}

	l.Release(key1)
	l.Release(key2)
}

func TestConnLimiter_DifferentSecrets(t *testing.T) {
	l := NewConnLimiter(1)

	ip := net.ParseIP("192.168.1.1")
	secret1 := []byte("secret1_________")
	secret2 := []byte("secret2_________")

	// First secret
	key1, ok := l.TryAcquire(ip, secret1)
	if !ok {
		t.Fatal("secret1 first connection should succeed")
	}

	// Same IP, different secret should succeed (separate limit)
	key2, ok := l.TryAcquire(ip, secret2)
	if !ok {
		t.Fatal("different secret should have separate limit")
	}

	l.Release(key1)
	l.Release(key2)
}

func TestConnLimiter_Disabled(t *testing.T) {
	l := NewConnLimiter(0)

	ip := net.ParseIP("192.168.1.1")
	secret := []byte("testsecret123456")

	// Should always succeed when disabled
	for i := 0; i < 100; i++ {
		_, ok := l.TryAcquire(ip, secret)
		if !ok {
			t.Fatal("should always succeed when limit is 0")
		}
	}
}

func TestConnLimiter_ReleaseInvalidKey(t *testing.T) {
	l := NewConnLimiter(2)

	// Release with invalid key should not panic
	l.Release("")
	l.Release("short")
	l.Release("toolongkey123456")
}

func TestConnLimiter_ReleaseNonexistent(t *testing.T) {
	l := NewConnLimiter(2)

	// Release key that was never acquired should not panic
	l.Release("12345678") // 8 bytes
}

func TestConnLimiter_ActiveConnections(t *testing.T) {
	l := NewConnLimiter(10)

	ip := net.ParseIP("192.168.1.1")
	secret := []byte("testsecret123456")

	if l.ActiveConnections() != 0 {
		t.Fatal("should start at 0")
	}

	keys := make([]string, 5)
	for i := 0; i < 5; i++ {
		key, ok := l.TryAcquire(ip, secret)
		if !ok {
			t.Fatal("should succeed")
		}
		keys[i] = key
	}

	if l.ActiveConnections() != 5 {
		t.Fatalf("expected 5, got %d", l.ActiveConnections())
	}

	for _, key := range keys {
		l.Release(key)
	}

	if l.ActiveConnections() != 0 {
		t.Fatalf("expected 0 after release, got %d", l.ActiveConnections())
	}
}

func TestConnLimiter_Concurrent(t *testing.T) {
	l := NewConnLimiter(100)

	ip := net.ParseIP("192.168.1.1")
	secret := []byte("testsecret123456")

	var wg sync.WaitGroup
	successCount := make(chan int, 200)

	// Try 200 concurrent acquisitions with limit of 100
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok := l.TryAcquire(ip, secret)
			if ok {
				successCount <- 1
			}
		}()
	}

	wg.Wait()
	close(successCount)

	count := 0
	for range successCount {
		count++
	}

	// Exactly 100 should succeed
	if count != 100 {
		t.Fatalf("expected exactly 100 successes, got %d", count)
	}
}

func TestConnLimiter_IPv6(t *testing.T) {
	l := NewConnLimiter(2)

	ip := net.ParseIP("2001:db8::1")
	secret := []byte("testsecret123456")

	key1, ok := l.TryAcquire(ip, secret)
	if !ok {
		t.Fatal("IPv6 should work")
	}

	key2, ok := l.TryAcquire(ip, secret)
	if !ok {
		t.Fatal("second IPv6 connection should succeed")
	}

	_, ok = l.TryAcquire(ip, secret)
	if ok {
		t.Fatal("third IPv6 connection should fail")
	}

	l.Release(key1)
	l.Release(key2)
}

func BenchmarkConnLimiter_TryAcquire(b *testing.B) {
	l := NewConnLimiter(1000000)
	ip := net.ParseIP("192.168.1.1")
	secret := []byte("testsecret123456")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.TryAcquire(ip, secret)
	}
}

func BenchmarkConnLimiter_TryAcquireRelease(b *testing.B) {
	l := NewConnLimiter(1000000)
	ip := net.ParseIP("192.168.1.1")
	secret := []byte("testsecret123456")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, _ := l.TryAcquire(ip, secret)
		l.Release(key)
	}
}

func BenchmarkConnLimiter_Parallel(b *testing.B) {
	l := NewConnLimiter(1000000)
	secret := []byte("testsecret123456")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ip := net.ParseIP("192.168.1.1")
		for pb.Next() {
			key, _ := l.TryAcquire(ip, secret)
			l.Release(key)
		}
	})
}
