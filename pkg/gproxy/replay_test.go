package gproxy

import (
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// TestReplayCache_FirstSeen tests that first call returns false.
func TestReplayCache_FirstSeen(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	seen := cache.Seen(sessionID)
	if seen {
		t.Error("first call should return false (not seen)")
	}
}

// TestReplayCache_Replay tests that second call returns true.
func TestReplayCache_Replay(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// First call
	seen1 := cache.Seen(sessionID)
	if seen1 {
		t.Error("first call should return false")
	}

	// Second call with same ID
	seen2 := cache.Seen(sessionID)
	if !seen2 {
		t.Error("second call should return true (replay detected)")
	}

	// Third call
	seen3 := cache.Seen(sessionID)
	if !seen3 {
		t.Error("third call should also return true")
	}
}

// TestReplayCache_DifferentIDs tests that different IDs are tracked separately.
func TestReplayCache_DifferentIDs(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	id1 := make([]byte, 32)
	id2 := make([]byte, 32)
	rand.Read(id1)
	rand.Read(id2)

	// Both should be new
	if cache.Seen(id1) {
		t.Error("id1 should be new")
	}
	if cache.Seen(id2) {
		t.Error("id2 should be new")
	}

	// Now both should be seen
	if !cache.Seen(id1) {
		t.Error("id1 should now be seen")
	}
	if !cache.Seen(id2) {
		t.Error("id2 should now be seen")
	}
}

// TestReplayCache_Expiry tests that entries expire after TTL.
func TestReplayCache_Expiry(t *testing.T) {
	for _, ttl := range []time.Duration{time.Nanosecond, time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cache := NewReplayCache(1000, ttl)
				sessionID := []byte("session")
				if cache.Seen(sessionID) {
					t.Fatal("first session was already seen")
				}
				time.Sleep(ttl - time.Nanosecond)
				if !cache.Seen(sessionID) {
					t.Fatal("session expired before its deadline")
				}
				time.Sleep(time.Nanosecond)
				if got := cache.Len(); got != 0 {
					t.Fatalf("expired entries = %d, want 0", got)
				}
				if cache.Seen(sessionID) {
					t.Fatal("replay hit extended the original deadline")
				}
				if !cache.Seen(sessionID) {
					t.Fatal("expired session was not reinserted")
				}
			})
		})
	}
}

// TestReplayCache_MaxSize tests cleanup when size is exceeded.
func TestReplayCache_MaxSize(t *testing.T) {
	maxSize := 100
	cache := NewReplayCache(maxSize, time.Minute)

	// Add more than maxSize entries
	for range maxSize * 2 {
		id := make([]byte, 32)
		rand.Read(id)
		cache.Seen(id)
	}

	totalSize := cache.Len()
	if capacity := cache.maxPerShard * numShards; totalSize > capacity {
		t.Errorf("cache size = %d, exceeds shard capacity %d", totalSize, capacity)
	}
}

func TestReplayCache_ReplayDoesNotRefreshEvictionOrder(t *testing.T) {
	cache := NewReplayCache(2*numShards, time.Minute)
	ids := [][]byte{{0}, {64}, {128}}
	for _, id := range ids[1:] {
		if cache.getShardIdx(string(id)) != cache.getShardIdx(string(ids[0])) {
			t.Fatal("test IDs must share a shard")
		}
	}
	cache.Seen(ids[0])
	cache.Seen(ids[1])
	if !cache.Seen(ids[0]) {
		t.Fatal("first session was not retained")
	}
	cache.Seen(ids[2])
	if !cache.Seen(ids[1]) || !cache.Seen(ids[2]) {
		t.Fatal("newer sessions were evicted")
	}
	if cache.Seen(ids[0]) {
		t.Fatal("replay hit changed capacity eviction order")
	}
}

func TestReplayCache_ConcurrentSameSession(t *testing.T) {
	cache := NewReplayCache(numShards, time.Minute)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Go(func() {
			<-start
			if !cache.Seen([]byte("same-session")) {
				accepted.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("first admissions = %d, want 1", got)
	}
}

func TestReplayCache_NonpositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cache := NewReplayCache(numShards, ttl)
				cache.Seen([]byte("session"))
				time.Sleep(20 * 365 * 24 * time.Hour)
				if !cache.Seen([]byte("session")) || cache.Len() != 1 {
					t.Fatal("nonpositive TTL must disable expiration")
				}
			})
		})
	}
}

// TestReplayCache_Concurrent tests thread-safety under parallel access.
func TestReplayCache_Concurrent(t *testing.T) {
	const numGoroutines = 100
	const opsPerGoroutine = 100
	// Even if every ID shares one shard, capacity eviction cannot interfere
	// with the check-and-add assertion in this concurrency test.
	cache := NewReplayCache(numGoroutines*opsPerGoroutine*numShards, time.Minute)

	var wg sync.WaitGroup

	for i := range numGoroutines {
		id := i
		wg.Go(func() {
			for j := range opsPerGoroutine {
				sessionID := []byte{byte(id), byte(j)}

				// First call
				cache.Seen(sessionID)

				// Second call should detect replay
				if !cache.Seen(sessionID) {
					t.Errorf("replay not detected for session %d-%d", id, j)
				}
			}
		})
	}

	wg.Wait()

	// Verify cache is still functional
	newID := make([]byte, 32)
	rand.Read(newID)
	if cache.Seen(newID) {
		t.Error("new ID should not be seen")
	}
}

// TestReplayCache_EmptySessionID tests handling of empty session ID.
func TestReplayCache_EmptySessionID(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	// Empty session ID
	seen := cache.Seen([]byte{})
	if seen {
		t.Error("first empty ID should not be seen")
	}

	seen = cache.Seen([]byte{})
	if !seen {
		t.Error("second empty ID should be seen")
	}
}

// TestReplayCache_NilSessionID tests handling of nil session ID.
func TestReplayCache_NilSessionID(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	// Nil converts to empty string key
	seen := cache.Seen(nil)
	if seen {
		t.Error("first nil ID should not be seen")
	}

	seen = cache.Seen(nil)
	if !seen {
		t.Error("second nil ID should be seen")
	}
}

// TestReplayCache_ShortSessionID tests handling of short session IDs.
func TestReplayCache_ShortSessionID(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	shortID := []byte{0x01, 0x02, 0x03}

	seen := cache.Seen(shortID)
	if seen {
		t.Error("first short ID should not be seen")
	}

	seen = cache.Seen(shortID)
	if !seen {
		t.Error("second short ID should be seen")
	}
}

// TestNewReplayCache tests cache creation.
func TestNewReplayCache(t *testing.T) {
	cache := NewReplayCache(100, time.Minute)

	if cache == nil {
		t.Fatal("NewReplayCache returned nil")
	}

	if cache.maxPerShard != 100/numShards {
		t.Errorf("maxPerShard: got %d, want %d", cache.maxPerShard, 100/numShards)
	}

	if cache.ttl != time.Minute {
		t.Errorf("ttl: got %v, want 1m", cache.ttl)
	}

	// Verify all shards are initialized
	for i := range cache.shards {
		if cache.shards[i].cache == nil {
			t.Errorf("shard %d cache is nil", i)
		}
	}
}

// TestReplayCache_SameContent tests that identical content is detected.
func TestReplayCache_SameContent(t *testing.T) {
	cache := NewReplayCache(1000, time.Minute)

	// Two separate slices with same content
	id1 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	id2 := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	cache.Seen(id1)

	// id2 has same content, should be detected
	if !cache.Seen(id2) {
		t.Error("same content should be detected as replay")
	}
}

// BenchmarkReplayCache_New benchmarks checking new session IDs.
func BenchmarkReplayCache_New(b *testing.B) {
	cache := NewReplayCache(100000, time.Minute)

	// Pre-generate session IDs
	ids := make([][]byte, b.N)
	for i := range ids {
		ids[i] = make([]byte, 32)
		rand.Read(ids[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Seen(ids[i])
	}
}

// BenchmarkReplayCache_Replay benchmarks detecting replay attacks.
func BenchmarkReplayCache_Replay(b *testing.B) {
	cache := NewReplayCache(100000, time.Minute)

	// Pre-add session ID
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	cache.Seen(sessionID)

	b.ResetTimer()
	for b.Loop() {
		cache.Seen(sessionID)
	}
}

// BenchmarkReplayCache_Parallel benchmarks concurrent access.
func BenchmarkReplayCache_Parallel(b *testing.B) {
	cache := NewReplayCache(100000, time.Minute)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sessionID := make([]byte, 32)
			rand.Read(sessionID)
			cache.Seen(sessionID)
			cache.Seen(sessionID) // Check for replay
		}
	})
}
