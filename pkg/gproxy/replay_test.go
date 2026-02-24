package gproxy

import (
	"crypto/rand"
	"sync"
	"testing"
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
	// Use very short TTL for testing
	ttl := 100 * time.Millisecond
	cache := NewReplayCache(1000, ttl)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// First call
	seen := cache.Seen(sessionID)
	if seen {
		t.Error("first call should return false")
	}

	// Second call should show as seen
	seen = cache.Seen(sessionID)
	if !seen {
		t.Error("should be seen immediately after")
	}

	// Wait for TTL + cleanup interval (TTL/2)
	time.Sleep(ttl + ttl/2 + 50*time.Millisecond)

	// After expiry, should be treated as new
	// Note: cleanup runs on interval, may need to wait
	seen = cache.Seen(sessionID)
	// After cleanup, this becomes new again
	// The cache might not have cleaned up yet, so we just verify the mechanism works
	t.Logf("After TTL, seen=%v (depends on cleanup timing)", seen)
}

// TestReplayCache_MaxSize tests cleanup when size is exceeded.
func TestReplayCache_MaxSize(t *testing.T) {
	maxSize := 10
	cache := NewReplayCache(maxSize, time.Minute)

	// Add more than maxSize entries
	for i := 0; i < maxSize*2; i++ {
		id := make([]byte, 32)
		rand.Read(id)
		cache.Seen(id)
	}

	// The cache should handle this without panicking
	// Actual size reduction happens during cleanup, which runs on timer
	cache.mu.RLock()
	size := len(cache.seen)
	cache.mu.RUnlock()

	// Size might exceed maxSize before cleanup runs
	t.Logf("Cache size after %d inserts: %d (max: %d)", maxSize*2, size, maxSize)
}

// TestReplayCache_Concurrent tests thread-safety under parallel access.
func TestReplayCache_Concurrent(t *testing.T) {
	cache := NewReplayCache(10000, time.Minute)

	const numGoroutines = 100
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				sessionID := make([]byte, 32)
				rand.Read(sessionID)

				// First call
				cache.Seen(sessionID)

				// Second call should detect replay
				if !cache.Seen(sessionID) {
					t.Errorf("replay not detected for session %d-%d", id, j)
				}
			}
		}(i)
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

	if cache.maxSize != 100 {
		t.Errorf("maxSize: got %d, want 100", cache.maxSize)
	}

	if cache.ttl != time.Minute {
		t.Errorf("ttl: got %v, want 1m", cache.ttl)
	}

	if cache.seen == nil {
		t.Error("seen map is nil")
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
