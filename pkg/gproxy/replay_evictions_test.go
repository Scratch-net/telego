package gproxy

import (
	"fmt"
	"testing"
	"time"
)

func TestReplayCacheCountsEvictionsBeforeTTL(t *testing.T) {
	cache := NewReplayCache(numShards, time.Hour) // one entry per shard
	first := []byte("first")
	var second []byte
	for i := 0; ; i++ {
		second = []byte(fmt.Sprintf("other-%d", i))
		if cache.getShardIdx(string(second)) == cache.getShardIdx(string(first)) {
			break
		}
	}
	cache.Seen(first)
	if cache.Evictions() != 0 {
		t.Fatal("eviction counted without a full shard")
	}
	cache.Seen(second)
	if cache.Evictions() != 1 {
		t.Fatalf("evictions = %d, want 1", cache.Evictions())
	}
	if cache.Seen(first) {
		t.Fatal("evicted entry still detected")
	}

	// Expired entries are pruned, not counted as early evictions.
	expiring := NewReplayCache(numShards, time.Nanosecond)
	expiring.Seen(first)
	time.Sleep(time.Millisecond)
	expiring.Seen(second)
	if expiring.Evictions() != 0 {
		t.Fatalf("expired entry counted as eviction: %d", expiring.Evictions())
	}
}

// An entry behind a longer-lived addUntil entry still expires on its own TTL.
func TestTTLSetEntryBehindLongHoldExpires(t *testing.T) {
	set := newTTLSet(8, 30*time.Millisecond)
	set.addUntil("held", time.Now().Add(time.Hour))
	set.add("short")
	time.Sleep(60 * time.Millisecond)
	if set.contains("short") {
		t.Fatal("entry past its TTL is still present behind a held entry")
	}
	if !set.contains("held") {
		t.Fatal("held entry expired before its deadline")
	}
}
