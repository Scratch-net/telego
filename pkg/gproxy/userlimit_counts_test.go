package gproxy

import (
	"math/rand/v2"
	"net"
	"testing"
	"time"
)

// The maintained counts must equal a walk over the tracked entries after
// acquires, releases, and LRU evictions in both limiter modes.
func TestUserLimiterCountsMatchWalk(t *testing.T) {
	for _, maxIPs := range []int{0, 3} {
		limiter := NewUserIPLimiter(maxIPs, time.Minute)
		secret := []byte("0123456789abcdef")
		random := rand.New(rand.NewPCG(1, 2))
		var keys []string
		for range 2000 {
			if len(keys) > 0 && random.IntN(2) == 0 {
				index := random.IntN(len(keys))
				limiter.Release(keys[index])
				keys = append(keys[:index], keys[index+1:]...)
				continue
			}
			ip := net.IPv4(192, 0, 2, byte(random.IntN(8)))
			if key, ok := limiter.TryAcquire(ip, secret, "user"); ok {
				keys = append(keys, key)
			}
		}
		stats := limiter.Stats()[0]
		shard := &limiter.shards[getShardIdx(secret)]
		shard.mu.Lock()
		var state *userIPState
		for _, candidate := range shard.users {
			state = candidate
		}
		var connections int64
		connected := 0
		for _, ip := range state.activeIPs.Keys() {
			entry, _ := state.activeIPs.Peek(ip)
			connections += entry.count
			if entry.count > 0 {
				connected++
			}
		}
		shard.mu.Unlock()
		if stats.Connections != connections || stats.ActiveIPs != connected {
			t.Fatalf("max=%d: Stats connections=%d active=%d, walk connections=%d active=%d",
				maxIPs, stats.Connections, stats.ActiveIPs, connections, connected)
		}
	}
}
