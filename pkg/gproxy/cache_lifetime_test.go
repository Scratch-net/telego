package gproxy

import (
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestReplayCache_NoBackgroundWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 2 {
			cache := NewReplayCache(64, time.Hour)
			if cache.Seen([]byte("session")) {
				t.Fatal("new cache retained a previous cache's session")
			}
		}
		// Bubble time stops when this function returns. A retained cleanup
		// worker causes a deadlock failure, even if it owns a periodic timer.
	})
}

func TestUserIPLimiter_NoBackgroundWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 2 {
			limiter := NewUserIPLimiter(1, time.Hour)
			secret := []byte("0123456789abcdef")
			for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
				if _, ok := limiter.TryAcquire(net.ParseIP(ip), secret, "test"); !ok {
					t.Fatal("initial connection was rejected")
				}
			}
			limiter.Close()
		}
		// Closing and discarding limiters must not retain timer workers.
	})
}
