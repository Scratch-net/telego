package gproxy

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkUserLimiterAdmissionDuringStats measures admission for one user
// with 10k tracked IPs while a metrics collector calls Stats continuously.
func BenchmarkUserLimiterAdmissionDuringStats(b *testing.B) {
	for _, collecting := range []bool{false, true} {
		name := "idle"
		if collecting {
			name = "stats"
		}
		b.Run(name, func(b *testing.B) {
			limiter := NewUserIPLimiter(0, time.Minute)
			secret := []byte("0123456789abcdef")
			for i := range statsOnlyMaxIPs {
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, 0x0a000000+uint32(i))
				limiter.TryAcquire(ip, secret, "user")
			}
			var stop atomic.Bool
			var wg sync.WaitGroup
			if collecting {
				wg.Go(func() {
					for !stop.Load() {
						_ = limiter.Stats()
					}
				})
			}
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				ip := net.IPv4(10, 0, 0, 1)
				for pb.Next() {
					key, _ := limiter.TryAcquire(ip, secret, "user")
					limiter.Release(key)
				}
			})
			stop.Store(true)
			wg.Wait()
		})
	}
}
