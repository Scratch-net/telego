package gproxy

import (
	"fmt"
	"testing"
)

// BenchmarkRelayBuffer measures one relay batch buffer: take, fill, release.
// 61460 is the largest EE downlink batch without DRS (60 KiB plus four TLS
// headers); 65536 is a typical EE uplink sum.
func BenchmarkRelayBuffer(b *testing.B) {
	h := NewProxyHandler(&Config{}, &testLogger{})
	output := newRelayOutput(newTestMockGnetConn(), newTestMockGnetConn(), NewConnContext(), defaultMaxWriteBuffer)
	for _, size := range []int{1024, 16 << 10, 61460, 65536, relayBatchSize} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				buffer, release := h.relayBuffer(output, size)
				buffer[0], buffer[len(buffer)-1] = 1, 1
				if release != nil {
					release()
				}
			}
		})
	}
}
