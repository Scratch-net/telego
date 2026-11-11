package middleend

import (
	"fmt"
	"testing"
)

// BenchmarkClientBootstrapReadyFeedFrames models the gnet read path: borrowed
// frame delivery over socket reads that end inside a CBC block.
func BenchmarkClientBootstrapReadyFeedFrames(b *testing.B) {
	const readSize = 16<<10 - 3
	for _, size := range []int{4 << 10, 64 << 10, 512 << 10} {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			client, server := newReadyBenchmarkPair(b)
			// The gnet runtime installs one buffer per event loop.
			client.useFeedScratch(make([]byte, maxBootstrapBorrowedFeedSize))
			payload, err := (ProxyAnswer{ConnectionID: 1, Packet: make([]byte, size)}).MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			frames := 0
			visit := func(Frame) error {
				frames++
				return nil
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				b.StopTimer()
				wire, err := server.encodePayloadRuntime(payload)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				for len(wire) != 0 {
					read := wire[:min(len(wire), readSize)]
					consumed, _, err := client.feedFrames(read, nil, visit)
					if err != nil {
						b.Fatal(err)
					}
					wire = wire[consumed:]
				}
			}
			if frames == 0 {
				b.Fatal("no frames decoded")
			}
		})
	}
}
