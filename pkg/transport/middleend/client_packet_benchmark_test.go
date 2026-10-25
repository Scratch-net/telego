package middleend

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// Repeated packets arrive in the same 64 KiB chunks used by the frontend.
// Keep the owned output allocation in the measurement, including under load.
func BenchmarkClientPacketDecoderUpload(b *testing.B) {
	for _, size := range benchmarkPacketSizes() {
		wire := make([]byte, size+4)
		binary.LittleEndian.PutUint32(wire, uint32(size))
		for i := 4; i < len(wire); i++ {
			wire[i] = byte(i)
		}
		b.Run(fmt.Sprintf("%d/serial", size), func(b *testing.B) {
			decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, MaxClientPacketSize)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = decoder.Close() })
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				benchmarkDecodeClientPacket(b, decoder, wire)
			}
		})
		b.Run(fmt.Sprintf("%d/parallel", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.RunParallel(func(pb *testing.PB) {
				decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, MaxClientPacketSize)
				if err != nil {
					b.Error(err)
					return
				}
				defer decoder.Close()
				for pb.Next() {
					benchmarkDecodeClientPacket(b, decoder, wire)
				}
			})
		})
	}
}

func benchmarkDecodeClientPacket(b *testing.B, decoder *ClientPacketDecoder, wire []byte) {
	for offset := 0; offset < len(wire); {
		end := min(offset+64*1024, len(wire))
		consumed, err := decoder.Feed(wire[offset:end])
		if err != nil || consumed != end-offset {
			b.Errorf("Feed consumed %d of %d bytes: %v", consumed, end-offset, err)
			return
		}
		offset = end
	}
	packet, ok, err := decoder.Next()
	if err != nil || !ok || len(packet.Payload) != len(wire)-4 || packet.Payload[len(packet.Payload)-1] != wire[len(wire)-1] {
		b.Errorf("Next returned %d bytes, complete %t: %v", len(packet.Payload), ok, err)
	}
}
