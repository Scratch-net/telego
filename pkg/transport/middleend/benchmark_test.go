package middleend

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

var (
	benchmarkWire    []byte
	benchmarkRequest ProxyRequest
	benchmarkFrames  []Frame
)

// These benchmarks record allocation and latency baselines for later Phase 3
// decisions. Their sizes are measurements, not proposed acceptance defaults.
func BenchmarkProxyRequestMarshal(b *testing.B) {
	for _, size := range benchmarkPacketSizes() {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			request := benchmarkProxyRequest(size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				wire, err := request.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				benchmarkWire = wire
			}
		})
	}
}

func BenchmarkProxyRequestParse(b *testing.B) {
	for _, size := range benchmarkPacketSizes() {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			wire, err := benchmarkProxyRequest(size).MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				request, err := ParseProxyRequest(wire)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkRequest = request
			}
		})
	}
}

func BenchmarkPaddedIntermediateEncode(b *testing.B) {
	for _, size := range benchmarkPacketSizes() {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			encoder, err := NewClientPacketEncoder(
				obfuscated2.ConnectionTypePaddedIntermediate,
				MaxClientPacketSize,
			)
			if err != nil {
				b.Fatal(err)
			}
			packet := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				wire, err := encoder.Encode(packet)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkWire = wire
			}
		})
	}
}

// BenchmarkClientBootstrapReadyEncode isolates the ready-state full-frame,
// checksum, CBC, and padding path that both link engines share.
func BenchmarkClientBootstrapReadyEncode(b *testing.B) {
	verifyReadyBenchmarkAffinity(b)
	defer verifyReadyBenchmarkAffinity(b)
	for _, size := range benchmarkPacketSizes() {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			client, _ := newReadyBenchmarkPair(b)
			payload, err := benchmarkProxyRequest(size).MarshalBinary()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				wire, err := client.Encode(payload)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkWire = wire
			}
		})
	}
}

// BenchmarkClientBootstrapReadyFeed isolates the ready-state CBC, full-frame,
// checksum, and decoded-frame path. Preparing the matching stateful peer frame
// is outside the timed region.
func BenchmarkClientBootstrapReadyFeed(b *testing.B) {
	verifyReadyBenchmarkAffinity(b)
	defer verifyReadyBenchmarkAffinity(b)
	for _, size := range benchmarkPacketSizes() {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			client, server := newReadyBenchmarkPair(b)
			payload, err := (ProxyAnswer{ConnectionID: 1, Packet: make([]byte, size)}).MarshalBinary()
			if err != nil {
				b.Fatal(err)
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
				consumed, update, err := client.Feed(wire)
				if err != nil {
					b.Fatal(err)
				}
				if consumed != len(wire) || len(update.Frames) != 1 {
					b.Fatalf("Feed consumed %d of %d and returned %d frames", consumed, len(wire), len(update.Frames))
				}
				benchmarkFrames = update.Frames
			}
		})
	}
}

func newReadyBenchmarkPair(b *testing.B) (*ClientBootstrap, *runtimeTestServer) {
	b.Helper()
	client, err := NewClientBootstrap(testBootstrapConfig())
	if err != nil {
		b.Fatal(err)
	}
	initial, err := client.Start()
	if err != nil {
		b.Fatal(err)
	}
	server, err := newRuntimeTestServer(initial)
	if err != nil {
		b.Fatal(err)
	}
	consumed, update, err := client.Feed(server.nonceWire)
	if err != nil {
		b.Fatal(err)
	}
	if consumed != len(server.nonceWire) || len(update.Outbound) == 0 {
		b.Fatalf("nonce Feed consumed %d of %d and returned %d outbound bytes", consumed, len(server.nonceWire), len(update.Outbound))
	}
	if err := server.acceptClientHandshakeRuntime(update.Outbound); err != nil {
		b.Fatal(err)
	}
	handshake, err := server.encodeHandshakeRuntime(HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: ProcessID{IP: 0xc0000201, Port: 443, PID: 71, Uptime: 12345},
		Peer:   testLocalProcessID(),
	})
	if err != nil {
		b.Fatal(err)
	}
	consumed, update, err = client.Feed(handshake)
	if err != nil {
		b.Fatal(err)
	}
	if consumed != len(handshake) || !update.BecameReady || !client.Ready() {
		b.Fatalf("handshake Feed consumed %d of %d, became ready=%t, ready=%t", consumed, len(handshake), update.BecameReady, client.Ready())
	}
	return client, server
}

func benchmarkPacketSizes() []int {
	return []int{4 << 10, 64 << 10, 512 << 10, MaxClientPacketSize}
}

func benchmarkProxyRequest(size int) ProxyRequest {
	tag := new(ProxyTag)
	return ProxyRequest{
		Flags: ProxyRequestFlagHasAdTag |
			ProxyRequestFlagMagic |
			ProxyRequestFlagExternalMode2 |
			ProxyRequestFlagIntermediate,
		ConnectionID: 1,
		RemoteAddr:   netip.MustParseAddrPort("192.0.2.1:1234"),
		ProxyAddr:    netip.MustParseAddrPort("198.51.100.2:443"),
		Tag:          tag,
		Packet:       validEncryptedPacket(size),
	}
}
