package middleend

import (
	"bytes"
	"fmt"
	"testing"
)

func TestProxyRequestInPlaceEncodeMatchesCopiedPayload(t *testing.T) {
	client, server := newReadyBenchmarkPair(t)
	for _, size := range []int{64, 4100, 65536, MaxClientPacketSize} {
		request := benchmarkProxyRequest(size)
		want, err := request.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		frame, payload, err := request.marshalFrame()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, want) {
			t.Fatalf("size %d: framed payload differs from MarshalBinary", size)
		}
		wire, err := client.encodeSubmission(LinkSubmission{SubmissionID: 1, Payload: payload, frame: frame})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := server.decodePayloadRuntime(wire)
		if err != nil {
			t.Fatalf("size %d: decode in-place frame: %v", size, err)
		}
		if !bytes.Equal(decoded.Payload, want) {
			t.Fatalf("size %d: decoded payload differs", size)
		}
		// A copied submission continues the same sequence and cipher stream.
		wire, err = client.encodeSubmission(LinkSubmission{SubmissionID: 2, Payload: want})
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err = server.decodePayloadRuntime(wire); err != nil || !bytes.Equal(decoded.Payload, want) {
			t.Fatalf("size %d: decode copied frame after in-place frame: %v", size, err)
		}
	}
}

// BenchmarkProxyRequestSubmissionEncode measures one request from marshal
// through encrypted wire, as the manager and the gnet owner loop produce it.
func BenchmarkProxyRequestSubmissionEncode(b *testing.B) {
	for _, size := range benchmarkPacketSizes() {
		b.Run(fmt.Sprintf("%d", size), func(b *testing.B) {
			client, _ := newReadyBenchmarkPair(b)
			request := benchmarkProxyRequest(size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				submission, err := benchmarkRequestSubmission(request)
				if err != nil {
					b.Fatal(err)
				}
				wire, err := benchmarkEncodeSubmission(client, submission)
				if err != nil {
					b.Fatal(err)
				}
				benchmarkWire = wire
			}
		})
	}
}
