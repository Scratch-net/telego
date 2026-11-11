package gproxy

import (
	"bytes"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

func TestMaskFallbackReasons(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
		SpliceHost:        "127.0.0.1",
		SplicePort:        1,
	}, &testLogger{})
	hello := func(payload []byte) {
		connection := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateReadTLSPayload)
		ctx.tlsPayloadLen = len(payload)
		connection.SetContext(ctx)
		connection.SetReadData(buildTLSRecord(faketls.RecordTypeHandshake, payload))
		handler.handleTLSPayload(connection, ctx)
	}
	count := func(reason string) uint64 {
		for _, stat := range handler.MaskFallbackStats() {
			if stat.Reason == reason {
				return stat.Total
			}
		}
		t.Fatalf("no reason %q", reason)
		return 0
	}

	header := newTestMockGnetConn()
	headerCtx := NewConnContext()
	header.SetContext(headerCtx)
	header.SetReadData([]byte{0x16, 0x02, 0x00, 0x00, 0x10})
	handler.handleTLSHeader(header, headerCtx)

	hello(buildPaddedClientHello(key, "other.example", 512))
	hello(buildPaddedClientHello([]byte("fedcba9876543210"), "example.com", 512))
	hello(buildPaddedClientHelloAt(key, "example.com", 512, uint32(time.Now().Add(-time.Hour).Unix())))
	fresh := buildPaddedClientHello(key, "example.com", 600) // body differs from the stale hello
	hello(fresh)
	hello(fresh)

	dd := newTestMockGnetConn()
	ddCtx := NewConnContext()
	ddCtx.SetState(StateReadDDFrame)
	dd.SetContext(ddCtx)
	dd.SetReadData(bytes.Repeat([]byte{0x42}, 64))
	handler.handleDDFrame(dd, ddCtx)

	for reason, want := range map[string]uint64{
		"malformed":      1,
		"unknown_sni":    1,
		"unknown_secret": 2,
		"bad_timestamp":  1,
		"replay":         1,
	} {
		if got := count(reason); got != want {
			t.Errorf("%s = %d, want %d", reason, got, want)
		}
	}
}
