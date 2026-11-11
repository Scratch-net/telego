package gproxy

import (
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// An authenticated hello rejected only for its timestamp must be remembered,
// so it cannot be replayed once its timestamp becomes acceptable. Widening
// the tolerance stands in for the passage of time.
func TestRejectedTimestampHelloCannotBeReplayedLater(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{})
	payload := buildPaddedClientHelloAt(key, "example.com", 512, uint32(time.Now().Add(-time.Hour).Unix()))
	run := func() ConnState {
		connection := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateReadTLSPayload)
		ctx.tlsPayloadLen = len(payload)
		connection.SetContext(ctx)
		connection.SetReadData(buildTLSRecord(faketls.RecordTypeHandshake, payload))
		handler.handleTLSPayload(connection, ctx)
		return ctx.State()
	}
	if state := run(); state == StateReadO2Frame {
		t.Fatal("stale hello accepted")
	}
	handler.config.TimeSkewTolerance = 2 * time.Hour
	if state := run(); state == StateReadO2Frame {
		t.Fatal("hello rejected for its timestamp was accepted later")
	}
}

// A hello dated in the future becomes acceptable only when the clock reaches
// it. Its replay entry must outlive the cache TTL until then.
func TestRejectedFutureHelloOutlivesReplayTTL(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{})
	handler.replayCache = NewReplayCache(1024, 50*time.Millisecond)
	payload := buildPaddedClientHelloAt(key, "example.com", 512, uint32(time.Now().Add(time.Hour).Unix()))
	run := func() ConnState {
		connection := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateReadTLSPayload)
		ctx.tlsPayloadLen = len(payload)
		connection.SetContext(ctx)
		connection.SetReadData(buildTLSRecord(faketls.RecordTypeHandshake, payload))
		handler.handleTLSPayload(connection, ctx)
		return ctx.State()
	}
	if state := run(); state == StateReadO2Frame {
		t.Fatal("future hello accepted")
	}
	time.Sleep(100 * time.Millisecond) // past the cache TTL
	handler.config.TimeSkewTolerance = 2 * time.Hour
	if state := run(); state == StateReadO2Frame {
		t.Fatal("future hello was replayed after its replay entry expired")
	}
}
