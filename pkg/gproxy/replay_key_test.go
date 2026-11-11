package gproxy

import (
	"context"
	"net"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// Frame bytes 0..7 do not feed key/IV derivation. A replay with any of them
// changed must still be detected.
func TestDDReplayDetectedWhenUnusedPrefixBytesChange(t *testing.T) {
	secret := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{
		Secrets:    []Secret{{Name: "test", Key: secret}},
		SpliceHost: "127.0.0.1",
		SplicePort: 1,
	}, &testLogger{})
	handler.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return nil, net.ErrClosed
	}
	frame := buildDeterministicO2ClientFrame(t, secret, 2, obfuscated2.ConnectionTypeIntermediate)

	run := func(wire []byte) ConnState {
		connection := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateReadDDFrame)
		connection.SetContext(ctx)
		connection.SetReadData(wire)
		handler.handleDDFrame(connection, ctx)
		return ctx.State()
	}

	if state := run(frame); state == StateSplicing {
		t.Fatal("first frame was spliced")
	}
	for i := range 8 {
		mutated := append([]byte(nil), frame...)
		mutated[i] ^= 0xff
		if _, _, _, _, err := obfuscated2.ParseClientFrameWithType(secret, mutated); err != nil {
			t.Fatalf("mutated frame byte %d no longer parses: %v", i, err)
		}
		if state := run(mutated); state != StateSplicing {
			t.Fatalf("replay with byte %d flipped: state %v, want Splicing", i, state)
		}
	}
}
