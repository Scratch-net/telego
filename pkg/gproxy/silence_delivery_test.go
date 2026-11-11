package gproxy

import (
	"testing"
)

// The silence breaker must see a server reply only once the client output
// delivered it. A slow reader keeps the reply queued; queuing alone must not
// start the client-silence clock.
func TestServerActivityStampedOnDeliveryNotQueue(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		handler := NewProxyHandler(&Config{}, &testLogger{})
		client := &relayCapacityConn{testMockGnetConn: newTestMockGnetConn()}
		clientCtx := NewConnContext()
		clientCtx.protocolMode = mode
		clientCtx.SetState(StateRelaying)
		dcCtx := &DCConnContext{
			ClientConn:    client,
			ClientCtx:     clientCtx,
			ClientEncrypt: &mockCipherStream{},
			DCDecrypt:     &mockCipherStream{},
		}
		dc := newTestMockGnetConn()
		dc.SetReadData(make([]byte, 100))
		handler.handleDCTraffic(dc, dcCtx)
		if len(client.owner.tasks) != 1 {
			t.Fatalf("mode %v: write was not submitted", mode)
		}
		if err := client.owner.tasks[0].Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := clientCtx.lastServerByteMs.Load(); got != 0 {
			t.Fatalf("mode %v: server activity stamped while the reply is still queued", mode)
		}
		_, _ = client.output.Discard(client.output.Buffered())
		if clientCtx.lastServerByteMs.Load() == 0 {
			t.Fatalf("mode %v: server activity not stamped after delivery", mode)
		}
		dcCtx.ToClient.close()
		client.output.Release()
	}
}
