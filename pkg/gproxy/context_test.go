package gproxy

import (
	"crypto/cipher"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// mockCipherStream implements cipher.Stream for testing
type mockCipherStream struct{}

func (m *mockCipherStream) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

var _ cipher.Stream = (*mockCipherStream)(nil)

// TestConnContext_StateTransitions tests atomic state changes.
func TestConnContext_StateTransitions(t *testing.T) {
	ctx := NewConnContext()

	// Initial state
	if ctx.State() != StateReadTLSHeader {
		t.Errorf("initial state: got %v, want StateReadTLSHeader", ctx.State())
	}

	// Transition through states
	states := []ConnState{
		StateReadTLSPayload,
		StateReadO2Frame,
		StateDialingDC,
		StateRelaying,
		StateClosed,
	}

	for _, state := range states {
		ctx.SetState(state)
		if ctx.State() != state {
			t.Errorf("after SetState(%v): got %v", state, ctx.State())
		}
	}
}

// TestConnContext_SetRelay tests that relay context is set once.
func TestConnContext_SetRelay(t *testing.T) {
	ctx := NewConnContext()

	// Initially nil
	if ctx.Relay() != nil {
		t.Error("Relay() should be nil initially")
	}

	// Set relay
	relay := &RelayContext{}
	ctx.SetRelay(relay)

	// Should be set
	if ctx.Relay() != relay {
		t.Error("Relay() should return set relay")
	}

	// State should transition to Relaying
	if ctx.State() != StateRelaying {
		t.Errorf("state after SetRelay: got %v, want StateRelaying", ctx.State())
	}
}

// TestConnContext_Relay tests relay returns nil before set.
func TestConnContext_Relay(t *testing.T) {
	ctx := NewConnContext()

	if ctx.Relay() != nil {
		t.Error("Relay() should return nil before SetRelay()")
	}
}

// TestNewConnContext tests initialization.
func TestNewConnContext(t *testing.T) {
	ctx := NewConnContext()

	if ctx == nil {
		t.Fatal("NewConnContext returned nil")
	}

	// Check initial state
	if ctx.State() != StateReadTLSHeader {
		t.Errorf("initial state: got %v, want StateReadTLSHeader", ctx.State())
	}

	// Check time is recent
	if time.Since(ctx.connTime) > time.Second {
		t.Error("connTime should be recent")
	}

	// Check relay is nil
	if ctx.Relay() != nil {
		t.Error("relay should be nil initially")
	}
}

// TestConnState_String tests state string conversion.
func TestConnState_String(t *testing.T) {
	testCases := []struct {
		state    ConnState
		expected string
	}{
		{StateReadTLSHeader, "ReadTLSHeader"},
		{StateReadTLSPayload, "ReadTLSPayload"},
		{StateReadO2Frame, "ReadO2Frame"},
		{StateDialingDC, "DialingDC"},
		{StateRelaying, "Relaying"},
		{StateSplicing, "Splicing"},
		{StateClosed, "Closed"},
		{ConnState(99), "Unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			if tc.state.String() != tc.expected {
				t.Errorf("String(): got %q, want %q", tc.state.String(), tc.expected)
			}
		})
	}
}

// TestConnContext_ConcurrentState tests concurrent state access.
func TestConnContext_ConcurrentState(t *testing.T) {
	ctx := NewConnContext()

	var wg sync.WaitGroup
	const numGoroutines = 100

	wg.Add(numGoroutines * 2)

	// Writers
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			states := []ConnState{
				StateReadTLSHeader,
				StateReadTLSPayload,
				StateReadO2Frame,
				StateDialingDC,
			}
			for j := range 100 {
				ctx.SetState(states[j%len(states)])
			}
		}(i)
	}

	// Readers
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for range 100 {
				state := ctx.State()
				// Just verify it's a valid state
				_ = state.String()
			}
		}()
	}

	wg.Wait()
}

// TestConnContext_ConcurrentRelay tests concurrent relay access.
func TestConnContext_ConcurrentRelay(t *testing.T) {
	ctx := NewConnContext()

	var wg sync.WaitGroup
	const numReaders = 100

	// Set relay in one goroutine
	wg.Go(func() {
		relay := &RelayContext{}
		ctx.SetRelay(relay)
	})

	// Read relay in many goroutines
	wg.Add(numReaders)
	for range numReaders {
		go func() {
			defer wg.Done()
			for range 100 {
				_ = ctx.Relay()
			}
		}()
	}

	wg.Wait()

	// Relay should be set
	if ctx.Relay() == nil {
		t.Error("Relay should be set after concurrent access")
	}
}

// TestRelayContext_Fields tests RelayContext field access.
func TestRelayContext_Fields(t *testing.T) {
	// Create mock cipher streams (nil is fine for field testing)
	var encryptor, decryptor cipher.Stream
	var dcConn gnet.Conn // nil gnet.Conn for testing

	relay := &RelayContext{
		Encryptor: encryptor,
		Decryptor: decryptor,
		DCConn:    dcConn,
		DCEncrypt: nil,
		DCDecrypt: nil,
	}

	if relay.Encryptor != encryptor {
		t.Error("Encryptor field mismatch")
	}

	if relay.Decryptor != decryptor {
		t.Error("Decryptor field mismatch")
	}

	if relay.DCConn != dcConn {
		t.Error("DCConn field mismatch")
	}
}

// TestConnContext_HandshakeFields tests handshake-phase field access.
func TestConnContext_HandshakeFields(t *testing.T) {
	ctx := NewConnContext()

	// These fields are protected by mutex during handshake
	ctx.mu.Lock()
	ctx.tlsPayloadLen = 1000
	ctx.dcID = 2
	ctx.mu.Unlock()

	ctx.mu.Lock()
	if ctx.tlsPayloadLen != 1000 {
		t.Errorf("tlsPayloadLen: got %d, want 1000", ctx.tlsPayloadLen)
	}
	if ctx.dcID != 2 {
		t.Errorf("dcID: got %d, want 2", ctx.dcID)
	}
	ctx.mu.Unlock()
}

// TestConnContext_PendingData tests pending data field.
func TestConnContext_PendingData(t *testing.T) {
	ctx := NewConnContext()

	ctx.mu.Lock()
	ctx.pendingData = []byte("pending")
	ctx.mu.Unlock()

	ctx.mu.Lock()
	if string(ctx.pendingData) != "pending" {
		t.Error("pendingData mismatch")
	}
	ctx.mu.Unlock()
}

// TestConnState_Values tests state constant values.
func TestConnState_Values(t *testing.T) {
	// States should be sequential from 0
	if StateReadProxyProto != 0 {
		t.Errorf("StateReadProxyProto should be 0, got %d", StateReadProxyProto)
	}
	if StateReadTLSHeader != 1 {
		t.Errorf("StateReadTLSHeader should be 1, got %d", StateReadTLSHeader)
	}
	if StateReadTLSPayload != 2 {
		t.Errorf("StateReadTLSPayload should be 2, got %d", StateReadTLSPayload)
	}
	if StateReadO2Frame != 3 {
		t.Errorf("StateReadO2Frame should be 3, got %d", StateReadO2Frame)
	}
	if StateDialingDC != 4 {
		t.Errorf("StateDialingDC should be 4, got %d", StateDialingDC)
	}
	if StateRelaying != 5 {
		t.Errorf("StateRelaying should be 5, got %d", StateRelaying)
	}
	if StateSplicing != 6 {
		t.Errorf("StateSplicing should be 6, got %d", StateSplicing)
	}
	if StateClosed != 7 {
		t.Errorf("StateClosed should be 7, got %d", StateClosed)
	}
}

// TestConnContext_RealClientAddr tests real client address handling.
func TestConnContext_RealClientAddr(t *testing.T) {
	ctx := NewConnContext()
	fallback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888}

	// Initially returns fallback
	addr := ctx.RealClientAddr(fallback)
	if addr != fallback {
		t.Error("RealClientAddr should return fallback when not set")
	}

	// Set real address
	realAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	ctx.SetRealClientAddr(realAddr)

	// Should now return real address
	addr = ctx.RealClientAddr(fallback)
	if addr != realAddr {
		t.Error("RealClientAddr should return set address")
	}

	// Verify IP
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatal("expected *net.TCPAddr")
	}
	if !tcpAddr.IP.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("IP mismatch: got %s", tcpAddr.IP)
	}
	if tcpAddr.Port != 12345 {
		t.Errorf("Port mismatch: got %d", tcpAddr.Port)
	}
}

// TestConnContext_TrafficCounters tests traffic counter handling.
func TestConnContext_TrafficCounters(t *testing.T) {
	ctx := NewConnContext()

	// Initially nil
	if ctx.TrafficIn() != nil {
		t.Error("TrafficIn should be nil initially")
	}
	if ctx.TrafficOut() != nil {
		t.Error("TrafficOut should be nil initially")
	}

	// Set counters
	var bytesIn, bytesOut atomic.Int64
	ctx.SetTrafficCounters(&bytesIn, &bytesOut)

	// Verify they are set
	if ctx.TrafficIn() != &bytesIn {
		t.Error("TrafficIn not set correctly")
	}
	if ctx.TrafficOut() != &bytesOut {
		t.Error("TrafficOut not set correctly")
	}

	// Verify we can use them
	ctx.TrafficIn().Add(100)
	ctx.TrafficOut().Add(200)

	if bytesIn.Load() != 100 {
		t.Errorf("bytesIn: got %d, want 100", bytesIn.Load())
	}
	if bytesOut.Load() != 200 {
		t.Errorf("bytesOut: got %d, want 200", bytesOut.Load())
	}
}

// TestConnContext_DCID tests DC ID getter.
func TestConnContext_DCID(t *testing.T) {
	ctx := NewConnContext()

	// Initially 0
	if ctx.DCID() != 0 {
		t.Errorf("DCID should be 0 initially, got %d", ctx.DCID())
	}

	// Set via mutex
	ctx.mu.Lock()
	ctx.dcID = 2
	ctx.mu.Unlock()

	// Verify getter
	if ctx.DCID() != 2 {
		t.Errorf("DCID: got %d, want 2", ctx.DCID())
	}
}

// TestConnContext_CleanupWithData tests cleanup zeroes sensitive data.
func TestConnContext_CleanupWithData(t *testing.T) {
	ctx := NewConnContext()

	// Set up sensitive data
	ctx.mu.Lock()
	ctx.clientHello = &faketls.ClientHello{
		SessionID: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Random:    [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	ctx.pendingData = []byte{1, 2, 3, 4, 5}
	ctx.encryptor = &mockCipherStream{}
	ctx.decryptor = &mockCipherStream{}
	ctx.secret = &Secret{Name: "test"}
	ctx.mu.Unlock()

	// Cleanup
	ctx.Cleanup()

	// Verify everything is cleared
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	if ctx.clientHello != nil {
		t.Error("clientHello should be nil after cleanup")
	}
	if ctx.pendingData != nil {
		t.Error("pendingData should be nil after cleanup")
	}
	if ctx.encryptor != nil {
		t.Error("encryptor should be nil after cleanup")
	}
	if ctx.decryptor != nil {
		t.Error("decryptor should be nil after cleanup")
	}
	if ctx.secret != nil {
		t.Error("secret should be nil after cleanup")
	}
}
