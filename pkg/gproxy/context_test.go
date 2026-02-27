package gproxy

import (
	"crypto/cipher"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

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
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			states := []ConnState{
				StateReadTLSHeader,
				StateReadTLSPayload,
				StateReadO2Frame,
				StateDialingDC,
			}
			for j := 0; j < 100; j++ {
				ctx.SetState(states[j%len(states)])
			}
		}(i)
	}

	// Readers
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
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
	wg.Add(1)
	go func() {
		defer wg.Done()
		relay := &RelayContext{}
		ctx.SetRelay(relay)
	}()

	// Read relay in many goroutines
	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
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
	if StateReadTLSHeader != 0 {
		t.Errorf("StateReadTLSHeader should be 0, got %d", StateReadTLSHeader)
	}
	if StateReadTLSPayload != 1 {
		t.Errorf("StateReadTLSPayload should be 1, got %d", StateReadTLSPayload)
	}
	if StateReadO2Frame != 2 {
		t.Errorf("StateReadO2Frame should be 2, got %d", StateReadO2Frame)
	}
	if StateDialingDC != 3 {
		t.Errorf("StateDialingDC should be 3, got %d", StateDialingDC)
	}
	if StateRelaying != 4 {
		t.Errorf("StateRelaying should be 4, got %d", StateRelaying)
	}
	if StateSplicing != 5 {
		t.Errorf("StateSplicing should be 5, got %d", StateSplicing)
	}
	if StateClosed != 6 {
		t.Errorf("StateClosed should be 6, got %d", StateClosed)
	}
}
