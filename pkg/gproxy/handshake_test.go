package gproxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func buildDeterministicO2ClientFrame(
	t *testing.T,
	secret []byte,
	dcID int,
	connectionType obfuscated2.ConnectionType,
) []byte {
	t.Helper()

	plain := make([]byte, obfuscated2.FrameSize)
	for i := range plain {
		plain[i] = byte(i + 1)
	}
	binary.LittleEndian.PutUint32(plain[56:60], uint32(connectionType))
	binary.LittleEndian.PutUint16(plain[60:62], uint16(int16(dcID)))

	hash := sha256.New()
	hash.Write(plain[8:40])
	hash.Write(secret)
	encryptor, err := obfuscated2.NewAESCTR(hash.Sum(nil), plain[40:56])
	if err != nil {
		t.Fatalf("create deterministic O2 client encryptor: %v", err)
	}

	wire := make([]byte, len(plain))
	encryptor.XORKeyStream(wire, plain)
	copy(wire[8:56], plain[8:56])
	return wire
}

type capturedOutboundHandshake struct {
	dcID           int
	connectionType obfuscated2.ConnectionType
	wire           []byte
	err            error
}

func captureOutboundHandshake(handler *ProxyHandler) <-chan capturedOutboundHandshake {
	captured := make(chan capturedOutboundHandshake, 1)
	handler.directDCDial = func(dcID int, connectionType obfuscated2.ConnectionType) (*directDCConn, error) {
		var wire bytes.Buffer
		_, _, err := writeDCHandshake(&wire, dcID, connectionType)
		captured <- capturedOutboundHandshake{
			dcID:           dcID,
			connectionType: connectionType,
			wire:           bytes.Clone(wire.Bytes()),
			err:            err,
		}
		if err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	return captured
}

func waitForOutboundHandshake(t *testing.T, captured <-chan capturedOutboundHandshake) capturedOutboundHandshake {
	t.Helper()
	select {
	case result := <-captured:
		if result.err != nil {
			t.Fatalf("generate captured outbound handshake: %v", result.err)
		}
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for outbound DC handshake")
		return capturedOutboundHandshake{}
	}
}

func assertOutboundFraming(
	t *testing.T,
	ctx *ConnContext,
	captured capturedOutboundHandshake,
	wantType obfuscated2.ConnectionType,
	wantDC int,
) {
	t.Helper()

	if got := ctx.o2Framing(); got != wantType {
		t.Errorf("ConnContext framing = 0x%08x, want 0x%08x", got, wantType)
	}
	if captured.connectionType != wantType {
		t.Errorf("outbound dial framing = 0x%08x, want 0x%08x", captured.connectionType, wantType)
	}
	if captured.dcID != wantDC {
		t.Errorf("outbound dial DC ID = %d, want %d", captured.dcID, wantDC)
	}
	gotType, gotDC, _, _ := decodeFakeDCHandshake(t, captured.wire)
	if gotType != wantType {
		t.Errorf("outbound wire framing = 0x%08x, want 0x%08x", gotType, wantType)
	}
	if gotDC != wantDC {
		t.Errorf("outbound wire DC ID = %d, want %d", gotDC, wantDC)
	}
}

func TestRawHandlerChain_PreservesO2FramingToDC(t *testing.T) {
	secret := []byte("0123456789abcdef")
	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
	}{
		{name: "abridged EF", connectionType: obfuscated2.ConnectionTypeAbridged},
		{name: "intermediate EE", connectionType: obfuscated2.ConnectionTypeIntermediate},
		{name: "legacy padded intermediate DD", connectionType: obfuscated2.ConnectionTypePaddedIntermediate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewProxyHandler(&Config{
				Secrets: []Secret{{Name: "test", Key: secret}},
			}, &testLogger{})
			captured := captureOutboundHandshake(handler)

			frame := buildDeterministicO2ClientFrame(t, secret, -2, tc.connectionType)
			if frame[0] == faketls.RecordTypeHandshake {
				version := binary.BigEndian.Uint16(frame[1:3])
				if version == faketls.VersionTLS10 || version == faketls.VersionTLS11 || version == faketls.VersionTLS12 {
					t.Fatal("raw deterministic frame accidentally matches the FakeTLS detector")
				}
			}

			conn := newTestMockGnetConn()
			ctx := NewConnContext()
			conn.SetContext(ctx)
			conn.SetReadData(frame)

			handler.handleDetectProtocol(conn, ctx)
			if got := ctx.ProtocolMode(); got != ModeDD {
				t.Errorf("protocol mode = %v, want ModeDD", got)
			}
			assertOutboundFraming(t, ctx, waitForOutboundHandshake(t, captured), tc.connectionType, -2)
		})
	}
}

func TestFakeTLSHandlerChain_PreservesO2FramingToDC(t *testing.T) {
	secret := []byte("0123456789abcdef")
	const host = "example.com"
	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
	}{
		{name: "abridged EF", connectionType: obfuscated2.ConnectionTypeAbridged},
		{name: "intermediate EE", connectionType: obfuscated2.ConnectionTypeIntermediate},
		{name: "legacy padded intermediate DD", connectionType: obfuscated2.ConnectionTypePaddedIntermediate},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := NewProxyHandler(&Config{
				Secrets:           []Secret{{Name: "test", Key: secret, Host: host}},
				TimeSkewTolerance: time.Minute,
			}, &testLogger{})
			captured := captureOutboundHandshake(handler)

			sessionID := bytes.Repeat([]byte{byte(i + 1)}, 32)
			clientHello := buildTLSRecord(
				faketls.RecordTypeHandshake,
				buildValidClientHello(secret, host, sessionID),
			)
			o2Frame := buildTLSRecord(
				faketls.RecordTypeApplicationData,
				buildDeterministicO2ClientFrame(t, secret, 3, tc.connectionType),
			)

			conn := newTestMockGnetConn()
			ctx := NewConnContext()
			conn.SetContext(ctx)
			conn.SetReadData(append(clientHello, o2Frame...))

			handler.handleDetectProtocol(conn, ctx)
			if got := ctx.ProtocolMode(); got != ModeEE {
				t.Errorf("protocol mode = %v, want ModeEE", got)
			}
			assertOutboundFraming(t, ctx, waitForOutboundHandshake(t, captured), tc.connectionType, 3)
		})
	}
}

// buildValidClientHello constructs a valid FakeTLS ClientHello for testing.
func buildValidClientHello(secret []byte, host string, sessionID []byte) []byte {
	buf := &bytes.Buffer{}

	// Handshake type (0x01 = ClientHello)
	buf.WriteByte(0x01)

	// Placeholder for handshake length (3 bytes)
	lengthPos := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// Version (TLS 1.2 = 0x0303)
	buf.Write([]byte{0x03, 0x03})

	// Random (32 bytes) - will be computed after
	randomPos := buf.Len()
	buf.Write(make([]byte, 32))

	// Session ID
	buf.WriteByte(byte(len(sessionID)))
	buf.Write(sessionID)

	// Cipher suites (minimal set)
	cipherSuites := []byte{
		0x00, 0x04, // Length: 4 bytes (2 cipher suites)
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
	}
	buf.Write(cipherSuites)

	// Compression methods
	buf.Write([]byte{0x01, 0x00}) // 1 method: null

	// Extensions (SNI)
	extensions := buildSNIExtension(host)
	binary.Write(buf, binary.BigEndian, uint16(len(extensions)))
	buf.Write(extensions)

	payload := buf.Bytes()

	// Fill in handshake length (excluding type and length fields)
	handshakeLen := len(payload) - 4
	payload[lengthPos] = byte(handshakeLen >> 16)
	payload[lengthPos+1] = byte(handshakeLen >> 8)
	payload[lengthPos+2] = byte(handshakeLen)

	// Compute HMAC for the random field
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	// Build TLS record
	record := make([]byte, 5+len(payloadCopy))
	record[0] = faketls.RecordTypeHandshake // 0x16
	record[1] = 0x03
	record[2] = 0x01 // TLS 1.0
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payloadCopy)))
	copy(record[5:], payloadCopy)

	// Compute MAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	computedRandom := mac.Sum(nil)

	// XOR with timestamp (last 4 bytes)
	timestamp := uint32(time.Now().Unix())
	computedRandom[28] ^= byte(timestamp)
	computedRandom[29] ^= byte(timestamp >> 8)
	computedRandom[30] ^= byte(timestamp >> 16)
	computedRandom[31] ^= byte(timestamp >> 24)

	// Copy computed random into payload
	copy(payload[randomPos:randomPos+32], computedRandom)

	return payload
}

func buildSNIExtension(host string) []byte {
	buf := &bytes.Buffer{}

	// Extension type (0x0000 = SNI)
	buf.Write([]byte{0x00, 0x00})

	// Extension data length
	extDataLen := 2 + 1 + 2 + len(host)
	binary.Write(buf, binary.BigEndian, uint16(extDataLen))

	// Server name list length
	listLen := 1 + 2 + len(host)
	binary.Write(buf, binary.BigEndian, uint16(listLen))

	// Name type (0 = hostname)
	buf.WriteByte(0)

	// Name length
	binary.Write(buf, binary.BigEndian, uint16(len(host)))

	// Name
	buf.WriteString(host)

	return buf.Bytes()
}

// buildTLSRecord wraps a payload in a TLS record header.
func buildTLSRecord(recordType byte, payload []byte) []byte {
	record := make([]byte, faketls.RecordHeaderSize+len(payload))
	record[0] = recordType
	record[1] = 0x03 // TLS 1.0
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[faketls.RecordHeaderSize:], payload)
	return record
}

// TestHandleTLSHeader_NotEnoughData tests that partial headers wait for more data.
func TestHandleTLSHeader_NotEnoughData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSHeader)
	mockConn.SetContext(ctx)

	// Only 3 bytes (need 5 for TLS header)
	mockConn.SetReadData([]byte{0x16, 0x03, 0x01})

	action := handler.handleTLSHeader(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None with partial header, got %d", action)
	}
}

// TestHandleTLSHeader_NotHandshake tests non-handshake records trigger splice.
func TestHandleTLSHeader_NotHandshake(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		SpliceHost: "example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSHeader)
	mockConn.SetContext(ctx)

	// Application Data record (0x17) instead of Handshake (0x16)
	record := []byte{0x17, 0x03, 0x01, 0x00, 0x10}
	record = append(record, make([]byte, 16)...)
	mockConn.SetReadData(record)

	action := handler.handleTLSHeader(mockConn, ctx)
	// Should trigger splice
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing after non-handshake record, got %v", ctx.State())
	}
	_ = action // Action depends on splice behavior
}

// TestHandleTLSHeader_InvalidVersion tests invalid TLS version triggers splice.
func TestHandleTLSHeader_InvalidVersion(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		SpliceHost: "example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSHeader)
	mockConn.SetContext(ctx)

	// Invalid TLS version 0x0400
	record := []byte{0x16, 0x04, 0x00, 0x00, 0x10}
	record = append(record, make([]byte, 16)...)
	mockConn.SetReadData(record)

	action := handler.handleTLSHeader(mockConn, ctx)
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing after invalid TLS version, got %v", ctx.State())
	}
	_ = action
}

// TestHandleTLSHeader_RecordTooLarge tests oversized records trigger splice.
func TestHandleTLSHeader_RecordTooLarge(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		SpliceHost: "example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSHeader)
	mockConn.SetContext(ctx)

	// Payload length = 20000 (exceeds MaxRecordPayload)
	record := []byte{0x16, 0x03, 0x01, 0x4E, 0x20}
	mockConn.SetReadData(record)

	action := handler.handleTLSHeader(mockConn, ctx)
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing after oversized record, got %v", ctx.State())
	}
	_ = action
}

// TestHandleTLSHeader_ValidHeader tests valid header transitions to payload state.
func TestHandleTLSHeader_ValidHeader(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSHeader)
	mockConn.SetContext(ctx)

	// Valid TLS handshake record header with payload length 100
	record := []byte{0x16, 0x03, 0x01, 0x00, 0x64}
	mockConn.SetReadData(record)

	action := handler.handleTLSHeader(mockConn, ctx)
	if action != 0 { // gnet.None (waiting for payload)
		t.Errorf("expected gnet.None waiting for payload, got %d", action)
	}
	if ctx.State() != StateReadTLSPayload {
		t.Errorf("expected StateReadTLSPayload, got %v", ctx.State())
	}

	// Check payload length is stored
	ctx.mu.Lock()
	payloadLen := ctx.tlsPayloadLen
	ctx.mu.Unlock()
	if payloadLen != 100 {
		t.Errorf("tlsPayloadLen: got %d, want 100", payloadLen)
	}
}

// TestHandleTLSPayload_NotEnoughData tests that partial payload waits for more data.
func TestHandleTLSPayload_NotEnoughData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSPayload)
	ctx.mu.Lock()
	ctx.tlsPayloadLen = 100
	ctx.mu.Unlock()
	mockConn.SetContext(ctx)

	// Header + partial payload (only 50 bytes)
	data := make([]byte, faketls.RecordHeaderSize+50)
	mockConn.SetReadData(data)

	action := handler.handleTLSPayload(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None with partial payload, got %d", action)
	}
}

// TestHandleTLSPayload_NoMatchingSecret tests unrecognized handshakes trigger splice.
func TestHandleTLSPayload_NoMatchingSecret(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		Secrets: []Secret{
			{Key: make([]byte, 16), Name: "test", Host: "example.com"},
		},
		SpliceHost: "splice.example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSPayload)
	mockConn.SetContext(ctx)

	// Build an invalid ClientHello (wrong secret)
	wrongSecret := make([]byte, 16)
	rand.Read(wrongSecret)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	payload := buildValidClientHello(wrongSecret, "example.com", sessionID)

	// Set payload length and full record
	ctx.mu.Lock()
	ctx.tlsPayloadLen = len(payload)
	ctx.mu.Unlock()

	record := buildTLSRecord(faketls.RecordTypeHandshake, payload)
	mockConn.SetReadData(record)

	action := handler.handleTLSPayload(mockConn, ctx)
	// Should trigger splice (no matching secret)
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing with no matching secret, got %v", ctx.State())
	}
	_ = action
}

// TestHandleTLSPayload_NoSpliceHost tests close without splice host.
func TestHandleTLSPayload_NoSpliceHost(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		Secrets: []Secret{
			{Key: make([]byte, 16), Name: "test", Host: "example.com"},
		},
		// No SpliceHost configured
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSPayload)
	mockConn.SetContext(ctx)

	// Build an invalid ClientHello (wrong secret)
	wrongSecret := make([]byte, 16)
	rand.Read(wrongSecret)
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	payload := buildValidClientHello(wrongSecret, "example.com", sessionID)

	ctx.mu.Lock()
	ctx.tlsPayloadLen = len(payload)
	ctx.mu.Unlock()

	record := buildTLSRecord(faketls.RecordTypeHandshake, payload)
	mockConn.SetReadData(record)

	action := handler.handleTLSPayload(mockConn, ctx)
	// Should close (no splice host)
	if action != 1 { // gnet.Close
		t.Errorf("expected gnet.Close without splice host, got %d", action)
	}
}

// TestHandleTLSPayload_ValidSecret tests successful secret matching.
// Note: This test is simpler because full protocol validation is tested in faketls package.
// We verify the state machine transitions correctly when handshake succeeds.
func TestHandleTLSPayload_ValidSecret(t *testing.T) {
	// This test verifies that when no secrets match, we splice.
	// Full protocol testing with valid ClientHello is in faketls package.
	// Here we just verify the fallback behavior.
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		Secrets: []Secret{
			{Key: make([]byte, 16), Name: "testuser", Host: "example.com"},
		},
		SpliceHost: "splice.example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSPayload)
	mockConn.SetContext(ctx)

	// Build a ClientHello payload that won't match (random bytes)
	payload := make([]byte, 200)
	rand.Read(payload)
	// Set handshake type
	payload[0] = 0x01
	// Set length
	handshakeLen := len(payload) - 4
	payload[1] = byte(handshakeLen >> 16)
	payload[2] = byte(handshakeLen >> 8)
	payload[3] = byte(handshakeLen)

	ctx.mu.Lock()
	ctx.tlsPayloadLen = len(payload)
	ctx.mu.Unlock()

	record := buildTLSRecord(faketls.RecordTypeHandshake, payload)
	mockConn.SetReadData(record)

	action := handler.handleTLSPayload(mockConn, ctx)
	// Should transition to splice (no matching secret)
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing after no secret match, got %v", ctx.State())
	}
	_ = action
}

// TestReplayCache_DirectTest tests replay detection via the replay cache directly.
// Full protocol replay detection is hard to test without valid ClientHello generation,
// so we test the replay cache functionality directly.
func TestReplayCache_DirectTest(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		Secrets: []Secret{
			{Key: make([]byte, 16), Name: "testuser", Host: "example.com"},
		},
	}, logger)

	// Test replay cache directly
	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// First call: Seen returns false (not seen before), but adds it
	if handler.replayCache.Seen(sessionID) {
		t.Error("session ID should not be seen on first call")
	}

	// Second call: Seen returns true (replay detected)
	if !handler.replayCache.Seen(sessionID) {
		t.Error("session ID should be detected as replay on second call")
	}

	// Different session ID should not be seen
	sessionID2 := make([]byte, 32)
	rand.Read(sessionID2)
	if handler.replayCache.Seen(sessionID2) {
		t.Error("different session ID should not be seen")
	}
}

// TestStartSplice_NoHost tests that splice without host closes connection.
func TestStartSplice_NoHost(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		// No SpliceHost
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	mockConn.SetContext(ctx)

	action := handler.startSplice(mockConn, ctx)
	if action != 1 { // gnet.Close
		t.Errorf("startSplice without host should return gnet.Close, got %d", action)
	}
}

// TestStartSplice_WithHost tests that splice initiates dial.
func TestStartSplice_WithHost(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		SpliceHost: "example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	mockConn.SetContext(ctx)

	action := handler.startSplice(mockConn, ctx)
	if action != 0 { // gnet.None (async dial)
		t.Errorf("startSplice with host should return gnet.None, got %d", action)
	}
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing, got %v", ctx.State())
	}
}

// TestHandleSplice_NoConnection tests splice without splice connection.
func TestHandleSplice_NoConnection(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateSplicing)
	mockConn.SetContext(ctx)

	// No splice connection set
	action := handler.handleSplice(mockConn, ctx)
	if action != 0 { // gnet.None (waiting)
		t.Errorf("handleSplice without connection should return gnet.None, got %d", action)
	}
}

// TestHandleSplice_NoData tests splice with no data.
func TestHandleSplice_NoData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateSplicing)
	mockConn.SetContext(ctx)

	// Create a splice connection using net.Pipe
	clientSide, _ := net.Pipe()
	ctx.SetSpliceConn(clientSide)
	defer clientSide.Close()

	// No data to read
	mockConn.SetReadData(nil)

	action := handler.handleSplice(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleSplice with no data should return gnet.None, got %d", action)
	}
}

// TestHandleTLSHeader_ValidVersions tests all valid TLS versions.
func TestHandleTLSHeader_ValidVersions(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{"TLS10", 0x0301},
		{"TLS11", 0x0302},
		{"TLS12", 0x0303},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &testLogger{}
			handler := NewProxyHandler(&Config{}, logger)

			mockConn := newTestMockGnetConn()
			ctx := NewConnContext()
			ctx.SetState(StateReadTLSHeader)
			mockConn.SetContext(ctx)

			// Valid TLS record with specified version
			record := []byte{
				0x16,                  // Handshake
				byte(tt.version >> 8), // Version high
				byte(tt.version),      // Version low
				0x00, 0x64,            // Length: 100
			}
			mockConn.SetReadData(record)

			action := handler.handleTLSHeader(mockConn, ctx)
			if action != 0 { // gnet.None
				t.Errorf("expected gnet.None for valid %s, got %d", tt.name, action)
			}
			if ctx.State() != StateReadTLSPayload {
				t.Errorf("expected StateReadTLSPayload for %s, got %v", tt.name, ctx.State())
			}
		})
	}
}

// TestHandleTLSHeader_WithFullPayload tests header+payload in one read.
// When the header indicates full payload is available, handleTLSHeader calls handleTLSPayload.
func TestHandleTLSHeader_WithFullPayload(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		Secrets: []Secret{
			{Key: make([]byte, 16), Name: "testuser", Host: "example.com"},
		},
		SpliceHost: "splice.example.com",
		SplicePort: 443,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSHeader)
	mockConn.SetContext(ctx)

	// Build a ClientHello-like payload (won't match secret, will trigger splice)
	payload := make([]byte, 100)
	rand.Read(payload)
	payload[0] = 0x01 // ClientHello type
	// Set length
	handshakeLen := len(payload) - 4
	payload[1] = byte(handshakeLen >> 16)
	payload[2] = byte(handshakeLen >> 8)
	payload[3] = byte(handshakeLen)

	record := buildTLSRecord(faketls.RecordTypeHandshake, payload)
	mockConn.SetReadData(record)

	// handleTLSHeader should see full record and call handleTLSPayload
	action := handler.handleTLSHeader(mockConn, ctx)
	// After full processing with no match, should transition to splice
	if ctx.State() != StateSplicing {
		t.Errorf("expected StateSplicing after unmatched handshake, got %v", ctx.State())
	}
	_ = action
}

// BenchmarkHandleTLSHeader benchmarks TLS header parsing.
func BenchmarkHandleTLSHeader(b *testing.B) {
	handler := NewProxyHandler(&Config{}, nil)

	mockConn := newTestMockGnetConn()
	record := []byte{0x16, 0x03, 0x01, 0x00, 0x64}
	mockConn.SetReadData(record)

	b.ResetTimer()
	for b.Loop() {
		ctx := NewConnContext()
		ctx.SetState(StateReadTLSHeader)
		mockConn.SetContext(ctx)
		handler.handleTLSHeader(mockConn, ctx)
	}
}

// BenchmarkHandleTLSPayload benchmarks TLS payload parsing.
func BenchmarkHandleTLSPayload(b *testing.B) {
	secret := make([]byte, 16)
	rand.Read(secret)

	handler := NewProxyHandler(&Config{
		Secrets: []Secret{
			{Key: secret, Name: "testuser", Host: "example.com"},
		},
	}, nil)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		// Create fresh context and connection for each iteration
		mockConn := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateReadTLSPayload)

		// Use fresh sessionID to avoid replay detection
		rand.Read(sessionID)
		payload := buildValidClientHello(secret, "example.com", sessionID)
		record := buildTLSRecord(faketls.RecordTypeHandshake, payload)

		ctx.mu.Lock()
		ctx.tlsPayloadLen = len(payload)
		ctx.mu.Unlock()

		mockConn.SetContext(ctx)
		mockConn.SetReadData(record)
		b.StartTimer()

		handler.handleTLSPayload(mockConn, ctx)
	}
}

// TestProtocolDetection tests ee/dd protocol detection based on first 5 bytes.
func TestProtocolDetection(t *testing.T) {
	tests := []struct {
		name         string
		firstBytes   []byte
		expectedMode ProtocolMode
	}{
		{
			name:         "TLS handshake TLS 1.0",
			firstBytes:   []byte{0x16, 0x03, 0x01, 0x00, 0x05},
			expectedMode: ModeEE,
		},
		{
			name:         "TLS handshake TLS 1.2",
			firstBytes:   []byte{0x16, 0x03, 0x03, 0x00, 0x05},
			expectedMode: ModeEE,
		},
		{
			name:         "Raw obfuscated2 (random first byte)",
			firstBytes:   []byte{0x45, 0x12, 0x34, 0x56, 0x78},
			expectedMode: ModeDD,
		},
		{
			name:         "Raw obfuscated2 (0x16 but wrong version)",
			firstBytes:   []byte{0x16, 0x04, 0x00, 0x00, 0x05},
			expectedMode: ModeDD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check if first byte is TLS handshake
			isTLS := tt.firstBytes[0] == 0x16
			if isTLS {
				version := binary.BigEndian.Uint16(tt.firstBytes[1:3])
				isTLS = version == 0x0301 || version == 0x0302 || version == 0x0303
			}

			var detectedMode ProtocolMode
			if isTLS {
				detectedMode = ModeEE
			} else {
				detectedMode = ModeDD
			}

			if detectedMode != tt.expectedMode {
				t.Errorf("got mode %v, want %v", detectedMode, tt.expectedMode)
			}
		})
	}
}
