package gproxy

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// mockCipher implements cipher.Stream for testing
type mockCipher struct{}

func (m *mockCipher) XORKeyStream(dst, src []byte) {
	// Identity cipher - just copy
	copy(dst, src)
}

var _ cipher.Stream = (*mockCipher)(nil)

// buildTLSApplicationData creates a TLS ApplicationData record
func buildTLSApplicationData(payload []byte) []byte {
	record := make([]byte, faketls.RecordHeaderSize+len(payload))
	record[0] = faketls.RecordTypeApplicationData // 0x17
	record[1] = 0x03                              // TLS 1.2
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[faketls.RecordHeaderSize:], payload)
	return record
}

// TestHandleRelay_NoRelayContext tests that relay waits when DC not ready.
func TestHandleRelay_NoRelayContext(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)
	mockConn.SetContext(ctx)

	// No relay context set
	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleRelay without relay context should return gnet.None, got %d", action)
	}
}

// TestHandleRelay_NotEnoughData tests that relay waits for complete TLS header.
func TestHandleRelay_NotEnoughData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	// Set up relay context
	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)

	// Only 3 bytes (need 5 for TLS header)
	mockConn.SetReadData([]byte{0x17, 0x03, 0x03})

	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleRelay with partial header should return gnet.None, got %d", action)
	}
}

// TestHandleRelay_SingleRecord tests processing a single ApplicationData record.
func TestHandleRelay_SingleRecord(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)

	// Create a single ApplicationData record
	payload := []byte("Hello, DC!")
	record := buildTLSApplicationData(payload)
	mockConn.SetReadData(record)

	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleRelay should return gnet.None, got %d", action)
	}

	// Data should have been written to DC (via AsyncWrite)
	// MockGnetConn tracks async writes
	asyncWrites := mockDCConn.GetAsyncWrites()
	if len(asyncWrites) == 0 {
		t.Error("data should have been written to DC")
	}
}

// TestHandleRelay_MultipleRecords tests processing multiple records in one batch.
func TestHandleRelay_MultipleRecords(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)

	// Create multiple ApplicationData records
	var data []byte
	for range 5 {
		payload := make([]byte, 100)
		rand.Read(payload)
		data = append(data, buildTLSApplicationData(payload)...)
	}
	mockConn.SetReadData(data)

	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleRelay should return gnet.None, got %d", action)
	}

	// Data should have been written to DC
	asyncWrites := mockDCConn.GetAsyncWrites()
	if len(asyncWrites) == 0 {
		t.Error("data should have been written to DC")
	}
}

// TestHandleRelay_IncompleteRecord tests incomplete record handling.
func TestHandleRelay_IncompleteRecord(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)

	// Header says 100 bytes but only 50 provided
	record := []byte{
		0x17, 0x03, 0x03, // ApplicationData, TLS 1.2
		0x00, 0x64, // Length: 100
	}
	record = append(record, make([]byte, 50)...) // Only 50 bytes
	mockConn.SetReadData(record)

	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None (waiting for more data)
		t.Errorf("handleRelay with incomplete record should return gnet.None, got %d", action)
	}
}

// TestHandleRelay_NonApplicationData tests handling of non-ApplicationData records.
func TestHandleRelay_NonApplicationData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)

	// Create a Handshake record (should be skipped)
	record := []byte{
		0x16, 0x03, 0x03, // Handshake, TLS 1.2
		0x00, 0x05, // Length: 5
		0x01, 0x02, 0x03, 0x04, 0x05, // Payload
	}
	mockConn.SetReadData(record)

	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleRelay should return gnet.None, got %d", action)
	}
}

// TestHandleRelay_DesyncDetection tests that oversized frames are detected.
func TestHandleRelay_DesyncDetection(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)

	// Create a record with abnormally large payload (triggers desync detection)
	// DesyncFrameSizeThreshold is 1MB
	record := []byte{
		0x17, 0x03, 0x03, // ApplicationData, TLS 1.2
		0x10, 0x00, // Length: 4096 (0x1000) - normal size
	}
	record = append(record, make([]byte, 4096)...)
	mockConn.SetReadData(record)

	action := handler.handleRelay(mockConn, ctx)
	// Normal frame size should not trigger desync
	if action != 0 { // gnet.None
		t.Errorf("normal frame size should return gnet.None, got %d", action)
	}
}

// TestHandleRelay_BackpressureThrottling tests backpressure handling.
func TestHandleRelay_BackpressureThrottling(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 1024 * 1024, // 1MB max buffer
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()

	// Simulate congested DC connection
	mockDCConn.SetOutboundBuffered(2 * 1024 * 1024) // 2MB buffered (above max)

	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)
	mockConn.SetContext(ctx)
	relay.ToDC = newRelayOutput(mockDCConn, mockConn, ctx, handler.maxWriteBuffer)
	relay.ToDC.buffered = mockDCConn.OutboundBuffered()
	t.Cleanup(relay.ToDC.close)

	// Create a large amount of data
	var data []byte
	for range 100 {
		payload := make([]byte, 1000)
		data = append(data, buildTLSApplicationData(payload)...)
	}
	mockConn.SetReadData(data)

	action := handler.handleRelay(mockConn, ctx)
	if action != 0 { // gnet.None
		t.Errorf("handleRelay should return gnet.None, got %d", action)
	}

	if len(mockDCConn.GetAsyncWrites()) != 0 || mockConn.InboundBuffered() != len(data) {
		t.Error("saturated output must leave client data untouched")
	}
}

// TestHandleRelay_TrafficCounting tests traffic counter updates.
func TestHandleRelay_TrafficCounting(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockConn := newTestMockGnetConn()
	mockDCConn := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)

	// Set up traffic counters
	counters := newTestTrafficCounters()
	ctx.SetTrafficCounters(&counters.BytesIn, &counters.BytesOut)
	mockConn.SetContext(ctx)

	// Create some data
	payload := make([]byte, 1000)
	record := buildTLSApplicationData(payload)
	mockConn.SetReadData(record)

	handler.handleRelay(mockConn, ctx)

	// Check traffic was counted
	if counters.BytesIn.Load() != 1000 {
		t.Errorf("trafficIn: got %d, want 1000", counters.BytesIn.Load())
	}
}

// TestRelayContext_FieldsRelay tests RelayContext field access.
func TestRelayContext_FieldsRelay(t *testing.T) {
	mockDCConn := newTestMockGnetConn()
	decryptor := &mockCipher{}
	dcEncrypt := &mockCipher{}

	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: decryptor,
		DCEncrypt: dcEncrypt,
	}

	if relay.DCConn != mockDCConn {
		t.Error("DCConn mismatch")
	}
	if relay.Decryptor != decryptor {
		t.Error("Decryptor mismatch")
	}
	if relay.DCEncrypt != dcEncrypt {
		t.Error("DCEncrypt mismatch")
	}
}

// TestConnContext_SetGetRelay tests relay context setter/getter.
func TestConnContext_SetGetRelay(t *testing.T) {
	ctx := NewConnContext()

	// Initially nil
	if ctx.Relay() != nil {
		t.Error("Relay() should be nil initially")
	}

	// Set relay
	mockDCConn := newTestMockGnetConn()
	relay := &RelayContext{
		DCConn:    mockDCConn,
		Decryptor: &mockCipher{},
		DCEncrypt: &mockCipher{},
	}
	ctx.SetRelay(relay)

	// Get relay
	gotRelay := ctx.Relay()
	if gotRelay != relay {
		t.Error("Relay() should return the set relay")
	}
}

// BenchmarkHandleRelay benchmarks relay processing.
func BenchmarkHandleRelay(b *testing.B) {
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, nil)

	// Create test data
	payload := make([]byte, 1000)
	rand.Read(payload)
	record := buildTLSApplicationData(payload)

	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		mockConn := newTestMockGnetConn()
		mockDCConn := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateRelaying)

		relay := &RelayContext{
			DCConn:    mockDCConn,
			Decryptor: &mockCipher{},
			DCEncrypt: &mockCipher{},
		}
		ctx.SetRelay(relay)
		mockConn.SetContext(ctx)
		mockConn.SetReadData(record)
		b.StartTimer()

		handler.handleRelay(mockConn, ctx)
	}
}

// BenchmarkHandleRelay_LargePayload benchmarks relay with large payloads.
func BenchmarkHandleRelay_LargePayload(b *testing.B) {
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, nil)

	// Create large test data (16KB payload)
	payload := make([]byte, 16*1024)
	rand.Read(payload)
	record := buildTLSApplicationData(payload)

	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		mockConn := newTestMockGnetConn()
		mockDCConn := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateRelaying)

		relay := &RelayContext{
			DCConn:    mockDCConn,
			Decryptor: &mockCipher{},
			DCEncrypt: &mockCipher{},
		}
		ctx.SetRelay(relay)
		mockConn.SetContext(ctx)
		mockConn.SetReadData(record)
		b.StartTimer()

		handler.handleRelay(mockConn, ctx)
	}
}
