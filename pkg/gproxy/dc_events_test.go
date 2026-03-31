package gproxy

import (
	"testing"
	"time"
)

func TestDCConnContext_Fields(t *testing.T) {
	clientConn := newTestMockGnetConn()
	clientCtx := NewConnContext()
	dcConn := newTestMockGnetConn()

	dcCtx := &DCConnContext{
		ClientConn: clientConn,
		ClientCtx:  clientCtx,
		DCConn:     dcConn,
	}

	if dcCtx.ClientConn != clientConn {
		t.Error("ClientConn mismatch")
	}
	if dcCtx.ClientCtx != clientCtx {
		t.Error("ClientCtx mismatch")
	}
	if dcCtx.DCConn != dcConn {
		t.Error("DCConn mismatch")
	}
}

func TestDCConnContext_ThrottleState(t *testing.T) {
	dcCtx := &DCConnContext{}

	// Initially not throttled
	if dcCtx.throttledToClient.Load() {
		t.Error("should not be throttled initially")
	}

	// Set throttled
	dcCtx.throttledToClient.Store(true)
	if !dcCtx.throttledToClient.Load() {
		t.Error("should be throttled after Store(true)")
	}

	// Clear throttled
	dcCtx.throttledToClient.Store(false)
	if dcCtx.throttledToClient.Load() {
		t.Error("should not be throttled after Store(false)")
	}
}

func TestDcEventHandler_GetDCContext(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}
	mockConn := newTestMockGnetConn()

	// No context set - should return nil
	ctx := dcHandler.getDCContext(mockConn)
	if ctx != nil {
		t.Error("should return nil when no context set")
	}

	// Set context directly
	dcCtx := &DCConnContext{
		ClientCtx: NewConnContext(),
	}
	mockConn.SetContext(dcCtx)

	// Should now return the context
	ctx = dcHandler.getDCContext(mockConn)
	if ctx != dcCtx {
		t.Error("should return the set context")
	}
}

func TestDcEventHandler_GetDCContext_PendingMap(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}
	mockConn := newTestMockGnetConn()
	mockConn.SetFD(12345)

	// Store in pending map
	dcCtx := &DCConnContext{
		ClientCtx: NewConnContext(),
	}
	handler.pendingDCContexts.Store(12345, dcCtx)
	defer handler.pendingDCContexts.Delete(12345)

	// Should find via pending map fallback
	ctx := dcHandler.getDCContext(mockConn)
	if ctx != dcCtx {
		t.Error("should find context via pending map")
	}
}

func TestDcEventHandler_OnTraffic_NoContext(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}
	mockConn := newTestMockGnetConn()

	// No context - should close
	action := dcHandler.OnTraffic(mockConn)
	if action != 1 { // gnet.Close
		t.Errorf("OnTraffic without context should return Close, got %d", action)
	}
}

func TestDcEventHandler_OnClose_NoContext(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}
	mockConn := newTestMockGnetConn()

	// No context - should return None
	action := dcHandler.OnClose(mockConn, nil)
	if action != 0 { // gnet.None
		t.Errorf("OnClose without context should return None, got %d", action)
	}
}

func TestDcEventHandler_OnClose_WithContext(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}
	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	dcCtx := &DCConnContext{
		ClientConn: mockClientConn,
		ClientCtx:  clientCtx,
	}
	mockDCConn.SetContext(dcCtx)

	// Should close client connection
	action := dcHandler.OnClose(mockDCConn, nil)
	if action != 0 { // gnet.None
		t.Errorf("OnClose should return None, got %d", action)
	}

	// Client connection should be closed
	if !mockClientConn.IsClosed() {
		t.Error("client connection should be closed")
	}
}

func TestDcEventHandler_OnClose_Logging(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}
	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.mu.Lock()
	clientCtx.dcID = 2
	clientCtx.secret = &Secret{Name: "testuser"}
	clientCtx.mu.Unlock()

	dcCtx := &DCConnContext{
		ClientConn: mockClientConn,
		ClientCtx:  clientCtx,
	}
	mockDCConn.SetContext(dcCtx)

	// Close with error
	dcHandler.OnClose(mockDCConn, nil)

	// Should have logged
	if len(logger.debugs) == 0 && len(logger.warnings) == 0 {
		t.Error("should log DC disconnect")
	}
}

func TestHandleDCTraffic_ClientClosed(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateClosed)

	dcCtx := &DCConnContext{
		ClientConn: mockClientConn,
		ClientCtx:  clientCtx,
	}

	// Client already closed - should return Close
	action := handler.handleDCTraffic(mockDCConn, dcCtx)
	if action != 1 { // gnet.Close
		t.Errorf("handleDCTraffic with closed client should return Close, got %d", action)
	}
}

func TestHandleDCTraffic_NoData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     nil, // Will cause nil cipher check
		ClientEncrypt: nil,
	}

	// No data - should return None (or Close due to nil ciphers)
	mockDCConn.SetReadData(nil)
	action := handler.handleDCTraffic(mockDCConn, dcCtx)
	// Either None (no data) or Close (nil ciphers) is acceptable
	if action != 0 && action != 1 {
		t.Errorf("unexpected action: %d", action)
	}
}

// BenchmarkDCConnContext_ThrottleState benchmarks atomic operations
func BenchmarkDCConnContext_ThrottleState(b *testing.B) {
	dcCtx := &DCConnContext{}

	b.ResetTimer()
	for b.Loop() {
		dcCtx.throttledToClient.Store(true)
		_ = dcCtx.throttledToClient.Load()
		dcCtx.throttledToClient.Store(false)
	}
}

// TestNewDCEventHandler tests handler creation
func TestNewDCEventHandler(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{}, logger)

	dcHandler := &dcEventHandler{proxy: handler}

	if dcHandler.proxy != handler {
		t.Error("proxy not set correctly")
	}
}

// TestDCConnContext_TimingSafety tests that timing information is accessible
func TestDCConnContext_TimingSafety(t *testing.T) {
	clientCtx := NewConnContext()

	// connTime should be set at creation
	if time.Since(clientCtx.connTime) > time.Second {
		t.Error("connTime should be recent")
	}

	dcCtx := &DCConnContext{
		ClientCtx: clientCtx,
	}

	// Should be able to access timing info
	duration := time.Since(dcCtx.ClientCtx.connTime)
	if duration > time.Second {
		t.Error("should be able to calculate duration")
	}
}

// mockStream implements cipher.Stream for testing
type mockStream struct{}

func (m *mockStream) XORKeyStream(dst, src []byte) {
	copy(dst, src) // Identity cipher
}

// TestHandleDCTraffic_FullPath tests the complete DC->client data path.
func TestHandleDCTraffic_FullPath(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     &mockStream{},
		ClientEncrypt: &mockStream{},
	}
	mockDCConn.SetContext(dcCtx)

	// Put some data in DC connection
	testData := []byte("Hello from DC")
	mockDCConn.SetReadData(testData)

	action := handler.handleDCTraffic(mockDCConn, dcCtx)

	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None, got %d", action)
	}

	// Data should have been written to client (wrapped in TLS)
	asyncWrites := mockClientConn.GetAsyncWrites()
	if len(asyncWrites) == 0 {
		t.Error("data should have been written to client")
	}
}

// TestHandleDCTraffic_NilCiphers tests that nil ciphers cause close.
func TestHandleDCTraffic_NilCiphers(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     nil, // Nil cipher
		ClientEncrypt: nil,
	}
	mockDCConn.SetContext(dcCtx)

	mockDCConn.SetReadData([]byte("test"))

	action := handler.handleDCTraffic(mockDCConn, dcCtx)

	if action != 1 { // gnet.Close
		t.Errorf("expected gnet.Close with nil ciphers, got %d", action)
	}
}

// TestHandleDCTraffic_EmptyData tests handling of empty data.
func TestHandleDCTraffic_EmptyData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     &mockStream{},
		ClientEncrypt: &mockStream{},
	}
	mockDCConn.SetContext(dcCtx)

	// No data
	mockDCConn.SetReadData(nil)

	action := handler.handleDCTraffic(mockDCConn, dcCtx)

	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None with no data, got %d", action)
	}
}

// TestHandleDCTraffic_Backpressure tests backpressure handling.
func TestHandleDCTraffic_Backpressure(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 1 * 1024 * 1024, // 1MB max
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	// Simulate congested client
	mockClientConn.SetOutboundBuffered(2 * 1024 * 1024) // 2MB buffered

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     &mockStream{},
		ClientEncrypt: &mockStream{},
	}
	mockDCConn.SetContext(dcCtx)

	// Large data
	testData := make([]byte, 100*1024)
	mockDCConn.SetReadData(testData)

	handler.handleDCTraffic(mockDCConn, dcCtx)

	// Should be throttled
	if !dcCtx.throttledToClient.Load() {
		t.Error("should be throttled due to client backpressure")
	}
}

// TestHandleDCTraffic_LargeData tests handling of large data that exceeds pool buffer.
func TestHandleDCTraffic_LargeData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     &mockStream{},
		ClientEncrypt: &mockStream{},
	}
	mockDCConn.SetContext(dcCtx)

	// Large data that may exceed pool buffer
	testData := make([]byte, 256*1024) // 256KB
	for i := range testData {
		testData[i] = byte(i)
	}
	mockDCConn.SetReadData(testData)

	action := handler.handleDCTraffic(mockDCConn, dcCtx)

	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None, got %d", action)
	}

	// Should have written TLS-wrapped data
	asyncWrites := mockClientConn.GetAsyncWrites()
	if len(asyncWrites) == 0 {
		t.Error("large data should have been written")
	}
}

// TestHandleDCTraffic_TrafficCounting tests traffic counter updates.
func TestHandleDCTraffic_TrafficCounting(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, logger)

	mockDCConn := newTestMockGnetConn()
	mockClientConn := newTestMockGnetConn()

	clientCtx := NewConnContext()
	clientCtx.SetState(StateRelaying)

	// Set up traffic counters
	counters := newTestTrafficCounters()
	clientCtx.SetTrafficCounters(&counters.BytesIn, &counters.BytesOut)

	dcCtx := &DCConnContext{
		ClientConn:    mockClientConn,
		ClientCtx:     clientCtx,
		DCDecrypt:     &mockStream{},
		ClientEncrypt: &mockStream{},
	}
	mockDCConn.SetContext(dcCtx)

	// Data from DC (counts as TrafficOut from user's perspective)
	testData := make([]byte, 1000)
	mockDCConn.SetReadData(testData)

	handler.handleDCTraffic(mockDCConn, dcCtx)

	// DC->client is download/out traffic
	if counters.BytesOut.Load() != 1000 {
		t.Errorf("BytesOut: got %d, want 1000", counters.BytesOut.Load())
	}
}

// BenchmarkHandleDCTraffic benchmarks DC traffic handling.
func BenchmarkHandleDCTraffic(b *testing.B) {
	handler := NewProxyHandler(&Config{
		MaxWriteBuffer: 4 * 1024 * 1024,
	}, nil)

	testData := make([]byte, 16*1024)

	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		mockDCConn := newTestMockGnetConn()
		mockClientConn := newTestMockGnetConn()

		clientCtx := NewConnContext()
		clientCtx.SetState(StateRelaying)

		dcCtx := &DCConnContext{
			ClientConn:    mockClientConn,
			ClientCtx:     clientCtx,
			DCDecrypt:     &mockStream{},
			ClientEncrypt: &mockStream{},
		}
		mockDCConn.SetContext(dcCtx)
		mockDCConn.SetReadData(testData)
		b.StartTimer()

		handler.handleDCTraffic(mockDCConn, dcCtx)
	}
}
