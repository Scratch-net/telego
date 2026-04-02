package gproxy

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	
)

func TestNewProxyHandler(t *testing.T) {
	cfg := &Config{
		IdleTimeout:         5 * time.Minute,
		MaxConnectionsPerIP: 10,
		MaxIPsPerUser:       5,
		IPBlockTimeout:      time.Minute,
	}

	logger := &testLogger{}
	handler := NewProxyHandler(cfg, logger)

	if handler == nil {
		t.Fatal("NewProxyHandler returned nil")
	}

	// Check config is stored
	if handler.config != cfg {
		t.Error("config not stored")
	}

	// Check idle timeout
	if handler.IdleTimeout() != 5*time.Minute {
		t.Errorf("IdleTimeout: got %v, want 5m", handler.IdleTimeout())
	}

	// Check conn limiter is created when MaxConnectionsPerIP > 0
	if handler.connLimiter == nil {
		t.Error("connLimiter should be created")
	}

	// Check user limiter is created
	if handler.userLimiter == nil {
		t.Error("userLimiter should be created")
	}

	// Check replay cache is created
	if handler.replayCache == nil {
		t.Error("replayCache should be created")
	}

	// Check buffer pools are created
	if handler.dcBufPool == nil {
		t.Error("dcBufPool should be created")
	}
	if handler.relayBufPool == nil {
		t.Error("relayBufPool should be created")
	}

	// Check desync detector is created
	if handler.desyncDetector == nil {
		t.Error("desyncDetector should be created")
	}
}

func TestNewProxyHandler_NoLimits(t *testing.T) {
	cfg := &Config{
		IdleTimeout: 5 * time.Minute,
		// No connection limits set
	}

	logger := &testLogger{}
	handler := NewProxyHandler(cfg, logger)

	// Conn limiter should be nil when not configured
	if handler.connLimiter != nil {
		t.Error("connLimiter should be nil when MaxConnectionsPerIP is 0")
	}

	// User limiter should still be created (for stats tracking)
	if handler.userLimiter == nil {
		t.Error("userLimiter should be created for stats tracking")
	}
}

func TestNewProxyHandler_DefaultLogger(t *testing.T) {
	cfg := &Config{}

	// Passing nil logger should use default
	handler := NewProxyHandler(cfg, nil)

	if handler == nil {
		t.Fatal("NewProxyHandler returned nil")
	}

	// Should have a default logger (won't panic when logging)
	handler.logger.Debug("test %s", "debug")
	handler.logger.Info("test %s", "info")
}

func TestNewProxyHandler_MaxWriteBuffer(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"default", 0, defaultMaxWriteBuffer},
		{"negative", -100, defaultMaxWriteBuffer},
		{"custom", 8 * 1024 * 1024, 8 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				MaxWriteBuffer: tt.input,
			}
			handler := NewProxyHandler(cfg, nil)
			if handler.maxWriteBuffer != tt.expected {
				t.Errorf("maxWriteBuffer: got %d, want %d", handler.maxWriteBuffer, tt.expected)
			}
		})
	}
}

func TestProxyHandler_ApplyHotConfig(t *testing.T) {
	cfg := &Config{
		IdleTimeout: 5 * time.Minute,
	}

	handler := NewProxyHandler(cfg, nil)

	// Apply new config
	newCfg := &Config{
		IdleTimeout: 10 * time.Minute,
	}
	handler.ApplyHotConfig(newCfg)

	// Check idle timeout was updated
	if handler.IdleTimeout() != 10*time.Minute {
		t.Errorf("IdleTimeout after hot config: got %v, want 10m", handler.IdleTimeout())
	}
}

func TestProxyHandler_UserLimiter(t *testing.T) {
	cfg := &Config{
		MaxIPsPerUser:  5,
		IPBlockTimeout: time.Minute,
	}

	handler := NewProxyHandler(cfg, nil)

	limiter := handler.UserLimiter()
	if limiter == nil {
		t.Fatal("UserLimiter() returned nil")
	}

	// Should be the same instance
	if limiter != handler.userLimiter {
		t.Error("UserLimiter() should return the same instance")
	}
}

func TestProxyHandler_IdleTimeout_Concurrent(t *testing.T) {
	cfg := &Config{
		IdleTimeout: time.Minute,
	}

	handler := NewProxyHandler(cfg, nil)

	// Concurrent reads and writes
	var wg atomic.Int32
	done := make(chan struct{})

	// Readers
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Add(-1)
			for {
				select {
				case <-done:
					return
				default:
					_ = handler.IdleTimeout()
				}
			}
		}()
	}

	// Writer
	go func() {
		for i := range 100 {
			handler.ApplyHotConfig(&Config{
				IdleTimeout: time.Duration(i) * time.Second,
			})
		}
		close(done)
	}()

	// Wait for readers to finish
	for wg.Load() > 0 {
		time.Sleep(time.Millisecond)
	}
}

func TestDefaultLogger(t *testing.T) {
	logger := defaultLogger{}

	// Should not panic
	logger.Debug("test %s", "debug")
	logger.Info("test %s", "info")
	logger.Warn("test %s", "warn")
	logger.Error("test %s", "error")

	if logger.DebugEnabled() {
		t.Error("defaultLogger should have debug disabled")
	}
}

func TestProxyHandler_BackpressureLimits(t *testing.T) {
	cfg := &Config{
		MaxWriteBuffer: 4 * 1024 * 1024, // 4MB
	}

	handler := NewProxyHandler(cfg, nil)

	// Soft limit should be half of max
	expectedSoft := 2 * 1024 * 1024
	if handler.bpSoftLimit != expectedSoft {
		t.Errorf("bpSoftLimit: got %d, want %d", handler.bpSoftLimit, expectedSoft)
	}

	// Resume threshold should be quarter of max
	expectedResume := 1 * 1024 * 1024
	if handler.bpResumeAt != expectedResume {
		t.Errorf("bpResumeAt: got %d, want %d", handler.bpResumeAt, expectedResume)
	}
}

// TestProxyHandler_OnOpen tests connection open handling
func TestProxyHandler_OnOpen_Context(t *testing.T) {
	cfg := &Config{
		IdleTimeout: 5 * time.Minute,
	}

	handler := NewProxyHandler(cfg, &testLogger{})

	// Create mock connection
	mockConn := newTestMockGnetConn()

	// Call OnOpen
	out, action := handler.OnOpen(mockConn)

	if out != nil {
		t.Error("OnOpen should return nil data")
	}
	if action != 0 { // gnet.None
		t.Errorf("OnOpen should return gnet.None, got %d", action)
	}

	// Context should be set
	ctx := mockConn.Context()
	if ctx == nil {
		t.Fatal("context not set on connection")
	}

	connCtx, ok := ctx.(*ConnContext)
	if !ok {
		t.Fatal("context is not *ConnContext")
	}

	// Initial state should be StateDetectProtocol (not proxy protocol mode)
	if connCtx.State() != StateDetectProtocol {
		t.Errorf("initial state: got %v, want StateDetectProtocol", connCtx.State())
	}
}

func TestProxyHandler_OnOpen_ProxyProtocol(t *testing.T) {
	cfg := &Config{
		IdleTimeout:   5 * time.Minute,
		ProxyProtocol: true,
	}

	handler := NewProxyHandler(cfg, &testLogger{})
	mockConn := newTestMockGnetConn()

	handler.OnOpen(mockConn)

	connCtx, ok := mockConn.Context().(*ConnContext)
	if !ok {
		t.Fatal("context is not *ConnContext")
	}

	// Should start in StateReadProxyProto when proxy protocol is enabled
	if connCtx.State() != StateReadProxyProto {
		t.Errorf("initial state with proxy protocol: got %v, want StateReadProxyProto", connCtx.State())
	}
}

func TestProxyHandler_OnClose(t *testing.T) {
	cfg := &Config{
		IdleTimeout: 5 * time.Minute,
	}

	handler := NewProxyHandler(cfg, &testLogger{})
	mockConn := newTestMockGnetConn()

	// Open and close
	handler.OnOpen(mockConn)

	action := handler.OnClose(mockConn, nil)
	if action != 0 { // gnet.None
		t.Errorf("OnClose should return gnet.None, got %d", action)
	}

	// Context should be cleaned up
	ctx := mockConn.Context().(*ConnContext)
	if ctx.State() != StateClosed {
		t.Errorf("state after close: got %v, want StateClosed", ctx.State())
	}
}

func TestProxyHandler_OnClose_NoContext(t *testing.T) {
	cfg := &Config{}
	handler := NewProxyHandler(cfg, &testLogger{})

	// Connection without context
	mockConn := newTestMockGnetConn()

	// Should not panic
	action := handler.OnClose(mockConn, nil)
	if action != 0 { // gnet.None
		t.Errorf("OnClose should return gnet.None, got %d", action)
	}
}

func TestProxyHandler_OnTraffic_InvalidState(t *testing.T) {
	cfg := &Config{}
	handler := NewProxyHandler(cfg, &testLogger{})

	// Connection without context
	mockConn := newTestMockGnetConn()

	// Should return Close action when no context
	action := handler.OnTraffic(mockConn)
	if action != 1 { // gnet.Close
		t.Errorf("OnTraffic without context should return gnet.Close, got %d", action)
	}
}

func TestProxyHandler_OnTraffic_ClosedState(t *testing.T) {
	cfg := &Config{}
	handler := NewProxyHandler(cfg, &testLogger{})

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	// Set state to closed
	ctx := mockConn.Context().(*ConnContext)
	ctx.SetState(StateClosed)

	// Should return Close action
	action := handler.OnTraffic(mockConn)
	if action != 1 { // gnet.Close
		t.Errorf("OnTraffic in Closed state should return gnet.Close, got %d", action)
	}
}

func TestProxyHandler_ActiveConnections(t *testing.T) {
	cfg := &Config{}
	handler := NewProxyHandler(cfg, &testLogger{})

	// Open multiple connections
	conns := make([]*testMockGnetConn, 5)
	for i := range conns {
		conns[i] = newTestMockGnetConn()
		handler.OnOpen(conns[i])
	}

	// Check active count
	if handler.activeConns != 5 {
		t.Errorf("activeConns: got %d, want 5", handler.activeConns)
	}

	// Close some
	handler.OnClose(conns[0], nil)
	handler.OnClose(conns[1], nil)

	if handler.activeConns != 3 {
		t.Errorf("activeConns after close: got %d, want 3", handler.activeConns)
	}

	// Close rest
	for i := 2; i < len(conns); i++ {
		handler.OnClose(conns[i], nil)
	}

	if handler.activeConns != 0 {
		t.Errorf("activeConns after all closed: got %d, want 0", handler.activeConns)
	}
}

// BenchmarkProxyHandler_OnOpen benchmarks connection opening
func BenchmarkProxyHandler_OnOpen(b *testing.B) {
	cfg := &Config{IdleTimeout: time.Minute}
	handler := NewProxyHandler(cfg, nil)

	b.ResetTimer()
	for b.Loop() {
		conn := newTestMockGnetConn()
		handler.OnOpen(conn)
	}
}

// BenchmarkProxyHandler_OnClose benchmarks connection closing
func BenchmarkProxyHandler_OnClose(b *testing.B) {
	cfg := &Config{IdleTimeout: time.Minute}
	handler := NewProxyHandler(cfg, nil)

	conns := make([]*testMockGnetConn, b.N)
	for i := range conns {
		conns[i] = newTestMockGnetConn()
		handler.OnOpen(conns[i])
	}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		handler.OnClose(conns[i], nil)
	}
}

// TestHandleProxyProto_V1 tests PROXY protocol v1 parsing in handler.
func TestHandleProxyProto_V1(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// Set up PROXY protocol v1 header
	header := []byte("PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n")
	mockConn.SetReadData(header)

	action := handler.handleProxyProto(mockConn, ctx)

	// Should transition to protocol detection state
	if ctx.State() != StateDetectProtocol {
		t.Errorf("expected StateDetectProtocol, got %v", ctx.State())
	}

	// Real client address should be set
	fallback := mockConn.RemoteAddr()
	realAddr := ctx.RealClientAddr(fallback)
	tcpAddr, ok := realAddr.(*net.TCPAddr)
	if !ok {
		t.Fatal("expected *net.TCPAddr")
	}
	if !tcpAddr.IP.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("IP: got %s, want 192.168.1.100", tcpAddr.IP)
	}
	if tcpAddr.Port != 12345 {
		t.Errorf("Port: got %d, want 12345", tcpAddr.Port)
	}
	_ = action
}

// TestHandleProxyProto_V2 tests PROXY protocol v2 parsing in handler.
func TestHandleProxyProto_V2(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// Build PROXY protocol v2 header
	header := []byte{
		// Signature (12 bytes)
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		// Version + PROXY command
		0x21,
		// AF_INET + STREAM
		0x11,
		// Address length (12 bytes for IPv4)
		0x00, 0x0C,
		// Source IP (192.168.1.100)
		0xC0, 0xA8, 0x01, 0x64,
		// Dest IP (10.0.0.1)
		0x0A, 0x00, 0x00, 0x01,
		// Source port (12345 = 0x3039)
		0x30, 0x39,
		// Dest port (443 = 0x01BB)
		0x01, 0xBB,
	}
	mockConn.SetReadData(header)

	action := handler.handleProxyProto(mockConn, ctx)

	// Should transition to protocol detection state
	if ctx.State() != StateDetectProtocol {
		t.Errorf("expected StateDetectProtocol, got %v", ctx.State())
	}
	_ = action
}

// TestHandleProxyProto_NotProxy tests non-PROXY data is passed through.
func TestHandleProxyProto_NotProxy(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// TLS ClientHello-like data (not PROXY protocol)
	// First byte is 0x16 which doesn't match 'P' (0x50) or 0x0D
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x64} // TLS handshake header
	mockConn.SetReadData(data)

	action := handler.handleProxyProto(mockConn, ctx)

	// handleProxyProto transitions to StateDetectProtocol, then calls handleDetectProtocol
	// which detects TLS and may transition through TLS states
	state := ctx.State()
	if state != StateDetectProtocol && state != StateReadTLSHeader && state != StateReadTLSPayload {
		t.Errorf("expected protocol detect or TLS state, got %v", state)
	}
	_ = action
}

// TestHandleProxyProto_Incomplete tests incomplete PROXY header handling.
// Note: The PROXY protocol parser returns an error for incomplete v1 headers
// (where PROXY prefix is present but no CRLF found), which results in Close.
func TestHandleProxyProto_Incomplete(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// Partial PROXY v1 header (no CRLF yet) - parser returns error for incomplete
	data := []byte("PROXY TCP4 192.168")
	mockConn.SetReadData(data)

	action := handler.handleProxyProto(mockConn, ctx)

	// Parser returns error for incomplete v1 header, so connection is closed
	if action != 1 { // gnet.Close
		t.Errorf("expected gnet.Close for incomplete v1 header (error case), got %d", action)
	}
}

// TestHandleProxyProto_WaitingForData tests waiting for more data scenario.
func TestHandleProxyProto_WaitingForData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// Just the 'P' byte - could be start of PROXY, need more to determine
	data := []byte("P")
	mockConn.SetReadData(data)

	action := handler.handleProxyProto(mockConn, ctx)

	// Need at least 6 bytes to determine protocol type
	// With only 1 byte, returns None (waiting)
	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None for 1 byte, got %d", action)
	}
}

// TestHandleProxyProto_InvalidFormat tests invalid PROXY header handling.
func TestHandleProxyProto_InvalidFormat(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// Invalid PROXY header (missing fields)
	data := []byte("PROXY TCP4 invalid\r\n")
	mockConn.SetReadData(data)

	action := handler.handleProxyProto(mockConn, ctx)

	// Should close connection on invalid header
	if action != 1 { // gnet.Close
		t.Errorf("expected gnet.Close for invalid header, got %d", action)
	}
}

// TestHandleProxyProto_NoData tests empty data handling.
func TestHandleProxyProto_NoData(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// No data
	mockConn.SetReadData(nil)

	action := handler.handleProxyProto(mockConn, ctx)

	// Should return None (waiting for data)
	if action != 0 { // gnet.None
		t.Errorf("expected gnet.None for no data, got %d", action)
	}
}

// TestOnTraffic_ProxyProtocolState tests OnTraffic dispatches to handleProxyProto.
func TestOnTraffic_ProxyProtocolState(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	// Should start in StateReadProxyProto
	ctx := mockConn.Context().(*ConnContext)
	if ctx.State() != StateReadProxyProto {
		t.Fatalf("expected StateReadProxyProto, got %v", ctx.State())
	}

	// Send non-PROXY data
	mockConn.SetReadData([]byte{0x16, 0x03, 0x01, 0x00, 0x64})

	action := handler.OnTraffic(mockConn)

	// Should transition through protocol detection to TLS handling
	state := ctx.State()
	if state != StateDetectProtocol && state != StateReadTLSHeader && state != StateReadTLSPayload {
		t.Errorf("expected protocol detect or TLS state, got %v", state)
	}
	_ = action
}

// TestOnTraffic_StateDispatch tests OnTraffic state machine dispatch.
func TestOnTraffic_StateDispatch(t *testing.T) {
	tests := []struct {
		name          string
		initialState  ConnState
		expectedClose bool
	}{
		{"Closed", StateClosed, true},
		{"DialingDC", StateDialingDC, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewProxyHandler(&Config{}, &testLogger{})
			mockConn := newTestMockGnetConn()
			handler.OnOpen(mockConn)

			ctx := mockConn.Context().(*ConnContext)
			ctx.SetState(tt.initialState)

			action := handler.OnTraffic(mockConn)

			if tt.expectedClose && action != 1 { // gnet.Close
				t.Errorf("expected gnet.Close, got %d", action)
			}
			if !tt.expectedClose && action != 0 { // gnet.None
				t.Errorf("expected gnet.None, got %d", action)
			}
		})
	}
}
