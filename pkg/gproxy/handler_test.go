package gproxy

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func TestInternalProxyProtocolTransfersAdmissionAfterValidatedHeader(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.InternalProxyProtocol = true
	cfg.InternalProxyAuth = auth
	cfg.MaxConnectionsPerIP = 1
	handler := NewProxyHandler(&cfg, &testLogger{})

	openInternal := func(clientIP string) (*testMockGnetConn, *ConnContext, gnet.Action) {
		connection := newTestMockGnetConn()
		connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000})
		_, action := handler.OnOpen(connection)
		connectionContext := connection.Context().(*ConnContext)
		if action != gnet.None || connectionContext.State() != StateReadProxyProto || !connectionContext.ipLimitTracked {
			t.Fatalf("OnOpen = action %v state %v tracked %t", action, connectionContext.State(), connectionContext.ipLimitTracked)
		}
		input := auth.AppendPreface(nil)
		input = append(input, "PROXY TCP4 "+clientIP+" 127.0.0.1 0 443\r\n"...)
		connection.SetReadData(input)
		action = handler.handleProxyProto(connection, connectionContext)
		return connection, connectionContext, action
	}

	first, firstContext, action := openInternal("198.51.100.1")
	if action != gnet.None || !firstContext.ipLimitTracked || firstContext.RealClientAddr(nil).String() != "198.51.100.1:0" {
		t.Fatalf("first internal = action %v tracked %t real %v", action, firstContext.ipLimitTracked, firstContext.RealClientAddr(nil))
	}
	second, secondContext, action := openInternal("198.51.100.2")
	if action != gnet.None || !secondContext.ipLimitTracked {
		t.Fatalf("second internal = action %v tracked %t", action, secondContext.ipLimitTracked)
	}
	if _, ok := handler.connLimiter.TryAcquireIP(net.ParseIP("198.51.100.1")); ok {
		t.Fatal("first validated client IP was not charged")
	}
	loopbackKey, ok := handler.connLimiter.TryAcquireIP(net.ParseIP("127.0.0.1"))
	if !ok {
		t.Fatal("internal loopback peer was charged instead of the validated client")
	}
	handler.connLimiter.Release(loopbackKey)
	handler.OnClose(first, nil)
	handler.OnClose(second, nil)
}

func TestDirectAndExternalProxyAdmissionRemainImmediate(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		proxyProtocol bool
		wantState     ConnState
	}{
		{name: "direct", wantState: StateDetectProtocol},
		{name: "external PROXY", proxyProtocol: true, wantState: StateReadProxyProto},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.InternalProxyProtocol = true
			cfg.InternalProxyAuth = auth
			cfg.ProxyProtocol = test.proxyProtocol
			cfg.MaxConnectionsPerIP = 1
			handler := NewProxyHandler(&cfg, &testLogger{})
			remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}

			first := newTestMockGnetConn()
			first.SetRemoteAddr(remote)
			_, action := handler.OnOpen(first)
			connectionContext := first.Context().(*ConnContext)
			if action != gnet.None || connectionContext.State() != test.wantState || !connectionContext.ipLimitTracked {
				t.Fatalf("first = action %v state %v tracked %t", action, connectionContext.State(), connectionContext.ipLimitTracked)
			}

			second := newTestMockGnetConn()
			second.SetRemoteAddr(remote)
			_, action = handler.OnOpen(second)
			if action != gnet.Close {
				t.Fatalf("second action = %v, want close", action)
			}
			handler.OnClose(first, nil)
			handler.OnClose(second, nil)
		})
	}
}

func TestInternalProxyCandidateSaturationAndClose(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewProxyHandler(&Config{
		InternalProxyProtocol: true,
		InternalProxyAuth:     auth,
		MaxConnectionsPerIP:   1,
	}, &testLogger{})

	first := newTestMockGnetConn()
	first.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000})
	if _, action := handler.OnOpen(first); action != gnet.None {
		t.Fatalf("first OnOpen action = %v", action)
	}
	firstContext := first.Context().(*ConnContext)
	if !firstContext.ipLimitTracked || handler.connLimiter.ActiveConnections() != 1 {
		t.Fatalf("silent candidate = tracked %t active %d", firstContext.ipLimitTracked, handler.connLimiter.ActiveConnections())
	}
	first.AppendReadData(auth.AppendPreface(nil)[:1])
	if action := handler.OnTraffic(first); action != gnet.None || !firstContext.ipLimitTracked {
		t.Fatalf("partial candidate = action %v tracked %t", action, firstContext.ipLimitTracked)
	}

	second := newTestMockGnetConn()
	second.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001})
	if _, action := handler.OnOpen(second); action != gnet.Close {
		t.Fatalf("saturated candidate action = %v, want close", action)
	}
	if handler.connLimiter.ActiveConnections() != 1 {
		t.Fatalf("saturated limiter active = %d", handler.connLimiter.ActiveConnections())
	}

	handler.OnClose(second, nil)
	handler.OnClose(first, nil)
	if handler.connLimiter.ActiveConnections() != 0 {
		t.Fatalf("limiter active after close = %d", handler.connLimiter.ActiveConnections())
	}
	// A duplicate close must not release a different connection slot.
	handler.OnClose(first, nil)
	if handler.connLimiter.ActiveConnections() != 0 {
		t.Fatalf("limiter active after duplicate close = %d", handler.connLimiter.ActiveConnections())
	}
}

func TestInternalProxyTransferKeepsProvisionalSlotWhenRealIPSaturated(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewProxyHandler(&Config{
		InternalProxyProtocol: true,
		InternalProxyAuth:     auth,
		MaxConnectionsPerIP:   1,
	}, &testLogger{})

	open := func(port int) (*testMockGnetConn, *ConnContext, gnet.Action) {
		connection := newTestMockGnetConn()
		connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		_, action := handler.OnOpen(connection)
		connectionContext := connection.Context().(*ConnContext)
		if action != gnet.None {
			return connection, connectionContext, action
		}
		input := auth.AppendPreface(nil)
		input = append(input, "PROXY TCP4 198.51.100.1 127.0.0.1 0 0\r\n"...)
		connection.SetReadData(input)
		return connection, connectionContext, handler.OnTraffic(connection)
	}

	first, firstContext, action := open(40000)
	if action != gnet.None || firstContext.RealClientAddr(nil).String() != "198.51.100.1:0" {
		t.Fatalf("first transfer = action %v real %v", action, firstContext.RealClientAddr(nil))
	}
	if handler.connLimiter.ActiveConnections() != 1 {
		t.Fatalf("active after successful transfer = %d", handler.connLimiter.ActiveConnections())
	}

	second, secondContext, action := open(40001)
	if action != gnet.Close {
		t.Fatalf("saturated real-IP transfer action = %v, want close", action)
	}
	if !secondContext.ipLimitTracked || secondContext.realClientAddr != nil {
		t.Fatalf("failed transfer = tracked %t real %v", secondContext.ipLimitTracked, secondContext.realClientAddr)
	}
	if handler.connLimiter.ActiveConnections() != 2 {
		t.Fatalf("failed transfer released provisional slot: active = %d", handler.connLimiter.ActiveConnections())
	}

	handler.OnClose(second, nil)
	if handler.connLimiter.ActiveConnections() != 1 {
		t.Fatalf("active after failed-transfer close = %d", handler.connLimiter.ActiveConnections())
	}
	handler.OnClose(first, nil)
	if handler.connLimiter.ActiveConnections() != 0 {
		t.Fatalf("active after all closes = %d", handler.connLimiter.ActiveConnections())
	}
}

func TestInternalProxyUnixCandidateUsesSyntheticLoopbackAdmission(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewProxyHandler(&Config{
		InternalProxyProtocol: true,
		InternalProxyAuth:     auth,
		MaxConnectionsPerIP:   1,
	}, &testLogger{})

	first := newTestMockGnetConn()
	first.SetRemoteAddr(&net.UnixAddr{Name: "/run/telego.sock", Net: "unix"})
	if _, action := handler.OnOpen(first); action != gnet.None {
		t.Fatalf("first Unix action = %v", action)
	}
	firstContext := first.Context().(*ConnContext)
	if !firstContext.ipLimitTracked || handler.connLimiter.ActiveConnections() != 1 {
		t.Fatalf("Unix admission = tracked %t active %d", firstContext.ipLimitTracked, handler.connLimiter.ActiveConnections())
	}

	second := newTestMockGnetConn()
	second.SetRemoteAddr(&net.UnixAddr{Name: "/run/telego.sock", Net: "unix"})
	if _, action := handler.OnOpen(second); action != gnet.Close {
		t.Fatalf("saturated Unix action = %v, want close", action)
	}
	handler.OnClose(second, nil)

	input := auth.AppendPreface(nil)
	input = append(input, "PROXY TCP4 198.51.100.7 127.0.0.1 0 0\r\n"...)
	first.SetReadData(input)
	if action := handler.OnTraffic(first); action != gnet.None {
		t.Fatalf("Unix transfer action = %v", action)
	}
	if got := firstContext.RealClientAddr(nil).String(); got != "198.51.100.7:0" {
		t.Fatalf("Unix real client = %q", got)
	}
	handler.OnClose(first, nil)
	if handler.connLimiter.ActiveConnections() != 0 {
		t.Fatalf("Unix limiter active after close = %d", handler.connLimiter.ActiveConnections())
	}
}

func TestInternalProxyAdmissionConcurrentOpenAndClose(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	const workers = 32
	handler := NewProxyHandler(&Config{
		InternalProxyProtocol: true,
		InternalProxyAuth:     auth,
		MaxConnectionsPerIP:   workers,
	}, nil)

	var waitGroup sync.WaitGroup
	waitGroup.Add(workers)
	for index := range workers {
		go func() {
			defer waitGroup.Done()
			connection := newTestMockGnetConn()
			connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000 + index})
			if _, action := handler.OnOpen(connection); action != gnet.None {
				t.Errorf("OnOpen action = %v", action)
				return
			}
			connection.AppendReadData(auth.AppendPreface(nil)[:1])
			if action := handler.OnTraffic(connection); action != gnet.None {
				t.Errorf("partial action = %v", action)
			}
			handler.OnClose(connection, nil)
		}()
	}
	waitGroup.Wait()
	if handler.connLimiter.ActiveConnections() != 0 {
		t.Fatalf("limiter active after concurrent close = %d", handler.connLimiter.ActiveConnections())
	}
}

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

func TestHandleProxyProtoPublicHeadersAreFragmentationSafe(t *testing.T) {
	v1 := []byte("PROXY TCP4 192.0.2.10 127.0.0.1 12345 443\r\n")
	v2 := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21, 0x11, 0x00, 0x0C,
		0xC0, 0x00, 0x02, 0x0A,
		0x7F, 0x00, 0x00, 0x01,
		0x30, 0x39, 0x01, 0xBB,
	}

	for _, test := range []struct {
		name   string
		header []byte
	}{
		{name: "v1", header: v1},
		{name: "v2", header: v2},
	} {
		t.Run(test.name+"_one_byte_at_a_time", func(t *testing.T) {
			handler := NewProxyHandler(&Config{ProxyProtocol: true}, &testLogger{})
			connection := newTestMockGnetConn()
			connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 40000})
			handler.OnOpen(connection)
			connectionContext := connection.Context().(*ConnContext)
			for index := range test.header {
				connection.AppendReadData(test.header[index : index+1])
				action := handler.OnTraffic(connection)
				if action != gnet.None {
					t.Fatalf("byte %d action = %v", index, action)
				}
				if index+1 < len(test.header) && connectionContext.State() != StateReadProxyProto {
					t.Fatalf("byte %d state = %v, want proxy wait", index, connectionContext.State())
				}
			}
			if got := connectionContext.RealClientAddr(nil).String(); got != "192.0.2.10:12345" {
				t.Fatalf("real client = %q", got)
			}
			handler.OnClose(connection, nil)
		})

		t.Run(test.name+"_every_split", func(t *testing.T) {
			for split := 1; split < len(test.header); split++ {
				handler := NewProxyHandler(&Config{ProxyProtocol: true}, &testLogger{})
				connection := newTestMockGnetConn()
				connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 40000})
				handler.OnOpen(connection)
				connection.AppendReadData(test.header[:split])
				if action := handler.OnTraffic(connection); action != gnet.None {
					t.Fatalf("split %d first action = %v", split, action)
				}
				connection.AppendReadData(test.header[split:])
				if action := handler.OnTraffic(connection); action != gnet.None {
					t.Fatalf("split %d final action = %v", split, action)
				}
				connectionContext := connection.Context().(*ConnContext)
				if got := connectionContext.RealClientAddr(nil).String(); got != "192.0.2.10:12345" {
					t.Fatalf("split %d real client = %q", split, got)
				}
				handler.OnClose(connection, nil)
			}
		})
	}
}

func TestHandleProxyProtoAuthenticatedInternalHeaderIsFragmentationSafe(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	input := auth.AppendPreface(nil)
	input = append(input, "PROXY TCP4 198.51.100.7 127.0.0.1 0 0\r\n"...)

	newConnection := func() (*ProxyHandler, *testMockGnetConn, *ConnContext) {
		handler := NewProxyHandler(&Config{
			InternalProxyProtocol: true,
			InternalProxyAuth:     auth,
		}, &testLogger{})
		connection := newTestMockGnetConn()
		connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000})
		handler.OnOpen(connection)
		return handler, connection, connection.Context().(*ConnContext)
	}

	t.Run("one_byte_at_a_time", func(t *testing.T) {
		handler, connection, connectionContext := newConnection()
		for index := range input {
			connection.AppendReadData(input[index : index+1])
			if action := handler.OnTraffic(connection); action != gnet.None {
				t.Fatalf("byte %d action = %v", index, action)
			}
		}
		if !connectionContext.internalProxyAuthenticated {
			t.Fatal("internal preface was not authenticated")
		}
		if got := connectionContext.RealClientAddr(nil).String(); got != "198.51.100.7:0" {
			t.Fatalf("real client = %q", got)
		}
		handler.OnClose(connection, nil)
	})

	t.Run("every_split", func(t *testing.T) {
		for split := 1; split < len(input); split++ {
			handler, connection, connectionContext := newConnection()
			connection.AppendReadData(input[:split])
			if action := handler.OnTraffic(connection); action != gnet.None {
				t.Fatalf("split %d first action = %v", split, action)
			}
			connection.AppendReadData(input[split:])
			if action := handler.OnTraffic(connection); action != gnet.None {
				t.Fatalf("split %d final action = %v", split, action)
			}
			if !connectionContext.internalProxyAuthenticated || connectionContext.RealClientAddr(nil).String() != "198.51.100.7:0" {
				t.Fatalf("split %d did not authenticate and attribute client", split)
			}
			handler.OnClose(connection, nil)
		}
	})
}

func TestInternalProxyProtocolRejectsLocalSpoofing(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	newConnection := func() (*ProxyHandler, *testMockGnetConn, *ConnContext) {
		handler := NewProxyHandler(&Config{
			InternalProxyProtocol: true,
			InternalProxyAuth:     auth,
			MaxConnectionsPerIP:   2,
		}, &testLogger{})
		connection := newTestMockGnetConn()
		connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000})
		handler.OnOpen(connection)
		return handler, connection, connection.Context().(*ConnContext)
	}

	t.Run("bare PROXY header", func(t *testing.T) {
		handler, connection, connectionContext := newConnection()
		connection.SetReadData([]byte("PROXY TCP4 198.51.100.9 127.0.0.1 0 0\r\n"))
		if action := handler.OnTraffic(connection); action != gnet.None {
			t.Fatalf("action = %v", action)
		}
		if connectionContext.internalProxyAuthenticated || connectionContext.realClientAddr != nil {
			t.Fatal("bare local PROXY header changed client attribution")
		}
		if !connectionContext.ipLimitTracked || handler.connLimiter.ActiveConnections() != 1 {
			t.Fatalf("loopback admission = tracked %t active %d", connectionContext.ipLimitTracked, handler.connLimiter.ActiveConnections())
		}
		handler.OnClose(connection, nil)
	})

	t.Run("wrong authentication token", func(t *testing.T) {
		handler, connection, connectionContext := newConnection()
		if !connectionContext.ipLimitTracked || handler.connLimiter.ActiveConnections() != 1 {
			t.Fatalf("wrong-token candidate was not charged at admission")
		}
		spoof := auth.AppendPreface(nil)
		spoof[len(spoof)-1] ^= 0xff
		spoof = append(spoof, "PROXY TCP4 198.51.100.9 127.0.0.1 0 0\r\n"...)
		connection.SetReadData(spoof)
		if action := handler.OnTraffic(connection); action != gnet.Close {
			t.Fatalf("action = %v, want close", action)
		}
		if connectionContext.internalProxyAuthenticated || connectionContext.realClientAddr != nil {
			t.Fatal("wrong internal token changed client attribution")
		}
		if !connectionContext.ipLimitTracked || handler.connLimiter.ActiveConnections() != 1 {
			t.Fatalf("loopback admission = tracked %t active %d", connectionContext.ipLimitTracked, handler.connLimiter.ActiveConnections())
		}
		handler.OnClose(connection, nil)
	})
}

func TestAuthenticatedInternalProxyReattributesPublicLoopbackAdmission(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewProxyHandler(&Config{
		ProxyProtocol:         true,
		InternalProxyProtocol: true,
		InternalProxyAuth:     auth,
		MaxConnectionsPerIP:   1,
	}, &testLogger{})

	openInternal := func(clientIP string) (*testMockGnetConn, *ConnContext) {
		connection := newTestMockGnetConn()
		connection.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000})
		if _, action := handler.OnOpen(connection); action != gnet.None {
			t.Fatalf("OnOpen action = %v", action)
		}
		connectionContext := connection.Context().(*ConnContext)
		if !connectionContext.ipLimitTracked {
			t.Fatal("public PROXY behavior did not charge loopback at admission")
		}
		input := auth.AppendPreface(nil)
		input = append(input, "PROXY TCP4 "+clientIP+" 127.0.0.1 0 0\r\n"...)
		connection.SetReadData(input)
		if action := handler.OnTraffic(connection); action != gnet.None {
			t.Fatalf("internal traffic action = %v", action)
		}
		return connection, connectionContext
	}

	first, firstContext := openInternal("198.51.100.1")
	second, secondContext := openInternal("198.51.100.2")
	if firstContext.RealClientAddr(nil).String() != "198.51.100.1:0" ||
		secondContext.RealClientAddr(nil).String() != "198.51.100.2:0" {
		t.Fatal("authenticated internal connections were not reattributed")
	}
	handler.OnClose(first, nil)
	handler.OnClose(second, nil)
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
func TestHandleProxyProto_Incomplete(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{
		ProxyProtocol: true,
	}, logger)

	mockConn := newTestMockGnetConn()
	handler.OnOpen(mockConn)

	ctx := mockConn.Context().(*ConnContext)

	// Partial PROXY v1 header (no CRLF yet).
	data := []byte("PROXY TCP4 192.168")
	mockConn.SetReadData(data)

	action := handler.handleProxyProto(mockConn, ctx)

	if action != gnet.None || ctx.State() != StateReadProxyProto {
		t.Errorf("incomplete v1 = action %v state %v, want wait", action, ctx.State())
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
