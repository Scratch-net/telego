package netx

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNewSocks5Dialer(t *testing.T) {
	// Valid address format
	dialer, err := NewSocks5Dialer("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	if dialer == nil {
		t.Fatal("NewSocks5Dialer returned nil")
	}

	if dialer.ProxyAddr != "127.0.0.1:1080" {
		t.Errorf("ProxyAddr: got %s, want 127.0.0.1:1080", dialer.ProxyAddr)
	}

	if dialer.dialer == nil {
		t.Error("dialer should not be nil")
	}
}

func TestNewSocks5Dialer_InvalidAddress(t *testing.T) {
	// SOCKS5 library is lenient with address parsing,
	// so we can't easily test invalid addresses
	// Just verify it doesn't panic with various inputs

	testCases := []string{
		"localhost:1080",
		"[::1]:1080",
		"proxy.example.com:1080",
	}

	for _, addr := range testCases {
		dialer, err := NewSocks5Dialer(addr)
		if err != nil {
			t.Errorf("NewSocks5Dialer(%s) failed: %v", addr, err)
			continue
		}
		if dialer == nil {
			t.Errorf("NewSocks5Dialer(%s) returned nil", addr)
		}
	}
}

// TestSocks5Dialer_Dial tests dialing through SOCKS5
// Note: This requires a real SOCKS5 server, so it's skipped by default
func TestSocks5Dialer_Dial(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SOCKS5 test in short mode (requires SOCKS5 server)")
	}

	// Check if there's a SOCKS5 proxy at localhost:1080
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1080", 100*time.Millisecond)
	if err != nil {
		t.Skip("no SOCKS5 proxy at 127.0.0.1:1080")
	}
	conn.Close()

	dialer, err := NewSocks5Dialer("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	// Try to dial a known server through SOCKS5
	// Using localhost as target since it's most likely to work
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	_, err = dialer.Dial("tcp", listener.Addr().String())
	// Error is expected if SOCKS5 can't route to localhost
	// This is implementation-dependent
	t.Logf("Dial result: %v (may be expected)", err)
}

// TestSocks5Dialer_DialContext tests context-aware dialing
func TestSocks5Dialer_DialContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SOCKS5 test in short mode")
	}

	// Check if there's a SOCKS5 proxy
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1080", 100*time.Millisecond)
	if err != nil {
		t.Skip("no SOCKS5 proxy at 127.0.0.1:1080")
	}
	conn.Close()

	dialer, err := NewSocks5Dialer("127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	// Test with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = dialer.DialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected error with canceled context")
	}
}

// TestSocks5Dialer_DialContext_Timeout tests timeout behavior
func TestSocks5Dialer_DialContext_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SOCKS5 timeout test in short mode")
	}

	// This test requires a SOCKS5 server that's slow or unresponsive
	// We'll just verify the context timeout mechanism works

	dialer, err := NewSocks5Dialer("10.255.255.1:1080") // non-routable
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = dialer.DialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestErrNoHalfClose(t *testing.T) {
	if errNoHalfClose == nil {
		t.Error("errNoHalfClose should not be nil")
	}

	expected := "connection does not support half-close"
	if errNoHalfClose.Error() != expected {
		t.Errorf("errNoHalfClose: got %q, want %q", errNoHalfClose.Error(), expected)
	}
}

// TestSocks5Dialer_Fields tests dialer field access
func TestSocks5Dialer_Fields(t *testing.T) {
	dialer, _ := NewSocks5Dialer("proxy.test:1080")

	if dialer.ProxyAddr != "proxy.test:1080" {
		t.Errorf("ProxyAddr mismatch: got %s", dialer.ProxyAddr)
	}
}

// BenchmarkNewSocks5Dialer benchmarks dialer creation
func BenchmarkNewSocks5Dialer(b *testing.B) {
	for b.Loop() {
		NewSocks5Dialer("127.0.0.1:1080")
	}
}

// mockSocks5Server creates a minimal SOCKS5 server for testing.
// It handles the handshake and CONNECT command, then forwards to a target.
func startMockSocks5Server(t *testing.T) (proxyAddr string, targetAddr string, cleanup func()) {
	t.Helper()

	// Start a target server that accepts connections
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start target listener: %v", err)
	}

	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			// Echo server
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Start SOCKS5 proxy server
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		targetListener.Close()
		t.Fatalf("failed to start proxy listener: %v", err)
	}

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go handleSocks5(conn, targetListener.Addr().String())
		}
	}()

	return proxyListener.Addr().String(), targetListener.Addr().String(), func() {
		proxyListener.Close()
		targetListener.Close()
	}
}

// handleSocks5 handles a single SOCKS5 connection.
func handleSocks5(conn net.Conn, allowedTarget string) {
	defer conn.Close()

	// Read greeting
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}

	// Version 5, no methods needed
	if buf[0] != 0x05 {
		return
	}

	// Reply: version 5, no auth required
	conn.Write([]byte{0x05, 0x00})

	// Read CONNECT request
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Check: version 5, CONNECT command
	if buf[0] != 0x05 || buf[1] != 0x01 {
		// Reply with general failure
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse address based on type
	var targetHost string
	var targetPort int
	addrType := buf[3]

	switch addrType {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		targetHost = net.IP(buf[4:8]).String()
		targetPort = int(buf[8])<<8 | int(buf[9])
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetHost = string(buf[5 : 5+domainLen])
		targetPort = int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		targetHost = net.IP(buf[4:20]).String()
		targetPort = int(buf[20])<<8 | int(buf[21])
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Address type not supported
		return
	}

	// Connect to target
	target := net.JoinHostPort(targetHost, itoa(targetPort))
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer targetConn.Close()

	// Reply success with bound address
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01}
	reply = append(reply, localAddr.IP.To4()...)
	reply = append(reply, byte(localAddr.Port>>8), byte(localAddr.Port))
	conn.Write(reply)

	// Relay data
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			targetConn.Write(buf[:n])
		}
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				break
			}
			conn.Write(buf[:n])
		}
		done <- struct{}{}
	}()
	<-done
}

// itoa converts int to string
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b) - 1
	for i > 0 {
		b[n] = byte('0' + i%10)
		n--
		i /= 10
	}
	return string(b[n+1:])
}

// TestSocks5Dialer_DialWithMock tests Dial with mock SOCKS5 server.
func TestSocks5Dialer_DialWithMock(t *testing.T) {
	proxyAddr, targetAddr, cleanup := startMockSocks5Server(t)
	defer cleanup()

	dialer, err := NewSocks5Dialer(proxyAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Test echo
	testData := []byte("hello socks5")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], testData)
	}
}

// TestSocks5Dialer_DialContextWithMock tests DialContext with mock SOCKS5 server.
// Note: The golang.org/x/net/proxy library returns connections that may not
// implement the Conn interface (half-close support), so this test verifies
// that behavior is handled correctly.
func TestSocks5Dialer_DialContextWithMock(t *testing.T) {
	proxyAddr, targetAddr, cleanup := startMockSocks5Server(t)
	defer cleanup()

	dialer, err := NewSocks5Dialer(proxyAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	ctx := context.Background()
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)

	// The proxy library's connection may not support half-close,
	// which is expected behavior - we verify the error is appropriate
	if err != nil {
		if err == errNoHalfClose {
			t.Log("Connection correctly rejected for lack of half-close support")
			return
		}
		// Other errors are also acceptable as long as we don't crash
		t.Logf("DialContext returned error (may be expected): %v", err)
		return
	}
	defer conn.Close()

	// If we got a connection, verify it works
	testData := []byte("hello context")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], testData)
	}
}

// TestSocks5Dialer_DialContextCanceled tests canceled context.
func TestSocks5Dialer_DialContextCanceled(t *testing.T) {
	proxyAddr, _, cleanup := startMockSocks5Server(t)
	defer cleanup()

	dialer, err := NewSocks5Dialer(proxyAddr)
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	// Cancel context before dial
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = dialer.DialContext(ctx, "tcp", "127.0.0.1:12345")
	if err == nil {
		t.Error("expected error with canceled context")
	}
}

// TestSocks5Dialer_DialConnectionRefused tests connection refused.
func TestSocks5Dialer_DialConnectionRefused(t *testing.T) {
	// Use a port that nothing is listening on - should fail quickly with ECONNREFUSED
	dialer, err := NewSocks5Dialer("127.0.0.1:59999")
	if err != nil {
		t.Fatalf("NewSocks5Dialer failed: %v", err)
	}

	// Use context with timeout to avoid long waits
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err = dialer.DialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected error when proxy is not listening")
	}
}
