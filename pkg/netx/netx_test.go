package netx

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestNewDialer tests dialer creation with defaults.
func TestNewDialer(t *testing.T) {
	dialer := NewDialer()

	if dialer == nil {
		t.Fatal("NewDialer returned nil")
	}

	if dialer.Timeout != DialTimeout {
		t.Errorf("Timeout: got %v, want %v", dialer.Timeout, DialTimeout)
	}

	if dialer.KeepAlive != KeepAliveInterval {
		t.Errorf("KeepAlive: got %v, want %v", dialer.KeepAlive, KeepAliveInterval)
	}
}

// TestDialer_Dial tests connecting to localhost.
func TestDialer_Dial(t *testing.T) {
	// Start a local listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Accept connections in background
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	// Test dial
	dialer := NewDialer()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Verify connection
	if conn == nil {
		t.Error("Dial returned nil connection")
	}

	// Verify the connection type is correct (Dial returns Conn)
	if conn.LocalAddr() == nil {
		t.Error("Connection should have a local address")
	}
}

// TestDialer_DialContext_Timeout tests context cancellation.
func TestDialer_DialContext_Timeout(t *testing.T) {
	dialer := NewDialer()

	// Use a non-routable IP to ensure timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should fail due to timeout (10.255.255.1 is non-routable)
	_, err := dialer.DialContext(ctx, "tcp", "10.255.255.1:443")
	if err == nil {
		t.Error("expected error for timeout/non-routable address")
	}

	// The error should be context-related or connection timeout
	t.Logf("Dial error (expected): %v", err)
}

// TestDialer_DialContext_Cancelled tests immediate cancellation.
func TestDialer_DialContext_Cancelled(t *testing.T) {
	dialer := NewDialer()

	// Pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:1234")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// TestConstants tests network constants.
func TestConstants(t *testing.T) {
	if TCPBufferSize != 512*1024 {
		t.Errorf("TCPBufferSize: got %d, want %d", TCPBufferSize, 512*1024)
	}

	if KeepAliveInterval != 30*time.Second {
		t.Errorf("KeepAliveInterval: got %v, want 30s", KeepAliveInterval)
	}

	if LingerTimeout != 3 {
		t.Errorf("LingerTimeout: got %d, want 3", LingerTimeout)
	}

	if DialTimeout != 10*time.Second {
		t.Errorf("DialTimeout: got %v, want 10s", DialTimeout)
	}
}

// TestTuneConn tests socket tuning.
func TestTuneConn(t *testing.T) {
	// Create a real TCP connection to test tuning
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Accept in background
	connChan := make(chan net.Conn)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		connChan <- conn
	}()

	// Connect
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Get server side connection
	serverConn := <-connChan
	defer serverConn.Close()

	// Test TuneConn on the client connection
	tcpConn := conn.(*net.TCPConn)
	err = TuneConn(tcpConn)
	if err != nil {
		t.Errorf("TuneConn failed: %v", err)
	}

	// Connection should still work after tuning
	_, err = conn.Write([]byte("test"))
	if err != nil {
		t.Errorf("Write after TuneConn failed: %v", err)
	}
}

// TestConn_Interface tests that *net.TCPConn satisfies Conn interface.
func TestConn_Interface(t *testing.T) {
	// The Conn interface extends net.Conn with CloseRead, CloseWrite, SyscallConn
	// *net.TCPConn should satisfy this

	// Create listener and connection
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

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	tcpConn := conn.(*net.TCPConn)

	// Verify interface compliance
	var _ Conn = tcpConn // This line verifies *net.TCPConn satisfies Conn

	// Test CloseRead (may not work on all platforms before actual use)
	// Test CloseWrite
	// Test SyscallConn
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		t.Logf("SyscallConn: %v (may be expected on some platforms)", err)
	} else if rawConn == nil {
		t.Error("SyscallConn returned nil")
	}
}

// TestDialer_DialToLocalhost tests successful local connection.
func TestDialer_DialToLocalhost(t *testing.T) {
	// Start echo server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Handle one connection
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo back
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	// Connect and test
	dialer := NewDialer()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send data
	testData := []byte("hello netx")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read response
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Echo mismatch: got %q, want %q", buf[:n], testData)
	}

	<-done
}

// TestDialer_CustomTimeout tests custom timeout setting.
func TestDialer_CustomTimeout(t *testing.T) {
	dialer := NewDialer()
	dialer.Timeout = 50 * time.Millisecond

	// Use non-routable address
	_, err := dialer.Dial("tcp", "10.255.255.1:443")
	if err == nil {
		t.Error("expected timeout error")
	}
}

// TestDialer_CustomKeepAlive tests custom keepalive setting.
func TestDialer_CustomKeepAlive(t *testing.T) {
	dialer := NewDialer()
	dialer.KeepAlive = 1 * time.Minute

	if dialer.KeepAlive != 1*time.Minute {
		t.Errorf("KeepAlive not set: got %v", dialer.KeepAlive)
	}

	// Actually connecting would test the keepalive is applied
	// but we can't easily verify the socket option was set
}

// TestDialer_NetworkTypes tests different network types.
func TestDialer_NetworkTypes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	dialer := NewDialer()

	// Test with "tcp" network
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial with 'tcp' failed: %v", err)
	}
	conn.Close()

	// Test with "tcp4" network
	conn, err = dialer.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("Dial with 'tcp4' failed: %v", err)
	}
	conn.Close()
}
