// Package netx provides high-performance networking primitives.
package netx

import (
	"net"
	"syscall"
	"time"
)

const (
	// TCPBufferSize is the socket buffer size for high throughput (512KB).
	TCPBufferSize = 512 * 1024

	// KeepAliveInterval for TCP keepalive probes.
	KeepAliveInterval = 30 * time.Second

	// LingerTimeout for graceful close.
	LingerTimeout = 3
)

// Conn wraps net.TCPConn with half-close support.
type Conn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
	SyscallConn() (syscall.RawConn, error)
}

// TuneConn applies high-performance socket options to a TCP connection.
func TuneConn(conn *net.TCPConn) error {
	// Disable Nagle's algorithm for lower latency
	if err := conn.SetNoDelay(true); err != nil {
		return err
	}

	// Enable keepalive
	if err := conn.SetKeepAlive(true); err != nil {
		return err
	}
	if err := conn.SetKeepAlivePeriod(KeepAliveInterval); err != nil {
		return err
	}

	// Set linger for graceful close
	if err := conn.SetLinger(LingerTimeout); err != nil {
		return err
	}

	// Get raw socket for advanced options
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		sockErr = tuneSocket(int(fd))
	})
	if err != nil {
		return err
	}

	return sockErr
}
