// Package netx provides high-performance networking primitives.
package netx

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// TCPBufferSize is the socket buffer size for high throughput.
	// 256KB per direction = 512KB total per connection.
	TCPBufferSize = 256 * 1024

	// CopyBufferSize for userspace relay when splice unavailable.
	CopyBufferSize = 256 * 1024

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
// This is critical for throughput - mtg ignores buffer sizing entirely.
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

// tuneSocket sets low-level socket options for performance.
func tuneSocket(fd int) error {
	// SO_REUSEADDR and SO_REUSEPORT for fast restarts and load balancing
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return err
	}

	// Large socket buffers for high throughput
	// This is THE critical difference from mtg which ignores buffer sizing
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, TCPBufferSize); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, TCPBufferSize); err != nil {
		return err
	}

	// TCP_QUICKACK to disable delayed ACKs (Linux-specific)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)

	return nil
}

// TuneListener applies socket options to a listener socket.
func TuneListener(ln *net.TCPListener) error {
	rawConn, err := ln.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		// SO_REUSEADDR and SO_REUSEPORT
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockErr = err
			return
		}
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			sockErr = err
			return
		}

		// Increase listen backlog via TCP_FASTOPEN (Linux 3.7+)
		// Allows data in SYN packet
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 256)
	})
	if err != nil {
		return err
	}

	return sockErr
}
