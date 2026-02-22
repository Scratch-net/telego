package netx

import (
	"context"
	"net"
	"syscall"
	"time"
)

// DialTimeout is the default timeout for establishing connections.
const DialTimeout = 10 * time.Second

// Dialer provides high-performance TCP dialing with proper socket tuning.
type Dialer struct {
	Timeout   time.Duration
	KeepAlive time.Duration
}

// NewDialer creates a new high-performance dialer.
func NewDialer() *Dialer {
	return &Dialer{
		Timeout:   DialTimeout,
		KeepAlive: KeepAliveInterval,
	}
}

// Dial connects to the address on the named network.
func (d *Dialer) Dial(network, address string) (Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address with context support.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
	dialer := &net.Dialer{
		Timeout:   d.Timeout,
		KeepAlive: d.KeepAlive,
		Control:   dialControl,
	}

	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	tcpConn := conn.(*net.TCPConn)
	if err := TuneConn(tcpConn); err != nil {
		conn.Close()
		return nil, err
	}

	return tcpConn, nil
}

// dialControl is called before the socket is bound.
// This allows setting socket options before connect().
func dialControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = tuneSocket(int(fd))
	})
	if err != nil {
		return err
	}
	return sockErr
}

// Listen creates a high-performance TCP listener.
func Listen(network, address string) (*net.TCPListener, error) {
	lc := net.ListenConfig{
		Control: listenControl,
	}

	ln, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	tcpLn := ln.(*net.TCPListener)
	if err := TuneListener(tcpLn); err != nil {
		ln.Close()
		return nil, err
	}

	return tcpLn, nil
}

// listenControl sets socket options before bind().
func listenControl(network, address string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		// SO_REUSEADDR and SO_REUSEPORT before bind
		sockErr = tuneSocket(int(fd))
	})
	if err != nil {
		return err
	}
	return sockErr
}

// Accept accepts a connection and tunes it for high performance.
func Accept(ln *net.TCPListener) (Conn, error) {
	conn, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}

	if err := TuneConn(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
