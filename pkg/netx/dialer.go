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
