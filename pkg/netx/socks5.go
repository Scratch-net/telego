package netx

import (
	"context"
	"errors"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

// DialWithConn keeps ownership of the raw socket with us. The contextual Dial
// method in x/net wraps it in a connection without SyscallConn or half-close.
type socks5Connector interface {
	DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
}

// Socks5Dialer wraps a SOCKS5 proxy dialer with socket tuning.
type Socks5Dialer struct {
	ProxyAddr string
	dialer    socks5Connector
}

// NewSocks5Dialer creates a new SOCKS5 dialer.
func NewSocks5Dialer(proxyAddr string) (*Socks5Dialer, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	connector, ok := dialer.(socks5Connector)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not support contextual handshakes")
	}
	return &Socks5Dialer{ProxyAddr: proxyAddr, dialer: connector}, nil
}

// Dial connects to the address via SOCKS5 proxy.
func (d *Socks5Dialer) Dial(network, address string) (Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address via SOCKS5 proxy with context support.
func (d *Socks5Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
	if ctx == nil {
		return nil, errors.New("nil context")
	}
	// Bound both TCP establishment and the SOCKS greeting/CONNECT exchange.
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()

	conn, err := NewDialer().DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, err
	}
	_, err = d.dialer.DialWithConn(ctx, conn, network, address)
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	} else if err != nil {
		// The socket deadline and context timer can fire in either order.
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= 0 {
			err = context.DeadlineExceeded
		}
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
