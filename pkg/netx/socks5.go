package netx

import (
	"context"
	"net"

	"golang.org/x/net/proxy"
)

// Socks5Dialer wraps a SOCKS5 proxy dialer with socket tuning.
type Socks5Dialer struct {
	ProxyAddr string
	dialer    proxy.Dialer
}

// NewSocks5Dialer creates a new SOCKS5 dialer.
func NewSocks5Dialer(proxyAddr string) (*Socks5Dialer, error) {
	// Create SOCKS5 dialer with direct connection as forward dialer
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return &Socks5Dialer{
		ProxyAddr: proxyAddr,
		dialer:    dialer,
	}, nil
}

// Dial connects to the address via SOCKS5 proxy.
func (d *Socks5Dialer) Dial(network, address string) (Conn, error) {
	conn, err := d.dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Tune the connection if it's TCP
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := TuneConn(tcpConn); err != nil {
			conn.Close()
			return nil, err
		}
		return tcpConn, nil
	}

	return conn.(Conn), nil
}

// DialContext connects to the address via SOCKS5 proxy with context support.
func (d *Socks5Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
	// Check if dialer supports context
	if ctxDialer, ok := d.dialer.(proxy.ContextDialer); ok {
		conn, err := ctxDialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := TuneConn(tcpConn); err != nil {
				conn.Close()
				return nil, err
			}
			return tcpConn, nil
		}
		return conn.(Conn), nil
	}

	// Fallback to non-context dial
	return d.Dial(network, address)
}
