package middleend

import (
	"context"
	"net"
	"time"

	"github.com/example/telego/pkg/netx"
)

// Dialer dials connections to ME servers.
type Dialer struct {
	netDialer *netx.Dialer
	timeout   time.Duration
}

// NewDialer creates a new ME dialer.
func NewDialer() *Dialer {
	return &Dialer{
		netDialer: netx.NewDialer(),
		timeout:   15 * time.Second,
	}
}

// DialME connects to an ME server and performs the handshake.
func (d *Dialer) DialME(ctx context.Context, addr string, secret []byte, publicIP string) (*MEConn, error) {
	// Add timeout to context
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Dial TCP connection
	conn, err := d.netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// Perform ME handshake
	meConn, err := MEHandshake(conn, secret, []byte(publicIP))
	if err != nil {
		conn.Close()
		return nil, err
	}

	return meConn, nil
}

// DialMEWithConn performs ME handshake on an existing connection.
func (d *Dialer) DialMEWithConn(conn net.Conn, secret []byte, publicIP string) (*MEConn, error) {
	return MEHandshake(conn, secret, []byte(publicIP))
}
