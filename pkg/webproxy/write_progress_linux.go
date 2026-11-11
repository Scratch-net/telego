//go:build linux

package webproxy

import (
	"github.com/panjf2000/gnet/v2"
	"golang.org/x/sys/unix"
)

// socketBytesAcked reads the bytes that the peer acknowledged on the socket.
// It must run on the connection's event loop while the connection is open,
// so that Fd still names this connection's socket.
func socketBytesAcked(connection gnet.Conn) (uint64, bool) {
	info, err := unix.GetsockoptTCPInfo(connection.Fd(), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return 0, false
	}
	return info.Bytes_acked, true
}
