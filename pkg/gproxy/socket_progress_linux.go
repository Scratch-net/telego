//go:build linux

package gproxy

import "golang.org/x/sys/unix"

// socketAckedBytes reads the bytes the peer has acknowledged on a TCP socket.
// It reads TCP_INFO and sets no socket option. A stall check counts an
// increase as delivery that the userspace backlog cannot show.
func socketAckedBytes(endpoint clientEndpoint) (uint64, bool) {
	conn, ok := endpoint.(interface{ Fd() int })
	if !ok {
		return 0, false
	}
	info, err := unix.GetsockoptTCPInfo(conn.Fd(), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return 0, false
	}
	return info.Bytes_acked, true
}
