//go:build linux

package gproxy

import (
	"github.com/panjf2000/gnet/v2"
	"golang.org/x/sys/unix"
)

const serverHelloPacingSupported = true

func serverHelloSocketBusy(conn gnet.Conn) (bool, error) {
	if conn.OutboundBuffered() != 0 {
		return true, nil
	}
	info, err := unix.GetsockoptTCPInfo(conn.Fd(), unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		return false, err
	}
	return info.Notsent_bytes != 0, nil
}

// writeServerHelloChunk sends one paced chunk directly on the socket with
// MSG_EOR. Without it, Linux can merge unacknowledged small segments into one
// full-size segment when it retransmits them (tcp_retrans_try_collapse), and
// the client then sees the ServerHello in one packet. The caller runs on the
// connection owner and only writes when the gnet outbound buffer is empty, so
// the direct write keeps the byte order. EAGAIN means no progress; the pacer
// tries again on its next step.
func writeServerHelloChunk(conn gnet.Conn, chunk []byte) (int, error) {
	n, err := unix.SendmsgN(conn.Fd(), chunk, nil, nil, unix.MSG_EOR)
	if err == unix.EAGAIN || err == unix.EINTR {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}
