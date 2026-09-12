//go:build linux

package middleend

import (
	"errors"
	"time"

	"github.com/panjf2000/gnet/v2"
	"golang.org/x/sys/unix"
)

// captureOwnerSocket runs only inside OnClose while gnet still owns the fd.
// Do not query SO_ERROR: reading it consumes the socket's pending error.
func captureOwnerSocket(conn gnet.Conn) LinkSocketSnapshot {
	snapshot := LinkSocketSnapshot{Status: LinkSocketUnavailable, At: time.Now()}
	if conn == nil {
		return snapshot
	}
	fd := conn.Fd()
	if fd < 0 {
		return snapshot
	}
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil {
		snapshot.Status = LinkSocketError
		if errno, ok := errors.AsType[unix.Errno](err); ok {
			snapshot.Errno = uint64(errno)
		}
		return snapshot
	}
	snapshot.Status = LinkSocketAvailable
	snapshot.State, snapshot.Unacked, snapshot.Lost = info.State, info.Unacked, info.Lost
	snapshot.Retrans, snapshot.TotalRetrans = info.Retrans, info.Total_retrans
	snapshot.RTTMicroseconds, snapshot.RTTVarMicroseconds = info.Rtt, info.Rttvar
	snapshot.SendCongestionWindow = info.Snd_cwnd
	return snapshot
}
