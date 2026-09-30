//go:build linux

package netx

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTuneConnPreservesBackgroundClose(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connection, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	conn := connection.(*net.TCPConn)
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	checkOptions := func(tuned bool) {
		t.Helper()
		var socketErr error
		var linger *unix.Linger
		values := make([]int, 5)
		options := [...]struct {
			level int
			name  int
			want  int
		}{
			{unix.IPPROTO_TCP, unix.TCP_NODELAY, 1},
			{unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1},
			{unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, int(KeepAliveInterval / time.Second)},
			{unix.SOL_SOCKET, unix.SO_REUSEADDR, 1},
			{unix.SOL_SOCKET, unix.SO_REUSEPORT, 1},
		}
		if err := raw.Control(func(fd uintptr) {
			linger, socketErr = unix.GetsockoptLinger(int(fd), unix.SOL_SOCKET, unix.SO_LINGER)
			if socketErr != nil || !tuned {
				return
			}
			for i, option := range options {
				values[i], socketErr = unix.GetsockoptInt(int(fd), option.level, option.name)
				if socketErr != nil {
					return
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
		if socketErr != nil {
			t.Fatal(socketErr)
		}
		if linger.Onoff != 0 {
			t.Errorf("SO_LINGER after tuning=%t: enabled=%d timeout=%d; want disabled background close", tuned, linger.Onoff, linger.Linger)
		}
		if tuned {
			for i, option := range options {
				if values[i] != option.want {
					t.Errorf("socket option level=%d name=%d: got %d, want %d", option.level, option.name, values[i], option.want)
				}
			}
		}
	}
	checkOptions(false)
	if err := conn.SetNoDelay(false); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetKeepAlive(false); err != nil {
		t.Fatal(err)
	}
	// Direct DC setup can tune a connection already tuned by netx.Dialer.
	for range 2 {
		if err := TuneConn(conn); err != nil {
			t.Fatal(err)
		}
		checkOptions(true)
	}
}
