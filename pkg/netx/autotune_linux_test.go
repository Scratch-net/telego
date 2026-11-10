//go:build linux

package netx

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestTuneSocketPreservesKernelAndCallerBufferSizes(t *testing.T) {
	for _, requested := range []int{0, 8192} {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		options := []int{unix.SO_RCVBUF, unix.SO_SNDBUF}
		before := make([]int, len(options))
		for i, option := range options {
			if requested != 0 {
				if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, option, requested); err != nil {
					t.Fatal(err)
				}
			}
			before[i], err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
			if err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			if err := tuneSocket(fd); err != nil {
				t.Fatal(err)
			}
			for i, option := range options {
				after, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option)
				if err != nil {
					t.Fatal(err)
				}
				if after != before[i] {
					t.Errorf("requested=%d option=%d: %d became %d", requested, option, before[i], after)
				}
			}
		}
	}
}
