//go:build !linux

package netx

import "golang.org/x/sys/unix"

// tuneSocket sets low-level socket options for performance.
func tuneSocket(fd int) error {
	// SO_REUSEADDR and SO_REUSEPORT for fast restarts and load balancing
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return err
	}

	// Large socket buffers for high throughput
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, TCPBufferSize); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, TCPBufferSize); err != nil {
		return err
	}

	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	return nil
}
