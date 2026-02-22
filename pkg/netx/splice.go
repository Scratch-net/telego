package netx

import (
	"io"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// Pipe represents a kernel pipe used for splice operations.
type Pipe struct {
	r, w int // read and write file descriptors
}

// pipePool reuses pipes to avoid syscall overhead.
var pipePool = sync.Pool{
	New: func() any {
		fds := make([]int, 2)
		// Use O_NONBLOCK for non-blocking splice
		if err := unix.Pipe2(fds, unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
			return nil
		}
		// Set large pipe buffer (1MB if allowed by system)
		// F_SETPIPE_SZ = 1031 on Linux
		unix.SyscallNoError(unix.SYS_FCNTL, uintptr(fds[0]), 1031, 1024*1024)
		return &Pipe{r: fds[0], w: fds[1]}
	},
}

func acquirePipe() *Pipe {
	p := pipePool.Get()
	if p == nil {
		return nil
	}
	return p.(*Pipe)
}

func releasePipe(p *Pipe) {
	if p != nil {
		pipePool.Put(p)
	}
}

// SpliceRelay performs zero-copy bidirectional relay using splice(2).
// Falls back to userspace copy if splice is not available.
func SpliceRelay(client, server Conn) error {
	done := make(chan error, 2)

	go func() {
		done <- splicePump(server, client) // client -> server
	}()

	err1 := splicePump(client, server) // server -> client
	err2 := <-done

	// Return first non-nil error, preferring non-EOF
	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}

// splicePump moves data from src to dst using splice(2) if possible.
func splicePump(dst, src Conn) error {
	defer dst.CloseWrite()
	defer src.CloseRead()

	// Try to get raw file descriptors for splice
	srcRaw, err := src.SyscallConn()
	if err != nil {
		return copyPump(dst, src)
	}
	dstRaw, err := dst.SyscallConn()
	if err != nil {
		return copyPump(dst, src)
	}

	var srcFD, dstFD int
	srcRaw.Control(func(fd uintptr) { srcFD = int(fd) })
	dstRaw.Control(func(fd uintptr) { dstFD = int(fd) })

	// Get a pipe from pool
	pipe := acquirePipe()
	if pipe == nil {
		return copyPump(dst, src)
	}
	defer releasePipe(pipe)

	return doSplice(srcFD, dstFD, pipe)
}

// doSplice performs the actual splice loop.
func doSplice(srcFD, dstFD int, pipe *Pipe) error {
	const maxSplice = 64 * 1024 // Max bytes per splice call

	for {
		// Splice from source socket to pipe (non-blocking read side)
		n, err := unix.Splice(srcFD, nil, pipe.w, nil, maxSplice, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
		if err != nil {
			if err == unix.EAGAIN {
				// Would block, wait for data
				if err := waitRead(srcFD); err != nil {
					return err
				}
				continue
			}
			if err == unix.EPIPE || err == unix.ECONNRESET {
				return io.EOF
			}
			return err
		}
		if n == 0 {
			return io.EOF
		}

		// Splice from pipe to destination socket
		for written := int64(0); written < n; {
			m, err := unix.Splice(pipe.r, nil, dstFD, nil, int(n-written), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if err != nil {
				if err == unix.EAGAIN {
					if err := waitWrite(dstFD); err != nil {
						return err
					}
					continue
				}
				if err == unix.EPIPE || err == unix.ECONNRESET {
					return io.EOF
				}
				return err
			}
			written += m
		}
	}
}

// waitRead waits for fd to become readable using poll.
func waitRead(fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n > 0 {
			if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return io.EOF
			}
			return nil
		}
	}
}

// waitWrite waits for fd to become writable using poll.
func waitWrite(fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	for {
		n, err := unix.Poll(fds, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n > 0 {
			if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return io.EOF
			}
			return nil
		}
	}
}

// copyPool provides reusable buffers for userspace copy fallback.
var copyPool = sync.Pool{
	New: func() any {
		buf := make([]byte, CopyBufferSize)
		return &buf
	},
}

// copyPump is the fallback when splice is not available.
func copyPump(dst io.Writer, src io.Reader) error {
	buf := copyPool.Get().(*[]byte)
	defer copyPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, *buf)
	return err
}

// Relay performs bidirectional relay, preferring splice on Linux.
// This is the main entry point for connection relaying.
func Relay(client, server net.Conn) error {
	// Check if both connections support the Conn interface
	clientConn, ok1 := client.(Conn)
	serverConn, ok2 := server.(Conn)

	if ok1 && ok2 {
		return SpliceRelay(clientConn, serverConn)
	}

	// Fallback to userspace copy
	return userspacRelay(client, server)
}

func userspacRelay(client, server net.Conn) error {
	done := make(chan error, 2)

	go func() {
		buf := copyPool.Get().(*[]byte)
		_, err := io.CopyBuffer(server, client, *buf)
		copyPool.Put(buf)
		if tcpConn, ok := server.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- err
	}()

	buf := copyPool.Get().(*[]byte)
	_, err1 := io.CopyBuffer(client, server, *buf)
	copyPool.Put(buf)
	if tcpConn, ok := client.(*net.TCPConn); ok {
		tcpConn.CloseWrite()
	}

	err2 := <-done

	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}
