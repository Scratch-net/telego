// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.
// This fixture is compiled only by dist/test-gnet-accept.py's source overlay.

//go:build linux

package gnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	errorx "github.com/panjf2000/gnet/v2/pkg/errors"
	"github.com/panjf2000/gnet/v2/pkg/socket"
	"golang.org/x/sys/unix"
)

type acceptFaultBoot struct {
	engine  Engine
	address string
	err     error
}

type acceptFaultEvents struct {
	BuiltinEventEngine
	boot      chan acceptFaultBoot
	begin     <-chan struct{}
	opened    atomic.Int32
	shutdowns atomic.Int32
}

func (h *acceptFaultEvents) OnBoot(e Engine) Action {
	for _, ln := range e.eng.listeners {
		address, err := unix.Getsockname(ln.fd)
		if err != nil {
			h.boot <- acceptFaultBoot{engine: e, err: err}
			return Shutdown
		}
		h.boot <- acceptFaultBoot{engine: e, address: socket.SockaddrToTCPOrUnixAddr(address).String()}
		break
	}
	<-h.begin
	return None
}

func (h *acceptFaultEvents) OnOpen(Conn) ([]byte, Action) {
	h.opened.Add(1)
	return []byte("accepted"), None
}

func (h *acceptFaultEvents) OnTraffic(c Conn) Action {
	data, err := c.Next(-1)
	if err != nil {
		return Close
	}
	if _, err = c.Write(data); err != nil {
		return Close
	}
	return None
}

func (h *acceptFaultEvents) OnShutdown(Engine) { h.shutdowns.Add(1) }

type acceptFaultServer struct {
	boot      acceptFaultBoot
	events    *acceptFaultEvents
	done      chan struct{}
	result    error
	begin     chan struct{}
	beginOnce sync.Once
}

func (s *acceptFaultServer) beginAccepting() {
	s.beginOnce.Do(func() { close(s.begin) })
}

func startAcceptFaultServer(t *testing.T, reuse bool, hook func(int) (int, unix.Sockaddr, error)) *acceptFaultServer {
	t.Helper()
	socket.TelegoAcceptTestHook = hook
	begin := make(chan struct{})
	h := &acceptFaultEvents{boot: make(chan acceptFaultBoot, 1), begin: begin}
	s := &acceptFaultServer{events: h, done: make(chan struct{}), begin: begin}
	go func() {
		s.result = Run(h, "tcp://127.0.0.1:0", WithNumEventLoop(1), WithReusePort(reuse))
		close(s.done)
	}()
	select {
	case s.boot = <-h.boot:
		if s.boot.err != nil {
			<-s.done
			socket.TelegoAcceptTestHook = nil
			t.Fatal(s.boot.err)
		}
	case <-s.done:
		socket.TelegoAcceptTestHook = nil
		t.Fatalf("server failed before boot: %v", s.result)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not boot")
	}
	t.Cleanup(func() {
		s.beginAccepting()
		if !s.boot.engine.eng.isShutdown() {
			s.boot.engine.eng.shutdown(nil)
		}
		select {
		case <-s.done:
			socket.TelegoAcceptTestHook = nil
		case <-time.After(3 * time.Second):
			panic("accept fault server did not join before hook retirement")
		}
		if h.shutdowns.Load() != 1 {
			t.Errorf("shutdown callbacks=%d; want one", h.shutdowns.Load())
		}
	})
	return s
}

func (s *acceptFaultServer) connect(t *testing.T, accepted bool) net.Conn {
	t.Helper()
	connection, err := net.DialTimeout("tcp", s.boot.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	// Complete the first TCP connect before allowing the acceptor to run.
	// A fatal injected error must not race the client's connect completion.
	s.beginAccepting()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if accepted {
		var greeting [8]byte
		if _, err := io.ReadFull(connection, greeting[:]); err != nil || string(greeting[:]) != "accepted" {
			t.Fatalf("queued client was not accepted: greeting=%q err=%v", greeting, err)
		}
	}
	return connection
}

func TestTelegoAcceptPendingErrorsRecoverQueuedClient(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		for _, errno := range []unix.Errno{unix.ENETDOWN, unix.EPROTO, unix.ENOPROTOOPT, unix.EHOSTDOWN, unix.ENONET, unix.EHOSTUNREACH, unix.EOPNOTSUPP, unix.ENETUNREACH} {
			t.Run(fmt.Sprintf("reuseport=%t/%s", reuse, errno.Error()), func(t *testing.T) {
				var calls atomic.Int32
				s := startAcceptFaultServer(t, reuse, func(fd int) (int, unix.Sockaddr, error) {
					if calls.Add(1) == 1 {
						return -1, nil, errno
					}
					return unix.Accept4(fd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
				})
				// One arrival only: ET recovery must drain the existing backlog.
				s.connect(t, true)
				if calls.Load() < 2 || s.events.opened.Load() != 1 {
					t.Fatal("pending error did not lead to exactly one admitted client")
				}
			})
		}
	}
}

func TestTelegoAcceptResourceAndPermanentErrorsRemainFatal(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		for _, errno := range []unix.Errno{unix.EMFILE, unix.ENFILE, unix.ENOBUFS, unix.ENOMEM, unix.EBADF, unix.EINVAL, unix.ENOTSOCK, unix.EIO} {
			t.Run(fmt.Sprintf("reuseport=%t/%s", reuse, errno.Error()), func(t *testing.T) {
				s := startAcceptFaultServer(t, reuse, func(int) (int, unix.Sockaddr, error) { return -1, nil, errno })
				connection := s.connect(t, false)
				select {
				case <-s.done:
				case <-time.After(2 * time.Second):
					t.Fatal("fatal accept error did not terminate engine")
				}
				// Run currently logs reactor failures during deferred shutdown;
				// the reactor group retains the actual terminal cause.
				if err := s.boot.engine.eng.concurrency.Wait(); !errors.Is(err, errorx.ErrAcceptSocket) {
					t.Fatalf("reactor error=%v; want ErrAcceptSocket", err)
				}
				if s.events.opened.Load() != 0 {
					t.Fatal("fatal accept error admitted a client")
				}
				var buffer [1]byte
				if n, err := connection.Read(buffer[:]); n != 0 || !errors.Is(err, io.EOF) && !errors.Is(err, unix.ECONNRESET) {
					t.Fatalf("failed listener peer remained usable: n=%d err=%v", n, err)
				}
			})
		}
	}
}

func TestTelegoAcceptPendingErrorDoesNotInterruptActiveClient(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuseport=%t", reuse), func(t *testing.T) {
			var inject atomic.Bool
			s := startAcceptFaultServer(t, reuse, func(fd int) (int, unix.Sockaddr, error) {
				if inject.Swap(false) {
					return -1, nil, unix.EPROTO
				}
				return unix.Accept4(fd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
			})
			active := s.connect(t, true)
			inject.Store(true)
			s.connect(t, true)
			const message = "still-connected"
			if _, err := io.WriteString(active, message); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(message))
			if _, err := io.ReadFull(active, got); err != nil || string(got) != message {
				t.Fatalf("active client lost relay progress: reply=%q err=%v", got, err)
			}
		})
	}
}

func TestTelegoAcceptPendingErrorStormStops(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuseport=%t", reuse), func(t *testing.T) {
			var release atomic.Bool
			entered := make(chan struct{})
			var once sync.Once
			s := startAcceptFaultServer(t, reuse, func(int) (int, unix.Sockaddr, error) {
				once.Do(func() { close(entered) })
				if release.Load() {
					return -1, nil, unix.EAGAIN
				}
				return -1, nil, unix.EPROTO
			})
			// Release before server cleanup if Stop fails, so the old draining
			// behavior can unwind instead of stranding the test process.
			t.Cleanup(func() { release.Store(true) })
			s.connect(t, false)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("error storm did not start")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if err := s.boot.engine.Stop(ctx); err != nil {
				t.Fatalf("Stop during pending errors: %v", err)
			}
			select {
			case <-s.done:
			case <-time.After(time.Second):
				t.Fatal("Run did not join after Stop")
			}
		})
	}
}
