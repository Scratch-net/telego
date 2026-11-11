// Copyright (c) 2021 The Gnet Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

// Telego local modification: explicit accept ownership, pending TCP error recovery,
// and accept backoff on resource exhaustion. See TELEGO.md.
package gnet

import (
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/panjf2000/gnet/v2/pkg/errors"
	"github.com/panjf2000/gnet/v2/pkg/netpoll"
	"github.com/panjf2000/gnet/v2/pkg/queue"
	"github.com/panjf2000/gnet/v2/pkg/socket"
)

func (el *eventloop) accept0(fd int, _ netpoll.IOEvent, _ netpoll.IOFlags) error {
	for {
		nfd, sa, err := socket.Accept(fd)
		switch err {
		case nil:
			el.listeners[fd].acceptPause = 0 // Telego: end the backoff episode.
		case unix.EAGAIN: // the Accept queue has been drained out, we can return now
			return nil
		case unix.EINTR, unix.ECONNRESET, unix.ECONNABORTED:
			// ECONNRESET or ECONNABORTED could indicate that a socket
			// in the Accept queue was closed before we Accept()ed it.
			// It's a silly error, let's retry it.
			continue
		default:
			if isPendingTCPAcceptError(el.listeners[fd].network, err) {
				if el.engine.isStopping() {
					return errors.ErrEngineShutdown
				}
				continue
			}
			if isResourceAcceptError(err) {
				return el.pauseAccept(el.listeners[fd], err, true)
			}
			el.getLogger().Errorf("Accept() failed due to error: %v", err)
			return errors.ErrAcceptSocket
		}

		remoteAddr := socket.SockaddrToTCPOrUnixAddr(sa)
		network := el.listeners[fd].network
		if opts := el.engine.opts; opts.TCPKeepAlive > 0 && network == "tcp" &&
			(runtime.GOOS != "linux" && runtime.GOOS != "freebsd" && runtime.GOOS != "dragonfly") {
			// TCP keepalive options are not inherited from the listening socket
			// on platforms other than Linux, FreeBSD, or DragonFlyBSD.
			// We therefore need to set them on the accepted socket explicitly.
			//
			// Check out https://github.com/nginx/nginx/pull/337 for details.
			if err = setKeepAlive(
				nfd,
				true,
				opts.TCPKeepAlive,
				opts.TCPKeepInterval,
				opts.TCPKeepCount); err != nil {
				el.getLogger().Errorf("failed to set TCP keepalive on fd=%d: %v", fd, err)
			}
		}

		el := el.engine.eventLoops.next(remoteAddr)
		c := newStreamConn(network, nfd, el, sa, el.listeners[fd].addr, remoteAddr)
		_, err = el.submitRegistration(c, queue.HighPriority)
		if err != nil {
			el.getLogger().Errorf("failed to enqueue the accepted socket fd=%d to poller: %v", c.fd, err)
		}
	}
}

func (el *eventloop) accept(fd int, ev netpoll.IOEvent, flags netpoll.IOFlags) error {
	network := el.listeners[fd].network
	if network == "udp" {
		return el.readUDP(fd, ev, flags)
	}

	nfd, sa, err := socket.Accept(fd)
	switch err {
	case nil:
		el.listeners[fd].acceptPause = 0 // Telego: end the backoff episode.
	case unix.EINTR, unix.EAGAIN, unix.ECONNRESET, unix.ECONNABORTED:
		// ECONNRESET or ECONNABORTED could indicate that a socket
		// in the Accept queue was closed before we Accept()ed it.
		// It's a silly error, let's retry it.
		return nil
	default:
		if isPendingTCPAcceptError(network, err) {
			if el.engine.isStopping() {
				return errors.ErrEngineShutdown
			}
			return nil
		}
		if isResourceAcceptError(err) {
			return el.pauseAccept(el.listeners[fd], err, false)
		}
		el.getLogger().Errorf("Accept() failed due to error: %v", err)
		return errors.ErrAcceptSocket
	}

	remoteAddr := socket.SockaddrToTCPOrUnixAddr(sa)
	if opts := el.engine.opts; opts.TCPKeepAlive > 0 && el.listeners[fd].network == "tcp" &&
		(runtime.GOOS != "linux" && runtime.GOOS != "freebsd" && runtime.GOOS != "dragonfly") {
		// TCP keepalive options are not inherited from the listening socket
		// on platforms other than Linux, FreeBSD, or DragonFlyBSD.
		// We therefore need to set them on the accepted socket explicitly.
		//
		// Check out https://github.com/nginx/nginx/pull/337 for details.
		if err = setKeepAlive(
			nfd,
			true,
			opts.TCPKeepAlive,
			opts.TCPKeepInterval,
			opts.TCPKeepCount); err != nil {
			el.getLogger().Errorf("failed to set TCP keepalive on fd=%d: %v", fd, err)
		}
	}

	c := newStreamConn(network, nfd, el, sa, el.listeners[fd].addr, remoteAddr)
	return el.register0(c)
}

// Telego: accept backoff on resource exhaustion; see TELEGO.md.
const (
	acceptPauseMin = 5 * time.Millisecond
	acceptPauseMax = time.Second
)

// isResourceAcceptError identifies accept errors caused by descriptor or
// memory exhaustion. The listener remains usable once resources are released.
func isResourceAcceptError(err error) bool {
	switch err {
	case unix.EMFILE, unix.ENFILE, unix.ENOBUFS, unix.ENOMEM:
		return true
	default:
		return false
	}
}

// pauseAccept disables listener readiness and re-enables it after a backoff
// that starts at 5ms and doubles up to 1s. The event loop keeps serving its
// connections and shutdown tasks while the listener is paused.
func (el *eventloop) pauseAccept(ln *listener, err error, edgeTriggered bool) error {
	ln.acceptPause = min(max(2*ln.acceptPause, acceptPauseMin), acceptPauseMax)
	if now := time.Now(); now.Sub(ln.acceptPauseLogged) >= time.Second {
		ln.acceptPauseLogged = now
		el.getLogger().Errorf("Accept() failed due to resource exhaustion: %v; retrying in %v", err, ln.acceptPause)
	}
	if err = el.poller.ModReadPaused(ln.pollAttachment, true, false, edgeTriggered); err != nil {
		el.getLogger().Errorf("failed to pause listener fd=%d: %v", ln.fd, err)
		return errors.ErrAcceptSocket
	}
	time.AfterFunc(ln.acceptPause, func() {
		// Trigger fails only after the poller closes during engine shutdown.
		_ = el.poller.Trigger(queue.HighPriority, func(any) error {
			return el.resumeAccept(ln, edgeTriggered)
		}, nil)
	})
	return nil
}

// resumeAccept runs on the listener owner. It restores readiness and then
// accepts directly. Linux EPOLL_CTL_MOD also reports a listener that is
// already readable; the direct accept does not depend on that behavior of
// each poller, and an empty backlog returns EAGAIN.
func (el *eventloop) resumeAccept(ln *listener, edgeTriggered bool) error {
	if el.engine.isStopping() {
		return nil
	}
	err := el.poller.ModReadPaused(ln.pollAttachment, false, false, edgeTriggered)
	if err == nil {
		err = ln.pollAttachment.Callback(ln.fd, 0, 0)
	} else {
		el.getLogger().Errorf("failed to resume listener fd=%d: %v", ln.fd, err)
		err = errors.ErrAcceptSocket
	}
	if err == errors.ErrAcceptSocket {
		// Task errors do not stop the poller; keep permanent errors fatal.
		el.engine.shutdown(err)
		return errors.ErrEngineShutdown
	}
	return err
}
