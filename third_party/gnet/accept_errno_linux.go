// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.
// Telego local modification: recover failed pending TCP connections. See TELEGO.md.

package gnet

import "golang.org/x/sys/unix"

// isPendingTCPAcceptError identifies errors Linux accept4 passes through from
// the pending TCP connection. The listener remains usable; accept(2) requires
// retrying these like EAGAIN. Resource exhaustion backs off; listener errors stay fatal.
func isPendingTCPAcceptError(network string, err error) bool {
	if network != "tcp" {
		return false
	}
	// socket.Accept returns the syscall errno directly, as in the caller's switch.
	switch err {
	case unix.ENETDOWN, unix.EPROTO, unix.ENOPROTOOPT, unix.EHOSTDOWN,
		unix.ENONET, unix.EHOSTUNREACH, unix.EOPNOTSUPP, unix.ENETUNREACH:
		return true
	default:
		return false
	}
}
