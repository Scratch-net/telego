// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.

package gnet

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTelegoPendingTCPAcceptErrors(t *testing.T) {
	for _, errno := range []unix.Errno{
		unix.ENETDOWN, unix.EPROTO, unix.ENOPROTOOPT, unix.EHOSTDOWN,
		unix.ENONET, unix.EHOSTUNREACH, unix.EOPNOTSUPP, unix.ENETUNREACH,
	} {
		t.Run(errno.Error(), func(t *testing.T) {
			if !isPendingTCPAcceptError("tcp", errno) {
				t.Fatal("pending TCP connection error must be recoverable")
			}
			for _, network := range []string{"unix", "udp"} {
				if isPendingTCPAcceptError(network, errno) {
					t.Fatalf("recovery changed %s listener behavior", network)
				}
			}
		})
	}
	for _, err := range []error{
		nil, unix.EAGAIN, unix.EINTR, unix.ECONNRESET, unix.ECONNABORTED,
		unix.EMFILE, unix.ENFILE, unix.ENOBUFS, unix.ENOMEM,
		unix.EBADF, unix.EINVAL, unix.ENOTSOCK, unix.EACCES,
		errors.New("unknown accept error"), fmt.Errorf("wrapped: %w", unix.EPROTO),
	} {
		if isPendingTCPAcceptError("tcp", err) {
			t.Errorf("unexpected pending-connection classification: %v", err)
		}
	}
}
