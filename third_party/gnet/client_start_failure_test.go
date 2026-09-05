// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.
// Telego local modification: failed-start completion regression. See TELEGO.md.

//go:build linux

package gnet

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/panjf2000/gnet/v2/pkg/queue"
	"golang.org/x/sys/unix"
)

func TestTelegoClientStartFailureCompletesOnce(t *testing.T) {
	const marker = "TELEGO_TEST_START_FD_LIMIT"
	if os.Getenv(marker) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestTelegoClientStartFailureCompletesOnce$", "-test.timeout=5s")
		command.Env = append(os.Environ(), marker+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated startup failure: %v\n%s", err, output)
		}
		return
	}
	h := &lifecycleEvents{}
	c, err := NewClient(h)
	if err != nil {
		t.Fatal(err)
	}
	var limit unix.Rlimit
	if err = unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = 0
	if err = unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	startErr := c.Start()
	if !errors.Is(startErr, unix.EMFILE) {
		t.Fatalf("Start = %v; want EMFILE", startErr)
	}
	lifecycleWait(t, c.Done())
	if c.Err() != startErr || c.Stop() != startErr || c.Stop() != startErr {
		t.Fatal("failed startup did not retain one terminal error")
	}
	if h.shutdowns.Load() != 1 {
		t.Fatal("failed startup did not clean up exactly once")
	}
}

func TestTelegoServerPartialStartFailureClosesPreparedPoller(t *testing.T) {
	const marker = "TELEGO_TEST_SERVER_PARTIAL_START"
	if os.Getenv(marker) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestTelegoServerPartialStartFailureClosesPreparedPoller$", "-test.timeout=5s")
		command.Env = append(os.Environ(), marker+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("isolated partial startup failure: %v\n%s", err, output)
		}
		return
	}
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	defer unix.Setrlimit(unix.RLIMIT_NOFILE, &original)
	var owned []int
	defer func() {
		for _, fd := range owned {
			_ = unix.Close(fd)
		}
	}()
	var engine Engine
	h := &lifecycleEvents{onBoot: func(e Engine) Action {
		engine = e
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		highest := 2
		for _, entry := range entries {
			fd, _ := strconv.Atoi(entry.Name())
			if fd > highest {
				highest = fd
			}
		}
		// Fill all lower gaps so exactly two new descriptors fit. The worker
		// poller opens successfully; creation of the ingress poller then fails.
		for {
			fd, err := unix.Dup(2)
			if err != nil {
				t.Fatal(err)
			}
			owned = append(owned, fd)
			if fd <= highest {
				continue
			}
			limited := original
			limited.Cur = uint64(fd + 3)
			if err = unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
				t.Fatal(err)
			}
			break
		}
		return None
	}}
	err := Run(h, "tcp://127.0.0.1:0", WithNumEventLoop(1), WithReusePort(false))
	if !errors.Is(err, unix.EMFILE) {
		t.Fatalf("Run = %v; want EMFILE", err)
	}
	if !engine.eng.isShutdown() || h.shutdowns.Load() != 1 {
		t.Fatal("partial startup did not finish cleanup")
	}
	prepared := 0
	engine.eng.eventLoops.iterate(func(_ int, el *eventloop) bool {
		prepared++
		if err := el.poller.Trigger(queue.HighPriority, func(any) error { t.Error("closed poller executed a callback"); return nil }, nil); !errors.Is(err, os.ErrClosed) {
			t.Errorf("prepared poller remained open: %v", err)
		}
		return true
	})
	if prepared != 1 {
		t.Fatalf("prepared pollers = %d; want one before ingress failure", prepared)
	}
}
