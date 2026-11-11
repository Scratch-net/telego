package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/log"
)

func TestWaitForStopReportsUnexpectedPublicStop(t *testing.T) {
	errCh := make(chan error, 1)
	errCh <- nil
	cleaned := false
	err := waitForStop(nil, errCh, nil, nil, func() { cleaned = true }, time.Second)
	if err == nil || !cleaned {
		t.Fatalf("unrequested public engine stop: err=%v cleaned=%t; want error after cleanup", err, cleaned)
	}
}

func TestWaitForStopSignalIsClean(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	if err := waitForStop(sigCh, nil, nil, nil, func() {}, time.Second); err != nil {
		t.Fatalf("requested shutdown: %v", err)
	}
}

func TestWaitForStopBoundsShutdown(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM
	release := make(chan struct{})
	defer close(release)
	started := time.Now()
	err := waitForStop(sigCh, nil, nil, nil, func() { <-release }, 50*time.Millisecond)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("stalled cleanup: err=%v after %v; want deadline error", err, time.Since(started))
	}
}

func TestWaitForStopSecondSignalExits(t *testing.T) {
	sigCh := make(chan os.Signal, 2)
	sigCh <- syscall.SIGTERM
	release := make(chan struct{})
	defer close(release)
	go func() {
		time.Sleep(20 * time.Millisecond)
		sigCh <- syscall.SIGINT
	}()
	started := time.Now()
	err := waitForStop(sigCh, nil, nil, nil, func() { <-release }, time.Minute)
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("second signal: err=%v after %v; want immediate error", err, time.Since(started))
	}
}

// The child sends itself SIGHUP and logs to a stderr pipe whose reader is
// closed. Without handling, either signal terminates the process.
func TestProcessSurvivesSIGHUPAndBrokenStderr(t *testing.T) {
	if os.Getenv("TELEGO_TEST_PROCESS_SIGNALS") == "1" {
		keepRunningOnSignals()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			os.Exit(2)
		}
		time.Sleep(100 * time.Millisecond)
		log.Info().Msg("write to a broken stderr pipe")
		_ = log.Close()
		_, _ = os.Stdout.WriteString("alive\n")
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProcessSurvivesSIGHUPAndBrokenStderr$")
	command.Env = append(os.Environ(), "TELEGO_TEST_PROCESS_SIGNALS=1")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	command.Stderr = writer
	var stdout bytes.Buffer
	command.Stdout = &stdout
	err = command.Run()
	_ = writer.Close()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		t.Fatalf("child terminated: %v (%s)", exitErr, exitErr.ProcessState)
	}
	if err != nil || stdout.String() != "alive\n" {
		t.Fatalf("child: err=%v stdout=%q", err, stdout.String())
	}
}

func TestWaitForStopReportsMiddleEndRuntimeFailure(t *testing.T) {
	meErrCh := make(chan error, 1)
	meErrCh <- errors.New("runtime gone")
	cleaned := false
	err := waitForStop(nil, nil, nil, meErrCh, func() { cleaned = true }, time.Second)
	if err == nil || !strings.Contains(err.Error(), "runtime gone") {
		t.Fatalf("err = %v, want the Middle-End runtime failure", err)
	}
	if !cleaned {
		t.Fatal("cleanup did not run")
	}
}
