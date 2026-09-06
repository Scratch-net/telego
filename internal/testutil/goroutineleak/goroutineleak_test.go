package goroutineleak

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

const childCaseEnv = "TELEGO_TEST_GOROUTINELEAK_CASE"

var cleanupComplete bool

func TestMain(m *testing.M) {
	if scenario := os.Getenv(childCaseEnv); scenario != "" {
		os.Exit(Run(func() int {
			code := m.Run()
			if scenario == "clean" && !cleanupComplete {
				return 8
			}
			if scenario == "original_exit" {
				return 7
			}
			return code
		}, os.Stderr))
	}
	os.Exit(m.Run())
}

func TestGateSubprocess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		code int
	}{
		{name: "clean", code: 0},
		{name: "leak", code: 1},
		{name: "original_exit", code: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestGateChild$", "-test.count=1")
			command.Env = append(os.Environ(), childCaseEnv+"="+test.name)
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				exit, ok := errors.AsType[*exec.ExitError](err)
				if !ok {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if ctx.Err() != nil || code != test.code {
				t.Fatalf("child exit=%d, want=%d, deadline=%v:\n%s", code, test.code, ctx.Err(), output)
			}
			if test.name == "leak" {
				if !strings.Contains(string(output), "1 permanently blocked goroutines after test cleanup") ||
					!strings.Contains(string(output), "goroutineLeakFixture") {
					t.Fatalf("leak check omitted count or stack evidence:\n%s", output)
				}
			} else if strings.Contains(string(output), "goroutine leak check:") {
				t.Fatalf("clean child reported a leak:\n%s", output)
			}
		})
	}
}

func TestGateChild(t *testing.T) {
	switch os.Getenv(childCaseEnv) {
	case "clean":
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			<-t.Context().Done()
		}()
		t.Cleanup(func() {
			<-finished
			cleanupComplete = true
		})
	case "leak":
		profile := pprof.Lookup("goroutineleak")
		if profile == nil {
			t.Fatal("Go runtime has no goroutineleak profile")
		}
		if err := profile.WriteTo(io.Discard, 1); err != nil {
			t.Fatal(err)
		}
		ready := make(chan struct{})
		go goroutineLeakFixture(ready)
		<-ready
		waitForFixtureBlock(t)
		if profile.Count() != 0 {
			t.Fatal("Count unexpectedly refreshed before the gate's WriteTo")
		}
	case "original_exit":
	default:
		t.Skip("subprocess-only fixture")
	}
}

//go:noinline
func goroutineLeakFixture(ready chan<- struct{}) {
	close(ready)
	<-make(chan struct{})
}

func waitForFixtureBlock(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		stack := make([]byte, 64*1024)
		stack = stack[:runtime.Stack(stack, true)]
		for block := range strings.SplitSeq(string(stack), "\n\n") {
			header, _, _ := strings.Cut(block, "\n")
			if strings.Contains(block, "goroutineLeakFixture(") && strings.Contains(header, "[chan receive]") {
				return
			}
		}
		// This is only the subprocess fixture's blocked-state barrier. The
		// actual leak gate collects one fresh profile without retry or sleep.
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("injected goroutine did not reach its permanent channel wait")
		}
	}
}

func TestInspectRejectsMalformedProfile(t *testing.T) {
	for _, profile := range []string{"", "goroutine profile: total 0\n", "goroutineleak profile: total -1\n", "goroutineleak profile: total invalid\n", "goroutineleak profile: total 0"} {
		if err := inspect(profile); err == nil {
			t.Errorf("accepted malformed profile %q", profile)
		}
	}
	if err := inspect("goroutineleak profile: total 0\n"); err != nil {
		t.Fatal(err)
	}
}
