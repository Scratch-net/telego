package log

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type blockedLogSink struct {
	bytes.Buffer
	entered chan struct{}
	release chan struct{}
	unblock func()
	started atomic.Bool
	closes  atomic.Int64
}

func newBlockedLogSink(t *testing.T) *blockedLogSink {
	t.Helper()
	sink := &blockedLogSink{entered: make(chan struct{}), release: make(chan struct{})}
	sink.unblock = sync.OnceFunc(func() { close(sink.release) })
	t.Cleanup(sink.unblock)
	return sink
}

func (s *blockedLogSink) Write(p []byte) (int, error) {
	if s.started.CompareAndSwap(false, true) {
		close(s.entered)
	}
	<-s.release
	return s.Buffer.Write(p)
}

func (s *blockedLogSink) Close() error {
	s.closes.Add(1)
	return nil
}

func waitForLogSink(t *testing.T, sink *blockedLogSink) {
	t.Helper()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("consumer did not reach the sink")
	}
}

func TestAsyncWriterBuffersAndDrainsInOrder(t *testing.T) {
	sink := newBlockedLogSink(t)
	w := newAsyncWriter(sink, 32, nil)
	t.Cleanup(func() { sink.unblock(); _ = w.Close() })
	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	waitForLogSink(t, sink)
	// A blocked sink must not prevent producers from filling the available queue.
	enqueued := make(chan struct{})
	go func() {
		for i := range 20 {
			_, _ = fmt.Fprintf(w, "%d\n", i)
		}
		close(enqueued)
	}()
	select {
	case <-enqueued:
	case <-time.After(time.Second):
		t.Fatal("producer blocked on sink I/O")
	}
	sink.unblock()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	want.WriteString("first\n")
	for i := range 20 {
		fmt.Fprintf(&want, "%d\n", i)
	}
	if got := sink.String(); got != want.String() {
		t.Fatalf("drained output = %q, want %q", got, want.String())
	}
	if sink.closes.Load() != 0 {
		t.Fatal("closing the logger closed its borrowed sink")
	}
}

func TestAsyncWriterCountsDroppedMessages(t *testing.T) {
	sink := newBlockedLogSink(t)
	before := DroppedMessages()
	w := newAsyncWriter(sink, 5, countDropped)
	t.Cleanup(func() { sink.unblock(); _ = w.Close() })
	_, _ = w.Write([]byte("first\n"))
	waitForLogSink(t, sink)
	for i := range 12 {
		_, _ = fmt.Fprintf(w, "%d\n", i)
	}
	if got := DroppedMessages() - before; got != 8 {
		t.Fatalf("dropped before sink resumes = %d, want 8", got)
	}
	sink.unblock()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := DroppedMessages() - before; got != 8 {
		t.Fatalf("dropped = %d, want 8", got)
	}
	if got, want := sink.String(), "first\n0\n1\n2\n3\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

type logWriterFunc func([]byte) (int, error)

func (f logWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestAsyncWriterShutdownDeadlineAndRepeatedClose(t *testing.T) {
	sink := newBlockedLogSink(t)
	w := newAsyncWriter(sink, 4, nil)
	t.Cleanup(func() { sink.unblock(); _ = w.Close() })
	_, _ = w.Write([]byte("blocked\n"))
	waitForLogSink(t, sink)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := w.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown = %v, want deadline", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("shutdown did not honor its deadline")
	}
	for range 5 {
		if err := w.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("repeated Shutdown = %v", err)
		}
	}
	if n, err := w.Write([]byte("late\n")); n != len("late\n") || err != nil {
		t.Fatalf("write after shutdown = %d, %v", n, err)
	}
	sink.unblock()
	for range 5 {
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := sink.String(); got != "blocked\n" {
		t.Fatalf("output = %q", got)
	}
	if sink.closes.Load() != 0 {
		t.Fatal("repeated logger close closed its borrowed sink")
	}
}

func TestAsyncWriterConcurrentShutdownAccounting(t *testing.T) {
	var sink bytes.Buffer
	var missed, accepted atomic.Int64
	w := newAsyncWriter(&sink, 64, func(n int) { missed.Add(int64(n)) })
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 300 {
				if _, err := w.Write([]byte("record\n")); err == nil {
					accepted.Add(1)
				} else {
					t.Errorf("write: %v", err)
				}
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			if err := w.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		})
	}
	wg.Wait()
	written := int64(strings.Count(sink.String(), "record\n"))
	if written+missed.Load() != accepted.Load() {
		t.Fatalf("accepted %d != written %d + dropped %d", accepted.Load(), written, missed.Load())
	}
}

func TestAsyncLoggerFormatAndLevel(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		t.Run(strconv.FormatBool(jsonMode), func(t *testing.T) {
			var sink bytes.Buffer
			originalWriter, originalOutput, originalLogger := writer, output, getLogger()
			output = &formatWriter{raw: &sink, console: zerolog.ConsoleWriter{Out: &sink, NoColor: true}}
			writer = newAsyncWriter(output, 16, nil)
			l := zerolog.New(writer).Level(zerolog.InfoLevel)
			logger.Store(&l)
			t.Cleanup(func() {
				_ = writer.Close()
				writer, output = originalWriter, originalOutput
				logger.Store(originalLogger)
			})
			SetLevel("warn")
			if jsonMode {
				SetJSON()
			}
			Info().Msg("filtered")
			Warn().Int("answer", 42).Msg("visible")
			if err := Shutdown(t.Context()); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(sink.String(), "filtered") || !strings.Contains(sink.String(), "visible") {
				t.Fatalf("wrong level filtering: %q", sink.String())
			}
			if jsonMode {
				var record struct {
					Level   string `json:"level"`
					Message string `json:"message"`
					Answer  int    `json:"answer"`
				}
				if err := json.Unmarshal(sink.Bytes(), &record); err != nil {
					t.Fatal(err)
				}
				if record.Level != "warn" || record.Message != "visible" || record.Answer != 42 {
					t.Fatalf("record = %+v", record)
				}
			} else if !strings.Contains(sink.String(), "WRN") || !strings.Contains(sink.String(), "answer=42") {
				t.Fatalf("wrong console formatting: %q", sink.String())
			}
		})
	}
}

func TestLoggerFatalFlushAndStderrOwnership(t *testing.T) {
	mode := os.Getenv("TELEGO_TEST_LOG_LIFECYCLE")
	if mode != "" {
		if mode == "fatal-blocked" {
			_, sink := io.Pipe()
			l := zerolog.New(newAsyncWriter(sink, 4, nil))
			logger.Store(&l)
			Fatal().Msg("blocked fatal")
			os.Exit(4)
		}
		if mode == "fatal-full" {
			entered, release := make(chan struct{}), make(chan struct{})
			started := false
			sink := logWriterFunc(func(p []byte) (int, error) {
				if !started {
					started = true
					close(entered)
				}
				<-release
				return os.Stderr.Write(p)
			})
			l := zerolog.New(newAsyncWriter(sink, 3, countDropped))
			logger.Store(&l)
			Info().Msg("before exit")
			<-entered
			for range 3 {
				Info().Msg("queued")
			}
			if DroppedMessages() != 1 {
				os.Exit(5)
			}
			go func() {
				time.Sleep(50 * time.Millisecond)
				close(release)
			}()
			Fatal().Msg("fatal exit")
			os.Exit(6)
		}
		SetJSON()
		Info().Msg("before exit")
		if mode == "fatal" {
			Fatal().Msg("fatal exit")
		}
		if err := Close(); err != nil {
			os.Exit(2)
		}
		if _, err := fmt.Fprintln(os.Stderr, "stderr remains open"); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	for _, mode := range []string{"fatal", "fatal-full", "fatal-blocked", "close"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoggerFatalFlushAndStderrOwnership$")
			command.Env = append(os.Environ(), "TELEGO_TEST_LOG_LIFECYCLE="+mode)
			output, err := command.CombinedOutput()
			if strings.HasPrefix(mode, "fatal") {
				exitErr, ok := errors.AsType[*exec.ExitError](err)
				if !ok || exitErr.ExitCode() != 1 {
					t.Fatalf("fatal exit = %v; %s", err, output)
				}
				if mode == "fatal-blocked" {
					return
				}
				if !bytes.Contains(output, []byte(`"message":"fatal exit"`)) {
					t.Fatalf("fatal record lost: %s", output)
				}
			} else if err != nil || !bytes.Contains(output, []byte("stderr remains open")) {
				t.Fatalf("stderr closed: %v; %s", err, output)
			}
			if !bytes.Contains(output, []byte(`"message":"before exit"`)) {
				t.Fatalf("buffered record lost: %s", output)
			}
		})
	}
}

func BenchmarkLogProducer(b *testing.B) {
	for _, async := range []bool{false, true} {
		b.Run(strconv.FormatBool(async), func(b *testing.B) {
			var sink io.Writer = zerolog.ConsoleWriter{Out: io.Discard, NoColor: true}
			var dropped atomic.Uint64
			if async {
				w := newAsyncWriter(sink, 4096, func(n int) { dropped.Add(uint64(n)) })
				b.Cleanup(func() { _ = w.Close() })
				sink = w
			}
			l := zerolog.New(sink).With().Timestamp().Logger()
			b.ReportAllocs()
			for b.Loop() {
				l.Info().Int("dc", 2).Str("reason", "timeout").Msg("upstream connection failed")
			}
			// This measures producer latency under sustained load. Report loss so
			// a saturated queue is not mistaken for increased sink throughput.
			b.ReportMetric(float64(dropped.Load())/float64(b.N), "dropped/op")
		})
	}
}
