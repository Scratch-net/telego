package log

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/diode"
)

const shutdownTimeout = 2 * time.Second

// asyncWriter serializes enqueue and shutdown, without holding its mutex during
// sink I/O. Serial enqueue also limits contention on the diode's writer slots.
type asyncWriter struct {
	mu       sync.Mutex
	closed   bool
	queue    diode.Writer
	done     chan struct{}
	closeErr error
	pending  atomic.Int64
	capacity int64
	alert    diode.Alerter
}

func newAsyncWriter(sink io.Writer, capacity int, alert diode.Alerter) *asyncWriter {
	if capacity < 2 {
		panic("log queue capacity must include a fatal reserve slot")
	}
	w := &asyncWriter{done: make(chan struct{}), capacity: int64(capacity), alert: alert}
	w.queue = diode.NewWriter(queueSink{writer: w, sink: sink}, capacity, 10*time.Millisecond, alert)
	return w
}

// queueSink deliberately hides Close: a process-owned sink such as stderr must
// stay open. TryNext has cleared the ring slot before calling this writer.
type queueSink struct {
	writer *asyncWriter
	sink   io.Writer
}

func (s queueSink) Write(p []byte) (int, error) {
	s.writer.pending.Add(-1)
	return s.sink.Write(p)
}

func (w *asyncWriter) Write(p []byte) (int, error) {
	return w.WriteLevel(zerolog.NoLevel, p)
}

func (w *asyncWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		// Returning an error makes zerolog synchronously write to stderr through
		// its default error handler, which can block late background producers.
		w.drop()
		return len(p), nil
	}
	limit := w.capacity - 1
	if level == zerolog.FatalLevel {
		limit = w.capacity
	}
	if w.pending.Load() >= limit {
		w.drop()
		return len(p), nil
	}
	// Serialized producers and this reservation keep the next ring slot empty.
	// The consumer releases it only after TryNext clears that slot. Diode cannot
	// overwrite a queued event or enter its synchronous collision-log path.
	w.pending.Add(1)
	return w.queue.Write(p)
}

func (w *asyncWriter) drop() {
	if w.alert != nil {
		w.alert(1)
	}
}

func (w *asyncWriter) Shutdown(ctx context.Context) error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		go func() {
			w.closeErr = w.queue.Close()
			close(w.done)
		}()
	}
	w.mu.Unlock()
	select {
	case <-w.done:
		return w.closeErr
	default:
	}
	select {
	case <-w.done:
		return w.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close is used by zerolog.Fatal before os.Exit. It must remain bounded even
// when the sink blocks, and repeated calls must not start additional drains.
func (w *asyncWriter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return w.Shutdown(ctx)
}
