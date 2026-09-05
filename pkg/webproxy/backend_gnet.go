package webproxy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// GnetBackendFactory keeps explicit TCP/Unix backend overrides on the WEB
// stream owner. The supplied dialer runs only during bounded establishment;
// enrolled sockets never have blocking relay readers or writers.
func GnetBackendFactory(dial BackendDialContextFunc) BackendFactory {
	if dial == nil {
		dialer := &net.Dialer{}
		dial = func(ctx context.Context, network, address, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
	}
	return func(options BackendOpenOptions) (Backend, error) {
		if options.Owner == nil || options.Context == nil || options.MaxInputBytes <= 0 || options.MaxOutputBytes <= 0 {
			return nil, ErrInvalidManagerConfig
		}
		backend := &socketBackend{options: options}
		go func() {
			defer backend.setupFinished()
			connection, err := dial(options.Context, options.Network, options.Address, options.ClientIP)
			if err == nil {
				err = options.Context.Err()
				if err == nil && backend.retired.Load() {
					err = io.ErrClosedPipe
				}
				if err == nil {
					backend.cancelDial = context.AfterFunc(options.Context, func() {
						backend.requested.Store(true)
						_ = connection.Close()
					})
					var enrolled <-chan gnet.RegisteredResult
					enrolled, err = options.Owner.Enroll(gnet.NewContext(context.Background(), backend), connection)
					if err == nil {
						result := <-enrolled
						err = result.Err
						if err == nil && result.Conn == nil {
							err = io.ErrClosedPipe
						}
					}
					backend.cancelDial()
				}
				_ = connection.Close()
			}
			if err != nil {
				if executeErr := options.Owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
					backend.finish(err)
					return nil
				})); executeErr != nil {
					// No connection became visible to the owner in this path.
					backend.requestDisposal(err)
				}
			}
		}()
		return backend, nil
	}
}

type socketBackend struct {
	options                 BackendOpenOptions
	conn                    gnet.Conn
	requested               atomic.Bool
	closed                  bool
	inputBytes, outputBytes int
	drainTimer              *time.Timer
	cancelDial              func() bool
	openOnce                sync.Once
	closeOnce               sync.Once
	disposeOnce             sync.Once
	retired                 atomic.Bool
	setupMu                 sync.Mutex
	setupComplete           bool
	disposalReady           bool
	disposalErr             error
}

func (b *socketBackend) opened(err error) {
	b.openOnce.Do(func() {
		if b.options.OnOpened != nil {
			b.options.OnOpened(err)
		}
	})
}

func (b *socketBackend) finished(err error) {
	b.closeOnce.Do(func() {
		if b.options.OnClosed != nil {
			b.options.OnClosed(err)
		}
	})
}

func (b *socketBackend) onOpen(c gnet.Conn) ([]byte, gnet.Action) {
	b.conn = c
	if b.cancelDial != nil {
		b.cancelDial()
	}
	if b.requested.Load() || b.options.Context.Err() != nil {
		return nil, gnet.Close
	}
	b.opened(nil)
	b.notify()
	return nil, gnet.None
}

func (b *socketBackend) onTraffic(c gnet.Conn) gnet.Action {
	if b.closed || b.requested.Load() {
		return gnet.Close
	}
	inbound := c.InboundBuffered()
	if inbound > b.options.MaxOutputBytes {
		return gnet.Close
	}
	if growth := inbound - b.outputBytes; growth > 0 {
		items := 0
		if b.outputBytes == 0 {
			items = 1
		}
		if !reserveBackendBudget(b.options.OutputBudget, growth, items) {
			return gnet.Close
		}
		b.outputBytes = inbound
	}
	b.refreshWriteBuffer()
	b.notify()
	return gnet.None
}

func (b *socketBackend) TryWrite(data []byte) (int, error) {
	if b.closed || b.requested.Load() {
		return 0, io.ErrClosedPipe
	}
	if b.conn == nil || len(data) == 0 {
		return 0, nil
	}
	b.refreshWriteBuffer()
	n := min(len(data), RelayDataChunk, b.options.MaxInputBytes-b.inputBytes)
	if n <= 0 {
		b.armDrain()
		return 0, nil
	}
	items := 0
	if b.inputBytes == 0 {
		items = 1
	}
	if !reserveBackendBudget(b.options.InputBudget, n, items) {
		return 0, nil
	}
	b.inputBytes += n
	written, err := b.conn.Write(data[:n])
	if b.closed {
		return written, err
	}
	b.refreshWriteBuffer()
	if b.inputBytes > 0 {
		b.armDrain()
	}
	return written, err
}

func (b *socketBackend) TryRead(data []byte) (int, error) {
	if b.closed || b.requested.Load() {
		return 0, io.EOF
	}
	if b.conn == nil || b.outputBytes == 0 || len(data) == 0 {
		return 0, nil
	}
	n := min(len(data), b.outputBytes, RelayDataChunk)
	read, err := b.conn.Read(data[:n])
	if read == 0 {
		return 0, err
	}
	b.outputBytes -= read
	items := 0
	if b.outputBytes == 0 {
		items = 1
	}
	releaseBackendBudget(b.options.OutputBudget, read, items)
	return read, err
}

func (b *socketBackend) ReadableBytes() int { return b.outputBytes }

func (b *socketBackend) refreshWriteBuffer() {
	if b.closed || b.conn == nil {
		return
	}
	buffered := b.conn.OutboundBuffered()
	if released := b.inputBytes - buffered; released > 0 {
		items := 0
		if buffered == 0 {
			items = 1
		}
		b.inputBytes = buffered
		releaseBackendBudget(b.options.InputBudget, released, items)
	}
}

func (b *socketBackend) armDrain() {
	if b.drainTimer != nil || b.closed {
		return
	}
	b.drainTimer = time.AfterFunc(drainCheckInterval, func() {
		_ = b.options.Owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
			b.drainTimer = nil
			if b.closed {
				return nil
			}
			before := b.inputBytes
			b.refreshWriteBuffer()
			if b.inputBytes < before {
				b.notify()
			}
			if b.inputBytes > 0 {
				b.armDrain()
			}
			return nil
		}))
	})
}

func (b *socketBackend) Close() error {
	if !b.requested.CompareAndSwap(false, true) || b.retired.Load() {
		return nil
	}
	return b.options.Owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		if b.conn != nil && !b.closed {
			return b.options.Owner.Close(b.conn)
		}
		// If enrollment is still in flight, its OnOpen sees requested and
		// closes before calling OnOpened. Its completion owns OnClosed.
		return nil
	}))
}

func (b *socketBackend) finish(err error) {
	if b.closed {
		return
	}
	b.closed = true
	if b.drainTimer != nil {
		b.drainTimer.Stop()
		b.drainTimer = nil
	}
	if b.conn == nil {
		b.requestDisposal(err)
		return
	}
	// OnClose precedes gnet's buffer release. A following owner task makes
	// the completion callback and budget release an actual disposal barrier.
	_ = b.options.Owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		b.requestDisposal(err)
		return nil
	}))
	// If that task is rejected or abandoned, HTTPServer calls OwnerStopped
	// after Run has released every socket. No per-stream waiter is needed.
}

func (b *socketBackend) OwnerStopped() {
	if b.retired.Swap(true) {
		return
	}
	b.requested.Store(true)
	b.closed = true
	if b.drainTimer != nil {
		b.drainTimer.Stop()
		b.drainTimer = nil
	}
	b.requestDisposal(io.EOF)
}

func (b *socketBackend) setupFinished() {
	b.setupMu.Lock()
	b.setupComplete = true
	ready, err := b.disposalReady, b.disposalErr
	b.setupMu.Unlock()
	if ready {
		b.dispose(err)
	}
}

func (b *socketBackend) requestDisposal(err error) {
	b.setupMu.Lock()
	b.disposalReady = true
	b.disposalErr = err
	ready := b.setupComplete
	b.setupMu.Unlock()
	if ready {
		b.dispose(err)
	}
}

func (b *socketBackend) dispose(err error) {
	b.disposeOnce.Do(func() {
		if b.inputBytes > 0 {
			releaseBackendBudget(b.options.InputBudget, b.inputBytes, 1)
			b.inputBytes = 0
		}
		if b.outputBytes > 0 {
			releaseBackendBudget(b.options.OutputBudget, b.outputBytes, 1)
			b.outputBytes = 0
		}
		if err == nil {
			err = io.EOF
		}
		b.opened(err)
		b.finished(err)
	})
}

func (b *socketBackend) notify() {
	if b.options.Notify != nil {
		b.options.Notify()
	}
}

func reserveBackendBudget(budget BackendBudget, bytes, items int) bool {
	return budget.Reserve == nil || budget.Reserve(bytes, items)
}

func releaseBackendBudget(budget BackendBudget, bytes, items int) {
	if budget.Release != nil && (bytes != 0 || items != 0) {
		budget.Release(bytes, items)
	}
}

var _ Backend = (*socketBackend)(nil)
