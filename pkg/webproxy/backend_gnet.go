package webproxy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

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
	inputItems, outputItems int
	outputCost              int
	outputHead, outputTail  *socketOutputChunk
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

type socketOutputChunk struct {
	data   []byte
	offset int
	next   *socketOutputChunk
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
	if inbound > b.options.MaxOutputBytes-b.outputCost {
		return gnet.Close
	}
	if inbound > 0 {
		if b.options.MaxOutputItems > 0 && b.outputItems >= b.options.MaxOutputItems {
			return gnet.Close
		}
		if !reserveBackendBudget(b.options.OutputBudget, inbound, 1) {
			return gnet.Close
		}
		// Consume the complete owner read. Leaving a suffix in gnet would let
		// its pooled ring retain capacity that unread-byte counts cannot show.
		data := make([]byte, inbound)
		read, err := c.Read(data)
		if err != nil || read != inbound {
			releaseBackendBudget(b.options.OutputBudget, inbound, 1)
			return gnet.Close
		}
		chunk := &socketOutputChunk{data: data}
		if b.outputTail == nil {
			b.outputHead = chunk
		} else {
			b.outputTail.next = chunk
		}
		b.outputTail = chunk
		b.outputBytes += inbound
		b.outputCost += inbound
		b.outputItems++
	}
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
	n := min(len(data), RelayDataChunk, b.options.MaxInputBytes-b.inputBytes)
	if n <= 0 || (b.options.MaxInputItems > 0 && b.inputItems >= b.options.MaxInputItems) {
		return 0, nil
	}
	writer, ok := b.conn.(gnet.OwnedWriter)
	if !ok {
		return 0, io.ErrClosedPipe
	}
	if !reserveBackendBudget(b.options.InputBudget, n, 1) {
		return 0, nil
	}
	b.inputBytes += n
	b.inputItems++
	owned := make([]byte, n)
	copy(owned, data)
	return writer.WriteOwned(owned, func(error) {
		b.inputBytes -= n
		b.inputItems--
		releaseBackendBudget(b.options.InputBudget, n, 1)
		if !b.closed {
			b.notify()
		}
	})
}

func (b *socketBackend) TryRead(data []byte) (int, error) {
	if b.closed || b.requested.Load() {
		return 0, io.EOF
	}
	if b.conn == nil || b.outputBytes == 0 || len(data) == 0 {
		return 0, nil
	}
	limit := min(len(data), b.outputBytes, RelayDataChunk)
	read := 0
	for read < limit {
		chunk := b.outputHead
		n := copy(data[read:limit], chunk.data[chunk.offset:])
		chunk.offset += n
		read += n
		b.outputBytes -= n
		if chunk.offset == len(chunk.data) {
			b.outputHead = chunk.next
			if b.outputHead == nil {
				b.outputTail = nil
			}
			cost := cap(chunk.data)
			chunk.data, chunk.next = nil, nil
			b.outputCost -= cost
			b.outputItems--
			releaseBackendBudget(b.options.OutputBudget, cost, 1)
		}
	}
	return read, nil
}

func (b *socketBackend) ReadableBytes() int { return b.outputBytes }

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
			releaseBackendBudget(b.options.InputBudget, b.inputBytes, b.inputItems)
			b.inputBytes = 0
			b.inputItems = 0
		}
		if b.outputCost > 0 {
			for chunk := b.outputHead; chunk != nil; {
				next := chunk.next
				chunk.data, chunk.next = nil, nil
				chunk = next
			}
			b.outputHead, b.outputTail = nil, nil
			cost, items := b.outputCost, b.outputItems
			b.outputBytes, b.outputCost, b.outputItems = 0, 0, 0
			releaseBackendBudget(b.options.OutputBudget, cost, items)
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
