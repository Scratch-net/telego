package gproxy

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const (
	relayDrainInterval    = 5 * time.Millisecond
	relayMaxPendingWrites = 512
)

// relayOutput bounds both submissions waiting for the destination loop and
// bytes retained by gnet. Only that loop reads OutboundBuffered. A stale
// snapshot overestimates usage until the next drain check; it never grants
// capacity for an outstanding submission twice.
type relayOutput struct {
	mu              sync.Mutex
	destination     clientEndpoint
	source          clientEndpoint
	client          *ConnContext
	limit           int
	queued          int
	inflight        int
	buffered        int
	ownedNative     bool
	waiting         int
	timer           *time.Timer
	closed          bool
	destinationGone bool
	chargedBytes    int
	chargedItems    int
	pendingWrites   map[*relayPendingWrite]struct{}
}

type relayPendingWrite struct {
	complete func(error)
	data     []byte
}

func newRelayOutput(destination, source clientEndpoint, client *ConnContext, limit int) *relayOutput {
	_, owned := destination.(gnet.OwnedWriter)
	if owned {
		// Owned output requires the same priority queue as native AsyncWrite.
		// Owners without it (including Windows) keep their original write path.
		_, owned = clientOwner(destination).(interface {
			ExecuteHighPriority(context.Context, gnet.Runnable) error
		})
	}
	return &relayOutput{destination: destination, source: source, client: client, limit: limit, ownedNative: owned}
}

// reserve is called before advancing any cipher. minimum allows a TLS record
// to remain untouched until the entire record fits.
func (o *relayOutput) reserve(want, minimum int) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.client.State() == StateClosed {
		return 0
	}
	n := min(want, o.limit-o.queued-o.buffered)
	if n < minimum || o.inflight >= relayMaxPendingWrites {
		o.waiting = max(o.waiting, minimum)
		o.scheduleLocked()
		return 0
	}
	if stream, ok := o.source.(*LogicalStream); ok {
		if !stream.reserveAuxInput(n, 1) {
			o.waiting = max(o.waiting, minimum)
			o.scheduleLocked()
			return 0
		}
		o.chargedBytes += n
		o.chargedItems++
	}
	granted := reserveClientOutput(o.destination, n, minimum)
	if granted == 0 {
		if stream, ok := o.source.(*LogicalStream); ok {
			stream.releaseAuxInput(n, 1)
			o.chargedBytes -= n
			o.chargedItems--
		}
		o.waiting = max(o.waiting, minimum)
		o.scheduleLocked()
		return 0
	}
	n = granted
	o.queued += n
	o.inflight++
	return n
}

func (o *relayOutput) releaseReservation(n int) {
	o.mu.Lock()
	o.queued -= n
	if stream, ok := o.source.(*LogicalStream); ok {
		stream.releaseAuxInput(n, 0)
		o.chargedBytes -= n
	}
	o.mu.Unlock()
	releaseClientOutput(o.destination, n, 0)
}

func (o *relayOutput) cancelReservation(n int) {
	o.mu.Lock()
	o.queued -= n
	o.inflight--
	o.releaseDrainedLocked()
	o.mu.Unlock()
	releaseClientOutput(o.destination, n, 1)
}

// relayBuffer uses the fixed-size pool only when every retained byte is
// charged to the output reservation. Small writes allocate their exact size.
func (h *ProxyHandler) relayBuffer(size int) ([]byte, func()) {
	buffer := h.dcBufPool.Get()
	if len(*buffer) == size {
		return *buffer, func() { h.dcBufPool.Put(buffer) }
	}
	h.dcBufPool.Put(buffer)
	return make([]byte, size), nil
}

func (o *relayOutput) scheduleLocked() {
	if o.timer != nil || o.closed {
		return
	}
	o.timer = time.AfterFunc(relayDrainInterval, func() {
		// Execute, unlike Wake, does not invoke the destination's input handler.
		err := executeClient(o.destination, gnet.RunnableFunc(func(context.Context) error {
			o.refresh(0)
			return nil
		}))
		if err != nil {
			o.fail()
		}
	})
}

// refresh runs only on the destination loop, after the submitted bytes have
// either entered its outbound buffer or reached the socket.
func (o *relayOutput) refresh(completed int) {
	o.mu.Lock()
	o.queued -= completed
	if completed > 0 {
		o.inflight--
	}
	if !o.destinationGone {
		if o.ownedNative {
			// queued keeps the whole borrowed allocation until its release
			// callback. Preserve an earlier ordinary handshake's backlog until
			// it drains; completion of an owned write proves its prefix drained.
			if completed > 0 {
				o.buffered = 0
			} else {
				o.buffered = min(o.buffered, o.destination.OutboundBuffered())
			}
		} else {
			o.buffered = o.destination.OutboundBuffered()
		}
	}
	o.releaseDrainedLocked()
	if o.closed || o.client.State() == StateClosed {
		o.stopLocked()
		o.mu.Unlock()
		return
	}
	if completed == 0 {
		o.timer = nil
	}
	wake := o.waiting > 0 && o.limit-o.queued-o.buffered >= o.waiting && o.inflight < relayMaxPendingWrites
	if wake {
		o.waiting = 0
	}
	_, logicalSource := o.source.(*LogicalStream)
	if o.waiting > 0 || (logicalSource && o.buffered > 0) {
		o.scheduleLocked()
	}
	o.mu.Unlock()
	if wake {
		if err := wakeClient(o.source); err != nil {
			o.fail()
		}
	}
}

// write transfers a reserved buffer until the destination owner has consumed
// it. release is deliberately one-shot, including synchronous callback errors.
func (o *relayOutput) write(data []byte, release func()) error {
	finishWork := retainLogicalWork(o.source)
	size := len(data)
	pending := &relayPendingWrite{data: data}
	finalize := func(err error) {
		o.mu.Lock()
		delete(o.pendingWrites, pending)
		pending.data = nil
		o.mu.Unlock()
		if release != nil {
			release()
		}
		if err != nil {
			o.fail()
			o.completeFailed(size)
		} else {
			o.refresh(size)
		}
		finishWork()
	}
	var complete sync.Once
	done := func(err error) {
		complete.Do(func() {
			finalize(err)
			// gnet can retain an abandoned callback after Stop. Drop our
			// references to the stream and pooled buffer from that callback.
			finalize = nil
		})
	}
	pending.complete = done
	if _, logical := o.source.(*LogicalStream); logical {
		o.mu.Lock()
		if o.destinationGone {
			o.mu.Unlock()
			done(net.ErrClosed)
			return net.ErrClosed
		}
		if o.pendingWrites == nil {
			o.pendingWrites = make(map[*relayPendingWrite]struct{})
		}
		o.pendingWrites[pending] = struct{}{}
		o.mu.Unlock()
	}
	var err error
	if o.ownedNative {
		writer := o.destination.(gnet.OwnedWriter)
		err = gnet.ExecuteHighPriority(clientOwner(o.destination), context.Background(), gnet.RunnableFunc(func(context.Context) error {
			o.mu.Lock()
			payload := pending.data
			pending.data = nil
			o.mu.Unlock()
			if payload == nil {
				return nil
			}
			if o.client.State() == StateClosed {
				done(net.ErrClosed)
				return nil
			}
			_, writeErr := writer.WriteOwned(payload, done)
			return writeErr
		}))
	} else {
		err = asyncWriteClient(o.destination, data, func(err error) error {
			done(err)
			return nil
		})
	}
	if err != nil {
		done(err)
	}
	return err
}

func (o *relayOutput) completeFailed(bytes int) {
	o.mu.Lock()
	o.queued -= bytes
	o.inflight--
	o.releaseDrainedLocked()
	o.mu.Unlock()
}

func (o *relayOutput) releaseDrainedLocked() {
	stream, ok := o.source.(*LogicalStream)
	if !ok {
		return
	}
	retained := o.queued + o.buffered
	releaseBytes := max(0, o.chargedBytes-retained)
	releaseItems := 0
	if retained == 0 {
		releaseItems = o.chargedItems
	}
	o.chargedBytes -= releaseBytes
	o.chargedItems -= releaseItems
	stream.releaseAuxInput(releaseBytes, releaseItems)
}

func (o *relayOutput) destinationClosed() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.destinationGone = true
	o.buffered = 0
	o.stopLocked()
	o.releaseDrainedLocked()
	pending := o.pendingWrites
	o.pendingWrites = nil
	o.mu.Unlock()
	// A native close barrier or joined client Stop proves that these writes
	// cannot reach the socket. gnet can abandon their callbacks on shutdown.
	for write := range pending {
		write.complete(net.ErrClosed)
	}
}

func (o *relayOutput) stopLocked() {
	o.closed = true
	if o.timer != nil {
		o.timer.Stop()
		o.timer = nil
	}
}

func (o *relayOutput) close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.stopLocked()
	o.mu.Unlock()
}

func (o *relayOutput) fail() {
	o.close()
	_ = o.source.Close()
	_ = o.destination.Close()
}
