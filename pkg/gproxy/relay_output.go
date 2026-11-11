package gproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const (
	relayDrainInterval    = 5 * time.Millisecond
	relayDrainIntervalMax = 80 * time.Millisecond
	relayMaxPendingWrites = 512
)

// relayOutputStallTimeout closes a relay whose source waits for output
// capacity while the destination accepts no bytes. It matches the
// Middle-End output stall timeout. Tests replace it.
var relayOutputStallTimeout = 100 * time.Second

// relayStallSamples is the number of owned-write backlog samples per stall
// period.
const relayStallSamples = 4

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
	sourceDraining  bool // Expected upstream EOF disposal must not abort its response drain.
	chargedBytes    int
	chargedItems    int
	pendingWrites   map[*relayPendingWrite]struct{}
	retryDelay      time.Duration // next drain poll; doubles while no progress
	stallDeadline   time.Time     // set while waiting; extended on progress
	// stallOutbound and stallAcked describe the destination at the last owned
	// stall sample. A smaller userspace backlog or more acknowledged socket
	// bytes at the next sample is partial drain of an owned write.
	stallOutbound int
	stallAcked    uint64
	stallSampled  bool
	timerDue      time.Time
	timerSeq      uint64
	timerRuns     int
	// serverActivity stamps the client's last server byte on each completed
	// write, so the silence breaker sees delivered replies, not queued ones.
	serverActivity bool
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

// newClientRelayOutput returns the DC-to-client relay output.
func newClientRelayOutput(destination, source clientEndpoint, client *ConnContext, limit int) *relayOutput {
	output := newRelayOutput(destination, source, client, limit)
	output.serverActivity = true
	return output
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
		o.waitForCapacityLocked(minimum)
		return 0
	}
	if stream, ok := o.source.(*LogicalStream); ok {
		if !stream.reserveAuxInput(n, 1) {
			o.waitForCapacityLocked(minimum)
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
		o.waitForCapacityLocked(minimum)
		return 0
	}
	n = granted
	o.queued += n
	o.inflight++
	return n
}

// waitForCapacityLocked runs on the source owner before any cipher advances.
func (o *relayOutput) waitForCapacityLocked(minimum int) {
	o.waiting = max(o.waiting, minimum)
	if o.stallDeadline.IsZero() {
		o.stallDeadline = time.Now().Add(relayOutputStallTimeout)
	}
	if controller, ok := o.source.(gnet.ReadController); ok {
		if err := controller.PauseRead(); err != nil {
			// Closing is asynchronous. Do not reenter a relay callback under o.mu.
			_ = o.source.Close()
		}
	}
	o.scheduleLocked()
}

func (o *relayOutput) resumeSource() error {
	if controller, ok := o.source.(gnet.ReadController); ok {
		return executeClient(o.source, gnet.RunnableFunc(func(context.Context) error {
			o.mu.Lock()
			closed := o.closed
			o.mu.Unlock()
			if closed {
				return nil
			}
			if err := controller.ResumeRead(); err != nil && !errors.Is(err, net.ErrClosed) {
				o.fail()
			}
			return nil
		}))
	}
	return wakeClient(o.source)
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

// relayPoolMinimum is the smallest batch that takes a pooled buffer. The
// unused pool capacity is at most half of the retained buffer.
const relayPoolMinimum = relayBatchSize / 2

// relayBuffer uses the fixed-size pool only when every retained byte is
// charged to the output reservation: a large batch also charges the unused
// pool capacity until release. Small writes and logical endpoints, whose
// shared budgets charge only the batch size, allocate their exact size.
func (h *ProxyHandler) relayBuffer(o *relayOutput, size int) ([]byte, func()) {
	if size < relayPoolMinimum || size > relayBatchSize {
		return make([]byte, size), nil
	}
	extra := relayBatchSize - size
	if !o.chargeExtra(extra) {
		return make([]byte, size), nil
	}
	buffer := h.dcBufPool.Get()
	return (*buffer)[:size], func() {
		h.dcBufPool.Put(buffer)
		o.releaseExtra(extra)
	}
}

// chargeExtra adds retained bytes beyond a granted reservation. The write
// that carries them releases the charge before its completion refresh.
func (o *relayOutput) chargeExtra(n int) bool {
	if _, logical := o.source.(*LogicalStream); logical {
		return false
	}
	if _, logical := o.destination.(*LogicalStream); logical {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.limit-o.queued-o.buffered < n {
		return false
	}
	o.queued += n
	return true
}

func (o *relayOutput) releaseExtra(n int) {
	o.mu.Lock()
	o.queued -= n
	o.mu.Unlock()
}

// scheduleLocked arms the drain timer. When every wait is covered by an
// owned write completion, that completion calls refresh and wakes the
// source, so the timer only enforces the stall deadline. Otherwise the
// timer polls OutboundBuffered with exponential backoff.
func (o *relayOutput) scheduleLocked() {
	if o.closed {
		return
	}
	now := time.Now()
	delay := max(o.retryDelay, relayDrainInterval)
	_, logicalSource := o.source.(*LogicalStream)
	if o.ownedNative && o.inflight > 0 && !logicalSource && !o.stallDeadline.IsZero() {
		// Completions wake the source. Sample the backlog a few times per
		// stall period so partial drain of an owned write counts as progress.
		delay = min(o.stallDeadline.Sub(now), relayOutputStallTimeout/relayStallSamples)
	}
	if !o.stallDeadline.IsZero() {
		delay = max(0, min(delay, o.stallDeadline.Sub(now)))
	}
	due := now.Add(delay)
	if o.timer != nil {
		if !o.timerDue.After(due) {
			return
		}
		o.timer.Stop()
	}
	o.timerSeq++
	seq := o.timerSeq
	o.timerDue = due
	o.timer = time.AfterFunc(delay, func() {
		// Execute, unlike Wake, does not invoke the destination's input handler.
		err := executeClient(o.destination, gnet.RunnableFunc(func(context.Context) error {
			o.mu.Lock()
			current := o.timer != nil && o.timerSeq == seq
			if current {
				o.timer = nil
				o.timerRuns++
			}
			o.mu.Unlock()
			if current {
				o.refresh(0)
			}
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
	if completed > 0 && o.serverActivity {
		o.client.recordServerActivity()
	}
	o.mu.Lock()
	retained := o.queued + o.buffered
	partialDrain := false
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
				o.stallSampled = false
			} else {
				outbound := o.destination.OutboundBuffered()
				acked, ackedKnown := socketAckedBytes(o.destination)
				partialDrain = o.stallSampled && (outbound < o.stallOutbound || (ackedKnown && acked > o.stallAcked))
				o.stallOutbound, o.stallAcked, o.stallSampled = outbound, acked, true
				o.buffered = min(o.buffered, outbound)
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
	now := time.Now()
	if o.queued+o.buffered < retained || partialDrain {
		o.retryDelay = relayDrainInterval
		if !o.stallDeadline.IsZero() {
			o.stallDeadline = now.Add(relayOutputStallTimeout)
		}
	} else if completed == 0 && o.waiting > 0 {
		o.retryDelay = min(2*max(o.retryDelay, relayDrainInterval), relayDrainIntervalMax)
	}
	wake := o.waiting > 0 && o.limit-o.queued-o.buffered >= o.waiting && o.inflight < relayMaxPendingWrites
	if wake {
		o.waiting = 0
		o.stallDeadline = time.Time{}
		o.stallSampled = false
		o.retryDelay = relayDrainInterval
	} else if o.waiting > 0 && !now.Before(o.stallDeadline) {
		// The source waited a full stall timeout with no destination progress.
		o.mu.Unlock()
		o.fail()
		return
	}
	_, logicalSource := o.source.(*LogicalStream)
	if o.waiting > 0 {
		o.scheduleLocked()
	} else if logicalSource && o.buffered > 0 {
		// Release the logical input charge as soon as the prefix drains.
		o.retryDelay = relayDrainInterval
		o.scheduleLocked()
	}
	o.mu.Unlock()
	if wake {
		if err := o.resumeSource(); err != nil {
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
	o.timerSeq++
}

func (o *relayOutput) close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.stopLocked()
	o.mu.Unlock()
}

func (o *relayOutput) closeForEOF() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.sourceDraining = true
	o.stopLocked()
	o.mu.Unlock()
}

func (o *relayOutput) fail() {
	o.mu.Lock()
	o.stopLocked()
	draining := o.sourceDraining
	o.mu.Unlock()
	if !draining {
		_ = o.source.Close()
	}
	_ = o.destination.Close()
}
