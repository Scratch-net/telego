package middleend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const (
	gnetDrainSubmissionBudget = 64
	gnetDrainPayloadBudget    = 1 << 20
	gnetOutboundPollFast      = time.Millisecond
	gnetOutboundPollBacklog   = 2 * time.Millisecond
	// Pin gnet v2.10's audited stream-buffer defaults. Dependency updates must
	// not silently change per-readable-event work or static outbound capacity.
	gnetClientReadBufferCap  = 64 << 10
	gnetClientWriteBufferCap = 64 << 10
	// gnet v2.10's default static outbound ring is 64 KiB. Resume one
	// application batch when only that fixed-capacity tail remains; larger
	// elastic backlogs must drain first.
	gnetDrainResumeOutboundBytes = 64 << 10
	gnetCBCBlockSize             = 4 * NoopFrameSize
	gnetEncryptedPongSize        = (KeepalivePayloadSize + FullFrameOverhead + gnetCBCBlockSize - 1) / gnetCBCBlockSize * gnetCBCBlockSize
)

var (
	// ErrGnetRuntimeStopped reports an operation on a stopping or stopped
	// shared gnet client runtime.
	ErrGnetRuntimeStopped = errors.New("Middle-End gnet runtime is stopped")
	// ErrInvalidGnetLink reports invalid construction inputs for a gnet link.
	ErrInvalidGnetLink = errors.New("invalid Middle-End gnet link")
	// ErrInvalidGnetRuntimeConfig reports a zero or negative event-loop count.
	ErrInvalidGnetRuntimeConfig = errors.New("invalid Middle-End gnet runtime config")
	// ErrGnetOutboundBackpressure reports that protocol-generated writes would
	// exceed the link's derived hard transport-buffer ceiling.
	ErrGnetOutboundBackpressure = errors.New("Middle-End gnet outbound buffer is full")
	// ErrGnetControlItemBackpressure reports that pending automatic/control
	// writes reached their hard item limit.
	ErrGnetControlItemBackpressure = errors.New("Middle-End gnet control write item queue is full")
	// ErrGnetControlByteBackpressure reports that pending automatic/control
	// writes reached their hard byte limit.
	ErrGnetControlByteBackpressure = errors.New("Middle-End gnet control write byte queue is full")
)

// MaxGnetClientEventLoops is gnet v2.10's EventLoopIndexMax. gnet stores an
// event-loop index in one byte and silently clamps larger NumEventLoop values
// to math.MaxUint8+1. Rejecting larger values keeps requested and effective
// runtime sizing identical.
const MaxGnetClientEventLoops = 256

// GnetClientRuntimeConfig contains explicit shared-runtime sizing. EventLoops
// must be positive and no larger than MaxGnetClientEventLoops; the engine never
// selects a production concurrency level.
type GnetClientRuntimeConfig struct {
	EventLoops int
}

// Validate rejects a runtime without an explicit event-loop count.
func (c GnetClientRuntimeConfig) Validate() error {
	if c.EventLoops <= 0 || c.EventLoops > MaxGnetClientEventLoops {
		return fmt.Errorf("%w: event loops must be in [1,%d]", ErrInvalidGnetRuntimeConfig, MaxGnetClientEventLoops)
	}
	return nil
}

// GnetClientRuntime owns one reusable gnet client. It may enroll many links;
// gnet assigns each connection to exactly one event loop. Per-link protocol
// state remains owned by that connection's loop.
type GnetClientRuntime struct {
	client *gnet.Client

	mu       sync.Mutex
	links    map[*GnetClientLink]struct{}
	stopping bool
	enrolls  sync.WaitGroup
	stopErr  error
	stopOnce sync.Once
	done     chan struct{}
}

// String redacts all nested link and protocol state.
func (*GnetClientRuntime) String() string {
	return "middleend.GnetClientRuntime{redacted}"
}

// GoString redacts all nested link and protocol state.
func (*GnetClientRuntime) GoString() string {
	return "middleend.GnetClientRuntime{redacted}"
}

// NewGnetClientRuntime starts a reusable gnet client runtime with an explicit
// event-loop count. Multiple links share this runtime and retain
// connection-local event-loop ownership. A caller must eventually call Stop.
func NewGnetClientRuntime(config GnetClientRuntimeConfig) (*GnetClientRuntime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	runtime := &GnetClientRuntime{
		links: make(map[*GnetClientLink]struct{}),
		done:  make(chan struct{}),
	}
	handler := &gnetClientEventHandler{runtime: runtime}
	client, err := gnet.NewClient(handler, gnetClientOptions(config)...)
	if err != nil {
		return nil, fmt.Errorf("create Middle-End gnet runtime: %w", err)
	}
	runtime.client = client
	if err := client.Start(); err != nil {
		return nil, fmt.Errorf("start Middle-End gnet runtime: %w", err)
	}
	return runtime, nil
}

func gnetClientOptions(config GnetClientRuntimeConfig) []gnet.Option {
	return []gnet.Option{
		gnet.WithNumEventLoop(config.EventLoops),
		gnet.WithReadBufferCap(gnetClientReadBufferCap),
		gnet.WithWriteBufferCap(gnetClientWriteBufferCap),
		gnet.WithTCPNoDelay(gnet.TCPNoDelay),
	}
}

// NewClientLink constructs an unstarted link over an established concrete TCP
// connection. Requiring *net.TCPConn makes compatibility with gnet v2.10's
// EnrollContext type switch explicit. The connection transfers to the link
// only on a successful return. Start performs enrollment exactly once; gnet
// duplicates the socket and closes the original TCPConn during enrollment.
func (r *GnetClientRuntime) NewClientLink(conn *net.TCPConn, bootstrap *ClientBootstrap, limits LinkLimits) (ClientLink, error) {
	if r == nil || r.client == nil {
		return nil, fmt.Errorf("%w: nil runtime", ErrInvalidGnetLink)
	}
	if conn == nil || bootstrap == nil {
		return nil, fmt.Errorf("%w: nil connection or bootstrap", ErrInvalidGnetLink)
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	maxOutboundBytes, err := maximumGnetOutboundBytes(limits)
	if err != nil {
		return nil, err
	}
	maxControlItems := limits.MaxPendingEvents + 1
	maxControlBytes := max(gnetEncryptedPongSize, limits.MaxPendingEventBytes)

	link := &GnetClientLink{
		runtime:          r,
		conn:             conn,
		bootstrap:        bootstrap,
		limits:           limits,
		maxOutboundBytes: maxOutboundBytes,
		maxControlItems:  maxControlItems,
		maxControlBytes:  maxControlBytes,
		state:            LinkStateCreated,
		events:           make(chan LinkEvent, limits.MaxPendingEvents),
		submissionReady:  make(chan struct{}, 1),
		done:             make(chan struct{}),
		startDone:        make(chan struct{}),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return nil, ErrGnetRuntimeStopped
	}
	r.links[link] = struct{}{}
	return link, nil
}

// Stop starts runtime-wide shutdown once and waits until gnet has closed every
// stream and every registered link has published Done. If ctx expires, the
// shutdown continues and a later Stop call may wait for its result.
func (r *GnetClientRuntime) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("stop Middle-End gnet runtime: nil context")
	}
	r.beginStop()
	select {
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.stopErr
	case <-ctx.Done():
		return fmt.Errorf("stop Middle-End gnet runtime: %w", context.Cause(ctx))
	}
}

func (r *GnetClientRuntime) beginStop() {
	r.stopOnce.Do(func() {
		// Publish the enrollment barrier before Stop returns control to a
		// concurrent constructor or Start call.
		r.mu.Lock()
		r.stopping = true
		r.mu.Unlock()
		go r.stop()
	})
}

func (r *GnetClientRuntime) stop() {
	r.mu.Lock()
	links := slices.Collect(maps.Keys(r.links))
	r.mu.Unlock()

	for _, link := range links {
		link.requestTerminal(nil)
	}
	// The runtime mutex orders every enrolls.Add before this Wait: setting
	// stopping under the same mutex prevents a later Add from succeeding.
	r.enrolls.Wait()
	stopErr := r.client.Stop()
	for _, link := range links {
		link.finalizeAfterStreamClose()
		<-link.Done()
	}

	r.mu.Lock()
	r.stopErr = stopErr
	close(r.done)
	r.mu.Unlock()
}

func (r *GnetClientRuntime) enroll(conn *net.TCPConn, link *GnetClientLink) (gnet.Conn, error) {
	// gnet v2.10 waits synchronously for the selected loop's OnOpen callback.
	// Register the enrollment before releasing the lifecycle mutex. Stop marks
	// the runtime as stopping under that mutex, then waits for all registered
	// enrollments before it stops the client pollers. Do not hold the mutex
	// across EnrollContext: an OnOpen failure can call OnClose synchronously,
	// and OnClose removes the link under the same runtime mutex.
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return nil, ErrGnetRuntimeStopped
	}
	r.enrolls.Add(1)
	r.mu.Unlock()
	defer r.enrolls.Done()
	return r.client.EnrollContext(conn, link)
}

func (r *GnetClientRuntime) removeLink(link *GnetClientLink) {
	r.mu.Lock()
	delete(r.links, link)
	r.mu.Unlock()
}

type gnetClientEventHandler struct {
	gnet.BuiltinEventEngine
	runtime *GnetClientRuntime
}

func (h *gnetClientEventHandler) OnOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	link, ok := conn.Context().(*GnetClientLink)
	if !ok || link == nil || link.runtime != h.runtime {
		return nil, gnet.Close
	}
	return link.onOpen(conn)
}

func (h *gnetClientEventHandler) OnTraffic(conn gnet.Conn) gnet.Action {
	link, ok := conn.Context().(*GnetClientLink)
	if !ok || link == nil || link.runtime != h.runtime {
		return gnet.Close
	}
	return link.onTraffic(conn)
}

func (h *gnetClientEventHandler) OnClose(conn gnet.Conn, closeErr error) gnet.Action {
	link, ok := conn.Context().(*GnetClientLink)
	if ok && link != nil && link.runtime == h.runtime {
		link.onClose(conn, closeErr)
	}
	return gnet.None
}

type gnetWireSegment struct {
	end             uint64
	submissionBytes int
	wireBytes       int
	control         bool
}

type gnetWireCharge struct {
	submissionBytes int
	wireBytes       int
	control         bool
}

// GnetClientLink is one Middle-End stream enrolled in a shared
// GnetClientRuntime. All bootstrap, CBC, frame-sequence, and gnet.Conn access
// is confined to the connection's owning event loop.
type GnetClientLink struct {
	runtime   *GnetClientRuntime
	conn      *net.TCPConn
	bootstrap *ClientBootstrap
	limits    LinkLimits
	// maxOutboundBytes includes exact RPC payload charges plus the maximum
	// full-frame and CBC padding overhead for every accepted item. It also
	// bounds protocol-generated pongs, which do not consume submission slots.
	maxOutboundBytes int
	maxControlItems  int
	maxControlBytes  int
	events           chan LinkEvent
	submissionReady  chan struct{}
	done             chan struct{}
	startDone        chan struct{}

	mu                        sync.Mutex
	state                     LinkState
	startInitiated            bool
	startPublished            bool
	startResult               error
	terminalClaimed           bool
	terminalErr               error
	finalized                 bool
	closeScheduled            bool
	drainScheduled            bool
	pollScheduled             bool
	pollDelay                 time.Duration
	pollTimer                 *time.Timer
	owner                     gnet.EventLoop
	gconn                     gnet.Conn
	submissions               []LinkSubmission
	eventCharges              []int
	pendingSubmissions        int
	pendingSubmissionBytes    int
	submissionHighWater       int
	submissionBytesHighWater  int
	pendingEvents             int
	pendingEventBytes         int
	eventHighWater            int
	eventBytesHighWater       int
	ownerWireTotal            uint64
	ownerWireSegments         []gnetWireSegment
	ownerControlItems         int
	ownerControlBytes         int
	ownerControlItemHighWater int
	ownerControlByteHighWater int
}

var _ ClientLink = (*GnetClientLink)(nil)

// String redacts the bootstrap, queued RPC payloads, and encrypted wire data.
func (*GnetClientLink) String() string {
	return "middleend.GnetClientLink{redacted}"
}

// GoString redacts the bootstrap, queued RPC payloads, and encrypted wire data.
func (*GnetClientLink) GoString() string {
	return "middleend.GnetClientLink{redacted}"
}

// Start enrolls the TCP stream and waits for the bilateral bootstrap. The
// first caller performs the work; every concurrent or repeated caller receives
// the exact first result.
func (l *GnetClientLink) Start(ctx context.Context) error {
	if l == nil {
		return ErrLinkClosed
	}
	l.mu.Lock()
	if l.startInitiated {
		startDone := l.startDone
		l.mu.Unlock()
		<-startDone
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.startResult
	}
	if l.terminalClaimed || l.finalized {
		l.startInitiated = true
		l.publishStartLocked(ErrLinkClosed)
		result := l.startResult
		l.mu.Unlock()
		return result
	}
	l.startInitiated = true
	l.state = LinkStateBootstrapping
	l.mu.Unlock()

	if ctx == nil {
		err := errors.New("start Middle-End gnet link: nil context")
		l.requestTerminal(err)
		l.finalizeIfUnenrolled()
		return l.waitStartResult()
	}
	if cause := context.Cause(ctx); cause != nil {
		l.requestTerminal(fmt.Errorf("start Middle-End gnet link: %w", cause))
		l.finalizeIfUnenrolled()
		return l.waitStartResult()
	}

	if _, err := l.runtime.enroll(l.conn, l); err != nil {
		l.requestTerminal(fmt.Errorf("enroll Middle-End gnet link: %w", err))
		l.finalizeAfterStreamClose()
		return l.waitStartResult()
	}

	select {
	case <-l.startDone:
		return l.waitStartResult()
	case <-ctx.Done():
		return l.resolveStartCancellation(fmt.Errorf("bootstrap Middle-End gnet link: %w", context.Cause(ctx)))
	}
}

func (l *GnetClientLink) resolveStartCancellation(cancelErr error) error {
	l.mu.Lock()
	if l.startPublished {
		result := l.startResult
		l.mu.Unlock()
		return result
	}
	claimed := l.claimTerminalLocked(cancelErr)
	result := l.startResult
	l.mu.Unlock()
	if claimed && !l.scheduleOwnerClose() {
		l.finalizeIfUnenrolled()
	}
	return result
}

// TrySubmit transfers one validated payload into the bounded MPSC queue. It
// never blocks and never calls a gnet connection from the submitting goroutine.
func (l *GnetClientLink) TrySubmit(submission LinkSubmission) error {
	if l == nil {
		return ErrLinkClosed
	}
	l.mu.Lock()
	state := l.state
	l.mu.Unlock()
	switch state {
	case LinkStateCreated, LinkStateBootstrapping:
		return ErrLinkNotReady
	case LinkStateClosing, LinkStateClosed:
		return ErrLinkClosed
	}
	if err := submission.Validate(); err != nil {
		return err
	}
	charge := submission.ByteSize()

	l.mu.Lock()
	switch l.state {
	case LinkStateCreated, LinkStateBootstrapping:
		l.mu.Unlock()
		return ErrLinkNotReady
	case LinkStateClosing, LinkStateClosed:
		l.mu.Unlock()
		return ErrLinkClosed
	case LinkStateReady:
	}
	if charge > l.limits.MaxPendingSubmissionBytes {
		l.mu.Unlock()
		return fmt.Errorf("%w: %d exceeds %d", ErrLinkSubmissionTooLarge, charge, l.limits.MaxPendingSubmissionBytes)
	}
	if l.pendingSubmissions >= l.limits.MaxPendingSubmissions ||
		charge > l.limits.MaxPendingSubmissionBytes-l.pendingSubmissionBytes {
		l.mu.Unlock()
		return ErrLinkBackpressure
	}
	l.submissions = append(l.submissions, submission)
	l.pendingSubmissions++
	l.pendingSubmissionBytes += charge
	l.submissionHighWater = max(l.submissionHighWater, l.pendingSubmissions)
	l.submissionBytesHighWater = max(l.submissionBytesHighWater, l.pendingSubmissionBytes)
	owner := l.owner
	schedule := !l.drainScheduled
	if schedule {
		l.drainScheduled = true
	}
	l.mu.Unlock()

	if schedule {
		l.scheduleDrain(owner)
	}
	return nil
}

// SubmissionReady returns the stable coalesced capacity notification channel.
func (l *GnetClientLink) SubmissionReady() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.submissionReady
}

// Events returns the single-consumer bounded event stream.
func (l *GnetClientLink) Events() <-chan LinkEvent {
	if l == nil {
		return nil
	}
	return l.events
}

// Snapshot returns a concurrency-safe instantaneous view.
func (l *GnetClientLink) Snapshot() LinkSnapshot {
	if l == nil {
		return LinkSnapshot{State: LinkStateClosed}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reconcileEventsLocked()
	return LinkSnapshot{
		State:                    l.state,
		PendingSubmissions:       l.pendingSubmissions,
		PendingSubmissionBytes:   l.pendingSubmissionBytes,
		SubmissionHighWater:      l.submissionHighWater,
		SubmissionBytesHighWater: l.submissionBytesHighWater,
		PendingEvents:            l.pendingEvents,
		PendingEventBytes:        l.pendingEventBytes,
		EventHighWater:           l.eventHighWater,
		EventBytesHighWater:      l.eventBytesHighWater,
	}
}

// Done closes after terminal publication and removal from the shared runtime.
// For an enrolled link, this is the logical stream-close boundary in gnet's
// OnClose callback. gnet v2.10 flushes residual outbound bytes and closes the
// operating-system descriptor after OnClose returns.
func (l *GnetClientLink) Done() <-chan struct{} {
	if l == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return l.done
}

// Err returns the first terminal failure, or nil after an orderly Close.
func (l *GnetClientLink) Err() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.terminalErr
}

// Close is idempotent. It closes only this logical stream; the shared runtime
// remains available for fresh links. Runtime Stop is the boundary that waits
// for gnet's event loops and their physical descriptors to stop.
func (l *GnetClientLink) Close() error {
	if l == nil {
		return nil
	}
	l.requestTerminal(nil)
	<-l.done
	return nil
}

func (l *GnetClientLink) waitStartResult() error {
	<-l.startDone
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.startResult
}

func (l *GnetClientLink) publishStartLocked(result error) {
	if l.startPublished {
		return
	}
	l.startResult = result
	l.startPublished = true
	close(l.startDone)
}

func (l *GnetClientLink) onOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	l.mu.Lock()
	l.owner = conn.EventLoop()
	l.gconn = conn
	if l.terminalClaimed {
		l.closeScheduled = true
		l.mu.Unlock()
		return nil, gnet.Close
	}
	l.mu.Unlock()

	initial, err := l.bootstrap.Start()
	if err != nil {
		l.claimOwnerFailure(err)
		return nil, gnet.Close
	}
	return initial, gnet.None
}

func (l *GnetClientLink) onTraffic(conn gnet.Conn) gnet.Action {
	if l.isTerminalClaimed() {
		return gnet.Close
	}
	if l.bootstrap.Ready() {
		if err := l.observeOwnerOutbound(conn, false); err != nil {
			l.claimOwnerFailure(err)
			return gnet.Close
		}
	}
	buffered := conn.InboundBuffered()
	if buffered <= 0 {
		return gnet.None
	}
	data, err := conn.Next(buffered)
	if err != nil {
		l.claimOwnerFailure(fmt.Errorf("read Middle-End gnet inbound buffer: %w", err))
		return gnet.Close
	}

	remaining := data
	for len(remaining) != 0 {
		consumed, update, err := l.bootstrap.Feed(remaining)
		if err != nil {
			l.claimOwnerFailure(err)
			return gnet.Close
		}
		if consumed == 0 {
			l.claimOwnerFailure(io.ErrNoProgress)
			return gnet.Close
		}
		remaining = remaining[consumed:]
		if len(update.Outbound) != 0 {
			written, err := conn.Write(update.Outbound)
			if err != nil || written != len(update.Outbound) {
				l.claimOwnerFailure(writeResultError("bootstrap", written, len(update.Outbound), err))
				return gnet.Close
			}
		}
		if update.BecameReady {
			if outbound := conn.OutboundBuffered(); outbound != 0 {
				l.claimOwnerFailure(fmt.Errorf("Middle-End bootstrap became ready with %d gnet outbound bytes", outbound))
				return gnet.Close
			}
			if !l.publishReady() {
				return gnet.Close
			}
		}
		if err := l.processOwnerFrames(conn, update.Frames); err != nil {
			l.claimOwnerFailure(err)
			return gnet.Close
		}
	}
	if l.bootstrap.Ready() {
		if err := l.observeOwnerOutbound(conn, false); err != nil {
			l.claimOwnerFailure(err)
			return gnet.Close
		}
	}
	return gnet.None
}

func (l *GnetClientLink) onClose(_ gnet.Conn, closeErr error) {
	if !l.isTerminalClaimed() {
		terminalErr := closeErr
		if terminalErr == nil {
			terminalErr = net.ErrClosed
		}
		if l.bootstrap.Ready() {
			if err := l.bootstrap.Finish(); err != nil {
				terminalErr = err
			}
		} else {
			terminalErr = l.bootstrap.failTransport(terminalErr)
		}
		l.claimOwnerFailure(terminalErr)
	}

	// On Unix, gnet v2.10 eventloop.close runs delConn, OnClose, the residual
	// outbound flush, conn.release, poller.Delete, and unix.Close, in that order.
	// No more traffic or writes can enter this link after delConn. Thus, terminal
	// publication is safe here and cannot depend on a poller that is exiting.
	// gnet can still own its encrypted outbound copies until OnClose returns.
	// The finalizer drops only the link's byte-boundary ledger.
	l.finalizeAfterStreamClose()
}

func (l *GnetClientLink) publishReady() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.terminalClaimed || l.finalized {
		return false
	}
	l.state = LinkStateReady
	l.publishStartLocked(nil)
	return true
}

func (l *GnetClientLink) handleOwnerFrame(conn gnet.Conn, frame Frame) error {
	event, err := parseLinkEvent(frame.Payload)
	if err != nil {
		return err
	}
	if event.Kind == LinkEventPing {
		pongWire, err := l.bootstrap.Encode((Pong{ID: event.KeepaliveID}).MarshalBinary())
		if err != nil {
			return err
		}
		if err := l.writeOwnerBatch(conn, [][]byte{pongWire}, []gnetWireCharge{{control: true}}); err != nil {
			return err
		}
	}
	return l.enqueueOwnerEvent(event)
}

func (l *GnetClientLink) enqueueOwnerEvent(event LinkEvent) error {
	if err := l.enqueueEvent(event); err != nil {
		clear(event.Packet)
		return err
	}
	return nil
}

func (l *GnetClientLink) processOwnerFrames(conn gnet.Conn, frames []Frame) error {
	for index := range frames {
		err := l.handleOwnerFrame(conn, frames[index])
		clear(frames[index].Payload)
		frames[index] = Frame{}
		if err != nil {
			clearFrames(frames[index+1:])
			return err
		}
	}
	return nil
}

func (l *GnetClientLink) enqueueEvent(event LinkEvent) error {
	charge := event.ByteSize()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.terminalClaimed || l.finalized {
		return ErrLinkClosed
	}
	l.reconcileEventsLocked()
	if l.pendingEvents >= l.limits.MaxPendingEvents ||
		charge > l.limits.MaxPendingEventBytes-l.pendingEventBytes {
		return ErrLinkEventBackpressure
	}
	l.events <- event
	l.eventCharges = append(l.eventCharges, charge)
	l.pendingEvents++
	l.pendingEventBytes += charge
	l.eventHighWater = max(l.eventHighWater, l.pendingEvents)
	l.eventBytesHighWater = max(l.eventBytesHighWater, l.pendingEventBytes)
	return nil
}

func (l *GnetClientLink) reconcileEventsLocked() {
	if l.finalized || len(l.eventCharges) == 0 {
		return
	}
	delivered := len(l.eventCharges) - len(l.events)
	if delivered <= 0 {
		return
	}
	for _, charge := range l.eventCharges[:delivered] {
		l.pendingEvents--
		l.pendingEventBytes -= charge
	}
	clear(l.eventCharges[:delivered])
	l.eventCharges = l.eventCharges[delivered:]
	if len(l.eventCharges) == 0 {
		l.eventCharges = nil
	}
}

func (l *GnetClientLink) scheduleDrain(owner gnet.EventLoop) {
	if owner == nil {
		l.failExternal(errors.New("schedule Middle-End gnet drain: missing owner event loop"))
		return
	}
	if err := owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		l.drainOwner()
		return nil
	})); err != nil {
		l.failExternal(fmt.Errorf("schedule Middle-End gnet drain: %w", err))
	}
}

func (l *GnetClientLink) drainOwner() {
	l.mu.Lock()
	if l.terminalClaimed || l.finalized {
		l.drainScheduled = false
		l.mu.Unlock()
		return
	}
	conn := l.gconn
	ownerHasPendingWire := len(l.ownerWireSegments) != 0
	l.mu.Unlock()

	// Keep at most one encoded application batch in gnet's user-space
	// outbound buffer. Without this gate, a slow peer lets successive drain
	// runnables encode the entire bounded submission queue while the first
	// batch is still pending. That retains both queued plaintext and copied
	// ciphertext and lets one connection monopolize its event loop.
	if ownerHasPendingWire {
		if err := l.observeOwnerOutbound(conn, false); err != nil {
			l.claimOwnerFailure(err)
			l.scheduleOwnerClose()
			return
		}
		if len(l.ownerWireSegments) != 0 && conn.OutboundBuffered() > gnetDrainResumeOutboundBytes {
			l.mu.Lock()
			l.drainScheduled = false
			l.mu.Unlock()
			return
		}
	}

	l.mu.Lock()
	l.drainScheduled = false
	if l.terminalClaimed || l.finalized {
		l.mu.Unlock()
		return
	}
	count := 0
	payloadBytes := 0
	for count < len(l.submissions) && count < gnetDrainSubmissionBudget {
		next := l.submissions[count].ByteSize()
		if count != 0 && payloadBytes+next > gnetDrainPayloadBudget {
			break
		}
		payloadBytes += next
		count++
	}
	batch := make([]LinkSubmission, count)
	copy(batch, l.submissions[:count])
	clear(l.submissions[:count])
	l.submissions = l.submissions[count:]
	if len(l.submissions) == 0 {
		l.submissions = nil
	}
	conn = l.gconn
	l.mu.Unlock()

	wires := make([][]byte, 0, len(batch))
	charges := make([]gnetWireCharge, 0, len(batch))
	for index := range batch {
		if l.isTerminalClaimed() {
			clearSubmissionBatch(batch[index:])
			clearWireBatch(wires)
			return
		}
		wire, err := l.bootstrap.Encode(batch[index].Payload)
		charge := batch[index].ByteSize()
		clear(batch[index].Payload)
		batch[index] = LinkSubmission{}
		if err != nil {
			clearSubmissionBatch(batch[index+1:])
			clearWireBatch(wires)
			l.claimOwnerFailure(err)
			l.scheduleOwnerClose()
			return
		}
		wires = append(wires, wire)
		charges = append(charges, gnetWireCharge{submissionBytes: charge})
	}
	if l.isTerminalClaimed() {
		clearWireBatch(wires)
		return
	}
	if len(wires) != 0 {
		if err := l.writeOwnerBatch(conn, wires, charges); err != nil {
			l.claimOwnerFailure(err)
			l.scheduleOwnerClose()
			return
		}
	}
}

func (l *GnetClientLink) writeOwnerBatch(conn gnet.Conn, wires [][]byte, charges []gnetWireCharge) error {
	if len(wires) != len(charges) {
		clearWireBatch(wires)
		return errors.New("write Middle-End gnet batch: wire and charge counts differ")
	}
	total := 0
	additionalControlItems := 0
	additionalControlBytes := 0
	for index, wire := range wires {
		if len(wire) > int(^uint(0)>>1)-total {
			clearWireBatch(wires)
			return errors.New("write Middle-End gnet batch: byte count overflows int")
		}
		total += len(wire)
		if charges[index].control {
			additionalControlItems++
			additionalControlBytes += len(wire)
		}
	}
	if additionalControlItems > l.maxControlItems-l.ownerControlItems {
		clearWireBatch(wires)
		return fmt.Errorf("%w: %d pending plus %d new exceeds %d",
			ErrGnetControlItemBackpressure, l.ownerControlItems, additionalControlItems, l.maxControlItems)
	}
	if additionalControlBytes > l.maxControlBytes-l.ownerControlBytes {
		clearWireBatch(wires)
		return fmt.Errorf("%w: %d pending plus %d new exceeds %d",
			ErrGnetControlByteBackpressure, l.ownerControlBytes, additionalControlBytes, l.maxControlBytes)
	}
	// gnet v2.10 mutates the outer slice while it advances through a partial
	// write and copies every unsent byte into its own outbound buffer. Preserve
	// the original entries long enough to record boundaries, then drop the
	// link-owned ciphertext immediately after the synchronous call returns.
	// Ciphertext is public wire data; unlike plaintext and keys, wiping it adds
	// no secrecy and would zero every transmitted byte on the owner-loop path.
	written, err := conn.Writev(slices.Clone(wires))
	for index := range wires {
		charges[index].wireBytes = len(wires[index])
		wires[index] = nil
	}
	if err != nil || written != total {
		return writeResultError("application", written, total, err)
	}
	for _, charge := range charges {
		if uint64(charge.wireBytes) > ^uint64(0)-l.ownerWireTotal {
			return errors.New("write Middle-End gnet batch: wire cursor overflow")
		}
		l.ownerWireTotal += uint64(charge.wireBytes)
		l.ownerWireSegments = append(l.ownerWireSegments, gnetWireSegment{
			end:             l.ownerWireTotal,
			submissionBytes: charge.submissionBytes,
			wireBytes:       charge.wireBytes,
			control:         charge.control,
		})
		if charge.control {
			l.ownerControlItems++
			l.ownerControlBytes += charge.wireBytes
			l.ownerControlItemHighWater = max(l.ownerControlItemHighWater, l.ownerControlItems)
			l.ownerControlByteHighWater = max(l.ownerControlByteHighWater, l.ownerControlBytes)
		}
	}
	return l.observeOwnerOutbound(conn, true)
}

func (l *GnetClientLink) observeOwnerOutbound(conn gnet.Conn, afterWrite bool) error {
	outbound := conn.OutboundBuffered()
	if outbound < 0 || uint64(outbound) > l.ownerWireTotal {
		return fmt.Errorf("observe Middle-End gnet outbound buffer: %d buffered with %d tracked", outbound, l.ownerWireTotal)
	}
	if outbound > l.maxOutboundBytes {
		return fmt.Errorf("%w: %d exceeds %d", ErrGnetOutboundBackpressure, outbound, l.maxOutboundBytes)
	}
	consumed := l.ownerWireTotal - uint64(outbound)
	releasedItems := 0
	releasedBytes := 0
	releasedControlItems := 0
	releasedControlBytes := 0
	releasedSegments := 0
	for _, segment := range l.ownerWireSegments {
		if segment.end > consumed {
			break
		}
		releasedItems += boolInt(segment.submissionBytes != 0)
		releasedBytes += segment.submissionBytes
		if segment.control {
			releasedControlItems++
			releasedControlBytes += segment.wireBytes
		}
		releasedSegments++
	}
	if releasedSegments != 0 {
		clear(l.ownerWireSegments[:releasedSegments])
		l.ownerWireSegments = l.ownerWireSegments[releasedSegments:]
		if len(l.ownerWireSegments) == 0 {
			l.ownerWireSegments = nil
		}
	}
	if releasedItems != 0 {
		l.mu.Lock()
		if releasedItems > l.pendingSubmissions || releasedBytes > l.pendingSubmissionBytes {
			l.mu.Unlock()
			return errors.New("observe Middle-End gnet outbound buffer: submission accounting underflow")
		}
		l.pendingSubmissions -= releasedItems
		l.pendingSubmissionBytes -= releasedBytes
		if l.state == LinkStateReady && !l.terminalClaimed {
			signalSubmissionReady(l.submissionReady)
		}
		l.mu.Unlock()
	}
	if releasedControlItems > l.ownerControlItems || releasedControlBytes > l.ownerControlBytes {
		return errors.New("observe Middle-End gnet outbound buffer: control accounting underflow")
	}
	l.ownerControlItems -= releasedControlItems
	l.ownerControlBytes -= releasedControlBytes
	if len(l.ownerWireSegments) == 0 {
		l.cancelOutboundPoll()
		l.scheduleNextDrain()
	} else if outbound != 0 {
		delay := gnetOutboundPollBacklog
		if afterWrite {
			delay = gnetOutboundPollFast
		}
		l.scheduleOutboundPoll(delay)
		if outbound <= gnetDrainResumeOutboundBytes {
			l.scheduleNextDrain()
		}
	}
	return nil
}

func (l *GnetClientLink) cancelOutboundPoll() {
	l.mu.Lock()
	if l.pollTimer != nil {
		l.pollTimer.Stop()
		l.pollTimer = nil
	}
	l.pollScheduled = false
	l.pollDelay = 0
	l.mu.Unlock()
}

func (l *GnetClientLink) scheduleOutboundPoll(delay time.Duration) {
	l.mu.Lock()
	if l.terminalClaimed || l.finalized || (l.pollScheduled && l.pollDelay <= delay) {
		l.mu.Unlock()
		return
	}
	l.pollScheduled = true
	l.pollDelay = delay
	if l.pollTimer == nil {
		l.pollTimer = time.AfterFunc(delay, l.fireOutboundPoll)
	} else {
		l.pollTimer.Reset(delay)
	}
	l.mu.Unlock()
}

func (l *GnetClientLink) fireOutboundPoll() {
	l.mu.Lock()
	if !l.pollScheduled || l.terminalClaimed || l.finalized {
		l.pollScheduled = false
		l.pollDelay = 0
		l.mu.Unlock()
		return
	}
	l.pollScheduled = false
	l.pollDelay = 0
	conn := l.gconn
	l.mu.Unlock()
	if conn == nil {
		l.failExternal(errors.New("poll Middle-End gnet outbound buffer: missing owner connection"))
		return
	}
	// Wake is gnet v2.10's concurrency-safe path to OnTraffic on this
	// connection's owning loop. OnTraffic performs the outbound observation
	// before it reads inbound bytes, so no separate Execute closure is needed.
	if err := conn.Wake(nil); err != nil {
		l.failExternal(fmt.Errorf("schedule Middle-End gnet outbound poll: %w", err))
	}
}

func (l *GnetClientLink) scheduleNextDrain() {
	l.mu.Lock()
	if l.terminalClaimed || l.finalized || len(l.submissions) == 0 || l.drainScheduled {
		l.mu.Unlock()
		return
	}
	l.drainScheduled = true
	owner := l.owner
	l.mu.Unlock()
	l.scheduleDrain(owner)
}

func (l *GnetClientLink) failExternal(err error) {
	l.requestTerminal(err)
}

func (l *GnetClientLink) claimOwnerFailure(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	l.claimTerminal(err)
}

func (l *GnetClientLink) requestTerminal(err error) {
	claimed := l.claimTerminal(err)
	if !claimed {
		return
	}
	if !l.scheduleOwnerClose() {
		l.finalizeIfUnenrolled()
	}
}

func (l *GnetClientLink) claimTerminal(err error) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.claimTerminalLocked(err)
}

func (l *GnetClientLink) claimTerminalLocked(err error) bool {
	if l.terminalClaimed || l.finalized {
		return false
	}
	l.terminalClaimed = true
	l.terminalErr = err
	l.state = LinkStateClosing
	if l.pollTimer != nil {
		l.pollTimer.Stop()
		l.pollTimer = nil
	}
	l.pollScheduled = false
	l.pollDelay = 0
	if !l.startPublished {
		startResult := err
		if startResult == nil {
			startResult = ErrLinkClosed
		}
		l.publishStartLocked(startResult)
	}
	return true
}

func (l *GnetClientLink) isTerminalClaimed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.terminalClaimed || l.finalized
}

func (l *GnetClientLink) scheduleOwnerClose() bool {
	l.mu.Lock()
	if l.finalized || l.closeScheduled {
		l.mu.Unlock()
		return true
	}
	owner := l.owner
	conn := l.gconn
	if owner == nil || conn == nil {
		started := l.startInitiated
		l.mu.Unlock()
		_ = l.conn.Close()
		return started
	}
	l.closeScheduled = true
	l.mu.Unlock()

	err := owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		return owner.Close(conn)
	}))
	if err != nil {
		l.runtime.beginStop()
	}
	return true
}

func (l *GnetClientLink) finalizeIfUnenrolled() {
	l.mu.Lock()
	unenrolled := l.owner == nil
	l.mu.Unlock()
	if unenrolled {
		_ = l.conn.Close()
		l.finalizeAfterStreamClose()
	}
}

func (l *GnetClientLink) finalizeAfterStreamClose() {
	l.mu.Lock()
	if l.finalized {
		l.mu.Unlock()
		return
	}
	if !l.terminalClaimed {
		l.terminalClaimed = true
		l.terminalErr = net.ErrClosed
		l.state = LinkStateClosing
		if !l.startPublished {
			l.publishStartLocked(l.terminalErr)
		}
	}
	if l.pollTimer != nil {
		l.pollTimer.Stop()
		l.pollTimer = nil
	}
	l.pollScheduled = false
	l.pollDelay = 0
	l.drainScheduled = false
	for index := range l.submissions {
		clear(l.submissions[index].Payload)
		l.submissions[index] = LinkSubmission{}
	}
	l.submissions = nil
	// gnet owns any residual encrypted outbound copies. The link retains only
	// byte boundaries and charges, so finalization can discard the ledger.
	clear(l.ownerWireSegments)
	l.ownerWireSegments = nil
	l.ownerWireTotal = 0
	l.ownerControlItems = 0
	l.ownerControlBytes = 0
	// I/O has ended, so the link can actively retire the ready bootstrap's
	// expanded CBC state and partial frame buffers. Published events own cloned
	// payloads and are not backed by this state.
	l.bootstrap.retire()
	l.pendingSubmissions = 0
	l.pendingSubmissionBytes = 0
	clear(l.eventCharges)
	l.eventCharges = nil
	l.pendingEvents = 0
	l.pendingEventBytes = 0
	close(l.events)
	l.state = LinkStateClosed
	l.finalized = true
	l.mu.Unlock()

	l.runtime.removeLink(l)
	close(l.done)
}

func writeResultError(stage string, written int, want int, err error) error {
	if err != nil {
		return fmt.Errorf("write Middle-End gnet %s bytes: wrote %d of %d: %w", stage, written, want, err)
	}
	return fmt.Errorf("write Middle-End gnet %s bytes: wrote %d of %d: %w", stage, written, want, io.ErrShortWrite)
}

func clearSubmissionBatch(batch []LinkSubmission) {
	for index := range batch {
		clear(batch[index].Payload)
		batch[index] = LinkSubmission{}
	}
}

func clearWireBatch(wires [][]byte) {
	for index := range wires {
		clear(wires[index])
		wires[index] = nil
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func maximumGnetOutboundBytes(limits LinkLimits) (int, error) {
	maximumInt := int(^uint(0) >> 1)
	if limits.MaxPendingSubmissions > (maximumInt-limits.MaxPendingSubmissionBytes)/maxLinkSubmissionWireOverhead {
		return 0, fmt.Errorf("%w: derived gnet outbound byte limit overflows int", ErrInvalidLinkLimits)
	}
	submissionBytes := limits.MaxPendingSubmissionBytes + limits.MaxPendingSubmissions*maxLinkSubmissionWireOverhead
	controlBytes := max(gnetEncryptedPongSize, limits.MaxPendingEventBytes)
	if controlBytes > maximumInt-submissionBytes {
		return 0, fmt.Errorf("%w: derived gnet outbound byte limit overflows int", ErrInvalidLinkLimits)
	}
	return submissionBytes + controlBytes, nil
}
