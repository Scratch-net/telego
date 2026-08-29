package middleend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// BlockingClientLinkEngine is the goroutine-per-link reference implementation
// of ClientLink. One owner goroutine performs all protocol decoding and
// encoding. Two I/O goroutines only read and write opaque socket bytes. This
// keeps both directions of ClientBootstrap under one owner while allowing
// full-duplex progress and letting Close interrupt blocked I/O.
type BlockingClientLinkEngine struct {
	conn      net.Conn
	bootstrap *ClientBootstrap
	limits    LinkLimits

	mu          sync.Mutex
	state       LinkState
	startResult error
	startSet    bool
	terminalErr error
	closeResult error

	pendingSubmissions       int
	pendingSubmissionBytes   int
	submissionHighWater      int
	submissionBytesHighWater int
	submissions              []*blockingSubmission

	pendingEvents       int
	pendingEventBytes   int
	eventHighWater      int
	eventBytesHighWater int
	eventSizes          []int

	startDone          chan struct{}
	done               chan struct{}
	events             chan LinkEvent
	submissionQueued   chan struct{}
	submissionCapacity chan struct{}
	readResults        chan blockingReadResult
	writeJobs          chan *blockingWriteJob
	writeResults       chan blockingWriteResult
	terminalRequested  chan struct{}
	readerDone         chan struct{}
	writerDone         chan struct{}
	readerStarted      bool
	writerStarted      bool

	closeConnOnce sync.Once
	finishOnce    sync.Once
}

type blockingSubmission struct {
	value LinkSubmission
}

type blockingReadResult struct {
	data []byte
	err  error
}

type blockingWriteJob struct {
	wire       []byte
	submission *blockingSubmission
}

type blockingWriteResult struct {
	job *blockingWriteJob
	err error
}

// NewBlockingClientLinkEngine constructs an unstarted reference link over an
// already-established stream. The link owns conn and bootstrap after a
// successful return.
func NewBlockingClientLinkEngine(
	conn net.Conn,
	bootstrap *ClientBootstrap,
	limits LinkLimits,
) (*BlockingClientLinkEngine, error) {
	if conn == nil {
		return nil, errors.New("create blocking Middle-End link: nil connection")
	}
	if bootstrap == nil {
		return nil, errors.New("create blocking Middle-End link: nil bootstrap")
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	writeQueueSize := limits.MaxPendingEvents + 1
	return &BlockingClientLinkEngine{
		conn:               conn,
		bootstrap:          bootstrap,
		limits:             limits,
		state:              LinkStateCreated,
		startDone:          make(chan struct{}),
		done:               make(chan struct{}),
		events:             make(chan LinkEvent, limits.MaxPendingEvents),
		submissionQueued:   make(chan struct{}, 1),
		submissionCapacity: make(chan struct{}, 1),
		readResults:        make(chan blockingReadResult, 1),
		writeJobs:          make(chan *blockingWriteJob, writeQueueSize),
		writeResults:       make(chan blockingWriteResult, writeQueueSize),
		terminalRequested:  make(chan struct{}),
		readerDone:         make(chan struct{}),
		writerDone:         make(chan struct{}),
	}, nil
}

// String prevents accidental disclosure through queued RPC payloads and the
// enclosed bootstrap cipher state.
func (*BlockingClientLinkEngine) String() string {
	return "middleend.BlockingClientLinkEngine{redacted}"
}

// GoString prevents accidental disclosure through queued RPC payloads and the
// enclosed bootstrap cipher state.
func (*BlockingClientLinkEngine) GoString() string {
	return "middleend.BlockingClientLinkEngine{redacted}"
}

// Start performs the bilateral bootstrap exactly once. The first caller's
// context applies only until readiness; later calls share its stored result.
func (l *BlockingClientLinkEngine) Start(ctx context.Context) error {
	if l == nil {
		return ErrLinkClosed
	}

	l.mu.Lock()
	switch l.state {
	case LinkStateCreated:
		l.state = LinkStateBootstrapping
		l.mu.Unlock()
		return l.startFirst(ctx)
	case LinkStateBootstrapping:
		startDone := l.startDone
		l.mu.Unlock()
		<-startDone
		return l.loadStartResult()
	case LinkStateReady:
		result := l.startResult
		l.mu.Unlock()
		return result
	case LinkStateClosing, LinkStateClosed:
		if l.startSet {
			result := l.startResult
			l.mu.Unlock()
			return result
		}
		startDone := l.startDone
		l.mu.Unlock()
		<-startDone
		return l.loadStartResult()
	default:
		l.mu.Unlock()
		return ErrLinkClosed
	}
}

func (l *BlockingClientLinkEngine) startFirst(ctx context.Context) error {
	diagnostic, err := BootstrapBlocking(ctx, l.conn, l.bootstrap)
	if err != nil {
		won, _ := l.beginTerminal(err)
		result := err
		if !won && l.loadTerminalError() == nil {
			result = ErrLinkClosed
		}
		l.publishStart(result)
		l.finishTerminal(nil)
		return result
	}

	initialFrames := diagnostic.inbox
	diagnostic.inbox = nil
	pendingReadErr := diagnostic.pendingReadErr
	diagnostic.pendingReadErr = nil
	clear(diagnostic.readBuf)
	diagnostic.readBuf = nil

	l.mu.Lock()
	if l.state != LinkStateBootstrapping {
		l.mu.Unlock()
		clearFrames(initialFrames)
		l.publishStart(ErrLinkClosed)
		l.finishTerminal(nil)
		return ErrLinkClosed
	}
	l.readerStarted = true
	l.writerStarted = true
	go l.readLoop()
	go l.writeLoop()
	go l.ownerLoop(initialFrames, pendingReadErr)
	l.state = LinkStateReady
	l.publishStartLocked(nil)
	l.mu.Unlock()
	return nil
}

// TrySubmit accepts a validated RPC without blocking. Accepted payloads remain
// charged until the socket consumes their complete encoded frame.
func (l *BlockingClientLinkEngine) TrySubmit(submission LinkSubmission) error {
	if l == nil {
		return ErrLinkClosed
	}

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
	l.mu.Unlock()

	if err := submission.Validate(); err != nil {
		return err
	}
	size := submission.ByteSize()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != LinkStateReady {
		return ErrLinkClosed
	}
	if size > l.limits.MaxPendingSubmissionBytes {
		return fmt.Errorf("%w: %d exceeds %d", ErrLinkSubmissionTooLarge, size, l.limits.MaxPendingSubmissionBytes)
	}
	if l.pendingSubmissions >= l.limits.MaxPendingSubmissions ||
		size > l.limits.MaxPendingSubmissionBytes-l.pendingSubmissionBytes {
		return ErrLinkBackpressure
	}

	l.submissions = append(l.submissions, &blockingSubmission{value: submission})
	l.pendingSubmissions++
	l.pendingSubmissionBytes += size
	l.submissionHighWater = max(l.submissionHighWater, l.pendingSubmissions)
	l.submissionBytesHighWater = max(l.submissionBytesHighWater, l.pendingSubmissionBytes)
	select {
	case l.submissionQueued <- struct{}{}:
	default:
	}
	return nil
}

// SubmissionReady returns the stable coalesced capacity notification channel.
func (l *BlockingClientLinkEngine) SubmissionReady() <-chan struct{} {
	if l == nil {
		return nil
	}
	return l.submissionCapacity
}

// Events returns the single-consumer stream of validated peer RPCs.
func (l *BlockingClientLinkEngine) Events() <-chan LinkEvent {
	if l == nil {
		return nil
	}
	return l.events
}

// Snapshot returns a concurrency-safe instantaneous accounting view.
func (l *BlockingClientLinkEngine) Snapshot() LinkSnapshot {
	if l == nil {
		return LinkSnapshot{State: LinkStateClosed}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reconcileConsumedEventsLocked()
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

// Done closes after terminal event and counter publication is complete.
func (l *BlockingClientLinkEngine) Done() <-chan struct{} {
	if l == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return l.done
}

// Err returns the first terminal protocol or transport error. An explicit
// Close that wins the terminal race leaves Err nil.
func (l *BlockingClientLinkEngine) Err() error {
	if l == nil {
		return nil
	}
	return l.loadTerminalError()
}

// Close is idempotent. It closes the stream to interrupt blocked I/O and waits
// for the owner to publish the complete terminal state.
func (l *BlockingClientLinkEngine) Close() error {
	if l == nil {
		return nil
	}
	won, previous := l.beginTerminal(nil)
	if won && previous == LinkStateCreated {
		l.publishStart(ErrLinkClosed)
		l.finishTerminal(nil)
	}
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeResult
}

func (l *BlockingClientLinkEngine) ownerLoop(initialFrames []Frame, pendingReadErr error) {
	var active *blockingSubmission
	defer func() { l.finishTerminal(active) }()

	for index := range initialFrames {
		if err := l.handleFrame(initialFrames[index]); err != nil {
			clearFrames(initialFrames[index+1:])
			l.beginTerminal(err)
			return
		}
		initialFrames[index] = Frame{}
	}
	if pendingReadErr != nil {
		if err := l.bootstrap.Finish(); err != nil {
			l.beginTerminal(err)
		} else {
			l.beginTerminal(pendingReadErr)
		}
		return
	}

	for {
		select {
		case <-l.terminalRequested:
			return
		case <-l.submissionQueued:
			if active != nil || len(l.writeJobs) == cap(l.writeJobs) {
				continue
			}
			active = l.takeSubmission()
			if active == nil {
				continue
			}
			wire, err := l.bootstrap.Encode(active.value.Payload)
			if err != nil {
				l.beginTerminal(err)
				return
			}
			l.writeJobs <- &blockingWriteJob{wire: wire, submission: active}
		case result := <-l.writeResults:
			if result.err != nil {
				l.beginTerminal(result.err)
				return
			}
			if result.job.submission != nil {
				l.releaseSubmission(result.job.submission)
				if result.job.submission == active {
					active = nil
				}
			}
			result.job = nil
			l.wakeSubmissionOwner()
		case result := <-l.readResults:
			if len(result.data) != 0 {
				err := l.processRead(result.data)
				clear(result.data)
				if err != nil {
					l.beginTerminal(err)
					return
				}
			}
			if result.err != nil {
				if err := l.bootstrap.Finish(); err != nil {
					l.beginTerminal(err)
				} else {
					l.beginTerminal(fmt.Errorf("read blocking Middle-End link: %w", result.err))
				}
				return
			}
		}
	}
}

func (l *BlockingClientLinkEngine) writeLoop() {
	defer close(l.writerDone)
	for {
		select {
		case <-l.terminalRequested:
			return
		case job := <-l.writeJobs:
			err := l.writeWire(job.wire)
			clear(job.wire)
			job.wire = nil
			result := blockingWriteResult{job: job, err: err}
			select {
			case l.writeResults <- result:
			case <-l.terminalRequested:
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func (l *BlockingClientLinkEngine) readLoop() {
	defer close(l.readerDone)
	for {
		select {
		case <-l.terminalRequested:
			return
		default:
		}

		buffer := make([]byte, 32<<10)
		read, err := l.conn.Read(buffer)
		if read == 0 {
			clear(buffer)
			buffer = nil
			if err == nil {
				err = io.ErrNoProgress
			}
		} else {
			buffer = buffer[:read]
		}
		result := blockingReadResult{data: buffer, err: err}
		select {
		case l.readResults <- result:
		case <-l.terminalRequested:
			clear(result.data)
			return
		}
		if err != nil {
			return
		}
	}
}

func (l *BlockingClientLinkEngine) processRead(data []byte) error {
	remaining := data
	for len(remaining) != 0 {
		consumed, update, err := l.bootstrap.Feed(remaining)
		if err != nil {
			return err
		}
		if consumed == 0 {
			return io.ErrNoProgress
		}
		remaining = remaining[consumed:]
		if len(update.Outbound) != 0 {
			if err := l.enqueueProtocolWrite(update.Outbound); err != nil {
				clear(update.Outbound)
				clearFrames(update.Frames)
				return err
			}
		}
		for index := range update.Frames {
			if err := l.handleFrame(update.Frames[index]); err != nil {
				clearFrames(update.Frames[index+1:])
				return err
			}
			update.Frames[index] = Frame{}
		}
	}
	return nil
}

func (l *BlockingClientLinkEngine) handleFrame(frame Frame) error {
	defer clear(frame.Payload)
	event, err := parseLinkEvent(frame.Payload)
	if err != nil {
		return err
	}
	if event.Kind == LinkEventPing {
		pong := (Pong{ID: event.KeepaliveID}).MarshalBinary()
		wire, err := l.bootstrap.Encode(pong)
		clear(pong)
		if err != nil {
			return err
		}
		if err := l.enqueueProtocolWrite(wire); err != nil {
			clear(wire)
			return err
		}
	}
	return l.publishEvent(event)
}

func (l *BlockingClientLinkEngine) enqueueProtocolWrite(wire []byte) error {
	job := &blockingWriteJob{wire: wire}
	select {
	case l.writeJobs <- job:
		return nil
	default:
		return fmt.Errorf("queue blocking Middle-End protocol write: %w", ErrLinkBackpressure)
	}
}

func (l *BlockingClientLinkEngine) publishEvent(event LinkEvent) error {
	size := event.ByteSize()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != LinkStateReady {
		clear(event.Packet)
		return ErrLinkClosed
	}
	l.reconcileConsumedEventsLocked()
	if l.pendingEvents >= l.limits.MaxPendingEvents ||
		size > l.limits.MaxPendingEventBytes-l.pendingEventBytes {
		clear(event.Packet)
		return ErrLinkEventBackpressure
	}

	l.pendingEvents++
	l.pendingEventBytes += size
	l.eventHighWater = max(l.eventHighWater, l.pendingEvents)
	l.eventBytesHighWater = max(l.eventBytesHighWater, l.pendingEventBytes)
	l.eventSizes = append(l.eventSizes, size)
	select {
	case l.events <- event:
		return nil
	default:
		l.eventSizes = l.eventSizes[:len(l.eventSizes)-1]
		l.pendingEvents--
		l.pendingEventBytes -= size
		clear(event.Packet)
		return ErrLinkEventBackpressure
	}
}

func (l *BlockingClientLinkEngine) takeSubmission() *blockingSubmission {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != LinkStateReady || len(l.submissions) == 0 {
		return nil
	}
	submission := l.submissions[0]
	l.submissions[0] = nil
	l.submissions = l.submissions[1:]
	if len(l.submissions) == 0 {
		l.submissions = nil
	}
	return submission
}

func (l *BlockingClientLinkEngine) releaseSubmission(submission *blockingSubmission) {
	l.mu.Lock()
	l.pendingSubmissions--
	l.pendingSubmissionBytes -= submission.value.ByteSize()
	if l.state == LinkStateReady {
		signalSubmissionReady(l.submissionCapacity)
	}
	l.mu.Unlock()
	clear(submission.value.Payload)
	submission.value = LinkSubmission{}
}

func (l *BlockingClientLinkEngine) wakeSubmissionOwner() {
	l.mu.Lock()
	hasQueued := l.state == LinkStateReady && len(l.submissions) != 0
	l.mu.Unlock()
	if !hasQueued {
		return
	}
	select {
	case l.submissionQueued <- struct{}{}:
	default:
	}
}

func (l *BlockingClientLinkEngine) writeWire(wire []byte) error {
	written := 0
	for written < len(wire) {
		count, err := l.conn.Write(wire[written:])
		if count < 0 || count > len(wire)-written {
			return fmt.Errorf("write blocking Middle-End link: invalid count %d", count)
		}
		written += count
		if err != nil {
			return fmt.Errorf("write blocking Middle-End link after %d of %d bytes: %w", written, len(wire), err)
		}
		if count == 0 {
			return fmt.Errorf("write blocking Middle-End link after %d of %d bytes: %w", written, len(wire), io.ErrNoProgress)
		}
	}
	return nil
}

func (l *BlockingClientLinkEngine) beginTerminal(err error) (bool, LinkState) {
	l.mu.Lock()
	if l.state == LinkStateClosing || l.state == LinkStateClosed {
		l.mu.Unlock()
		return false, LinkStateClosing
	}
	previous := l.state
	l.state = LinkStateClosing
	l.terminalErr = err
	close(l.terminalRequested)
	l.mu.Unlock()

	l.closeConnOnce.Do(func() {
		closeErr := l.conn.Close()
		l.mu.Lock()
		l.closeResult = closeErr
		l.mu.Unlock()
	})
	return true, previous
}

func (l *BlockingClientLinkEngine) finishTerminal(active *blockingSubmission) {
	l.finishOnce.Do(func() {
		l.mu.Lock()
		readerStarted := l.readerStarted
		writerStarted := l.writerStarted
		l.mu.Unlock()
		if readerStarted {
			<-l.readerDone
		}
		if writerStarted {
			<-l.writerDone
		}
		l.bootstrap.retire()

		if active != nil {
			clear(active.value.Payload)
			active.value = LinkSubmission{}
		}
		l.mu.Lock()
		for _, submission := range l.submissions {
			if submission != nil {
				clear(submission.value.Payload)
				submission.value = LinkSubmission{}
			}
		}
		clear(l.submissions)
		l.submissions = nil
		for {
			select {
			case result := <-l.readResults:
				clear(result.data)
			default:
				goto readsCleared
			}
		}
	readsCleared:
		for {
			select {
			case job := <-l.writeJobs:
				clear(job.wire)
				job.wire = nil
			default:
				goto writesCleared
			}
		}
	writesCleared:
		for {
			select {
			case result := <-l.writeResults:
				clear(result.job.wire)
				result.job.wire = nil
			default:
				goto writeResultsCleared
			}
		}
	writeResultsCleared:
		l.pendingSubmissions = 0
		l.pendingSubmissionBytes = 0
		clear(l.eventSizes)
		l.eventSizes = nil
		l.pendingEvents = 0
		l.pendingEventBytes = 0
		close(l.events)
		l.state = LinkStateClosed
		l.mu.Unlock()
		close(l.done)
	})
}

func (l *BlockingClientLinkEngine) reconcileConsumedEventsLocked() {
	if l.state == LinkStateClosed {
		return
	}
	buffered := len(l.events)
	consumed := len(l.eventSizes) - buffered
	if consumed <= 0 {
		return
	}
	for _, size := range l.eventSizes[:consumed] {
		l.pendingEvents--
		l.pendingEventBytes -= size
	}
	clear(l.eventSizes[:consumed])
	l.eventSizes = l.eventSizes[consumed:]
	if len(l.eventSizes) == 0 {
		l.eventSizes = nil
	}
}

func (l *BlockingClientLinkEngine) publishStart(result error) {
	l.mu.Lock()
	l.publishStartLocked(result)
	l.mu.Unlock()
}

func (l *BlockingClientLinkEngine) publishStartLocked(result error) {
	if l.startSet {
		return
	}
	l.startResult = result
	l.startSet = true
	close(l.startDone)
}

func (l *BlockingClientLinkEngine) loadStartResult() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.startResult
}

func (l *BlockingClientLinkEngine) loadTerminalError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.terminalErr
}

func clearFrames(frames []Frame) {
	for index := range frames {
		clear(frames[index].Payload)
		frames[index] = Frame{}
	}
}

var _ ClientLink = (*BlockingClientLinkEngine)(nil)
