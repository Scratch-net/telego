package gproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// LogicalQueueBudget charges retained payload capacity and queue items. The
// integration adds its standard item overhead. Callbacks must be thread-safe,
// must not call the stream, and must remain available until OnClosed returns.
// Existing ME decoder/request storage remains in the frontend's separate hard
// process budget; the logical transport does not duplicate that accounting.
type LogicalQueueBudget struct {
	Reserve func(bytes, items int) bool
	Release func(bytes, items int)
}

// LogicalStreamOptions supplies trusted process-local ingress metadata. The
// owner remains fixed across HTTP requests, carrier lanes, and reconnects.
type LogicalStreamOptions struct {
	Owner      gnet.EventLoop
	ClientAddr netip.AddrPort
	LocalAddr  net.Addr
	// MaxInputBytes bounds parser staging (at most one item). Extra handshake
	// and upstream relay storage is separately bounded by the core's record
	// and relay limits, and charged to the same external InputBudget.
	MaxInputBytes  int
	MaxOutputBytes int
	MaxInputItems  int
	MaxOutputItems int
	InputBudget    LogicalQueueBudget
	OutputBudget   LogicalQueueBudget
	Notify         func()
	OnOpened       func(error)
	OnClosed       func(error)
}

var ErrLogicalStreamConfig = errors.New("invalid logical MTProxy stream configuration")

// LogicalStream is an MTProxy client driven by a real gnet owner loop. TryRead
// and TryWrite never block and run on that owner; (0, nil) means would block.
// Close may run anywhere. OnClosed acknowledges completed owner cleanup.
// For ME, this means detaching the client route and releasing logical queues;
// the shared manager still owns accepted requests and pending close controls.
type LogicalStream struct {
	handler *ProxyHandler
	ctx     *ConnContext
	options LogicalStreamOptions
	local   net.Addr
	remote  *net.TCPAddr

	// ownerMu also serializes terminal cleanup if the engine rejects new work.
	ownerMu             sync.Mutex
	opened              bool
	finished            bool
	openNotified        bool
	input               []byte
	inputOffset         int
	preparedOutput      int
	inputRetry          *time.Timer
	terminal            error
	requestedClose      atomic.Bool
	scheduled           atomic.Bool
	completionScheduled atomic.Bool
	fallbackClose       sync.Once
	work                atomic.Int64
	closedNotified      bool
	tasksMu             sync.Mutex
	ownerStopped        bool
	tasks               map[*logicalTask]struct{}
	auxMu               sync.Mutex
	auxBytes            int
	auxItems            int

	// Output reservations can originate on the direct DC loop. Queue reads
	// and writes remain on the client owner; counters cover both stages.
	outputMu       sync.Mutex
	output         [][]byte
	outputOffset   int
	outputBytes    int
	outputCapacity int
	outputItems    int
	reservedBytes  int
	reservedItems  int

	outputOrderMu sync.Mutex
	outputHead    *logicalOutputTask
	outputTail    *logicalOutputTask
	outputRunning bool
	outputError   error
}

func (h *ProxyHandler) OpenLogicalStream(options LogicalStreamOptions) (*LogicalStream, error) {
	if options.Owner == nil || !options.ClientAddr.IsValid() || options.ClientAddr.Addr().IsUnspecified() ||
		options.ClientAddr.Addr().Zone() != "" || options.LocalAddr == nil ||
		options.MaxInputBytes <= 0 || options.MaxOutputBytes <= 0 || options.MaxInputItems <= 0 || options.MaxOutputItems <= 0 ||
		options.InputBudget.Reserve == nil || options.InputBudget.Release == nil ||
		options.OutputBudget.Reserve == nil || options.OutputBudget.Release == nil ||
		options.Notify == nil || options.OnOpened == nil || options.OnClosed == nil {
		return nil, ErrLogicalStreamConfig
	}
	// The protocol parser only needs one complete wire record. A fixed staging
	// maximum bounds transient copies during budget ownership transfers.
	options.MaxInputBytes = min(options.MaxInputBytes, relayBatchSize)
	stream := &LogicalStream{
		handler: h, ctx: NewConnContext(), options: options,
		local: options.LocalAddr, remote: net.TCPAddrFromAddrPort(options.ClientAddr),
	}
	if err := stream.schedule(); err != nil {
		return nil, err
	}
	return stream, nil
}

func (s *LogicalStream) execute(run gnet.Runnable) error {
	s.tasksMu.Lock()
	if s.ownerStopped {
		s.tasksMu.Unlock()
		return net.ErrClosed
	}
	task := &logicalTask{stream: s, runnable: run}
	if s.tasks == nil {
		s.tasks = make(map[*logicalTask]struct{})
	}
	s.tasks[task] = struct{}{}
	s.work.Add(1)
	s.tasksMu.Unlock()
	err := s.options.Owner.Execute(context.Background(), task)
	if err != nil {
		task.cancel()
	}
	return err
}

type logicalTask struct {
	stream   *LogicalStream
	runnable gnet.Runnable
	once     sync.Once
}

func (task *logicalTask) remove() {
	task.stream.tasksMu.Lock()
	delete(task.stream.tasks, task)
	task.stream.tasksMu.Unlock()
}

func (task *logicalTask) Run(ctx context.Context) (err error) {
	task.once.Do(func() {
		s := task.stream
		s.ownerMu.Lock()
		defer s.ownerMu.Unlock()
		task.remove()
		defer func() { task.runnable = nil; s.work.Add(-1); s.notifyClosed() }()
		err = task.runnable.Run(ctx)
	})
	return err
}

func (task *logicalTask) cancel() {
	task.once.Do(func() {
		task.remove()
		task.runnable = nil
		task.stream.work.Add(-1)
	})
}

// OwnerStopped retires work accepted but abandoned by gnet during an
// unexpected exit. The integration must call it only after the owning engine
// has returned, when none of its callbacks can still run. Normal shutdown
// closes streams and waits for OnClosed before stopping the engine instead.
func (s *LogicalStream) OwnerStopped() {
	s.tasksMu.Lock()
	if s.ownerStopped {
		s.tasksMu.Unlock()
		return
	}
	s.ownerStopped = true
	pending := make([]*logicalTask, 0, len(s.tasks))
	for task := range s.tasks {
		pending = append(pending, task)
	}
	s.tasksMu.Unlock()
	s.requestedClose.Store(true)
	s.ownerMu.Lock()
	s.finish(net.ErrClosed)
	s.ownerMu.Unlock()
	// Every task checks terminal state before doing client work. Running its
	// terminal branch releases captured output reservations and pool buffers,
	// and closes any upstream enrolled before activation was abandoned.
	for _, task := range pending {
		_ = task.Run(context.Background())
	}
	s.ownerMu.Lock()
	s.notifyClosed()
	s.ownerMu.Unlock()
}

func (s *LogicalStream) schedule() error {
	if !s.scheduled.CompareAndSwap(false, true) {
		return nil
	}
	err := s.execute(gnet.RunnableFunc(func(context.Context) error {
		s.scheduled.Store(false)
		if s.finished {
			return nil
		}
		if s.requestedClose.Load() {
			s.finish(io.EOF)
			return nil
		}
		if !s.opened {
			s.ctx.internalProxyAuthenticated = true
			s.ctx.SetRealClientAddr(s.remote)
			s.ctx.setTrustedProxyTuple(s.remote, s.local)
			s.opened = true
			if s.handler.openClient(s, s.ctx) == gnet.Close {
				s.finish(net.ErrClosed)
				return nil
			}
			s.notifyOpened(nil)
		}
		if s.handler.clientTraffic(s, s.ctx) == gnet.Close {
			s.finish(io.EOF)
		}
		return nil
	}))
	if err != nil {
		s.scheduled.Store(false)
	}
	return err
}

func (s *LogicalStream) notifyOpened(err error) {
	if !s.openNotified {
		s.openNotified = true
		s.options.OnOpened(err)
	}
}

func (s *LogicalStream) Close() error {
	if !s.requestedClose.CompareAndSwap(false, true) {
		return nil
	}
	if err := s.execute(gnet.RunnableFunc(func(context.Context) error {
		s.finish(io.EOF)
		return nil
	})); err != nil {
		// Shutdown rejects Execute after stopping admission to the loop. The
		// mutex waits for any accepted logical task before releasing resources.
		s.fallbackClose.Do(func() {
			go func() {
				s.ownerMu.Lock()
				defer s.ownerMu.Unlock()
				s.finish(err)
				s.notifyClosed()
			}()
		})
		return err
	}
	return nil
}

func (s *LogicalStream) finish(err error) {
	if s.finished {
		return
	}
	s.finished = true
	s.requestedClose.Store(true)
	s.terminal = err
	if s.inputRetry != nil {
		s.inputRetry.Stop()
		s.inputRetry = nil
	}
	if s.opened {
		s.handler.closeClient(s, s.ctx, err)
	} else {
		s.ctx.SetState(StateClosed)
		s.ctx.Cleanup()
	}
	if cap(s.input) > 0 {
		s.options.InputBudget.Release(cap(s.input), 1)
		clear(s.input)
		s.input = nil
	}
	s.outputMu.Lock()
	bytes, items := s.outputCapacity, s.outputItems
	s.output, s.outputBytes, s.outputCapacity, s.outputItems = nil, 0, 0, 0
	s.outputMu.Unlock()
	if bytes != 0 || items != 0 {
		s.options.OutputBudget.Release(bytes, items)
	}
	s.notifyOpened(err)
	s.options.Notify()
}

func (s *LogicalStream) armInputRetry() {
	if s.inputRetry != nil || s.requestedClose.Load() {
		return
	}
	s.inputRetry = time.AfterFunc(relayDrainInterval, func() {
		if err := s.execute(gnet.RunnableFunc(func(context.Context) error {
			s.inputRetry = nil
			if !s.requestedClose.Load() {
				return s.schedule()
			}
			return nil
		})); err != nil {
			_ = s.Close()
		}
	})
}

func (s *LogicalStream) notifyClosed() {
	if !s.finished || s.closedNotified || s.work.Load() != 0 {
		return
	}
	s.auxMu.Lock()
	auxiliary := s.auxBytes != 0 || s.auxItems != 0
	s.auxMu.Unlock()
	s.outputMu.Lock()
	reserved := s.reservedBytes != 0 || s.reservedItems != 0
	s.outputMu.Unlock()
	if auxiliary || reserved {
		return
	}
	s.closedNotified = true
	s.options.OnClosed(s.terminal)
}

func retainLogicalWork(c clientEndpoint) func() {
	s, ok := c.(*LogicalStream)
	if !ok {
		return func() {}
	}
	s.work.Add(1)
	return sync.OnceFunc(func() {
		s.work.Add(-1)
		s.requestCompletion()
	})
}

func (s *LogicalStream) requestCompletion() {
	if !s.requestedClose.Load() || !s.completionScheduled.CompareAndSwap(false, true) {
		return
	}
	if err := s.execute(gnet.RunnableFunc(func(context.Context) error {
		s.completionScheduled.Store(false)
		return nil
	})); err != nil {
		go func() {
			s.ownerMu.Lock()
			defer s.ownerMu.Unlock()
			s.completionScheduled.Store(false)
			s.notifyClosed()
		}()
	}
}

func (s *LogicalStream) reserveAuxInput(bytes, items int) bool {
	s.auxMu.Lock()
	defer s.auxMu.Unlock()
	if s.requestedClose.Load() || !s.options.InputBudget.Reserve(bytes, items) {
		return false
	}
	s.auxBytes += bytes
	s.auxItems += items
	return true
}

func (s *LogicalStream) releaseAuxInput(bytes, items int) {
	if bytes == 0 && items == 0 {
		return
	}
	s.auxMu.Lock()
	s.auxBytes -= bytes
	s.auxItems -= items
	s.auxMu.Unlock()
	s.options.InputBudget.Release(bytes, items)
	s.requestCompletion()
}

func (s *LogicalStream) TryWrite(data []byte) (int, error) {
	s.ownerMu.Lock()
	defer s.ownerMu.Unlock()
	if s.finished || s.requestedClose.Load() {
		return 0, net.ErrClosed
	}
	if !s.opened || len(data) == 0 {
		return 0, nil
	}
	n := min(len(data), 64*1024, s.options.MaxInputBytes-s.InboundBuffered())
	if n <= 0 {
		return 0, nil
	}
	if s.inputOffset > 0 && cap(s.input)-len(s.input) < n {
		copy(s.input, s.input[s.inputOffset:])
		s.input = s.input[:s.InboundBuffered()]
		s.inputOffset = 0
	}
	needed := len(s.input) + n
	if needed > cap(s.input) {
		capacity := min(s.options.MaxInputBytes, max(needed, 2*cap(s.input)))
		items := 0
		if cap(s.input) == 0 {
			items = 1
		}
		if !s.options.InputBudget.Reserve(capacity-cap(s.input), items) {
			capacity = needed
			if !s.options.InputBudget.Reserve(capacity-cap(s.input), items) {
				return 0, nil
			}
		}
		grown := make([]byte, len(s.input), capacity)
		copy(grown, s.input)
		s.input = grown
	}
	s.input = append(s.input, data[:n]...)
	if err := s.schedule(); err != nil {
		return n, err
	}
	return n, nil
}

func (s *LogicalStream) TryRead(dst []byte) (int, error) {
	s.ownerMu.Lock()
	defer s.ownerMu.Unlock()
	if s.finished || s.requestedClose.Load() {
		return 0, net.ErrClosed
	}
	s.outputMu.Lock()
	if len(s.output) == 0 || len(dst) == 0 {
		s.outputMu.Unlock()
		return 0, nil
	}
	data := s.output[0]
	n := copy(dst[:min(len(dst), 64*1024)], data[s.outputOffset:])
	s.outputOffset += n
	s.outputBytes -= n
	released := 0
	if s.outputOffset == len(data) {
		released = cap(data)
		s.output[0] = nil
		s.output = s.output[1:]
		s.outputOffset = 0
		s.outputCapacity -= released
		s.outputItems--
	}
	s.outputMu.Unlock()
	if released > 0 {
		s.options.OutputBudget.Release(released, 1)
	}
	_ = s.schedule()
	return n, nil
}

func (s *LogicalStream) Peek(n int) ([]byte, error) {
	data := s.input[s.inputOffset:]
	if n < 0 {
		return data, nil
	}
	if n > len(data) {
		return nil, io.ErrShortBuffer
	}
	return data[:n], nil
}

func (s *LogicalStream) Discard(n int) (int, error) {
	if n < 0 || n > s.InboundBuffered() {
		return 0, io.ErrShortBuffer
	}
	s.inputOffset += n
	if s.inputOffset == len(s.input) && cap(s.input) > 0 {
		s.options.InputBudget.Release(cap(s.input), 1)
		s.input = nil
		s.inputOffset = 0
	}
	if n > 0 {
		s.options.Notify()
	}
	return n, nil
}

func (s *LogicalStream) InboundBuffered() int { return len(s.input) - s.inputOffset }
func (s *LogicalStream) LocalAddr() net.Addr  { return s.local }
func (s *LogicalStream) RemoteAddr() net.Addr { return s.remote }

func (s *LogicalStream) OutboundBuffered() int {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	return s.outputBytes
}

// ReadableBytes lets the owner reserve an exact destination before TryRead.
func (s *LogicalStream) ReadableBytes() int { return s.OutboundBuffered() }

func (s *LogicalStream) reserveOutput(want, minimum int) int {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	if s.requestedClose.Load() || s.outputItems+s.reservedItems >= s.options.MaxOutputItems {
		return 0
	}
	n := min(want, s.options.MaxOutputBytes-s.outputCapacity-s.reservedBytes)
	if n < minimum {
		return 0
	}
	if !s.options.OutputBudget.Reserve(n, 1) {
		if n == minimum || !s.options.OutputBudget.Reserve(minimum, 1) {
			return 0
		}
		n = minimum
	}
	s.reservedBytes += n
	s.reservedItems++
	return n
}

func (s *LogicalStream) releaseOutput(bytes, items int) {
	if bytes == 0 && items == 0 {
		return
	}
	s.outputMu.Lock()
	s.reservedBytes -= bytes
	s.reservedItems -= items
	s.outputMu.Unlock()
	s.options.OutputBudget.Release(bytes, items)
	s.requestCompletion()
}

func (s *LogicalStream) writeReserved(data []byte) error {
	s.outputMu.Lock()
	if s.requestedClose.Load() {
		s.outputMu.Unlock()
		s.releaseOutput(len(data), 1)
		return net.ErrClosed
	}
	if len(data) > s.reservedBytes || s.reservedItems == 0 {
		s.outputMu.Unlock()
		return io.ErrShortBuffer
	}
	buffer := make([]byte, len(data))
	copy(buffer, data)
	s.reservedBytes -= len(data)
	s.reservedItems--
	s.output = append(s.output, buffer)
	s.outputBytes += len(data)
	s.outputCapacity += len(data)
	s.outputItems++
	s.outputMu.Unlock()
	s.options.Notify()
	return nil
}

func (s *LogicalStream) Write(data []byte) (int, error) {
	reservation := s.preparedOutput
	if reservation != 0 {
		if len(data) > reservation {
			return 0, io.ErrShortBuffer
		}
		s.preparedOutput = 0
		s.releaseOutput(reservation-len(data), 0)
	} else if s.reserveOutput(len(data), len(data)) == 0 {
		return 0, io.ErrShortBuffer
	}
	if err := s.writeReserved(data); err != nil {
		return 0, err
	}
	return len(data), nil
}
