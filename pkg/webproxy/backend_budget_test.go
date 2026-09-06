package webproxy

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// These tests run real manager/session/pump code without network listeners.
// Owners execute only queued work: tests never manually retry a blocked pump.
type budgetTestOwner struct {
	gnet.EventLoop
	queue  chan gnet.Runnable
	reject atomic.Bool
}

func (o *budgetTestOwner) Execute(_ context.Context, run gnet.Runnable) error {
	if o.reject.Load() {
		return net.ErrClosed
	}
	o.queue <- run
	return nil
}

func (o *budgetTestOwner) drain(t *testing.T) {
	t.Helper()
	for range 100 {
		select {
		case run := <-o.queue:
			if err := run.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
		default:
			return
		}
	}
	t.Fatal("owner did not quiesce")
}

func (o *budgetTestOwner) next(t *testing.T) {
	t.Helper()
	select {
	case run := <-o.queue:
		if err := run.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("global budget release did not notify the blocked owner")
	}
}

type budgetTestFixture struct {
	manager  *Manager
	owners   []*budgetTestOwner
	sessions []*Session
	opened   chan *ownerProbeBackend
}

func newBudgetTestFixture(t *testing.T, count int, mutate ...func(*ManagerConfig)) *budgetTestFixture {
	t.Helper()
	x := &budgetTestFixture{opened: make(chan *ownerProbeBackend, count)}
	config := DefaultManagerConfig(testProfiles(t), "")
	config.Limits.MaxSessions = count
	config.Limits.MaxStreamsPerSession = 2
	config.Limits.MaxPendingPerSession = 128 << 10
	config.Limits.MaxPendingGlobal = max(128<<10, count*(64<<10))
	config.Limits.MaxBodyBytes = 4096
	config.Limits.CarrierBatchBytes = 4096
	config.BackendFactory = ownerProbeFactory(x.opened, RelayDataChunk, false)
	for _, apply := range mutate {
		apply(&config)
	}
	var err error
	x.manager, err = NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, session := range x.sessions {
			session.Close()
		}
		for _, owner := range x.owners {
			owner.reject.Store(false)
			owner.drain(t)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := x.manager.Shutdown(ctx); err != nil {
			t.Error(err)
		}
		if got := x.manager.Capacity(); got.Streams != 0 || got.BackendDials != 0 || got.PendingBytes != 0 || got.PendingItems != 0 {
			t.Errorf("retained capacity: %+v", got)
		}
	})
	for range count {
		owner := &budgetTestOwner{queue: make(chan gnet.Runnable, 128)}
		token, err := x.manager.IssueBootstrap(config.Profiles[0].Capability(), "198.51.100.1")
		if err != nil {
			t.Fatal(err)
		}
		auth, err := x.manager.AuthenticateBootstrap(token)
		if err != nil {
			t.Fatal(err)
		}
		created, err := auth.create("198.51.100.1", testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}}), owner)
		if err != nil {
			t.Fatal(err)
		}
		x.owners = append(x.owners, owner)
		x.sessions = append(x.sessions, created.Session)
	}
	return x
}

func (x *budgetTestFixture) fillGlobal(t *testing.T, class pendingClass) int {
	t.Helper()
	x.manager.mu.Lock()
	limit, _ := x.manager.pendingBudgetLimits(class)
	cost := limit - int(x.manager.pendingBytes)
	x.manager.mu.Unlock()
	producer := x.sessions[0]
	producer.mu.Lock()
	ok := producer.reservePendingLocked(cost, 0, pendingHandoff)
	producer.mu.Unlock()
	if !ok {
		t.Fatal("cannot construct global pressure")
	}
	return cost
}

func (x *budgetTestFixture) releaseGlobal(cost int) {
	producer := x.sessions[0]
	producer.mu.Lock()
	producer.releasePendingLocked(cost, 0)
	producer.mu.Unlock()
}

func (x *budgetTestFixture) openInput(t *testing.T, index int, data []byte) {
	t.Helper()
	if _, err := x.sessions[index].ProcessUp(1, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: data})); err != nil {
		t.Fatal(err)
	}
}

func TestBackendGlobalBudgetReleaseResumesOtherOwner(t *testing.T) {
	x := newBudgetTestFixture(t, 2)
	payload := bytes.Repeat([]byte{1}, 3000)
	x.openInput(t, 1, payload)
	filler := x.fillGlobal(t, pendingBackendInput)
	x.owners[1].drain(t)
	backend := <-x.opened
	if backend.heldBytes != 0 || backend.writes.Load() == 0 {
		t.Fatal("input was not blocked on global budget")
	}
	x.releaseGlobal(filler)
	x.owners[1].next(t)
	if backend.heldBytes != len(payload) {
		t.Fatalf("automatic retry transferred %d bytes", backend.heldBytes)
	}
	x.owners[1].drain(t)
	x.manager.mu.Lock()
	remaining := len(x.manager.budgetWaiters)
	x.manager.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("successful retry retained %d waiters", remaining)
	}
}

func TestBackendGlobalBudgetWakeDoesNotHerdOrSpin(t *testing.T) {
	x := newBudgetTestFixture(t, 3)
	payload := bytes.Repeat([]byte{1}, 3000)
	for index := 1; index < 3; index++ {
		x.openInput(t, index, payload)
	}
	filler := x.fillGlobal(t, pendingBackendInput)
	for index := 1; index < 3; index++ {
		x.owners[index].drain(t)
	}
	first, second := <-x.opened, <-x.opened
	const oneCopy = 3000 + queueItemCost
	x.releaseGlobal(oneCopy)
	x.owners[1].next(t)
	x.owners[1].drain(t)
	if first.heldBytes != len(payload) || second.heldBytes != 0 {
		t.Fatal("one reservation woke the wrong set of backends")
	}
	select {
	case <-x.owners[2].queue:
		t.Fatal("insufficient remaining capacity woke another owner")
	case <-time.After(20 * time.Millisecond):
	}
	x.releaseGlobal(filler - oneCopy)
	x.owners[2].next(t)
	if second.heldBytes != len(payload) {
		t.Fatal("eligible second waiter did not resume")
	}
}

func TestBackendGlobalBudgetCancelAndRetireQueuedWake(t *testing.T) {
	x := newBudgetTestFixture(t, 3)
	for index := 1; index < 3; index++ {
		x.openInput(t, index, []byte{1})
	}
	filler := x.fillGlobal(t, pendingBackendInput)
	for index := 1; index < 3; index++ {
		x.owners[index].drain(t)
	}
	first, second := <-x.opened, <-x.opened
	x.releaseGlobal(filler)
	var abandoned gnet.Runnable
	select {
	case abandoned = <-x.owners[1].queue:
	case <-time.After(time.Second):
		t.Fatal("first owner did not receive notification")
	}
	x.sessions[1].retireBackendOwner()
	x.manager.retireBudgetOwners(map[gnet.EventLoop]struct{}{x.owners[1]: {}})
	x.owners[2].next(t)
	if first.heldBytes != 0 || second.heldBytes != 1 {
		t.Fatal("canceled active waiter blocked the healthy owner")
	}
	if err := abandoned.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	x.manager.mu.Lock()
	retained := len(x.manager.budgetWaiters)
	tasks := len(x.manager.budgetTasks)
	x.manager.mu.Unlock()
	if retained != 0 || tasks != 0 {
		t.Fatalf("retirement retained waiters=%d tasks=%d", retained, tasks)
	}
}

func TestBackendGlobalBudgetRejectedOwnerDoesNotBlockOtherWaiter(t *testing.T) {
	x := newBudgetTestFixture(t, 3)
	for index := 1; index < 3; index++ {
		x.openInput(t, index, []byte{1})
	}
	filler := x.fillGlobal(t, pendingBackendInput)
	for index := 1; index < 3; index++ {
		x.owners[index].drain(t)
	}
	first, second := <-x.opened, <-x.opened
	x.owners[1].reject.Store(true)
	x.releaseGlobal(filler)
	x.owners[2].next(t)
	if first.heldBytes != 0 || second.heldBytes != 1 {
		t.Fatal("rejected owner blocked the healthy owner")
	}
	x.sessions[1].retireBackendOwner()
}

func TestBackendGlobalOutputBudgetRegistersAndNotifies(t *testing.T) {
	x := newBudgetTestFixture(t, 2, func(config *ManagerConfig) {
		config.Limits.MaxPendingPerSession = 512 << 10
		config.Limits.MaxPendingGlobal = 512 << 10
	})
	if _, err := x.sessions[1].ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	x.owners[1].drain(t)
	backend := <-x.opened
	filler := x.fillGlobal(t, pendingDownlink)
	if backend.options.OutputBudget.Reserve(100, 1) {
		t.Fatal("output ignored full global budget")
	}
	x.manager.mu.Lock()
	entry := x.manager.budgetWaiters[backendBudgetKey{backend: x.sessions[1].streams[1].backend, class: pendingDownlink}]
	x.manager.mu.Unlock()
	if entry == nil {
		t.Fatal("output budget rejection was not registered")
	}
	before := backend.reads.Load()
	x.releaseGlobal(filler)
	x.owners[1].next(t)
	if backend.reads.Load() == before {
		t.Fatal("output waiter did not notify owner")
	}
}

type budgetReadProbe struct {
	*ownerProbeBackend
	data   []byte
	offset int
}

func (b *budgetReadProbe) ReadableBytes() int { return len(b.data) - b.offset }
func (b *budgetReadProbe) TryRead(dst []byte) (int, error) {
	n := copy(dst, b.data[b.offset:])
	b.offset += n
	if b.offset == len(b.data) && len(b.data) != 0 {
		b.options.OutputBudget.Release(len(b.data), 1)
		b.data, b.offset = nil, 0
	}
	return n, nil
}
func (b *budgetReadProbe) Close() error {
	if len(b.data) != 0 {
		b.options.OutputBudget.Release(len(b.data), 1)
		b.data, b.offset = nil, 0
	}
	return b.ownerProbeBackend.Close()
}

func TestBackendGlobalHandoffReleaseResumesDownlink(t *testing.T) {
	payload := bytes.Repeat([]byte{42}, 3000)
	x := newBudgetTestFixture(t, 2, func(config *ManagerConfig) {
		config.Limits.MaxPendingPerSession = 512 << 10
		config.Limits.MaxPendingGlobal = 512 << 10
		config.BackendFactory = func(options BackendOpenOptions) (Backend, error) {
			backend := &budgetReadProbe{ownerProbeBackend: &ownerProbeBackend{options: options}}
			if err := options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
				if !options.OutputBudget.Reserve(len(payload), 1) {
					t.Error("could not charge initial output")
					return nil
				}
				backend.data = bytes.Clone(payload)
				options.OnOpened(nil)
				return nil
			})); err != nil {
				return nil, err
			}
			return backend, nil
		}
	})
	session := x.sessions[1]
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.streams[1].sendCredit = 0
	session.mu.Unlock()
	x.owners[1].drain(t)
	filler := x.fillGlobal(t, pendingHandoff)
	window, err := WindowPayload(uint32(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameWindow, StreamID: 1, Payload: window})); err != nil {
		t.Fatal(err)
	}
	x.owners[1].drain(t)
	x.manager.mu.Lock()
	entry := x.manager.budgetWaiters[backendBudgetKey{backend: session.streams[1].backend, class: pendingHandoff}]
	x.manager.mu.Unlock()
	if entry == nil {
		t.Fatal("downlink handoff did not register global pressure")
	}
	x.releaseGlobal(filler)
	x.owners[1].next(t)
	session.mu.Lock()
	frames := session.carrierLanes[0].pendingFrames
	if len(frames) != 1 || frames[0].frameType != FrameData || !bytes.Equal(frames[0].encoded[FrameHeaderSize:], payload) {
		t.Error("available downlink did not move to carrier after global release")
	}
	session.mu.Unlock()
}

func TestBackendGlobalItemReleaseResumesInput(t *testing.T) {
	x := newBudgetTestFixture(t, 2, func(config *ManagerConfig) {
		config.Limits.MaxPendingPerSession = 1 << 20
		config.Limits.MaxPendingGlobal = 1 << 20
		config.Limits.MaxPendingItemsPerSession = 1024
		config.Limits.MaxPendingItemsGlobal = 1024
	})
	x.openInput(t, 1, []byte{1})
	x.manager.mu.Lock()
	_, limit := x.manager.pendingBudgetLimits(pendingBackendInput)
	items := limit - int(x.manager.pendingItems)
	x.manager.mu.Unlock()
	producer := x.sessions[0]
	producer.mu.Lock()
	ok := producer.reservePendingLocked(items*queueItemCost, items, pendingHandoff)
	producer.mu.Unlock()
	if !ok {
		t.Fatal("could not fill global item budget")
	}
	x.owners[1].drain(t)
	backend := <-x.opened
	if backend.heldBytes != 0 {
		t.Fatal("input ignored global item pressure")
	}
	producer.mu.Lock()
	producer.releasePendingLocked(items*queueItemCost, items)
	producer.mu.Unlock()
	x.owners[1].next(t)
	if backend.heldBytes != 1 {
		t.Fatal("item credit release did not resume input")
	}
}

func TestBackendGlobalCanceledNotificationTasksStayBounded(t *testing.T) {
	x := newBudgetTestFixture(t, 2)
	if _, err := x.sessions[1].ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	x.owners[1].drain(t)
	backend := <-x.opened
	stream := x.sessions[1].streams[1].backend
	_ = x.fillGlobal(t, pendingBackendInput)
	const cost = 100 + queueItemCost
	var pending []gnet.Runnable
	for range maxBackendBudgetWakeTasks {
		if backend.options.InputBudget.Reserve(100, 1) {
			t.Fatal("full global budget accepted a reservation")
		}
		x.releaseGlobal(cost)
		select {
		case run := <-x.owners[1].queue:
			pending = append(pending, run)
		case <-time.After(time.Second):
			t.Fatal("eligible waiter was not notified")
		}
		// Retire this demand without executing its queued owner notification.
		// A later independent demand must not allocate unlimited wake tasks.
		x.manager.cancelBackendBudgetWait(stream)
		x.sessions[0].mu.Lock()
		ok := x.sessions[0].reservePendingLocked(cost, 0, pendingHandoff)
		x.sessions[0].mu.Unlock()
		if !ok {
			t.Fatal("could not restore global pressure")
		}
	}
	if backend.options.InputBudget.Reserve(100, 1) {
		t.Fatal("full global budget accepted final reservation")
	}
	x.releaseGlobal(cost)
	select {
	case <-x.owners[1].queue:
		t.Fatal("canceled queued notifications exceeded their hard cap")
	case <-time.After(20 * time.Millisecond):
	}
	x.manager.mu.Lock()
	tasks := len(x.manager.budgetTasks)
	waiters := len(x.manager.budgetWaiters)
	x.manager.mu.Unlock()
	if tasks != maxBackendBudgetWakeTasks || waiters != 1 {
		t.Fatalf("queued tasks=%d waiters=%d", tasks, waiters)
	}
	if err := pending[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	x.owners[1].next(t)
	for _, run := range pending[1:] {
		if err := run.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}
