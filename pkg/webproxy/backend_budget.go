package webproxy

import (
	"container/list"
	"context"
	"sync/atomic"

	"github.com/panjf2000/gnet/v2"
)

// Canceled notifications can still be queued on an owner. Keep those tasks
// bounded too, not just the one notification currently allowed to retry.
const maxBackendBudgetWakeTasks = 4

type backendBudgetKey struct {
	backend *backendStream
	class   pendingClass
}

type backendBudgetWait struct {
	key         backendBudgetKey
	cost, items int
}

type backendBudgetWake struct {
	owner   gnet.EventLoop
	backend atomic.Pointer[backendStream]
}

// The failed reservation and waiter registration share manager.mu. A release
// cannot pass between them and lose the only notification of usable capacity.
func (m *Manager) reserveBackendPending(backend *backendStream, cost, items int, class pendingClass) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := backendBudgetKey{backend: backend, class: class}
	if m.changePendingBudgetLocked(cost, items, class) {
		m.removeBudgetWaiterLocked(key)
		return true
	}
	if m.closed || backend.ctx.Err() != nil {
		return false
	}
	byteLimit, itemLimit := m.pendingBudgetLimits(class)
	if cost > byteLimit || items > itemLimit {
		return false
	}
	if entry := m.budgetWaiters[key]; entry != nil {
		waiter := entry.Value.(*backendBudgetWait)
		waiter.cost, waiter.items = cost, items
		return false
	}
	if m.budgetWaiters == nil {
		m.budgetWaiters = make(map[backendBudgetKey]*list.Element)
	}
	m.budgetWaiters[key] = m.budgetQueue.PushBack(&backendBudgetWait{key: key, cost: cost, items: items})
	return false
}

func (m *Manager) removeBudgetWaiterLocked(key backendBudgetKey) {
	if entry := m.budgetWaiters[key]; entry != nil {
		delete(m.budgetWaiters, key)
		m.budgetQueue.Remove(entry)
	}
}

func (m *Manager) signalBudgetWaitersLocked() {
	if m.closed || m.budgetActive != nil || m.budgetQueue.Len() == 0 || len(m.budgetTasks) >= maxBackendBudgetWakeTasks {
		return
	}
	select {
	case m.budgetWake <- struct{}{}:
	default:
	}
}

// The existing manager worker selects one eligible waiter. It never holds
// manager.mu while entering session code. The owner tries that backend once;
// completion, rejection, or cancellation permits the next eligible waiter.
func (m *Manager) wakeBudgetWaiter() {
	m.mu.Lock()
	if m.closed || m.budgetActive != nil || len(m.budgetTasks) >= maxBackendBudgetWakeTasks {
		m.mu.Unlock()
		return
	}
	var backend *backendStream
	for entry := m.budgetQueue.Front(); entry != nil; entry = entry.Next() {
		waiter := entry.Value.(*backendBudgetWait)
		byteLimit, itemLimit := m.pendingBudgetLimits(waiter.key.class)
		if int64(waiter.cost) > int64(byteLimit)-m.pendingBytes || int64(waiter.items) > int64(itemLimit)-m.pendingItems {
			continue
		}
		backend = waiter.key.backend
		m.removeBudgetWaiterLocked(waiter.key)
		break
	}
	if backend == nil {
		m.mu.Unlock()
		return
	}
	wake := &backendBudgetWake{owner: backend.session.owner}
	wake.backend.Store(backend)
	m.budgetActive = wake
	if m.budgetTasks == nil {
		m.budgetTasks = make(map[*backendBudgetWake]struct{})
	}
	m.budgetTasks[wake] = struct{}{}
	m.mu.Unlock()
	err := wake.owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		defer m.finishBudgetWake(wake)
		if current := wake.backend.Swap(nil); current != nil && current.ctx.Err() == nil {
			// One nonblocking backend quantum: at most one 64 KiB read and
			// write. Further work joins the ordinary coalesced session pump.
			if current.pump() {
				current.session.scheduleBackendPump()
			}
		}
		return nil
	}))
	if err != nil {
		wake.backend.Store(nil)
		m.finishBudgetWake(wake)
		backend.session.closeWithReason(sessionCloseShutdown)
	}
}

func (m *Manager) finishBudgetWake(wake *backendBudgetWake) {
	m.mu.Lock()
	delete(m.budgetTasks, wake)
	if m.budgetActive == wake {
		m.budgetActive = nil
	}
	m.signalBudgetWaitersLocked()
	m.mu.Unlock()
}

func (m *Manager) cancelBackendBudgetWait(backend *backendStream) {
	m.mu.Lock()
	for _, class := range [...]pendingClass{pendingBackendInput, pendingDownlink, pendingHandoff} {
		m.removeBudgetWaiterLocked(backendBudgetKey{backend: backend, class: class})
	}
	if wake := m.budgetActive; wake != nil && wake.backend.CompareAndSwap(backend, nil) {
		m.budgetActive = nil
	}
	m.signalBudgetWaitersLocked()
	m.mu.Unlock()
}

// Run completion proves these owner tasks cannot execute. Retire their small
// notification slots as well as clearing any references to canceled streams.
func (m *Manager) retireBudgetOwners(owners map[gnet.EventLoop]struct{}) {
	m.mu.Lock()
	for entry := m.budgetQueue.Front(); entry != nil; {
		next := entry.Next()
		key := entry.Value.(*backendBudgetWait).key
		if _, stopped := owners[key.backend.session.owner]; stopped {
			m.removeBudgetWaiterLocked(key)
		}
		entry = next
	}
	for wake := range m.budgetTasks {
		if _, stopped := owners[wake.owner]; stopped {
			wake.backend.Store(nil)
			delete(m.budgetTasks, wake)
			if m.budgetActive == wake {
				m.budgetActive = nil
			}
		}
	}
	m.signalBudgetWaitersLocked()
	m.mu.Unlock()
}
