package webproxy

import (
	"context"

	"github.com/panjf2000/gnet/v2"
)

// Backend is a bounded nonblocking stream. TryRead and TryWrite run on the
// owner supplied to the factory; zero with no error means temporary pressure.
// Close may be called from another goroutine and completes through OnClosed.
type Backend interface {
	TryWrite([]byte) (int, error)
	TryRead([]byte) (int, error)
	Close() error
}

// A backend may also expose ReadableBytes() int on its owner loop. The pump
// uses it to avoid allocating an empty read and to size small carrier frames.
type readableBackend interface {
	ReadableBytes() int
}

// OwnerStopped is an optional backend lifecycle hook. HTTPServer invokes it
// only after gnet.Run returns and all owner callbacks have stopped. Backends
// use it to retire cleanup tasks that the owner accepted but never ran.
type ownerStoppedBackend interface {
	OwnerStopped()
}

// BackendBudget accounts retained capacity and queue metadata. Callbacks are
// concurrency-safe and must never run while the caller holds a session lock.
type BackendBudget struct {
	Reserve func(bytes, items int) bool
	Release func(bytes, items int)
}

// BackendOpenOptions gives each stream a stable owner and bounded queues.
// Notify schedules further work; OnOpened and OnClosed each run exactly once.
// OnClosed runs after owner cleanup and every budget release has completed.
type BackendOpenOptions struct {
	Context                       context.Context
	Owner                         gnet.EventLoop
	ClientIP                      string
	Network, Address              string
	MaxInputBytes, MaxOutputBytes int
	MaxInputItems, MaxOutputItems int
	InputBudget, OutputBudget     BackendBudget
	Notify                        func()
	OnOpened                      func(error)
	OnClosed                      func(error)
}

type BackendFactory func(BackendOpenOptions) (Backend, error)
