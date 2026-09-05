package gproxy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/panjf2000/gnet/v2"
)

var errUpstreamClientStopped = errors.New("upstream gnet client stopped unexpectedly")

// startDCClient completes before publishing the handler to WEB or the public
// engine. After this returns successfully, the client pointer never changes.
func (h *ProxyHandler) startDCClient(client *gnet.Client, report func(error)) (<-chan struct{}, error) {
	if err := client.Start(); err != nil {
		h.cancelUpstream()
		_ = client.Stop()
		return nil, err
	}
	h.dcClient = client
	return h.monitorDCClient(report), nil
}

// monitorDCClient observes one engine, not individual streams. The local gnet
// Client.Done contract joins owners and retires enrollment before signaling.
// Stop remains the shared idempotent boundary for local close-barrier cleanup.
func (h *ProxyHandler) monitorDCClient(report func(error)) <-chan struct{} {
	done := make(chan struct{})
	client := h.dcClient
	go func() {
		defer close(done)
		<-client.Done()
		unexpected := !h.upstreamStopRequested.Load()
		terminalErr := client.Err()
		_ = h.stopDCClient()
		if report != nil && (unexpected || terminalErr != nil) {
			if terminalErr == nil {
				terminalErr = errUpstreamClientStopped
			}
			report(fmt.Errorf("DC event-loop client failed: %w", terminalErr))
		}
	}()
	return done
}

// upstreamCloseBarriers retains close callbacks that gnet can abandon when its
// poller exits. The owning client must join all loops before retirement.
type upstreamCloseBarriers struct {
	mu      sync.Mutex
	stopped bool
	pending map[*upstreamCloseBarrier]struct{}
}

type upstreamCloseBarrier struct {
	finish func()
}

func (barriers *upstreamCloseBarriers) add(complete func()) *upstreamCloseBarrier {
	barrier := &upstreamCloseBarrier{}
	barrier.finish = sync.OnceFunc(func() {
		barriers.mu.Lock()
		delete(barriers.pending, barrier)
		barriers.mu.Unlock()
		complete()
	})
	barriers.mu.Lock()
	if barriers.stopped {
		barriers.mu.Unlock()
		barrier.finish()
		return barrier
	}
	if barriers.pending == nil {
		barriers.pending = make(map[*upstreamCloseBarrier]struct{})
	}
	barriers.pending[barrier] = struct{}{}
	barriers.mu.Unlock()
	return barrier
}

func (barriers *upstreamCloseBarriers) retire() {
	barriers.mu.Lock()
	barriers.stopped = true
	pending := barriers.pending
	barriers.pending = nil
	barriers.mu.Unlock()
	for barrier := range pending {
		barrier.finish()
	}
}
