package gproxy

import (
	"sync/atomic"

	"github.com/panjf2000/gnet/v2"
)

// MiddleEndFrontendStats is a redacted snapshot of bytes retained between the
// public gnet connections and the fixed-binding manager.
type MiddleEndFrontendStats struct {
	MiddleEndBindingsActive int64
	MiddleEndBindingsTotal  uint64
	DirectFallbacksActive   int64
	DirectFallbacksTotal    uint64

	InputBytes              int64
	InputBytesHighWater     int64
	InputBytesLimit         int64
	InputBackpressureEvents uint64

	OutputBytes              int64
	OutputBytesHighWater     int64
	OutputBytesLimit         int64
	OutputBackpressureEvents uint64
	OutputEvictions          uint64
}

type middleEndByteBudget struct {
	limit        int64
	current      atomic.Int64
	highWater    atomic.Int64
	backpressure atomic.Uint64
}

func newMiddleEndByteBudget(limit int) middleEndByteBudget {
	return middleEndByteBudget{limit: int64(limit)}
}

func (b *middleEndByteBudget) observe(delta int64) int64 {
	current := b.current.Add(delta)
	for highWater := b.highWater.Load(); current > highWater; highWater = b.highWater.Load() {
		if b.highWater.CompareAndSwap(highWater, current) {
			break
		}
	}
	return current
}

func (b *middleEndByteBudget) tryReserve(size int64) bool {
	for {
		current := b.current.Load()
		if size > b.limit-current {
			b.backpressure.Add(1)
			return false
		}
		if b.current.CompareAndSwap(current, current+size) {
			b.recordHighWater(current + size)
			return true
		}
	}
}

func (b *middleEndByteBudget) recordHighWater(current int64) {
	for highWater := b.highWater.Load(); current > highWater; highWater = b.highWater.Load() {
		if b.highWater.CompareAndSwap(highWater, current) {
			return
		}
	}
}

func (b *middleEndByteBudget) release(size int64) {
	if size != 0 {
		b.current.Add(-size)
	}
}

func (b *middleEndByteBudget) snapshot() (current, highWater, limit int64, backpressure uint64) {
	return b.current.Load(), b.highWater.Load(), b.limit, b.backpressure.Load()
}

func (f *middleEndFrontend) stats() MiddleEndFrontendStats {
	input, inputHighWater, inputLimit, inputBackpressure := f.inputBudget.snapshot()
	output, outputHighWater, outputLimit, outputBackpressure := f.outputBudget.snapshot()
	f.mu.Lock()
	middleEndBindingsActive := int64(len(f.routes))
	directFallbacksActive := int64(len(f.directFallbacks))
	f.mu.Unlock()
	return MiddleEndFrontendStats{
		MiddleEndBindingsActive:  middleEndBindingsActive,
		MiddleEndBindingsTotal:   f.middleEndCommits.Load(),
		DirectFallbacksActive:    directFallbacksActive,
		DirectFallbacksTotal:     f.fallbackCommits.Load(),
		InputBytes:               input,
		InputBytesHighWater:      inputHighWater,
		InputBytesLimit:          inputLimit,
		InputBackpressureEvents:  inputBackpressure,
		OutputBytes:              output,
		OutputBytesHighWater:     outputHighWater,
		OutputBytesLimit:         outputLimit,
		OutputBackpressureEvents: outputBackpressure,
		OutputEvictions:          f.outputEvictions.Load(),
	}
}

func (c *middleEndClient) retainedInputBytes(connection gnet.Conn) int64 {
	retained := connection.InboundBuffered() + c.pendingCipherRetained + c.pendingPlainRetained
	if c.decoder != nil {
		retained += c.decoder.RetainedCapacityBytes()
	}
	if c.waiting != nil {
		retained += cap(c.waiting.Packet)
	}
	return int64(retained)
}

func (c *middleEndClient) reconcileInput(connection gnet.Conn) bool {
	current := c.retainedInputBytes(connection)
	delta := current - c.inputAccounted
	if delta == 0 {
		return true
	}
	c.inputAccounted = current
	total := c.frontend.inputBudget.observe(delta)
	if total <= c.frontend.inputBudget.limit {
		return true
	}
	c.frontend.inputBudget.backpressure.Add(1)
	return false
}

func (c *middleEndClient) reconcileOutput(connection gnet.Conn, reservation int64) (current, previous int) {
	current = connection.OutboundBuffered()
	previousBytes := c.outputAccounted.Swap(int64(current))
	c.frontend.outputBudget.observe(int64(current) - previousBytes - reservation)
	return current, int(previousBytes)
}

func (c *middleEndClient) releaseBudgets() {
	c.frontend.inputBudget.release(c.inputAccounted)
	c.inputAccounted = 0
	c.frontend.outputBudget.release(c.outputAccounted.Swap(0))
}

func (f *middleEndFrontend) reserveOutput() bool {
	return f.outputBudget.tryReserve(int64(middleEndMaxEncodedResponse))
}

func (f *middleEndFrontend) evictOutputPressureVictim(current *middleEndClient) bool {
	f.mu.Lock()
	var victim *middleEndRoute
	var victimBytes int64
	for _, candidate := range f.routes {
		bytes := candidate.client.outputAccounted.Load()
		if bytes <= 0 || candidate.client.outputEvicting.Load() {
			continue
		}
		if victim == nil || bytes > victimBytes ||
			bytes == victimBytes && candidate.client.binding.ConnectionID() < victim.client.binding.ConnectionID() {
			victim = candidate
			victimBytes = bytes
		}
	}
	if victim == nil || !victim.client.outputEvicting.CompareAndSwap(false, true) {
		f.mu.Unlock()
		return false
	}
	f.outputEvictions.Add(1)
	isCurrent := victim.client == current
	connection := victim.conn
	f.mu.Unlock()
	if !isCurrent {
		_ = connection.Close()
	}
	return isCurrent
}
