package middleend

import "sync/atomic"

// Two idle buffers per size retain less than 4 MiB in total. A cache miss
// allocates normally; a full slot drops the returned buffer. Neither path
// waits for another decoder or changes the active connection's byte budget.
var clientPacketBuffers clientPacketBufferPool

var clientPacketBufferSizes = [...]int{
	64 * 1024,
	128 * 1024,
	256 * 1024,
	512 * 1024,
	MaxClientPacketSize + maxClientPacketHeaderSize,
}

type clientPacketBuffer struct {
	data []byte
}

type clientPacketBufferPool struct {
	slots [len(clientPacketBufferSizes)][2]atomic.Pointer[clientPacketBuffer]
}

// get returns exclusive ownership of a clean buffer, or nil when rounding
// its capacity would exceed the decoder's limit. Small buffers stay local.
func (p *clientPacketBufferPool) get(capacity, limit int) *clientPacketBuffer {
	if capacity < clientPacketBufferSizes[0] {
		return nil
	}
	for class, size := range clientPacketBufferSizes {
		if size < capacity {
			continue
		}
		if size > limit {
			return nil
		}
		for i := range p.slots[class] {
			slot := &p.slots[class][i]
			// Load only avoids writes to empty cache lines. Inspect the buffer
			// itself only after Swap transfers its ownership to this decoder.
			if slot.Load() != nil {
				if buffer := slot.Swap(nil); buffer != nil {
					return buffer
				}
			}
		}
		return &clientPacketBuffer{data: make([]byte, size)}
	}
	return nil
}

// put transfers ownership once. The caller must first clear every written
// byte and must not access the buffer after this call, even when it is full.
func (p *clientPacketBufferPool) put(buffer *clientPacketBuffer) {
	if buffer == nil {
		return
	}
	for class, size := range clientPacketBufferSizes {
		if cap(buffer.data) != size {
			continue
		}
		for i := range p.slots[class] {
			if p.slots[class][i].CompareAndSwap(nil, buffer) {
				return
			}
		}
		return
	}
}
