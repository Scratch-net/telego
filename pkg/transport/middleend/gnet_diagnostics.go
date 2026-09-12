package middleend

import (
	"time"

	"github.com/panjf2000/gnet/v2"
)

func (l *GnetClientLink) observeReadBytes(count int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.transportFrozen {
		l.transport.IO.read(count, time.Now())
	}
}

func (l *GnetClientLink) observeWriteAttempt(count int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.transportFrozen {
		l.transport.IO.writeAttempt(count, time.Now())
	}
}

func (l *GnetClientLink) beginOwnerWrite(count int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.transportFrozen {
		l.transport.IO.writeAttempt(count, time.Now())
		l.transport.IO.WriteInFlight = true
	}
}

func (l *GnetClientLink) endOwnerWrite() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.transportFrozen {
		l.transport.IO.WriteInFlight = false
	}
}

func (l *GnetClientLink) observeOutboundProgress(buffered int, consumed uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.transportFrozen {
		l.observeOutboundProgressLocked(buffered, consumed, time.Now())
	}
}

func (l *GnetClientLink) observeOutboundProgressLocked(buffered int, consumed uint64, now time.Time) {
	observation := &l.transport.IO
	observation.OutboundObserved = true
	observation.OutboundBufferedBytes = buffered
	observation.OutboundObservedAt = now
	observation.OutboundProgressIncomplete = false
	if consumed > observation.OutboundProgressBytes {
		observation.OutboundProgressBytes = consumed
		observation.LastOutboundProgressAt = now
	}
}

// The owner callback samples before gnet releases the descriptor. Nothing stores
// an fd or schedules a later sample. A synchronous Writev can enter OnClose
// before it returns, so all subsequent observations must respect this freeze.
func (l *GnetClientLink) captureOwnerDiagnostics(conn gnet.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.transportFrozen || l.finalized {
		return
	}
	if conn != nil {
		buffered := conn.OutboundBuffered()
		if buffered >= 0 {
			consumed := l.transport.IO.OutboundProgressBytes
			if !l.transport.IO.WriteInFlight && uint64(buffered) <= l.ownerWireTotal {
				consumed = l.ownerWireTotal - uint64(buffered)
			}
			l.observeOutboundProgressLocked(buffered, consumed, time.Now())
		}
	}
	l.transport.IO.OutboundProgressIncomplete = l.transport.IO.WriteInFlight
	l.transport.Socket = captureOwnerSocket(conn)
	l.transportFrozen = true
}
