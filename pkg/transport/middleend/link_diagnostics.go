package middleend

import "time"

// LinkIOSnapshot contains local observations, never proof of peer delivery.
// ReadBytes counts wire bytes received by the engine. WriteAttemptBytes counts
// bytes offered by the engine to gnet, including bootstrap output. It excludes
// gnet's internal buffered-write retries.
// Gnet outbound progress excludes bootstrap writes and means only that encoded
// frame bytes left its user-space buffer, not that the peer acknowledged them.
type LinkIOSnapshot struct {
	Available              bool
	ReadBytes              uint64
	ReadEvents             uint64
	LastReadAt             time.Time
	WriteAttemptBytes      uint64
	WriteAttempts          uint64
	LastWriteAttemptAt     time.Time
	WriteInFlight          bool
	OutboundObserved       bool
	OutboundBufferedBytes  int
	OutboundObservedAt     time.Time
	OutboundProgressBytes  uint64
	LastOutboundProgressAt time.Time
	// A close inside Write/Writev cannot reconcile the uncommitted batch with
	// gnet's buffer. The progress value then retains its last exact observation.
	OutboundProgressIncomplete bool
}

// LinkSocketStatus distinguishes absent evidence from a successful zero sample.
type LinkSocketStatus string

const (
	LinkSocketNotCaptured LinkSocketStatus = "not_captured"
	LinkSocketUnavailable LinkSocketStatus = "unavailable"
	LinkSocketUnsupported LinkSocketStatus = "unsupported"
	LinkSocketAvailable   LinkSocketStatus = "available"
	LinkSocketError       LinkSocketStatus = "error"
)

// LinkSocketSnapshot contains the original Linux TCP_INFO fields only. At is
// the close-callback observation time, before gnet flushes residual wire bytes.
// The snapshot retains no descriptor, address, raw error or kernel structure.
type LinkSocketSnapshot struct {
	Status               LinkSocketStatus
	At                   time.Time
	Errno                uint64
	State                uint8
	Unacked              uint32
	Lost                 uint32
	Retrans              uint32
	RTTMicroseconds      uint32
	RTTVarMicroseconds   uint32
	SendCongestionWindow uint32
	TotalRetrans         uint32
}

// LinkTransportSnapshot is cached evidence. Reading it never accesses a socket.
// IO and Socket can have different observation times. Once the engine closes,
// its terminal value is immutable even if a write returns after OnClose.
type LinkTransportSnapshot struct {
	IO     LinkIOSnapshot
	Socket LinkSocketSnapshot
}

func addObservedBytes(current uint64, count int) uint64 {
	if count <= 0 {
		return current
	}
	return current + min(uint64(count), ^uint64(0)-current)
}

func (s *LinkIOSnapshot) read(count int, now time.Time) {
	if count <= 0 {
		return
	}
	s.ReadBytes = addObservedBytes(s.ReadBytes, count)
	s.ReadEvents = addObservedBytes(s.ReadEvents, 1)
	s.LastReadAt = now
}

func (s *LinkIOSnapshot) writeAttempt(count int, now time.Time) {
	if count <= 0 {
		return
	}
	s.WriteAttemptBytes = addObservedBytes(s.WriteAttemptBytes, count)
	s.WriteAttempts = addObservedBytes(s.WriteAttempts, 1)
	s.LastWriteAttemptAt = now
}
