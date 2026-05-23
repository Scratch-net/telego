package faketls

// Dynamic Record Sizer + Split-TLS state machine.
//
// DRS mimics Chrome/Firefox: emit small "probe" records up front, then ramp
// to full-size once the connection is warmed up. Defeats DPI heuristics that
// flag steady-state large-record traffic from connection start.
//
// Split-TLS emits the first ApplicationData record as a 1-byte record before
// continuing normally. Defeats passive signatures keyed on the first record.

// DRS constants chosen to match Chrome's observed pattern.
const (
	// DRSProbeSize is the record size used during the probe phase.
	// Matches Chrome's small-record probe-phase size.
	DRSProbeSize = 1369

	// DRSRampRecords is the number of records after which DRS ramps to full size.
	DRSRampRecords = 8

	// DRSRampBytes is the byte count after which DRS ramps to full size,
	// regardless of record count.
	DRSRampBytes = 128 * 1024
)

// DRSState tracks per-connection record sizing for outbound (proxy->client)
// ApplicationData records. Not safe for concurrent use — callers must serialize
// access (e.g. by confining it to a single event-loop goroutine).
type DRSState struct {
	records   uint32
	bytes     uint64
	splitNext bool // arm for split-TLS on the next record
	drsOn     bool // probe-phase ramp-up active
	maxSize   int  // chunk size once ramped (or whenever DRS is off)
}

// NewDRSState builds a state with the given features.
// maxSize is the steady-state chunk size (typically MaxRecordPayload).
// When drsOn=false and splitFirst=false the state is a no-op that returns
// min(remaining, maxSize) — identical to the prior behavior.
func NewDRSState(drsOn, splitFirst bool, maxSize int) *DRSState {
	return &DRSState{
		splitNext: splitFirst,
		drsOn:     drsOn,
		maxSize:   maxSize,
	}
}

// NextChunk returns the size for the next record given how many payload bytes
// are still pending. Self-consumes the split-TLS arming on the first call when
// splitFirst was set. Returns 0 only when remaining <= 0.
func (d *DRSState) NextChunk(remaining int) int {
	if remaining <= 0 {
		return 0
	}
	if d.splitNext {
		d.splitNext = false
		return 1 // remaining > 0 guaranteed by the early-return above
	}
	if d.drsOn && d.records < DRSRampRecords && d.bytes < DRSRampBytes {
		return min(remaining, DRSProbeSize)
	}
	return min(remaining, d.maxSize)
}

// Advance updates record/byte counters after writing a record of size n.
func (d *DRSState) Advance(n int) {
	if n <= 0 {
		return
	}
	d.records++
	d.bytes += uint64(n)
}

// PlanSize simulates wrapping `payloadLen` bytes through this state and
// returns the total encoded size including record headers. Does not mutate
// the state — callers can use the result to size an output buffer before
// invoking the real loop.
func (d *DRSState) PlanSize(payloadLen int) int {
	if payloadLen <= 0 {
		return 0
	}
	sim := *d
	total := 0
	remaining := payloadLen
	for remaining > 0 {
		c := sim.NextChunk(remaining)
		if c <= 0 {
			break
		}
		total += RecordHeaderSize + c
		sim.Advance(c)
		remaining -= c
	}
	return total
}
