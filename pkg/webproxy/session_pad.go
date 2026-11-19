package webproxy

import (
	"encoding/binary"
	"math/rand/v2"
)

// Padding follows the Xray Vision defaults (proxy/proxy.go XtlsPadding):
// content under 900 bytes grows to 900 plus a random 0-500 bytes, and longer
// content gets a random 0-256 bytes. padDownlinkBatches is a Telego choice:
// it covers the MTProto key exchange of the first streams, which needs about
// three round trips for each stream.
const (
	padShortContent    = 900
	padShortJitter     = 500
	padLongJitter      = 256
	padDownlinkBatches = 8
)

// padLength returns the PAD payload size for content bytes of real frames.
func padLength(content int, random func(int) int) int {
	if content < padShortContent {
		return max(0, padShortContent+random(padShortJitter+1)-content-FrameHeaderSize)
	}
	return random(padLongJitter + 1)
}

// padDownBatchLocked appends one PAD frame to a new downlink batch while the
// session still has padded batches left. The padding is charged with the
// batch, so the replay owner releases it with the batch. It reports whether
// the batch got a PAD frame. Padding never makes a batch exceed the carrier
// batch size or the frame limit, because the bridge rejects such a batch.
func (s *Session) padDownBatchLocked(batch *downBatch) bool {
	if s.padBatches == 0 {
		return false
	}
	s.padBatches--
	if batch.items >= MaxBatchFrames {
		return false
	}
	payload := min(padLength(len(batch.body), rand.IntN), MaxPadPayload,
		s.limits.CarrierBatchBytes-len(batch.body)-FrameHeaderSize)
	if payload < 0 || !s.reservePendingLocked(FrameHeaderSize+payload, 0, pendingDownlink) {
		return false
	}
	padded := make([]byte, len(batch.body)+FrameHeaderSize+payload)
	copy(padded, batch.body)
	header := padded[len(batch.body):]
	header[0] = byte(FramePad)
	binary.BigEndian.PutUint32(header[4:FrameHeaderSize], uint32(payload))
	batch.body = padded
	batch.cost += FrameHeaderSize + payload
	return true
}
