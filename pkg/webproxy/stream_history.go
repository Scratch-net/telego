package webproxy

const (
	streamHistoryChunkShift = 16
	streamHistoryChunkBits  = 1 << streamHistoryChunkShift
	streamHistoryWordShift  = 6
	streamHistoryWordBits   = 1 << streamHistoryWordShift
	streamHistoryChunkCount = (MaxStreamID + 1) / streamHistoryChunkBits
	streamHistoryWordCount  = streamHistoryChunkBits / streamHistoryWordBits
	streamHistoryMaxBytes   = (MaxStreamID + 1) / 8
)

type streamIDChunk [streamHistoryWordCount]uint64

// streamIDHistory is a lazy, exact set for the protocol's complete 24-bit ID
// space. It never forgets an ID during a session and cannot grow beyond 2 MiB.
type streamIDHistory struct {
	chunks    [streamHistoryChunkCount]*streamIDChunk
	allocated uint16
}

func (h *streamIDHistory) Contains(id uint32) bool {
	chunk := h.chunks[id>>streamHistoryChunkShift]
	if chunk == nil {
		return false
	}
	withinChunk := id & (streamHistoryChunkBits - 1)
	word := withinChunk >> streamHistoryWordShift
	bit := withinChunk & (streamHistoryWordBits - 1)
	return chunk[word]&(uint64(1)<<bit) != 0
}

// Add records id and reports whether it was new.
func (h *streamIDHistory) Add(id uint32) bool {
	chunkIndex := id >> streamHistoryChunkShift
	chunk := h.chunks[chunkIndex]
	if chunk == nil {
		chunk = new(streamIDChunk)
		h.chunks[chunkIndex] = chunk
		h.allocated++
	}
	withinChunk := id & (streamHistoryChunkBits - 1)
	word := withinChunk >> streamHistoryWordShift
	bit := withinChunk & (streamHistoryWordBits - 1)
	mask := uint64(1) << bit
	if chunk[word]&mask != 0 {
		return false
	}
	chunk[word] |= mask
	return true
}

func (h *streamIDHistory) AllocatedBytes() int {
	return int(h.allocated) * streamHistoryWordCount * 8
}
