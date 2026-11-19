package webproxy

import "slices"

// webSocketFairMessageBytes caps one multiplexed WebSocket message when fair
// downlink scheduling is on. A browser delivers only complete messages, so a
// small reply can wait behind at most one message. 160 KiB holds two full
// backend reads (2 x (RelayDataChunk + FrameHeaderSize) = 131088 bytes) plus
// 32 KiB of control and small frames. The default FIFO message can reach
// CarrierBatchBytes, 2 MiB.
const webSocketFairMessageBytes = 160 * 1024

func (l Limits) fairMessageBytes() int {
	return min(webSocketFairMessageBytes, l.CarrierBatchBytes)
}

// takeFairDownBatchLocked builds one downlink batch in the order of the
// xtaci/smux shaper: WINDOW control frames first, then DATA and CLOSE frames
// in round-robin order across streams. The frames of one stream keep their
// queue order, so a CLOSE never overtakes DATA of its stream. WINDOW credit
// applies to the uplink direction, so it can safely precede downlink DATA.
// Rotation starts after the stream that the previous batch served first.
//
// Unlike takeDownFramesLocked, the result is not a queue prefix. The caller
// gets the same cost and item accounting, and pendingWindows indexes the
// remaining queue afterward.
func (s *Session) takeFairDownBatchLocked(lane *carrierLane, byteLimit int) downBatch {
	pending := lane.pendingFrames
	taken := make([]bool, len(pending))
	order := make([]int, 0, min(len(pending), MaxBatchFrames))
	size, streamFrames := 0, 0
	// The first stream frame is always taken, as in takeDownFramesLocked.
	// Otherwise a steady flow of WINDOW frames could starve a large frame.
	take := func(index int) bool {
		next := len(pending[index].encoded)
		control := pending[index].frameType == FrameWindow
		overflow := size+next > byteLimit && (control && len(order) != 0 || !control && streamFrames != 0)
		if len(order) == MaxBatchFrames || overflow {
			return false
		}
		if !control {
			streamFrames++
		}
		taken[index] = true
		order = append(order, index)
		size += next
		return true
	}

	streams := make(map[uint32][]int)
	for index := range pending {
		if pending[index].frameType == FrameWindow {
			take(index)
			continue
		}
		streams[pending[index].streamID] = append(streams[pending[index].streamID], index)
	}
	ids := make([]uint32, 0, len(streams))
	for id := range streams {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	start, _ := slices.BinarySearch(ids, lane.fairAfter+1)
	first := true
	for progress := true; progress; {
		progress = false
		for offset := range ids {
			id := ids[(start+offset)%len(ids)]
			queue := streams[id]
			if len(queue) == 0 || !take(queue[0]) {
				// A stream whose next frame does not fit keeps its later frames.
				streams[id] = nil
				continue
			}
			streams[id] = queue[1:]
			progress = true
			if first {
				lane.fairAfter = id
				first = false
			}
		}
	}

	body := make([]byte, 0, size)
	cost := 0
	for _, index := range order {
		body = append(body, pending[index].encoded...)
		cost += pending[index].cost
	}
	kept := pending[:0]
	for index := range pending {
		if !taken[index] {
			kept = append(kept, pending[index])
		}
	}
	clear(pending[len(kept):])
	lane.pendingFrames = kept
	clear(lane.pendingWindows)
	for index := range kept {
		if kept[index].frameType == FrameWindow {
			lane.pendingWindows[kept[index].streamID] = index
		}
	}
	if len(lane.pendingFrames) == 0 {
		lane.pendingFrames = nil
	}
	return downBatch{body: body, cost: cost, items: len(order)}
}
