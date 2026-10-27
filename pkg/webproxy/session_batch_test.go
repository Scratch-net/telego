package webproxy

import (
	"fmt"
	"math"
	"testing"
)

func TestPendingStreamRemovalClearsRetainedTail(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierWebSocket} {
		t.Run(string(carrier), func(t *testing.T) {
			s := &Session{
				limits:       DefaultLimits(),
				carrier:      carrier,
				carrierLanes: map[uint32]*carrierLane{0: newCarrierLane()},
				budgetNotify: make(chan struct{}),
			}
			for _, frame := range []Frame{
				{Type: FrameClose, StreamID: 1},
				{Type: FrameData, StreamID: 2, Payload: []byte{1}},
				{Type: FrameData, StreamID: 3, Payload: make([]byte, MaxFramePayload)},
			} {
				if !s.queueFrameLocked(frame.Type, frame.StreamID, frame.Payload) {
					t.Fatal("queue frame")
				}
			}
			// The first removal moves stream 3 into an earlier slot. The next
			// removal must release both that slot and its old backing-array slot.
			s.dropPendingStreamFramesLocked(1)
			s.dropPendingStreamFramesLocked(3)
			frames := s.carrierLanes[0].pendingFrames
			if len(frames) != 1 || frames[0].streamID != 2 {
				t.Fatal("removal changed the surviving stream")
			}
			if s.pendingCost != FrameHeaderSize+1+queueItemCost || s.pendingItems != 1 {
				t.Fatalf("remaining budget: bytes=%d items=%d", s.pendingCost, s.pendingItems)
			}
			for _, frame := range frames[len(frames):cap(frames)] {
				if frame.encoded != nil {
					t.Fatalf("removed stream %d retains %d uncharged bytes", frame.streamID, cap(frame.encoded))
				}
			}
		})
	}
}

func TestSparseBatchValidationPreservesSequentialState(t *testing.T) {
	data := func(id uint32, size int) Frame {
		return Frame{Type: FrameData, StreamID: id, Payload: make([]byte, size)}
	}
	open := func(id uint32) Frame { return Frame{Type: FrameOpen, StreamID: id} }
	closeFrame := func(id uint32) Frame { return Frame{Type: FrameClose, StreamID: id} }
	windowPayload, err := WindowPayload(math.MaxUint32)
	if err != nil {
		t.Fatal(err)
	}
	window := func(id uint32) Frame { return Frame{Type: FrameWindow, StreamID: id, Payload: windowPayload} }
	for _, test := range []struct {
		name   string
		frames []Frame
		valid  bool
		bytes  int
		items  int
	}{
		{"live data", []Frame{data(1, 3)}, true, 3, 1},
		{"cumulative receive window", []Frame{data(1, 2), data(1, 2)}, false, 0, 0},
		{"close then late data", []Frame{data(1, 2), closeFrame(1), data(1, 4)}, true, 2, 1},
		{"open data close late data", []Frame{open(2), data(2, 4), closeFrame(2), data(2, 5)}, true, 4, 1},
		{"reuse within batch", []Frame{open(2), closeFrame(2), open(2)}, false, 0, 0},
		{"reuse existing stream", []Frame{closeFrame(1), open(1)}, false, 0, 0},
		{"reuse historical stream", []Frame{open(7)}, false, 0, 0},
		{"duplicate live open", []Frame{open(1)}, false, 0, 0},
		{"unknown data", []Frame{data(99, 1)}, false, 0, 0},
		{"unknown window", []Frame{window(99)}, false, 0, 0},
		{"unknown close", []Frame{closeFrame(99)}, false, 0, 0},
		{"historical late frames", []Frame{data(7, 1), window(7), closeFrame(7)}, true, 0, 0},
		{"saturating credit", []Frame{window(1), window(1), data(1, 1)}, true, 1, 1},
		{"control pong", []Frame{{Type: FramePong}}, true, 0, 0},
		{"control ping", []Frame{{Type: FramePing}}, false, 0, 0},
		{"failure after new open", []Frame{open(2), data(99, 1)}, false, 0, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := streamState{receiveWindow: 3, sendCredit: math.MaxUint32 - 1}
			s := &Session{streams: map[uint32]*streamState{1: new(original)}}
			s.usedStreams.Add(1)
			s.usedStreams.Add(7)
			if valid := s.validateBatchLocked(test.frames); valid != test.valid {
				t.Fatalf("valid=%t, want %t", valid, test.valid)
			}
			if len(s.streams) != 1 || s.streams[1].receiveWindow != original.receiveWindow ||
				s.streams[1].sendCredit != original.sendCredit || s.usedStreams.Contains(2) {
				t.Fatal("validation mutated session state")
			}
			if test.valid {
				cost, items, ok := s.backendWriteReservationLocked(test.frames)
				if !ok || cost != test.bytes+test.items*queueItemCost || items != test.items {
					t.Fatalf("reservation=(%d,%d,%t), want=(%d,%d,true)", cost, items, ok, test.bytes+test.items*queueItemCost, test.items)
				}
			}
		})
	}
}

func BenchmarkSingleFrameValidation(b *testing.B) {
	for _, streams := range []int{1, 128} {
		b.Run(fmt.Sprintf("streams_%d", streams), func(b *testing.B) {
			s := &Session{streams: make(map[uint32]*streamState)}
			for id := range streams {
				s.streams[uint32(id+1)] = &streamState{receiveWindow: InitialStreamWindow, sendCredit: InitialStreamWindow}
			}
			frames := []Frame{{Type: FrameData, StreamID: 1, Payload: make([]byte, 64)}}
			b.ReportAllocs()
			for b.Loop() {
				if !s.validateBatchLocked(frames) {
					b.Fatal("validation failed")
				}
				if _, _, ok := s.backendWriteReservationLocked(frames); !ok {
					b.Fatal("reservation failed")
				}
			}
		})
	}
}
