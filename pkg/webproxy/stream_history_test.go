package webproxy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStreamIDHistoryIsExactAndBounded(t *testing.T) {
	var history streamIDHistory
	for chunk := range streamHistoryChunkCount {
		id := uint32(chunk<<streamHistoryChunkShift) | uint32(chunk+1)
		if !history.Add(id) {
			t.Fatalf("first Add(%d) reported reuse", id)
		}
		if !history.Contains(id) {
			t.Fatalf("history lost %d", id)
		}
		if history.Add(id) {
			t.Fatalf("second Add(%d) reported new", id)
		}
	}
	if got := history.AllocatedBytes(); got != streamHistoryMaxBytes {
		t.Fatalf("fully populated chunk allocation = %d, want %d", got, streamHistoryMaxBytes)
	}
	if history.Contains(0x00fffe) {
		t.Fatal("history reported an ID that was never added")
	}
}

func TestSessionStreamHistoryChurnAndFailedBatchMutation(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxClosedStreamIDs = 32
	timeouts := DefaultTimeouts()
	timeouts.LongPoll = 20 * time.Millisecond
	session := newSession(sessionOptions{
		limits:        limits,
		timeouts:      timeouts,
		acquireStream: func() bool { return false },
	})
	t.Cleanup(func() {
		session.Close()
		session.wait()
	})

	const total = 5000
	const perBatch = 100
	sequence := uint64(1)
	cursor := uint64(0)
	firstID := uint32(0)
	for start := 0; start < total; start += perBatch {
		frames := make([]Frame, 0, perBatch)
		for index := start; index < min(start+perBatch, total); index++ {
			id := uint32((uint64(index)*3001)%MaxStreamID) + 1
			if index == 0 {
				firstID = id
			}
			frames = append(frames, Frame{Type: FrameOpen, StreamID: id})
		}
		body := testFrameBatch(t, frames...)
		if _, err := session.ProcessUp(sequence, body); err != nil {
			t.Fatalf("ProcessUp sequence %d: %v", sequence, err)
		}
		down, nextCursor, err := session.Poll(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Poll cursor %d: %v", cursor, err)
		}
		closed, err := ParseBatch(down)
		if err != nil || len(closed) != len(frames) {
			t.Fatalf("closed batch = %d frames, %v; want %d", len(closed), err, len(frames))
		}
		sequence++
		cursor = nextCursor
	}
	if got := session.usedStreams.AllocatedBytes(); got <= 0 || got > streamHistoryMaxBytes {
		t.Fatalf("stream history allocation = %d", got)
	}
	if len(session.tombstones.values) != limits.MaxClosedStreamIDs {
		t.Fatalf("tombstone count = %d, want %d", len(session.tombstones.values), limits.MaxClosedStreamIDs)
	}
	if _, err := session.ProcessUp(sequence, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: firstID})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("reused churned ID error = %v", err)
	}

	other := newSession(sessionOptions{limits: limits, timeouts: timeouts})
	invalid := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 77},
		Frame{Type: FrameOpen, StreamID: 77},
	)
	if _, err := other.ProcessUp(1, invalid); !errors.Is(err, ErrProtocol) {
		t.Fatalf("invalid duplicate OPEN error = %v", err)
	}
	if other.usedStreams.Contains(77) {
		t.Fatal("failed batch mutated stream-ID history")
	}
	other.wait()
}
