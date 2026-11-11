package webproxy

import (
	"context"
	"errors"
	"net"
	"testing"
)

// OPEN frames spread across the 24-bit ID space allocate one history chunk
// each, also when the stream limit rejects them. That growth must stay inside
// the session budget instead of pinning up to 2 MiB per session.
func TestStreamHistoryGrowthIsChargedToSessionBudget(t *testing.T) {
	const budget = 1 << 20
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxStreamsPerSession = 1
		config.Limits.MaxPendingPerSession = budget
	}, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("test backend unavailable")
	})
	session := createTestSession(t, manager, profiles[0]).Session
	frames := make([]Frame, 0, streamHistoryChunkCount)
	for chunk := range uint32(streamHistoryChunkCount) {
		frames = append(frames, Frame{Type: FrameOpen, StreamID: chunk<<streamHistoryChunkShift | 1})
	}
	_, err := session.ProcessUp(1, testFrameBatch(t, frames...))
	session.mu.Lock()
	allocated := session.usedStreams.AllocatedBytes()
	pending := session.pendingCost
	session.mu.Unlock()
	if allocated > budget {
		t.Fatalf("stream history allocated %d bytes beyond the %d-byte session budget (ProcessUp error %v)", allocated, budget, err)
	}
	if charged := allocated - streamHistoryChunkBytes; charged > pending {
		t.Fatalf("stream history charged %d of %d bytes beyond its first chunk", pending, charged)
	}
	if !errors.Is(err, ErrBackpressure) {
		t.Fatalf("oversized history growth = %v, want backpressure", err)
	}

	// Growth that fits is charged until the session closes.
	if _, err := session.ProcessUp(1, testFrameBatch(t, frames[:4]...)); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	allocated = session.usedStreams.AllocatedBytes()
	pending = session.pendingCost
	session.mu.Unlock()
	if allocated != 4*streamHistoryChunkBytes || pending < 3*streamHistoryChunkBytes {
		t.Fatalf("history allocated %d bytes and charged %d", allocated, pending)
	}
	before := manager.Capacity()
	session.Close()
	session.wait()
	if after := manager.Capacity(); after.PendingBytes > before.PendingBytes-3*streamHistoryChunkBytes {
		t.Fatalf("session close kept the history charge: before %d, after %d", before.PendingBytes, after.PendingBytes)
	}
}
