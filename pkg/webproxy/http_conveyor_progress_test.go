package webproxy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// Later requests can arrive first on independent HTTP connections. They must
// leave capacity for the next batch, because they cannot commit without it.
func TestHTTPConveyorReorderedLargeBatchesLeaveHeadroom(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	frame := testFrameBatch(t, Frame{Type: FramePong})
	body := bytes.Repeat(frame, MaxBatchFrames)
	for sequence := uint64(2); sequence <= httpUpWindow; sequence++ {
		reservation, err := session.reserveHTTPUp(0, sequence, len(body))
		if errors.Is(err, ErrBackpressure) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(reservation.Release)
	}
	reservation, err := session.reserveHTTPUp(0, 1, len(body))
	if err != nil {
		t.Fatalf("later batches blocked the next ordered batch: %v; capacity=%+v", err, manager.Capacity())
	}
	reservation.Release()
}

func maximumHTTPProgressBody(t *testing.T) []byte {
	t.Helper()
	frame := testFrameBatch(t, Frame{Type: FrameData, StreamID: 1,
		Payload: bytes.Repeat([]byte("x"), maxCarrierBatchBytes/MaxBatchFrames-FrameHeaderSize)})
	return bytes.Repeat(frame, MaxBatchFrames)
}

// Another session consumes every unreserved global byte and item. This makes
// a missing predecessor rely entirely on its already-owned progress capacity.
func fillHTTPProgressBudget(t *testing.T, manager *Manager, profile Profile) {
	t.Helper()
	filler := createTestSession(t, manager, profile).Session
	byteLimit, itemLimit := manager.pendingBudgetLimits(pendingUplink)
	capacity := manager.Capacity()
	cost, items := byteLimit-int(capacity.PendingBytes), itemLimit-int(capacity.PendingItems)
	filler.mu.Lock()
	ok := filler.reservePendingLocked(cost, items, pendingUplink)
	filler.mu.Unlock()
	if !ok {
		t.Fatalf("cannot fill global remainder: bytes=%d items=%d", cost, items)
	}
	t.Cleanup(func() {
		filler.mu.Lock()
		filler.releasePendingLocked(cost, items)
		filler.mu.Unlock()
	})
}

func httpProgressManager(t *testing.T) (*Manager, []Profile) {
	t.Helper()
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxSessions = 3
		config.Limits.MaxPendingGlobal = config.Limits.MaxPendingPerSession
		config.Limits.MaxPendingItemsGlobal = config.Limits.MaxPendingItemsPerSession
		// The HTTP protocol cap, rather than MaxBodyBytes, bounds escrow.
		config.Limits.MaxBodyBytes = 2 * maxCarrierBatchBytes
	}, nil)
	return manager, profiles
}

func TestHTTPConveyorHeadConsumesEscrowAtGlobalLimit(t *testing.T) {
	manager, profiles := httpProgressManager(t)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	session.usedStreams.Add(1) // Valid late DATA has no backend side effects.
	session.mu.Unlock()
	futureBody := bytes.Repeat(testFrameBatch(t, Frame{Type: FramePong}), MaxBatchFrames)
	future := reserveHTTPTest(t, session, 0, 2, futureBody)
	fillHTTPProgressBudget(t, manager, profiles[0])
	before := manager.Capacity()
	body := maximumHTTPProgressBody(t)
	head := reserveHTTPTest(t, session, 0, 1, body)
	if capacity := manager.Capacity(); capacity.PendingBytes != before.PendingBytes || capacity.PendingItems != before.PendingItems {
		t.Fatalf("head needed unreserved global capacity: before=%+v after=%+v", before, capacity)
	}
	if ack, err := head.Process(t.Context(), body); err != nil || ack != 1 {
		t.Fatalf("maximum head cannot commit: %d, %v", ack, err)
	}
	if head.cost != len(body)+queueItemCost || head.items != 1 {
		t.Fatalf("commit released live body ownership: bytes=%d items=%d", head.cost, head.items)
	}
	head.Release()
	if ack, err := future.Process(t.Context(), futureBody); err != nil || ack != 2 {
		t.Fatalf("future cannot commit: %d, %v", ack, err)
	}
	future.Release()
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.pendingCost != 0 || session.pendingItems != 0 || len(session.httpUpLanes) != 0 {
		t.Fatalf("retained session ownership: bytes=%d items=%d lanes=%d", session.pendingCost, session.pendingItems, len(session.httpUpLanes))
	}
}

func TestHTTPConveyorCanceledPredecessorRestoresEscrow(t *testing.T) {
	manager, profiles := httpProgressManager(t)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	session.usedStreams.Add(1)
	session.mu.Unlock()
	small := testFrameBatch(t, Frame{Type: FramePong})
	first := reserveHTTPTest(t, session, 0, 1, small)
	third := reserveHTTPTest(t, session, 0, 3, small)
	result := make(chan error, 1)
	go func() { _, err := third.Process(t.Context(), small); result <- err }()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return third.batch.known
	})
	// The first body was admitted before its successor, so future admission
	// must have topped it up before the smaller request could cancel.
	first.Release()
	fillHTTPProgressBudget(t, manager, profiles[0])
	body := maximumHTTPProgressBody(t)
	first = reserveHTTPTest(t, session, 0, 1, body)
	if _, err := first.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	first.Release()
	// Sequence 2 remains absent after the original head commits. Its body
	// can be read and canceled without forfeiting the next retry's capacity.
	second := reserveHTTPTest(t, session, 0, 2, body)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := second.Process(ctx, body); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled consumed body=%v", err)
	}
	second.Release()
	second = reserveHTTPTest(t, session, 0, 2, body)
	if _, err := second.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	second.Release()
	third.Release()
}

func TestHTTPConveyorEscrowSupportsItemOnlyAdmission(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	small := testFrameBatch(t, Frame{Type: FramePong})
	future := reserveHTTPTest(t, session, 0, 2, small)
	head := reserveHTTPTest(t, session, 0, 1, small)
	before := manager.Capacity()
	// The byte escrow covers both readers, while their combined item charge
	// exceeds the predecessor's max-items escrow by the first reader's items.
	duplicate := reserveHTTPTest(t, session, 0, 1, bytes.Repeat(small, MaxBatchFrames))
	after := manager.Capacity()
	if after.PendingBytes != before.PendingBytes || after.PendingItems-before.PendingItems != int64(head.items) {
		t.Fatalf("item-only admission: before=%+v after=%+v", before, after)
	}
	duplicate.Release()
	head.Release()
	future.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("item-only rollback leaked ownership: %+v", capacity)
	}
}

func TestHTTPConveyorCloseRetainsBodiesWithEscrow(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	body := bytes.Repeat(testFrameBatch(t, Frame{Type: FramePong}), MaxBatchFrames)
	future := reserveHTTPTest(t, session, 0, 2, body)
	head := reserveHTTPTest(t, session, 0, 1, body)
	before := manager.Capacity()
	session.Close()
	if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatalf("close released owned request storage: before=%+v after=%+v", before, after)
	}
	head.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != int64(future.cost) || capacity.PendingItems != int64(future.items) {
		t.Fatalf("close released another live body: %+v", capacity)
	}
	future.Release()
	future.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("close retained released bodies: %+v", capacity)
	}
}

func TestHTTPConveyorEscrowAdmissionRollback(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxPendingItemsPerSession = 2 * (MaxBatchFrames + 1)
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	body := bytes.Repeat(testFrameBatch(t, Frame{Type: FramePong}), MaxBatchFrames)
	if _, err := session.reserveHTTPUp(0, 2, len(body)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("oversized predecessor obligation=%v", err)
	}
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("rejected escrow retained ownership: %+v", capacity)
	}
	for _, size := range []int{0, FrameHeaderSize - 1, maxCarrierBatchBytes + 1} {
		if _, err := session.reserveHTTPUp(0, 1, size); !errors.Is(err, ErrProtocol) {
			t.Fatalf("invalid body size %d=%v", size, err)
		}
	}
	head := reserveHTTPTest(t, session, 0, 1, body)
	if _, err := head.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	head.Release()
}

func TestHTTPConveyorIndependentHeadsShareGlobalEscrow(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierHTTPSLanes} {
		t.Run(string(carrier), func(t *testing.T) {
			profiles := testProfiles(t)
			manager := testManager(t, profiles, func(config *ManagerConfig) {
				config.Carrier = carrier
				config.Limits.MaxSessions = 3
				config.Limits.MaxPendingGlobal = config.Limits.MaxPendingPerSession
				config.Limits.MaxPendingItemsGlobal = config.Limits.MaxPendingItemsPerSession
			}, nil)
			type target struct {
				session *Session
				lane    uint32
				head    []byte
				body    []byte
				future  *httpUpReservation
			}
			shared := createTestSession(t, manager, profiles[0]).Session
			targets := make([]target, 2)
			for i := range targets {
				entry := &targets[i]
				entry.session = shared
				entry.head = testFrameBatch(t, Frame{Type: FramePong})
				entry.body = entry.head
				if carrier == CarrierHTTPSLanes {
					entry.lane = uint32(41 + i)
					entry.head = testFrameBatch(t, Frame{Type: FrameOpen, StreamID: entry.lane}, Frame{Type: FrameClose, StreamID: entry.lane})
					entry.body = testFrameBatch(t, Frame{Type: FrameClose, StreamID: entry.lane})
				} else if i != 0 {
					entry.session = createTestSession(t, manager, profiles[0]).Session
				}
				entry.future = reserveHTTPTest(t, entry.session, entry.lane, 2, entry.body)
			}
			fillHTTPProgressBudget(t, manager, profiles[0])
			before := manager.Capacity()
			heads := make([]*httpUpReservation, len(targets))
			for i, entry := range targets {
				heads[i] = reserveHTTPTest(t, entry.session, entry.lane, 1, entry.head)
			}
			if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
				t.Fatalf("independent heads stole each other's capacity: before=%+v after=%+v", before, after)
			}
			for i, entry := range targets {
				if _, err := heads[i].Process(t.Context(), entry.head); err != nil {
					t.Fatalf("head lane %d=%v", entry.lane, err)
				}
				heads[i].Release()
				if _, err := entry.future.Process(t.Context(), entry.body); err != nil {
					t.Fatalf("future lane %d=%v", entry.lane, err)
				}
				entry.future.Release()
			}
		})
	}
}
