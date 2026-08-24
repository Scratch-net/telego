package webproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionUplinkSequenceAndByteIdenticalRetry(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, nil, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session

	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})
	if acknowledged, err := session.ProcessUp(1, open); err != nil || acknowledged != 1 {
		t.Fatalf("first ProcessUp = %d, %v", acknowledged, err)
	}
	peer := dialer.Peer(t)
	defer peer.Close()
	if acknowledged, err := session.ProcessUp(1, bytes.Clone(open)); err != nil || acknowledged != 1 {
		t.Fatalf("retry ProcessUp = %d, %v", acknowledged, err)
	}
	select {
	case extra := <-dialer.peers:
		_ = extra.Close()
		t.Fatal("retry opened a second backend")
	case <-time.After(20 * time.Millisecond):
	}

	session.mu.Lock()
	session.upActive = true
	session.mu.Unlock()
	pong := testFrameBatch(t, Frame{Type: FramePong, Payload: []byte("probe")})
	if _, err := session.ProcessUp(2, pong); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("concurrent next sequence error = %v", err)
	}
	session.mu.Lock()
	session.upActive = false
	session.mu.Unlock()
	if acknowledged, err := session.ProcessUp(2, pong); err != nil || acknowledged != 2 {
		t.Fatalf("second ProcessUp = %d, %v", acknowledged, err)
	}

	different := testFrameBatch(t, Frame{Type: FramePong, Payload: []byte("other")})
	if _, err := session.ProcessUp(2, different); !errors.Is(err, ErrProtocol) {
		t.Fatalf("non-identical retry error = %v", err)
	}
	if _, _, err := session.Poll(context.Background(), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("Poll after protocol failure error = %v", err)
	}
}

func TestSessionWindowFollowsBackendWriteConsumption(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, nil, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	payload := []byte("client-to-backend")
	body := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: payload},
	)
	if _, err := session.ProcessUp(1, body); err != nil {
		t.Fatal(err)
	}
	peer := dialer.Peer(t)
	defer peer.Close()

	pollContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := session.Poll(pollContext, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Poll before backend consumption error = %v", err)
	}

	received := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("backend received %q, want %q", received, payload)
	}
	down, cursor, err := session.Poll(context.Background(), 0)
	if err != nil || cursor != 1 {
		t.Fatalf("Poll WINDOW = cursor %d, %v", cursor, err)
	}
	frames, err := ParseBatch(down)
	if err != nil || len(frames) != 1 || frames[0].Type != FrameWindow || frames[0].StreamID != 1 {
		t.Fatalf("down frames = %#v, %v", frames, err)
	}
	delta, err := WindowDelta(frames[0].Payload)
	if err != nil || delta != uint32(len(payload)) {
		t.Fatalf("WINDOW delta = %d, %v", delta, err)
	}
}

func TestSessionDownlinkReplayAndCredit(t *testing.T) {
	profiles := testProfiles(t)
	peers := make(chan net.Conn, 1)
	releaseDial := make(chan struct{})
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		select {
		case peers <- server:
		case <-ctx.Done():
			_ = client.Close()
			_ = server.Close()
			return nil, ctx.Err()
		}
		select {
		case <-releaseDial:
			return client, nil
		case <-ctx.Done():
			_ = client.Close()
			_ = server.Close()
			return nil, ctx.Err()
		}
	}
	manager := testManager(t, profiles, nil, dial)
	session := createTestSession(t, manager, profiles[0]).Session
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 7})); err != nil {
		t.Fatal(err)
	}
	var peer net.Conn
	select {
	case peer = <-peers:
	case <-time.After(time.Second):
		t.Fatal("backend dial did not start")
	}
	defer peer.Close()

	session.mu.Lock()
	if got := session.streams[7].sendCredit; got != InitialStreamWindow {
		t.Fatalf("initial send credit = %d", got)
	}
	session.streams[7].sendCredit = 3
	session.mu.Unlock()
	close(releaseDial)

	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write([]byte("abcd"))
		writeDone <- err
	}()
	first, cursor, err := session.Poll(context.Background(), 0)
	if err != nil || cursor != 1 {
		t.Fatalf("first Poll = cursor %d, %v", cursor, err)
	}
	assertSingleDataFrame(t, first, 7, []byte("abc"))
	first[FrameHeaderSize] ^= 0xff
	replayed, replayCursor, err := session.Poll(context.Background(), 0)
	if err != nil || replayCursor != cursor {
		t.Fatalf("replay Poll = cursor %d, %v", replayCursor, err)
	}
	assertSingleDataFrame(t, replayed, 7, []byte("abc"))
	select {
	case err := <-writeDone:
		t.Fatalf("backend write completed without WINDOW: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	window, err := WindowPayload(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameWindow, StreamID: 7, Payload: window})); err != nil {
		t.Fatal(err)
	}
	second, secondCursor, err := session.Poll(context.Background(), cursor)
	if err != nil || secondCursor != 2 {
		t.Fatalf("second Poll = cursor %d, %v", secondCursor, err)
	}
	assertSingleDataFrame(t, second, 7, []byte("d"))
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend write did not resume after WINDOW")
	}

	ackContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := session.Poll(ackContext, secondCursor); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ack Poll error = %v", err)
	}
	eventually(t, time.Second, func() bool {
		capacity := manager.Capacity()
		return capacity.PendingBytes == 0 && capacity.PendingItems == 0
	})
}

func TestSessionDialFailureAndBackendEOFIsolateStreams(t *testing.T) {
	profiles := testProfiles(t)
	peers := make(chan net.Conn, 1)
	var calls atomic.Int32
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("dial failed")
		}
		client, server := net.Pipe()
		select {
		case peers <- server:
			return client, nil
		case <-ctx.Done():
			_ = client.Close()
			_ = server.Close()
			return nil, ctx.Err()
		}
	}
	manager := testManager(t, profiles, nil, dial)
	created := createTestSession(t, manager, profiles[0])
	session := created.Session

	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	closedBody, cursor, err := session.Poll(context.Background(), 0)
	if err != nil || cursor != 1 {
		t.Fatalf("failure Poll = cursor %d, %v", cursor, err)
	}
	assertSingleFrameType(t, closedBody, FrameClose, 1)

	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 2})); err != nil {
		t.Fatal(err)
	}
	var peer net.Conn
	select {
	case peer = <-peers:
	case <-time.After(time.Second):
		t.Fatal("second backend did not connect")
	}
	if _, err := peer.Write([]byte("still-live")); err != nil {
		t.Fatal(err)
	}
	dataBody, nextCursor, err := session.Poll(context.Background(), cursor)
	if err != nil || nextCursor != 2 {
		t.Fatalf("live stream Poll = cursor %d, %v", nextCursor, err)
	}
	assertSingleDataFrame(t, dataBody, 2, []byte("still-live"))
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	eofBody, eofCursor, err := session.Poll(context.Background(), nextCursor)
	if err != nil || eofCursor != 3 {
		t.Fatalf("EOF Poll = cursor %d, %v", eofCursor, err)
	}
	assertSingleFrameType(t, eofBody, FrameClose, 2)
	if _, err := manager.Get(created.Token); err != nil {
		t.Fatalf("backend failures closed the parent session: %v", err)
	}
}

func TestSessionBackendCloseDropsUndeliveredStreamData(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, nil, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	peer := dialer.Peer(t)
	if _, err := peer.Write([]byte("must-be-dropped")); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.streams[1] == nil
	})
	body, _, err := session.Poll(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	assertSingleFrameType(t, body, FrameClose, 1)
}

func TestSessionStreamDialAndPendingLimits(t *testing.T) {
	profiles := testProfiles(t)

	t.Run("per-session streams", func(t *testing.T) {
		dialer := newPipeDialer()
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Limits.MaxStreamsPerSession = 1
		}, dialer.DialContext)
		session := createTestSession(t, manager, profiles[0]).Session
		body := testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: 1},
			Frame{Type: FrameOpen, StreamID: 2},
		)
		if _, err := session.ProcessUp(1, body); err != nil {
			t.Fatal(err)
		}
		peer := dialer.Peer(t)
		defer peer.Close()
		down, _, err := session.Poll(context.Background(), 0)
		if err != nil {
			t.Fatal(err)
		}
		assertSingleFrameType(t, down, FrameClose, 2)
		if got := manager.Capacity().Streams; got != 1 {
			t.Fatalf("live streams = %d", got)
		}
	})

	t.Run("dial in flight", func(t *testing.T) {
		started := make(chan struct{}, 1)
		release := make(chan struct{})
		dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
			started <- struct{}{}
			select {
			case <-release:
				return nil, errors.New("released")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Limits.MaxBackendDialsInFlight = 1
		}, dial)
		session := createTestSession(t, manager, profiles[0]).Session
		body := testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: 1},
			Frame{Type: FrameOpen, StreamID: 2},
		)
		if _, err := session.ProcessUp(1, body); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("dial did not start")
		}
		down, _, err := session.Poll(context.Background(), 0)
		if err != nil {
			t.Fatal(err)
		}
		assertSingleFrameType(t, down, FrameClose, 2)
		close(release)
	})

	t.Run("atomic uplink backpressure", func(t *testing.T) {
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Limits.CarrierBatchBytes = 512
			config.Limits.MaxBodyBytes = 1024
			config.Limits.MaxStreamsPerSession = 1
			config.Limits.MaxClosedStreamIDs = 2
			config.Limits.MaxPendingPerSession = 6000
			config.Limits.MaxPendingGlobal = 12000
			config.Limits.MaxPendingItemsPerSession = 100
			config.Limits.MaxPendingItemsGlobal = 200
			config.Limits.MaxSessions = 1
			config.Limits.MaxStreams = 1
			config.Limits.MaxBackendDialsInFlight = 1
		}, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		})
		session := createTestSession(t, manager, profiles[0]).Session
		body := testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: 1},
			Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte{1}, 1000)},
		)
		if _, err := session.ProcessUp(1, body); !errors.Is(err, ErrBackpressure) {
			t.Fatalf("oversized pending batch error = %v", err)
		}
		if capacity := manager.Capacity(); capacity.Streams != 0 || capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
			t.Fatalf("backpressured batch mutated capacity: %+v", capacity)
		}
		if session.usedStreams.Contains(1) {
			t.Fatal("backpressured batch mutated stream-ID history")
		}
		if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
			t.Fatalf("retry of uncommitted sequence: %v", err)
		}
	})

	t.Run("global pending", func(t *testing.T) {
		dialer := newPipeDialer()
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Limits.CarrierBatchBytes = 512
			config.Limits.MaxBodyBytes = 1024
			config.Limits.MaxStreamsPerSession = 1
			config.Limits.MaxPendingPerSession = 8000
			config.Limits.MaxPendingGlobal = 11000
			config.Limits.MaxPendingItemsPerSession = 100
			config.Limits.MaxPendingItemsGlobal = 100
			config.Limits.MaxSessions = 2
			config.Limits.MaxStreams = 2
			config.Limits.MaxBackendDialsInFlight = 2
		}, dialer.DialContext)
		first := createTestSession(t, manager, profiles[0]).Session
		second := createTestSession(t, manager, profiles[1]).Session
		batch := testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: 1},
			Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte{1}, 500)},
		)
		if _, err := first.ProcessUp(1, batch); err != nil {
			t.Fatal(err)
		}
		peer := dialer.Peer(t)
		defer peer.Close()
		if _, err := second.ProcessUp(1, batch); !errors.Is(err, ErrBackpressure) {
			t.Fatalf("second global-pending batch error = %v", err)
		}
		capacity := manager.Capacity()
		if capacity.PendingBytes > int64(manager.limits.MaxPendingGlobal) || capacity.PendingItems > int64(manager.limits.MaxPendingItemsGlobal) {
			t.Fatalf("global pending exceeded: %+v", capacity)
		}
	})
}

func TestSessionNewestPollWinsAndStreamIDsNeverReuse(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxClosedStreamIDs = 2
	}, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	})
	session := createTestSession(t, manager, profiles[0]).Session

	type pollResult struct {
		body   []byte
		cursor uint64
		err    error
	}
	oldResult := make(chan pollResult, 1)
	newResult := make(chan pollResult, 1)
	go func() {
		body, cursor, err := session.Poll(context.Background(), 0)
		oldResult <- pollResult{body, cursor, err}
	}()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.downActive
	})
	session.mu.Lock()
	oldPoll := session.superseded
	session.mu.Unlock()
	go func() {
		body, cursor, err := session.Poll(context.Background(), 0)
		newResult <- pollResult{body, cursor, err}
	}()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.downActive && session.superseded != oldPoll
	})
	session.mu.Lock()
	if !session.queueFrameLocked(FrameClose, 1, nil) {
		session.mu.Unlock()
		t.Fatal("failed to queue deterministic poll wakeup")
	}
	session.mu.Unlock()
	select {
	case result := <-oldResult:
		if result.err != nil || result.cursor != 0 || len(result.body) != 0 {
			t.Fatalf("superseded poll = %#v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("old poll was not superseded")
	}
	select {
	case result := <-newResult:
		if result.err != nil || result.cursor != 1 {
			t.Fatalf("new poll = %#v", result)
		}
		assertSingleFrameType(t, result.body, FrameClose, 1)
	case <-time.After(time.Second):
		t.Fatal("new poll did not receive backend close")
	}

	closeBatch := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 2}, Frame{Type: FrameClose, StreamID: 2},
		Frame{Type: FrameOpen, StreamID: 3}, Frame{Type: FrameClose, StreamID: 3},
		Frame{Type: FrameOpen, StreamID: 4}, Frame{Type: FrameClose, StreamID: 4},
	)
	if _, err := session.ProcessUp(1, closeBatch); err != nil {
		t.Fatal(err)
	}
	if len(session.tombstones.values) != 2 {
		t.Fatalf("tombstones retained %d IDs, want 2", len(session.tombstones.values))
	}
	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 2})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("reused evicted stream ID error = %v", err)
	}
}

func TestSessionConcurrentOldCursorReplayHasOneCarrierOwner(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unused")
	})
	session := createTestSession(t, manager, profiles[0]).Session

	session.mu.Lock()
	if !session.queueFrameLocked(FrameClose, 1, nil) {
		session.mu.Unlock()
		t.Fatal("failed to queue replay frame")
	}
	session.mu.Unlock()
	first, cursor, err := session.Poll(context.Background(), 0)
	if err != nil || cursor != 1 || len(first) == 0 {
		t.Fatalf("initial poll = %x, %d, %v", first, cursor, err)
	}

	replayOne, nextOne, leaseOne, err := session.PollCarrier(context.Background(), 0)
	if err != nil || nextOne != cursor || !bytes.Equal(replayOne, first) || leaseOne == nil {
		t.Fatalf("first replay = %x, %d, %v, lease %v", replayOne, nextOne, err, leaseOne != nil)
	}
	type replayResult struct {
		body   []byte
		cursor uint64
		lease  *PollLease
		err    error
	}
	second := make(chan replayResult, 1)
	go func() {
		body, next, lease, pollErr := session.PollCarrier(context.Background(), 0)
		second <- replayResult{body: body, cursor: next, lease: lease, err: pollErr}
	}()
	eventually(t, time.Second, leaseOne.Superseded)
	select {
	case result := <-second:
		t.Fatalf("second replay materialized before the first carrier released: %#v", result)
	default:
	}
	leaseOne.Release()
	var result replayResult
	select {
	case result = <-second:
	case <-time.After(time.Second):
		t.Fatal("second replay did not acquire the released carrier slot")
	}
	if result.err != nil || result.cursor != cursor || !bytes.Equal(result.body, first) || result.lease == nil || result.lease.Superseded() {
		t.Fatalf("second replay = %x, %d, %v, lease %v", result.body, result.cursor, result.err, result.lease != nil)
	}
	waitForDownPoll(t, session, true)
	result.lease.Release()
	waitForDownPoll(t, session, false)
}

func TestSessionPollCarrierClosePathsReleaseLeaseOnce(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unused")
	})
	session := createTestSession(t, manager, profiles[0]).Session

	type pollResult struct {
		body   []byte
		cursor uint64
		lease  *PollLease
		err    error
	}
	parked := make(chan pollResult, 1)
	go func() {
		body, cursor, lease, err := session.PollCarrier(context.Background(), 0)
		parked <- pollResult{body: body, cursor: cursor, lease: lease, err: err}
	}()
	waitForDownPoll(t, session, true)

	session.Close()
	select {
	case result := <-parked:
		if result.body != nil || result.cursor != 0 || result.lease != nil || !errors.Is(result.err, ErrClosed) {
			t.Fatalf("parked PollCarrier after Close = %x, %d, lease %v, %v",
				result.body, result.cursor, result.lease != nil, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("parked PollCarrier did not wake after Close")
	}
	waitForDownPoll(t, session, false)

	body, cursor, lease, err := session.PollCarrier(context.Background(), 7)
	if body != nil || cursor != 7 || lease != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("PollCarrier called after Close = %x, %d, lease %v, %v", body, cursor, lease != nil, err)
	}
}

func TestSessionPendingBudgetPausesBackendReadUntilAcknowledged(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.CarrierBatchBytes = 16
		config.Limits.MaxBodyBytes = 16
		config.Limits.MaxStreamsPerSession = 1
		config.Limits.MaxClosedStreamIDs = 2
		config.Limits.MaxPendingPerSession = 6000
		config.Limits.MaxPendingGlobal = 12000
		config.Limits.MaxPendingItemsPerSession = 30
		config.Limits.MaxPendingItemsGlobal = 60
		config.Limits.MaxSessions = 1
		config.Limits.MaxStreams = 1
		config.Limits.MaxBackendDialsInFlight = 1
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	peer := dialer.Peer(t)
	defer peer.Close()

	session.mu.Lock()
	allowance := session.dataFrameAllowanceLocked(RelayDataChunk)
	session.mu.Unlock()
	if allowance <= 0 || allowance >= RelayDataChunk {
		t.Fatalf("test downlink allowance = %d", allowance)
	}
	payload := bytes.Repeat([]byte{0x5a}, allowance+1)
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(payload)
		writeDone <- err
	}()

	first, cursor, err := session.Poll(context.Background(), 0)
	if err != nil || cursor != 1 {
		t.Fatalf("first Poll = cursor %d, %v", cursor, err)
	}
	assertSingleDataFrame(t, first, 1, payload[:allowance])
	select {
	case err := <-writeDone:
		t.Fatalf("backend read exceeded retained pending budget: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	second, nextCursor, err := session.Poll(context.Background(), cursor)
	if err != nil || nextCursor != 2 {
		t.Fatalf("acknowledging Poll = cursor %d, %v", nextCursor, err)
	}
	assertSingleDataFrame(t, second, 1, payload[allowance:])
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend read did not resume after pending budget release")
	}
}

func TestSessionBlockedConnectionCloseDoesNotHoldMutexOrDefeatShutdownDeadline(t *testing.T) {
	profiles := testProfiles(t)
	connection := newBlockedCloseConn()
	manager := testManager(t, profiles, nil, func(context.Context, string, string) (net.Conn, error) {
		return connection, nil
	})
	created := createTestSession(t, manager, profiles[0])
	if _, err := created.Session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-connection.readStarted:
	case <-time.After(time.Second):
		t.Fatal("backend read did not start")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Shutdown(shutdownContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked-close Shutdown error = %v", err)
	}
	select {
	case <-connection.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("connection Close did not start")
	}
	activityDone := make(chan struct{})
	go func() {
		_ = created.Session.LastActivity()
		close(activityDone)
	}()
	select {
	case <-activityDone:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("blocked net.Conn.Close held Session.mu")
	}

	close(connection.allowClose)
	finalContext, finalCancel := context.WithTimeout(context.Background(), time.Second)
	defer finalCancel()
	if err := manager.Shutdown(finalContext); err != nil {
		t.Fatalf("Shutdown after releasing Close: %v", err)
	}
}

type blockedCloseConn struct {
	readStarted  chan struct{}
	closeStarted chan struct{}
	allowClose   chan struct{}
	readDone     chan struct{}
	readOnce     sync.Once
	closeOnce    sync.Once
}

func newBlockedCloseConn() *blockedCloseConn {
	return &blockedCloseConn{
		readStarted:  make(chan struct{}),
		closeStarted: make(chan struct{}),
		allowClose:   make(chan struct{}),
		readDone:     make(chan struct{}),
	}
}

func (c *blockedCloseConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	<-c.readDone
	return 0, io.EOF
}

func (c *blockedCloseConn) Write(buffer []byte) (int, error) { return len(buffer), nil }

func (c *blockedCloseConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeStarted)
		<-c.allowClose
		close(c.readDone)
	})
	return nil
}

func (c *blockedCloseConn) LocalAddr() net.Addr              { return testNetAddr("local") }
func (c *blockedCloseConn) RemoteAddr() net.Addr             { return testNetAddr("remote") }
func (c *blockedCloseConn) SetDeadline(time.Time) error      { return nil }
func (c *blockedCloseConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockedCloseConn) SetWriteDeadline(time.Time) error { return nil }

type testNetAddr string

func (a testNetAddr) Network() string { return "test" }
func (a testNetAddr) String() string  { return string(a) }

type pipeDialer struct {
	peers chan net.Conn
}

func newPipeDialer() *pipeDialer {
	return &pipeDialer{peers: make(chan net.Conn, 16)}
}

func (d *pipeDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case d.peers <- server:
		return client, nil
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	}
}

func (d *pipeDialer) Peer(t *testing.T) net.Conn {
	t.Helper()
	select {
	case peer := <-d.peers:
		return peer
	case <-time.After(time.Second):
		t.Fatal("backend connection did not arrive")
		return nil
	}
}

func assertSingleDataFrame(t *testing.T, body []byte, streamID uint32, payload []byte) {
	t.Helper()
	frames, err := ParseBatch(body)
	if err != nil || len(frames) != 1 || frames[0].Type != FrameData ||
		frames[0].StreamID != streamID || !bytes.Equal(frames[0].Payload, payload) {
		t.Fatalf("DATA batch = %#v, %v; want stream %d payload %q", frames, err, streamID, payload)
	}
}

func assertSingleFrameType(t *testing.T, body []byte, frameType FrameType, streamID uint32) {
	t.Helper()
	frames, err := ParseBatch(body)
	if err != nil || len(frames) != 1 || frames[0].Type != frameType || frames[0].StreamID != streamID {
		t.Fatalf("frame batch = %#v, %v; want %d stream %d", frames, err, frameType, streamID)
	}
}
