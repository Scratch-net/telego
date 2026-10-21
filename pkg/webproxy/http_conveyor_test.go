package webproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"testing"
	"time"
)

func reserveHTTPTest(t *testing.T, s *Session, lane uint32, seq uint64, body []byte) *httpUpReservation {
	t.Helper()
	r, err := s.reserveHTTPUp(lane, seq, len(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Release)
	return r
}

func TestHTTPConveyorOrderedApplyAndDigestReplay(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	s := createTestSession(t, manager, profiles[0]).Session
	first := testFrameBatch(t, Frame{Type: FramePong, Payload: []byte("one")})
	second := testFrameBatch(t, Frame{Type: FramePong, Payload: []byte("two")})
	r2 := reserveHTTPTest(t, s, 0, 2, second)
	result := make(chan error, 1)
	go func() { _, err := r2.Process(t.Context(), second); result <- err }()
	select {
	case err := <-result:
		t.Fatalf("gap applied early: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	r1 := reserveHTTPTest(t, s, 0, 1, first)
	if ack, err := r1.Process(t.Context(), first); err != nil || ack != 1 {
		t.Fatalf("first=%d,%v", ack, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	r1.Release()
	r2.Release()
	for seq := uint64(3); seq <= 4; seq++ {
		r := reserveHTTPTest(t, s, 0, seq, second)
		if _, err := r.Process(t.Context(), second); err != nil {
			t.Fatal(err)
		}
		r.Release()
	}
	retry := reserveHTTPTest(t, s, 0, 1, first)
	if ack, err := retry.Process(t.Context(), bytes.Clone(first)); err != nil || ack != 1 {
		t.Fatalf("oldest replay=%d,%v", ack, err)
	}
	retry.Release()
	changed := reserveHTTPTest(t, s, 0, 1, first)
	bad := bytes.Clone(first)
	bad[len(bad)-1] ^= 1
	if _, err := changed.Process(t.Context(), bad); !errors.Is(err, ErrProtocol) {
		t.Fatalf("changed replay=%v", err)
	}
	changed.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("closed ownership=%+v", capacity)
	}
}

func TestHTTPConveyorPendingDuplicateAndCancellation(t *testing.T) {
	for _, closeSession := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "close"}[closeSession], func(t *testing.T) {
			profiles := testProfiles(t)
			manager := testManager(t, profiles, nil, nil)
			s := createTestSession(t, manager, profiles[0]).Session
			body := testFrameBatch(t, Frame{Type: FramePong})
			r := reserveHTTPTest(t, s, 0, 2, body)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := r.Process(ctx, body); result <- err }()
			if closeSession {
				s.Close()
				if manager.Capacity().PendingBytes == 0 {
					t.Fatal("close released live request storage")
				}
			} else {
				cancel()
			}
			if err := <-result; err == nil {
				t.Fatal("waiting request survived cancellation")
			}
			r.Release()
			r.Release()
			if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
				t.Fatalf("ownership=%+v", capacity)
			}
		})
	}
	t.Run("changed pending duplicate", func(t *testing.T) {
		profiles := testProfiles(t)
		manager := testManager(t, profiles, nil, nil)
		s := createTestSession(t, manager, profiles[0]).Session
		body := testFrameBatch(t, Frame{Type: FramePong, Payload: []byte("a")})
		r := reserveHTTPTest(t, s, 0, 2, body)
		result := make(chan error, 1)
		go func() { _, err := r.Process(t.Context(), body); result <- err }()
		eventually(t, time.Second, func() bool { s.mu.Lock(); defer s.mu.Unlock(); b := r.lane.pending[2]; return b != nil && b.known })
		bad := bytes.Clone(body)
		bad[len(bad)-1] = 'b'
		duplicate := reserveHTTPTest(t, s, 0, 2, bad)
		if _, err := duplicate.Process(t.Context(), bad); !errors.Is(err, ErrProtocol) {
			t.Fatalf("changed pending=%v", err)
		}
		<-result
		r.Release()
		duplicate.Release()
	})
}

func TestHTTPConveyorAdmissionBoundsAndWrap(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	s := createTestSession(t, manager, profiles[0]).Session
	body := testFrameBatch(t, Frame{Type: FramePong})
	if _, err := s.reserveHTTPUp(0, 5, len(body)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("ahead window=%v", err)
	}
	leases := make([]*httpUpReservation, 0, 2*httpUpWindow)
	for range 2*httpUpWindow - 1 {
		leases = append(leases, reserveHTTPTest(t, s, 0, 2, body))
	}
	if _, err := s.reserveHTTPUp(0, 2, len(body)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("duplicate bound=%v", err)
	}
	// Duplicate future readers must leave a reader slot for the missing head.
	head := reserveHTTPTest(t, s, 0, 1, body)
	head.Release()
	for _, r := range leases {
		r.Release()
	}
	s.mu.Lock()
	s.carrierLanes[0].lastUpSequence = math.MaxUint64
	s.mu.Unlock()
	for _, seq := range []uint64{0, 1, math.MaxUint64 - 4} {
		if _, err := s.reserveHTTPUp(0, seq, len(body)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("wrap sequence %d=%v", seq, err)
		}
	}
}

func TestHTTPConveyorGlobalStagingTransfersApplyCapacity(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(c *ManagerConfig) {
		c.Limits.MaxSessions = 4
		c.Limits.MaxPendingPerSession = 64 * 1024
		c.Limits.MaxPendingGlobal = 128 * 1024
		c.Limits.MaxStreamsPerSession = 1
		c.Limits.MaxBodyBytes = 1024
		c.Limits.CarrierBatchBytes = 1024
	}, dialer.DialContext)
	body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte("x"), 1000)})
	sessions := make([]*Session, 4)
	for i := range sessions {
		sessions[i] = createTestSession(t, manager, profiles[0]).Session
	}
	var staged []*httpUpReservation
	for _, s := range sessions {
		r, err := s.reserveHTTPUp(0, 1, len(body))
		if err != nil {
			if !errors.Is(err, ErrBackpressure) {
				t.Fatal(err)
			}
			break
		}
		staged = append(staged, r)
		t.Cleanup(r.Release)
	}
	if len(staged) == 0 || len(staged) == len(sessions) {
		t.Fatalf("expected partial global fill, staged=%d bytes=%d", len(staged), manager.Capacity().PendingBytes)
	}
	for _, r := range staged {
		if _, err := r.Process(t.Context(), body); err != nil {
			t.Fatalf("prepaid apply cannot progress: %v", err)
		}
		r.Release()
		peer := dialer.Peer(t)
		defer peer.Close()
	}
	if manager.Capacity().PendingBytes == 0 {
		t.Fatal("backend data lost its transferred charge")
	}
	for _, s := range sessions {
		s.Close()
	}
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("staging ownership=%+v", capacity)
	}
}

func TestHTTPConveyorReservesBeforeReadingBody(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(c *ManagerConfig) { c.Limits.MaxPendingPerSession = 200 * 1024 }, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	connection := dialHTTPTest(t, application.address)
	defer connection.Close()
	raw := "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nContent-Type: application/octet-stream\r\nContent-Length: 2097152\r\nX-Up-Seq: 1\r\n\r\n"
	if _, err := io.WriteString(connection, raw); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("admission waited for body: %v", err)
	}
	_ = readHTTPBody(t, response)
	if response.StatusCode != 503 || response.Header.Get(FallbackClassificationHeader) != "" {
		t.Fatalf("admission status=%d", response.StatusCode)
	}
	if capacity := application.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("rejected body ownership=%+v", capacity)
	}
}

func TestHTTPConveyorPartialBodyCloseReleasesReservation(t *testing.T) {
	application := newHTTPTestApplication(t, 100*time.Millisecond)
	created := createTestSession(t, application.manager, application.profiles[0])
	connection := dialHTTPTest(t, application.address)
	raw := "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024\r\nX-Up-Seq: 1\r\n\r\n"
	if _, err := io.WriteString(connection, raw); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool { return application.manager.Capacity().PendingBytes != 0 })
	_ = connection.Close()
	eventually(t, time.Second, func() bool { c := application.manager.Capacity(); return c.PendingBytes == 0 && c.PendingItems == 0 })
}

func TestHTTPConveyorDispatchedGapDisconnectReleasesBody(t *testing.T) {
	application := newHTTPTestApplication(t, 100*time.Millisecond)
	created := createTestSession(t, application.manager, application.profiles[0])
	body := testFrameBatch(t, Frame{Type: FramePong})
	connection := dialHTTPTest(t, application.address)
	raw := "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nContent-Type: application/octet-stream\r\nContent-Length: 8\r\nX-Up-Seq: 2\r\n\r\n"
	if _, err := connection.Write(append([]byte(raw), body...)); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		created.Session.mu.Lock()
		defer created.Session.mu.Unlock()
		lane := created.Session.httpUpLanes[0]
		return lane != nil && lane.pending[2] != nil && lane.pending[2].known
	})
	if application.manager.Capacity().PendingBytes == 0 {
		t.Fatal("dispatched body lost ownership")
	}
	_ = connection.Close()
	eventually(t, time.Second, func() bool { c := application.manager.Capacity(); return c.PendingBytes == 0 && c.PendingItems == 0 })
	if _, err := created.Session.ProcessUp(1, body); err != nil {
		t.Fatalf("canceled gap poisoned session: %v", err)
	}
}

func TestHTTPConveyorRetiredLaneIgnoresLateData(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(c *ManagerConfig) { c.Carrier = CarrierHTTPSLanes }, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	session.usedStreams.Add(41)
	session.mu.Unlock()
	body := testFrameBatch(t, Frame{Type: FrameData, StreamID: 41, Payload: []byte("late")})
	reservation := reserveHTTPTest(t, session, 41, 99, body)
	if ack, err := reservation.Process(t.Context(), body); err != nil || ack != 99 {
		t.Fatalf("retired lane=%d,%v", ack, err)
	}
	reservation.Release()
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || len(session.streams) != 0 || session.carrierLanes[41] != nil {
		t.Fatal("late data recreated its retired lane")
	}
}

func TestHTTPConveyorNewLaneReordersAndAppliesDuplicateOnce(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(c *ManagerConfig) { c.Carrier = CarrierHTTPSLanes }, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 41})
	payload := []byte("ordered once")
	data := testFrameBatch(t, Frame{Type: FrameData, StreamID: 41, Payload: payload})
	second := reserveHTTPTest(t, session, 41, 2, data)
	duplicate := reserveHTTPTest(t, session, 41, 2, data)
	results := make(chan error, 2)
	for _, r := range []*httpUpReservation{second, duplicate} {
		go func() { _, err := r.Process(t.Context(), data); results <- err }()
	}
	eventually(t, time.Second, func() bool { session.mu.Lock(); defer session.mu.Unlock(); return second.lane.pending[2].known })
	first := reserveHTTPTest(t, session, 41, 1, open)
	if _, err := first.Process(t.Context(), open); err != nil {
		t.Fatal(err)
	}
	first.Release()
	peer := dialer.Peer(t)
	defer peer.Close()
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	second.Release()
	duplicate.Release()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("backend data=%q", received)
	}
	if err := peer.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("duplicate uplink reached backend twice")
	}
}
