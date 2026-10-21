package webproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"testing"
	"time"
)

func conveyorHTTPUp(t *testing.T, app *httpTestApplication, token string, sequence uint64, size int, body []byte) net.Conn {
	t.Helper()
	conn := dialHTTPTest(t, app.address)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf("POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer %s\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nX-Up-Seq: %d\r\n\r\n", token, size, sequence)
	if _, err := io.WriteString(conn, header); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(conn, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func conveyorHTTPAck(t *testing.T, conn net.Conn, status int, sequence uint64) {
	t.Helper()
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	_ = readHTTPBody(t, response)
	if response.StatusCode != status || response.Header.Get(FallbackClassificationHeader) != "" {
		t.Fatalf("status=%d fallback=%q", response.StatusCode, response.Header.Get(FallbackClassificationHeader))
	}
	if status == http.StatusNoContent && response.Header.Get("X-Up-Ack") != fmt.Sprint(sequence) {
		t.Fatalf("ack=%q want=%d", response.Header.Get("X-Up-Ack"), sequence)
	}
}

func conveyorWaitKnown(t *testing.T, session *Session, sequence uint64) {
	t.Helper()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		lane := session.httpUpLanes[0]
		return lane != nil && lane.pending[sequence] != nil && lane.pending[sequence].known
	})
}

func conveyorHTTPApp(t *testing.T) *httpTestApplication {
	t.Helper()
	return newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
		config.Limits.MaxSessions = 3
		config.Limits.MaxPendingGlobal = config.Limits.MaxPendingPerSession
		config.Limits.MaxPendingItemsGlobal = config.Limits.MaxPendingItemsPerSession
	}, nil)
}

func TestHTTPConveyorReorderedRetryAtGlobalLimit(t *testing.T) {
	app := conveyorHTTPApp(t)
	created := createTestSession(t, app.manager, app.profiles[0])
	created.Session.mu.Lock()
	created.Session.usedStreams.Add(1)
	created.Session.mu.Unlock()
	body := bytes.Repeat(testFrameBatch(t, Frame{Type: FramePong}), MaxBatchFrames)
	second := conveyorHTTPUp(t, app, created.Token, 2, len(body), body)
	conveyorWaitKnown(t, created.Session, 2)
	third := conveyorHTTPUp(t, app, created.Token, 3, len(body), body)
	conveyorWaitKnown(t, created.Session, 3)
	// The fourth body cannot fit all predecessor obligations. Its headers
	// receive the retry response before the client sends any body bytes.
	rejected := conveyorHTTPUp(t, app, created.Token, 4, len(body), nil)
	conveyorHTTPAck(t, rejected, http.StatusServiceUnavailable, 0)
	fillHTTPProgressBudget(t, app.manager, app.profiles[0])
	headBody := maximumHTTPProgressBody(t)
	head := conveyorHTTPUp(t, app, created.Token, 1, len(headBody), headBody)
	conveyorHTTPAck(t, head, http.StatusNoContent, 1)
	conveyorHTTPAck(t, second, http.StatusNoContent, 2)
	conveyorHTTPAck(t, third, http.StatusNoContent, 3)
	retry := conveyorHTTPUp(t, app, created.Token, 4, len(body), body)
	conveyorHTTPAck(t, retry, http.StatusNoContent, 4)
	eventually(t, time.Second, func() bool {
		created.Session.mu.Lock()
		defer created.Session.mu.Unlock()
		return created.Session.pendingCost == 0 && created.Session.pendingItems == 0 && len(created.Session.httpUpLanes) == 0
	})
}

func TestHTTPConveyorPartialPredecessorCancelAtGlobalLimit(t *testing.T) {
	app := conveyorHTTPApp(t)
	created := createTestSession(t, app.manager, app.profiles[0])
	created.Session.mu.Lock()
	created.Session.usedStreams.Add(1)
	created.Session.mu.Unlock()
	small := testFrameBatch(t, Frame{Type: FramePong})
	partial := conveyorHTTPUp(t, app, created.Token, 1, 2*FrameHeaderSize, small)
	eventually(t, time.Second, func() bool {
		created.Session.mu.Lock()
		defer created.Session.mu.Unlock()
		lane := created.Session.httpUpLanes[0]
		return lane != nil && lane.pending[1] != nil && lane.pending[1].readers == 1
	})
	future := conveyorHTTPUp(t, app, created.Token, 3, len(small), small)
	conveyorWaitKnown(t, created.Session, 3)
	fillHTTPProgressBudget(t, app.manager, app.profiles[0])
	before := app.manager.Capacity()
	_ = partial.Close()
	eventually(t, time.Second, func() bool {
		created.Session.mu.Lock()
		defer created.Session.mu.Unlock()
		return created.Session.httpUpLanes[0].pending[1].readers == 0
	})
	if after := app.manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatalf("cancellation forfeited escrow: before=%+v after=%+v", before, after)
	}
	body := maximumHTTPProgressBody(t)
	for sequence := uint64(1); sequence <= 2; sequence++ {
		head := conveyorHTTPUp(t, app, created.Token, sequence, len(body), body)
		conveyorHTTPAck(t, head, http.StatusNoContent, sequence)
	}
	conveyorHTTPAck(t, future, http.StatusNoContent, 3)
}

func TestHTTPConveyorHighestSequenceDoesNotWrap(t *testing.T) {
	manager, profiles := httpProgressManager(t)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	session.carrierLanes[0].lastUpSequence = math.MaxUint64 - 3
	session.mu.Unlock()
	body := testFrameBatch(t, Frame{Type: FramePong})
	future := reserveHTTPTest(t, session, 0, math.MaxUint64, body)
	fillHTTPProgressBudget(t, manager, profiles[0])
	for sequence := uint64(math.MaxUint64 - 2); sequence < math.MaxUint64; sequence++ {
		head := reserveHTTPTest(t, session, 0, sequence, body)
		if ack, err := head.Process(t.Context(), body); err != nil || ack != sequence {
			t.Fatalf("sequence=%d ack=%d err=%v", sequence, ack, err)
		}
		head.Release()
	}
	if ack, err := future.Process(t.Context(), body); err != nil || ack != math.MaxUint64 {
		t.Fatalf("maximum sequence ack=%d err=%v", ack, err)
	}
	future.Release()
}
