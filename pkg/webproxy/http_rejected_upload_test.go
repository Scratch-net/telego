package webproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func rejectedUploadApplication(t *testing.T, bodyTimeout time.Duration) *httpTestApplication {
	t.Helper()
	return newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Limits.MaxPendingPerSession = 200 * 1024
	}, func(config *HTTPServerConfig) {
		config.BodyTimeout = bodyTimeout
		config.WriteTimeout = time.Second
	})
}

func waitRejectedUploadPermits(t *testing.T, session *Session, local, global int) {
	t.Helper()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		session.manager.mu.Lock()
		defer session.manager.mu.Unlock()
		return session.httpUpDiscards == local && session.manager.httpUpDiscards == global
	})
}

func TestHTTPRejectedUploadStreamsAfterImmediate503(t *testing.T) {
	app := rejectedUploadApplication(t, time.Second)
	created := createTestSession(t, app.manager, app.profiles[0])
	connection := conveyorHTTPUp(t, app, created.Token, 1, maxCarrierBatchBytes, nil)
	conveyorHTTPAck(t, connection, 503, 0)
	waitRejectedUploadPermits(t, created.Session, 1, 1)
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("rejected headers reserved queue capacity: %+v", capacity)
	}
	if _, err := io.Copy(connection, bytes.NewReader(bytes.Repeat([]byte{0xff}, maxCarrierBatchBytes))); err != nil {
		t.Fatalf("early response reset the still-arriving rejected body: %v", err)
	}
	if _, err := connection.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("discarded body did not end with a clean close: %v", err)
	}
	waitRejectedUploadPermits(t, created.Session, 0, 0)
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("discarded body acquired queue storage: %+v", capacity)
	}
}

func TestHTTPRejectedUploadKeepsFixedDeadline(t *testing.T) {
	app := rejectedUploadApplication(t, 80*time.Millisecond)
	created := createTestSession(t, app.manager, app.profiles[0])
	connection := conveyorHTTPUp(t, app, created.Token, 1, maxCarrierBatchBytes, nil)
	conveyorHTTPAck(t, connection, 503, 0)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := connection.Write([]byte{0}); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	if err := connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := connection.Read(make([]byte, 1))
	cancel()
	<-finished
	if err == nil {
		t.Fatal("incomplete rejected upload remained open")
	}
	if networkError, ok := errors.AsType[net.Error](err); ok && networkError.Timeout() {
		t.Fatal("incoming body chunks extended the fixed discard deadline")
	}
	waitRejectedUploadPermits(t, created.Session, 0, 0)
}

func TestHTTPRejectedUploadPermitReleaseOnLifecycle(t *testing.T) {
	for _, mode := range []string{"disconnect", "session close", "server shutdown"} {
		t.Run(mode, func(t *testing.T) {
			app := rejectedUploadApplication(t, time.Second)
			created := createTestSession(t, app.manager, app.profiles[0])
			connection := conveyorHTTPUp(t, app, created.Token, 1, maxCarrierBatchBytes, []byte("partial"))
			conveyorHTTPAck(t, connection, 503, 0)
			waitRejectedUploadPermits(t, created.Session, 1, 1)
			switch mode {
			case "session close":
				created.Session.Close()
				waitRejectedUploadPermits(t, created.Session, 1, 1)
			case "server shutdown":
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := app.server.Stop(ctx); err != nil {
					t.Fatal(err)
				}
			}
			_ = connection.Close()
			waitRejectedUploadPermits(t, created.Session, 0, 0)
			if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
				t.Fatalf("discard lifecycle changed queue capacity: %+v", capacity)
			}
		})
	}
}

func TestHTTPRejectedUploadPermitBoundsSurviveClosedSessions(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxSessions = 1
		config.Limits.MaxStreamsPerSession = 1
		config.Limits.MaxStreams = 2
		config.Limits.MaxBackendDialsInFlight = 1
	}, nil)
	first := createTestSession(t, manager, profiles[0]).Session
	var permits []*httpUpDiscardReservation
	for range 2 * httpUpWindow {
		permit := first.reserveHTTPUpDiscard()
		if permit == nil {
			t.Fatal("missing local discard permit")
		}
		permits = append(permits, permit)
		t.Cleanup(permit.Release)
	}
	if first.reserveHTTPUpDiscard() != nil {
		t.Fatal("discard local limit exceeded")
	}
	first.Close()
	eventually(t, time.Second, func() bool { return manager.Capacity().Sessions == 0 })
	second := createTestSession(t, manager, profiles[0]).Session
	for range httpUpWindow {
		permit := second.reserveHTTPUpDiscard()
		if permit == nil {
			t.Fatal("missing global discard permit")
		}
		permits = append(permits, permit)
		t.Cleanup(permit.Release)
	}
	if second.reserveHTTPUpDiscard() != nil || first.reserveHTTPUpDiscard() != nil {
		t.Fatal("discard permits escaped global or closed-session bound")
	}
	for _, permit := range permits {
		permit.Release()
		permit.Release()
	}
	waitRejectedUploadPermits(t, second, 0, 0)
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("discard metadata consumed queue capacity: %+v", capacity)
	}
}

type rejectedUploadDiscardSpy struct {
	gnet.Conn
	inbound, outbound, discarded, calls int
}

func (c *rejectedUploadDiscardSpy) InboundBuffered() int  { return c.inbound }
func (c *rejectedUploadDiscardSpy) OutboundBuffered() int { return c.outbound }
func (c *rejectedUploadDiscardSpy) Discard(n int) (int, error) {
	if n <= 0 {
		panic("Discard(0) would consume the pipeline suffix")
	}
	c.calls++
	c.inbound -= n
	c.discarded += n
	return n, nil
}

func TestHTTPRejectedUploadDiscardsOnlyDeclaredBody(t *testing.T) {
	for _, remaining := range []int{0, 7} {
		profiles := testProfiles(t)
		manager := testManager(t, profiles, nil, nil)
		session := createTestSession(t, manager, profiles[0]).Session
		permit := session.reserveHTTPUpDiscard()
		if permit == nil {
			t.Fatal("cannot reserve discard metadata")
		}
		state := &httpConnectionState{rejected: &rejectedHTTPUpload{reservation: permit, remaining: remaining}}
		connection := &rejectedUploadDiscardSpy{inbound: remaining + maxPipelineBytes}
		handler := &httpEventHandler{}
		if action := handler.discardRejectedUpload(connection, state); action != gnet.Close {
			t.Fatalf("completed discard action=%v", action)
		}
		if connection.discarded != remaining || connection.inbound != maxPipelineBytes || state.input != nil {
			t.Fatalf("discard crossed declared body: consumed=%d suffix=%d", connection.discarded, connection.inbound)
		}
		waitRejectedUploadPermits(t, session, 1, 1)
		state.close() // The counter follows actual connection disposal.
		state.close()
		waitRejectedUploadPermits(t, session, 0, 0)
	}
}

func TestHTTPRejectedUploadBoundsPipelineWhileResponseBlocked(t *testing.T) {
	for _, remaining := range []int{0, 7} {
		state := &httpConnectionState{rejected: &rejectedHTTPUpload{remaining: remaining}}
		connection := &rejectedUploadDiscardSpy{inbound: remaining + maxPipelineBytes + 1, outbound: 1}
		handler := &httpEventHandler{}
		if action := handler.discardRejectedUpload(connection, state); action != gnet.Close {
			t.Fatalf("blocked response retained an overflowing pipeline: action=%v", action)
		}
		if connection.calls != 0 || connection.discarded != 0 {
			t.Fatal("overflow guard discarded bytes beyond the body boundary")
		}
	}
}

func TestHTTPRejectedUploadDiscardLimitArithmetic(t *testing.T) {
	limits := DefaultLimits()
	local, global, ok := httpUpDiscardLimits(limits)
	if !ok || local != httpUpWindow*(limits.MaxStreamsPerSession+1) || global != httpUpWindow*(limits.MaxStreams+limits.MaxSessions) {
		t.Fatalf("lane-aware limits: local=%d global=%d valid=%t", local, global, ok)
	}
	for _, limits := range []Limits{
		{MaxStreamsPerSession: math.MaxInt, MaxStreams: 1, MaxSessions: 1},
		{MaxStreamsPerSession: 1, MaxStreams: math.MaxInt, MaxSessions: 1},
		{MaxStreamsPerSession: math.MaxInt / httpUpWindow, MaxStreams: 1, MaxSessions: 1},
		{MaxStreamsPerSession: 1, MaxStreams: math.MaxInt / httpUpWindow, MaxSessions: 1},
	} {
		if _, _, ok := httpUpDiscardLimits(limits); ok {
			t.Fatal("overflowing discard limit accepted")
		}
	}
}
