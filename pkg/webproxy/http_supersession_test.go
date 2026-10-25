package webproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func TestHTTPServerSupersededDownlinkRetiresStalledWriter(t *testing.T) {
	testHTTPSupersededDownlinkRetiresStalledWriter(t, false)
}

func TestHTTPNginxSupersededDownlinkRetiresStalledWriter(t *testing.T) {
	if os.Getenv("TELEGO_TEST_NGINX_UPLOAD_REJECTION") != "1" {
		t.Skip("run make test-web-nginx for the isolated Nginx integration gate")
	}
	testHTTPSupersededDownlinkRetiresStalledWriter(t, true)
}

func testHTTPSupersededDownlinkRetiresStalledWriter(t *testing.T, throughNginx bool) {
	t.Helper()
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierHTTPSLanes} {
		t.Run(string(carrier), func(t *testing.T) {
			application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
				config.Carrier = carrier
			}, func(config *HTTPServerConfig) {
				config.SocketSendBuffer = 4096
				config.WriteTimeout = 10 * time.Second
			})
			address := application.address
			if throughNginx {
				address, _ = startHTTPNginxTestProxy(t, application)
			}
			created := createTestSession(t, application.manager, application.profiles[0])
			laneID := uint32(0)
			laneHeader := ""
			if carrier == CarrierHTTPSLanes {
				laneID = 41
				laneHeader = "X-Lane-ID: 41\r\n"
				if _, err := created.Session.ProcessUpLane(laneID, 1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: laneID})); err != nil {
					t.Fatal(err)
				}
			}
			created.Session.mu.Lock()
			queued := created.Session.queueFrameLocked(FrameData, max(laneID, 1), bytes.Repeat([]byte{0x63}, MaxFramePayload))
			created.Session.mu.Unlock()
			if !queued {
				t.Fatal("cannot queue downlink")
			}
			stalled := dialHTTPTest(t, address)
			t.Cleanup(func() { _ = stalled.Close() })
			if tcp, ok := stalled.(*net.TCPConn); ok {
				if err := tcp.SetReadBuffer(1024); err != nil {
					t.Fatal(err)
				}
			}
			if err := stalled.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			request := "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nX-Down-Cursor: 0\r\n" + laneHeader + "Content-Length: 0\r\n\r\n"
			if _, err := io.WriteString(stalled, request); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(stalled), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("initial response status = %d", response.StatusCode)
			}
			created.Session.mu.Lock()
			lane := created.Session.carrierLanes[laneID]
			want := bytes.Clone(lane.unacked)
			active := lane.downActive
			created.Session.mu.Unlock()
			if !active || len(want) < MaxFramePayload {
				t.Fatalf("initial response did not retain its large batch: active=%t bytes=%d", active, len(want))
			}
			headers := map[string]string{"Authorization": "Bearer " + created.Token, "X-Down-Cursor": "0"}
			if laneID != 0 {
				headers["X-Lane-ID"] = "41"
			}
			// This deadline is much shorter than the old writer's timeout. The
			// old client never reads its body or closes before replacement.
			proxyApplication := *application
			proxyApplication.address = address
			replay := proxyApplication.do(t, &http.Client{Timeout: 2 * time.Second}, http.MethodPost, "/api/v1/down", nil, headers)
			body := readHTTPBody(t, replay)
			if replay.StatusCode != http.StatusOK || replay.Header.Get("X-Down-Cursor") != response.Header.Get("X-Down-Cursor") || !bytes.Equal(body, want) {
				t.Fatalf("replacement changed replay: status=%d cursor=%q bytes=%d", replay.StatusCode, replay.Header.Get("X-Down-Cursor"), len(body))
			}
		})
	}
}

type supersessionHTTPOwner struct {
	budgetTestOwner
	submitted chan error
	closeConn func(gnet.Conn) error
	closes    int
}

func (o *supersessionHTTPOwner) Execute(ctx context.Context, run gnet.Runnable) error {
	err := o.budgetTestOwner.Execute(ctx, run)
	o.submitted <- err
	return err
}

func (o *supersessionHTTPOwner) Close(connection gnet.Conn) error {
	o.closes++
	return o.closeConn(connection)
}

type supersessionHTTPWrite struct {
	parts    [][]byte
	callback gnet.AsyncCallback
}

type supersessionHTTPConn struct {
	gnet.Conn
	owner    *supersessionHTTPOwner
	writes   chan supersessionHTTPWrite
	buffered int
}

func (c *supersessionHTTPConn) EventLoop() gnet.EventLoop   { return c.owner }
func (c *supersessionHTTPConn) OutboundBuffered() int       { return c.buffered }
func (*supersessionHTTPConn) Wake(gnet.AsyncCallback) error { return nil }

func (c *supersessionHTTPConn) AsyncWritev(parts [][]byte, callback gnet.AsyncCallback) error {
	c.writes <- supersessionHTTPWrite{parts: parts, callback: callback}
	return nil
}

type supersessionHTTPFixture struct {
	session    *Session
	state      *httpConnectionState
	connection *supersessionHTTPConn
	write      supersessionHTTPWrite
	claim      chan struct{}
}

func newSupersessionHTTPFixture(t *testing.T) *supersessionHTTPFixture {
	t.Helper()
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	queued := session.queueFrameLocked(FrameData, 1, []byte("unchanged replay"))
	session.mu.Unlock()
	if !queued {
		t.Fatal("cannot queue response")
	}
	owner := &supersessionHTTPOwner{
		budgetTestOwner: budgetTestOwner{queue: make(chan gnet.Runnable, 4)},
		submitted:       make(chan error, 4),
	}
	connection := &supersessionHTTPConn{owner: owner, writes: make(chan supersessionHTTPWrite, 1), buffered: 1}
	state := &httpConnectionState{}
	t.Cleanup(state.close)
	owner.closeConn = func(gnet.Conn) error {
		state.close()
		connection.buffered = 0
		return nil
	}
	handler := &httpEventHandler{server: &HTTPServer{config: HTTPServerConfig{
		Manager: manager, BodyTimeout: time.Hour, WriteTimeout: time.Hour, IdleTimeout: time.Hour,
	}}}
	handler.dispatch(connection, state, &preparedRequest{kind: requestDown, session: session}, nil)
	var write supersessionHTTPWrite
	select {
	case write = <-connection.writes:
	case <-time.After(time.Second):
		t.Fatal("response did not reach its write callback")
	}
	session.mu.Lock()
	claim := session.carrierLanes[0].superseded
	session.mu.Unlock()
	return &supersessionHTTPFixture{session: session, state: state, connection: connection, write: write, claim: claim}
}

type supersessionHTTPReplay struct {
	body   []byte
	cursor uint64
	lease  *PollLease
	err    error
}

func (f *supersessionHTTPFixture) poll(ctx context.Context) <-chan supersessionHTTPReplay {
	result := make(chan supersessionHTTPReplay, 1)
	go func() {
		body, cursor, lease, err := f.session.PollCarrier(ctx, 0)
		result <- supersessionHTTPReplay{body: body, cursor: cursor, lease: lease, err: err}
	}()
	return result
}

func (f *supersessionHTTPFixture) completeWrite(t *testing.T) {
	t.Helper()
	if err := f.write.callback(f.connection, nil); err != nil {
		t.Fatal(err)
	}
	// Simulate the queue relinquishing references after its callback returns.
	f.write = supersessionHTTPWrite{}
}

func waitSupersessionHTTPClaim(t *testing.T, claim <-chan struct{}) {
	t.Helper()
	select {
	case <-claim:
	case <-time.After(time.Second):
		t.Fatal("replacement did not supersede the original claim")
	}
}

func waitSupersessionHTTPReplay(t *testing.T, result <-chan supersessionHTTPReplay) supersessionHTTPReplay {
	t.Helper()
	select {
	case replay := <-result:
		return replay
	case <-time.After(time.Second):
		t.Fatal("replacement did not finish")
		return supersessionHTTPReplay{}
	}
}

func waitSupersessionHTTPSubmission(t *testing.T, owner *supersessionHTTPOwner) error {
	t.Helper()
	select {
	case err := <-owner.submitted:
		return err
	case <-time.After(time.Second):
		t.Fatal("supersession did not schedule retirement")
		return nil
	}
}

func TestHTTPResponseSupersessionWaitsForWriteCallbackAndClose(t *testing.T) {
	for _, beforeCallback := range []bool{true, false} {
		t.Run(map[bool]string{true: "before callback", false: "during drain"}[beforeCallback], func(t *testing.T) {
			fixture := newSupersessionHTTPFixture(t)
			if !beforeCallback {
				fixture.completeWrite(t)
			}
			result := fixture.poll(t.Context())
			waitSupersessionHTTPClaim(t, fixture.claim)
			if beforeCallback {
				select {
				case <-fixture.connection.owner.submitted:
					t.Fatal("retirement scheduled before the write callback")
				default:
				}
				fixture.completeWrite(t)
			}
			owner := fixture.connection.owner
			if err := waitSupersessionHTTPSubmission(t, owner); err != nil {
				t.Fatal(err)
			}
			if owner.closes != 0 {
				t.Fatal("retirement closed inline in the write callback")
			}
			select {
			case <-result:
				t.Fatal("replacement materialized before old output retired")
			default:
			}
			owner.closeConn = func(gnet.Conn) error {
				fixture.state.close()
				// Match gnet: OnClose precedes outbound storage retirement.
				fixture.session.mu.Lock()
				lane := fixture.session.carrierLanes[0]
				slots, refs := len(lane.downSlot), lane.unackedOwner.refs
				fixture.session.mu.Unlock()
				if slots != 0 || refs != 2 {
					t.Errorf("OnClose released live output: slots=%d refs=%d", slots, refs)
				}
				fixture.connection.buffered = 0
				return nil
			}
			owner.next(t)
			replay := waitSupersessionHTTPReplay(t, result)
			t.Cleanup(replay.lease.Release)
			if replay.err != nil || replay.cursor != 1 || owner.closes != 1 {
				t.Fatalf("replacement cursor=%d error=%v closes=%d", replay.cursor, replay.err, owner.closes)
			}
			assertSingleDataFrame(t, replay.body, 1, []byte("unchanged replay"))
		})
	}
}

func TestHTTPResponseStaleSupersessionKeepsNextResponse(t *testing.T) {
	fixture := newSupersessionHTTPFixture(t)
	fixture.completeWrite(t)
	result := fixture.poll(t.Context())
	waitSupersessionHTTPClaim(t, fixture.claim)
	if err := waitSupersessionHTTPSubmission(t, fixture.connection.owner); err != nil {
		t.Fatal(err)
	}
	fixture.connection.buffered = 0
	fixture.state.finishResponse()
	replay := waitSupersessionHTTPReplay(t, result)
	if replay.err != nil {
		t.Fatal(replay.err)
	}
	fixture.state.beginResponse(fixture.connection, func() {}, replay.lease, false, time.Hour)
	fixture.state.watchResponse(fixture.connection, replay.lease)
	fixture.connection.owner.next(t)
	if fixture.connection.owner.closes != 0 || fixture.state.lease != replay.lease || !fixture.state.draining {
		t.Fatal("stale retirement closed or altered the next keepalive response")
	}
}

func TestHTTPResponseRejectedSupersessionKeepsOwnershipUntilClose(t *testing.T) {
	fixture := newSupersessionHTTPFixture(t)
	fixture.connection.owner.reject.Store(true)
	fixture.completeWrite(t)
	result := fixture.poll(t.Context())
	waitSupersessionHTTPClaim(t, fixture.claim)
	if err := waitSupersessionHTTPSubmission(t, fixture.connection.owner); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retirement submission error = %v", err)
	}
	select {
	case <-result:
		t.Fatal("failed scheduling released response ownership")
	default:
	}
	if fixture.state.lease == nil || fixture.connection.owner.closes != 0 {
		t.Fatal("failed scheduling detached or closed the response")
	}
	fixture.state.close()
	replay := waitSupersessionHTTPReplay(t, result)
	t.Cleanup(replay.lease.Release)
	if replay.err != nil {
		t.Fatal(replay.err)
	}
}

func TestHTTPResponseCancelledReplacementRetiresOnlyOldWriter(t *testing.T) {
	fixture := newSupersessionHTTPFixture(t)
	fixture.completeWrite(t)
	ctx, cancel := context.WithCancel(t.Context())
	result := fixture.poll(ctx)
	waitSupersessionHTTPClaim(t, fixture.claim)
	cancel()
	if replay := waitSupersessionHTTPReplay(t, result); !errors.Is(replay.err, context.Canceled) || replay.lease != nil {
		t.Fatalf("canceled replacement = %+v", replay)
	}
	if err := waitSupersessionHTTPSubmission(t, fixture.connection.owner); err != nil {
		t.Fatal(err)
	}
	fixture.connection.owner.next(t)
	body, cursor, lease, err := fixture.session.PollCarrier(t.Context(), 0)
	t.Cleanup(lease.Release)
	if err != nil || cursor != 1 {
		t.Fatalf("subsequent replay cursor=%d error=%v", cursor, err)
	}
	assertSingleDataFrame(t, body, 1, []byte("unchanged replay"))
}

func TestHTTPResponseRepeatedSupersessionKeepsNewestReplay(t *testing.T) {
	fixture := newSupersessionHTTPFixture(t)
	fixture.completeWrite(t)
	var results []<-chan supersessionHTTPReplay
	claim := fixture.claim
	for range 3 {
		results = append(results, fixture.poll(t.Context()))
		waitSupersessionHTTPClaim(t, claim)
		fixture.session.mu.Lock()
		claim = fixture.session.carrierLanes[0].superseded
		fixture.session.mu.Unlock()
	}
	for _, result := range results[:2] {
		replay := waitSupersessionHTTPReplay(t, result)
		if replay.err != nil || replay.lease != nil || len(replay.body) != 0 {
			t.Fatalf("superseded waiter materialized replay: %+v", replay)
		}
	}
	if err := waitSupersessionHTTPSubmission(t, fixture.connection.owner); err != nil {
		t.Fatal(err)
	}
	fixture.connection.owner.next(t)
	replay := waitSupersessionHTTPReplay(t, results[2])
	t.Cleanup(replay.lease.Release)
	if replay.err != nil || replay.cursor != 1 || fixture.connection.owner.closes != 1 {
		t.Fatalf("newest replacement = %+v, closes=%d", replay, fixture.connection.owner.closes)
	}
	assertSingleDataFrame(t, replay.body, 1, []byte("unchanged replay"))
}

func TestHTTPResponseSupersessionWatchStopsOnCompletionAndClose(t *testing.T) {
	for _, closeConnection := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "close"}[closeConnection], func(t *testing.T) {
			fixture := newSupersessionHTTPFixture(t)
			fixture.completeWrite(t)
			stop := fixture.state.responseStop
			if stop == nil {
				t.Fatal("buffered response omitted supersession watcher")
			}
			if closeConnection {
				fixture.session.Close()
				if capacity := fixture.session.manager.Capacity(); capacity.PendingBytes == 0 {
					t.Fatal("session close released live response ownership")
				}
				fixture.state.close()
				if capacity := fixture.session.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
					t.Fatalf("response close retained capacity: %+v", capacity)
				}
			} else {
				fixture.connection.buffered = 0
				fixture.state.finishResponse()
			}
			select {
			case <-stop:
			default:
				t.Fatal("terminal response left its watcher active")
			}
			if fixture.state.responseStop != nil || fixture.state.lease != nil {
				t.Fatal("terminal response retained watcher or lease association")
			}
			fixture.state.close()
		})
	}
}

func TestHTTPResponseDrainedWriteDoesNotStartSupersessionWatch(t *testing.T) {
	fixture := newSupersessionHTTPFixture(t)
	fixture.connection.buffered = 0
	fixture.completeWrite(t)
	if fixture.state.responseStop != nil || fixture.state.lease != nil || fixture.state.draining {
		t.Fatal("drained response retained watcher or response ownership")
	}
	body, cursor, lease, err := fixture.session.PollCarrier(t.Context(), 0)
	t.Cleanup(lease.Release)
	if err != nil || cursor != 1 {
		t.Fatalf("replay cursor=%d error=%v", cursor, err)
	}
	assertSingleDataFrame(t, body, 1, []byte("unchanged replay"))
}
