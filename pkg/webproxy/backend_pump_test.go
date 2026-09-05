package webproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/panjf2000/gnet/v2"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"
)

func createOwnerTestSession(t *testing.T, app *httpTestApplication) (string, *Session, string) {
	t.Helper()
	bootstrap, err := app.manager.IssueBootstrap(app.profiles[0].Capability(), "198.51.100.17")
	if err != nil {
		t.Fatal(err)
	}
	response := app.do(t, &http.Client{Timeout: 3 * time.Second}, "POST", "/api/v1/session",
		testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}}),
		map[string]string{"Authorization": "Bearer " + bootstrap, "Content-Type": "application/octet-stream"})
	readHTTPBody(t, response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CREATE returned %d", response.StatusCode)
	}
	token := response.Header.Get("X-Session-Token")
	session, err := app.manager.Get(token)
	if err != nil {
		t.Fatal(err)
	}
	return token, session, bootstrap
}

type ownerProbeBackend struct {
	options    BackendOpenOptions
	reads      atomic.Int64
	writes     atomic.Int64
	quota      int
	heldBytes  int
	heldItem   bool
	requested  atomic.Bool
	delayClose bool
}

func (b *ownerProbeBackend) TryRead([]byte) (int, error) {
	b.reads.Add(1)
	return 0, nil
}

func (b *ownerProbeBackend) TryWrite(data []byte) (int, error) {
	b.writes.Add(1)
	n := min(len(data), b.quota)
	if n == 0 {
		return 0, nil
	}
	items := 0
	if !b.heldItem {
		items = 1
	}
	if !b.options.InputBudget.Reserve(n, items) {
		return 0, nil
	}
	b.heldBytes += n
	b.heldItem = true
	b.quota -= n
	return n, nil
}

func (b *ownerProbeBackend) Close() error {
	if !b.requested.CompareAndSwap(false, true) {
		return nil
	}
	if !b.delayClose {
		b.finish()
	}
	return nil
}

func (b *ownerProbeBackend) finish() {
	if b.heldItem {
		b.options.InputBudget.Release(b.heldBytes, 1)
		b.heldBytes = 0
		b.heldItem = false
	}
	b.options.OnClosed(io.EOF)
}

func ownerProbeFactory(opened chan<- *ownerProbeBackend, quota int, delayClose bool) BackendFactory {
	return func(options BackendOpenOptions) (Backend, error) {
		backend := &ownerProbeBackend{options: options, quota: quota, delayClose: delayClose}
		if err := options.Owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
			options.OnOpened(nil)
			opened <- backend
			return nil
		})); err != nil {
			return nil, err
		}
		return backend, nil
	}
}

func TestOwnerBackendIdleDoesNotScheduleItself(t *testing.T) {
	opened := make(chan *ownerProbeBackend, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.BackendFactory = ownerProbeFactory(opened, 0, false)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	backend := <-opened
	time.Sleep(40 * time.Millisecond)
	reads := backend.reads.Load()
	if reads == 0 || reads > 8 {
		t.Fatalf("idle backend probed %d times without notification", reads)
	}
	time.Sleep(40 * time.Millisecond)
	if got := backend.reads.Load(); got != reads {
		t.Fatalf("idle backend scheduled itself: reads grew from %d to %d", reads, got)
	}
}

func TestOwnerBackendPartialWriteRetainsBudgetUntilOwnerClose(t *testing.T) {
	opened := make(chan *ownerProbeBackend, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Limits.MaxStreamsPerSession = 2
		config.Limits.MaxSessions = 2
		config.Limits.MaxPendingPerSession = 128 * 1024
		config.Limits.MaxPendingGlobal = 1024 * 1024
		config.Limits.MaxBodyBytes = 4096
		config.Limits.CarrierBatchBytes = 4096
		config.BackendFactory = ownerProbeFactory(opened, 1, true)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	payload := bytes.Repeat([]byte{0x5a}, 3000)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: payload})); err != nil {
		t.Fatal(err)
	}
	backend := <-opened
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		state := session.streams[1]
		return state != nil && state.writeOffset == 1
	})
	session.mu.Lock()
	state := session.streams[1]
	if state.pendingWriteCost != len(payload)+queueItemCost || state.pendingWriteBytes != len(payload)-1 {
		t.Errorf("partial source ownership: bytes=%d cost=%d", state.pendingWriteBytes, state.pendingWriteCost)
	}
	if state.backend.inputCost != 1+queueItemCost {
		t.Errorf("core copy charge=%d", state.backend.inputCost)
	}
	session.mu.Unlock()
	session.Close()
	eventually(t, time.Second, backend.requested.Load)
	if cost := app.manager.Capacity().PendingBytes; cost != int64(1+queueItemCost) {
		t.Fatalf("close released retained backend storage early: %d", cost)
	}
	short, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := app.manager.Shutdown(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown returned before owner cleanup: %v", err)
	}
	finished := make(chan struct{})
	if err := backend.options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		backend.finish()
		close(finished)
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	<-finished
	ctx, cancelFinal := context.WithTimeout(t.Context(), time.Second)
	defer cancelFinal()
	if err := app.manager.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 || capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("owner close leaked budgets: %+v", capacity)
	}
}

func TestOwnerBackendExplicitUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backend.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox forbids Unix socket creation")
		}
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			_, _ = io.Copy(connection, connection)
		}
	}()
	app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
		config.Backend = "unix://" + path
		config.BackendFactory = GnetBackendFactory(nil)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	payload := []byte("unix enrollment")
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: payload})); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		for _, frame := range session.carrierLanes[0].pendingFrames {
			if frame.frameType == FrameData && bytes.Equal(frame.encoded[FrameHeaderSize:], payload) {
				return true
			}
		}
		return false
	})
	session.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Unix backend did not close")
	}
}

func TestOwnerBackendCreateRetryKeepsFirstOwner(t *testing.T) {
	opened := make(chan *ownerProbeBackend, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.BackendFactory = ownerProbeFactory(opened, 0, false)
	}, func(config *HTTPServerConfig) { config.NumEventLoop = 2 })
	token, session, bootstrap := createOwnerTestSession(t, app)
	firstOwner := session.owner
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response := app.do(t, client, "POST", "/api/v1/session", testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}}),
		map[string]string{"Authorization": "Bearer " + bootstrap, "Content-Type": "application/octet-stream"})
	readHTTPBody(t, response)
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Session-Token") != token {
		t.Fatalf("CREATE retry changed session: status%d token%q", response.StatusCode, response.Header.Get("X-Session-Token"))
	}
	response = app.do(t, client, "POST", "/api/v1/up", testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}),
		map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream", "X-Up-Seq": "1"})
	readHTTPBody(t, response)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("reconnected UP returned %d", response.StatusCode)
	}
	backend := <-opened
	if session.owner != firstOwner || backend.options.Owner != firstOwner {
		t.Fatal("later HTTP attachments moved the stream to another owner")
	}
}

func TestOwnerBackendPumpYieldsBetweenStreamBatches(t *testing.T) {
	var factoryCalls atomic.Int64
	observed := make(chan int64, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.BackendFactory = func(options BackendOpenOptions) (Backend, error) {
			backend := &ownerProbeBackend{options: options}
			if factoryCalls.Add(1) == 1 {
				if err := options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
					observed <- factoryCalls.Load()
					return nil
				})); err != nil {
					return nil, err
				}
			}
			if err := options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
				options.OnOpened(nil)
				return nil
			})); err != nil {
				return nil, err
			}
			return backend, nil
		}
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	var frames []Frame
	for id := uint32(1); id <= 20; id++ {
		frames = append(frames, Frame{Type: FrameOpen, StreamID: id})
	}
	if _, err := session.ProcessUp(1, testFrameBatch(t, frames...)); err != nil {
		t.Fatal(err)
	}
	select {
	case count := <-observed:
		if count > 4 {
			t.Fatalf("pump processed %d streams before sibling owner work", count)
		}
	case <-time.After(time.Second):
		t.Fatal("sibling event-loop work was starved")
	}
	eventually(t, time.Second, func() bool { return factoryCalls.Load() == 20 })
}

func TestOwnerBackendCancelDuringDialFinishesBookkeeping(t *testing.T) {
	started := make(chan struct{})
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.BackendFactory = GnetBackendFactory(func(ctx context.Context, _, _, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameClose, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		capacity := app.manager.Capacity()
		return capacity.Streams == 0 && capacity.BackendDials == 0
	})
}

func TestOwnerBackendOwnerStopDuringDialFinishesBookkeeping(t *testing.T) {
	started := make(chan struct{})
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.BackendFactory = GnetBackendFactory(func(ctx context.Context, _, _, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := app.server.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	session.Close()
	if err := app.manager.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if capacity := app.manager.Capacity(); capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("owner rejection stranded establishment: %+v", capacity)
	}
}

func TestOwnerBackendFatalExitRetiresAbandonedSocketDisposal(t *testing.T) {
	created := make(chan *socketBackend, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		factory := GnetBackendFactory(nil)
		config.BackendFactory = func(options BackendOpenOptions) (Backend, error) {
			backend, err := factory(options)
			if err == nil {
				created <- backend.(*socketBackend)
			}
			return backend, err
		}
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.streams[1].sendCredit = 0
	session.mu.Unlock()
	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameData, StreamID: 1, Payload: []byte("retained response")})); err != nil {
		t.Fatal(err)
	}
	backend := <-created
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.streams[1].backend.outputItems == 1
	})
	entered, release := make(chan struct{}), make(chan struct{})
	closed := make(chan error, 1)
	if err := session.owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		close(entered)
		<-release
		// OnClose accepts its next-owner disposal barrier, then this fatal
		// event abandons that barrier before it can acknowledge OnClosed.
		closed <- session.owner.Close(backend.conn)
		return errorx.ErrEngineShutdown
	})); err != nil {
		t.Fatal(err)
	}
	<-entered
	session.Close()
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := app.server.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := app.manager.Shutdown(ctx); err != nil {
		t.Fatalf("owner retirement stranded manager shutdown: %v", err)
	}
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 || capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("abandoned socket disposal retained resources: %+v", capacity)
	}
}

func TestOwnerBackendLateDialSuccessAfterRetirementClosesSocket(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	socket := make(chan net.Conn, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.BackendFactory = GnetBackendFactory(func(ctx context.Context, network, address, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			close(started)
			<-release
			socket <- conn
			return conn, nil
		})
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	<-started
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := app.server.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if capacity := app.manager.Capacity(); capacity.Streams != 1 || capacity.BackendDials != 1 {
		t.Fatalf("retirement acknowledged unfinished setup: %+v", capacity)
	}
	close(release)
	conn := <-socket
	if err := app.manager.Shutdown(ctx); err != nil {
		t.Fatalf("late successful dial stranded retirement: %v", err)
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retired owner retained late setup socket: %v", err)
	}
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 || capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("late setup retained resources: %+v", capacity)
	}
}

func TestOwnerBackendDirectionalHandoffReserves(t *testing.T) {
	opened := make(chan *ownerProbeBackend, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Limits.MaxStreamsPerSession = 2
		config.Limits.MaxSessions = 2
		config.Limits.MaxPendingPerSession = 128 * 1024
		config.Limits.MaxPendingGlobal = 1024 * 1024
		config.Limits.MaxBodyBytes = 4096
		config.Limits.CarrierBatchBytes = 4096
		config.BackendFactory = ownerProbeFactory(opened, 0, false)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	backend := <-opened
	finished := make(chan error, 1)
	if err := session.owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		session.mu.Lock()
		ordinaryLimit, _ := session.uplinkPendingLimits()
		filler := ordinaryLimit - session.pendingCost
		ok := session.reservePendingLocked(filler, 0, pendingUplink)
		session.mu.Unlock()
		if !ok {
			finished <- errors.New("could not saturate ordinary uplink budget")
			return nil
		}
		control, _, _ := pendingControlReserve(session.limits)
		headroom, _ := backendHandoffReserve(session.limits)
		globalLimit := session.limits.MaxPendingGlobal - (control+headroom)*session.limits.MaxSessions
		globalFiller := globalLimit - int(app.manager.Capacity().PendingBytes)
		if globalFiller > 0 && !app.manager.changePendingBudget(globalFiller, 0, pendingUplink) {
			finished <- errors.New("could not saturate global ordinary budget")
			return nil
		}
		input := headroom/2 - queueItemCost
		if !backend.options.InputBudget.Reserve(input, 1) {
			finished <- errors.New("full carrier queue prevented source-to-core handoff")
			return nil
		}
		if backend.options.InputBudget.Reserve(1, 0) {
			finished <- errors.New("uplink consumed reserved downlink transfer capacity")
			return nil
		}
		session.mu.Lock()
		downCost := min(4096, headroom/2)
		ok = session.reservePendingLocked(downCost, 1, pendingHandoff)
		if ok {
			session.releasePendingQuietLocked(downCost, 1)
		}
		session.releasePendingQuietLocked(filler, 0)
		session.mu.Unlock()
		backend.options.InputBudget.Release(input, 1)
		if globalFiller > 0 {
			app.manager.changePendingBudget(-globalFiller, 0, pendingUplink)
		}
		if !ok {
			finished <- errors.New("stalled uplink prevented downlink destination reservation")
		} else {
			finished <- nil
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestOwnerBackendWithheldWindowKeepsDownlinkBounded(t *testing.T) {
	app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
		config.BackendFactory = GnetBackendFactory(nil)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	payload := []byte("wait for WINDOW")
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.streams[1].sendCredit = 0
	session.mu.Unlock()
	if _, err := session.ProcessUp(2, testFrameBatch(t, Frame{Type: FrameData, StreamID: 1, Payload: payload})); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.streams[1].backend.outputCost == len(payload)+queueItemCost
	})
	session.mu.Lock()
	for _, frame := range session.carrierLanes[0].pendingFrames {
		if frame.frameType == FrameData {
			t.Error("backend bypassed withheld receive credit")
		}
	}
	session.mu.Unlock()
	window, err := WindowPayload(uint32(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.ProcessUp(3, testFrameBatch(t, Frame{Type: FrameWindow, StreamID: 1, Payload: window})); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		for _, frame := range session.carrierLanes[0].pendingFrames {
			if frame.frameType == FrameData && bytes.Equal(frame.encoded[FrameHeaderSize:], payload) {
				return true
			}
		}
		return false
	})
}

func TestOwnerBackendAllCarriers(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierHTTPSLanes, CarrierWebSocket, CarrierWebSocketLanes} {
		t.Run(string(carrier), func(t *testing.T) {
			app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
				config.Carrier = carrier
				config.BackendFactory = GnetBackendFactory(nil)
			}, nil)
			token, session, _ := createOwnerTestSession(t, app)
			payload := []byte("owner loop echo")
			body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: payload})
			var got []byte
			if carrier.usesWebSocket() {
				protocol := webSocketProtocolPrefix + token
				if carrier.usesLanes() {
					protocol = webSocketLaneProtocolPrefix + token + ".1"
				}
				client, response := dialWebSocketTest(t, app.address, protocol, "", nil)
				if response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("upgrade returned %d", response.StatusCode)
				}
				defer client.close()
				client.write(t, ws.OpBinary, true, body)
				for len(got) < len(payload) {
					frames, err := readWebSocketBatchResult(t, client, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					for _, frame := range frames {
						if frame.Type == FrameData {
							got = append(got, frame.Payload...)
						}
					}
				}
				client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameClose, StreamID: 1}))
			} else {
				client := &http.Client{Timeout: 3 * time.Second}
				headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream", "X-Up-Seq": "1"}
				if carrier.usesLanes() {
					headers["X-Lane-ID"] = "1"
				}
				response := app.do(t, client, "POST", "/api/v1/up", body, headers)
				readHTTPBody(t, response)
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("UP returned %d", response.StatusCode)
				}
				cursor := "0"
				delete(headers, "X-Up-Seq")
				delete(headers, "Content-Type")
				for attempts := 0; len(got) < len(payload) && attempts < 10; attempts++ {
					headers["X-Down-Cursor"] = cursor
					response = app.do(t, client, "POST", "/api/v1/down", nil, headers)
					data := readHTTPBody(t, response)
					if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
						t.Fatalf("DOWN returned %d", response.StatusCode)
					}
					cursor = response.Header.Get("X-Down-Cursor")
					if len(data) == 0 {
						continue
					}
					frames, err := ParseBatch(data)
					if err != nil {
						t.Fatal(err)
					}
					for _, frame := range frames {
						if frame.Type == FrameData {
							got = append(got, frame.Payload...)
						}
					}
				}
				delete(headers, "X-Down-Cursor")
				headers["X-Up-Seq"] = strconv.Itoa(2)
				headers["Content-Type"] = "application/octet-stream"
				response = app.do(t, client, "POST", "/api/v1/up", testFrameBatch(t, Frame{Type: FrameClose, StreamID: 1}), headers)
				readHTTPBody(t, response)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo=%q", got)
			}
			eventually(t, time.Second, func() bool { return app.manager.Capacity().Streams == 0 })
			session.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := app.manager.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			capacity := app.manager.Capacity()
			if capacity.PendingBytes != 0 || capacity.PendingItems != 0 || capacity.BackendDials != 0 {
				t.Fatalf("leaked ownership: %+v", capacity)
			}
		})
	}
}
