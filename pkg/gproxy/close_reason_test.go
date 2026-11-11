package gproxy

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func connectionCloseTotals(h *ProxyHandler) (map[string]uint64, uint64) {
	totals := make(map[string]uint64)
	var sum uint64
	for _, stat := range h.ConnectionCloseStats() {
		totals[stat.Reason] = stat.Total
		sum += stat.Total
	}
	return totals, sum
}

// awaitConnectionClose waits for the first counted close, then checks that
// it has the expected reason and that later events do not count it again.
func awaitConnectionClose(t *testing.T, h *ProxyHandler, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, sum := connectionCloseTotals(h); sum > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection close was counted, want %s", want)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	assertConnectionClose(t, h, want)
}

func assertConnectionClose(t *testing.T, h *ProxyHandler, want string) {
	t.Helper()
	totals, sum := connectionCloseTotals(h)
	if sum != 1 || totals[want] != 1 {
		t.Fatalf("connection closes = %v, want exactly one %s", totals, want)
	}
}

func assertNoConnectionClose(t *testing.T, h *ProxyHandler) {
	t.Helper()
	if totals, sum := connectionCloseTotals(h); sum != 0 {
		t.Fatalf("connection closes = %v, want none", totals)
	}
}

func TestConnectionCloseStatsHaveStableReasons(t *testing.T) {
	h := NewProxyHandler(&Config{}, &testLogger{})
	want := []string{
		"client_eof", "client_error", "upstream_closed", "middleend_closed",
		"middleend_backpressure", "middleend_terminal", "idle_timeout", "relay_stall_downlink", "relay_stall_uplink",
		"output_stall", "client_silence", "shutdown", "other",
	}
	stats := h.ConnectionCloseStats()
	if len(stats) != len(want) {
		t.Fatalf("reasons = %v, want %v", stats, want)
	}
	for i, stat := range stats {
		if stat.Reason != want[i] || stat.Total != 0 {
			t.Fatalf("reason %d = %+v, want %s with zero total", i, stat, want[i])
		}
	}
}

// startCountedDirectRelay starts a real two-loop direct relay and returns its
// handler so the test can read the close counters.
func startCountedDirectRelay(t *testing.T, cfg *Config, mode ProtocolMode) (*net.TCPConn, *net.TCPConn, *ConnContext, gnet.Conn, *ProxyHandler) {
	t.Helper()
	clientPeer, clientSocket := directTCPPair(t)
	dcPeer, dcSocket := directTCPPair(t)
	proxy := NewProxyHandler(cfg, &testLogger{})
	proxy.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: dcSocket, encryptor: &mockCipher{}, decryptor: &mockCipher{}}, nil
	}
	dcClient, err := gnet.NewClient(&dcEventHandler{proxy: proxy})
	if err != nil {
		t.Fatal(err)
	}
	if err := dcClient.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.stopDCClient() })
	proxy.dcClient = dcClient
	clientEngine, err := gnet.NewClient(&directClientTestHandler{ProxyHandler: proxy})
	if err != nil {
		t.Fatal(err)
	}
	if err := clientEngine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientEngine.Stop() })
	ctx := NewConnContext()
	ctx.protocolMode = mode
	ctx.decryptor = &mockCipher{}
	ctx.encryptor = &mockCipher{}
	ctx.secret = &Secret{Name: "desktop"}
	ctx.SetState(StateDialingDC)
	clientConn, err := clientEngine.EnrollContext(clientSocket, ctx)
	if err != nil {
		t.Fatal(err)
	}
	awaitDirectRelay(t, ctx)
	return clientPeer, dcPeer, ctx, clientConn, proxy
}

func TestConnectionCloseClientEOF(t *testing.T) {
	client, dc, _, _, proxy := startCountedDirectRelay(t, &Config{}, ModeDD)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	awaitConnectionClose(t, proxy, "client_eof")
	_ = dc.Close()
	time.Sleep(50 * time.Millisecond)
	assertConnectionClose(t, proxy, "client_eof")
}

func TestConnectionCloseClientError(t *testing.T) {
	client, _, _, _, proxy := startCountedDirectRelay(t, &Config{}, ModeDD)
	// A zero linger time makes close send a reset instead of EOF.
	if err := client.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	awaitConnectionClose(t, proxy, "client_error")
}

func TestConnectionCloseUpstreamClosed(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name := "eof"
		if reset {
			name = "reset"
		}
		t.Run(name, func(t *testing.T) {
			_, dc, _, _, proxy := startCountedDirectRelay(t, &Config{}, ModeDD)
			if reset {
				if err := dc.SetLinger(0); err != nil {
					t.Fatal(err)
				}
			}
			if err := dc.Close(); err != nil {
				t.Fatal(err)
			}
			awaitConnectionClose(t, proxy, "upstream_closed")
		})
	}
}

func TestConnectionCloseIdleTimeout(t *testing.T) {
	_, _, ctx, conn, proxy := startCountedDirectRelay(t, &Config{}, ModeDD)
	if err := conn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		ctx.startAuthenticatedIdle(conn, 50*time.Millisecond)
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	awaitConnectionClose(t, proxy, "idle_timeout")
}

func TestConnectionCloseRelayStall(t *testing.T) {
	previous := relayOutputStallTimeout
	relayOutputStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { relayOutputStallTimeout = previous })

	_, observed := stalledDownloadRelay(t)
	awaitRelayWaiting(t, observed)
	awaitConnectionClose(t, observed.proxy, "relay_stall_downlink")
}

// An upload whose DC side stops reading closes as an uplink stall.
func TestConnectionCloseRelayStallUplink(t *testing.T) {
	previous := relayOutputStallTimeout
	relayOutputStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { relayOutputStallTimeout = previous })

	ctx, proxy := stalledUploadRelay(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		relay := ctx.Relay()
		if relay != nil && relay.ToDC != nil {
			relay.ToDC.mu.Lock()
			waiting := relay.ToDC.waiting > 0
			relay.ToDC.mu.Unlock()
			if waiting {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("uplink output never waited for capacity")
		}
		time.Sleep(time.Millisecond)
	}
	awaitConnectionClose(t, proxy, "relay_stall_uplink")
}

func TestConnectionCloseClientSilence(t *testing.T) {
	client, dc, ctx, _, proxy := startCountedDirectRelay(t, &Config{ClientSilenceClose: 50 * time.Millisecond}, ModeDD)
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if err := dc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.Read(got[:]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := dc.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(got[:]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !silenceWedged(ctx.lastClientByteMs.Load(), ctx.lastServerByteMs.Load(), time.Now().UnixMilli(), proxy.clientSilenceCloseMs) {
		if time.Now().After(deadline) {
			t.Fatal("relay never reached the silence wedge state")
		}
		time.Sleep(5 * time.Millisecond)
	}
	proxy.OnTick()
	awaitConnectionClose(t, proxy, "client_silence")
}

func TestConnectionCloseShutdown(t *testing.T) {
	_, _, _, _, proxy := startCountedDirectRelay(t, &Config{}, ModeDD)
	proxy.OnShutdown(gnet.Engine{})
	awaitConnectionClose(t, proxy, "shutdown")
}

func TestConnectionCloseMarkShutdownClassifiesUnrecordedClose(t *testing.T) {
	client, _, _, _, proxy := startCountedDirectRelay(t, &Config{}, ModeDD)
	proxy.MarkShutdown()
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	awaitConnectionClose(t, proxy, "shutdown")
}

func TestConnectionCloseOther(t *testing.T) {
	client, _, _, _, proxy := startCountedDirectRelay(t, &Config{MaxWriteBuffer: 4096}, ModeEE)
	// A complete application record larger than the relay bound is rejected
	// by the client handler, a close without a classified cause.
	record := append([]byte{0x17, 0x03, 0x03, 0x13, 0x88}, bytes.Repeat([]byte{1}, 5000)...)
	if _, err := client.Write(record); err != nil {
		t.Fatal(err)
	}
	awaitConnectionClose(t, proxy, "other")
}

func TestConnectionClosePreRelayIsNotCounted(t *testing.T) {
	h := NewProxyHandler(&Config{}, &testLogger{})
	for _, err := range []error{nil, net.ErrClosed} {
		conn := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateDialingDC)
		conn.SetContext(ctx)
		h.activeConns.Add(1)
		h.OnClose(conn, err)
	}
	assertNoConnectionClose(t, h)
}

func TestConnectionCloseCountedOnceAndLoggedAtDebug(t *testing.T) {
	for _, debug := range []bool{false, true} {
		logger := &webDiagnosticTestLogger{debug: debug}
		h := NewProxyHandler(&Config{}, logger)
		conn := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.secret = &Secret{Name: "desktop"}
		ctx.SetRelay(&RelayContext{})
		ctx.noteClose(closeReasonIdleTimeout)
		ctx.noteClose(closeReasonRelayStallDownlink)
		conn.SetContext(ctx)
		h.activeConns.Add(1)
		h.OnClose(conn, nil)
		h.OnClose(conn, nil)
		assertConnectionClose(t, h, "idle_timeout")

		logger.mu.Lock()
		var lines []string
		for _, message := range logger.debugs {
			if strings.Contains(message, "connection closed reason=") {
				lines = append(lines, message)
			}
		}
		logger.mu.Unlock()
		if !debug {
			if len(lines) != 0 {
				t.Fatalf("debug disabled logged %v", lines)
			}
			continue
		}
		if len(lines) != 1 {
			t.Fatalf("debug close lines = %v, want one", lines)
		}
		for _, part := range []string{"desktop", "reason=idle_timeout", "route=direct", "web=false", "age_ms="} {
			if !strings.Contains(lines[0], part) {
				t.Fatalf("debug close line %q has no %q", lines[0], part)
			}
		}
	}
}

func TestConnectionCloseMiddleEndClosed(t *testing.T) {
	handler, link, conn, ctx, _ := establishMiddleEndDD(t, nil)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventCloseExternal,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
	})
	waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("CloseExternal action = %v, want Close", action)
	}
	closeMiddleEndTestClient(handler, conn, ctx)
	closeMiddleEndTestClient(handler, conn, ctx)
	assertConnectionClose(t, handler, "middleend_closed")
}

func TestConnectionCloseMiddleEndOutputStall(t *testing.T) {
	handler, link, conn, ctx, _ := establishMiddleEndDD(t, func(config *MiddleEndFrontendConfig) {
		config.OutputRetryInitial = time.Millisecond
		config.OutputRetryMax = 2 * time.Millisecond
		config.OutputStallTimeout = 10 * time.Millisecond
	})
	conn.SetOutboundBuffered(handler.maxWriteBuffer)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventProxyAnswer,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
		Packet:       append(validMiddleEndPacket(), 1, 2, 3, 4),
	})
	waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("parked output action = %v", action)
	}
	time.Sleep(25 * time.Millisecond)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("stalled output action = %v, want Close", action)
	}
	closeMiddleEndTestClient(handler, conn, ctx)
	assertConnectionClose(t, handler, "output_stall")
}

func TestConnectionCloseMiddleEndInputBackpressure(t *testing.T) {
	handler, _, conn, ctx, _ := establishMiddleEndDD(t, nil)
	conn.SetReadData(make([]byte, ctx.middleEnd.frontend.maxPendingClient+1))
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("input overflow action = %v, want Close", action)
	}
	closeMiddleEndTestClient(handler, conn, ctx)
	assertConnectionClose(t, handler, "middleend_backpressure")
}

func TestConnectionCloseMiddleEndResponseEviction(t *testing.T) {
	handler, link, conn, ctx, _ := establishMiddleEndDD(t, nil)
	limit := middleEndTestLimits().MaxPendingResponseItemsPerBinding
	for range limit + 1 {
		link.emit(middleend.LinkEvent{
			Kind:         middleend.LinkEventProxyAnswer,
			ConnectionID: ctx.middleEnd.binding.ConnectionID(),
			Packet:       append(validMiddleEndPacket(), 1, 2, 3, 4),
		})
	}
	waitMiddleEndToken(t, ctx.middleEnd)
	deadline := time.Now().Add(3 * time.Second)
	for {
		action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
		if action == gnet.Close {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("evicted binding did not close its client")
		}
		time.Sleep(time.Millisecond)
	}
	closeMiddleEndTestClient(handler, conn, ctx)
	assertConnectionClose(t, handler, "middleend_backpressure")
}

func TestConnectionCloseMiddleEndTerminal(t *testing.T) {
	for _, name := range []string{"link_failure", "manager_close"} {
		t.Run(name, func(t *testing.T) {
			handler, link, conn, ctx, _ := establishMiddleEndDD(t, nil)
			if name == "link_failure" {
				if err := link.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := handler.middleEnd.source.(*middleend.FixedBindingManager).Close(); err != nil {
				t.Fatal(err)
			}
			waitMiddleEndToken(t, ctx.middleEnd)
			deadline := time.Now().Add(3 * time.Second)
			for {
				action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
				if action == gnet.Close {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("terminal binding did not close its client")
				}
				time.Sleep(time.Millisecond)
			}
			closeMiddleEndTestClient(handler, conn, ctx)
			assertConnectionClose(t, handler, "middleend_terminal")
		})
	}
}

func TestConnectionCloseMiddleEndOutputEvictionVictim(t *testing.T) {
	handler, _, _, _, _, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	victimConn, victimCtx, _ := commitMiddleEndDDClient(t, handler)
	currentConn, currentCtx, _ := commitMiddleEndDDClient(t, handler)
	victimCtx.middleEnd.outputAccounted.Store(1024)
	if handler.middleEnd.evictOutputPressureVictim(currentCtx.middleEnd) {
		t.Fatal("eviction selected the current client")
	}
	if !victimConn.IsClosed() {
		t.Fatal("eviction did not close the victim")
	}
	closeMiddleEndTestClient(handler, victimConn, victimCtx)
	assertConnectionClose(t, handler, "middleend_backpressure")
	closeMiddleEndTestClient(handler, currentConn, currentCtx)
}
