//go:build linux

package gproxy

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

type stallObservedDCHandler struct {
	*dcEventHandler
	output atomic.Pointer[relayOutput]
}

func (h *stallObservedDCHandler) OnTraffic(c gnet.Conn) gnet.Action {
	action := h.dcEventHandler.OnTraffic(c)
	if ctx := h.getDCContext(c); ctx != nil && ctx.ToClient != nil {
		h.output.Store(ctx.ToClient)
	}
	return action
}

// stalledDownloadRelay starts a direct relay whose client never reads its
// downlink while the DC keeps sending and the client keeps sending pings.
func stalledDownloadRelay(t *testing.T) (*ConnContext, *stallObservedDCHandler) {
	t.Helper()
	client, clientSocket := directTCPPair(t)
	dc, dcSocket := directTCPPair(t)
	if err := client.SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyHandler(&Config{MaxWriteBuffer: 4096, IdleTimeout: time.Hour}, &testLogger{})
	proxy.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: dcSocket, encryptor: &mockCipher{}, decryptor: &mockCipher{}}, nil
	}
	observed := &stallObservedDCHandler{dcEventHandler: &dcEventHandler{proxy: proxy}}
	upstream, err := gnet.NewClient(observed, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err = upstream.Start(); err != nil {
		t.Fatal(err)
	}
	proxy.dcClient = upstream
	t.Cleanup(func() { _ = proxy.stopDCClient() })
	frontend, err := gnet.NewClient(&directClientTestHandler{ProxyHandler: proxy}, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err = frontend.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frontend.Stop() })
	ctx := NewConnContext()
	ctx.protocolMode = ModeDD
	ctx.decryptor = &mockCipher{}
	ctx.encryptor = &mockCipher{}
	ctx.SetState(StateDialingDC)
	if _, err = frontend.EnrollContext(clientSocket, ctx); err != nil {
		t.Fatal(err)
	}
	awaitDirectRelay(t, ctx)

	stop := make(chan struct{})
	done := make(chan struct{}, 3)
	t.Cleanup(func() {
		close(stop)
		_ = dc.Close()
		_ = client.Close()
		for range 3 {
			<-done
		}
	})
	go func() { // DC downlink that the client never reads
		defer func() { done <- struct{}{} }()
		block := bytes.Repeat([]byte{0x6d}, 16<<10)
		for {
			_ = dc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := dc.Write(block); err != nil && !isTimeout(err) {
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	go func() { // DC drains the client's pings
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, 4096)
		for {
			if _, err := dc.Read(buffer); err != nil {
				return
			}
		}
	}()
	go func() { // client pings
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := client.Write([]byte{1, 2, 3, 4}); err != nil {
				return
			}
		}
	}()
	return ctx, observed
}

func isTimeout(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

func awaitRelayWaiting(t *testing.T, observed *stallObservedDCHandler) *relayOutput {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if output := observed.output.Load(); output != nil {
			output.mu.Lock()
			waiting := output.waiting > 0
			output.mu.Unlock()
			if waiting {
				return output
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("downlink output never waited for capacity")
	return nil
}

func TestDirectRelayStalledReaderClosedAfterDeadline(t *testing.T) {
	previous := relayOutputStallTimeout
	relayOutputStallTimeout = 300 * time.Millisecond
	t.Cleanup(func() { relayOutputStallTimeout = previous })

	ctx, observed := stalledDownloadRelay(t)
	awaitRelayWaiting(t, observed)
	deadline := time.Now().Add(3 * time.Second)
	for ctx.State() != StateClosed {
		if time.Now().After(deadline) {
			t.Fatal("client that never reads its downlink was not closed after the stall deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDirectRelayStalledReaderTimerWakeups(t *testing.T) {
	ctx, observed := stalledDownloadRelay(t)
	output := awaitRelayWaiting(t, observed)
	output.mu.Lock()
	before := output.timerRuns
	output.mu.Unlock()
	time.Sleep(500 * time.Millisecond)
	output.mu.Lock()
	runs := output.timerRuns - before
	output.mu.Unlock()
	if ctx.State() == StateClosed {
		t.Fatal("stalled relay closed before the default stall deadline")
	}
	t.Logf("timer runs in 500ms while stalled: %d", runs)
	if runs > 5 {
		t.Fatalf("timer ran %d times in 500ms while write completions were pending", runs)
	}
}

// slowSteadyRelay starts a direct relay whose client reads chunk bytes every
// readEvery. The client also sends pings, as a real client does.
func slowSteadyRelay(t *testing.T, readEvery time.Duration, chunk int) (*ConnContext, *stallObservedDCHandler) {
	t.Helper()
	client, clientSocket := directTCPPair(t)
	dc, dcSocket := directTCPPair(t)
	if err := client.SetReadBuffer(4096); err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyHandler(&Config{MaxWriteBuffer: 4096, IdleTimeout: time.Hour}, &testLogger{})
	proxy.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: dcSocket, encryptor: &mockCipher{}, decryptor: &mockCipher{}}, nil
	}
	observed := &stallObservedDCHandler{dcEventHandler: &dcEventHandler{proxy: proxy}}
	upstream, err := gnet.NewClient(observed, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err = upstream.Start(); err != nil {
		t.Fatal(err)
	}
	proxy.dcClient = upstream
	t.Cleanup(func() { _ = proxy.stopDCClient() })
	frontend, err := gnet.NewClient(&directClientTestHandler{ProxyHandler: proxy}, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err = frontend.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = frontend.Stop() })
	ctx := NewConnContext()
	ctx.protocolMode = ModeDD
	ctx.decryptor = &mockCipher{}
	ctx.encryptor = &mockCipher{}
	ctx.SetState(StateDialingDC)
	if _, err = frontend.EnrollContext(clientSocket, ctx); err != nil {
		t.Fatal(err)
	}
	awaitDirectRelay(t, ctx)

	stop := make(chan struct{})
	done := make(chan struct{}, 4)
	t.Cleanup(func() {
		close(stop)
		_ = dc.Close()
		_ = client.Close()
		for range 4 {
			<-done
		}
	})
	go func() { // slow but steady reader
		defer func() { done <- struct{}{} }()
		buf := make([]byte, chunk)
		for {
			select {
			case <-stop:
				return
			case <-time.After(readEvery):
			}
			_ = client.SetReadDeadline(time.Now().Add(readEvery))
			if _, err := client.Read(buf); err != nil && !isTimeout(err) {
				return
			}
		}
	}()
	go func() { // DC downlink that the client never reads
		defer func() { done <- struct{}{} }()
		block := bytes.Repeat([]byte{0x6d}, 16<<10)
		for {
			_ = dc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := dc.Write(block); err != nil && !isTimeout(err) {
				return
			}
			select {
			case <-stop:
				return
			default:
			}
		}
	}()
	go func() { // DC drains the client's pings
		defer func() { done <- struct{}{} }()
		buffer := make([]byte, 4096)
		for {
			if _, err := dc.Read(buffer); err != nil {
				return
			}
		}
	}()
	go func() { // client pings
		defer func() { done <- struct{}{} }()
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			if _, err := client.Write([]byte{1, 2, 3, 4}); err != nil {
				return
			}
		}
	}()
	return ctx, observed
}

// A client that keeps draining its downlink slowly is not a stalled client.
// Partial drain of an owned write counts as progress.
// The stall period must exceed the TCP zero-window persist interval of the
// tiny test receive window, as the 100s production period does.
func TestDirectRelaySlowSteadyReaderNotClosed(t *testing.T) {
	previous := relayOutputStallTimeout
	relayOutputStallTimeout = 2 * time.Second
	t.Cleanup(func() { relayOutputStallTimeout = previous })
	ctx, observed := slowSteadyRelay(t, 100*time.Millisecond, 1024)
	awaitRelayWaiting(t, observed)
	time.Sleep(3 * relayOutputStallTimeout)
	if ctx.State() == StateClosed {
		t.Fatal("steadily draining slow reader was closed by the stall deadline")
	}
}
