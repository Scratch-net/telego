package gproxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func TestUpstreamCloseBarriersCompleteExactlyOnce(t *testing.T) {
	var registry upstreamCloseBarriers
	var completed atomic.Int64
	var workers sync.WaitGroup
	for range 128 {
		barrier := registry.add(func() { completed.Add(1) })
		workers.Go(func() { barrier.finish(); barrier.finish() })
	}
	workers.Go(registry.retire)
	workers.Wait()
	registry.retire()
	late := registry.add(func() { completed.Add(1) })
	late.finish()
	if got := completed.Load(); got != 129 {
		t.Fatalf("completed barriers = %d, want 129", got)
	}
}

func TestLogicalUpstreamStopRetiresAbandonedWritesAndCloseBarriers(t *testing.T) {
	for _, spliceMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "splice"}[spliceMode], func(t *testing.T) {
			key := []byte("0123456789abcdef")
			handler := NewProxyHandler(&Config{
				Secrets: []Secret{{Name: "test", Key: key}}, SpliceHost: "127.0.0.1", SplicePort: 443,
			}, &testLogger{})
			_, socket := directTCPPair(t)
			startLogicalDC(t, handler, socket)
			x := newLogicalTestStream(t, handler, nil)
			var upstream gnet.Conn
			var output *relayOutput
			if spliceMode {
				handler.spliceDial = func(context.Context, string) (net.Conn, error) { return socket, nil }
				x.write(t, buildDeterministicO2ClientFrame(t, []byte("different secret"), 2, obfuscated2.ConnectionTypeIntermediate))
				awaitSpliceCondition(t, "logical splice activation", func() bool {
					splice := x.stream.ctx.splice.Load()
					return splice != nil && splice.active.Load()
				})
				target := x.stream.ctx.splice.Load().upstream.Load()
				upstream, output = target.conn, target.output
			} else {
				x.write(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate))
				relay := awaitDirectRelay(t, x.stream.ctx)
				upstream, output = relay.DCConn, relay.ToDC
			}
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			if err := upstream.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
				close(entered)
				<-release
				// Real gnet exits without consuming the queued write or the
				// next-owner close barrier that OnClose submits afterwards.
				return errorx.ErrEngineShutdown
			})); err != nil {
				t.Fatal(err)
			}
			<-entered
			x.write(t, bytes.Repeat([]byte{1}, 1024))
			awaitSpliceCondition(t, "logical write retained by the stopped owner", func() bool {
				output.mu.Lock()
				defer output.mu.Unlock()
				return output.queued > 0 && len(output.pendingWrites) > 0
			})
			_ = x.stream.Close()
			unblock()
			awaitSpliceCondition(t, "abandoned upstream close barrier", func() bool {
				handler.upstreamCloses.mu.Lock()
				defer handler.upstreamCloses.mu.Unlock()
				return len(handler.upstreamCloses.pending) > 0
			})
			select {
			case err := <-x.closed:
				x.closed <- err
				t.Fatal("logical close released the abandoned write before owner retirement")
			default:
			}
			if err := handler.stopDCClient(); err != nil {
				t.Fatal(err)
			}
			x.awaitClosed(t)
			x.input.assertEmpty(t)
			x.output.assertEmpty(t)
			output.mu.Lock()
			queued, pending := output.queued, len(output.pendingWrites)
			output.mu.Unlock()
			if queued != 0 || pending != 0 {
				t.Fatalf("retained upstream writes after Stop: %d bytes, %d callbacks", queued, pending)
			}
		})
	}
}

func TestUpstreamClientFailureAutomaticallyRetiresDirectAndSplice(t *testing.T) {
	for _, spliceMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "splice"}[spliceMode], func(t *testing.T) {
			key := []byte("0123456789abcdef")
			handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}, SpliceHost: "127.0.0.1", SplicePort: 443}, &testLogger{})
			_, socket := directTCPPair(t)
			startLogicalDC(t, handler, socket)
			failed := make(chan error, 1)
			monitorDone := handler.monitorDCClient(func(err error) { failed <- err })
			x := newLogicalTestStream(t, handler, nil)
			var upstream gnet.Conn
			var output *relayOutput
			if spliceMode {
				handler.spliceDial = func(context.Context, string) (net.Conn, error) { return socket, nil }
				x.write(t, buildDeterministicO2ClientFrame(t, []byte("different secret"), 2, obfuscated2.ConnectionTypeIntermediate))
				awaitSpliceCondition(t, "splice activation", func() bool {
					splice := x.stream.ctx.splice.Load()
					return splice != nil && splice.active.Load()
				})
				target := x.stream.ctx.splice.Load().upstream.Load()
				upstream, output = target.conn, target.output
			} else {
				x.write(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate))
				relay := awaitDirectRelay(t, x.stream.ctx)
				upstream, output = relay.DCConn, relay.ToDC
			}
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			if err := upstream.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
				close(entered)
				<-release
				return errorx.ErrEngineShutdown
			})); err != nil {
				t.Fatal(err)
			}
			<-entered
			x.write(t, bytes.Repeat([]byte{1}, 1024))
			awaitSpliceCondition(t, "queued upstream write", func() bool {
				output.mu.Lock()
				defer output.mu.Unlock()
				return output.queued > 0
			})
			unblock()
			select {
			case err := <-failed:
				if !errors.Is(err, errUpstreamClientStopped) {
					t.Fatalf("unexpected failure cause: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("DC engine failure was not reported")
			}
			<-monitorDone
			x.awaitClosed(t)
			x.input.assertEmpty(t)
			x.output.assertEmpty(t)
			output.mu.Lock()
			queued, pending := output.queued, len(output.pendingWrites)
			output.mu.Unlock()
			if queued != 0 || pending != 0 {
				t.Fatalf("automatic engine cleanup retained %d bytes and %d writes", queued, pending)
			}
		})
	}
}

func TestUpstreamClientFailureCancelsPendingSetup(t *testing.T) {
	for _, spliceMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "splice"}[spliceMode], func(t *testing.T) {
			key := []byte("0123456789abcdef")
			handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}, SpliceHost: "127.0.0.1", SplicePort: 443}, &testLogger{})
			_, socket := directTCPPair(t)
			engine, err := gnet.NewClient(&gnet.BuiltinEventEngine{})
			if err != nil {
				t.Fatal(err)
			}
			if err := engine.Start(); err != nil {
				t.Fatal(err)
			}
			handler.dcClient = engine
			t.Cleanup(func() { _ = handler.stopDCClient() })
			anchor, err := engine.Enroll(socket)
			if err != nil {
				t.Fatal(err)
			}
			failed := make(chan error, 1)
			monitorDone := handler.monitorDCClient(func(err error) { failed <- err })
			started := make(chan struct{})
			waitForCancel := func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				return ctx.Err()
			}
			frameKey := key
			if spliceMode {
				handler.spliceDial = func(ctx context.Context, _ string) (net.Conn, error) { return nil, waitForCancel(ctx) }
				frameKey = []byte("different secret")
			} else {
				handler.directDCDial = func(ctx context.Context, _ int, _ obfuscated2.ConnectionType) (*directDCConn, error) {
					return nil, waitForCancel(ctx)
				}
			}
			x := newLogicalTestStream(t, handler, nil)
			x.write(t, buildDeterministicO2ClientFrame(t, frameKey, 2, obfuscated2.ConnectionTypeIntermediate))
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream setup did not start")
			}
			if err := anchor.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error { return errorx.ErrEngineShutdown })); err != nil {
				t.Fatal(err)
			}
			select {
			case <-failed:
			case <-time.After(3 * time.Second):
				t.Fatal("DC engine failure was not reported")
			}
			<-monitorDone
			x.awaitClosed(t)
			x.input.assertEmpty(t)
			x.output.assertEmpty(t)
		})
	}
}

func TestUpstreamClientConcurrentNormalStopDoesNotReportFailure(t *testing.T) {
	handler := NewProxyHandler(&Config{}, &testLogger{})
	engine, err := gnet.NewClient(&gnet.BuiltinEventEngine{})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	handler.dcClient = engine
	failed := make(chan error, 1)
	monitorDone := handler.monitorDCClient(func(err error) { failed <- err })
	var stopped sync.WaitGroup
	for range 16 {
		stopped.Go(func() {
			if err := handler.stopDCClient(); err != nil {
				t.Errorf("normal Stop: %v", err)
			}
		})
	}
	stopped.Wait()
	select {
	case <-monitorDone:
	case <-time.After(3 * time.Second):
		t.Fatal("normal shutdown retained the engine watcher")
	}
	select {
	case err := <-failed:
		t.Fatalf("normal Stop reported fatal failure: %v", err)
	default:
	}
}

func TestUpstreamPeerDisconnectDoesNotReportEngineFailure(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}}, &testLogger{})
	peer, socket := directTCPPair(t)
	startLogicalDC(t, handler, socket)
	failed := make(chan error, 1)
	monitorDone := handler.monitorDCClient(func(err error) { failed <- err })
	x := newLogicalTestStream(t, handler, nil)
	x.write(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate))
	_ = awaitDirectRelay(t, x.stream.ctx)
	_ = peer.Close()
	x.awaitClosed(t)
	select {
	case <-handler.dcClient.Done():
		t.Fatal("ordinary peer EOF stopped the shared DC engine")
	default:
	}
	if err := handler.stopDCClient(); err != nil {
		t.Fatal(err)
	}
	<-monitorDone
	select {
	case err := <-failed:
		t.Fatalf("ordinary peer EOF reported fatal failure: %v", err)
	default:
	}
}
