//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package gproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

type pressureObservation struct {
	inputMax    atomic.Int64
	closedInput atomic.Int64
	pressured   atomic.Bool
}

type pressureDCHandler struct {
	*dcEventHandler
	observation *pressureObservation
}

func (h *pressureDCHandler) OnTraffic(c gnet.Conn) gnet.Action {
	n := c.InboundBuffered()
	h.observation.inputMax.Store(max(h.observation.inputMax.Load(), int64(n)))
	ctx := h.getDCContext(c)
	wasRelaying := ctx != nil && ctx.ClientCtx.State() == StateRelaying
	action := h.dcEventHandler.OnTraffic(c)
	if ctx != nil && ctx.ToClient != nil {
		ctx.ToClient.mu.Lock()
		if ctx.ToClient.waiting > 0 {
			h.observation.pressured.Store(true)
		}
		ctx.ToClient.mu.Unlock()
	}
	if action == gnet.Close && wasRelaying {
		h.observation.closedInput.Store(int64(n))
	}
	return action
}

func pressureRelay(t *testing.T, limit int, edge bool) (*net.TCPConn, *net.TCPConn, *ConnContext, *pressureObservation) {
	t.Helper()
	client, clientSocket := directTCPPair(t)
	dc, dcSocket := directTCPPair(t)
	if err := client.SetReadBuffer(64 << 10); err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyHandler(&Config{MaxWriteBuffer: limit}, &testLogger{})
	proxy.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: dcSocket, encryptor: &mockCipher{}, decryptor: &mockCipher{}}, nil
	}
	observation := &pressureObservation{}
	upstream, err := gnet.NewClient(&pressureDCHandler{dcEventHandler: &dcEventHandler{proxy: proxy}, observation: observation}, gnet.WithReadBufferCap(64<<10), gnet.WithSocketSendBuffer(64<<10), gnet.WithEdgeTriggeredIO(edge))
	if err != nil {
		t.Fatal(err)
	}
	if err = upstream.Start(); err != nil {
		t.Fatal(err)
	}
	proxy.dcClient = upstream
	t.Cleanup(func() { _ = proxy.stopDCClient() })
	frontend, err := gnet.NewClient(&directClientTestHandler{ProxyHandler: proxy}, gnet.WithReadBufferCap(64<<10), gnet.WithSocketSendBuffer(64<<10), gnet.WithEdgeTriggeredIO(edge))
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
	return client, dc, ctx, observation
}

func TestDirectDownloadPressureResumes(t *testing.T) {
	const total = 16 << 20
	for _, limit := range []int{4096, 4 << 20} {
		for _, edge := range []bool{false, true} {
			for _, paused := range []bool{false, true} {
				t.Run(fmt.Sprintf("limit=%d/edge=%v/paused=%v", limit, edge, paused), func(t *testing.T) {
					client, dc, ctx, observation := pressureRelay(t, limit, edge)
					if err := dc.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
						t.Fatal(err)
					}
					written := make(chan error, 1)
					go func() {
						block := bytes.Repeat([]byte{0x6d}, 64<<10)
						for range total / len(block) {
							if _, err := dc.Write(block); err != nil {
								written <- err
								return
							}
							time.Sleep(time.Millisecond)
						}
						written <- dc.CloseWrite()
					}()
					t.Cleanup(func() { _ = dc.Close() })
					if paused {
						awaitSpliceCondition(t, "download output pressure", observation.pressured.Load)
						time.Sleep(150 * time.Millisecond)
						if ctx.State() == StateClosed {
							t.Fatalf("slow reader closed: unread=%d", observation.closedInput.Load())
						}
						if n := observation.inputMax.Load(); n > 2*(64<<10)+relayBatchSize {
							t.Fatalf("input grew during pause: %d", n)
						}
					}
					if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(client)
					if err != nil {
						t.Fatalf("received %d/%d bytes: %v", len(got), total, err)
					}
					if !bytes.Equal(got, bytes.Repeat([]byte{0x6d}, total)) {
						t.Fatalf("payload mismatch: received=%d wanted=%d", len(got), total)
					}
					select {
					case err := <-written:
						if err != nil {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("source writer did not complete")
					}
					t.Logf("received %d bytes and orderly EOF; max unread input=%d", len(got), observation.inputMax.Load())
				})
			}
		}
	}
}
