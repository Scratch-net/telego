package gproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func decodeDirectEOFResponse(t *testing.T, mode ProtocolMode, wire []byte) []byte {
	t.Helper()
	if mode == ModeEE {
		var payload []byte
		for len(wire) > 0 {
			if len(wire) < faketls.RecordHeaderSize || wire[0] != faketls.RecordTypeApplicationData {
				t.Fatal("incomplete or invalid EOF TLS record")
			}
			n := int(binary.BigEndian.Uint16(wire[3:5]))
			if n == 0 || n > faketls.MaxRecordPayload || len(wire) < faketls.RecordHeaderSize+n {
				t.Fatal("incomplete EOF TLS payload")
			}
			payload = append(payload, wire[faketls.RecordHeaderSize:faketls.RecordHeaderSize+n]...)
			wire = wire[faketls.RecordHeaderSize+n:]
		}
		wire = payload
	}
	directTestCipher(t, 4).XORKeyStream(wire, wire)
	return wire
}

func TestDirectEOFPreservesSlowNativeResponse(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			client, dc, ctx, _ := startDirectRelay(t, mode, nil,
				directTestCipher(t, 1), directTestCipher(t, 2), directTestCipher(t, 3), directTestCipher(t, 4), 2<<20)
			relay := awaitDirectRelay(t, ctx)
			if err := dc.SetReadBuffer(4096); err != nil {
				t.Fatal(err)
			}
			if err := client.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			uplink := make([]byte, 512<<10)
			if mode == ModeEE {
				uplink = nil
				for range 32 {
					uplink = append(uplink, buildTLSRecord(faketls.RecordTypeApplicationData, make([]byte, 16<<10))...)
				}
			}
			if _, err := client.Write(uplink); err != nil {
				t.Fatal(err)
			}
			awaitSpliceCondition(t, "pending uplink at EOF", func() bool {
				var pending bool
				runLogicalOwner(t, relay.DCConn.EventLoop(), func() { pending = relay.DCConn.OutboundBuffered() > 0 })
				return pending
			})
			if mode == ModeEE {
				runLogicalOwner(t, relay.DCConn.EventLoop(), func() {
					relay.DCConn.Context().(*DCConnContext).drs = faketls.NewDRSState(true, true, faketls.MaxRecordPayload)
				})
			}
			if err := client.SetReadBuffer(64 << 10); err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte("response"), 65536)
			wire := make([]byte, len(want))
			directTestCipher(t, 3).XORKeyStream(wire, want)
			if err := dc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := dc.Write(wire); err != nil {
				t.Fatal(err)
			}
			if err := dc.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			awaitSpliceCondition(t, "direct EOF drain", ctx.spliceDrainRequested.Load)
			if err := client.SetReadBuffer(256 << 10); err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(client)
			if err != nil {
				t.Fatal(err)
			}
			if got = decodeDirectEOFResponse(t, mode, got); !bytes.Equal(got, want) {
				t.Fatalf("orderly DC EOF delivered %d/%d bytes", len(got), len(want))
			}
		})
	}
}

func TestDirectEOFLogicalResponseAndEarlyActivation(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		for _, early := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode=%d/early=%v", mode, early), func(t *testing.T) {
				h := NewProxyHandler(&Config{MaxWriteBuffer: 256 << 10, EnableDRS: true, EnableSplitTLS: true}, &testLogger{})
				peer, socket := directTCPPair(t)
				startLogicalDC(t, h, socket)
				allowDial := make(chan struct{})
				releaseDial := sync.OnceFunc(func() { close(allowDial) })
				t.Cleanup(releaseDial)
				dial := h.directDCDial
				h.directDCDial = func(ctx context.Context, id int, kind obfuscated2.ConnectionType) (*directDCConn, error) {
					select {
					case <-allowDial:
						return dial(ctx, id, kind)
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				x := newLogicalTestStream(t, h, func(o *LogicalStreamOptions) {
					o.MaxInputBytes, o.MaxOutputBytes = 64<<10, 4096
				})
				runLogicalOwner(t, x.owner, func() {
					x.stream.ctx.protocolMode = mode
					x.stream.ctx.decryptor = directTestCipher(t, 1)
					x.stream.ctx.encryptor = directTestCipher(t, 4)
					h.startDirectRoute(x.stream, x.stream.ctx)
				})
				unblockOwner := func() {}
				if early {
					entered, release := make(chan struct{}), make(chan struct{})
					unblockOwner = sync.OnceFunc(func() { close(release) })
					t.Cleanup(unblockOwner)
					if err := x.owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
						close(entered)
						<-release
						return nil
					})); err != nil {
						t.Fatal(err)
					}
					<-entered
				}
				releaseDial()
				if !early {
					awaitDirectRelay(t, x.stream.ctx)
				}
				want := bytes.Repeat([]byte("retained direct EOF"), 4000)
				wire := make([]byte, len(want))
				directTestCipher(t, 3).XORKeyStream(wire, want)
				prefix := 0
				if !early {
					prefix = 2048
					if _, err := peer.Write(wire[:prefix]); err != nil {
						t.Fatal(err)
					}
					awaitSpliceCondition(t, "queued logical output", func() bool { return x.stream.ReadableBytes() >= prefix })
				}
				x.output.blocked.Store(true)
				if _, err := peer.Write(wire[prefix:]); err != nil {
					t.Fatal(err)
				}
				if err := peer.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				awaitSpliceCondition(t, "logical direct EOF", x.stream.ctx.spliceDrainRequested.Load)
				if early && x.stream.ctx.State() != StateDialingDC {
					t.Fatal("fixture activated before upstream EOF")
				}
				unblockOwner()
				runLogicalOwner(t, x.owner, func() {})
				x.input.mu.Lock()
				charged := x.input.bytes
				x.input.mu.Unlock()
				if charged < len(want)-prefix {
					t.Fatalf("EOF tail has only %d charged bytes", charged)
				}
				x.output.blocked.Store(false)
				var got []byte
				buf := make([]byte, 4096)
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					n, err := x.stream.TryRead(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						break
					}
					if n == 0 {
						time.Sleep(time.Millisecond)
					}
				}
				if got = decodeDirectEOFResponse(t, mode, got); !bytes.Equal(got, want) {
					t.Fatalf("logical EOF delivered %d/%d bytes", len(got), len(want))
				}
				x.awaitClosed(t)
			})
		}
	}
}

func TestClientEOFDrainTimeoutReleasesLogicalTail(t *testing.T) {
	h := NewProxyHandler(&Config{}, &testLogger{})
	x := newLogicalTestStream(t, h, nil)
	x.output.blocked.Store(true)
	const size = 128
	if !x.stream.reserveAuxInput(size, 1) {
		t.Fatal("tail reservation rejected")
	}
	h.beginClientDrain(x.stream, x.stream.ctx, 20*time.Millisecond, make([]byte, size), func() {
		x.stream.releaseAuxInput(size, 1)
	})
	x.awaitClosed(t)
	x.input.assertEmpty(t)
	x.output.assertEmpty(t)
}

func TestDirectEOFUplinkDisposalKeepsClientDrain(t *testing.T) {
	for _, orderly := range []bool{false, true} {
		t.Run(fmt.Sprint(orderly), func(t *testing.T) {
			client, dc := newTestMockGnetConn(), newTestMockGnetConn()
			ctx := NewConnContext()
			ctx.SetState(StateRelaying)
			output := newRelayOutput(dc, client, ctx, 4096)
			if orderly {
				output.closeForEOF()
			} else {
				output.close()
			}
			output.fail()
			if client.IsClosed() == orderly || !dc.IsClosed() {
				t.Fatalf("retirement orderly=%v closed client=%v DC=%v", orderly, client.IsClosed(), dc.IsClosed())
			}
		})
	}
}
