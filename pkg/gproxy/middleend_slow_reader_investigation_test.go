//go:build me_pressure_investigation

package gproxy

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
	"github.com/scratch-net/telego/pkg/webproxy"
)

// These opt-in acceptance cases exercise the shared response policy through
// production managers, codecs, owners and client transports with a controlled
// post-decode ME event source. They do not change production defaults.
const pressureInvestigationBudget = 32*1024*1024 + 16*1024

type pressureInvestigationHandler struct {
	*ProxyHandler
	opened chan gnet.Conn
}

func (h *pressureInvestigationHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	out, action := h.ProxyHandler.OnOpen(c)
	h.opened <- c
	return out, action
}

type pressureInvestigationRig struct {
	handler *ProxyHandler
	manager *middleend.FixedBindingManager
	link    *middleEndTestLink
	native  *gnet.Client
	opened  chan gnet.Conn
	serial  uint64
	budget  *middleend.ResponseBudget
}

func newPressureInvestigationRig(t *testing.T, queueBytes int, stall time.Duration) *pressureInvestigationRig {
	t.Helper()
	link := newMiddleEndTestLink()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-link.submitted:
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-stopped })
	budget, err := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{
		LimitBytes:             2*pressureInvestigationBudget + MiddleEndResponseProcessingBytes(),
		ProcessingReserveBytes: MiddleEndResponseProcessingBytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 || snapshot.HighWaterBytes > snapshot.LimitBytes {
			t.Errorf("response ownership after complete cleanup: %+v", snapshot)
		}
	})
	limits := middleEndTestLimits()
	// Match the default resident limits derived by pkg/config/middleend.go.
	limits.MaxResidentBindings = 10_000
	limits.MaxResidentBindingsPerSlot = 2_500
	limits.MaxPendingResponseBytesPerBinding = queueBytes
	limits.MaxPendingResponseBytesPerSlot = pressureInvestigationBudget
	limits.MaxPendingResponseBytes = pressureInvestigationBudget
	limits.MaxPendingResponseItemsPerBinding = 768
	limits.MaxPendingResponseItemsPerSlot = 4096
	limits.MaxPendingResponseItems = 4096
	manager, err := middleend.NewFixedBindingManagerWithResponseBudget(
		[]middleend.FixedBindingSlot{{DCID: 2, SourceIP: netip.MustParseAddr("8.8.8.8"), Link: link}}, limits, budget,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	config := middleEndTestFrontendConfig(t, manager)
	config.MaxPendingOutputBytesTotal = pressureInvestigationBudget
	config.MaxPendingClientBytesTotal = pressureInvestigationBudget
	config.ResponseBudget = budget
	config.OutputRetryInitial = 25 * time.Millisecond
	config.OutputRetryMax = 120 * time.Millisecond
	config.OutputStallTimeout = stall
	handler, err := NewProxyHandlerWithMiddleEnd(&Config{
		Secrets:        []Secret{{Name: "investigation", Key: []byte("0123456789abcdef"), Host: "example.com"}},
		MaxWriteBuffer: 4 << 20, TimeSkewTolerance: time.Minute,
	}, &testLogger{}, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.middleEnd.stop)
	rig := &pressureInvestigationRig{handler: handler, manager: manager, link: link, budget: budget, opened: make(chan gnet.Conn, 4)}
	engine, err := gnet.NewClient(&pressureInvestigationHandler{ProxyHandler: handler, opened: rig.opened},
		gnet.WithSocketSendBuffer(4096), gnet.WithReadBufferCap(64<<10))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	rig.native = engine
	t.Cleanup(func() { _ = engine.Stop() })
	return rig
}

type pressureInvestigationClient struct {
	endpoint clientEndpoint
	ctx      *ConnContext
	client   *middleEndClient
	owner    gnet.EventLoop
	read     func([]byte) error
	close    func()
	mode     ProtocolMode
	cipher   cipher.Stream
	decoder  *middleend.ClientPacketDecoder
}

func (r *pressureInvestigationRig) connect(t *testing.T, web bool, mode ProtocolMode) *pressureInvestigationClient {
	t.Helper()
	r.serial++
	p := &pressureInvestigationClient{mode: mode}
	var write func([]byte)
	if web {
		x := newLogicalTestStream(t, r.handler, func(options *LogicalStreamOptions) {
			// backendStream.open uses this cap with DefaultLimits. The HTTP
			// experiment below also checks the actual factory-derived value.
			options.MaxOutputBytes = webproxy.MaxFramePayload + webproxy.RelayDataChunk
		})
		p.endpoint, p.ctx, p.owner = x.stream, x.stream.ctx, x.owner
		p.read = func(dst []byte) error { copy(dst, x.read(t, len(dst))); return nil }
		p.close = func() { _ = x.stream.Close() }
		write = func(data []byte) { x.write(t, data) }
	} else {
		peer, socket := directTCPPair(t)
		if err := peer.SetReadBuffer(64 << 10); err != nil {
			t.Fatal(err)
		}
		if _, err := r.native.Enroll(socket); err != nil {
			t.Fatal(err)
		}
		var conn gnet.Conn
		select {
		case conn = <-r.opened:
		case <-time.After(3 * time.Second):
			t.Fatal("native client did not open")
		}
		p.endpoint, p.ctx, p.owner = conn, conn.Context().(*ConnContext), conn.EventLoop()
		p.read = func(dst []byte) error {
			if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			_, err := io.ReadFull(peer, dst)
			return err
		}
		p.close = func() { _ = peer.Close(); _ = conn.Close() }
		write = func(data []byte) {
			if _, err := peer.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(p.close)
	}
	key := r.handler.config.Secrets[0].Key
	if mode == ModeEE {
		sessionID := make([]byte, 32)
		binary.LittleEndian.PutUint64(sessionID, r.serial)
		write(buildTLSRecord(faketls.RecordTypeHandshake,
			buildValidClientHello(key, "example.com", sessionID)))
		for _, kind := range []byte{faketls.RecordTypeHandshake, faketls.RecordTypeChangeCipherSpec, faketls.RecordTypeApplicationData} {
			header := make([]byte, 5)
			if err := p.read(header); err != nil {
				t.Fatal(err)
			}
			if header[0] != kind {
				t.Fatalf("handshake record %x, want %x", header[0], kind)
			}
			if err := p.read(make([]byte, int(binary.BigEndian.Uint16(header[3:5])))); err != nil {
				t.Fatal(err)
			}
		}
	}
	frame := buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate)
	// The first eight bytes are outside the key/IV block. Give each DD
	// client a distinct replay-cache identity without changing its ciphers.
	binary.LittleEndian.PutUint64(frame[:8], r.serial<<8|0xa5)
	_, _, responseCipher, _, err := obfuscated2.ParseClientFrameWithType(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	p.cipher = responseCipher
	p.decoder, err = middleend.NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, middleend.MaxClientPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.decoder.Close() })
	if mode == ModeEE {
		frame = buildTLSRecord(faketls.RecordTypeApplicationData, frame)
	}
	write(frame)
	awaitSpliceCondition(t, "ME client commit", func() bool {
		runLogicalOwner(t, p.owner, func() { p.client = p.ctx.middleEnd })
		return p.client != nil
	})
	return p
}

func pressureInvestigationPacket(size, sequence int) []byte {
	packet := bytes.Repeat([]byte{byte(sequence%251 + 1)}, size)
	binary.LittleEndian.PutUint64(packet, 1)
	binary.LittleEndian.PutUint64(packet[8:], uint64(sequence))
	return packet
}

func (p *pressureInvestigationClient) receive(t *testing.T, expected []byte) {
	t.Helper()
	for {
		packet, ok, err := p.decoder.Next()
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			defer clear(packet.Payload)
			if !bytes.Equal(packet.Payload, expected) {
				t.Fatalf("response changed or reordered: got %d bytes, want %d", len(packet.Payload), len(expected))
			}
			return
		}
		var wire []byte
		if p.mode == ModeEE {
			header := make([]byte, 5)
			if err := p.read(header); err != nil {
				t.Fatal(err)
			}
			if header[0] != faketls.RecordTypeApplicationData {
				t.Fatalf("unexpected response TLS record %x", header[0])
			}
			wire = make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
		} else {
			wire = make([]byte, len(expected)+4)
		}
		if err := p.read(wire); err != nil {
			t.Fatal(err)
		}
		p.cipher.XORKeyStream(wire, wire)
		if _, err := p.decoder.Feed(wire); err != nil {
			t.Fatal(err)
		}
	}
}

func (p *pressureInvestigationClient) progress(t *testing.T) (written uint64, buffered int, closed bool) {
	t.Helper()
	runLogicalOwner(t, p.owner, func() {
		written = p.client.responseWriteEvents
		closed = p.ctx.State() == StateClosed
		if !closed {
			buffered = p.endpoint.OutboundBuffered()
		}
	})
	return
}

func (r *pressureInvestigationRig) send(t *testing.T, p *pressureInvestigationClient, packet []byte, submitted int) {
	t.Helper()
	r.link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer,
		ConnectionID: p.client.binding.ConnectionID(), Packet: bytes.Clone(packet)})
	awaitSpliceCondition(t, "response admitted or terminal", func() bool {
		written, _, closed := p.progress(t)
		snapshot := r.manager.Snapshot()
		return closed || snapshot.ResponseBackpressureEvents != 0 || int(written)+snapshot.ResponseItems >= submitted
	})
}

func TestInvestigationSlowReaderMatrix(t *testing.T) {
	for _, transport := range []struct {
		name string
		web  bool
		mode ProtocolMode
	}{{"tcp_dd", false, ModeDD}, {"tcp_ee", false, ModeEE}, {"web_dd", true, ModeDD}, {"web_ee", true, ModeEE}} {
		for _, scenario := range []struct {
			name       string
			queueBytes int
			packets    int
			paced      bool
		}{{"pause_2m", 2 << 20, 4, false}, {"burst_8m", 2 << 20, 16, false},
			{"queue8_burst8", 8 << 20, 16, false}, {"queue8_burst16", 8 << 20, 32, false},
			{"shared_burst16", pressureInvestigationBudget, 32, false}, {"paced_12m", 2 << 20, 24, true}} {
			t.Run(transport.name+"/"+scenario.name, func(t *testing.T) {
				rig := newPressureInvestigationRig(t, scenario.queueBytes, 100*time.Second)
				slow := rig.connect(t, transport.web, transport.mode)
				fast := rig.connect(t, transport.web, transport.mode)
				start := time.Now()
				admitted := 0
				peakOutput := 0
				var fastLatency time.Duration
				for sequence := range scenario.packets {
					rig.send(t, slow, pressureInvestigationPacket(512<<10, sequence), sequence+1)
					_, buffered, closed := slow.progress(t)
					peakOutput = max(peakOutput, buffered)
					fastPacket := pressureInvestigationPacket(64, sequence)
					fastStart := time.Now()
					rig.link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer,
						ConnectionID: fast.client.binding.ConnectionID(), Packet: bytes.Clone(fastPacket)})
					fast.receive(t, fastPacket)
					fastLatency = max(fastLatency, time.Since(fastStart))
					if closed || rig.manager.Snapshot().ResponseBackpressureEvents != 0 {
						break
					}
					admitted++
					if scenario.paced {
						time.Sleep(25 * time.Millisecond)
						slow.receive(t, pressureInvestigationPacket(512<<10, sequence))
					}
				}
				beforeDrain := rig.manager.Snapshot()
				recovered := beforeDrain.ResponseBackpressureEvents == 0
				if recovered && !scenario.paced {
					time.Sleep(100 * time.Millisecond)
					for sequence := range admitted {
						slow.receive(t, pressureInvestigationPacket(512<<10, sequence))
					}
				}
				if !recovered || admitted != scenario.packets {
					t.Error("acceptance failure: finite burst evicted a client with spare shared response budget")
				}
				if rig.budget.Snapshot().HighWaterBytes > rig.budget.Snapshot().LimitBytes ||
					beforeDrain.SlotFailures != 0 || fast.ctx.State() == StateClosed {
					t.Error("shared budget or fast-client isolation failed")
				}
				slow.close()
				fast.close()
				awaitSpliceCondition(t, "frontend and queue cleanup", func() bool {
					s := rig.handler.middleEnd.stats()
					return s.MiddleEndBindingsActive == 0 && s.OutputBytes == 0 && rig.manager.Snapshot().ResponseBytes == 0 && rig.budget.Snapshot().UsedBytes == 0
				})
				t.Logf("recovered=%t admitted=%d/%d legacy_queue_limit_ignored=%d response_high_water=%d output_peak=%d evictions=%d fast_latency_max=%s elapsed=%s",
					recovered, admitted, scenario.packets, scenario.queueBytes, beforeDrain.ResponseBytesHighWater,
					peakOutput, beforeDrain.ResponseBackpressureEvents, fastLatency, time.Since(start))
			})
		}
	}
}

// The former optional small-ACK checks are unconditional regular coverage in
// TestMiddleEndSmallAckUsesActualHeadroom and TestMiddleEndSmallAckFitsCarrierHeadroom.

func TestInvestigationItemPressure(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		name := map[ProtocolMode]string{ModeDD: "dd", ModeEE: "ee"}[mode]
		t.Run(name, func(t *testing.T) {
			rig := newPressureInvestigationRig(t, 2<<20, 100*time.Second)
			client := rig.connect(t, true, mode)
			const count = 2048
			for sequence := range count {
				rig.link.emit(middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck,
					ConnectionID: client.client.binding.ConnectionID(), ConfirmKey: uint32(sequence + 1)})
			}
			awaitSpliceCondition(t, "ACK burst retained", func() bool {
				written, _, closed := client.progress(t)
				return closed || int(written)+rig.manager.Snapshot().ResponseItems == count
			})
			before := rig.manager.Snapshot()
			if before.ResponseItems <= 768 || before.ResponseBackpressureEvents != 0 {
				t.Fatalf("ACK burst did not borrow beyond old item cliff: %+v", before)
			}
			for sequence := range count {
				client.receiveAck(t, uint32(sequence+1))
			}
			_, _, closed := client.progress(t)
			if closed || rig.manager.Snapshot().ResponseBackpressureEvents != 0 {
				t.Fatal("ACK burst did not recover")
			}
			client.close()
			awaitSpliceCondition(t, "ACK ownership cleanup", func() bool { return rig.budget.Snapshot().UsedBytes == 0 })
			t.Logf("mode=%s ACKs=%d queued_before_drain=%d shared_high_water=%d", name, count, before.ResponseItems, rig.budget.Snapshot().HighWaterBytes)
		})
	}
}

func (p *pressureInvestigationClient) receiveAck(t *testing.T, expected uint32) {
	t.Helper()
	var plain []byte
	for len(plain) < 4 {
		size := 4 - len(plain)
		if p.mode == ModeEE {
			header := make([]byte, 5)
			if err := p.read(header); err != nil {
				t.Fatal(err)
			}
			if header[0] != faketls.RecordTypeApplicationData {
				t.Fatal("unexpected ACK TLS record")
			}
			size = int(binary.BigEndian.Uint16(header[3:]))
		}
		wire := make([]byte, size)
		if err := p.read(wire); err != nil {
			t.Fatal(err)
		}
		p.cipher.XORKeyStream(wire, wire)
		plain = append(plain, wire...)
	}
	if len(plain) != 4 || binary.LittleEndian.Uint32(plain) != expected {
		t.Fatalf("ACK changed or reordered: got %x want %d", plain, expected)
	}
}

func TestInvestigationOutputProgress(t *testing.T) {
	for _, progress := range []bool{false, true} {
		name := "stalled"
		if progress {
			name = "progressing"
		}
		t.Run(name, func(t *testing.T) {
			// A shorter test timeout exposes several real retry cycles. The
			// production timeout is 100 seconds; its policy is the same code.
			const stall = 500 * time.Millisecond
			rig := newPressureInvestigationRig(t, 2<<20, stall)
			client := rig.connect(t, true, ModeDD)
			packet := pressureInvestigationPacket(512<<10, 0)
			rig.send(t, client, packet, 1)
			awaitSpliceCondition(t, "output buffered", func() bool {
				written, _, _ := client.progress(t)
				return written == 1
			})
			start := time.Now()
			if progress {
				wire := make([]byte, len(packet)+4)
				for offset := 0; offset < len(wire); {
					time.Sleep(75 * time.Millisecond)
					end := min(offset+(32<<10), len(wire))
					if err := client.read(wire[offset:end]); err != nil {
						t.Fatal(err)
					}
					offset = end
				}
				client.cipher.XORKeyStream(wire, wire)
				if binary.LittleEndian.Uint32(wire) != uint32(len(packet)) || !bytes.Equal(wire[4:], packet) {
					t.Fatal("progressing response changed")
				}
				_, _, closed := client.progress(t)
				if closed || time.Since(start) <= 2*stall {
					t.Fatal("progress did not preserve the client beyond two stall intervals")
				}
				client.close()
			} else {
				awaitSpliceCondition(t, "stalled client closed", func() bool {
					_, _, closed := client.progress(t)
					return closed
				})
				if time.Since(start) < stall-50*time.Millisecond {
					t.Fatal("stalled client closed before its deadline")
				}
			}
			awaitSpliceCondition(t, "stalled/progress cleanup", func() bool {
				s := rig.handler.middleEnd.stats()
				return s.MiddleEndBindingsActive == 0 && s.OutputBytes == 0 && rig.manager.Snapshot().ResponseBytes == 0 && rig.budget.Snapshot().UsedBytes == 0
			})
			if rig.manager.Snapshot().ResponseBackpressureEvents != 0 {
				t.Fatal("timeout experiment hit queue pressure")
			}
			t.Logf("progress=%t stall=%s elapsed=%s", progress, stall, time.Since(start))
		})
	}
}

func TestInvestigationSharedQueuePressure(t *testing.T) {
	rig := newPressureInvestigationRig(t, pressureInvestigationBudget, 100*time.Second)
	slow := []*pressureInvestigationClient{
		rig.connect(t, true, ModeDD),
		rig.connect(t, true, ModeDD),
		rig.connect(t, true, ModeDD),
	}
	fast := rig.connect(t, true, ModeDD)
	for sequence := range 256 {
		client := slow[sequence%len(slow)]
		rig.link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer,
			ConnectionID: client.client.binding.ConnectionID(), Packet: pressureInvestigationPacket(512<<10, sequence)})
		awaitSpliceCondition(t, "shared response admitted or terminal", func() bool {
			totalWrites := 0
			for _, p := range slow {
				written, _, _ := p.progress(t)
				totalWrites += int(written)
			}
			snapshot := rig.manager.Snapshot()
			return snapshot.ResponseBackpressureEvents != 0 || totalWrites+snapshot.ResponseItems >= sequence+1
		})
		packet := pressureInvestigationPacket(64, sequence)
		rig.link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer,
			ConnectionID: fast.client.binding.ConnectionID(), Packet: bytes.Clone(packet)})
		fast.receive(t, packet)
		if rig.manager.Snapshot().ResponseBackpressureEvents != 0 {
			break
		}
	}
	snapshot := rig.manager.Snapshot()
	pool := rig.budget.Snapshot()
	if snapshot.ResponseBackpressureEvents == 0 || pool.HighWaterBytes < pool.OrdinaryLimitBytes-(2<<20) || pool.HighWaterBytes > pool.LimitBytes || snapshot.SlotFailures != 0 {
		t.Fatalf("shared queue pressure did not preserve its bounds: %+v", snapshot)
	}
	if pool.ProcessingReserveBytes != MiddleEndResponseProcessingBytes() {
		t.Fatal("processing reserve drifted")
	}
	for _, p := range slow {
		p.close()
	}
	fast.close()
	awaitSpliceCondition(t, "shared pressure cleanup", func() bool {
		s := rig.handler.middleEnd.stats()
		return s.MiddleEndBindingsActive == 0 && s.OutputBytes == 0 && rig.manager.Snapshot().ResponseBytes == 0 && rig.budget.Snapshot().UsedBytes == 0
	})
	t.Logf("response_high_water=%d shared_high_water=%d shared_limit=%d ordinary_limit=%d evictions=%d fast_client_received=true",
		snapshot.ResponseBytesHighWater, pool.HighWaterBytes, pool.LimitBytes, pool.OrdinaryLimitBytes, snapshot.ResponseBackpressureEvents)
}

func TestInvestigationHTTPPauseRecovery(t *testing.T) {
	rig := newPressureInvestigationRig(t, 2<<20, 100*time.Second)
	web := startLogicalWeb(t, rig.handler)
	key := rig.handler.config.Secrets[0].Key
	frame := buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate)
	_, _, responseCipher, _, err := obfuscated2.ParseClientFrameWithType(key, frame)
	if err != nil {
		t.Fatal(err)
	}
	web.upload(t, frame, true)
	stream := <-web.streams
	client := &pressureInvestigationClient{endpoint: stream, ctx: stream.ctx, owner: stream.options.Owner}
	awaitSpliceCondition(t, "HTTP ME commit", func() bool {
		runLogicalOwner(t, client.owner, func() { client.client = stream.ctx.middleEnd })
		return client.client != nil
	})
	if stream.options.MaxOutputBytes != webproxy.MaxFramePayload+webproxy.RelayDataChunk {
		t.Fatalf("default WEB output cap changed: %d", stream.options.MaxOutputBytes)
	}
	var expected []byte
	for sequence := range 3 {
		packet := pressureInvestigationPacket(middleend.MaxClientPacketSize, sequence)
		expected = binary.LittleEndian.AppendUint32(expected, uint32(len(packet)))
		expected = append(expected, packet...)
		rig.send(t, client, packet, sequence+1)
	}
	// The real WEB session can retain carrier frames while no HTTP download
	// runs. This differs from the matrix, which stops the backend consumer.
	time.Sleep(100 * time.Millisecond)
	got := web.download(t, len(expected))
	responseCipher.XORKeyStream(got, got)
	if !bytes.Equal(got, expected) || rig.manager.Snapshot().ResponseBackpressureEvents != 0 {
		t.Fatal("HTTP pause lost or reordered maximum-size ME responses")
	}
	t.Logf("http_recovered_bytes=%d default_backend_output_cap=%d", len(got), stream.options.MaxOutputBytes)
}

func TestInvestigationClientCount(t *testing.T) {
	for _, count := range []int{100, 1000} {
		for _, stagger := range []bool{false, true} {
			for _, retained := range []bool{false, true} {
				pattern, profile := "synchronized", "draining64k"
				if stagger {
					pattern = "staggered"
				}
				if retained {
					profile = "retained60k"
				}
				t.Run(fmt.Sprintf("%d/%s/%s", count, pattern, profile), func(t *testing.T) {
					runPressureInvestigationClientCount(t, count, stagger, retained)
				})
			}
		}
	}
}

func runPressureInvestigationClientCount(t *testing.T, count int, stagger, retained bool) {
	t.Helper()
	rig := newPressureInvestigationRig(t, 2<<20, 100*time.Second)
	packetBytes := 64 << 10
	if retained {
		packetBytes = 60 << 10
	}
	maximum, _ := middleend.ClientResponseOutputBound(middleend.LinkEventProxyAnswer, middleend.MaxClientPacketSize)
	outputBound, _ := middleend.ClientResponseOutputBound(middleend.LinkEventProxyAnswer, packetBytes)
	perBindingCharge := middleend.MinimumResponseOrdinaryBytes() - middleend.ResponseAllocationCharge(maximum+middleend.ResponseOutputMetadataBytes) + middleend.ResponseAllocationCharge(outputBound+middleend.ResponseOutputMetadataBytes)
	if retained && count*perBindingCharge > rig.budget.Snapshot().OrdinaryLimitBytes {
		t.Fatal("declared fitting burst exceeds exact ordinary admission capacity")
	}
	runtime.GC()
	var before, connected runtime.MemStats
	runtime.ReadMemStats(&before)
	clients := make([]*pressureInvestigationClient, count)
	for i := range clients {
		clients[i] = rig.connect(t, false, ModeDD)
	}
	if got := rig.handler.middleEnd.stats().MiddleEndBindingsActive; got != int64(count) {
		t.Fatalf("active bindings=%d, want%d", got, count)
	}
	runtime.GC()
	runtime.ReadMemStats(&connected)
	start := time.Now()
	batchSize := count
	if stagger {
		batchSize = min(32, count)
	}
	verified := 0
	recovered := true
waves:
	for wave := range 3 {
		for batchStart := 0; batchStart < count; batchStart += batchSize {
			batch := clients[batchStart:min(batchStart+batchSize, count)]
			var processing *middleend.ResponseAllocation
			if retained {
				var ok bool
				processing, ok = rig.budget.TryReserve(MiddleEndResponseProcessingBytes()-middleend.ResponseAllocationCharge(0), middleend.ResponseMemoryProcessing, middleend.ResponseMemoryEncode)
				if !ok {
					t.Fatal("previous batch retained processing ownership")
				}
				t.Cleanup(processing.Release)
			}
			var readers sync.WaitGroup
			failures := make(chan error, len(batch))
			for offset, client := range batch {
				index := batchStart + offset
				readers.Go(func() {
					wire := make([]byte, packetBytes+4)
					if err := client.read(wire); err != nil {
						failures <- fmt.Errorf("client%d: %w", index, err)
						return
					}
					client.cipher.XORKeyStream(wire, wire)
					packet := pressureInvestigationPacket(packetBytes, wave*count+index)
					if binary.LittleEndian.Uint32(wire) != uint32(len(packet)) || !bytes.Equal(wire[4:], packet) {
						failures <- fmt.Errorf("client%d: response changed or reordered", index)
					}
				})
			}
			for offset, client := range batch {
				index := batchStart + offset
				rig.link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer, ConnectionID: client.client.binding.ConnectionID(), Packet: pressureInvestigationPacket(packetBytes, wave*count+index)})
			}
			if retained {
				awaitSpliceCondition(t, "entire fitting batch retained before encode", func() bool {
					return rig.manager.Snapshot().ResponseItems == len(batch) || rig.manager.Snapshot().ResponseBackpressureEvents != 0
				})
				if snapshot := rig.manager.Snapshot(); snapshot.ResponseItems != len(batch) || snapshot.ResponseBackpressureEvents != 0 {
					t.Errorf("fitting retained batch failed: %+v pool=%+v", snapshot, rig.budget.Snapshot())
				}
				processing.Release()
			}
			readers.Wait()
			close(failures)
			readErrors := 0
			var firstError error
			for err := range failures {
				readErrors++
				if firstError == nil {
					firstError = err
				}
			}
			verified += len(batch) - readErrors
			if readErrors != 0 || t.Failed() {
				recovered = false
				t.Logf("wave=%d receive_failures=%d first_error=%v pool=%+v", wave, readErrors, firstError, rig.budget.Snapshot())
				break waves
			}
		}
	}
	elapsed := time.Since(start)
	snapshot := rig.manager.Snapshot()
	output := rig.handler.middleEnd.stats()
	pool := rig.budget.Snapshot()
	if snapshot.SlotFailures != 0 || pool.HighWaterBytes > pool.LimitBytes {
		t.Error("many-client run violated combined response bound or failed the link")
	}
	if !recovered || verified != 3*count || snapshot.ResponseBackpressureEvents != 0 || output.OutputEvictions != 0 {
		t.Errorf("acceptance failure: clients encountered pressure or lost responses; pool=%+v", pool)
	}
	for _, client := range clients {
		client.close()
	}
	awaitSpliceCondition(t, "many-client cleanup", func() bool {
		s := rig.handler.middleEnd.stats()
		m := rig.manager.Snapshot()
		return s.MiddleEndBindingsActive == 0 && s.OutputBytes == 0 && m.ResponseBytes == 0 && m.ResidentBindings == 0 && rig.budget.Snapshot().UsedBytes == 0
	})
	t.Logf("clients=%d batch=%d packet_bytes=%d all_retained=%t theoretical_ordinary_charge=%d ordinary_limit=%d recovered=%t verified_responses=%d/%d elapsed=%s shared_high_water=%d shared_limit=%d response_high_water=%d output_high_water=%d pressure_events=%d output_evictions=%d fixture_live_heap_delta=%d", count, batchSize, packetBytes, retained, count*perBindingCharge, pool.OrdinaryLimitBytes, recovered, verified, 3*count, elapsed, pool.HighWaterBytes, pool.LimitBytes, snapshot.ResponseBytesHighWater, output.OutputBytesHighWater, snapshot.ResponseBackpressureEvents, output.OutputEvictions, int64(connected.HeapAlloc)-int64(before.HeapAlloc))
	// This heap delta includes both proxy and load-generator objects. The separate
	// process harness measures server RSS and container memory independently.
}
