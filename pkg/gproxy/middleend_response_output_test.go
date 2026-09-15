package gproxy

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

type responseOutputTestConn struct {
	*middleEndOwnerConn
	data      []byte
	release   func(error)
	immediate bool
	reject    bool
}

func (c *responseOutputTestConn) WriteOwned(data []byte, release func(error)) (int, error) {
	if c.reject {
		release(net.ErrClosed)
		return 0, net.ErrClosed
	}
	if c.immediate {
		size := len(data)
		release(nil)
		// Reentry after release must observe consistent budget counters.
		_ = c.OutboundBuffered()
		return size, nil
	}
	c.data, c.release = data, release
	c.SetOutboundBuffered(len(data))
	return len(data), nil
}

func (c *responseOutputTestConn) drain(bytes int, err error) {
	remaining := max(0, c.OutboundBuffered()-bytes)
	c.SetOutboundBuffered(remaining)
	if (remaining == 0 || err != nil) && c.release != nil {
		release := c.release
		c.data, c.release = nil, nil
		release(err)
	}
}

type promotionCheckingCipher struct {
	t      *testing.T
	budget *middleend.ResponseBudget
	calls  int
}

func (c *promotionCheckingCipher) XORKeyStream(dst, src []byte) {
	c.calls++
	if snapshot := c.budget.Snapshot(); snapshot.StageBytes[middleend.ResponseMemoryOutput] == 0 {
		c.t.Error("cipher advanced before output promotion")
	}
	copy(dst, src)
}

var _ cipher.Stream = (*promotionCheckingCipher)(nil)

func TestMiddleEndOwnedOutputPromotesAtFullOrdinaryCapacity(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		for _, kind := range []middleend.LinkEventKind{middleend.LinkEventProxyAnswer, middleend.LinkEventSimpleAck} {
			for _, completion := range []string{"drain", "close", "immediate", "reject"} {
				t.Run(string(mode)+"/"+kindName(kind)+"/"+completion, func(t *testing.T) {
					event := middleend.LinkEvent{Kind: kind, ConfirmKey: 42}
					if kind == middleend.LinkEventProxyAnswer {
						event.Packet = bytes.Repeat([]byte{7}, 128)
					}
					bound, err := middleend.ClientResponseOutputBound(kind, len(event.Packet))
					if err != nil {
						t.Fatal(err)
					}
					envelope := middleend.ResponseAllocationCharge(bound + middleend.ResponseOutputMetadataBytes)
					metadata := middleend.ResponseAllocationCharge(4 * middleend.ResponseQueueEntryBytes)
					budget, err := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{
						LimitBytes: envelope + metadata + 4096, ProcessingReserveBytes: 4096,
					})
					if err != nil {
						t.Fatal(err)
					}
					event.ResponseAllocation, _ = budget.TryReserve(bound+middleend.ResponseOutputMetadataBytes, middleend.ResponseMemoryOrdinary, middleend.ResponseMemoryQueuePayload)
					ring, ok := budget.TryReserve(4*middleend.ResponseQueueEntryBytes, middleend.ResponseMemoryOrdinary, middleend.ResponseMemoryQueueMetadata)
					if !ok || event.ResponseAllocation == nil || budget.Snapshot().ClassBytes[middleend.ResponseMemoryOrdinary] != envelope+metadata {
						t.Fatal("ordinary capacity is not exactly full")
					}
					defer ring.Release()
					framing := obfuscated2.ConnectionType(obfuscated2.ConnectionTypePaddedIntermediate)
					encoder, err := middleend.NewClientPacketEncoder(framing, middleend.MaxClientPacketSize)
					if err != nil {
						t.Fatal(err)
					}
					stream := &promotionCheckingCipher{t: t, budget: budget}
					client := &middleEndClient{mode: mode, connectionType: framing, encoder: encoder, encryptor: stream,
						drs: faketls.NewDRSState(true, true, faketls.MaxRecordPayload)}
					plain, output, err := client.responseOutputBounds(middleend.ClientResponseHead{Kind: kind, PacketBytes: len(event.Packet)})
					if err != nil {
						t.Fatal(err)
					}
					work, ok := reserveMiddleEndResponseWork(budget, plain, output)
					if !ok {
						t.Fatal("processing reserve cannot drain full ordinary capacity")
					}
					defer work.release()
					conn := &responseOutputTestConn{middleEndOwnerConn: newMiddleEndOwnerConn(), immediate: completion == "immediate", reject: completion == "reject"}
					handler := NewProxyHandler(&Config{}, &testLogger{})
					ctx := NewConnContext()
					action := handler.writeMiddleEndOwnedEvent(conn, ctx, client, event, &work)
					if stream.calls == 0 || action != gnet.None && completion != "reject" || action != gnet.Close && completion == "reject" {
						t.Fatalf("cipher calls=%d action=%v completion=%s", stream.calls, action, completion)
					}
					if budget.Snapshot().ClassBytes[middleend.ResponseMemoryProcessing] != 0 {
						t.Fatal("stalled output retained processing capacity")
					}
					if conn.release != nil {
						wire := conn.data
						if mode == ModeEE {
							wire = nil
							for remaining := conn.data; len(remaining) > 0; {
								if len(remaining) < faketls.RecordHeaderSize {
									t.Fatal("truncated FakeTLS header")
								}
								size := int(binary.BigEndian.Uint16(remaining[3:5]))
								if size == 0 || size > len(remaining)-faketls.RecordHeaderSize {
									t.Fatal("invalid FakeTLS record size")
								}
								wire = append(wire, remaining[5:5+size]...)
								remaining = remaining[5+size:]
							}
						}
						if kind == middleend.LinkEventSimpleAck {
							if !bytes.Equal(wire, []byte{42, 0, 0, 0}) {
								t.Fatalf("ACK bytes changed: %x", wire)
							}
						} else {
							decoder, _ := middleend.NewClientPacketDecoder(framing, middleend.MaxClientPacketSize)
							if _, err := decoder.Feed(wire); err != nil {
								t.Fatal(err)
							}
							packet, ok, err := decoder.Next()
							if err != nil || !ok || !bytes.Equal(packet.Payload, bytes.Repeat([]byte{7}, 128)) {
								t.Fatalf("owned response framing changed: %v, %v", ok, err)
							}
						}
						before := budget.Snapshot().UsedBytes
						conn.drain(1, nil)
						if budget.Snapshot().UsedBytes != before {
							t.Fatal("partial write released retained allocation")
						}
						var terminal error
						if completion == "close" {
							terminal = net.ErrClosed
						}
						conn.drain(conn.OutboundBuffered(), terminal)
					}
					work.release()
					if budget.Snapshot().UsedBytes != metadata {
						t.Fatalf("output did not release exactly once: %+v", budget.Snapshot())
					}
					ring.Release()
					if budget.Snapshot().UsedBytes != 0 {
						t.Fatal("final output ownership leaked")
					}
				})
			}
		}
	}
}

func kindName(kind middleend.LinkEventKind) string {
	if kind == middleend.LinkEventSimpleAck {
		return "ack"
	}
	return "packet"
}

func TestMiddleEndProcessingContentionReturnsPartialReservation(t *testing.T) {
	budget, err := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 2048, ProcessingReserveBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	occupied, ok := budget.TryReserve(300, middleend.ResponseMemoryProcessing, middleend.ResponseMemoryDecode)
	if !ok {
		t.Fatal("setup reserve")
	}
	before := budget.Snapshot().UsedBytes
	for range 5 {
		work, ok := reserveMiddleEndResponseWork(budget, 100, 100)
		if ok {
			work.release()
			t.Fatal("processing overlap bypassed reserve")
		}
		if budget.Snapshot().UsedBytes != before {
			t.Fatal("failed reservation pinned a processing allocation")
		}
	}
	occupied.Release()
	work, ok := reserveMiddleEndResponseWork(budget, 100, 100)
	if !ok {
		t.Fatal("released processing capacity did not recover")
	}
	work.release()
}

func TestMiddleEndConcurrentMaximumEncodeAdmission(t *testing.T) {
	reserve := MiddleEndResponseProcessingBytes()
	budget, err := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 2 * reserve, ProcessingReserveBytes: reserve})
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		work     middleEndResponseWork
		admitted bool
	}
	for range 32 {
		start := make(chan struct{})
		results := make(chan result, 2)
		for range 2 {
			go func() {
				<-start
				work, admitted := reserveMiddleEndResponseWork(budget, middleEndMaxClientWire, middleEndMaxEncodedResponse)
				results <- result{work, admitted}
			}()
		}
		close(start)
		first, second := <-results, <-results
		snapshot := budget.Snapshot()
		first.work.release()
		second.work.release()
		if first.admitted == second.admitted || snapshot.ClassBytes[middleend.ResponseMemoryProcessing] != reserve {
			t.Fatalf("competing maximum encodes failed to admit exactly one complete operation: %+v", snapshot)
		}
		if budget.Snapshot().UsedBytes != 0 {
			t.Fatal("concurrent encode admission leaked processing capacity")
		}
	}
}

func TestMiddleEndSmallAckUsesActualHeadroom(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "client", true: "shared"}[shared], func(t *testing.T) {
			handler, link, conn, ctx, decryptor := establishMiddleEndDD(t, nil)
			defer closeMiddleEndTestClient(handler, conn, ctx)
			conn.SetOutboundBuffered(handler.maxWriteBuffer - 4)
			if shared {
				conn.SetOutboundBuffered(0)
				handler.middleEnd.outputBudget.limit = 4
			}
			link.emit(middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ConnectionID: ctx.middleEnd.binding.ConnectionID(), ConfirmKey: 42})
			waitMiddleEndToken(t, ctx.middleEnd)
			if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
				t.Fatalf("ACK action = %v", action)
			}
			ciphertext := conn.GetWrittenData()
			plain := make([]byte, len(ciphertext))
			decryptor.XORKeyStream(plain, ciphertext)
			if !bytes.Equal(plain, []byte{42, 0, 0, 0}) || handler.middleEnd.stats().OutputEvictions != 0 {
				t.Fatalf("ACK was blocked or corrupted: %x", plain)
			}
		})
	}
}

func TestMiddleEndMissingEnvelopeFailsBeforeCipher(t *testing.T) {
	budget, _ := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 8192, ProcessingReserveBytes: 4096})
	work, ok := reserveMiddleEndResponseWork(budget, 4, 4)
	if !ok {
		t.Fatal("processing admission failed")
	}
	defer work.release()
	stream := &promotionCheckingCipher{t: t, budget: budget}
	client := &middleEndClient{mode: ModeDD, connectionType: obfuscated2.ConnectionTypeIntermediate, encryptor: stream}
	handler := NewProxyHandler(&Config{}, &testLogger{})
	conn := &responseOutputTestConn{middleEndOwnerConn: newMiddleEndOwnerConn()}
	if action := handler.writeMiddleEndOwnedEvent(conn, NewConnContext(), client, middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck}, &work); action != gnet.Close || stream.calls != 0 {
		t.Fatal("missing envelope advanced cipher")
	}
	work.release()
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatal(errors.New("missing envelope leaked processing ownership"))
	}
}

func TestMiddleEndLegacyOutputRejectsAndReleasesOwnedSourceEvent(t *testing.T) {
	budget, _ := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 4096})
	event := middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ConfirmKey: 42}
	event.ResponseAllocation, _ = budget.TryReserve(64, middleend.ResponseMemoryOrdinary, middleend.ResponseMemoryQueuePayload)
	stream := &promotionCheckingCipher{t: t, budget: budget}
	client := &middleEndClient{mode: ModeDD, connectionType: obfuscated2.ConnectionTypeIntermediate, encryptor: stream}
	handler := NewProxyHandler(&Config{}, &testLogger{})
	conn := newMiddleEndOwnerConn()
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.writeMiddleEndEvent(conn, NewConnContext(), client, event) }); action != gnet.Close || stream.calls != 0 {
		t.Fatal("legacy event advanced cipher without output ownership")
	}
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatal("legacy frontend leaked owned source event")
	}
}

func TestMiddleEndFrontendRejectsInsufficientProcessingReserve(t *testing.T) {
	for _, reserve := range []int{0, MiddleEndResponseProcessingBytes() - 1, MiddleEndResponseProcessingBytes()} {
		budget, _ := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 8 << 20, ProcessingReserveBytes: reserve})
		config := middleEndTestFrontendConfig(t, &middleend.FixedBindingManager{})
		config.ResponseBudget = budget
		err := config.validate()
		if reserve < MiddleEndResponseProcessingBytes() && !errors.Is(err, ErrInvalidMiddleEndFrontend) || reserve == MiddleEndResponseProcessingBytes() && err != nil {
			t.Fatalf("reserve %d: %v", reserve, err)
		}
	}
}

func TestMiddleEndForeignEnvelopeFailsBeforeCipherAndDRS(t *testing.T) {
	budget, _ := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 8192, ProcessingReserveBytes: 4096})
	foreign, _ := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 4096})
	work, ok := reserveMiddleEndResponseWork(budget, 4, 14)
	if !ok {
		t.Fatal("processing admission failed")
	}
	defer work.release()
	allocation, _ := foreign.TryReserve(14+middleend.ResponseOutputMetadataBytes, middleend.ResponseMemoryOrdinary, middleend.ResponseMemoryQueuePayload)
	stream := &promotionCheckingCipher{t: t, budget: budget}
	client := &middleEndClient{mode: ModeEE, connectionType: obfuscated2.ConnectionTypeIntermediate, encryptor: stream,
		drs: faketls.NewDRSState(true, true, faketls.MaxRecordPayload)}
	before := client.drs.PlanSize(4)
	handler := NewProxyHandler(&Config{}, &testLogger{})
	conn := &responseOutputTestConn{middleEndOwnerConn: newMiddleEndOwnerConn()}
	event := middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ResponseAllocation: allocation}
	if action := handler.writeMiddleEndOwnedEvent(conn, NewConnContext(), client, event, &work); action != gnet.Close || stream.calls != 0 || client.drs.PlanSize(4) != before {
		t.Fatal("foreign envelope advanced cipher or DRS")
	}
	work.release()
	if budget.Snapshot().UsedBytes != 0 || foreign.Snapshot().UsedBytes != 0 {
		t.Fatal("foreign envelope rejection leaked ownership")
	}
}

func TestMiddleEndSharedFrontendWaitPreservesHeadAndRecovers(t *testing.T) {
	budget, err := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 8 << 20, ProcessingReserveBytes: MiddleEndResponseProcessingBytes()})
	if err != nil {
		t.Fatal(err)
	}
	link := newMiddleEndTestLink()
	manager, err := middleend.NewFixedBindingManagerWithResponseBudget([]middleend.FixedBindingSlot{
		{DCID: 2, SourceIP: netip.MustParseAddr("8.8.8.8"), Link: link},
	}, middleEndTestLimits(), budget)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	config := middleEndTestFrontendConfig(t, manager)
	config.ResponseBudget = budget
	handler, err := NewProxyHandlerWithMiddleEnd(&Config{Secrets: []Secret{{Name: "test", Key: []byte("0123456789abcdef")}}}, &testLogger{}, config)
	if err != nil {
		t.Fatal(err)
	}
	handler.OnBoot(gnet.Engine{})
	defer handler.OnShutdown(gnet.Engine{})
	base, ctx, _ := commitMiddleEndDDClient(t, handler)
	defer closeMiddleEndTestClient(handler, base, ctx)
	conn := &responseOutputTestConn{middleEndOwnerConn: base}
	defer func() { conn.drain(conn.OutboundBuffered(), net.ErrClosed) }()
	stream := &promotionCheckingCipher{t: t, budget: budget}
	ctx.middleEnd.encryptor = stream
	link.emit(middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ConnectionID: ctx.middleEnd.binding.ConnectionID(), ConfirmKey: 42})
	token := waitMiddleEndToken(t, ctx.middleEnd)
	for deadline := time.Now().Add(3 * time.Second); manager.Snapshot().ResponseItems != 1; {
		if !time.Now().Before(deadline) {
			t.Fatal("timed out waiting for shared response admission")
		}
		time.Sleep(time.Millisecond)
	}
	victim := budget.SelectPressureVictim(time.Now(), budget.Snapshot().OrdinaryLimitBytes)
	participant := victim.Participant
	victim.Cancel()
	if participant == nil {
		t.Fatal("queued response did not register its owner")
	}
	processing, ok := budget.TryReserve(budget.Snapshot().ProcessingReserveBytes-middleend.ResponseAllocationCharge(0), middleend.ResponseMemoryProcessing, middleend.ResponseMemoryDecode)
	if !ok {
		t.Fatal("failed to occupy processing reserve")
	}
	defer processing.Release()
	before := budget.Snapshot().UsedBytes
	var blocked bool
	action := runMiddleEndOwner(base, func() gnet.Action {
		ctx.middleEnd.refreshOutput(conn, 0)
		var action gnet.Action
		blocked, action = handler.handleMiddleEndToken(conn, ctx, ctx.middleEnd)
		return action
	})
	if action != gnet.None || !blocked || stream.calls != 0 || ctx.middleEnd.route.currentToken() != token || manager.Snapshot().ResponseItems != 1 || budget.Snapshot().UsedBytes != before {
		t.Fatal("processing wait changed head, cipher, or allocation ownership")
	}
	if snapshot := participant.Snapshot(); snapshot.ObservedAt.IsZero() || snapshot.UnreadBytes != 0 ||
		!snapshot.LastProgressAt.IsZero() || snapshot.Wait != middleend.ResponseOutputProcessingReserve {
		t.Fatalf("processing wait was not published independently of output backlog: %+v", snapshot)
	}
	processing.Release()
	action = runMiddleEndOwner(base, func() gnet.Action {
		ctx.middleEnd.refreshOutput(conn, 0)
		var action gnet.Action
		blocked, action = handler.handleMiddleEndToken(conn, ctx, ctx.middleEnd)
		return action
	})
	if action != gnet.None || blocked || stream.calls != 1 || manager.Snapshot().ResponseItems != 0 || !bytes.Equal(conn.data, []byte{42, 0, 0, 0}) {
		t.Fatal("shared frontend did not recover after processing capacity returned")
	}
	if budget.Snapshot().ClassBytes[middleend.ResponseMemoryProcessing] != 0 {
		t.Fatal("owned output retained processing capacity")
	}
	backlogged := participant.Snapshot()
	if backlogged.UnreadBytes != 4 || backlogged.LastProgressAt.IsZero() || backlogged.Wait != middleend.ResponseOutputNotWaiting {
		t.Fatalf("new output backlog was not published: %+v", backlogged)
	}
	// An accepted write must not reset the last observed drain time.
	runMiddleEndOwner(base, func() gnet.Action {
		ctx.middleEnd.responseLastWriteAt = time.Now()
		ctx.middleEnd.refreshOutput(conn, 0)
		return gnet.None
	})
	if snapshot := participant.Snapshot(); snapshot.LastProgressAt != backlogged.LastProgressAt {
		t.Fatal("accepted write was reported as output drain progress")
	}
	conn.drain(1, nil)
	runMiddleEndOwner(base, func() gnet.Action {
		ctx.middleEnd.refreshOutput(conn, 0)
		return gnet.None
	})
	if snapshot := participant.Snapshot(); snapshot.UnreadBytes != 3 || !snapshot.LastProgressAt.After(backlogged.LastProgressAt) ||
		snapshot.OutputBytes != backlogged.OutputBytes {
		t.Fatalf("partial drain did not publish progress while retaining its allocation: %+v", snapshot)
	}
	conn.drain(conn.OutboundBuffered(), nil)
	runMiddleEndOwner(base, func() gnet.Action {
		ctx.middleEnd.refreshOutput(conn, 0)
		return gnet.None
	})
	if snapshot := participant.Snapshot(); snapshot.UnreadBytes != 0 || !snapshot.LastProgressAt.IsZero() {
		t.Fatalf("empty output did not clear the backlog baseline: %+v", snapshot)
	}
	closeMiddleEndTestClient(handler, base, ctx)
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatalf("shared frontend output leaked: %+v", budget.Snapshot())
	}
}
