package gproxy

import (
	"fmt"
	"io"
	"time"
	"unsafe"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/buffer/linkedlist"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

// Fail compilation if the native retained record outgrows the shared envelope.
const _ = uint(middleend.ResponseOutputNodeBytes - linkedlist.OwnedNodeBytes)
const _ = uint(middleend.ResponseOutputNodeBytes - int(logicalOwnedOutputMetadataBytes))

type middleEndOwnedOutput struct {
	data       []byte
	allocation *middleend.ResponseAllocation
}

const _ = uint(middleend.ResponseOutputOwnerBytes - int(unsafe.Sizeof(middleEndOwnedOutput{})))

func (o *middleEndOwnedOutput) release() {
	clear(o.data)
	o.data = nil
	allocation := o.allocation
	o.allocation = nil
	allocation.Release()
}

// MiddleEndResponseProcessingBytes is the minimum reserve for one complete
// frontend encode. The ME decoder has its own bounded scratch storage.
func MiddleEndResponseProcessingBytes() int {
	return middleend.ResponseAllocationCharge(middleEndMaxClientWire) +
		middleend.ResponseAllocationCharge(middleEndMaxEncodedResponse+middleend.ResponseOutputMetadataBytes)
}

type middleEndResponseWork struct {
	plain  *middleend.ResponseAllocation
	output *middleend.ResponseAllocation
}

func reserveMiddleEndResponseWork(budget *middleend.ResponseBudget, plainBytes, outputBytes int) (middleEndResponseWork, bool) {
	plain, output, ok := budget.TryReservePair(plainBytes, outputBytes+middleend.ResponseOutputMetadataBytes,
		middleend.ResponseMemoryProcessing, middleend.ResponseMemoryEncode)
	if !ok {
		return middleEndResponseWork{}, false
	}
	return middleEndResponseWork{plain: plain, output: output}, true
}

func (w *middleEndResponseWork) release() {
	w.plain.Release()
	w.output.Release()
	w.plain, w.output = nil, nil
}

func (c *middleEndClient) responseOutputBounds(head middleend.ClientResponseHead) (plain, output int, err error) {
	switch head.Kind {
	case middleend.LinkEventProxyAnswer:
		plain, err = c.encoder.EncodedSizeBound(head.PacketBytes)
	case middleend.LinkEventSimpleAck:
		plain = 4
	default:
		err = fmt.Errorf("%w: response kind %d", ErrMiddleEndClientProtocol, head.Kind)
	}
	if err != nil {
		return 0, 0, err
	}
	output = plain
	if c.mode != ModeDD {
		output = c.drs.PlanSize(plain)
	}
	if output > middleEndMaxEncodedResponse {
		return 0, 0, fmt.Errorf("%w: encoded response bound %d", ErrMiddleEndClientProtocol, output)
	}
	return plain, output, nil
}

func (h *ProxyHandler) writeMiddleEndOwnedEvent(connection clientEndpoint, ctx *ConnContext, client *middleEndClient, event middleend.LinkEvent, work *middleEndResponseWork) gnet.Action {
	defer event.Release()
	var wire []byte
	var err error
	payloadBytes := len(event.Packet)
	switch event.Kind {
	case middleend.LinkEventProxyAnswer:
		wire, err = client.encoder.Encode(event.Packet)
	case middleend.LinkEventSimpleAck:
		payloadBytes = 4
		wire, err = middleend.EncodeSimpleAckForClient(client.connectionType, event.ConfirmKey)
	default:
		return gnet.Close
	}
	if err != nil {
		return gnet.Close
	}
	defer func() { clear(wire) }()
	outputBytes := len(wire)
	if client.mode != ModeDD {
		outputBytes = client.drs.PlanSize(len(wire))
	}
	if !work.plain.Shrink(cap(wire)) || !work.output.Shrink(outputBytes+middleend.ResponseOutputMetadataBytes) ||
		event.ResponseAllocation.Bytes() < work.output.Bytes() {
		return gnet.Close
	}
	// No packet storage remains after framing. The queued envelope includes
	// output expansion and metadata, so this promotion cannot lose a race for
	// ordinary capacity. Cipher and DRS state have not advanced yet.
	clear(event.Packet)
	event.Packet = nil
	if !work.output.TryMoveReplacing(middleend.ResponseMemoryOrdinary, middleend.ResponseMemoryOutput, event.ResponseAllocation) {
		return gnet.Close
	}
	event.ResponseAllocation = nil
	out := make([]byte, outputBytes)
	if err := client.encryptResponse(out, wire); err != nil {
		clear(out)
		return gnet.Close
	}
	wireBytes := len(wire)
	clear(wire)
	wire = nil
	work.plain.Release()
	work.plain = nil
	owner := &middleEndOwnedOutput{data: out, allocation: work.output}
	work.output = nil
	size := len(out)
	// Keep this capture immutable and singular: the shared envelope charges
	// the code pointer plus this owner pointer, without a boxed slice header.
	written, err := writeMiddleEndOwnedOutput(connection, out, func(error) {
		owner.release()
	})
	if err == nil && written != size {
		err = io.ErrShortWrite
	}
	if err != nil {
		h.logger.Debug("[%s] write owned Middle-End response: %v", ctx.LogPrefix(), err)
		return gnet.Close
	}
	client.responseLastWriteAt = time.Now()
	client.responseWriteBytes += uint64(wireBytes)
	client.responseWriteEvents++
	if counter := ctx.TrafficOut(); counter != nil {
		counter.Add(int64(payloadBytes))
	}
	ctx.recordServerActivity()
	return gnet.None
}
