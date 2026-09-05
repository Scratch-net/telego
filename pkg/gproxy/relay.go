package gproxy

import (
	"encoding/binary"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

const relayBatchSize = 64*1024 + 256

// handleRelay processes complete TLS records on the client owner loop. No
// cipher advances until the corresponding output capacity is reserved.
func (h *ProxyHandler) handleRelay(c clientEndpoint, ctx *ConnContext) gnet.Action {
	relay := ctx.Relay()
	if relay == nil {
		return gnet.None
	}
	data, _ := c.Peek(-1)
	// gnet does not expose a read-pause operation. A peer that keeps sending
	// while the destination is stalled must not grow its input without bound.
	if len(data) > max(h.maxWriteBuffer, relayBatchSize) {
		return gnet.Close
	}
	if relay.ToDC == nil {
		relay.ToDC = newRelayOutput(relay.DCConn, c, ctx, h.maxWriteBuffer)
	}
	consumed, planned, minimum := 0, 0, 0
	for len(data)-consumed >= faketls.RecordHeaderSize {
		record := data[consumed:]
		payloadLen := int(binary.BigEndian.Uint16(record[3:5]))
		if CheckFrameSize(payloadLen) {
			h.desyncDetector.Report(ctx, payloadLen, "c2dc", h.logger)
			return gnet.Close
		}
		recordLen := faketls.RecordHeaderSize + payloadLen
		if len(record) < recordLen {
			break
		}
		if record[0] == faketls.RecordTypeApplicationData {
			if payloadLen > h.maxWriteBuffer {
				return gnet.Close
			}
			if planned+payloadLen > relayBatchSize {
				break
			}
			if minimum == 0 {
				minimum = payloadLen
			}
			planned += payloadLen
		}
		consumed += recordLen
	}
	if planned == 0 {
		if consumed > 0 {
			_, _ = c.Discard(consumed)
		}
		return gnet.None
	}
	budget := relay.ToDC.reserve(planned, minimum)
	if budget == 0 {
		return gnet.None
	}
	// Capacity can end between records, so determine the exact retained size
	// before taking a buffer or advancing cipher state.
	consumed, planned = 0, 0
	for len(data)-consumed >= faketls.RecordHeaderSize {
		record := data[consumed:]
		payloadLen := int(binary.BigEndian.Uint16(record[3:5]))
		recordLen := faketls.RecordHeaderSize + payloadLen
		if len(record) < recordLen {
			break
		}
		if record[0] == faketls.RecordTypeApplicationData {
			if planned+payloadLen > budget {
				break
			}
			planned += payloadLen
		}
		consumed += recordLen
	}
	relay.ToDC.releaseReservation(budget - planned)
	buffer, release := h.relayBuffer(planned)
	offset := 0
	for remaining := data[:consumed]; len(remaining) > 0; {
		payloadLen := int(binary.BigEndian.Uint16(remaining[3:5]))
		recordLen := faketls.RecordHeaderSize + payloadLen
		if remaining[0] == faketls.RecordTypeApplicationData {
			payload := buffer[offset : offset+payloadLen]
			relay.Decryptor.XORKeyStream(payload, remaining[faketls.RecordHeaderSize:recordLen])
			relay.DCEncrypt.XORKeyStream(payload, payload)
			offset += payloadLen
		}
		remaining = remaining[recordLen:]
	}
	if err := relay.ToDC.write(buffer, release); err != nil {
		return gnet.Close
	}
	if counter := ctx.TrafficIn(); counter != nil {
		counter.Add(int64(planned))
	}
	ctx.recordClientActivity()
	_, _ = c.Discard(consumed)
	if len(data)-consumed >= faketls.RecordHeaderSize {
		if err := wakeClient(c); err != nil {
			return gnet.Close
		}
	}
	return gnet.None
}

// handleRelayDD processes the raw obfuscated stream on its client owner loop.
func (h *ProxyHandler) handleRelayDD(c clientEndpoint, ctx *ConnContext) gnet.Action {
	relay := ctx.Relay()
	if relay == nil {
		return gnet.None
	}
	data, _ := c.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}
	if len(data) > max(h.maxWriteBuffer, relayBatchSize) {
		return gnet.Close
	}
	if relay.ToDC == nil {
		relay.ToDC = newRelayOutput(relay.DCConn, c, ctx, h.maxWriteBuffer)
	}
	n := relay.ToDC.reserve(min(len(data), relayBatchSize), 1)
	if n == 0 {
		return gnet.None
	}
	buffer, release := h.relayBuffer(n)
	relay.Decryptor.XORKeyStream(buffer, data[:n])
	relay.DCEncrypt.XORKeyStream(buffer, buffer)
	if err := relay.ToDC.write(buffer, release); err != nil {
		return gnet.Close
	}
	if counter := ctx.TrafficIn(); counter != nil {
		counter.Add(int64(n))
	}
	ctx.recordClientActivity()
	_, _ = c.Discard(n)
	if len(data) > n {
		if err := wakeClient(c); err != nil {
			return gnet.Close
		}
	}
	return gnet.None
}
