package gproxy

import (
	"crypto/cipher"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

type dcEventHandler struct {
	gnet.BuiltinEventEngine
	proxy *ProxyHandler
}

// EnrollContext installs the context before any connection callback can run.
func (h *dcEventHandler) getDCContext(c gnet.Conn) *DCConnContext {
	ctx, _ := c.Context().(*DCConnContext)
	return ctx
}

type DCConnContext struct {
	ClientConn    clientEndpoint
	ClientCtx     *ConnContext
	DCEncrypt     cipher.Stream
	DCDecrypt     cipher.Stream
	ClientEncrypt cipher.Stream
	DCConn        gnet.Conn
	ToDC          *relayOutput
	ToClient      *relayOutput
	activationMu  sync.Mutex // Serializes activation with early upstream closure.
	orderlyEOF    atomic.Bool
	// active publishes the client-owner activation, including ToClient and
	// its initial outbound snapshot, before DC input is allowed to run.
	active   atomic.Bool
	closed   atomic.Bool
	onClosed func()
	drs      *faketls.DRSState
}

func (h *dcEventHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	if splice, ok := c.Context().(*spliceConnContext); ok {
		return nil, splice.onOpen(c)
	}
	ctx := h.getDCContext(c)
	if ctx == nil || ctx.ClientCtx.State() == StateClosed {
		return nil, gnet.Close
	}
	ctx.DCConn = c
	ctx.ToDC = newRelayOutput(c, ctx.ClientConn, ctx.ClientCtx, h.proxy.maxWriteBuffer)
	ctx.ToDC.buffered = c.OutboundBuffered()
	return nil, gnet.None
}

func (h *dcEventHandler) OnTraffic(c gnet.Conn) gnet.Action {
	if splice, ok := c.Context().(*spliceConnContext); ok {
		return splice.onTraffic(c)
	}
	ctx := h.getDCContext(c)
	if ctx == nil {
		return gnet.Close
	}
	if !ctx.active.Load() {
		if c.InboundBuffered() > max(h.proxy.maxWriteBuffer, relayBatchSize) {
			return gnet.Close
		}
		return gnet.None
	}
	return h.proxy.handleDCTraffic(c, ctx)
}

func (h *dcEventHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	if splice, ok := c.Context().(*spliceConnContext); ok {
		return splice.onClose(c, err)
	}
	ctx := h.getDCContext(c)
	if ctx == nil {
		return gnet.None
	}
	ctx.activationMu.Lock()
	defer ctx.activationMu.Unlock()
	ctx.closed.Store(true)
	orderly := ctx.ClientConn != nil && ctx.ClientCtx != nil && ctx.ClientCtx.State() != StateClosed && errors.Is(err, io.EOF)
	if orderly {
		ctx.orderlyEOF.Store(true)
		ctx.ToDC.closeForEOF()
	} else {
		ctx.ToDC.close()
	}
	defer h.proxy.completeUpstreamClose(c, ctx.ClientConn, ctx.ToDC, ctx.onClosed)
	if ctx.active.Load() {
		ctx.ToClient.close()
	}
	if ctx.ClientCtx != nil {
		prefix := ctx.ClientCtx.LogPrefix()
		dcID := ctx.ClientCtx.DCID()
		duration := time.Since(ctx.ClientCtx.connTime)
		if err != nil && !errors.Is(err, io.EOF) {
			h.proxy.logger.Warn("[%s] DC %d disconnected (%v): %v", prefix, dcID, duration.Round(time.Millisecond), err)
		} else {
			h.proxy.logger.Debug("[%s] DC %d disconnected (%v)", prefix, dcID, duration.Round(time.Millisecond))
		}
	}
	if orderly {
		h.proxy.drainDirectEOF(c, ctx)
	} else if ctx.ClientConn != nil {
		_ = ctx.ClientConn.Close()
	}
	return gnet.None
}

// handleDCTraffic owns the downlink cipher streams on the DC loop.
func (h *ProxyHandler) handleDCTraffic(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientCtx := dcCtx.ClientCtx
	if clientCtx.State() == StateClosed || dcCtx.ClientEncrypt == nil || dcCtx.DCDecrypt == nil {
		return gnet.Close
	}
	if clientCtx.ProtocolMode() == ModeDD {
		return h.handleDCTrafficDD(dcConn, dcCtx)
	}
	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}
	if len(data) > max(h.maxWriteBuffer, relayBatchSize) {
		return gnet.Close
	}
	if dcCtx.ToClient == nil {
		dcCtx.ToClient = newRelayOutput(dcCtx.ClientConn, dcConn, clientCtx, h.maxWriteBuffer)
	}
	planSize := dcCtx.responseSize
	maximum := min(len(data), 60*1024)
	minimum := planSize(1)
	if minimum > h.maxWriteBuffer {
		return gnet.Close
	}
	budget := dcCtx.ToClient.reserve(planSize(maximum), minimum)
	if budget == 0 {
		return gnet.None
	}
	// PlanSize does not advance the shaping state. Find the largest plaintext
	// prefix whose TLS headers also fit the output reservation.
	low, high := 1, maximum
	for low < high {
		mid := low + (high-low+1)/2
		if planSize(mid) <= budget {
			low = mid
		} else {
			high = mid - 1
		}
	}
	n := low
	tlsSize := planSize(n)
	dcCtx.ToClient.releaseReservation(budget - tlsSize)
	buffer, release := h.relayBuffer(tlsSize)
	dcCtx.encodeResponse(buffer, data[:n])
	if err := dcCtx.ToClient.write(buffer, release); err != nil {
		return gnet.Close
	}
	if counter := clientCtx.TrafficOut(); counter != nil {
		counter.Add(int64(n))
	}
	clientCtx.recordServerActivity()
	_, _ = dcConn.Discard(n)
	if len(data) > n {
		if err := dcConn.Wake(nil); err != nil {
			return gnet.Close
		}
	}
	return gnet.None
}

func (ctx *DCConnContext) responseSize(n int) int {
	if ctx.ClientCtx.ProtocolMode() == ModeDD {
		return n
	}
	if ctx.drs != nil {
		return ctx.drs.PlanSize(n)
	}
	return n + ((n+faketls.MaxRecordPayload-1)/faketls.MaxRecordPayload)*faketls.RecordHeaderSize
}

// encodeResponse runs only on the DC owner, including its final EOF callback.
func (ctx *DCConnContext) encodeResponse(out, data []byte) {
	if ctx.ClientCtx.ProtocolMode() == ModeDD {
		ctx.DCDecrypt.XORKeyStream(out, data)
		ctx.ClientEncrypt.XORKeyStream(out, out)
		return
	}
	for len(data) > 0 {
		n := min(faketls.MaxRecordPayload, len(data))
		if ctx.drs != nil {
			n = ctx.drs.NextChunk(len(data))
		}
		out[0], out[1], out[2] = faketls.RecordTypeApplicationData, 0x03, 0x03
		out[3], out[4] = byte(n>>8), byte(n)
		payload := out[faketls.RecordHeaderSize : faketls.RecordHeaderSize+n]
		ctx.DCDecrypt.XORKeyStream(payload, data[:n])
		ctx.ClientEncrypt.XORKeyStream(payload, payload)
		if ctx.drs != nil {
			ctx.drs.Advance(n)
		}
		out = out[faketls.RecordHeaderSize+n:]
		data = data[n:]
	}
}

// gnet frees unread DC input immediately after OnClose. Encode its bounded
// tail before that return, then drain it after all earlier client writes.
func (h *ProxyHandler) drainDirectEOF(conn gnet.Conn, ctx *DCConnContext) {
	data, _ := conn.Peek(-1)
	if len(data) > max(h.maxWriteBuffer, relayBatchSize) || ctx.DCDecrypt == nil || ctx.ClientEncrypt == nil {
		_ = ctx.ClientConn.Close()
		return
	}
	size := ctx.responseSize(len(data))
	var release func()
	if stream, ok := ctx.ClientConn.(*LogicalStream); ok && size > 0 {
		if !stream.reserveAuxInput(size, 1) {
			_ = stream.Close()
			return
		}
		release = func() { stream.releaseAuxInput(size, 1) }
	}
	tail := make([]byte, size)
	ctx.encodeResponse(tail, data)
	if counter := ctx.ClientCtx.TrafficOut(); counter != nil {
		counter.Add(int64(len(data)))
	}
	h.beginClientDrain(ctx.ClientConn, ctx.ClientCtx, 30*time.Second, tail, release)
}

func (h *ProxyHandler) handleDCTrafficDD(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientCtx := dcCtx.ClientCtx
	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}
	if len(data) > max(h.maxWriteBuffer, relayBatchSize) {
		return gnet.Close
	}
	if dcCtx.ToClient == nil {
		dcCtx.ToClient = newRelayOutput(dcCtx.ClientConn, dcConn, clientCtx, h.maxWriteBuffer)
	}
	n := dcCtx.ToClient.reserve(min(len(data), relayBatchSize), 1)
	if n == 0 {
		return gnet.None
	}
	buffer, release := h.relayBuffer(n)
	dcCtx.DCDecrypt.XORKeyStream(buffer, data[:n])
	dcCtx.ClientEncrypt.XORKeyStream(buffer, buffer)
	if err := dcCtx.ToClient.write(buffer, release); err != nil {
		return gnet.Close
	}
	if counter := clientCtx.TrafficOut(); counter != nil {
		counter.Add(int64(n))
	}
	clientCtx.recordServerActivity()
	_, _ = dcConn.Discard(n)
	if len(data) > n {
		if err := dcConn.Wake(nil); err != nil {
			return gnet.Close
		}
	}
	return gnet.None
}
