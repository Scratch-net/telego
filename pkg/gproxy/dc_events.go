package gproxy

import (
	"crypto/cipher"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// dcEventHandler handles events from DC connections.
type dcEventHandler struct {
	gnet.BuiltinEventEngine
	proxy *ProxyHandler
}

// getDCContext retrieves the DCConnContext for a connection.
// Falls back to the pending map if c.Context() returns nil (race window during setup).
func (h *dcEventHandler) getDCContext(c gnet.Conn) *DCConnContext {
	if ctx, ok := c.Context().(*DCConnContext); ok && ctx != nil {
		return ctx
	}
	// Fallback: check pending map during Enroll/SetContext race window
	if val, ok := h.proxy.pendingDCContexts.Load(c.Fd()); ok {
		return val.(*DCConnContext)
	}
	return nil
}

// DCConnContext holds per-DC-connection state.
type DCConnContext struct {
	// Link back to client connection
	ClientConn gnet.Conn

	// Client context for state access
	ClientCtx *ConnContext

	// DC ciphers (proxy <-> DC)
	DCEncrypt cipher.Stream
	DCDecrypt cipher.Stream

	// Client ciphers (cached from relay context)
	ClientEncrypt cipher.Stream // encrypt TO client

	// Flow control: DC connection reference for wake mechanism
	DCConn gnet.Conn

	// Backpressure state for hysteresis (avoids oscillation at threshold boundaries)
	// Once throttled, stays throttled until buffer drops below resumeAt
	throttledToClient atomic.Bool // DC->Client direction is throttled

	// drs shapes outbound TLS ApplicationData records for anti-DPI.
	// Mutated only from the dcClient event loop (single goroutine), so no
	// synchronization is needed. nil = legacy fixed-size chunking.
	drs *faketls.DRSState
}

// OnTraffic handles data arriving from DC.
func (h *dcEventHandler) OnTraffic(c gnet.Conn) gnet.Action {
	ctx := h.getDCContext(c)
	if ctx == nil {
		// Should never happen with pending map fallback
		return gnet.Close
	}
	return h.proxy.handleDCTraffic(c, ctx)
}

// OnClose handles DC connection close.
func (h *dcEventHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx := h.getDCContext(c)
	if ctx == nil {
		return gnet.None
	}

	// Log DC disconnect with details for debugging
	if ctx.ClientCtx != nil {
		prefix := ctx.ClientCtx.LogPrefix()
		dcID := ctx.ClientCtx.DCID()
		duration := time.Since(ctx.ClientCtx.connTime)

		isRealError := err != nil && !errors.Is(err, io.EOF)
		if isRealError {
			h.proxy.logger.Warn("[%s] DC %d disconnected (%v): %v", prefix, dcID, duration.Round(time.Millisecond), err)
		} else {
			h.proxy.logger.Debug("[%s] DC %d disconnected (%v)", prefix, dcID, duration.Round(time.Millisecond))
		}
	}

	if ctx.ClientConn != nil {
		ctx.ClientConn.Close()
	}
	return gnet.None
}

// handleDCTraffic processes data from DC and forwards to client.
// Implements flow control with rate limiting and wake callbacks.
func (h *ProxyHandler) handleDCTraffic(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientConn := dcCtx.ClientConn
	clientCtx := dcCtx.ClientCtx

	// Check if client connection was closed
	if clientCtx.State() == StateClosed {
		return gnet.Close
	}

	// Defense in depth: should never be nil since dialDC checks under mutex.
	// Kept as safety net against future bugs - costs nothing, prevents panic.
	if dcCtx.ClientEncrypt == nil || dcCtx.DCDecrypt == nil {
		return gnet.Close
	}

	// DD mode uses raw stream without TLS wrapping
	if clientCtx.ProtocolMode() == ModeDD {
		return h.handleDCTrafficDD(dcConn, dcCtx)
	}

	// NOTE: OutboundBuffered is not concurrency-safe per gnet docs.
	// We call it cross-event-loop (clientConn belongs to server event loop).
	// This is acceptable: we only use the value for approximate flow control
	// decisions (is buffer above threshold?). A stale read just means we
	// throttle slightly early or late, which doesn't affect correctness.
	clientBuffered := clientConn.OutboundBuffered()

	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Rate limiting with hysteresis: once throttled, stay throttled until buffer
	// drops below resumeAt to prevent oscillation at threshold boundaries.
	// No hard disconnects - let TCP flow control + idle timeout handle stuck clients.
	wasThrottled := dcCtx.throttledToClient.Load()
	maxProcess := len(data) // Default: full speed

	if clientBuffered > h.maxWriteBuffer {
		// Above hard limit: trickle mode - keep alive but minimal throughput
		// TCP backpressure will naturally slow DC, idle timeout catches truly stuck clients
		maxProcess = min(16*1024, len(data))
		dcCtx.throttledToClient.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: client buffer %dMB > hard limit, trickle mode",
				clientCtx.LogPrefix(), clientBuffered/1024/1024)
		}
	} else if clientBuffered > h.bpSoftLimit {
		// Above soft limit: small chunks only
		maxProcess = min(64*1024, len(data))
		dcCtx.throttledToClient.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: client buffer %dKB > soft limit, throttling",
				clientCtx.LogPrefix(), clientBuffered/1024)
		}
	} else if wasThrottled && clientBuffered > h.bpResumeAt {
		// Hysteresis: stay throttled until below resumeAt
		maxProcess = min(256*1024, len(data))
	} else if wasThrottled {
		// Exiting throttle mode
		dcCtx.throttledToClient.Store(false)
	}
	// else: full speed - process all available data

	// Limit data to what we'll process
	processData := data[:maxProcess]

	// Count traffic (DC -> client = download/out)
	if counter := clientCtx.TrafficOut(); counter != nil {
		counter.Add(int64(len(processData)))
	}

	// Record server downlink activity for the silence wedge breaker.
	if h.clientSilenceCloseMs > 0 && len(processData) > 0 {
		clientCtx.lastServerByteMs.Store(time.Now().UnixMilli())
	}

	// Calculate TLS output size.
	// With DRS/split-TLS active, record sizes vary so PlanSize simulates the
	// upcoming chunking. Without DRS the formula is identical to the legacy one.
	var tlsSize int
	if dcCtx.drs != nil {
		tlsSize = dcCtx.drs.PlanSize(len(processData))
	} else {
		numRecords := (len(processData) + faketls.MaxRecordPayload - 1) / faketls.MaxRecordPayload
		tlsSize = len(processData) + numRecords*faketls.RecordHeaderSize
	}

	// Get buffer from pool
	tlsBufPtr := h.dcBufPool.Get()
	var tlsBuf []byte
	if tlsSize <= len(*tlsBufPtr) {
		tlsBuf = (*tlsBufPtr)[:tlsSize]
	} else {
		// Large data - allocate (rare)
		h.dcBufPool.Put(tlsBufPtr)
		tlsBufPtr = nil
		tlsBuf = make([]byte, tlsSize)
	}

	// Decrypt from DC, encrypt for client, wrap in TLS - all in one pass
	srcOffset := 0
	dstOffset := 0
	for srcOffset < len(processData) {
		remaining := len(processData) - srcOffset
		var chunk int
		if dcCtx.drs != nil {
			chunk = dcCtx.drs.NextChunk(remaining)
		} else {
			chunk = min(faketls.MaxRecordPayload, remaining)
		}

		// Write TLS header
		tlsBuf[dstOffset] = faketls.RecordTypeApplicationData
		tlsBuf[dstOffset+1] = 0x03
		tlsBuf[dstOffset+2] = 0x03
		tlsBuf[dstOffset+3] = byte(chunk >> 8)
		tlsBuf[dstOffset+4] = byte(chunk)
		dstOffset += faketls.RecordHeaderSize

		// Decrypt from DC into TLS payload
		dcCtx.DCDecrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], processData[srcOffset:srcOffset+chunk])

		// Encrypt for client (in-place)
		dcCtx.ClientEncrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], tlsBuf[dstOffset:dstOffset+chunk])

		if dcCtx.drs != nil {
			dcCtx.drs.Advance(chunk)
		}
		dstOffset += chunk
		srcOffset += chunk
	}

	// Discard what we processed
	dcConn.Discard(len(processData))

	// Must use AsyncWrite for cross-event-loop writes.
	// Sync Write() on error calls c.loop.close() from current goroutine,
	// but c.loop is the SERVER event loop while we're on DC goroutine.
	// This causes concurrent map writes in server's connMatrix.
	// AsyncWrite queues to owning event loop via poller.Trigger().
	//
	// Slice to dstOffset rather than the pre-sized tlsBuf: the two are equal
	// under current code (PlanSize and the real loop run in lockstep), but
	// slicing defensively guards against any future drift between predicted
	// and actual record output, and ensures we never send unwritten pool
	// buffer bytes past the real data.
	out := tlsBuf[:dstOffset]
	var err error
	if tlsBufPtr != nil {
		poolRef := tlsBufPtr
		err = clientConn.AsyncWrite(out, func(_ gnet.Conn, _ error) error {
			h.dcBufPool.Put(poolRef)
			return nil
		})
		if err != nil {
			h.dcBufPool.Put(poolRef)
		}
	} else {
		err = clientConn.AsyncWrite(out, nil)
	}
	if err != nil {
		return gnet.Close
	}

	// Wake to continue processing if there's more data in DC buffer.
	// This is NOT a spin loop because each wake processes real data (crypto,
	// TLS framing, syscalls). Rate limiting caps throughput when client buffer
	// is congested, but we still make forward progress each iteration.
	if dcConn.InboundBuffered() > 0 {
		dcConn.Wake(nil)
	}

	return gnet.None
}

// handleDCTrafficDD processes data from DC and forwards to client in DD mode.
// DD mode sends raw obfuscated2 stream without TLS wrapping.
func (h *ProxyHandler) handleDCTrafficDD(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientConn := dcCtx.ClientConn
	clientCtx := dcCtx.ClientCtx

	clientBuffered := clientConn.OutboundBuffered()

	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Rate limiting with hysteresis (same as TLS mode)
	wasThrottled := dcCtx.throttledToClient.Load()
	maxProcess := len(data)

	if clientBuffered > h.maxWriteBuffer {
		maxProcess = min(16*1024, len(data))
		dcCtx.throttledToClient.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: client buffer %dMB > hard limit, trickle mode",
				clientCtx.LogPrefix(), clientBuffered/1024/1024)
		}
	} else if clientBuffered > h.bpSoftLimit {
		maxProcess = min(64*1024, len(data))
		dcCtx.throttledToClient.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: client buffer %dKB > soft limit, throttling",
				clientCtx.LogPrefix(), clientBuffered/1024)
		}
	} else if wasThrottled && clientBuffered > h.bpResumeAt {
		maxProcess = min(256*1024, len(data))
	} else if wasThrottled {
		dcCtx.throttledToClient.Store(false)
	}

	processData := data[:maxProcess]

	// Count traffic (DC -> client = download/out)
	if counter := clientCtx.TrafficOut(); counter != nil {
		counter.Add(int64(len(processData)))
	}

	// Record server downlink activity for the silence wedge breaker.
	if h.clientSilenceCloseMs > 0 && len(processData) > 0 {
		clientCtx.lastServerByteMs.Store(time.Now().UnixMilli())
	}

	// Get buffer from pool
	bufPtr := h.dcBufPool.Get()
	buf := *bufPtr

	// Ensure buffer is large enough
	if len(processData) > len(buf) {
		h.dcBufPool.Put(bufPtr)
		bufPtr = nil
		buf = make([]byte, len(processData))
	}

	// Decrypt from DC, encrypt for client (no TLS wrapping in DD mode)
	dcCtx.DCDecrypt.XORKeyStream(buf[:len(processData)], processData)
	dcCtx.ClientEncrypt.XORKeyStream(buf[:len(processData)], buf[:len(processData)])

	dcConn.Discard(len(processData))

	var err error
	if bufPtr != nil {
		poolRef := bufPtr
		err = clientConn.AsyncWrite(buf[:len(processData)], func(_ gnet.Conn, _ error) error {
			h.dcBufPool.Put(poolRef)
			return nil
		})
		if err != nil {
			h.dcBufPool.Put(poolRef)
		}
	} else {
		err = clientConn.AsyncWrite(buf[:len(processData)], nil)
	}
	if err != nil {
		return gnet.Close
	}

	if dcConn.InboundBuffered() > 0 {
		dcConn.Wake(nil)
	}

	return gnet.None
}
