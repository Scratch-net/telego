package gproxy

import (
	"encoding/binary"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// handleRelay processes data from the client and forwards to DC.
// Implements flow control with rate limiting and wake callbacks.
func (h *ProxyHandler) handleRelay(c gnet.Conn, ctx *ConnContext) gnet.Action {
	// Lock-free read of relay context
	relay := ctx.Relay()
	if relay == nil {
		// DC connection not ready yet
		return gnet.None
	}

	dcConn := relay.DCConn
	decryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	// NOTE: OutboundBuffered is not concurrency-safe per gnet docs.
	// We call it cross-event-loop (dcConn belongs to dcClient event loop).
	// This is acceptable: we only use the value for approximate flow control
	// decisions (is buffer above threshold?). A stale read just means we
	// throttle slightly early or late, which doesn't affect correctness.
	dcBuffered := dcConn.OutboundBuffered()

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Rate limiting with hysteresis: once throttled, stay throttled until buffer
	// drops below resumeAt to prevent oscillation at threshold boundaries.
	// No hard disconnects - let TCP flow control + idle timeout handle stuck DCs.
	wasThrottled := ctx.throttledToDC.Load()
	var maxProcess int

	if dcBuffered > h.maxWriteBuffer {
		// Above hard limit: trickle mode
		maxProcess = 16 * 1024
		ctx.throttledToDC.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: DC buffer %dMB > hard limit, trickle mode",
				ctx.LogPrefix(), dcBuffered/1024/1024)
		}
	} else if dcBuffered > h.bpSoftLimit {
		// Above soft limit: small chunks only
		maxProcess = 64 * 1024
		ctx.throttledToDC.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: DC buffer %dKB > soft limit, throttling",
				ctx.LogPrefix(), dcBuffered/1024)
		}
	} else if wasThrottled && dcBuffered > h.bpResumeAt {
		// Hysteresis: stay throttled until below resumeAt
		maxProcess = 256 * 1024
	} else {
		// Full speed - process everything
		maxProcess = len(data)
		if wasThrottled {
			ctx.throttledToDC.Store(false)
		}
	}

	// Get pooled buffer for batching writes to DC
	batchBufPtr := h.dcBufPool.Get()
	batchBuf := *batchBufPtr

	batchOffset := 0
	processed := 0
	hasMoreData := false // Track if we stopped with unprocessed data remaining

	// Process complete TLS records
	consumed := 0
	for len(data) >= faketls.RecordHeaderSize {
		// Parse TLS record header
		recordType := data[0]
		payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
		recordLen := faketls.RecordHeaderSize + payloadLen

		// Check for desync (abnormally large frame indicates crypto state divergence)
		if CheckFrameSize(payloadLen) {
			h.desyncDetector.Report(ctx, payloadLen, "c2dc", h.logger)
			h.dcBufPool.Put(batchBufPtr)
			return gnet.Close
		}

		if len(data) < recordLen {
			// Incomplete record, wait for more data
			break
		}

		// Only process ApplicationData records
		if recordType == faketls.RecordTypeApplicationData {
			payload := data[faketls.RecordHeaderSize:recordLen]

			// Check if we'd exceed maxProcess (but always process at least one record)
			if processed > 0 && processed+len(payload) > maxProcess {
				hasMoreData = true
				break
			}

			// Check if batch buffer has space
			if batchOffset+len(payload) > len(batchBuf) {
				// Flush current batch via AsyncWrite (cross-event-loop safe)
				if batchOffset > 0 {
					flushBuf := batchBufPtr
					flushData := batchBuf[:batchOffset]
					err := dcConn.AsyncWrite(flushData, func(_ gnet.Conn, _ error) error {
						h.dcBufPool.Put(flushBuf)
						return nil
					})
					if err != nil {
						h.dcBufPool.Put(flushBuf)
						return gnet.Close
					}
					// Get fresh buffer for continued processing
					batchBufPtr = h.dcBufPool.Get()
					batchBuf = *batchBufPtr
					batchOffset = 0
				}
			}

			// Decrypt from client, encrypt for DC directly into batch buffer
			decryptor.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], payload)
			dcEncrypt.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], batchBuf[batchOffset:batchOffset+len(payload)])
			batchOffset += len(payload)
			processed += len(payload)
		}

		consumed += recordLen
		data = data[recordLen:]
	}

	// Count traffic once after processing all records (client -> DC = upload/in)
	if counter := ctx.TrafficIn(); counter != nil && processed > 0 {
		counter.Add(int64(processed))
	}

	// Record client uplink activity for the silence wedge breaker.
	if h.clientSilenceCloseMs > 0 && processed > 0 {
		ctx.lastClientByteMs.Store(time.Now().UnixMilli())
	}

	// Flush remaining batch via AsyncWrite (cross-event-loop safe)
	if batchOffset > 0 {
		poolRef := batchBufPtr
		err := dcConn.AsyncWrite(batchBuf[:batchOffset], func(_ gnet.Conn, _ error) error {
			h.dcBufPool.Put(poolRef)
			return nil
		})
		if err != nil {
			h.dcBufPool.Put(poolRef)
			return gnet.Close
		}
	} else {
		h.dcBufPool.Put(batchBufPtr)
	}

	if consumed > 0 {
		c.Discard(consumed)
	}

	// Wake to continue processing if there's more data in buffer.
	// This is NOT a spin loop because each wake processes at least one TLS record
	// (real work: crypto, syscalls). Rate limiting caps throughput when DC buffer
	// is congested, but we still make forward progress each iteration.
	if hasMoreData {
		c.Wake(nil)
	}

	return gnet.None
}

// handleRelayDD processes data from client in DD mode (raw stream, no TLS framing).
func (h *ProxyHandler) handleRelayDD(c gnet.Conn, ctx *ConnContext) gnet.Action {
	relay := ctx.Relay()
	if relay == nil {
		return gnet.None
	}

	dcConn := relay.DCConn
	decryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	dcBuffered := dcConn.OutboundBuffered()

	data, _ := c.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Rate limiting with hysteresis (same as TLS relay)
	wasThrottled := ctx.throttledToDC.Load()
	var maxProcess int

	if dcBuffered > h.maxWriteBuffer {
		maxProcess = 16 * 1024
		ctx.throttledToDC.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: DC buffer %dMB > hard limit, trickle mode",
				ctx.LogPrefix(), dcBuffered/1024/1024)
		}
	} else if dcBuffered > h.bpSoftLimit {
		maxProcess = 64 * 1024
		ctx.throttledToDC.Store(true)
		if h.logger.DebugEnabled() {
			h.logger.Debug("[%s] backpressure: DC buffer %dKB > soft limit, throttling",
				ctx.LogPrefix(), dcBuffered/1024)
		}
	} else if wasThrottled && dcBuffered > h.bpResumeAt {
		maxProcess = 256 * 1024
	} else {
		maxProcess = len(data)
		if wasThrottled {
			ctx.throttledToDC.Store(false)
		}
	}

	// Limit data to process
	if len(data) > maxProcess {
		data = data[:maxProcess]
	}

	// Get pooled buffer
	batchBufPtr := h.dcBufPool.Get()
	batchBuf := *batchBufPtr

	// Ensure buffer is large enough
	if len(data) > len(batchBuf) {
		h.dcBufPool.Put(batchBufPtr)
		// Process in smaller chunk
		data = data[:len(batchBuf)]
	}

	// Decrypt from client, encrypt for DC
	decryptor.XORKeyStream(batchBuf[:len(data)], data)
	dcEncrypt.XORKeyStream(batchBuf[:len(data)], batchBuf[:len(data)])

	// Count traffic
	if counter := ctx.TrafficIn(); counter != nil {
		counter.Add(int64(len(data)))
	}

	// Record client uplink activity for the silence wedge breaker.
	if h.clientSilenceCloseMs > 0 && len(data) > 0 {
		ctx.lastClientByteMs.Store(time.Now().UnixMilli())
	}

	// Send to DC
	err := dcConn.AsyncWrite(batchBuf[:len(data)], func(_ gnet.Conn, _ error) error {
		h.dcBufPool.Put(batchBufPtr)
		return nil
	})
	if err != nil {
		h.dcBufPool.Put(batchBufPtr)
		return gnet.Close
	}

	c.Discard(len(data))

	// Wake if more data to process
	remaining, _ := c.Peek(-1)
	if len(remaining) > 0 {
		c.Wake(nil)
	}

	return gnet.None
}
