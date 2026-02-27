package gproxy

import (
	"crypto/cipher"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// dcEventHandler handles events from DC connections.
type dcEventHandler struct {
	gnet.BuiltinEventEngine
	proxy *ProxyHandler
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
}

// OnTraffic handles data arriving from DC.
func (h *dcEventHandler) OnTraffic(c gnet.Conn) gnet.Action {
	ctx, ok := c.Context().(*DCConnContext)
	if !ok || ctx == nil {
		return gnet.Close
	}
	return h.proxy.handleDCTraffic(c, ctx)
}

// OnClose handles DC connection close.
func (h *dcEventHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx, ok := c.Context().(*DCConnContext)
	if !ok || ctx == nil {
		return gnet.None
	}

	// Close the associated client connection
	if ctx.ClientConn != nil {
		ctx.ClientConn.Close()
	}

	return gnet.None
}

// handleDCTraffic processes data from DC and forwards to client.
// This is the event-driven replacement for relayDCToClientLoop.
func (h *ProxyHandler) handleDCTraffic(dcConn gnet.Conn, dcCtx *DCConnContext) gnet.Action {
	clientConn := dcCtx.ClientConn
	clientCtx := dcCtx.ClientCtx

	// Check client is still in relay state
	if clientCtx.State() != StateRelaying {
		return gnet.Close
	}

	// Read available data from DC
	data, _ := dcConn.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Calculate TLS output size
	numRecords := (len(data) + faketls.MaxRecordPayload - 1) / faketls.MaxRecordPayload
	tlsSize := len(data) + numRecords*faketls.RecordHeaderSize

	// Get buffer from pool
	tlsBufPtr := dcBufPool.Get().(*[]byte)
	var tlsBuf []byte
	if tlsSize <= len(*tlsBufPtr) {
		tlsBuf = (*tlsBufPtr)[:tlsSize]
	} else {
		// Large data - allocate (rare)
		dcBufPool.Put(tlsBufPtr)
		tlsBufPtr = nil
		tlsBuf = make([]byte, tlsSize)
	}

	// Decrypt from DC, encrypt for client, wrap in TLS - all in one pass
	srcOffset := 0
	dstOffset := 0
	for srcOffset < len(data) {
		chunk := min(faketls.MaxRecordPayload, len(data)-srcOffset)

		// Write TLS header
		tlsBuf[dstOffset] = faketls.RecordTypeApplicationData
		tlsBuf[dstOffset+1] = 0x03
		tlsBuf[dstOffset+2] = 0x03
		tlsBuf[dstOffset+3] = byte(chunk >> 8)
		tlsBuf[dstOffset+4] = byte(chunk)
		dstOffset += faketls.RecordHeaderSize

		// Decrypt from DC into TLS payload
		dcCtx.DCDecrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], data[srcOffset:srcOffset+chunk])

		// Encrypt for client (in-place)
		dcCtx.ClientEncrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], tlsBuf[dstOffset:dstOffset+chunk])

		dstOffset += chunk
		srcOffset += chunk
	}

	// Discard processed data from DC buffer
	dcConn.Discard(len(data))

	// Async write to client - buffer returned to pool after write completes
	err := clientConn.AsyncWrite(tlsBuf, func(c gnet.Conn, err error) error {
		if tlsBufPtr != nil {
			dcBufPool.Put(tlsBufPtr)
		}
		return nil
	})
	if err != nil {
		if tlsBufPtr != nil {
			dcBufPool.Put(tlsBufPtr)
		}
		return gnet.Close
	}

	return gnet.None
}
