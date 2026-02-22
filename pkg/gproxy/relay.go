package gproxy

import (
	"encoding/binary"
	"sync"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// Buffer size matches TCP buffer size for optimal throughput
const relayBufSize = 512 * 1024 // 512KB

// Buffer pools for relay operations to avoid allocations in hot path
var (
	// relayBufPool for decrypt/encrypt buffers (up to 16KB TLS record)
	relayBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, faketls.MaxRecordPayload)
			return &buf
		},
	}

	// dcBufPool for batching writes - 512KB to match TCP buffers
	// Used for both Client->DC batching and DC->Client TLS wrapping
	dcBufPool = sync.Pool{
		New: func() any {
			// 512KB + TLS header overhead (5 bytes per 16KB = 160 bytes max)
			buf := make([]byte, relayBufSize+256)
			return &buf
		},
	}
)

// handleRelay processes data from the client and forwards to DC.
func (h *ProxyHandler) handleRelay(c gnet.Conn, ctx *ConnContext) gnet.Action {
	// Lock-free read of relay context
	relay := ctx.Relay()
	if relay == nil {
		// DC connection not ready yet
		return gnet.None
	}

	dcNetConn := relay.DCConn
	decryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Get pooled buffer for batching writes to DC
	// dcNetConn.Write is blocking, so we can safely reuse after it returns
	batchBufPtr := dcBufPool.Get().(*[]byte)
	batchBuf := *batchBufPtr
	defer dcBufPool.Put(batchBufPtr)

	batchOffset := 0

	// Process complete TLS records
	consumed := 0
	for len(data) >= faketls.RecordHeaderSize {
		// Parse TLS record header
		recordType := data[0]
		payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
		recordLen := faketls.RecordHeaderSize + payloadLen

		if len(data) < recordLen {
			// Incomplete record, wait for more data
			break
		}

		// Only process ApplicationData records
		if recordType == faketls.RecordTypeApplicationData {
			// Extract payload
			payload := data[faketls.RecordHeaderSize:recordLen]

			// Check if batch buffer has space
			if batchOffset+len(payload) > len(batchBuf) {
				// Flush current batch
				if batchOffset > 0 {
					if _, err := dcNetConn.Write(batchBuf[:batchOffset]); err != nil {
						return gnet.Close
					}
					batchOffset = 0
				}
			}

			// Decrypt from client, encrypt for DC directly into batch buffer
			decryptor.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], payload)
			dcEncrypt.XORKeyStream(batchBuf[batchOffset:batchOffset+len(payload)], batchBuf[batchOffset:batchOffset+len(payload)])
			batchOffset += len(payload)
		}

		consumed += recordLen
		data = data[recordLen:]
	}

	// Flush remaining batch
	if batchOffset > 0 {
		if _, err := dcNetConn.Write(batchBuf[:batchOffset]); err != nil {
			return gnet.Close
		}
	}

	if consumed > 0 {
		c.Discard(consumed)
	}

	return gnet.None
}

