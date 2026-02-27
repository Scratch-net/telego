package gproxy

import (
	"encoding/binary"
	"sync"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// Buffer size for optimal throughput - larger buffers reduce syscalls
const relayBufSize = 768 * 1024 // 768KB for better batching

// Buffer pools for relay operations to avoid allocations in hot path
var (
	// relayBufPool for decrypt/encrypt buffers (up to 16KB TLS record)
	relayBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, faketls.MaxRecordPayload)
			return &buf
		},
	}

	// dcBufPool for batching writes - 768KB for reduced syscalls
	// Used for both Client->DC batching and DC->Client TLS wrapping
	// Sized to hold 768KB data + TLS header overhead (5 bytes per 16KB = ~240 bytes)
	dcBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, relayBufSize+512)
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

	dcConn := relay.DCConn
	decryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		return gnet.None
	}

	// Get pooled buffer for batching writes to DC
	batchBufPtr := dcBufPool.Get().(*[]byte)
	batchBuf := *batchBufPtr

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
				// Flush current batch via async write
				if batchOffset > 0 {
					// Need a separate buffer for async write
					flushBuf := make([]byte, batchOffset)
					copy(flushBuf, batchBuf[:batchOffset])
					if err := dcConn.AsyncWrite(flushBuf, nil); err != nil {
						dcBufPool.Put(batchBufPtr)
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
		// For final batch, we can reuse the pool buffer with callback
		finalBuf := batchBuf[:batchOffset]
		err := dcConn.AsyncWrite(finalBuf, func(c gnet.Conn, err error) error {
			dcBufPool.Put(batchBufPtr)
			return nil
		})
		if err != nil {
			dcBufPool.Put(batchBufPtr)
			return gnet.Close
		}
	} else {
		// No data written, return buffer immediately
		dcBufPool.Put(batchBufPtr)
	}

	if consumed > 0 {
		c.Discard(consumed)
	}

	return gnet.None
}
