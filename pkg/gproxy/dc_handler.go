package gproxy

import (
	"crypto/cipher"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/netx"
	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// Buffer pools for read operations
var (
	// 128KB buffer pool for DC->client relay
	dcReadBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, 128*1024)
			return &buf
		},
	}
	// 64KB buffer pool for splice relay
	spliceReadBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, 64*1024)
			return &buf
		},
	}
)

// dialDC establishes a direct connection to the Telegram DC.
func (h *ProxyHandler) dialDC(clientConn gnet.Conn, ctx *ConnContext) {
	ctx.mu.Lock()
	dcID := ctx.dcID
	userName := ""
	if ctx.secret != nil {
		userName = ctx.secret.Name
	}
	ctx.mu.Unlock()

	// Direct DC connection (simple, reliable)
	dcConn, err := h.dialDirectDC(dcID)
	if err != nil {
		h.logger.Debug("[%s] failed to dial DC %d: %v", userName, dcID, err)
		clientConn.Close()
		return
	}
	h.logger.Info("[%s] DC %d connected", userName, dcID)

	// Build relay context with DC connection info
	ctx.mu.Lock()
	relay := &RelayContext{
		Encryptor: ctx.encryptor,
		Decryptor: ctx.decryptor,
	}
	if ddc, ok := dcConn.(*directDCConn); ok {
		relay.DCConn = ddc.Conn
		relay.DCEncrypt = ddc.encryptor
		relay.DCDecrypt = ddc.decryptor
	} else {
		relay.DCConn = dcConn
	}
	pendingData := ctx.pendingData
	ctx.pendingData = nil
	ctx.mu.Unlock()

	// Atomically set relay context and state
	ctx.SetRelay(relay)

	// Process any pending data
	if len(pendingData) > 0 {
		h.sendPendingData(dcConn, ctx, pendingData)
	}

	// Start relay goroutine for DC -> client traffic
	go h.relayDCToClientLoop(dcConn, clientConn, ctx)
}

// dialDirectDC connects directly to Telegram DC with obfuscated2 handshake.
func (h *ProxyHandler) dialDirectDC(dcID int) (net.Conn, error) {
	// Negative DC IDs are for media/CDN - use absolute value for address lookup
	// but preserve the sign for the obfuscated2 handshake
	addrDC := dcID
	if addrDC < 0 {
		addrDC = -addrDC
	}

	// Get DC addresses based on IP preference
	var addrs []dc.Addr
	switch h.config.IPPreference {
	case dc.OnlyIPv4:
		addrs = dc.DCAddressesIPv4(addrDC)
	case dc.OnlyIPv6:
		addrs = dc.DCAddressesIPv6(addrDC)
	default:
		addrs = dc.DCAddresses(addrDC)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for DC %d", dcID)
	}

	dialer := netx.NewDialer()

	var conn netx.Conn
	var err error
	for _, addr := range addrs {
		conn, err = dialer.Dial(addr.Network, addr.Address)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	// Tune the connection
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		netx.TuneConn(tcpConn)
	}

	// Generate and send server handshake frame
	frame, encryptor, decryptor, err := obfuscated2.GenerateServerFrame(dcID)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write(frame); err != nil {
		conn.Close()
		return nil, err
	}

	// Store ciphers for later use - we need a way to pass these back
	// We'll use a wrapper or store in context before calling
	return &directDCConn{
		Conn:      conn,
		encryptor: encryptor,
		decryptor: decryptor,
	}, nil
}

// directDCConn wraps a direct DC connection with its ciphers.
type directDCConn struct {
	net.Conn
	encryptor, decryptor cipher.Stream
}

// sendPendingData sends buffered client data to DC.
func (h *ProxyHandler) sendPendingData(dcConn net.Conn, ctx *ConnContext, pendingData []byte) {
	// Lock-free read of relay context
	relay := ctx.Relay()
	if relay == nil {
		return
	}
	clientDecryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	// Get buffer from pool for crypto operations
	bufPtr := relayBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayBufPool.Put(bufPtr)

	// Handle data larger than pool buffer (rare)
	var decrypted []byte
	if len(pendingData) <= len(buf) {
		decrypted = buf[:len(pendingData)]
		copy(decrypted, pendingData)
	} else {
		decrypted = make([]byte, len(pendingData))
		copy(decrypted, pendingData)
	}

	// Decrypt from client
	clientDecryptor.XORKeyStream(decrypted, decrypted)

	// Encrypt for DC (obfuscated2)
	if dcEncrypt != nil {
		dcEncrypt.XORKeyStream(decrypted, decrypted)
	}

	if _, err := dcConn.Write(decrypted); err != nil {
		h.logger.Debug("failed to send pending data to DC: %v", err)
	}
}

// relayDCToClientLoop reads from DC and writes to client.
func (h *ProxyHandler) relayDCToClientLoop(dcConn net.Conn, clientConn gnet.Conn, ctx *ConnContext) {
	defer dcConn.Close()
	defer clientConn.Close()

	// Cache relay context once - it's immutable after handshake
	relay := ctx.Relay()
	if relay == nil {
		return
	}
	dcDecrypt := relay.DCDecrypt
	encryptor := relay.Encryptor

	// Get read buffer from pool
	readBufPtr := dcReadBufPool.Get().(*[]byte)
	readBuf := *readBufPtr
	defer dcReadBufPool.Put(readBufPtr)

	for {
		// Set read deadline
		if h.config.IdleTimeout > 0 {
			dcConn.SetReadDeadline(time.Now().Add(h.config.IdleTimeout))
		}

		n, err := dcConn.Read(readBuf)
		if err != nil {
			return
		}

		if n == 0 {
			continue
		}

		// Check state (lock-free)
		if ctx.State() != StateRelaying {
			return
		}

		// Calculate TLS output size
		numRecords := (n + faketls.MaxRecordPayload - 1) / faketls.MaxRecordPayload
		tlsSize := n + numRecords*faketls.RecordHeaderSize

		// Get buffer from pool - returned via AsyncWrite callback
		var tlsBuf []byte
		var tlsBufPtr *[]byte
		tlsBufPtr = dcBufPool.Get().(*[]byte)
		if tlsSize <= len(*tlsBufPtr) {
			tlsBuf = (*tlsBufPtr)[:tlsSize]
		} else {
			// Large data - allocate (rare for 512KB+ pool)
			dcBufPool.Put(tlsBufPtr)
			tlsBufPtr = nil
			tlsBuf = make([]byte, tlsSize)
		}

		// Decrypt from DC, encrypt for client, wrap in TLS - all in one pass
		// Process in 16KB chunks to build TLS records
		srcOffset := 0
		dstOffset := 0
		for srcOffset < n {
			chunk := min(faketls.MaxRecordPayload, n-srcOffset)

			// Write TLS header
			tlsBuf[dstOffset] = faketls.RecordTypeApplicationData
			tlsBuf[dstOffset+1] = 0x03
			tlsBuf[dstOffset+2] = 0x03
			tlsBuf[dstOffset+3] = byte(chunk >> 8)
			tlsBuf[dstOffset+4] = byte(chunk)
			dstOffset += faketls.RecordHeaderSize

			// Decrypt from DC directly into TLS payload area
			dcDecrypt.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], readBuf[srcOffset:srcOffset+chunk])

			// Encrypt for client (in-place)
			encryptor.XORKeyStream(tlsBuf[dstOffset:dstOffset+chunk], tlsBuf[dstOffset:dstOffset+chunk])

			dstOffset += chunk
			srcOffset += chunk
		}

		// Send to client - buffer returned to pool after write completes
		err = clientConn.AsyncWrite(tlsBuf, func(c gnet.Conn, err error) error {
			if tlsBufPtr != nil {
				dcBufPool.Put(tlsBufPtr)
			}
			return nil
		})
		if err != nil {
			// Write failed, return buffer now
			if tlsBufPtr != nil {
				dcBufPool.Put(tlsBufPtr)
			}
			return
		}
	}
}

// dialSplice establishes a connection to the splice target (mask host).
func (h *ProxyHandler) dialSplice(clientConn gnet.Conn, ctx *ConnContext) {
	addr := fmt.Sprintf("%s:%d", h.config.MaskHost, h.config.MaskPort)

	dialer := netx.NewDialer()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		h.logger.Debug("failed to dial splice target %s: %v", addr, err)
		clientConn.Close()
		return
	}

	h.logger.Debug("splice target connected: %s", addr)

	// Get buffered data from client BEFORE storing connection
	data, _ := clientConn.Peek(-1)

	// Store splice connection in context for handleSplice
	ctx.mu.Lock()
	ctx.spliceNetConn = conn
	ctx.mu.Unlock()
	// State already set to StateSplicing by startSplice

	// Send buffered data to splice target
	if len(data) > 0 {
		clientConn.Discard(len(data))
		if _, err := conn.Write(data); err != nil {
			conn.Close()
			clientConn.Close()
			return
		}
	}

	// Start goroutine for splice->client direction
	go h.relaySpliceToClientLoop(conn, clientConn, ctx)
}

// relaySpliceToClientLoop reads from splice target and writes to client.
func (h *ProxyHandler) relaySpliceToClientLoop(spliceConn net.Conn, clientConn gnet.Conn, _ *ConnContext) {
	defer spliceConn.Close()
	defer clientConn.Close()

	// Get buffer from pool (no crypto needed for splice)
	bufPtr := spliceReadBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer spliceReadBufPool.Put(bufPtr)

	for {
		if h.config.IdleTimeout > 0 {
			spliceConn.SetReadDeadline(time.Now().Add(h.config.IdleTimeout))
		}

		n, err := spliceConn.Read(buf)
		if err != nil {
			return
		}

		if n > 0 {
			clientConn.AsyncWrite(buf[:n], nil)
		}
	}
}

