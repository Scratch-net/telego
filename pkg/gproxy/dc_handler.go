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
	// 256KB buffer pool for DC->client relay - larger reads reduce syscalls
	dcReadBufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, 256*1024)
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
	// Get DC addresses (sorted by RTT if probing was done)
	addrs, known := dc.GetProbedAddresses(dcID)

	// Filter by IP preference
	if h.config.IPPreference == dc.OnlyIPv4 || h.config.IPPreference == dc.OnlyIPv6 {
		filtered := make([]dc.Addr, 0, len(addrs))
		for _, a := range addrs {
			if h.config.IPPreference == dc.OnlyIPv4 && !a.IsIPv6() {
				filtered = append(filtered, a)
			} else if h.config.IPPreference == dc.OnlyIPv6 && a.IsIPv6() {
				filtered = append(filtered, a)
			}
		}
		addrs = filtered
	}

	if !known {
		h.logger.Warn("unknown DC %d requested, falling back to DC %d", dcID, dc.DefaultDC)
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

// dialSplice establishes a connection to the splice target.
func (h *ProxyHandler) dialSplice(clientConn gnet.Conn, ctx *ConnContext) {
	addr := fmt.Sprintf("%s:%d", h.config.SpliceHost, h.config.SplicePort)

	dialer := netx.NewDialer()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		h.logger.Debug("failed to dial splice target %s: %v", addr, err)
		clientConn.Close()
		return
	}

	h.logger.Debug("splice target connected: %s", addr)

	// Send PROXY protocol header if configured
	if h.config.SpliceProxyProtocol > 0 {
		header := buildProxyProtocolHeader(
			h.config.SpliceProxyProtocol,
			clientConn.RemoteAddr(),
			clientConn.LocalAddr(),
		)
		if header != nil {
			if _, err := conn.Write(header); err != nil {
				h.logger.Debug("failed to send PROXY protocol header: %v", err)
				conn.Close()
				clientConn.Close()
				return
			}
		}
	}

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

	for {
		if h.config.IdleTimeout > 0 {
			spliceConn.SetReadDeadline(time.Now().Add(h.config.IdleTimeout))
		}

		// Get a fresh buffer each iteration - returned via AsyncWrite callback
		// This prevents buffer reuse race with gnet's async write queue
		bufPtr := spliceReadBufPool.Get().(*[]byte)
		buf := *bufPtr

		n, err := spliceConn.Read(buf)
		if err != nil {
			spliceReadBufPool.Put(bufPtr)
			return
		}

		if n > 0 {
			// Buffer ownership transfers to gnet until callback fires
			err = clientConn.AsyncWrite(buf[:n], func(c gnet.Conn, err error) error {
				spliceReadBufPool.Put(bufPtr)
				return nil
			})
			if err != nil {
				spliceReadBufPool.Put(bufPtr)
				return
			}
		} else {
			spliceReadBufPool.Put(bufPtr)
		}
	}
}

// buildProxyProtocolHeader builds a PROXY protocol header.
// version: 1 = v1 (text), 2 = v2 (binary)
func buildProxyProtocolHeader(version int, src, dst net.Addr) []byte {
	srcTCP, srcOK := src.(*net.TCPAddr)
	dstTCP, dstOK := dst.(*net.TCPAddr)
	if !srcOK || !dstOK {
		return nil
	}

	if version == 1 {
		return buildProxyProtocolV1(srcTCP, dstTCP)
	}
	return buildProxyProtocolV2(srcTCP, dstTCP)
}

// buildProxyProtocolV1 builds a PROXY protocol v1 (text) header.
// Format: "PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>\r\n"
func buildProxyProtocolV1(src, dst *net.TCPAddr) []byte {
	proto := "TCP4"
	if src.IP.To4() == nil {
		proto = "TCP6"
	}
	return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		proto, src.IP.String(), dst.IP.String(), src.Port, dst.Port))
}

// proxyProtocolV2Sig is the 12-byte signature for PROXY protocol v2.
var proxyProtocolV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// buildProxyProtocolV2 builds a PROXY protocol v2 (binary) header.
func buildProxyProtocolV2(src, dst *net.TCPAddr) []byte {
	var (
		family byte
		addrs  []byte
	)

	if src4, dst4 := src.IP.To4(), dst.IP.To4(); src4 != nil && dst4 != nil {
		// IPv4
		family = 0x11 // AF_INET << 4 | STREAM
		addrs = make([]byte, 12)
		copy(addrs[0:4], src4)
		copy(addrs[4:8], dst4)
		addrs[8] = byte(src.Port >> 8)
		addrs[9] = byte(src.Port)
		addrs[10] = byte(dst.Port >> 8)
		addrs[11] = byte(dst.Port)
	} else {
		// IPv6
		family = 0x21 // AF_INET6 << 4 | STREAM
		addrs = make([]byte, 36)
		copy(addrs[0:16], src.IP.To16())
		copy(addrs[16:32], dst.IP.To16())
		addrs[32] = byte(src.Port >> 8)
		addrs[33] = byte(src.Port)
		addrs[34] = byte(dst.Port >> 8)
		addrs[35] = byte(dst.Port)
	}

	// Build header: signature(12) + ver_cmd(1) + family(1) + len(2) + addrs
	header := make([]byte, 16+len(addrs))
	copy(header[0:12], proxyProtocolV2Sig)
	header[12] = 0x21 // version 2, PROXY command
	header[13] = family
	header[14] = byte(len(addrs) >> 8)
	header[15] = byte(len(addrs))
	copy(header[16:], addrs)

	return header
}
