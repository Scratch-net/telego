package gproxy

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/netx"
	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// Buffer pool for splice relay (still uses goroutine)
var spliceReadBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

const spliceDrainCheckInterval = 5 * time.Millisecond

// getFd extracts the file descriptor from a net.Conn.
// Returns -1 if the fd cannot be obtained.
func getFd(conn net.Conn) int {
	type syscallConn interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := conn.(syscallConn)
	if !ok {
		return -1
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return -1
	}
	fd := -1
	rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	return fd
}

// dialDC establishes a direct connection to the Telegram DC.
func (h *ProxyHandler) dialDC(clientConn gnet.Conn, ctx *ConnContext) {
	// Read all needed state under mutex.
	// Cleanup() also uses this mutex when nilling ciphers.
	// Mutex guarantees: either we read valid values (Cleanup hasn't run),
	// or we read nil (Cleanup already ran). No in-between state possible.
	ctx.mu.Lock()
	dcID := ctx.dcID
	connectionType := ctx.o2ConnectionType
	userName := ""
	if ctx.secret != nil {
		userName = ctx.secret.Name
	}
	clientEncryptor := ctx.encryptor
	clientDecryptor := ctx.decryptor
	pendingData := ctx.pendingData
	ctx.pendingData = nil
	ctx.mu.Unlock()

	// If Cleanup() ran before we acquired the lock, ciphers are nil.
	// If we acquired first, we have valid copies that Cleanup() can't affect.
	if clientEncryptor == nil || clientDecryptor == nil {
		return
	}

	// Direct DC connection (simple, reliable)
	ddc, err := h.directDCDial(dcID, connectionType)
	if err != nil {
		h.logger.Debug("[#%d:%s] failed to dial DC %d: %v", ctx.id, userName, dcID, err)
		h.recordHandshakeFailure(ctx, handshakeFailureBackendDial)
		clientConn.Close()
		return
	}

	// Optimization: skip setup if client closed during slow dial.
	// Not required for correctness - handleDCTraffic would detect StateClosed anyway.
	if ctx.State() == StateClosed {
		ddc.Close()
		return
	}

	// Pre-create DC context before Enroll.
	//
	// RACE WINDOW MITIGATION: gnet's SetContext() is not concurrency-safe,
	// but we must set context after Enroll returns. Between Enroll return and
	// SetContext, DC event handlers might run with c.Context() == nil.
	//
	// Solution: Store context in pendingDCContexts map BEFORE Enroll.
	// DC event handlers (getDCContext) check both c.Context() and this map.
	// This eliminates the race: either c.Context() works or the map works.
	//
	// The map entry is deleted after SetContext. The sync.Map delete provides
	// a memory barrier ensuring the SetContext write is visible.
	dcCtx := &DCConnContext{
		ClientConn:    clientConn,
		ClientCtx:     ctx,
		DCEncrypt:     ddc.encryptor,
		DCDecrypt:     ddc.decryptor,
		ClientEncrypt: clientEncryptor,
		// DCConn set below after Enroll
	}

	// DRS / Split-TLS only apply to FakeTLS (EE) mode — DD mode is a raw stream.
	if ctx.ProtocolMode() == ModeEE && (h.config.EnableDRS || h.config.EnableSplitTLS) {
		dcCtx.drs = faketls.NewDRSState(
			h.config.EnableDRS,
			h.config.EnableSplitTLS,
			faketls.MaxRecordPayload,
		)
	}

	// Get fd and store context in map BEFORE Enroll - eliminates race completely
	fd := getFd(ddc.Conn)
	if fd >= 0 {
		h.pendingDCContexts.Store(fd, dcCtx)
	}

	// Enroll the DC connection into gnet client event loop
	dcGnetConn, err := h.dcClient.Enroll(ddc.Conn)
	if err != nil {
		if fd >= 0 {
			h.pendingDCContexts.Delete(fd)
		}
		h.logger.Debug("[#%d:%s] failed to enroll DC connection: %v", ctx.id, userName, err)
		h.recordHandshakeFailure(ctx, handshakeFailureBackendDial)
		ddc.Close()
		clientConn.Close()
		return
	}

	// Set context on the gnet connection
	dcCtx.DCConn = dcGnetConn
	dcGnetConn.SetContext(dcCtx)

	// Remove from pending map - context is now accessible via c.Context()
	if fd >= 0 {
		h.pendingDCContexts.Delete(fd)
	}

	// Log with client IP (use real IP from PROXY protocol if available)
	clientAddr := ctx.RealClientAddr(clientConn.RemoteAddr())
	h.logger.Info("[#%d:%s] %s -> DC %d", ctx.id, userName, clientAddr, dcID)

	// Build relay context for client -> DC direction
	relay := &RelayContext{
		Encryptor: clientEncryptor,
		Decryptor: clientDecryptor,
		DCConn:    dcGnetConn,
		DCEncrypt: ddc.encryptor,
		DCDecrypt: ddc.decryptor,
	}

	// Atomically set relay context and state
	ctx.SetRelay(relay)

	// Register for the client-silence wedge sweep (OnTick) when enabled.
	if h.clientSilenceCloseMs > 0 {
		h.relayConns.Store(ctx.id, &relayEntry{conn: clientConn, ctx: ctx})
	}

	// Process any pending data from handshake
	if len(pendingData) > 0 {
		h.sendPendingDataGnet(dcGnetConn, relay, pendingData)
	}

	// Wake client to process any data buffered during DC dial
	// Without this, data that arrived while in StateDialingDC would never be processed
	clientConn.Wake(nil)
}

// dialDirectDC connects directly to Telegram DC with obfuscated2 handshake.
func (h *ProxyHandler) dialDirectDC(dcID int, connectionType obfuscated2.ConnectionType) (*directDCConn, error) {
	// Get DC addresses (sorted by RTT if probing was done)
	addrs, known := dc.GetProbedAddresses(dcID)

	// Apply IP preference
	switch h.config.IPPreference {
	case dc.OnlyIPv4:
		addrs = filterAddrs(addrs, false)
	case dc.OnlyIPv6:
		addrs = filterAddrs(addrs, true)
	case dc.PreferIPv4:
		addrs = sortAddrsByPreference(addrs, false)
	case dc.PreferIPv6:
		addrs = sortAddrsByPreference(addrs, true)
	}

	if !known {
		h.logger.Warn("unknown DC %d requested, falling back to DC %d", dcID, dc.DefaultDC)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for DC %d", dcID)
	}

	// Create dialer - use SOCKS5 if configured
	var dialFunc func(network, address string) (netx.Conn, error)
	if h.config.Socks5Addr != "" {
		socks5Dialer, err := netx.NewSocks5Dialer(h.config.Socks5Addr)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		dialFunc = socks5Dialer.Dial
	} else {
		dialer := netx.NewDialer()
		dialFunc = dialer.Dial
	}

	var conn netx.Conn
	var err error
	var usedAddr dc.Addr
	dialStart := time.Now()
	for _, addr := range addrs {
		conn, err = dialFunc(addr.Network, addr.Address)
		if err == nil {
			usedAddr = addr
			break
		}
		h.logger.Debug("DC %d dial failed: %s: %v", dcID, addr.Address, err)
	}
	dialDuration := time.Since(dialStart)

	if err != nil {
		h.logger.Warn("DC %d all addresses failed after %v", dcID, dialDuration)
		return nil, err
	}

	h.logger.Debug("DC %d connected to %s in %v", dcID, usedAddr.Address, dialDuration)

	// Tune the connection
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		netx.TuneConn(tcpConn)
	}

	// Generate and send the server handshake using the client's packet framing.
	// Relay code forwards the decrypted packet bytes unchanged, so selecting a
	// different framing here would make Telegram parse those bytes incorrectly.
	encryptor, decryptor, err := writeDCHandshake(conn, dcID, connectionType)
	if err != nil {
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

// writeDCHandshake writes a complete obfuscated2 handshake and returns the
// continued cipher streams for the upstream connection.
func writeDCHandshake(w io.Writer, dcID int, connectionType obfuscated2.ConnectionType) (cipher.Stream, cipher.Stream, error) {
	frame, encryptor, decryptor, err := obfuscated2.GenerateServerFrameWithType(dcID, connectionType)
	if err != nil {
		return nil, nil, err
	}

	for len(frame) > 0 {
		n, writeErr := w.Write(frame)
		if writeErr != nil {
			return nil, nil, writeErr
		}
		if n == 0 {
			return nil, nil, io.ErrShortWrite
		}
		frame = frame[n:]
	}

	return encryptor, decryptor, nil
}

// directDCConn wraps a direct DC connection with its ciphers.
type directDCConn struct {
	net.Conn
	encryptor, decryptor cipher.Stream
}

// sendPendingDataGnet sends buffered client data to DC via gnet.Conn.
func (h *ProxyHandler) sendPendingDataGnet(dcConn gnet.Conn, relay *RelayContext, pendingData []byte) {
	clientDecryptor := relay.Decryptor
	dcEncrypt := relay.DCEncrypt

	// Get buffer from pool for crypto operations
	bufPtr := h.relayBufPool.Get()
	buf := *bufPtr

	// Handle data larger than pool buffer (rare)
	var decrypted []byte
	if len(pendingData) <= len(buf) {
		decrypted = buf[:len(pendingData)]
		copy(decrypted, pendingData)
	} else {
		h.relayBufPool.Put(bufPtr)
		bufPtr = nil
		decrypted = make([]byte, len(pendingData))
		copy(decrypted, pendingData)
	}

	// Decrypt from client
	clientDecryptor.XORKeyStream(decrypted, decrypted)

	// Encrypt for DC (obfuscated2)
	if dcEncrypt != nil {
		dcEncrypt.XORKeyStream(decrypted, decrypted)
	}

	// Use AsyncWrite - this runs from dialDC goroutine, not dcClient event loop
	if bufPtr != nil {
		poolRef := bufPtr
		err := dcConn.AsyncWrite(decrypted, func(_ gnet.Conn, _ error) error {
			h.relayBufPool.Put(poolRef)
			return nil
		})
		if err != nil {
			h.relayBufPool.Put(poolRef)
			h.logger.Debug("failed to send pending data to DC: %v", err)
		}
	} else {
		if err := dcConn.AsyncWrite(decrypted, nil); err != nil {
			h.logger.Debug("failed to send pending data to DC: %v", err)
		}
	}
}

// dialSplice establishes a connection to the splice target.
func (h *ProxyHandler) dialSplice(clientConn gnet.Conn, ctx *ConnContext) {
	// Check if client already closed
	if ctx.State() == StateClosed {
		return
	}

	addr := fmt.Sprintf("%s:%d", h.config.SpliceHost, h.config.SplicePort)

	// SNI-following: an unauthenticated probe whose SNI is on the mask safelist
	// is fronted to that domain's own server instead of the default target.
	if override := ctx.consumeSpliceOverride(); override != "" {
		addr = override
		h.logger.Debug("[#%d] splicing to safelisted SNI target %s", ctx.id, addr)
	}

	dialer := netx.NewDialer()
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		h.logger.Debug("failed to dial splice target %s: %v", addr, err)
		clientConn.Close()
		return
	}

	// Check again after slow dial
	if ctx.State() == StateClosed {
		conn.Close()
		return
	}

	h.logger.Debug("splice target connected: %s", addr)

	// Send PROXY protocol header if configured
	if h.config.SpliceProxyProtocol > 0 {
		// Use real client address from PROXY protocol if available
		srcAddr := ctx.RealClientAddr(clientConn.RemoteAddr())
		header := buildProxyProtocolHeader(
			h.config.SpliceProxyProtocol,
			srcAddr,
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

	// Store splice connection atomically for handleSplice
	ctx.SetSpliceConn(conn)
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
// Implements flow control by waiting for buffer space instead of busy-polling.
func (h *ProxyHandler) relaySpliceToClientLoop(spliceConn net.Conn, clientConn gnet.Conn, ctx *ConnContext) {
	defer spliceConn.Close()

	// Cache config and set initial deadline
	// Only update deadline when half the timeout has elapsed to reduce syscalls
	idleTimeout := h.config.SpliceIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	var lastDeadlineSet time.Time
	deadlineRefreshThreshold := idleTimeout / 2
	if idleTimeout > 0 {
		lastDeadlineSet = time.Now()
		spliceConn.SetReadDeadline(lastDeadlineSet.Add(idleTimeout))
	}

	// Cache resume channel - used for flow control signaling
	resumeCh := ctx.spliceResume

	for {
		// Check if client connection was closed
		if ctx.State() == StateClosed {
			return
		}

		buffered := ctx.spliceBufferedBytes()

		// HARD LIMIT: Close if client buffer exceeds max
		if buffered > h.maxWriteBuffer {
			h.logger.Warn("splice: client write buffer exceeded %dMB, closing slow client",
				h.maxWriteBuffer/1024/1024)
			clientConn.Close()
			return
		}

		// Throttle when buffer is getting full - wait for signal instead of sleeping
		if buffered > h.bpSoftLimit {
			h.sampleSpliceBuffer(clientConn, ctx)
			select {
			case <-resumeCh:
				// Buffer drained, continue
			case <-time.After(50 * time.Millisecond):
				// Fallback timeout prevents deadlock if signal is missed
			}
			continue
		}

		// Refresh deadline only if threshold elapsed (reduces syscalls)
		if idleTimeout > 0 && time.Since(lastDeadlineSet) >= deadlineRefreshThreshold {
			lastDeadlineSet = time.Now()
			spliceConn.SetReadDeadline(lastDeadlineSet.Add(idleTimeout))
		}

		// Get a fresh buffer each iteration - returned via AsyncWrite callback
		// This prevents buffer reuse race with gnet's async write queue
		bufPtr := spliceReadBufPool.Get().(*[]byte)
		buf := *bufPtr

		n, readErr := spliceConn.Read(buf)

		if n > 0 {
			// Capture variables for callback closure
			poolBuf := bufPtr
			resume := resumeCh
			softLimit := h.bpSoftLimit
			writeSize := n

			// Buffer ownership transfers to gnet until callback fires
			ctx.addSplicePendingBytes(writeSize)
			err := clientConn.AsyncWrite(buf[:n], func(c gnet.Conn, _ error) error {
				spliceReadBufPool.Put(poolBuf)
				// This callback runs on the owning event loop. Its buffer read is
				// only a flow-control snapshot, never a flush-completion signal.
				buffered := ctx.completeSpliceWrite(writeSize, c.OutboundBuffered())
				if buffered < softLimit {
					select {
					case resume <- struct{}{}:
					default:
						// Channel full, already signaled
					}
				}
				return nil
			})
			if err != nil {
				ctx.cancelSplicePendingBytes(writeSize)
				spliceReadBufPool.Put(bufPtr)
				clientConn.Close()
				return
			}
		} else {
			spliceReadBufPool.Put(bufPtr)
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				h.beginSpliceClientDrain(clientConn, ctx, idleTimeout)
			} else {
				clientConn.Close()
			}
			return
		}
	}
}

func (h *ProxyHandler) sampleSpliceBuffer(clientConn gnet.Conn, ctx *ConnContext) {
	_ = clientConn.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		buffered := ctx.updateSpliceOutboundBytes(clientConn.OutboundBuffered())
		if buffered < h.bpSoftLimit {
			select {
			case ctx.spliceResume <- struct{}{}:
			default:
			}
		}
		return nil
	}))
}

func (ctx *ConnContext) spliceBufferedBytes() int {
	ctx.spliceFlowMu.Lock()
	defer ctx.spliceFlowMu.Unlock()
	return ctx.splicePendingBytes + ctx.spliceOutboundBytes
}

func (ctx *ConnContext) addSplicePendingBytes(n int) {
	ctx.spliceFlowMu.Lock()
	ctx.splicePendingBytes += n
	ctx.spliceFlowMu.Unlock()
}

func (ctx *ConnContext) cancelSplicePendingBytes(n int) {
	ctx.spliceFlowMu.Lock()
	ctx.splicePendingBytes -= n
	ctx.spliceFlowMu.Unlock()
}

func (ctx *ConnContext) completeSpliceWrite(n, outbound int) int {
	ctx.spliceFlowMu.Lock()
	ctx.splicePendingBytes -= n
	ctx.spliceOutboundBytes = outbound
	buffered := ctx.splicePendingBytes + ctx.spliceOutboundBytes
	ctx.spliceFlowMu.Unlock()
	return buffered
}

func (ctx *ConnContext) updateSpliceOutboundBytes(outbound int) int {
	ctx.spliceFlowMu.Lock()
	ctx.spliceOutboundBytes = outbound
	buffered := ctx.splicePendingBytes + ctx.spliceOutboundBytes
	ctx.spliceFlowMu.Unlock()
	return buffered
}

// beginSpliceClientDrain transfers a clean upstream EOF to the client event
// loop. AsyncWrite uses gnet's high-priority queue while Execute uses the
// low-priority queue, so this runnable observes every write submitted before
// the EOF. Only the event loop decides when the outbound buffer is empty.
func (h *ProxyHandler) beginSpliceClientDrain(clientConn gnet.Conn, ctx *ConnContext, timeout time.Duration) {
	ctx.spliceDrainRequested.Store(true)
	err := clientConn.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		if ctx.State() == StateClosed {
			return nil
		}
		ctx.beginSpliceDrain(clientConn, timeout)
		if h.handleSpliceDrain(clientConn, ctx) == gnet.Close {
			return clientConn.EventLoop().Close(clientConn)
		}
		return nil
	}))
	if err != nil {
		ctx.spliceDrainRequested.Store(false)
		clientConn.Close()
	}
}

func (ctx *ConnContext) beginSpliceDrain(clientConn gnet.Conn, timeout time.Duration) {
	ctx.spliceDrainMu.Lock()
	defer ctx.spliceDrainMu.Unlock()
	if ctx.spliceDraining {
		return
	}
	ctx.spliceDraining = true
	ctx.spliceDrainID++
	id := ctx.spliceDrainID
	ctx.spliceDrainDeadline = time.AfterFunc(timeout, func() {
		err := clientConn.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
			ctx.spliceDrainMu.Lock()
			if !ctx.spliceDraining || ctx.spliceDrainID != id {
				ctx.spliceDrainMu.Unlock()
				return nil
			}
			ctx.finishSpliceDrainLocked()
			ctx.spliceDrainMu.Unlock()
			return clientConn.EventLoop().Close(clientConn)
		}))
		if err != nil && ctx.State() != StateClosed {
			clientConn.Close()
		}
	})
}

func (ctx *ConnContext) isSpliceDraining() bool {
	ctx.spliceDrainMu.Lock()
	defer ctx.spliceDrainMu.Unlock()
	return ctx.spliceDraining
}

func (ctx *ConnContext) armSpliceDrainWake(clientConn gnet.Conn) {
	ctx.spliceDrainMu.Lock()
	if !ctx.spliceDraining || ctx.spliceDrainWake != nil {
		ctx.spliceDrainMu.Unlock()
		return
	}
	id := ctx.spliceDrainID
	ctx.spliceDrainWake = time.AfterFunc(spliceDrainCheckInterval, func() {
		ctx.spliceDrainMu.Lock()
		if !ctx.spliceDraining || ctx.spliceDrainID != id {
			ctx.spliceDrainMu.Unlock()
			return
		}
		ctx.spliceDrainWake = nil
		ctx.spliceDrainMu.Unlock()
		_ = clientConn.Wake(nil)
	})
	ctx.spliceDrainMu.Unlock()
}

func (ctx *ConnContext) finishSpliceDrain() {
	ctx.spliceDrainMu.Lock()
	ctx.finishSpliceDrainLocked()
	ctx.spliceDrainMu.Unlock()
}

func (ctx *ConnContext) finishSpliceDrainLocked() {
	ctx.spliceDraining = false
	ctx.spliceDrainRequested.Store(false)
	ctx.spliceDrainID++
	if ctx.spliceDrainDeadline != nil {
		ctx.spliceDrainDeadline.Stop()
		ctx.spliceDrainDeadline = nil
	}
	if ctx.spliceDrainWake != nil {
		ctx.spliceDrainWake.Stop()
		ctx.spliceDrainWake = nil
	}
}

func (ctx *ConnContext) cancelSpliceDrain() {
	ctx.finishSpliceDrain()
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
	return fmt.Appendf(nil, "PROXY %s %s %s %d %d\r\n",
		proto, src.IP.String(), dst.IP.String(), src.Port, dst.Port)
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

// filterAddrs filters addresses by IP version.
func filterAddrs(addrs []dc.Addr, wantIPv6 bool) []dc.Addr {
	filtered := make([]dc.Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.IsIPv6() == wantIPv6 {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// sortAddrsByPreference reorders addresses to prefer IPv4 or IPv6.
// Preferred family comes first, maintaining relative RTT order within each group.
func sortAddrsByPreference(addrs []dc.Addr, preferIPv6 bool) []dc.Addr {
	var preferred, other []dc.Addr
	for _, a := range addrs {
		if a.IsIPv6() == preferIPv6 {
			preferred = append(preferred, a)
		} else {
			other = append(other, a)
		}
	}
	return append(preferred, other...)
}
