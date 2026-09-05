package gproxy

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/netx"
	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// dialDC establishes a direct connection to the Telegram DC.
func (h *ProxyHandler) dialDC(clientConn clientEndpoint, ctx *ConnContext) {
	dialContext, cancelDial := context.WithCancel(h.upstreamContext)
	defer cancelDial()
	// Read all needed state under mutex.
	// Cleanup() also uses this mutex when nilling ciphers.
	// Mutex guarantees: either we read valid values (Cleanup hasn't run),
	// or we read nil (Cleanup already ran). No in-between state possible.
	ctx.mu.Lock()
	if ctx.State() == StateClosed {
		ctx.mu.Unlock()
		return
	}
	ctx.directDialCancel = cancelDial
	dcID := ctx.dcID
	connectionType := ctx.o2ConnectionType
	userName := ""
	if ctx.secret != nil {
		userName = ctx.secret.Name
	}
	clientEncryptor := ctx.encryptor
	clientDecryptor := ctx.decryptor
	ctx.mu.Unlock()
	defer func() { ctx.mu.Lock(); ctx.directDialCancel = nil; ctx.mu.Unlock() }()

	// If Cleanup() ran before we acquired the lock, ciphers are nil.
	// If we acquired first, we have valid copies that Cleanup() can't affect.
	if clientEncryptor == nil || clientDecryptor == nil {
		return
	}

	// Direct DC connection (simple, reliable)
	ddc, err := h.directDCDial(dialContext, dcID, connectionType)
	if err != nil {
		if h.upstreamContext.Err() != nil {
			_ = clientConn.Close()
		}
		if ctx.State() == StateClosed || dialContext.Err() != nil {
			return
		}
		h.logger.Debug("[#%d:%s] failed to dial DC %d: %v", ctx.id, userName, dcID, err)
		h.recordHandshakeFailure(ctx, handshakeFailureBackendDial)
		clientConn.Close()
		return
	}
	stopCancellation := context.AfterFunc(dialContext, func() { _ = ddc.Close() })
	defer stopCancellation()

	// Optimization: skip setup if client closed during slow dial.
	// Not required for correctness - handleDCTraffic would detect StateClosed anyway.
	if ctx.State() == StateClosed || dialContext.Err() != nil {
		ddc.Close()
		_ = clientConn.Close()
		return
	}

	// Context and downlink ciphers are installed before enrollment makes the
	// socket visible to its loop. OnOpen initializes owner-only DC state.
	dcCtx := &DCConnContext{
		ClientConn:    clientConn,
		ClientCtx:     ctx,
		DCEncrypt:     ddc.encryptor,
		DCDecrypt:     ddc.decryptor,
		ClientEncrypt: clientEncryptor,
		onClosed:      retainLogicalWork(clientConn),
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

	dcGnetConn, err := h.dcClient.EnrollContext(ddc.Conn, dcCtx)
	if err != nil {
		dcCtx.onClosed()
		if h.upstreamContext.Err() != nil {
			_ = clientConn.Close()
		}
		if ctx.State() == StateClosed || dialContext.Err() != nil {
			_ = ddc.Close()
			return
		}
		h.logger.Debug("[#%d:%s] failed to enroll DC connection: %v", ctx.id, userName, err)
		h.recordHandshakeFailure(ctx, handshakeFailureBackendDial)
		ddc.Close()
		clientConn.Close()
		return
	}

	// Build relay context for client -> DC direction
	relay := &RelayContext{
		Encryptor: clientEncryptor,
		Decryptor: clientDecryptor,
		DCConn:    dcGnetConn,
		DCEncrypt: ddc.encryptor,
		DCDecrypt: ddc.decryptor,
		ToDC:      dcCtx.ToDC,
	}

	// The client loop owns both uplink ciphers. Flush handshake leftovers on
	// that same loop before publishing StateRelaying so newer bytes cannot
	// overtake them or advance either cipher concurrently.
	err = executeClient(clientConn, gnet.RunnableFunc(func(context.Context) error {
		if ctx.State() == StateClosed || dcCtx.closed.Load() {
			_ = dcGnetConn.Close()
			return nil
		}
		// Native gnet address storage is released on this owner at close.
		clientAddr := ctx.RealClientAddr(clientConn.RemoteAddr())
		h.logger.Info("[#%d:%s] %s -> DC %d", ctx.id, userName, clientAddr, dcID)
		dcCtx.ToClient = newRelayOutput(clientConn, dcGnetConn, ctx, h.maxWriteBuffer)
		dcCtx.ToClient.buffered = clientConn.OutboundBuffered()
		ctx.mu.Lock()
		pendingData, pendingRelease := ctx.pendingData, ctx.pendingDataRelease
		ctx.pendingData, ctx.pendingDataRelease = nil, nil
		ctx.mu.Unlock()
		if pendingRelease != nil {
			defer pendingRelease()
		}
		defer clear(pendingData)
		if len(pendingData) > 0 {
			if err := h.sendPendingDataGnet(relay, pendingData); err != nil {
				dcCtx.ToClient.close()
				_ = dcGnetConn.Close()
				_ = clientConn.Close()
				return nil
			}
			ctx.recordClientActivity()
			if counter := ctx.TrafficIn(); counter != nil {
				counter.Add(int64(len(pendingData)))
			}
		}
		ctx.SetRelay(relay)
		dcCtx.active.Store(true)
		if h.clientSilenceCloseMs > 0 {
			h.relayConns.Store(ctx.id, &relayEntry{conn: clientConn, ctx: ctx})
		}
		if err := dcGnetConn.Wake(nil); err != nil {
			_ = clientConn.Close()
		}
		if err := wakeClient(clientConn); err != nil {
			_ = dcGnetConn.Close()
		}
		return nil
	}))
	if err != nil {
		_ = dcGnetConn.Close()
		_ = clientConn.Close()
	}
}

// dialDirectDC connects directly to Telegram DC with obfuscated2 handshake.
func (h *ProxyHandler) dialDirectDC(ctx context.Context, dcID int, connectionType obfuscated2.ConnectionType) (*directDCConn, error) {
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
	var dialFunc func(context.Context, string, string) (netx.Conn, error)
	if h.config.Socks5Addr != "" {
		socks5Dialer, err := netx.NewSocks5Dialer(h.config.Socks5Addr)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		dialFunc = socks5Dialer.DialContext
	} else {
		dialer := netx.NewDialer()
		dialFunc = dialer.DialContext
	}

	var conn netx.Conn
	var err error
	var usedAddr dc.Addr
	dialStart := time.Now()
	for _, addr := range addrs {
		if err = ctx.Err(); err != nil {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, netx.DialTimeout)
		conn, err = dialFunc(attempt, addr.Network, addr.Address)
		cancel()
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
	stopCancellation := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancellation()
	if err := conn.SetWriteDeadline(time.Now().Add(netx.DialTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	encryptor, decryptor, err := writeDCHandshake(conn, dcID, connectionType)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
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
func (h *ProxyHandler) sendPendingDataGnet(relay *RelayContext, pendingData []byte) error {
	if relay.ToDC.reserve(len(pendingData), len(pendingData)) == 0 {
		return errors.New("pending handshake data exceeds direct output capacity")
	}
	buffer, release := h.relayBuffer(len(pendingData))
	relay.Decryptor.XORKeyStream(buffer, pendingData)
	relay.DCEncrypt.XORKeyStream(buffer, buffer)
	return relay.ToDC.write(buffer, release)
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
