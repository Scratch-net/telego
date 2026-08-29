package gproxy

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// handleDetectProtocol detects whether the client is using ee (TLS) or dd (raw) mode.
// TLS traffic starts with 0x16 (handshake record type).
func (h *ProxyHandler) handleDetectProtocol(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(5)
	if len(data) < 5 {
		// Need at least 5 bytes to detect protocol
		return gnet.None
	}

	// Check for TLS handshake record: type=0x16, version=0x0301/0x0302/0x0303
	if data[0] == faketls.RecordTypeHandshake {
		version := binary.BigEndian.Uint16(data[1:3])
		if version == faketls.VersionTLS10 || version == faketls.VersionTLS11 || version == faketls.VersionTLS12 {
			// TLS traffic -> ee mode
			ctx.SetProtocolMode(ModeEE)
			ctx.SetState(StateReadTLSHeader)
			h.logger.Debug("[#%d] detected ee mode (TLS)", ctx.id)
			return h.handleTLSHeader(c, ctx)
		}
	}

	// Non-TLS traffic -> dd mode (raw obfuscated2)
	ctx.SetProtocolMode(ModeDD)
	ctx.SetState(StateReadDDFrame)
	h.logger.Debug("[#%d] detected dd mode (raw)", ctx.id)
	return h.handleDDFrame(c, ctx)
}

// handleDDFrame parses the raw obfuscated2 handshake frame (DD mode).
// In DD mode, the 64-byte O2 frame comes directly without TLS wrapping.
func (h *ProxyHandler) handleDDFrame(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(-1)
	if len(data) < obfuscated2.FrameSize {
		// Need more data
		return gnet.None
	}

	// Try each secret until one matches
	var dcID int
	var connectionType obfuscated2.ConnectionType
	var encryptor, decryptor cipher.Stream
	var matchedSecret *Secret
	var err error

	for i := range h.config.Secrets {
		s := &h.config.Secrets[i]
		dcID, connectionType, encryptor, decryptor, err = obfuscated2.ParseClientFrameWithType(s.Key, data[:obfuscated2.FrameSize])
		if err == nil {
			matchedSecret = s
			break
		}
	}

	if matchedSecret == nil {
		h.logger.Debug("[#%d] dd mode: no matching secret found", ctx.id)
		return h.startSplice(c, ctx)
	}

	// Check replay using first 32 bytes of frame as session ID
	sessionID := data[:32]
	if h.replayCache.Seen(sessionID) {
		h.logger.Debug("[#%d] dd mode: replay attack detected", ctx.id)
		return h.startSplice(c, ctx)
	}

	// Discard the frame from buffer
	c.Discard(obfuscated2.FrameSize)

	// Store matched secret
	ctx.mu.Lock()
	ctx.secret = matchedSecret
	ctx.mu.Unlock()

	// Get client IP for limiter checks
	clientAddr := ctx.RealClientAddr(c.RemoteAddr())
	var clientIP net.IP
	if tcpAddr, ok := clientAddr.(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP
	} else if host, _, err := net.SplitHostPort(clientAddr.String()); err == nil {
		clientIP = net.ParseIP(host)
	}

	// Check connection limit per IP (if enabled)
	if h.connLimiter != nil && clientIP != nil {
		key, ok := h.connLimiter.TryAcquire(clientIP, matchedSecret.Key)
		if !ok {
			h.logger.Info("[#%d:%s] connection limit exceeded for IP: %s", ctx.id, matchedSecret.Name, clientIP)
			return h.failHandshake(ctx, handshakeFailureAdmission)
		}
		ctx.mu.Lock()
		ctx.connLimitTracked = true
		ctx.connLimitKey = key
		ctx.mu.Unlock()
	}

	// Check user IP limit and track stats
	if h.userLimiter != nil && clientIP != nil {
		key, ok := h.userLimiter.TryAcquire(clientIP, matchedSecret.Key, matchedSecret.Name)
		if !ok {
			// Release conn limiter slot if acquired
			if h.connLimiter != nil {
				ctx.mu.Lock()
				if ctx.connLimitTracked {
					h.connLimiter.Release(ctx.connLimitKey)
					ctx.connLimitTracked = false
				}
				ctx.mu.Unlock()
			}
			h.logger.Info("[#%d:%s] IP blocked for user (too many unique IPs): %s", ctx.id, matchedSecret.Name, clientIP)
			return h.failHandshake(ctx, handshakeFailureAdmission)
		}
		// Store tracking info for cleanup in OnClose
		ctx.mu.Lock()
		ctx.limitTracked = true
		ctx.limitKey = key
		ctx.mu.Unlock()

		// Store traffic counter pointers for hot-path counting
		bytesIn, bytesOut := h.userLimiter.TrafficCounters(matchedSecret.Key)
		ctx.SetTrafficCounters(bytesIn, bytesOut)
	}

	// The authenticated direct-only client must leave the handshake states
	// before a potentially blocking logger runs. Middle-End remains precommit
	// until exact Bind succeeds below.
	if h.middleEnd == nil {
		ctx.SetState(StateDialingDC)
	}
	h.logger.Debug("[#%d] dd mode: matched secret %q, DC %d", ctx.id, matchedSecret.Name, dcID)

	// Store ciphers and DC ID
	ctx.mu.Lock()
	ctx.dcID = dcID
	ctx.o2ConnectionType = connectionType
	ctx.encryptor = encryptor
	ctx.decryptor = decryptor
	ctx.mu.Unlock()
	return h.commitAuthenticatedRoute(c, ctx)
}

// handleTLSHeader reads and validates the TLS record header (5 bytes).
func (h *ProxyHandler) handleTLSHeader(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		// Need more data
		return gnet.None
	}

	// Check if this is a TLS handshake record
	if data[0] != faketls.RecordTypeHandshake {
		h.logger.Debug("[#%d] not a TLS handshake record: 0x%02x", ctx.id, data[0])
		return h.startSplice(c, ctx)
	}

	// Validate TLS version (should be TLS 1.0 for ClientHello record header)
	version := binary.BigEndian.Uint16(data[1:3])
	if version != faketls.VersionTLS10 && version != faketls.VersionTLS11 && version != faketls.VersionTLS12 {
		h.logger.Debug("[#%d] invalid TLS version: 0x%04x", ctx.id, version)
		return h.startSplice(c, ctx)
	}

	// Extract payload length
	payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
	if payloadLen > faketls.MaxRecordPayload {
		h.logger.Debug("TLS record too large: %d", payloadLen)
		return h.startSplice(c, ctx)
	}

	ctx.mu.Lock()
	ctx.tlsPayloadLen = payloadLen
	ctx.mu.Unlock()
	ctx.SetState(StateReadTLSPayload)

	// Check if we already have the full record
	if len(data) >= faketls.RecordHeaderSize+payloadLen {
		return h.handleTLSPayload(c, ctx)
	}

	return gnet.None
}

// handleTLSPayload parses the ClientHello and sends ServerHello.
func (h *ProxyHandler) handleTLSPayload(c gnet.Conn, ctx *ConnContext) gnet.Action {
	ctx.mu.Lock()
	payloadLen := ctx.tlsPayloadLen
	ctx.mu.Unlock()

	needed := faketls.RecordHeaderSize + payloadLen
	data, _ := c.Peek(-1)
	if len(data) < needed {
		// Need more data
		return gnet.None
	}

	// Extract payload (skip 5-byte header)
	payload := data[faketls.RecordHeaderSize:needed]

	// Try each secret until one matches
	var hello *faketls.ClientHello
	var matchedSecret *Secret
	for i := range h.config.Secrets {
		s := &h.config.Secrets[i]
		parsed, err := faketls.ParseClientHello(s.Key, payload)
		if err != nil {
			continue
		}
		// Validate against this secret's hostname
		if err := parsed.Valid(s.Host, h.config.TimeSkewTolerance); err != nil {
			continue
		}
		hello = parsed
		matchedSecret = s
		break
	}

	if hello == nil {
		// Log diagnostic info to help troubleshoot
		var hexDump strings.Builder
		for i := 0; i < 20 && i < len(payload); i++ {
			fmt.Fprintf(&hexDump, "%02x ", payload[i])
		}
		h.logger.Debug("[#%d] no matching secret found (payload len=%d, first bytes: %s)", ctx.id, len(payload), hexDump.String())

		// SNI-following: if this probe's claimed SNI is on the mask safelist,
		// front it to that domain's own server instead of the default target.
		if len(h.maskSafelist) > 0 {
			if sni := faketls.ExtractSNI(payload); sni != "" {
				if target, ok := h.maskSafelist[strings.ToLower(sni)]; ok {
					ctx.SetSpliceOverride(target)
					h.logger.Debug("[#%d] SNI %q safelisted, fronting to %s", ctx.id, sni, target)
				}
			}
		}
		return h.startSplice(c, ctx)
	}

	// Check replay
	if h.replayCache.Seen(hello.SessionID) {
		h.logger.Debug("[#%d] replay attack detected", ctx.id)
		return h.startSplice(c, ctx)
	}

	// Discard the TLS record from buffer
	c.Discard(needed)

	// Store client hello and matched secret
	ctx.mu.Lock()
	ctx.clientHello = hello
	ctx.secret = matchedSecret
	ctx.mu.Unlock()

	// Get client IP for limiter checks
	clientAddr := ctx.RealClientAddr(c.RemoteAddr())
	var clientIP net.IP
	if tcpAddr, ok := clientAddr.(*net.TCPAddr); ok {
		clientIP = tcpAddr.IP
	} else if host, _, err := net.SplitHostPort(clientAddr.String()); err == nil {
		clientIP = net.ParseIP(host)
	}

	// Check connection limit per IP (if enabled)
	if h.connLimiter != nil && clientIP != nil {
		key, ok := h.connLimiter.TryAcquire(clientIP, matchedSecret.Key)
		if !ok {
			h.logger.Info("[#%d:%s] connection limit exceeded for IP: %s", ctx.id, matchedSecret.Name, clientIP)
			return h.failHandshake(ctx, handshakeFailureAdmission)
		}
		ctx.mu.Lock()
		ctx.connLimitTracked = true
		ctx.connLimitKey = key
		ctx.mu.Unlock()
	}

	// Check user IP limit and track stats
	if h.userLimiter != nil && clientIP != nil {
		key, ok := h.userLimiter.TryAcquire(clientIP, matchedSecret.Key, matchedSecret.Name)
		if !ok {
			// Release conn limiter slot if acquired
			if h.connLimiter != nil {
				ctx.mu.Lock()
				if ctx.connLimitTracked {
					h.connLimiter.Release(ctx.connLimitKey)
					ctx.connLimitTracked = false
				}
				ctx.mu.Unlock()
			}
			h.logger.Info("[#%d:%s] IP blocked for user (too many unique IPs): %s", ctx.id, matchedSecret.Name, clientIP)
			return h.failHandshake(ctx, handshakeFailureAdmission)
		}
		// Store tracking info for cleanup in OnClose
		ctx.mu.Lock()
		ctx.limitTracked = true
		ctx.limitKey = key
		ctx.mu.Unlock()

		// Store traffic counter pointers for hot-path counting
		bytesIn, bytesOut := h.userLimiter.TrafficCounters(matchedSecret.Key)
		ctx.SetTrafficCounters(bytesIn, bytesOut)
	}

	h.logger.Debug("[#%d] matched secret %q", ctx.id, matchedSecret.Name)

	// Build ServerHello response
	var response []byte
	var err error

	// HYBRID MODE: Use real ServerHello from mask host (best DPI evasion)
	if h.serverHelloFetcher != nil {
		realHello, randomOffset, fetchErr := h.serverHelloFetcher.GetServerHelloTemplate()
		if fetchErr == nil && len(realHello) > 0 {
			// Size the fake cert record to match the mask backend (config override,
			// else the captured real first cert-record size) so the accept path and
			// the splice path show the same cert-record length.
			certSize := h.config.FakeCertSize
			if certSize == 0 {
				certSize = h.serverHelloFetcher.CertRecordLen()
			}
			opts := &faketls.ServerHelloOptions{
				RealServerHello:             realHello,
				RealServerHelloRandomOffset: randomOffset,
				FakeCertSize:                certSize,
			}
			response, err = faketls.BuildServerHelloWithOptions(matchedSecret.Key, hello, opts)
			if err != nil {
				h.logger.Debug("BuildServerHelloWithOptions (hybrid) failed: %v", err)
				return h.failHandshake(ctx, handshakeFailureTLSServerHello)
			}
			h.logger.Debug("[#%d] using hybrid ServerHello (real TLS fingerprint)", ctx.id)
		} else {
			h.logger.Debug("[#%d] hybrid ServerHello fetch failed: %v, falling back", ctx.id, fetchErr)
		}
	}

	// LEGACY MODE: Synthetic ServerHello with optional real cert embedding
	if response == nil {
		if h.certFetcher != nil {
			cachedCert, certErr := h.certFetcher.FetchCert(h.config.CertHost, h.config.CertPort)
			if certErr == nil && cachedCert != nil && len(cachedCert.RawChain) > 0 {
				opts := &faketls.ServerHelloOptions{
					CertChain: cachedCert.GetRawCertChain(),
				}
				response, err = faketls.BuildServerHelloWithOptions(matchedSecret.Key, hello, opts)
			} else {
				response, err = faketls.BuildServerHello(matchedSecret.Key, hello)
			}
		} else {
			response, err = faketls.BuildServerHello(matchedSecret.Key, hello)
		}
		if err != nil {
			h.logger.Debug("BuildServerHello failed: %v", err)
			return h.failHandshake(ctx, handshakeFailureTLSServerHello)
		}
	}

	// Send ServerHello - Write() is safe here since we're in EventHandler
	c.Write(response)

	// Transition to reading obfuscated2 frame
	ctx.SetState(StateReadO2Frame)

	// Check if we already have data for the next state
	data, _ = c.Peek(-1)
	if len(data) >= obfuscated2.FrameSize {
		return h.handleO2Frame(c, ctx)
	}

	return gnet.None
}

// handleO2Frame parses the obfuscated2 handshake frame and initiates DC connection.
// The O2 frame is wrapped in a TLS ApplicationData record, possibly preceded by ChangeCipherSpec.
func (h *ProxyHandler) handleO2Frame(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(-1)

	// Skip any ChangeCipherSpec records (0x14) that precede the ApplicationData
	consumed := 0
	for len(data) >= faketls.RecordHeaderSize {
		recordType := data[0]
		payloadLen := int(binary.BigEndian.Uint16(data[3:5]))
		recordLen := faketls.RecordHeaderSize + payloadLen

		if recordType == faketls.RecordTypeChangeCipherSpec {
			// Skip ChangeCipherSpec record
			if len(data) < recordLen {
				// Need more data to skip the full record
				if consumed > 0 {
					c.Discard(consumed)
				}
				return gnet.None
			}
			consumed += recordLen
			data = data[recordLen:]
			continue
		}

		if recordType == faketls.RecordTypeApplicationData {
			// Found ApplicationData - this contains the O2 frame
			if len(data) < recordLen {
				// Need more data
				if consumed > 0 {
					c.Discard(consumed)
				}
				return gnet.None
			}

			// Extract payload (the obfuscated2 frame) from TLS record
			payload := data[faketls.RecordHeaderSize:recordLen]

			if len(payload) < obfuscated2.FrameSize {
				h.logger.Debug("O2 frame too short: %d bytes", len(payload))
				return h.failHandshake(ctx, handshakeFailureTLSMTProto)
			}

			// Get matched secret from context
			ctx.mu.Lock()
			secret := ctx.secret
			ctx.mu.Unlock()

			if secret == nil {
				h.logger.Debug("no secret in context")
				return h.failHandshake(ctx, handshakeFailureTLSMTProto)
			}

			// Parse obfuscated2 handshake frame
			dcID, connectionType, encryptor, decryptor, err := obfuscated2.ParseClientFrameWithType(secret.Key, payload[:obfuscated2.FrameSize])
			if err != nil {
				h.logger.Debug("ParseClientFrame failed: %v", err)
				return h.failHandshake(ctx, handshakeFailureTLSMTProto)
			}

			// Check for extra data after the O2 frame in the same TLS record
			var pendingData []byte
			if len(payload) > obfuscated2.FrameSize {
				extraData := payload[obfuscated2.FrameSize:]
				pendingData = make([]byte, len(extraData))
				copy(pendingData, extraData)
			}

			// Discard all consumed records plus this one
			c.Discard(consumed + recordLen)

			// Store ciphers and DC ID
			ctx.mu.Lock()
			ctx.dcID = dcID
			ctx.o2ConnectionType = connectionType
			ctx.encryptor = encryptor
			ctx.decryptor = decryptor
			ctx.pendingData = pendingData
			ctx.mu.Unlock()

			// Preserve the direct-only ordering: the authenticated connection is
			// no longer in a handshake state before a potentially blocking logger
			// runs. The Middle-End branch remains precommit until exact Bind wins.
			if h.middleEnd == nil {
				ctx.SetState(StateDialingDC)
			}
			h.logger.Debug("[#%d:%s] dialing DC %d", ctx.id, secret.Name, dcID)
			return h.commitAuthenticatedRoute(c, ctx)
		}

		// Unknown record type - close connection
		h.logger.Debug("Unexpected record type 0x%02x while waiting for O2 frame", recordType)
		return h.failHandshake(ctx, handshakeFailureTLSMTProto)
	}

	// Need more data
	if consumed > 0 {
		c.Discard(consumed)
	}
	return gnet.None
}

// startSplice transitions to splice mode for unrecognized clients.
func (h *ProxyHandler) startSplice(c gnet.Conn, ctx *ConnContext) gnet.Action {
	if h.config.SpliceHost == "" {
		h.logger.Debug("[#%d] no splice host configured, closing", ctx.id)
		return h.failHandshake(ctx, handshakeStageForState(ctx.State()))
	}

	ctx.SetState(StateSplicing)

	// Clear handshake deadline, set splice idle timeout
	spliceTimeout := h.config.SpliceIdleTimeout
	if spliceTimeout <= 0 {
		spliceTimeout = 30 * time.Second
	}
	c.SetReadDeadline(time.Now().Add(spliceTimeout))

	h.logger.Debug("[#%d] splicing to %s:%d", ctx.id, h.config.SpliceHost, h.config.SplicePort)

	// Dial mask host asynchronously
	go h.dialSplice(c, ctx)

	return gnet.None
}

// handleSplice forwards data to the splice target.
func (h *ProxyHandler) handleSplice(c gnet.Conn, ctx *ConnContext) gnet.Action {
	if ctx.spliceDrainRequested.Load() {
		return h.handleSpliceDrain(c, ctx)
	}

	// Lock-free read of splice connection
	spliceConn := ctx.SpliceConn()
	if spliceConn == nil {
		// Still waiting for splice connection
		return gnet.None
	}

	// Peek data first - don't consume until write succeeds
	data, _ := c.Peek(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Forward to splice target
	n, err := spliceConn.Write(data)
	if n > 0 {
		// Discard only what was successfully written
		c.Discard(n)
	}
	if err != nil {
		return gnet.Close
	}

	return gnet.None
}

// handleSpliceDrain runs only on the client connection's event loop. A wake
// timer keeps checking until gnet has flushed every queued upstream byte.
func (h *ProxyHandler) handleSpliceDrain(c gnet.Conn, ctx *ConnContext) gnet.Action {
	if buffered := c.InboundBuffered(); buffered > 0 {
		_, _ = c.Discard(buffered)
	}
	if !ctx.isSpliceDraining() {
		return gnet.None
	}
	if c.OutboundBuffered() != 0 {
		ctx.armSpliceDrainWake(c)
		return gnet.None
	}
	ctx.finishSpliceDrain()
	return gnet.Close
}
