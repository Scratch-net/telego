package gproxy

import (
	"encoding/binary"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// handleTLSHeader reads and validates the TLS record header (5 bytes).
func (h *ProxyHandler) handleTLSHeader(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(-1)
	if len(data) < faketls.RecordHeaderSize {
		// Need more data
		return gnet.None
	}

	// Check if this is a TLS handshake record
	if data[0] != faketls.RecordTypeHandshake {
		h.logger.Debug("not a TLS handshake record: 0x%02x", data[0])
		return h.startSplice(c, ctx)
	}

	// Validate TLS version (should be TLS 1.0 for ClientHello record header)
	version := binary.BigEndian.Uint16(data[1:3])
	if version != faketls.VersionTLS10 && version != faketls.VersionTLS11 && version != faketls.VersionTLS12 {
		h.logger.Debug("invalid TLS version: 0x%04x", version)
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
		h.logger.Debug("no matching secret found")
		return h.startSplice(c, ctx)
	}

	// Check replay
	if h.replayCache.Seen(hello.SessionID) {
		h.logger.Debug("replay attack detected")
		return h.startSplice(c, ctx)
	}

	// Discard the TLS record from buffer
	c.Discard(needed)

	// Store client hello and matched secret
	ctx.mu.Lock()
	ctx.clientHello = hello
	ctx.secret = matchedSecret
	ctx.mu.Unlock()

	h.logger.Debug("client matched secret %q", matchedSecret.Name)

	// Build ServerHello response
	var response []byte
	if h.certFetcher != nil {
		cachedCert, err := h.certFetcher.FetchCert(h.config.CertHost, h.config.CertPort)
		if err == nil && cachedCert != nil && len(cachedCert.RawChain) > 0 {
			opts := &faketls.ServerHelloOptions{
				CertChain: cachedCert.GetRawCertChain(),
			}
			response, err = faketls.BuildServerHelloWithOptions(matchedSecret.Key, hello, opts)
			if err != nil {
				h.logger.Debug("BuildServerHelloWithOptions failed: %v", err)
				return gnet.Close
			}
		} else {
			response, err = faketls.BuildServerHello(matchedSecret.Key, hello)
			if err != nil {
				h.logger.Debug("BuildServerHello failed: %v", err)
				return gnet.Close
			}
		}
	} else {
		var err error
		response, err = faketls.BuildServerHello(matchedSecret.Key, hello)
		if err != nil {
			h.logger.Debug("BuildServerHello failed: %v", err)
			return gnet.Close
		}
	}

	// Send ServerHello asynchronously
	c.AsyncWrite(response, nil)

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
				return gnet.Close
			}

			// Get matched secret from context
			ctx.mu.Lock()
			secret := ctx.secret
			ctx.mu.Unlock()

			if secret == nil {
				h.logger.Debug("no secret in context")
				return gnet.Close
			}

			// Parse obfuscated2 handshake frame
			dcID, encryptor, decryptor, err := obfuscated2.ParseClientFrame(secret.Key, payload[:obfuscated2.FrameSize])
			if err != nil {
				h.logger.Debug("ParseClientFrame failed: %v", err)
				return gnet.Close
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
			ctx.encryptor = encryptor
			ctx.decryptor = decryptor
			ctx.pendingData = pendingData
			ctx.mu.Unlock()
			ctx.SetState(StateDialingDC)

			h.logger.Info("[%s] connecting to DC %d", secret.Name, dcID)

			// Clear handshake deadline, set idle timeout
			c.SetReadDeadline(time.Time{})
			if h.config.IdleTimeout > 0 {
				c.SetReadDeadline(time.Now().Add(h.config.IdleTimeout))
			}

			// Dial DC asynchronously
			go h.dialDC(c, ctx)

			return gnet.None
		}

		// Unknown record type - close connection
		h.logger.Debug("Unexpected record type 0x%02x while waiting for O2 frame", recordType)
		return gnet.Close
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
		h.logger.Debug("no splice host configured, closing")
		return gnet.Close
	}

	ctx.SetState(StateSplicing)

	h.logger.Debug("splicing to %s:%d", h.config.SpliceHost, h.config.SplicePort)

	// Dial mask host asynchronously
	go h.dialSplice(c, ctx)

	return gnet.None
}

// handleSplice forwards data to the splice target.
func (h *ProxyHandler) handleSplice(c gnet.Conn, ctx *ConnContext) gnet.Action {
	// Lock-free read of splice connection
	spliceConn := ctx.SpliceConn()
	if spliceConn == nil {
		// Still waiting for splice connection
		return gnet.None
	}

	// Read all available data
	data, _ := c.Next(-1)
	if len(data) == 0 {
		return gnet.None
	}

	// Forward to splice target
	if _, err := spliceConn.Write(data); err != nil {
		return gnet.Close
	}

	return gnet.None
}
