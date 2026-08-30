package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"slices"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func TestProxyRequestTaggedIPv4GoldenRoundTrip(t *testing.T) {
	var tag ProxyTag
	for i := range tag {
		tag[i] = byte(i)
	}
	packet := mustDecodeHex(t,
		"0000000000000000887766554433221114000000f18e7ebe"+
			"000102030405060708090a0b0c0d0e0f",
	)
	request := ProxyRequest{
		Flags: ProxyRequestFlagNotEncrypted |
			ProxyRequestFlagHasAdTag |
			ProxyRequestFlagMagic |
			ProxyRequestFlagExternalMode2 |
			ProxyRequestFlagAbridged |
			ProxyRequestFlagQuickAck,
		ConnectionID: 0x0102030405060708,
		RemoteAddr:   netip.MustParseAddrPort("192.0.2.10:54321"),
		ProxyAddr:    netip.MustParseAddrPort("198.51.100.20:443"),
		Tag:          &tag,
		Packet:       packet,
	}
	want := mustDecodeHex(t,
		"eef1ce360a1002c00807060504030201"+
			"00000000000000000000ffffc000020a31d40000"+
			"00000000000000000000ffffc6336414bb010000"+
			"18000000ae261edb10000102030405060708090a0b0c0d0e0f000000"+
			"0000000000000000887766554433221114000000f18e7ebe"+
			"000102030405060708090a0b0c0d0e0f",
	)

	wire, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("proxy request = %x, want %x", wire, want)
	}

	parsed, err := ParseProxyRequest(wire)
	if err != nil {
		t.Fatalf("ParseProxyRequest: %v", err)
	}
	if parsed.Flags != request.Flags || parsed.ConnectionID != request.ConnectionID {
		t.Fatalf("parsed header = %+v, want %+v", parsed, request)
	}
	if parsed.RemoteAddr != request.RemoteAddr || parsed.ProxyAddr != request.ProxyAddr {
		t.Fatalf("parsed addresses = %s -> %s", parsed.RemoteAddr, parsed.ProxyAddr)
	}
	if parsed.Tag == nil || *parsed.Tag != tag {
		t.Fatalf("parsed tag = %v, want %x", parsed.Tag, tag)
	}
	if !bytes.Equal(parsed.Packet, packet) {
		t.Fatalf("parsed packet = %x, want %x", parsed.Packet, packet)
	}

	wire[65] ^= 0xff
	wire[len(wire)-1] ^= 0xff
	if *parsed.Tag != tag || !bytes.Equal(parsed.Packet, packet) {
		t.Fatal("parsed request aliases its wire input")
	}
}

func TestProxyRequestIPv6GoldenRoundTrip(t *testing.T) {
	var tag ProxyTag
	for i := range tag {
		tag[i] = byte(i)
	}
	packet := mustDecodeHex(t,
		"080706050403020108090a0b0c0d0e0f1011121314151617"+
			"18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
	)
	request := ProxyRequest{
		Flags: ProxyRequestFlagHasAdTag |
			ProxyRequestFlagMagic |
			ProxyRequestFlagExternalMode2 |
			ProxyRequestFlagIntermediate,
		ConnectionID: -7,
		RemoteAddr:   netip.MustParseAddrPort("[2001:db8::a]:8888"),
		ProxyAddr:    netip.MustParseAddrPort("[2001:db8:1::14]:54321"),
		Tag:          &tag,
		Packet:       packet,
	}
	want := mustDecodeHex(t,
		"eef1ce3608100220f9ffffffffffffff"+
			"20010db800000000000000000000000ab8220000"+
			"20010db800010000000000000000001431d40000"+
			"18000000ae261edb10000102030405060708090a0b0c0d0e0f000000"+
			"080706050403020108090a0b0c0d0e0f1011121314151617"+
			"18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
	)

	wire, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("proxy request = %x, want %x", wire, want)
	}
	parsed, err := ParseProxyRequest(wire)
	if err != nil {
		t.Fatalf("ParseProxyRequest: %v", err)
	}
	if parsed.ConnectionID != -7 || parsed.RemoteAddr != request.RemoteAddr || parsed.ProxyAddr != request.ProxyAddr {
		t.Fatalf("parsed request = %+v", parsed)
	}
}

func TestProxyRequestOfficialWEBUnknownRemotePortRoundTrip(t *testing.T) {
	request := ProxyRequest{
		Flags:        ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagAbridged,
		ConnectionID: 9,
		RemoteAddr:   netip.MustParseAddrPort("198.51.100.7:0"),
		ProxyAddr:    netip.MustParseAddrPort("192.0.2.1:443"),
		Packet:       validEncryptedPacket(EncryptedMessageHeaderSize),
	}
	wire, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	parsed, err := ParseProxyRequest(wire)
	if err != nil {
		t.Fatalf("ParseProxyRequest: %v", err)
	}
	if parsed.RemoteAddr != request.RemoteAddr || parsed.ProxyAddr != request.ProxyAddr {
		t.Fatalf("parsed addresses = %s -> %s", parsed.RemoteAddr, parsed.ProxyAddr)
	}
}

func TestProxyRequestFlagsForClient(t *testing.T) {
	encrypted := validEncryptedPacket(EncryptedMessageHeaderSize)
	unencrypted := validUnencryptedPacket(MTProtoReqPQMultiConstructor)

	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		packet         []byte
		quickAck       bool
		hasAdTag       bool
		want           ProxyRequestFlags
	}{
		{
			name:           "abridged encrypted",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			packet:         encrypted,
			want:           ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagAbridged,
		},
		{
			name:           "intermediate unencrypted quick ack tagged",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			packet:         unencrypted,
			quickAck:       true,
			hasAdTag:       true,
			want: ProxyRequestFlagMagic |
				ProxyRequestFlagExternalMode2 |
				ProxyRequestFlagIntermediate |
				ProxyRequestFlagNotEncrypted |
				ProxyRequestFlagQuickAck |
				ProxyRequestFlagHasAdTag,
		},
		{
			name:           "padded intermediate omits frontend-local pad flag",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			packet:         encrypted,
			want:           ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagIntermediate,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ProxyRequestFlagsForClient(tc.connectionType, tc.packet, tc.quickAck, tc.hasAdTag)
			if err != nil {
				t.Fatalf("ProxyRequestFlagsForClient: %v", err)
			}
			if got != tc.want {
				t.Fatalf("flags = %08x, want %08x", uint32(got), uint32(tc.want))
			}
		})
	}

	if _, err := ProxyRequestFlagsForClient(obfuscated2.ConnectionType(1), encrypted, false, false); !errors.Is(err, ErrUnsupportedClientFraming) {
		t.Fatalf("unsupported framing error = %v, want %v", err, ErrUnsupportedClientFraming)
	}
	for _, packet := range [][]byte{nil, make([]byte, 4), make([]byte, 9)} {
		if _, err := ProxyRequestFlagsForClient(obfuscated2.ConnectionTypeAbridged, packet, false, false); !errors.Is(err, ErrInvalidMTProtoEnvelope) {
			t.Fatalf("packet length %d error = %v, want %v", len(packet), err, ErrInvalidMTProtoEnvelope)
		}
	}
}

func TestProxyRequestRejectsMalformedPayloads(t *testing.T) {
	var tag ProxyTag
	packet := validUnencryptedPacket(MTProtoReqPQConstructor)
	valid, err := (ProxyRequest{
		Flags: ProxyRequestFlagNotEncrypted |
			ProxyRequestFlagHasAdTag |
			ProxyRequestFlagMagic |
			ProxyRequestFlagExternalMode2 |
			ProxyRequestFlagAbridged,
		ConnectionID: 1,
		RemoteAddr:   netip.MustParseAddrPort("192.0.2.1:1"),
		ProxyAddr:    netip.MustParseAddrPort("198.51.100.1:65535"),
		Tag:          &tag,
		Packet:       packet,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary valid fixture: %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{
			name: "wrong operation",
			mutate: func(wire []byte) []byte {
				binary.LittleEndian.PutUint32(wire[:4], OperationProxyAnswer)
				return wire
			},
			want: ErrInvalidRPCPayload,
		},
		{
			name: "missing magic",
			mutate: func(wire []byte) []byte {
				flags := ProxyRequestFlags(binary.LittleEndian.Uint32(wire[4:8]))
				binary.LittleEndian.PutUint32(wire[4:8], uint32(flags&^ProxyRequestFlagMagic))
				return wire
			},
			want: ErrInvalidRPCFlags,
		},
		{
			name: "both transport modes",
			mutate: func(wire []byte) []byte {
				flags := ProxyRequestFlags(binary.LittleEndian.Uint32(wire[4:8]))
				binary.LittleEndian.PutUint32(wire[4:8], uint32(flags|ProxyRequestFlagIntermediate))
				return wire
			},
			want: ErrInvalidRPCFlags,
		},
		{
			name: "unsupported padding bit",
			mutate: func(wire []byte) []byte {
				flags := binary.LittleEndian.Uint32(wire[4:8]) | 0x08000000
				binary.LittleEndian.PutUint32(wire[4:8], flags)
				return wire
			},
			want: ErrInvalidRPCFlags,
		},
		{
			name: "extra section too large",
			mutate: func(wire []byte) []byte {
				binary.LittleEndian.PutUint32(wire[56:60], MaximumProxyExtraSize+4)
				return wire
			},
			want: ErrInvalidRPCPayload,
		},
		{
			name: "unexpected extra section length",
			mutate: func(wire []byte) []byte {
				binary.LittleEndian.PutUint32(wire[56:60], 20)
				return wire
			},
			want: ErrInvalidRPCPayload,
		},
		{
			name: "bad tag constructor",
			mutate: func(wire []byte) []byte {
				binary.LittleEndian.PutUint32(wire[60:64], 1)
				return wire
			},
			want: ErrInvalidTLString,
		},
		{
			name: "bad tag length",
			mutate: func(wire []byte) []byte {
				wire[64] = 15
				return wire
			},
			want: ErrInvalidTLString,
		},
		{
			name: "nonzero tag padding",
			mutate: func(wire []byte) []byte {
				wire[83] = 1
				return wire
			},
			want: ErrInvalidTLString,
		},
		{
			name: "zero proxy port",
			mutate: func(wire []byte) []byte {
				clear(wire[52:56])
				return wire
			},
			want: ErrInvalidProxyAddress,
		},
		{
			name: "out of range proxy port",
			mutate: func(wire []byte) []byte {
				binary.LittleEndian.PutUint32(wire[52:56], 65536)
				return wire
			},
			want: ErrInvalidProxyAddress,
		},
		{
			name: "not-encrypted flag mismatch",
			mutate: func(wire []byte) []byte {
				flags := ProxyRequestFlags(binary.LittleEndian.Uint32(wire[4:8]))
				binary.LittleEndian.PutUint32(wire[4:8], uint32(flags&^ProxyRequestFlagNotEncrypted))
				return wire
			},
			want: ErrInvalidRPCFlags,
		},
		{
			name: "truncated tagged header",
			mutate: func(wire []byte) []byte {
				return wire[:ProxyRequestTaggedHeaderSize-4]
			},
			want: ErrInvalidRPCPayload,
		},
		{
			name: "unaligned",
			mutate: func(wire []byte) []byte {
				return append(wire, 0)
			},
			want: ErrInvalidRPCPayload,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseProxyRequest(tc.mutate(slices.Clone(valid)))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestProxyRequestMarshalRejectsInconsistentInputs(t *testing.T) {
	base := ProxyRequest{
		Flags:        ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagAbridged,
		ConnectionID: 1,
		RemoteAddr:   netip.MustParseAddrPort("127.0.0.1:1234"),
		ProxyAddr:    netip.MustParseAddrPort("192.0.2.1:443"),
		Packet:       validEncryptedPacket(EncryptedMessageHeaderSize),
	}

	t.Run("tag without flag", func(t *testing.T) {
		request := base
		request.Tag = new(ProxyTag)
		if _, err := request.MarshalBinary(); !errors.Is(err, ErrInvalidRPCFlags) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRPCFlags)
		}
	})

	t.Run("flag without tag", func(t *testing.T) {
		request := base
		request.Flags |= ProxyRequestFlagHasAdTag
		if _, err := request.MarshalBinary(); !errors.Is(err, ErrInvalidRPCFlags) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRPCFlags)
		}
	})

	t.Run("auth key mismatch", func(t *testing.T) {
		request := base
		request.Flags |= ProxyRequestFlagNotEncrypted
		if _, err := request.MarshalBinary(); !errors.Is(err, ErrInvalidRPCFlags) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRPCFlags)
		}
	})

	t.Run("invalid address", func(t *testing.T) {
		request := base
		request.RemoteAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), 1234)
		if _, err := request.MarshalBinary(); !errors.Is(err, ErrInvalidProxyAddress) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidProxyAddress)
		}
	})

	t.Run("packet over exact tagged bound", func(t *testing.T) {
		request := base
		request.Packet = make([]byte, MaxClientPacketSize+4)
		binary.LittleEndian.PutUint64(request.Packet[:8], 1)
		if _, err := request.MarshalBinary(); !errors.Is(err, ErrClientPacketTooLarge) {
			t.Fatalf("error = %v, want %v", err, ErrClientPacketTooLarge)
		}
	})
}

func TestProxyRequestMaximumTaggedPacketFitsFullFrame(t *testing.T) {
	if got, want := MaxMEFrameSize, MaxClientPacketSize+ProxyRequestTaggedHeaderSize+FullFrameOverhead; got != want {
		t.Fatalf("local frame maximum = %d, want exact derived bound %d", got, want)
	}
	if got, want := MaxRPCPayloadSize, MaxClientPacketSize+ProxyRequestTaggedHeaderSize; got != want {
		t.Fatalf("RPC payload maximum = %d, want exact derived bound %d", got, want)
	}
	var tag ProxyTag
	packet := validEncryptedPacket(MaxClientPacketSize)
	request := ProxyRequest{
		Flags: ProxyRequestFlagHasAdTag |
			ProxyRequestFlagMagic |
			ProxyRequestFlagExternalMode2 |
			ProxyRequestFlagIntermediate,
		RemoteAddr: netip.MustParseAddrPort("127.0.0.1:1"),
		ProxyAddr:  netip.MustParseAddrPort("192.0.2.1:1"),
		Tag:        &tag,
		Packet:     packet,
	}
	payload, err := request.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary at maximum: %v", err)
	}
	if len(payload) != MaxRPCPayloadSize {
		t.Fatalf("RPC payload length = %d, want %d", len(payload), MaxRPCPayloadSize)
	}
	frame, err := EncodeFrame(0, payload, ChecksumCRC32C)
	if err != nil {
		t.Fatalf("EncodeFrame at maximum: %v", err)
	}
	if len(frame) != MaxMEFrameSize {
		t.Fatalf("full frame length = %d, want %d", len(frame), MaxMEFrameSize)
	}
}

func TestMTProtoEnvelopeValidation(t *testing.T) {
	constructors := []uint32{
		MTProtoReqPQConstructor,
		MTProtoReqPQMultiConstructor,
		MTProtoReqDHParamsConstructor,
		MTProtoSetClientDHParamsConstructor,
	}
	for _, constructor := range constructors {
		packet := validUnencryptedPacket(constructor)
		notEncrypted, err := validateMTProtoEnvelope(packet)
		if err != nil || !notEncrypted {
			t.Fatalf("constructor %08x = notEncrypted %t, error %v", constructor, notEncrypted, err)
		}
	}

	encrypted := validEncryptedPacket(EncryptedMessageHeaderSize)
	if notEncrypted, err := validateMTProtoEnvelope(encrypted); err != nil || notEncrypted {
		t.Fatalf("minimum encrypted = notEncrypted %t, error %v", notEncrypted, err)
	}

	tests := []struct {
		name   string
		packet []byte
		want   error
	}{
		{name: "encrypted below struct offset", packet: validEncryptedPacket(EncryptedMessageHeaderSize - 4), want: ErrInvalidMTProtoEnvelope},
		{name: "unaligned", packet: append(validEncryptedPacket(EncryptedMessageHeaderSize), 0), want: ErrInvalidMTProtoEnvelope},
		{name: "over official maximum", packet: validEncryptedPacket(MaxClientPacketSize + 4), want: ErrClientPacketTooLarge},
		{name: "zero auth below seven words", packet: make([]byte, 24), want: ErrInvalidMTProtoEnvelope},
		{name: "negative inner length", packet: malformedUnencryptedPacket(-1, MTProtoReqPQConstructor, 40), want: ErrInvalidMTProtoEnvelope},
		{name: "inner below official minimum", packet: malformedUnencryptedPacket(MinimumUnencryptedBodySize-4, MTProtoReqPQConstructor, 40), want: ErrInvalidMTProtoEnvelope},
		{name: "inner exceeds packet", packet: malformedUnencryptedPacket(24, MTProtoReqPQConstructor, 40), want: ErrInvalidMTProtoEnvelope},
		{name: "signed inner overflow", packet: malformedUnencryptedPacket(math.MaxInt32, MTProtoReqPQConstructor, 40), want: ErrInvalidMTProtoEnvelope},
		{name: "unsupported constructor", packet: malformedUnencryptedPacket(MinimumUnencryptedBodySize, 0x01020304, 40), want: ErrInvalidMTProtoEnvelope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateMTProtoEnvelope(tc.packet); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestProxyAnswerRoundTripAndValidation(t *testing.T) {
	packet := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	answer := ProxyAnswer{
		Flags:        ProxyAnswerFlagFlush | ProxyAnswerFlagSmallError,
		ConnectionID: -123,
		Packet:       packet,
	}
	want := mustDecodeHex(t, "0dda03441800000085ffffffffffffff0102030405060708")
	wire, err := answer.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("proxy answer = %x, want %x", wire, want)
	}
	parsed, err := ParseProxyAnswer(wire)
	if err != nil {
		t.Fatalf("ParseProxyAnswer: %v", err)
	}
	if parsed.Flags != answer.Flags || parsed.ConnectionID != answer.ConnectionID || !bytes.Equal(parsed.Packet, packet) {
		t.Fatalf("parsed answer = %+v", parsed)
	}
	wire[len(wire)-1] ^= 0xff
	if !bytes.Equal(parsed.Packet, packet) {
		t.Fatal("parsed answer aliases input")
	}

	badFlags := slices.Clone(want)
	binary.LittleEndian.PutUint32(badFlags[4:8], 0x20)
	if _, err := ParseProxyAnswer(badFlags); !errors.Is(err, ErrInvalidRPCFlags) {
		t.Fatalf("bad flags error = %v, want %v", err, ErrInvalidRPCFlags)
	}
	if _, err := (ProxyAnswer{Packet: []byte{1}}).MarshalBinary(); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("unaligned marshal error = %v, want %v", err, ErrInvalidRPCPayload)
	}
	if _, err := ParseProxyAnswer(want[:15]); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("short parse error = %v, want %v", err, ErrInvalidRPCPayload)
	}

	maximum := ProxyAnswer{Packet: make([]byte, MaxClientPacketSize)}
	maximumWire, err := maximum.MarshalBinary()
	if err != nil {
		t.Fatalf("maximum MarshalBinary: %v", err)
	}
	if _, err := ParseProxyAnswer(maximumWire); err != nil {
		t.Fatalf("maximum ParseProxyAnswer: %v", err)
	}
	tooLarge := ProxyAnswer{Packet: make([]byte, MaxClientPacketSize+4)}
	if _, err := tooLarge.MarshalBinary(); !errors.Is(err, ErrClientPacketTooLarge) {
		t.Fatalf("over-maximum marshal error = %v, want %v", err, ErrClientPacketTooLarge)
	}
	tooLargeWire := make([]byte, ProxyAnswerHeaderSize+MaxClientPacketSize+4)
	binary.LittleEndian.PutUint32(tooLargeWire[:4], OperationProxyAnswer)
	if _, err := ParseProxyAnswer(tooLargeWire); !errors.Is(err, ErrClientPacketTooLarge) {
		t.Fatalf("over-maximum parse error = %v, want %v", err, ErrClientPacketTooLarge)
	}
}

func TestFixedRPCPayloadsGoldenRoundTrip(t *testing.T) {
	const connectionID int64 = -0x0102030405060708
	const value uint64 = 0x1122334455667788

	closeConnectionWire := mustDecodeHex(t, "5d42cf1ff8f8f9fafbfcfdfe")
	closeConnection := CloseConnection{ConnectionID: connectionID}
	if got := closeConnection.MarshalBinary(); !bytes.Equal(got, closeConnectionWire) {
		t.Fatalf("close connection = %x, want %x", got, closeConnectionWire)
	}
	if got, err := ParseCloseConnection(closeConnectionWire); err != nil || got != closeConnection {
		t.Fatalf("ParseCloseConnection = %+v, error %v", got, err)
	}

	closeExternalWire := mustDecodeHex(t, "a234b65ef8f8f9fafbfcfdfe")
	closeExternal := CloseExternal{ConnectionID: connectionID}
	if got := closeExternal.MarshalBinary(); !bytes.Equal(got, closeExternalWire) {
		t.Fatalf("close external = %x, want %x", got, closeExternalWire)
	}
	if got, err := ParseCloseExternal(closeExternalWire); err != nil || got != closeExternal {
		t.Fatalf("ParseCloseExternal = %+v, error %v", got, err)
	}

	ackWire := mustDecodeHex(t, "9b40ac3bf8f8f9fafbfcfdfe44332211")
	ack := SimpleAck{ConnectionID: connectionID, ConfirmKey: 0x11223344}
	if got := ack.MarshalBinary(); !bytes.Equal(got, ackWire) {
		t.Fatalf("simple ack = %x, want %x", got, ackWire)
	}
	if got, err := ParseSimpleAck(ackWire); err != nil || got != ack {
		t.Fatalf("ParseSimpleAck = %+v, error %v", got, err)
	}

	pingWire := mustDecodeHex(t, "dfa230578877665544332211")
	ping := Ping{ID: value}
	if got := ping.MarshalBinary(); !bytes.Equal(got, pingWire) {
		t.Fatalf("ping = %x, want %x", got, pingWire)
	}
	if got, err := ParsePing(pingWire); err != nil || got != ping {
		t.Fatalf("ParsePing = %+v, error %v", got, err)
	}

	pongWire := mustDecodeHex(t, "a7ea30848877665544332211")
	pong := Pong{ID: value}
	if got := pong.MarshalBinary(); !bytes.Equal(got, pongWire) {
		t.Fatalf("pong = %x, want %x", got, pongWire)
	}
	if got, err := ParsePong(pongWire); err != nil || got != pong {
		t.Fatalf("ParsePong = %+v, error %v", got, err)
	}
}

func TestFixedRPCPayloadsRejectWrongOperationOrLength(t *testing.T) {
	validClose := (CloseConnection{ConnectionID: 1}).MarshalBinary()
	if _, err := ParseCloseConnection(validClose[:8]); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("short close error = %v, want %v", err, ErrInvalidRPCPayload)
	}
	wrongClose := slices.Clone(validClose)
	binary.LittleEndian.PutUint32(wrongClose[:4], OperationCloseExternal)
	if _, err := ParseCloseConnection(wrongClose); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("wrong close operation error = %v, want %v", err, ErrInvalidRPCPayload)
	}

	validAck := (SimpleAck{ConnectionID: 1}).MarshalBinary()
	if _, err := ParseSimpleAck(append(validAck, 0, 0, 0, 0)); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("long ack error = %v, want %v", err, ErrInvalidRPCPayload)
	}

	validPing := (Ping{ID: 1}).MarshalBinary()
	binary.LittleEndian.PutUint32(validPing[:4], OperationPong)
	if _, err := ParsePing(validPing); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("wrong ping operation error = %v, want %v", err, ErrInvalidRPCPayload)
	}
}

func TestParseRPCOperation(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		want uint32
	}{
		{name: "proxy request", wire: binary.LittleEndian.AppendUint32(nil, OperationProxyRequest), want: OperationProxyRequest},
		{name: "proxy answer", wire: binary.LittleEndian.AppendUint32(nil, OperationProxyAnswer), want: OperationProxyAnswer},
		{name: "close connection", wire: binary.LittleEndian.AppendUint32(nil, OperationCloseConnection), want: OperationCloseConnection},
		{name: "close external", wire: binary.LittleEndian.AppendUint32(nil, OperationCloseExternal), want: OperationCloseExternal},
		{name: "simple ack", wire: binary.LittleEndian.AppendUint32(nil, OperationSimpleAck), want: OperationSimpleAck},
		{name: "ping", wire: binary.LittleEndian.AppendUint32(nil, OperationPing), want: OperationPing},
		{name: "pong", wire: binary.LittleEndian.AppendUint32(nil, OperationPong), want: OperationPong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRPCOperation(tc.wire)
			if err != nil || got != tc.want {
				t.Fatalf("ParseRPCOperation = %08x, error %v; want %08x", got, err, tc.want)
			}
		})
	}

	if _, err := ParseRPCOperation([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidRPCPayload) {
		t.Fatalf("short operation error = %v, want %v", err, ErrInvalidRPCPayload)
	}
	if _, err := ParseRPCOperation([]byte{1, 2, 3, 4}); !errors.Is(err, ErrUnsupportedRPC) {
		t.Fatalf("unknown operation error = %v, want %v", err, ErrUnsupportedRPC)
	}
}

func FuzzProxyRequestRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3, 4})
	f.Add(bytes.Repeat([]byte{0xff}, 65))

	f.Fuzz(func(t *testing.T, input []byte) {
		input = input[:min(len(input), 4096)]
		packetSize := max(EncryptedMessageHeaderSize, (len(input)+3)&^3)
		packet := validEncryptedPacket(packetSize)
		copy(packet[8:], input)

		flags, err := ProxyRequestFlagsForClient(obfuscated2.ConnectionTypeAbridged, packet, len(input)%2 != 0, true)
		if err != nil {
			t.Fatalf("ProxyRequestFlagsForClient: %v", err)
		}
		var tag ProxyTag
		request := ProxyRequest{
			Flags:        flags,
			ConnectionID: int64(len(input)),
			RemoteAddr:   netip.MustParseAddrPort("192.0.2.1:1234"),
			ProxyAddr:    netip.MustParseAddrPort("[::ffff:198.51.100.2]:443"),
			Tag:          &tag,
			Packet:       packet,
		}
		wire, err := request.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		parsed, err := ParseProxyRequest(wire)
		if err != nil {
			t.Fatalf("ParseProxyRequest: %v", err)
		}
		if parsed.Flags != request.Flags || parsed.ConnectionID != request.ConnectionID || !bytes.Equal(parsed.Packet, packet) {
			t.Fatalf("round trip mismatch: got %+v", parsed)
		}
	})
}

func validEncryptedPacket(size int) []byte {
	packet := make([]byte, size)
	if size >= 8 {
		binary.LittleEndian.PutUint64(packet[:8], 0x0102030405060708)
	}
	return packet
}

func validUnencryptedPacket(constructor uint32) []byte {
	return malformedUnencryptedPacket(MinimumUnencryptedBodySize, constructor, UnencryptedMessageHeaderSize+MinimumUnencryptedBodySize)
}

func malformedUnencryptedPacket(innerLength int32, constructor uint32, size int) []byte {
	packet := make([]byte, size)
	if size >= 20 {
		binary.LittleEndian.PutUint64(packet[8:16], 0x1122334455667788)
		binary.LittleEndian.PutUint32(packet[16:20], uint32(innerLength))
	}
	if size >= 24 {
		binary.LittleEndian.PutUint32(packet[20:24], constructor)
	}
	for i := 24; i < size; i++ {
		packet[i] = byte(i)
	}
	return packet
}

func FuzzRPCDecodersRejectMalformedWithoutPanicking(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xee, 0xf1, 0xce, 0x36})
	f.Add(bytes.Repeat([]byte{0xff}, 128))

	f.Fuzz(func(t *testing.T, input []byte) {
		input = slices.Clone(input[:min(len(input), MaxRPCPayloadSize+1)])
		_, _ = ParseRPCOperation(input)
		_, _ = ParseProxyRequest(input)
		_, _ = ParseProxyAnswer(input)
		_, _ = ParseCloseConnection(input)
		_, _ = ParseCloseExternal(input)
		_, _ = ParseSimpleAck(input)
		_, _ = ParsePing(input)
		_, _ = ParsePong(input)
	})
}
