package middleend

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// ProxyRequestFlags are the flags carried by RPC_PROXY_REQ.
//
// The values come from RPC_F_* in net/net-tcp-rpc-common.h and the literal
// front/proxy flags in mtproto/mtproto-proxy.c at MTProxy commit
// f36d8af769ffaeac36978d38c2c0f6d1104c2137.
type ProxyRequestFlags uint32

const (
	ProxyRequestFlagNotEncrypted  ProxyRequestFlags = 0x00000002
	ProxyRequestFlagHasAdTag      ProxyRequestFlags = 0x00000008
	ProxyRequestFlagMagic         ProxyRequestFlags = 0x00001000
	ProxyRequestFlagExternalMode2 ProxyRequestFlags = 0x00020000
	ProxyRequestFlagIntermediate  ProxyRequestFlags = 0x20000000
	ProxyRequestFlagAbridged      ProxyRequestFlags = 0x40000000
	ProxyRequestFlagQuickAck      ProxyRequestFlags = 0x80000000
)

const supportedProxyRequestFlags = ProxyRequestFlagNotEncrypted |
	ProxyRequestFlagHasAdTag |
	ProxyRequestFlagMagic |
	ProxyRequestFlagExternalMode2 |
	ProxyRequestFlagIntermediate |
	ProxyRequestFlagAbridged |
	ProxyRequestFlagQuickAck

// ProxyAnswerFlags are the flags carried by RPC_PROXY_ANS.
type ProxyAnswerFlags uint32

const (
	ProxyAnswerFlagFlush      ProxyAnswerFlags = 0x08
	ProxyAnswerFlagSmallError ProxyAnswerFlags = 0x10
)

const supportedProxyAnswerFlags = ProxyAnswerFlagFlush | ProxyAnswerFlagSmallError

// ProxyTag is the exact 16-byte tag issued by Telegram's MTProxy bot.
type ProxyTag [16]byte

// ProxyRequest is an RPC_PROXY_REQ payload. Packet contains one complete,
// unframed MTProto packet.
type ProxyRequest struct {
	Flags        ProxyRequestFlags
	ConnectionID int64
	RemoteAddr   netip.AddrPort
	ProxyAddr    netip.AddrPort
	Tag          *ProxyTag
	Packet       []byte
}

// MarshalBinary encodes a strict RPC_PROXY_REQ payload.
func (r ProxyRequest) MarshalBinary() ([]byte, error) {
	hasTag := r.Tag != nil
	if err := validateProxyRequestFlags(r.Flags, hasTag); err != nil {
		return nil, err
	}
	if err := validateProxyPacket(r.Packet, r.Flags); err != nil {
		return nil, err
	}

	headerSize := ProxyRequestBaseSize
	if hasTag {
		headerSize = ProxyRequestTaggedHeaderSize
	}
	if len(r.Packet) > MaxClientPacketSize {
		return nil, fmt.Errorf("%w: proxy request packet %d exceeds %d", ErrClientPacketTooLarge, len(r.Packet), MaxClientPacketSize)
	}

	wire := make([]byte, headerSize+len(r.Packet))
	binary.LittleEndian.PutUint32(wire[0:4], OperationProxyRequest)
	binary.LittleEndian.PutUint32(wire[4:8], uint32(r.Flags))
	binary.LittleEndian.PutUint64(wire[8:16], uint64(r.ConnectionID))
	if err := putProxyAddress(wire[16:36], r.RemoteAddr, true); err != nil {
		return nil, fmt.Errorf("encode remote address: %w", err)
	}
	if err := putProxyAddress(wire[36:56], r.ProxyAddr, false); err != nil {
		return nil, fmt.Errorf("encode proxy address: %w", err)
	}

	if hasTag {
		binary.LittleEndian.PutUint32(wire[56:60], ProxyRequestTaggedHeaderSize-ProxyRequestBaseSize-4)
		binary.LittleEndian.PutUint32(wire[60:64], TLProxyTag)
		wire[64] = byte(len(*r.Tag))
		copy(wire[65:81], r.Tag[:])
		// wire[81:84] is the zero TL-string padding.
	}
	copy(wire[headerSize:], r.Packet)
	return wire, nil
}

// ParseProxyRequest decodes a strict RPC_PROXY_REQ payload.
func ParseProxyRequest(wire []byte) (ProxyRequest, error) {
	return parseProxyRequest(wire, true)
}

func parseProxyRequest(wire []byte, clonePacket bool) (ProxyRequest, error) {
	var request ProxyRequest
	if err := validateRPCPayload(wire, ProxyRequestBaseSize); err != nil {
		return request, err
	}
	if operation := binary.LittleEndian.Uint32(wire[0:4]); operation != OperationProxyRequest {
		return request, fmt.Errorf("%w: proxy request operation %08x", ErrInvalidRPCPayload, operation)
	}

	request.Flags = ProxyRequestFlags(binary.LittleEndian.Uint32(wire[4:8]))
	hasTag := request.Flags&ProxyRequestFlagHasAdTag != 0
	if err := validateProxyRequestFlags(request.Flags, hasTag); err != nil {
		return ProxyRequest{}, err
	}
	request.ConnectionID = int64(binary.LittleEndian.Uint64(wire[8:16]))

	var err error
	request.RemoteAddr, err = parseProxyAddress(wire[16:36], true)
	if err != nil {
		return ProxyRequest{}, fmt.Errorf("decode remote address: %w", err)
	}
	request.ProxyAddr, err = parseProxyAddress(wire[36:56], false)
	if err != nil {
		return ProxyRequest{}, fmt.Errorf("decode proxy address: %w", err)
	}

	headerSize := ProxyRequestBaseSize
	if hasTag {
		if len(wire) < ProxyRequestTaggedHeaderSize {
			return ProxyRequest{}, fmt.Errorf("%w: tagged proxy request length %d, want at least %d", ErrInvalidRPCPayload, len(wire), ProxyRequestTaggedHeaderSize)
		}
		extraSize := binary.LittleEndian.Uint32(wire[56:60])
		if extraSize > MaximumProxyExtraSize {
			return ProxyRequest{}, fmt.Errorf("%w: proxy extra data %d exceeds %d", ErrInvalidRPCPayload, extraSize, MaximumProxyExtraSize)
		}
		const taggedExtraSize = ProxyRequestTaggedHeaderSize - ProxyRequestBaseSize - 4
		if extraSize != taggedExtraSize {
			return ProxyRequest{}, fmt.Errorf("%w: proxy tag extra data length %d, want %d", ErrInvalidRPCPayload, extraSize, taggedExtraSize)
		}
		tag, err := parseProxyTag(wire[60:ProxyRequestTaggedHeaderSize])
		if err != nil {
			return ProxyRequest{}, err
		}
		request.Tag = &tag
		headerSize = ProxyRequestTaggedHeaderSize
	}

	request.Packet = wire[headerSize:]
	if err := validateProxyPacket(request.Packet, request.Flags); err != nil {
		return ProxyRequest{}, err
	}
	if clonePacket {
		request.Packet = slices.Clone(request.Packet)
	}
	return request, nil
}

// ProxyRequestFlagsForClient maps one decoded client packet to the exact
// flags forwarded by Telegram's external RPC frontend.
//
// Padded-intermediate and intermediate intentionally have the same request
// flags. The official frontend strips DD padding before forwarding and omits
// RPC_F_PAD from ext_rpcs_execute's forwarded flag mask. Response padding is
// restored from the local client connection state.
func ProxyRequestFlagsForClient(
	connectionType obfuscated2.ConnectionType,
	packet []byte,
	quickAck bool,
	hasAdTag bool,
) (ProxyRequestFlags, error) {
	notEncrypted, err := validateMTProtoEnvelope(packet)
	if err != nil {
		return 0, err
	}

	flags := ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2
	switch connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		flags |= ProxyRequestFlagAbridged
	case obfuscated2.ConnectionTypeIntermediate, obfuscated2.ConnectionTypePaddedIntermediate:
		flags |= ProxyRequestFlagIntermediate
	default:
		return 0, fmt.Errorf("%w: 0x%08x", ErrUnsupportedClientFraming, uint32(connectionType))
	}
	if notEncrypted {
		flags |= ProxyRequestFlagNotEncrypted
	}
	if quickAck {
		flags |= ProxyRequestFlagQuickAck
	}
	if hasAdTag {
		flags |= ProxyRequestFlagHasAdTag
	}
	return flags, nil
}

// ProxyAnswer is an RPC_PROXY_ANS payload. Packet contains one complete,
// unframed MTProto packet or the small-error body indicated by Flags.
type ProxyAnswer struct {
	Flags        ProxyAnswerFlags
	ConnectionID int64
	Packet       []byte
}

// MarshalBinary encodes a strict RPC_PROXY_ANS payload.
func (a ProxyAnswer) MarshalBinary() ([]byte, error) {
	if err := validateProxyAnswerFlags(a.Flags); err != nil {
		return nil, err
	}
	if len(a.Packet)%4 != 0 {
		return nil, fmt.Errorf("%w: proxy answer packet length %d", ErrInvalidRPCPayload, len(a.Packet))
	}
	if len(a.Packet) > MaxClientPacketSize {
		return nil, fmt.Errorf("%w: proxy answer packet %d exceeds %d", ErrClientPacketTooLarge, len(a.Packet), MaxClientPacketSize)
	}

	wire := make([]byte, ProxyAnswerHeaderSize+len(a.Packet))
	binary.LittleEndian.PutUint32(wire[0:4], OperationProxyAnswer)
	binary.LittleEndian.PutUint32(wire[4:8], uint32(a.Flags))
	binary.LittleEndian.PutUint64(wire[8:16], uint64(a.ConnectionID))
	copy(wire[ProxyAnswerHeaderSize:], a.Packet)
	return wire, nil
}

// ParseProxyAnswer decodes a strict RPC_PROXY_ANS payload.
func ParseProxyAnswer(wire []byte) (ProxyAnswer, error) {
	var answer ProxyAnswer
	if err := validateRPCPayload(wire, ProxyAnswerHeaderSize); err != nil {
		return answer, err
	}
	if operation := binary.LittleEndian.Uint32(wire[0:4]); operation != OperationProxyAnswer {
		return answer, fmt.Errorf("%w: proxy answer operation %08x", ErrInvalidRPCPayload, operation)
	}
	answer.Flags = ProxyAnswerFlags(binary.LittleEndian.Uint32(wire[4:8]))
	if err := validateProxyAnswerFlags(answer.Flags); err != nil {
		return ProxyAnswer{}, err
	}
	answer.ConnectionID = int64(binary.LittleEndian.Uint64(wire[8:16]))
	answer.Packet = slices.Clone(wire[ProxyAnswerHeaderSize:])
	if len(answer.Packet) > MaxClientPacketSize {
		return ProxyAnswer{}, fmt.Errorf("%w: proxy answer packet %d exceeds %d", ErrClientPacketTooLarge, len(answer.Packet), MaxClientPacketSize)
	}
	return answer, nil
}

// CloseConnection is the proxy-to-Middle-End RPC_CLOSE_CONN payload.
type CloseConnection struct {
	ConnectionID int64
}

// MarshalBinary encodes RPC_CLOSE_CONN.
func (c CloseConnection) MarshalBinary() []byte {
	return marshalConnectionIDPayload(OperationCloseConnection, c.ConnectionID)
}

// ParseCloseConnection decodes RPC_CLOSE_CONN.
func ParseCloseConnection(wire []byte) (CloseConnection, error) {
	connectionID, err := parseConnectionIDPayload(wire, OperationCloseConnection)
	if err != nil {
		return CloseConnection{}, err
	}
	return CloseConnection{ConnectionID: connectionID}, nil
}

// CloseExternal is the Middle-End-to-proxy RPC_CLOSE_EXT payload.
type CloseExternal struct {
	ConnectionID int64
}

// MarshalBinary encodes RPC_CLOSE_EXT.
func (c CloseExternal) MarshalBinary() []byte {
	return marshalConnectionIDPayload(OperationCloseExternal, c.ConnectionID)
}

// ParseCloseExternal decodes RPC_CLOSE_EXT.
func ParseCloseExternal(wire []byte) (CloseExternal, error) {
	connectionID, err := parseConnectionIDPayload(wire, OperationCloseExternal)
	if err != nil {
		return CloseExternal{}, err
	}
	return CloseExternal{ConnectionID: connectionID}, nil
}

// SimpleAck is an RPC_SIMPLE_ACK payload.
type SimpleAck struct {
	ConnectionID int64
	ConfirmKey   uint32
}

// MarshalBinary encodes RPC_SIMPLE_ACK.
func (a SimpleAck) MarshalBinary() []byte {
	wire := make([]byte, SimpleAckPayloadSize)
	binary.LittleEndian.PutUint32(wire[0:4], OperationSimpleAck)
	binary.LittleEndian.PutUint64(wire[4:12], uint64(a.ConnectionID))
	binary.LittleEndian.PutUint32(wire[12:16], a.ConfirmKey)
	return wire
}

// ParseSimpleAck decodes RPC_SIMPLE_ACK.
func ParseSimpleAck(wire []byte) (SimpleAck, error) {
	if err := validateFixedRPCPayload(wire, OperationSimpleAck, SimpleAckPayloadSize); err != nil {
		return SimpleAck{}, err
	}
	return SimpleAck{
		ConnectionID: int64(binary.LittleEndian.Uint64(wire[4:12])),
		ConfirmKey:   binary.LittleEndian.Uint32(wire[12:16]),
	}, nil
}

// Ping is an RPC_PING payload.
type Ping struct {
	ID uint64
}

// MarshalBinary encodes RPC_PING.
func (p Ping) MarshalBinary() []byte {
	return marshalKeepalive(OperationPing, p.ID)
}

// ParsePing decodes RPC_PING.
func ParsePing(wire []byte) (Ping, error) {
	id, err := parseKeepalive(wire, OperationPing)
	if err != nil {
		return Ping{}, err
	}
	return Ping{ID: id}, nil
}

// Pong is an RPC_PONG payload.
type Pong struct {
	ID uint64
}

// MarshalBinary encodes RPC_PONG.
func (p Pong) MarshalBinary() []byte {
	return marshalKeepalive(OperationPong, p.ID)
}

// ParsePong decodes RPC_PONG.
func ParsePong(wire []byte) (Pong, error) {
	id, err := parseKeepalive(wire, OperationPong)
	if err != nil {
		return Pong{}, err
	}
	return Pong{ID: id}, nil
}

// ParseRPCOperation validates a bounded, aligned payload and returns its
// little-endian operation code.
func ParseRPCOperation(wire []byte) (uint32, error) {
	if err := validateRPCPayload(wire, 4); err != nil {
		return 0, err
	}
	operation := binary.LittleEndian.Uint32(wire[:4])
	switch operation {
	case OperationProxyRequest,
		OperationProxyAnswer,
		OperationCloseConnection,
		OperationCloseExternal,
		OperationSimpleAck,
		OperationPing,
		OperationPong:
		return operation, nil
	default:
		return 0, fmt.Errorf("%w: %08x", ErrUnsupportedRPC, operation)
	}
}

func validateProxyRequestFlags(flags ProxyRequestFlags, hasTag bool) error {
	if unknown := flags &^ supportedProxyRequestFlags; unknown != 0 {
		return fmt.Errorf("%w: unsupported request bits %08x", ErrInvalidRPCFlags, uint32(unknown))
	}
	if flags&ProxyRequestFlagMagic == 0 || flags&ProxyRequestFlagExternalMode2 == 0 {
		return fmt.Errorf("%w: request is missing magic or external-mode-2", ErrInvalidRPCFlags)
	}
	mode := flags & (ProxyRequestFlagIntermediate | ProxyRequestFlagAbridged)
	if mode != ProxyRequestFlagIntermediate && mode != ProxyRequestFlagAbridged {
		return fmt.Errorf("%w: request has invalid transport mode %08x", ErrInvalidRPCFlags, uint32(mode))
	}
	if (flags&ProxyRequestFlagHasAdTag != 0) != hasTag {
		return fmt.Errorf("%w: ad-tag flag and payload disagree", ErrInvalidRPCFlags)
	}
	return nil
}

func validateProxyAnswerFlags(flags ProxyAnswerFlags) error {
	if unknown := flags &^ supportedProxyAnswerFlags; unknown != 0 {
		return fmt.Errorf("%w: unsupported answer bits %08x", ErrInvalidRPCFlags, uint32(unknown))
	}
	return nil
}

func validateProxyPacket(packet []byte, flags ProxyRequestFlags) error {
	notEncrypted, err := validateMTProtoEnvelope(packet)
	if err != nil {
		return err
	}
	if (flags&ProxyRequestFlagNotEncrypted != 0) != notEncrypted {
		return fmt.Errorf("%w: not-encrypted flag and auth_key_id disagree", ErrInvalidRPCFlags)
	}
	return nil
}

// validateMTProtoEnvelope follows forward_mtproto_packet and
// forward_mtproto_enc_packet in mtproto/mtproto-proxy.c at MTProxy commit
// f36d8af769ffaeac36978d38c2c0f6d1104c2137. It also admits the unencrypted
// msgs_ack emitted between handshake steps by current Telegram clients.
func validateMTProtoEnvelope(packet []byte) (bool, error) {
	if len(packet)%4 != 0 {
		return false, fmt.Errorf("%w: packet length %d is not word-aligned", ErrInvalidMTProtoEnvelope, len(packet))
	}
	if len(packet) > MaxClientPacketSize {
		return false, fmt.Errorf("%w: %d > %d", ErrClientPacketTooLarge, len(packet), MaxClientPacketSize)
	}
	if len(packet) < 8 {
		return false, fmt.Errorf("%w: packet length %d cannot contain auth_key_id", ErrInvalidMTProtoEnvelope, len(packet))
	}

	notEncrypted := binary.LittleEndian.Uint64(packet[:8]) == 0
	if !notEncrypted {
		if len(packet) < EncryptedMessageHeaderSize {
			return false, fmt.Errorf("%w: encrypted packet length %d is below %d", ErrInvalidMTProtoEnvelope, len(packet), EncryptedMessageHeaderSize)
		}
		return false, nil
	}

	// The official function first requires seven 32-bit words so it can read
	// the constructor, then validates the signed length at offset 16.
	if len(packet) < 28 {
		return true, fmt.Errorf("%w: unencrypted packet length %d is below 28", ErrInvalidMTProtoEnvelope, len(packet))
	}
	innerLength := int32(binary.LittleEndian.Uint32(packet[16:20]))
	if innerLength < MinimumUnencryptedBodySize {
		return true, fmt.Errorf("%w: unencrypted body length %d is below %d", ErrInvalidMTProtoEnvelope, innerLength, MinimumUnencryptedBodySize)
	}
	if int64(innerLength)+UnencryptedMessageHeaderSize > int64(len(packet)) {
		return true, fmt.Errorf("%w: unencrypted body length %d exceeds packet length %d", ErrInvalidMTProtoEnvelope, innerLength, len(packet))
	}

	constructor := binary.LittleEndian.Uint32(packet[20:24])
	switch constructor {
	case MTProtoReqPQConstructor,
		MTProtoReqPQMultiConstructor,
		MTProtoReqDHParamsConstructor,
		MTProtoSetClientDHParamsConstructor,
		MTProtoMsgsAckConstructor:
		return true, nil
	default:
		return true, fmt.Errorf("%w: unsupported unencrypted constructor %08x", ErrInvalidMTProtoEnvelope, constructor)
	}
}

func putProxyAddress(dst []byte, addrPort netip.AddrPort, allowZeroPort bool) error {
	if len(dst) != 20 {
		return fmt.Errorf("%w: address destination length %d", ErrInvalidProxyAddress, len(dst))
	}
	if err := validateProxyAddress(addrPort, allowZeroPort); err != nil {
		return err
	}

	clear(dst)
	addr := addrPort.Addr().Unmap()
	if addr.Is4() {
		addr4 := addr.As4()
		dst[10], dst[11] = 0xff, 0xff
		copy(dst[12:16], addr4[:])
	} else {
		addr16 := addr.As16()
		copy(dst[:16], addr16[:])
	}
	binary.LittleEndian.PutUint32(dst[16:20], uint32(addrPort.Port()))
	return nil
}

func parseProxyAddress(wire []byte, allowZeroPort bool) (netip.AddrPort, error) {
	if len(wire) != 20 {
		return netip.AddrPort{}, fmt.Errorf("%w: address length %d", ErrInvalidProxyAddress, len(wire))
	}
	addr, ok := netip.AddrFromSlice(wire[:16])
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("%w: malformed IP", ErrInvalidProxyAddress)
	}
	port := binary.LittleEndian.Uint32(wire[16:20])
	if port > 65535 || (port == 0 && !allowZeroPort) {
		return netip.AddrPort{}, fmt.Errorf("%w: port %d", ErrInvalidProxyAddress, port)
	}
	addrPort := netip.AddrPortFrom(addr.Unmap(), uint16(port))
	if err := validateProxyAddress(addrPort, allowZeroPort); err != nil {
		return netip.AddrPort{}, err
	}
	return addrPort, nil
}

func validateProxyAddress(addrPort netip.AddrPort, allowZeroPort bool) error {
	if !addrPort.IsValid() || (addrPort.Port() == 0 && !allowZeroPort) {
		return fmt.Errorf("%w: endpoint must have a valid address and permitted port", ErrInvalidProxyAddress)
	}
	addr := addrPort.Addr()
	if addr.IsUnspecified() || addr.Zone() != "" {
		return fmt.Errorf("%w: unspecified or zoned address %s", ErrInvalidProxyAddress, addr)
	}
	return nil
}

func parseProxyTag(extra []byte) (ProxyTag, error) {
	var tag ProxyTag
	const taggedExtraSize = ProxyRequestTaggedHeaderSize - ProxyRequestBaseSize - 4
	if len(extra) != taggedExtraSize {
		return tag, fmt.Errorf("%w: proxy tag object length %d, want %d", ErrInvalidTLString, len(extra), taggedExtraSize)
	}
	if operation := binary.LittleEndian.Uint32(extra[0:4]); operation != TLProxyTag {
		return tag, fmt.Errorf("%w: proxy tag constructor %08x", ErrInvalidTLString, operation)
	}
	if extra[4] != byte(len(tag)) {
		return tag, fmt.Errorf("%w: proxy tag length %d, want %d", ErrInvalidTLString, extra[4], len(tag))
	}
	copy(tag[:], extra[5:21])
	if extra[21] != 0 || extra[22] != 0 || extra[23] != 0 {
		return ProxyTag{}, fmt.Errorf("%w: nonzero proxy tag padding", ErrInvalidTLString)
	}
	return tag, nil
}

func marshalConnectionIDPayload(operation uint32, connectionID int64) []byte {
	wire := make([]byte, ClosePayloadSize)
	binary.LittleEndian.PutUint32(wire[0:4], operation)
	binary.LittleEndian.PutUint64(wire[4:12], uint64(connectionID))
	return wire
}

func parseConnectionIDPayload(wire []byte, operation uint32) (int64, error) {
	if err := validateFixedRPCPayload(wire, operation, ClosePayloadSize); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(wire[4:12])), nil
}

func marshalKeepalive(operation uint32, id uint64) []byte {
	wire := make([]byte, KeepalivePayloadSize)
	binary.LittleEndian.PutUint32(wire[0:4], operation)
	binary.LittleEndian.PutUint64(wire[4:12], id)
	return wire
}

func parseKeepalive(wire []byte, operation uint32) (uint64, error) {
	if err := validateFixedRPCPayload(wire, operation, KeepalivePayloadSize); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(wire[4:12]), nil
}

func validateFixedRPCPayload(wire []byte, operation uint32, size int) error {
	if len(wire) != size {
		return fmt.Errorf("%w: operation %08x length %d, want %d", ErrInvalidRPCPayload, operation, len(wire), size)
	}
	if got := binary.LittleEndian.Uint32(wire[0:4]); got != operation {
		return fmt.Errorf("%w: operation %08x, want %08x", ErrInvalidRPCPayload, got, operation)
	}
	return nil
}

func validateRPCPayload(wire []byte, minimumSize int) error {
	if len(wire) < minimumSize || len(wire)%4 != 0 {
		return fmt.Errorf("%w: length %d, want aligned length at least %d", ErrInvalidRPCPayload, len(wire), minimumSize)
	}
	if len(wire) > MaxRPCPayloadSize {
		return fmt.Errorf("%w: length %d exceeds %d", ErrInvalidRPCPayload, len(wire), MaxRPCPayloadSize)
	}
	return nil
}
