// Package middleend implements Telegram's private Middle-End TCP RPC wire
// protocol. It does not implement connection pooling or proxy routing.
package middleend

import (
	"errors"
	"time"
)

const (
	// Handshake operation codes are defined by Telegram's
	// net/net-tcp-rpc-common.h; proxy operations are in
	// mtproto/mtproto-common.h; ping and pong are in common/rpc-const.h. All
	// references use MTProxy commit
	// f36d8af769ffaeac36978d38c2c0f6d1104c2137.
	OperationNonce           uint32 = 0x7acb87aa
	OperationHandshake       uint32 = 0x7682eef5
	OperationHandshakeError  uint32 = 0x6a27beda
	OperationProxyRequest    uint32 = 0x36cef1ee
	OperationProxyAnswer     uint32 = 0x4403da0d
	OperationCloseConnection uint32 = 0x1fcf425d
	OperationCloseExternal   uint32 = 0x5eb634a2
	OperationSimpleAck       uint32 = 0x3bac409b
	OperationPing            uint32 = 0x5730a2df
	OperationPong            uint32 = 0x8430eaa7

	// TLProxyTag identifies the optional 16-byte registered proxy tag in a
	// proxy request's extra-data section. It is defined by
	// mtproto/mtproto-proxy.c at the pinned MTProxy commit.
	TLProxyTag uint32 = 0xdb1e26ae

	CryptoSchemaAES int32 = 1

	// HandshakeFlagCRC32C negotiates CRC32C for packets after the handshake.
	// The nonce and handshake packets themselves always use IEEE CRC32.
	HandshakeFlagCRC32C uint32 = 1 << 11

	NoncePacketSize          = 32
	HandshakePacketSize      = 32
	HandshakeErrorPacketSize = 20
	FullFrameOverhead        = 12
	MinimumFullFrameSize     = 16
	NoopFrameSize            = 4

	// MaxClientPacketSize is Telegram's official MAX_POST_SIZE from
	// mtproto/mtproto-proxy.c. The external framing parser applies it to the
	// declared client transport packet before padded-intermediate stripping;
	// ext_rpcs_execute also applies it to the stripped packet. It is not a
	// Middle-End full RPC frame limit.
	MaxClientPacketSize = 262144*4 - 4096

	// Proxy request and answer overheads are the packed wire offsets confirmed
	// from Telegram's official structs. The tagged request additionally has a
	// four-byte extra-size field and a 24-byte TL_PROXY_TAG object.
	ProxyRequestBaseSize         = 56
	ProxyTagExtraSize            = 28
	ProxyRequestTaggedHeaderSize = ProxyRequestBaseSize + ProxyTagExtraSize
	ProxyAnswerHeaderSize        = 16
	ClosePayloadSize             = 12
	SimpleAckPayloadSize         = 16
	KeepalivePayloadSize         = 12
	MaximumProxyExtraSize        = 16384

	// MaxMEFrameSize is a local safety cap, not an official Telegram constant.
	// It admits an official-maximum client packet in the largest supported
	// tagged RPC_PROXY_REQ plus the full-frame length, sequence, and checksum.
	MaxMEFrameSize    = MaxClientPacketSize + ProxyRequestTaggedHeaderSize + FullFrameOverhead
	MaxRPCPayloadSize = MaxMEFrameSize - FullFrameOverhead

	// Deprecated: use MaxMEFrameSize.
	DefaultMaxFrameSize = MaxMEFrameSize
	// Deprecated: use MaxClientPacketSize.
	DefaultMaxClientPacketSize = MaxClientPacketSize

	// EncryptedMessageHeaderSize is offsetof(struct encrypted_message,
	// message) in Telegram's packed mtproto/mtproto-common.h definition.
	EncryptedMessageHeaderSize   = 56
	UnencryptedMessageHeaderSize = 20
	MinimumUnencryptedBodySize   = 20

	// The first four constructors are the unencrypted MTProto handshake
	// messages accepted by the pinned official external proxy. Some Telegram
	// clients also acknowledge a handshake response before sending the next
	// step, so the Middle-End frontend must admit msgs_ack as well.
	MTProtoReqPQConstructor             uint32 = 0x60469778
	MTProtoReqPQMultiConstructor        uint32 = 0xbe7e8ef1
	MTProtoReqDHParamsConstructor       uint32 = 0xd712e4be
	MTProtoSetClientDHParamsConstructor uint32 = 0xf5045f1f
	MTProtoMsgsAckConstructor           uint32 = 0x62d6b459

	MinimumSecretSize = 32
	MaximumSecretSize = 256

	// NonceClockSkew matches the 30-second nonce timestamp check in Telegram's
	// net/net-tcp-rpc-client.c and net/net-tcp-rpc-server.c.
	NonceClockSkew = 30 * time.Second
)

var (
	ErrInvalidChecksumMode      = errors.New("invalid middle-end checksum mode")
	ErrInvalidFrameSize         = errors.New("invalid middle-end full frame size")
	ErrFrameTooLarge            = errors.New("middle-end full frame is too large")
	ErrChecksumMismatch         = errors.New("middle-end full frame checksum mismatch")
	ErrSequenceMismatch         = errors.New("middle-end full frame sequence mismatch")
	ErrSequenceExhausted        = errors.New("middle-end full frame sequence exhausted")
	ErrIncompleteFrame          = errors.New("incomplete middle-end full frame")
	ErrIncompleteBlock          = errors.New("incomplete middle-end AES-CBC block")
	ErrInvalidPlaintext         = errors.New("invalid middle-end AES-CBC plaintext")
	ErrInvalidSecret            = errors.New("invalid middle-end infrastructure secret")
	ErrInvalidAddress           = errors.New("invalid middle-end KDF address tuple")
	ErrInvalidRole              = errors.New("invalid middle-end KDF role")
	ErrInvalidNonce             = errors.New("invalid middle-end nonce packet")
	ErrKeySelector              = errors.New("middle-end key selector mismatch")
	ErrTimestampSkew            = errors.New("middle-end nonce timestamp exceeds allowed skew")
	ErrInvalidHandshake         = errors.New("invalid middle-end handshake packet")
	ErrProcessIDMismatch        = errors.New("middle-end handshake process ID mismatch")
	ErrInvalidRPCPayload        = errors.New("invalid middle-end RPC payload")
	ErrUnsupportedRPC           = errors.New("unsupported middle-end RPC operation")
	ErrInvalidRPCFlags          = errors.New("invalid middle-end RPC flags")
	ErrInvalidProxyAddress      = errors.New("invalid middle-end proxy address")
	ErrInvalidTLString          = errors.New("invalid middle-end TL string")
	ErrInvalidMTProtoEnvelope   = errors.New("invalid MTProto envelope")
	ErrInvalidClientPacket      = errors.New("invalid MTProto client packet")
	ErrClientPacketTooLarge     = errors.New("MTProto client packet is too large")
	ErrIncompleteClientPacket   = errors.New("incomplete MTProto client packet")
	ErrUnsupportedClientFraming = errors.New("unsupported MTProto client framing")
	ErrChecksumTransition       = errors.New("invalid middle-end checksum transition")
)
