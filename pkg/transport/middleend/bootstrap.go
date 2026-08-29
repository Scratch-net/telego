package middleend

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

var (
	ErrBootstrapState        = errors.New("invalid Middle-End bootstrap state")
	ErrBootstrapIncomplete   = errors.New("incomplete Middle-End bootstrap")
	ErrTupleNotAuthoritative = errors.New("Middle-End address tuple is not authoritative")
	ErrUnexpectedPong        = errors.New("unexpected Middle-End pong")
)

// ClientBootstrapConfig contains the connection-specific inputs for one
// Telegram Middle-End client link. ServerAddr and ClientAddr must be the exact
// endpoints observed by Telegram; callers must establish that authority before
// constructing the bootstrap.
type ClientBootstrapConfig struct {
	Secret          []byte
	ServerAddr      netip.AddrPort
	ClientAddr      netip.AddrPort
	LocalProcessID  ProcessID
	ClientTimestamp int32
	NonceSource     io.Reader
}

// String prevents accidental disclosure of bootstrap key material.
func (ClientBootstrapConfig) String() string {
	return "middleend.ClientBootstrapConfig{redacted}"
}

// GoString prevents accidental disclosure of bootstrap key material.
func (ClientBootstrapConfig) GoString() string {
	return "middleend.ClientBootstrapConfig{redacted}"
}

// BootstrapUpdate is the result of consuming one bounded input prefix.
// Outbound contains protocol bytes that must be written before waiting for
// more peer data. Frames contains post-handshake RPC frames.
type BootstrapUpdate struct {
	Outbound    []byte
	Frames      []Frame
	BecameReady bool
}

type clientBootstrapStage uint8

const (
	clientBootstrapCreated clientBootstrapStage = iota
	clientBootstrapNonceSent
	clientBootstrapHandshakeSent
	clientBootstrapReady
	clientBootstrapRetired
	clientBootstrapFailed
)

// ClientBootstrap owns the nonce, AES-CBC, full-frame sequence, and checksum
// state for one outbound Middle-End link. It is independent of a socket or
// event-loop implementation and is not safe for concurrent use.
type ClientBootstrap struct {
	stage           clientBootstrapStage
	config          ClientBootstrapConfig
	selector        uint32
	clientNonce     [16]byte
	nonceBuffer     []byte
	encoder         *FrameEncoder
	decoder         *FrameDecoder
	encrypter       *CBCEncrypter
	decrypter       *CBCDecrypter
	localHandshake  HandshakePacket
	remoteProcessID ProcessID
	err             error
}

// String prevents accidental disclosure of bootstrap secret, nonce, and
// expanded cipher state.
func (ClientBootstrap) String() string {
	return "middleend.ClientBootstrap{redacted}"
}

// GoString prevents accidental disclosure of bootstrap secret, nonce, and
// expanded cipher state.
func (ClientBootstrap) GoString() string {
	return "middleend.ClientBootstrap{redacted}"
}

// NewClientBootstrap validates and copies the connection inputs. Call Start
// exactly once to generate the plaintext sequence -2 nonce frame.
func NewClientBootstrap(config ClientBootstrapConfig) (*ClientBootstrap, error) {
	if err := validateAddressTuple(config.ServerAddr, config.ClientAddr); err != nil {
		return nil, err
	}
	selector, err := SecretKeySelector(config.Secret)
	if err != nil {
		return nil, err
	}
	if config.ClientTimestamp == 0 {
		return nil, fmt.Errorf("%w: client timestamp is zero", ErrBootstrapState)
	}
	if config.LocalProcessID.PID == 0 || config.LocalProcessID.Uptime == 0 {
		return nil, fmt.Errorf("%w: local process ID and uptime must be nonzero", ErrBootstrapState)
	}

	nonceSource := config.NonceSource
	if nonceSource == nil {
		nonceSource = rand.Reader
	}
	stored := ClientBootstrapConfig{
		Secret:          slices.Clone(config.Secret),
		ServerAddr:      config.ServerAddr,
		ClientAddr:      config.ClientAddr,
		LocalProcessID:  config.LocalProcessID,
		ClientTimestamp: config.ClientTimestamp,
		NonceSource:     nonceSource,
	}
	return &ClientBootstrap{
		stage:    clientBootstrapCreated,
		config:   stored,
		selector: selector,
	}, nil
}

// Start generates and encodes the plaintext nonce packet. It returns no
// reusable reference to the bootstrap's secret or nonce storage.
func (b *ClientBootstrap) Start() ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: nil bootstrap", ErrBootstrapState)
	}
	if b.err != nil {
		return nil, b.err
	}
	if b.stage != clientBootstrapCreated {
		return nil, fmt.Errorf("%w: Start called in stage %d", ErrBootstrapState, b.stage)
	}
	if _, err := io.ReadFull(b.config.NonceSource, b.clientNonce[:]); err != nil {
		return nil, b.fail(fmt.Errorf("generate Middle-End client nonce: %w", err))
	}

	encoder, err := NewFrameEncoder(-2, MaxMEFrameSize)
	if err != nil {
		return nil, b.fail(err)
	}
	noncePayload, err := (NoncePacket{
		KeySelector: b.selector,
		Timestamp:   b.config.ClientTimestamp,
		Nonce:       b.clientNonce,
	}).MarshalBinary()
	if err != nil {
		return nil, b.fail(err)
	}
	wire, err := encoder.Encode(noncePayload)
	if err != nil {
		return nil, b.fail(err)
	}
	b.encoder = encoder
	b.stage = clientBootstrapNonceSent
	return wire, nil
}

// Feed consumes a bounded prefix of peer bytes. It accepts arbitrary network
// fragmentation and returns partial consumption at the plaintext-to-encrypted
// transition so the caller can immediately write Outbound before resuming.
func (b *ClientBootstrap) Feed(data []byte) (int, BootstrapUpdate, error) {
	var update BootstrapUpdate
	if b == nil {
		return 0, update, fmt.Errorf("%w: nil bootstrap", ErrBootstrapState)
	}
	if b.err != nil {
		return 0, update, b.err
	}
	switch b.stage {
	case clientBootstrapCreated:
		return 0, update, fmt.Errorf("%w: Start has not been called", ErrBootstrapState)
	case clientBootstrapNonceSent:
		return b.feedServerNonce(data)
	case clientBootstrapHandshakeSent, clientBootstrapReady:
		return b.feedEncrypted(data)
	default:
		return 0, update, b.fail(fmt.Errorf("%w: stage %d", ErrBootstrapState, b.stage))
	}
}

func (b *ClientBootstrap) feedServerNonce(data []byte) (int, BootstrapUpdate, error) {
	var update BootstrapUpdate
	const nonceFrameSize = NoncePacketSize + FullFrameOverhead
	needed := nonceFrameSize - len(b.nonceBuffer)
	consumed := min(len(data), needed)
	b.nonceBuffer = append(b.nonceBuffer, data[:consumed]...)
	if len(b.nonceBuffer) >= 4 {
		declared := int(binary.LittleEndian.Uint32(b.nonceBuffer[:4]))
		if declared != nonceFrameSize {
			return consumed, update, b.fail(fmt.Errorf("%w: server nonce frame size %d, want %d", ErrInvalidNonce, declared, nonceFrameSize))
		}
	}
	if len(b.nonceBuffer) != nonceFrameSize {
		return consumed, update, nil
	}

	frame, err := DecodeFrame(b.nonceBuffer, -2, ChecksumCRC32, MaxMEFrameSize)
	clear(b.nonceBuffer)
	b.nonceBuffer = nil
	if err != nil {
		return consumed, update, b.fail(err)
	}
	serverNonce, err := ParseNoncePacket(frame.Payload)
	if err != nil {
		return consumed, update, b.fail(err)
	}
	if err := serverNonce.Validate(b.selector, time.Unix(int64(b.config.ClientTimestamp), 0)); err != nil {
		return consumed, update, b.fail(err)
	}

	keys, err := DeriveKeys(KDFParams{
		ServerNonce:     serverNonce.Nonce,
		ClientNonce:     b.clientNonce,
		ClientTimestamp: b.config.ClientTimestamp,
		ServerAddr:      b.config.ServerAddr,
		ClientAddr:      b.config.ClientAddr,
		Secret:          b.config.Secret,
	}, RoleClient)
	clear(b.config.Secret)
	b.config.Secret = nil
	clear(b.clientNonce[:])
	if err != nil {
		return consumed, update, b.fail(err)
	}
	b.encrypter, err = NewCBCEncrypter(keys.WriteKey[:], keys.WriteIV[:])
	if err != nil {
		clearKeys(&keys)
		return consumed, update, b.fail(err)
	}
	b.decrypter, err = NewCBCDecrypter(keys.ReadKey[:], keys.ReadIV[:])
	clearKeys(&keys)
	if err != nil {
		return consumed, update, b.fail(err)
	}
	b.decoder, err = NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		return consumed, update, b.fail(err)
	}

	b.localHandshake = HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: b.config.LocalProcessID,
		Peer:   processPattern(b.config.ServerAddr),
	}
	handshakePayload, err := b.localHandshake.MarshalBinary()
	if err != nil {
		return consumed, update, b.fail(err)
	}
	handshakeFrame, err := b.encoder.Encode(handshakePayload)
	if err != nil {
		return consumed, update, b.fail(err)
	}
	update.Outbound, err = b.encrypter.Encrypt(handshakeFrame)
	if err != nil {
		return consumed, BootstrapUpdate{}, b.fail(err)
	}
	b.stage = clientBootstrapHandshakeSent
	return consumed, update, nil
}

func (b *ClientBootstrap) feedEncrypted(data []byte) (int, BootstrapUpdate, error) {
	var update BootstrapUpdate
	consumed, plaintext := b.decrypter.Feed(data)
	for len(plaintext) != 0 {
		fed, err := b.decoder.Feed(plaintext)
		if err != nil {
			return consumed, BootstrapUpdate{}, b.fail(err)
		}
		plaintext = plaintext[fed:]

		progress := false
		for {
			frame, ok, err := b.decoder.Next()
			if err != nil {
				return consumed, BootstrapUpdate{}, b.fail(err)
			}
			if !ok {
				break
			}
			progress = true
			if b.stage == clientBootstrapHandshakeSent {
				peer, err := ParseHandshakePacket(frame.Payload)
				if err != nil {
					return consumed, BootstrapUpdate{}, b.fail(err)
				}
				if err := peer.ValidatePeer(b.config.LocalProcessID); err != nil {
					return consumed, BootstrapUpdate{}, b.fail(err)
				}
				if err := b.decoder.ApplyPeerHandshake(peer, b.localHandshake); err != nil {
					return consumed, BootstrapUpdate{}, b.fail(err)
				}
				if err := b.encoder.ApplyPeerHandshake(peer); err != nil {
					return consumed, BootstrapUpdate{}, b.fail(err)
				}
				b.remoteProcessID = peer.Sender
				b.stage = clientBootstrapReady
				update.BecameReady = true
				continue
			}
			update.Frames = append(update.Frames, frame)
		}
		if fed == 0 && !progress {
			return consumed, BootstrapUpdate{}, b.fail(io.ErrNoProgress)
		}
	}
	return consumed, update, nil
}

// Encode encrypts one post-handshake RPC payload using this link's continuous
// CBC and sequence state.
func (b *ClientBootstrap) Encode(payload []byte) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("%w: nil bootstrap", ErrBootstrapState)
	}
	if b.err != nil {
		return nil, b.err
	}
	if b.stage != clientBootstrapReady {
		return nil, fmt.Errorf("%w: link is not ready", ErrBootstrapState)
	}
	frame, err := b.encoder.Encode(payload)
	if err != nil {
		return nil, b.fail(err)
	}
	wire, err := b.encrypter.Encrypt(frame)
	if err != nil {
		return nil, b.fail(err)
	}
	return wire, nil
}

// Ready reports whether the bilateral handshake and checksum transition are
// complete.
func (b *ClientBootstrap) Ready() bool {
	return b != nil && b.stage == clientBootstrapReady && b.err == nil
}

// RemoteProcessID returns the sender PID advertised by the peer handshake.
// The official mtfront client ignores this PID for endpoint matching but does
// validate that the peer pattern matches its own local PID.
func (b *ClientBootstrap) RemoteProcessID() (ProcessID, bool) {
	if !b.Ready() {
		return ProcessID{}, false
	}
	return b.remoteProcessID, true
}

// Finish validates an orderly end of the byte stream.
func (b *ClientBootstrap) Finish() error {
	if b == nil {
		return fmt.Errorf("%w: nil bootstrap", ErrBootstrapState)
	}
	if b.err != nil {
		return b.err
	}
	if b.stage != clientBootstrapReady {
		return ErrBootstrapIncomplete
	}
	if err := b.decrypter.Finish(); err != nil {
		return b.fail(err)
	}
	if err := b.decoder.Finish(); err != nil {
		return b.fail(err)
	}
	return nil
}

func (b *ClientBootstrap) fail(err error) error {
	if b.err == nil {
		b.err = err
		b.stage = clientBootstrapFailed
		b.clearTemporaryState()
	}
	return b.err
}

// failTransport permanently retires a bootstrap when its owning transport
// fails before the bilateral handshake becomes ready. A ready bootstrap keeps
// its protocol state so an orderly post-handshake link close is not rewritten
// as a bootstrap failure.
func (b *ClientBootstrap) failTransport(err error) error {
	if b == nil || b.Ready() {
		return err
	}
	if err == nil {
		err = ErrBootstrapState
	}
	return b.fail(err)
}

// retire releases every connection-owned protocol and cryptographic object
// after its transport has stopped. It does not rewrite an earlier bootstrap
// failure, and it does not touch LinkEvent packets already cloned and
// transferred to consumers.
func (b *ClientBootstrap) retire() {
	if b == nil {
		return
	}
	b.clearTemporaryState()
	if b.stage != clientBootstrapFailed {
		b.stage = clientBootstrapRetired
	}
}

func (b *ClientBootstrap) clearTemporaryState() {
	clear(b.config.Secret)
	b.config = ClientBootstrapConfig{}
	b.selector = 0
	clear(b.clientNonce[:])
	clear(b.nonceBuffer)
	b.nonceBuffer = nil
	if b.decrypter != nil {
		clear(b.decrypter.pending)
	}
	if b.decoder != nil {
		b.decoder.retire()
	}
	if b.encoder != nil {
		*b.encoder = FrameEncoder{}
	}
	if b.encrypter != nil {
		*b.encrypter = CBCEncrypter{}
	}
	if b.decrypter != nil {
		*b.decrypter = CBCDecrypter{}
	}
	b.encoder = nil
	b.decoder = nil
	b.encrypter = nil
	b.decrypter = nil
	b.localHandshake = HandshakePacket{}
	b.remoteProcessID = ProcessID{}
}

func clearKeys(keys *Keys) {
	clear(keys.ReadKey[:])
	clear(keys.ReadIV[:])
	clear(keys.WriteKey[:])
	clear(keys.WriteIV[:])
}

func processPattern(endpoint netip.AddrPort) ProcessID {
	processID := ProcessID{Port: endpoint.Port()}
	if address := endpoint.Addr().Unmap(); address.Is4() {
		ipv4 := address.As4()
		processID.IP = binary.BigEndian.Uint32(ipv4[:])
	}
	return processID
}

// BlockingClientLink is a synchronous diagnostic link over one established
// stream. It has no reader goroutine or pooling policy and is not safe for
// concurrent use.
type BlockingClientLink struct {
	conn           net.Conn
	bootstrap      *ClientBootstrap
	inbox          []Frame
	readBuf        []byte
	pendingReadErr error
}

// String prevents accidental disclosure through the enclosed bootstrap and
// buffered encrypted or plaintext data.
func (BlockingClientLink) String() string {
	return "middleend.BlockingClientLink{redacted}"
}

// GoString prevents accidental disclosure through the enclosed bootstrap and
// buffered encrypted or plaintext data.
func (BlockingClientLink) GoString() string {
	return "middleend.BlockingClientLink{redacted}"
}

// BootstrapBlocking writes the client nonce and drives the bilateral
// handshake. Any error or context cancellation closes conn.
func BootstrapBlocking(ctx context.Context, conn net.Conn, bootstrap *ClientBootstrap) (*BlockingClientLink, error) {
	if ctx == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, errors.New("bootstrap Middle-End link: nil context")
	}
	if conn == nil || bootstrap == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, errors.New("bootstrap Middle-End link: nil connection or bootstrap")
	}
	link := &BlockingClientLink{
		conn:      conn,
		bootstrap: bootstrap,
		readBuf:   make([]byte, 32<<10),
	}
	initial, err := bootstrap.Start()
	if err != nil {
		return nil, link.closeWithFailure(err)
	}
	if err := link.writeContext(ctx, initial); err != nil {
		return nil, err
	}
	for !bootstrap.Ready() {
		if err := link.readOnce(ctx); err != nil {
			return nil, err
		}
	}
	return link, nil
}

// WritePayload encodes and writes one complete RPC payload.
func (l *BlockingClientLink) WritePayload(ctx context.Context, payload []byte) error {
	if l == nil || l.conn == nil || l.bootstrap == nil {
		return ErrBootstrapState
	}
	wire, err := l.bootstrap.Encode(payload)
	if err != nil {
		_ = l.Close()
		return err
	}
	return l.writeContext(ctx, wire)
}

// ReadFrame returns the next complete RPC frame.
func (l *BlockingClientLink) ReadFrame(ctx context.Context) (Frame, error) {
	if l == nil || l.conn == nil || l.bootstrap == nil {
		return Frame{}, ErrBootstrapState
	}
	for len(l.inbox) == 0 {
		if err := l.readOnce(ctx); err != nil {
			return Frame{}, err
		}
	}
	frame := l.inbox[0]
	l.inbox[0] = Frame{}
	l.inbox = l.inbox[1:]
	if len(l.inbox) == 0 {
		l.inbox = nil
	}
	return frame, nil
}

// Ping sends one RPC_PING and requires the next application frame to be the
// exact corresponding RPC_PONG. A failure closes the link.
func (l *BlockingClientLink) Ping(ctx context.Context, id uint64) error {
	if err := l.WritePayload(ctx, (Ping{ID: id}).MarshalBinary()); err != nil {
		return err
	}
	frame, err := l.ReadFrame(ctx)
	if err != nil {
		return err
	}
	pong, err := ParsePong(frame.Payload)
	if err != nil {
		_ = l.Close()
		return fmt.Errorf("%w: %v", ErrUnexpectedPong, err)
	}
	if pong.ID != id {
		_ = l.Close()
		return fmt.Errorf("%w: ID does not match", ErrUnexpectedPong)
	}
	return nil
}

// Close closes the owned stream.
func (l *BlockingClientLink) Close() error {
	if l == nil || l.conn == nil {
		return nil
	}
	for index := range l.inbox {
		clear(l.inbox[index].Payload)
		l.inbox[index] = Frame{}
	}
	l.inbox = nil
	clear(l.readBuf)
	return l.closeConn()
}

func (l *BlockingClientLink) readOnce(ctx context.Context) error {
	if ctx == nil {
		return l.closeWithFailure(errors.New("read Middle-End link: nil context"))
	}
	if l.pendingReadErr != nil {
		return l.closeWithFailure(l.pendingReadErr)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = l.closeConn()
	})
	read, readErr := l.conn.Read(l.readBuf)
	causeBeforeStop := context.Cause(ctx)
	stopped := stopCancel()
	cause := cancellationCause(ctx, causeBeforeStop, stopped)

	if read > 0 {
		if err := l.processReadBytes(ctx, l.readBuf[:read]); err != nil {
			return l.closeWithFailure(err)
		}
	}
	if cause != nil {
		return l.closeWithFailure(fmt.Errorf("read Middle-End link: %w", cause))
	}
	if readErr != nil {
		terminalErr := fmt.Errorf("read Middle-End link: %w", readErr)
		if read > 0 {
			l.pendingReadErr = terminalErr
			return nil
		}
		return l.closeWithFailure(terminalErr)
	}
	if read == 0 {
		return l.closeWithFailure(fmt.Errorf("read Middle-End link: %w", io.ErrNoProgress))
	}
	return nil
}

func (l *BlockingClientLink) processReadBytes(ctx context.Context, data []byte) error {
	remaining := data
	for len(remaining) != 0 {
		consumed, update, err := l.bootstrap.Feed(remaining)
		if err != nil {
			return err
		}
		if consumed == 0 {
			return io.ErrNoProgress
		}
		remaining = remaining[consumed:]
		if len(update.Outbound) != 0 {
			if err := l.writeContext(ctx, update.Outbound); err != nil {
				return err
			}
		}
		l.inbox = append(l.inbox, update.Frames...)
	}
	return nil
}

func (l *BlockingClientLink) writeContext(ctx context.Context, wire []byte) error {
	if ctx == nil {
		return l.closeWithFailure(errors.New("write Middle-End link: nil context"))
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = l.closeConn()
	})
	err := writeAll(l.conn, wire)
	causeBeforeStop := context.Cause(ctx)
	stopped := stopCancel()
	cause := cancellationCause(ctx, causeBeforeStop, stopped)
	if cause != nil {
		return l.closeWithFailure(fmt.Errorf("write Middle-End link: %w", cause))
	}
	if err != nil {
		return l.closeWithFailure(fmt.Errorf("write Middle-End link: %w", err))
	}
	return nil
}

func (l *BlockingClientLink) closeWithFailure(err error) error {
	if l != nil && l.bootstrap != nil {
		err = l.bootstrap.failTransport(err)
	}
	_ = l.Close()
	return err
}

func (l *BlockingClientLink) closeConn() error {
	return l.conn.Close()
}

func cancellationCause(ctx context.Context, beforeStop error, stopped bool) error {
	if beforeStop != nil {
		return beforeStop
	}
	if stopped {
		return nil
	}
	if afterStop := context.Cause(ctx); afterStop != nil {
		return afterStop
	}
	// A failed stop means the cancellation callback started. Context records
	// its cause before starting callbacks, but keep the error non-nil even for
	// a non-conforming Context implementation.
	return context.Canceled
}
