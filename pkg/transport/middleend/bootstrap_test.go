package middleend

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

var (
	bootstrapTestServer = netip.MustParseAddrPort("192.0.2.10:443")
	bootstrapTestClient = netip.MustParseAddrPort("198.51.100.10:32000")
	bootstrapTestSecret = bytes.Repeat([]byte{0x31}, MinimumSecretSize)
)

func TestClientBootstrapFragmentationCoalescingAndCRC32C(t *testing.T) {
	client, initial := newStartedTestBootstrap(t)
	server := newTestServerState(t, initial)

	var clientHandshake []byte
	for _, part := range fragmentBytes(server.nonceWire, 1) {
		consumed, update, err := client.Feed(part)
		if err != nil {
			t.Fatalf("Feed server nonce fragment: %v", err)
		}
		if consumed != len(part) {
			t.Fatalf("nonce consumed = %d, want %d", consumed, len(part))
		}
		clientHandshake = append(clientHandshake, update.Outbound...)
	}
	if len(clientHandshake) == 0 {
		t.Fatal("client did not emit encrypted handshake")
	}
	server.acceptClientHandshake(t, clientHandshake)

	serverHandshake := server.encodeHandshake(t, HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: ProcessID{IP: 0x08080808, Port: 443, PID: 71, Uptime: 12345},
		Peer:   testLocalProcessID(),
	})
	pongWire := server.encodePayload(t, (Pong{ID: 0x123456789abcdef0}).MarshalBinary())
	coalesced := append(serverHandshake, pongWire...)

	var frames []Frame
	readyTransitions := 0
	for _, part := range fragmentPattern(coalesced, []int{3, 1, 17, 2, 29}) {
		for len(part) != 0 {
			consumed, update, err := client.Feed(part)
			if err != nil {
				t.Fatalf("Feed encrypted stream: %v", err)
			}
			if consumed == 0 {
				t.Fatal("encrypted Feed made no progress")
			}
			part = part[consumed:]
			if update.BecameReady {
				readyTransitions++
			}
			frames = append(frames, update.Frames...)
		}
	}
	if !client.Ready() || readyTransitions != 1 {
		t.Fatalf("ready = %t, transitions = %d", client.Ready(), readyTransitions)
	}
	if len(frames) != 1 {
		t.Fatalf("decoded frames = %d, want 1", len(frames))
	}
	pong, err := ParsePong(frames[0].Payload)
	if err != nil || pong.ID != 0x123456789abcdef0 {
		t.Fatalf("decoded pong = %+v, %v", pong, err)
	}
	if got := client.encoder.ChecksumMode(); got != ChecksumCRC32C {
		t.Fatalf("outbound checksum = %d, want CRC32C", got)
	}
	if got := client.decoder.ChecksumMode(); got != ChecksumCRC32C {
		t.Fatalf("inbound checksum = %d, want CRC32C", got)
	}
	if err := client.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

func TestClientBootstrapRejectsHandshakeFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload func(*testing.T, HandshakePacket) []byte
		mutate  func([]byte)
		want    error
	}{
		{
			name: "wrong peer process ID",
			payload: func(t *testing.T, handshake HandshakePacket) []byte {
				handshake.Peer.PID++
				return mustMarshalHandshake(t, handshake)
			},
			want: ErrProcessIDMismatch,
		},
		{
			name: "invalid low-byte flag",
			payload: func(t *testing.T, handshake HandshakePacket) []byte {
				wire := mustMarshalHandshake(t, handshake)
				binary.LittleEndian.PutUint32(wire[4:8], 1)
				return wire
			},
			want: ErrInvalidHandshake,
		},
		{
			name: "bad frame checksum",
			payload: func(t *testing.T, handshake HandshakePacket) []byte {
				return mustMarshalHandshake(t, handshake)
			},
			mutate: func(frame []byte) {
				binary.LittleEndian.PutUint32(frame[len(frame)-4:], 0)
			},
			want: ErrChecksumMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, initial := newStartedTestBootstrap(t)
			server := newTestServerState(t, initial)
			_, update, err := client.Feed(server.nonceWire)
			if err != nil {
				t.Fatalf("Feed nonce: %v", err)
			}
			server.acceptClientHandshake(t, update.Outbound)

			handshake := HandshakePacket{
				Flags:  HandshakeFlagCRC32C,
				Sender: ProcessID{IP: 0x08080808, Port: 443, PID: 71, Uptime: 12345},
				Peer:   testLocalProcessID(),
			}
			payload := test.payload(t, handshake)
			frame, err := EncodeFrame(-1, payload, ChecksumCRC32)
			if err != nil {
				t.Fatalf("EncodeFrame: %v", err)
			}
			if test.mutate != nil {
				test.mutate(frame)
			}
			wire, err := server.encrypter.Encrypt(frame)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			_, _, err = client.Feed(wire)
			if !errors.Is(err, test.want) {
				t.Fatalf("Feed error = %v, want %v", err, test.want)
			}
			if client.Ready() {
				t.Fatal("failed bootstrap reports ready")
			}
			if _, _, nextErr := client.Feed(nil); !errors.Is(nextErr, test.want) {
				t.Fatalf("permanent error = %v, want %v", nextErr, test.want)
			}
		})
	}
}

func TestClientBootstrapRejectsNonceFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{
			name: "selector",
			mutate: func(frame []byte) {
				binary.LittleEndian.PutUint32(frame[12:16], 2)
				recomputeFrameCRC32(frame)
			},
			want: ErrKeySelector,
		},
		{
			name: "timestamp",
			mutate: func(frame []byte) {
				binary.LittleEndian.PutUint32(frame[20:24], uint32(1700000100))
				recomputeFrameCRC32(frame)
			},
			want: ErrTimestampSkew,
		},
		{
			name: "crc",
			mutate: func(frame []byte) {
				frame[len(frame)-1] ^= 0xff
			},
			want: ErrChecksumMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, initial := newStartedTestBootstrap(t)
			server := newTestServerState(t, initial)
			wire := slices.Clone(server.nonceWire)
			test.mutate(wire)
			_, _, err := client.Feed(wire)
			if !errors.Is(err, test.want) {
				t.Fatalf("Feed error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestBlockingClientLinkPingAndFailureClose(t *testing.T) {
	tests := []struct {
		name       string
		pongOffset uint64
		want       error
	}{
		{name: "success"},
		{name: "wrong pong", pongOffset: 1, want: ErrUnexpectedPong},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- serveFakeMiddleEnd(serverConn, test.pongOffset)
			}()

			bootstrap := newTestBootstrap(t)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			link, err := BootstrapBlocking(ctx, clientConn, bootstrap)
			if err != nil {
				t.Fatalf("BootstrapBlocking: %v", err)
			}
			err = link.Ping(ctx, 0x1020304050607080)
			if !errors.Is(err, test.want) {
				t.Fatalf("Ping error = %v, want %v", err, test.want)
			}
			_ = link.Close()
			if serverErr := <-serverDone; serverErr != nil {
				t.Fatalf("fake server: %v", serverErr)
			}
		})
	}
}

func TestBlockingClientLinkDirectTCPFlow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- serveFakeMiddleEnd(conn, 0)
	}()
	connection, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	runBlockingTestProbe(t, connection)
	if err := <-serverDone; err != nil {
		t.Fatalf("fake direct server: %v", err)
	}
}

func TestBlockingClientLinkStrictSOCKS5Flow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- serveFakeSOCKS5MiddleEnd(conn)
	}()
	dialer, err := NewSOCKS5Dialer(listener.Addr().String(), nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	conn, bound, err := dialer.DialContext(t.Context(), bootstrapTestServer.String())
	if err != nil {
		t.Fatalf("SOCKS5 DialContext: %v", err)
	}
	serverAddr, clientAddr, err := SOCKS5AddressTuple(bootstrapTestServer, bound)
	if err != nil {
		t.Fatalf("SOCKS5AddressTuple: %v", err)
	}
	if serverAddr != bootstrapTestServer || clientAddr != bootstrapTestClient {
		t.Fatalf("SOCKS tuple = %s/%s", serverAddr, clientAddr)
	}
	runBlockingTestProbe(t, conn)
	if err := <-serverDone; err != nil {
		t.Fatalf("fake SOCKS5 server: %v", err)
	}
}

func TestBootstrapBlockingCancellationClosesConnection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverObservedClose := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		initial := make([]byte, NoncePacketSize+FullFrameOverhead)
		if _, err := io.ReadFull(serverConn, initial); err != nil {
			serverObservedClose <- err
			return
		}
		var one [1]byte
		_, err := serverConn.Read(one[:])
		serverObservedClose <- err
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err := BootstrapBlocking(ctx, clientConn, newTestBootstrap(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("BootstrapBlocking error = %v, want deadline", err)
	}
	if closeErr := <-serverObservedClose; closeErr == nil {
		t.Fatal("server did not observe client close")
	}
}

func TestBootstrapBlockingProtocolFailuresCloseConnection(t *testing.T) {
	tests := []struct {
		name string
		mode fakeHandshakeFailure
		want error
	}{
		{name: "wrong PID", mode: fakeWrongPID, want: ErrProcessIDMismatch},
		{name: "wrong flags", mode: fakeWrongFlags, want: ErrInvalidHandshake},
		{name: "wrong CRC", mode: fakeWrongCRC, want: ErrChecksumMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- serveFakeHandshakeFailure(serverConn, test.mode)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			_, err := BootstrapBlocking(ctx, clientConn, newTestBootstrap(t))
			if !errors.Is(err, test.want) {
				t.Fatalf("BootstrapBlocking error = %v, want %v", err, test.want)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("fake failure server: %v", err)
			}
		})
	}
}

func TestClientBootstrapFinishRejectsIncompleteStages(t *testing.T) {
	bootstrap := newTestBootstrap(t)
	if err := bootstrap.Finish(); !errors.Is(err, ErrBootstrapIncomplete) {
		t.Fatalf("Finish before Start = %v", err)
	}
	bootstrap = newTestBootstrap(t)
	if _, err := bootstrap.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := bootstrap.Finish(); !errors.Is(err, ErrBootstrapIncomplete) {
		t.Fatalf("Finish before nonce = %v", err)
	}
}

func TestClientBootstrapInputValidation(t *testing.T) {
	config := testBootstrapConfig()
	config.ClientTimestamp = 0
	if _, err := NewClientBootstrap(config); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("zero timestamp error = %v", err)
	}
	config = testBootstrapConfig()
	config.LocalProcessID.PID = 0
	if _, err := NewClientBootstrap(config); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("zero PID error = %v", err)
	}
	bootstrap := newTestBootstrap(t)
	if _, _, err := bootstrap.Feed(nil); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("Feed before Start error = %v", err)
	}
	if _, err := bootstrap.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := bootstrap.Start(); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("second Start error = %v", err)
	}
	if _, err := bootstrap.Encode((Ping{ID: 1}).MarshalBinary()); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("Encode before ready error = %v", err)
	}
}

type testServerState struct {
	nonceWire []byte
	encoder   *FrameEncoder
	decoder   *FrameDecoder
	encrypter *CBCEncrypter
	decrypter *CBCDecrypter
	peer      HandshakePacket
}

func newTestServerState(t *testing.T, clientInitial []byte) *testServerState {
	t.Helper()
	frame, err := DecodeFrame(clientInitial, -2, ChecksumCRC32, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("decode client nonce frame: %v", err)
	}
	clientNonce, err := ParseNoncePacket(frame.Payload)
	if err != nil {
		t.Fatalf("parse client nonce: %v", err)
	}
	serverNonce := NoncePacket{
		KeySelector: clientNonce.KeySelector,
		Timestamp:   clientNonce.Timestamp,
		Nonce:       [16]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf},
	}
	noncePayload, err := serverNonce.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal server nonce: %v", err)
	}
	nonceWire, err := EncodeFrame(-2, noncePayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("encode server nonce: %v", err)
	}
	params := KDFParams{
		ServerNonce:     serverNonce.Nonce,
		ClientNonce:     clientNonce.Nonce,
		ClientTimestamp: clientNonce.Timestamp,
		ServerAddr:      bootstrapTestServer,
		ClientAddr:      bootstrapTestClient,
		Secret:          bootstrapTestSecret,
	}
	keys, err := DeriveKeys(params, RoleServer)
	if err != nil {
		t.Fatalf("derive server keys: %v", err)
	}
	encrypter, err := NewCBCEncrypter(keys.WriteKey[:], keys.WriteIV[:])
	if err != nil {
		t.Fatalf("server encrypter: %v", err)
	}
	decrypter, err := NewCBCDecrypter(keys.ReadKey[:], keys.ReadIV[:])
	if err != nil {
		t.Fatalf("server decrypter: %v", err)
	}
	encoder, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("server encoder: %v", err)
	}
	decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("server decoder: %v", err)
	}
	return &testServerState{
		nonceWire: nonceWire,
		encoder:   encoder,
		decoder:   decoder,
		encrypter: encrypter,
		decrypter: decrypter,
	}
}

func (s *testServerState) acceptClientHandshake(t *testing.T, wire []byte) {
	t.Helper()
	consumed, plaintext := s.decrypter.Feed(wire)
	if consumed != len(wire) {
		t.Fatalf("server decrypter consumed %d of %d", consumed, len(wire))
	}
	if fed, err := s.decoder.Feed(plaintext); err != nil || fed != len(plaintext) {
		t.Fatalf("server decoder Feed = %d, %v", fed, err)
	}
	frame, ok, err := s.decoder.Next()
	if err != nil || !ok {
		t.Fatalf("server decoder Next = %t, %v", ok, err)
	}
	peer, err := ParseHandshakePacket(frame.Payload)
	if err != nil {
		t.Fatalf("parse client handshake: %v", err)
	}
	s.peer = peer
}

func (s *testServerState) encodeHandshake(t *testing.T, handshake HandshakePacket) []byte {
	t.Helper()
	payload, err := handshake.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal server handshake: %v", err)
	}
	frame, err := s.encoder.Encode(payload)
	if err != nil {
		t.Fatalf("encode server handshake: %v", err)
	}
	wire, err := s.encrypter.Encrypt(frame)
	if err != nil {
		t.Fatalf("encrypt server handshake: %v", err)
	}
	if err := s.decoder.ApplyPeerHandshake(s.peer, handshake); err != nil {
		t.Fatalf("apply server decoder handshake: %v", err)
	}
	if err := s.encoder.ApplyPeerHandshake(s.peer); err != nil {
		t.Fatalf("apply server encoder handshake: %v", err)
	}
	return wire
}

func (s *testServerState) encodePayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	frame, err := s.encoder.Encode(payload)
	if err != nil {
		t.Fatalf("encode server payload: %v", err)
	}
	wire, err := s.encrypter.Encrypt(frame)
	if err != nil {
		t.Fatalf("encrypt server payload: %v", err)
	}
	return wire
}

func newTestBootstrap(t *testing.T) *ClientBootstrap {
	t.Helper()
	bootstrap, err := NewClientBootstrap(testBootstrapConfig())
	if err != nil {
		t.Fatalf("NewClientBootstrap: %v", err)
	}
	return bootstrap
}

func newStartedTestBootstrap(t *testing.T) (*ClientBootstrap, []byte) {
	t.Helper()
	bootstrap := newTestBootstrap(t)
	initial, err := bootstrap.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return bootstrap, initial
}

func testBootstrapConfig() ClientBootstrapConfig {
	return ClientBootstrapConfig{
		Secret:          bootstrapTestSecret,
		ServerAddr:      bootstrapTestServer,
		ClientAddr:      bootstrapTestClient,
		LocalProcessID:  testLocalProcessID(),
		ClientTimestamp: 1700000000,
		NonceSource:     bytes.NewReader([]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}),
	}
}

func testLocalProcessID() ProcessID {
	return ProcessID{IP: 0x01010101, PID: 42, Uptime: 1699999000}
}

func serveFakeMiddleEnd(conn net.Conn, pongOffset uint64) error {
	defer conn.Close()
	clientNonceWire := make([]byte, NoncePacketSize+FullFrameOverhead)
	if _, err := io.ReadFull(conn, clientNonceWire); err != nil {
		return fmt.Errorf("read client nonce: %w", err)
	}
	server, err := newRuntimeTestServer(clientNonceWire)
	if err != nil {
		return err
	}
	if err := writeFragments(conn, server.nonceWire, []int{1, 7, 2, 19}); err != nil {
		return fmt.Errorf("write server nonce: %w", err)
	}
	clientHandshake := make([]byte, 48)
	if _, err := io.ReadFull(conn, clientHandshake); err != nil {
		return fmt.Errorf("read client handshake: %w", err)
	}
	if err := server.acceptClientHandshakeRuntime(clientHandshake); err != nil {
		return err
	}
	serverHandshake, err := server.encodeHandshakeRuntime(HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: ProcessID{IP: 0x08080808, Port: 443, PID: 71, Uptime: 12345},
		Peer:   testLocalProcessID(),
	})
	if err != nil {
		return err
	}
	if err := writeFragments(conn, serverHandshake, []int{5, 1, 13}); err != nil {
		return fmt.Errorf("write server handshake: %w", err)
	}
	clientPing := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientPing); err != nil {
		return fmt.Errorf("read client ping: %w", err)
	}
	pingFrame, err := server.decodePayloadRuntime(clientPing)
	if err != nil {
		return err
	}
	ping, err := ParsePing(pingFrame.Payload)
	if err != nil {
		return fmt.Errorf("parse client ping: %w", err)
	}
	pongWire, err := server.encodePayloadRuntime((Pong{ID: ping.ID + pongOffset}).MarshalBinary())
	if err != nil {
		return err
	}
	if err := writeFragments(conn, pongWire, []int{2, 3, 1, 11}); err != nil {
		return fmt.Errorf("write server pong: %w", err)
	}
	var one [1]byte
	_, err = conn.Read(one[:])
	if err == nil {
		return errors.New("client did not close after probe")
	}
	return nil
}

func serveFakeSOCKS5MiddleEnd(conn net.Conn) error {
	var greeting [3]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if greeting != [3]byte{socks5Version, 1, socks5AuthNone} {
		return fmt.Errorf("unexpected SOCKS5 greeting %x", greeting)
	}
	if err := writeAll(conn, []byte{socks5Version, socks5AuthNone}); err != nil {
		return fmt.Errorf("write SOCKS5 method: %w", err)
	}
	var request [10]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return fmt.Errorf("read SOCKS5 CONNECT: %w", err)
	}
	serverIPv4 := bootstrapTestServer.Addr().As4()
	wantRequest := [10]byte{socks5Version, socks5CommandConnect, socks5Reserved, byte(SOCKS5AddressIPv4), serverIPv4[0], serverIPv4[1], serverIPv4[2], serverIPv4[3], byte(bootstrapTestServer.Port() >> 8), byte(bootstrapTestServer.Port())}
	if request != wantRequest {
		return fmt.Errorf("unexpected SOCKS5 CONNECT %x", request)
	}
	clientIPv4 := bootstrapTestClient.Addr().As4()
	reply := []byte{socks5Version, socks5ReplySuccess, socks5Reserved, byte(SOCKS5AddressIPv4), clientIPv4[0], clientIPv4[1], clientIPv4[2], clientIPv4[3], byte(bootstrapTestClient.Port() >> 8), byte(bootstrapTestClient.Port())}
	if err := writeAll(conn, reply); err != nil {
		return fmt.Errorf("write SOCKS5 CONNECT reply: %w", err)
	}
	return serveFakeMiddleEnd(conn, 0)
}

func runBlockingTestProbe(t *testing.T, conn net.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	link, err := BootstrapBlocking(ctx, conn, newTestBootstrap(t))
	if err != nil {
		t.Fatalf("BootstrapBlocking: %v", err)
	}
	if err := link.Ping(ctx, 0x1020304050607080); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

type runtimeTestServer struct {
	*testServerState
}

type fakeHandshakeFailure uint8

const (
	fakeWrongPID fakeHandshakeFailure = iota + 1
	fakeWrongFlags
	fakeWrongCRC
)

func serveFakeHandshakeFailure(conn net.Conn, mode fakeHandshakeFailure) error {
	defer conn.Close()
	clientNonceWire := make([]byte, NoncePacketSize+FullFrameOverhead)
	if _, err := io.ReadFull(conn, clientNonceWire); err != nil {
		return fmt.Errorf("read client nonce: %w", err)
	}
	server, err := newRuntimeTestServer(clientNonceWire)
	if err != nil {
		return err
	}
	if err := writeAll(conn, server.nonceWire); err != nil {
		return fmt.Errorf("write server nonce: %w", err)
	}
	clientHandshake := make([]byte, 48)
	if _, err := io.ReadFull(conn, clientHandshake); err != nil {
		return fmt.Errorf("read client handshake: %w", err)
	}
	if err := server.acceptClientHandshakeRuntime(clientHandshake); err != nil {
		return err
	}
	handshake := HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: ProcessID{IP: 0x08080808, Port: 443, PID: 71, Uptime: 12345},
		Peer:   testLocalProcessID(),
	}
	if mode == fakeWrongPID {
		handshake.Peer.PID++
	}
	payload, err := handshake.MarshalBinary()
	if err != nil {
		return err
	}
	if mode == fakeWrongFlags {
		binary.LittleEndian.PutUint32(payload[4:8], 1)
	}
	frame, err := EncodeFrame(-1, payload, ChecksumCRC32)
	if err != nil {
		return err
	}
	if mode == fakeWrongCRC {
		frame[len(frame)-1] ^= 0xff
	}
	wire, err := server.encrypter.Encrypt(frame)
	if err != nil {
		return err
	}
	if err := writeAll(conn, wire); err != nil {
		return err
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err == nil {
		return errors.New("client did not close after handshake failure")
	}
	return nil
}

func newRuntimeTestServer(initial []byte) (*runtimeTestServer, error) {
	frame, err := DecodeFrame(initial, -2, ChecksumCRC32, MaxMEFrameSize)
	if err != nil {
		return nil, err
	}
	clientNonce, err := ParseNoncePacket(frame.Payload)
	if err != nil {
		return nil, err
	}
	serverNonce := NoncePacket{KeySelector: clientNonce.KeySelector, Timestamp: clientNonce.Timestamp, Nonce: [16]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}}
	payload, err := serverNonce.MarshalBinary()
	if err != nil {
		return nil, err
	}
	nonceWire, err := EncodeFrame(-2, payload, ChecksumCRC32)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveKeys(KDFParams{ServerNonce: serverNonce.Nonce, ClientNonce: clientNonce.Nonce, ClientTimestamp: clientNonce.Timestamp, ServerAddr: bootstrapTestServer, ClientAddr: bootstrapTestClient, Secret: bootstrapTestSecret}, RoleServer)
	if err != nil {
		return nil, err
	}
	encrypter, err := NewCBCEncrypter(keys.WriteKey[:], keys.WriteIV[:])
	if err != nil {
		return nil, err
	}
	decrypter, err := NewCBCDecrypter(keys.ReadKey[:], keys.ReadIV[:])
	if err != nil {
		return nil, err
	}
	encoder, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		return nil, err
	}
	decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		return nil, err
	}
	return &runtimeTestServer{&testServerState{nonceWire: nonceWire, encoder: encoder, decoder: decoder, encrypter: encrypter, decrypter: decrypter}}, nil
}

func (s *runtimeTestServer) acceptClientHandshakeRuntime(wire []byte) error {
	_, plaintext := s.decrypter.Feed(wire)
	if _, err := s.decoder.Feed(plaintext); err != nil {
		return err
	}
	frame, ok, err := s.decoder.Next()
	if err != nil || !ok {
		return fmt.Errorf("decode client handshake: complete=%t: %w", ok, err)
	}
	s.peer, err = ParseHandshakePacket(frame.Payload)
	return err
}

func (s *runtimeTestServer) encodeHandshakeRuntime(handshake HandshakePacket) ([]byte, error) {
	payload, err := handshake.MarshalBinary()
	if err != nil {
		return nil, err
	}
	frame, err := s.encoder.Encode(payload)
	if err != nil {
		return nil, err
	}
	wire, err := s.encrypter.Encrypt(frame)
	if err != nil {
		return nil, err
	}
	if err := s.decoder.ApplyPeerHandshake(s.peer, handshake); err != nil {
		return nil, err
	}
	if err := s.encoder.ApplyPeerHandshake(s.peer); err != nil {
		return nil, err
	}
	return wire, nil
}

func (s *runtimeTestServer) decodePayloadRuntime(wire []byte) (Frame, error) {
	_, plaintext := s.decrypter.Feed(wire)
	if _, err := s.decoder.Feed(plaintext); err != nil {
		return Frame{}, err
	}
	frame, ok, err := s.decoder.Next()
	if err != nil {
		return Frame{}, err
	}
	if !ok {
		return Frame{}, ErrIncompleteFrame
	}
	return frame, nil
}

func (s *runtimeTestServer) encodePayloadRuntime(payload []byte) ([]byte, error) {
	frame, err := s.encoder.Encode(payload)
	if err != nil {
		return nil, err
	}
	return s.encrypter.Encrypt(frame)
}

func fragmentBytes(data []byte, size int) [][]byte {
	fragments := make([][]byte, 0, (len(data)+size-1)/size)
	for len(data) != 0 {
		take := min(size, len(data))
		fragments = append(fragments, data[:take])
		data = data[take:]
	}
	return fragments
}

func fragmentPattern(data []byte, pattern []int) [][]byte {
	var fragments [][]byte
	for index := 0; len(data) != 0; index++ {
		take := min(pattern[index%len(pattern)], len(data))
		fragments = append(fragments, data[:take])
		data = data[take:]
	}
	return fragments
}

func writeFragments(writer io.Writer, data []byte, pattern []int) error {
	for _, fragment := range fragmentPattern(data, pattern) {
		if err := writeAll(writer, fragment); err != nil {
			return err
		}
	}
	return nil
}

func recomputeFrameCRC32(frame []byte) {
	binary.LittleEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
}

func mustMarshalHandshake(t testing.TB, handshake HandshakePacket) []byte {
	t.Helper()
	wire, err := handshake.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return wire
}
