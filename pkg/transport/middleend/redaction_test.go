package middleend

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestKeyAndNonceBearingFormattingIsRedacted(t *testing.T) {
	secret := bytes.Repeat([]byte{213}, MinimumSecretSize)
	nonce := [16]byte{}
	for index := range nonce {
		nonce[index] = 214
	}
	keys := Keys{}
	for index := range keys.ReadKey {
		keys.ReadKey[index] = 215
		keys.WriteKey[index] = 215
	}
	for index := range keys.ReadIV {
		keys.ReadIV[index] = 215
		keys.WriteIV[index] = 215
	}

	params := KDFParams{
		ServerNonce: nonce,
		ClientNonce: nonce,
		ServerAddr:  netip.MustParseAddrPort("192.0.2.1:443"),
		ClientAddr:  netip.MustParseAddrPort("198.51.100.2:32000"),
		Secret:      secret,
	}
	noncePacket := NoncePacket{KeySelector: 0xd5d5d5d5, Timestamp: 1, Nonce: nonce}
	config := ClientBootstrapConfig{
		Secret:          secret,
		ServerAddr:      params.ServerAddr,
		ClientAddr:      params.ClientAddr,
		LocalProcessID:  ProcessID{PID: 1, Uptime: 1},
		ClientTimestamp: 1,
		NonceSource:     bytes.NewReader(bytes.Repeat([]byte{214}, 16)),
	}
	bootstrap, err := NewClientBootstrap(config)
	if err != nil {
		t.Fatalf("NewClientBootstrap: %v", err)
	}
	encrypter, err := NewCBCEncrypter(keys.ReadKey[:], keys.ReadIV[:])
	if err != nil {
		t.Fatalf("NewCBCEncrypter: %v", err)
	}
	decrypter, err := NewCBCDecrypter(keys.ReadKey[:], keys.ReadIV[:])
	if err != nil {
		t.Fatalf("NewCBCDecrypter: %v", err)
	}
	cache := ArtifactCache{state: &artifactCacheState{}}
	cache.state.current.Store(&ArtifactSnapshot{secret: secret})
	link := BlockingClientLink{
		conn:      &staticNetConn{},
		bootstrap: bootstrap,
		inbox:     []Frame{{Payload: bytes.Repeat([]byte{216}, 16)}},
		readBuf:   bytes.Repeat([]byte{217}, 16),
	}

	type enclosing struct {
		Params    KDFParams
		Keys      Keys
		Nonce     NoncePacket
		Config    ClientBootstrapConfig
		Bootstrap ClientBootstrap
		Link      BlockingClientLink
		Cache     ArtifactCache
		Encrypter CBCEncrypter
		Decrypter CBCDecrypter
	}
	values := map[string]any{
		"KDF params value": params, "KDF params pointer": &params,
		"keys value": keys, "keys pointer": &keys,
		"nonce value": noncePacket, "nonce pointer": &noncePacket,
		"config value": config, "config pointer": &config,
		"bootstrap value": *bootstrap, "bootstrap pointer": bootstrap,
		"link value": link, "link pointer": &link,
		"cache value": cache, "cache pointer": &cache,
		"encrypter value": *encrypter, "encrypter pointer": encrypter,
		"decrypter value": *decrypter, "decrypter pointer": decrypter,
		"enclosing value": enclosing{
			Params: params, Keys: keys, Nonce: noncePacket, Config: config,
			Bootstrap: *bootstrap, Link: link, Cache: cache,
			Encrypter: *encrypter, Decrypter: *decrypter,
		},
	}
	for name, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if !strings.Contains(output, "redacted") {
				t.Fatalf("%s with %s was not visibly redacted: %s", name, format, output)
			}
			for _, marker := range []string{
				"213 213 213 213", "214 214 214 214", "215 215 215 215",
				"216 216 216 216", "217 217 217 217", "3587560917",
			} {
				if strings.Contains(output, marker) {
					t.Fatalf("%s with %s leaked marker %q: %s", name, format, marker, output)
				}
			}
			if len(output) > 1024 {
				t.Fatalf("%s with %s produced %d bytes", name, format, len(output))
			}
		}
	}

	for name, value := range map[string]any{
		"nil params": (*KDFParams)(nil), "nil keys": (*Keys)(nil),
		"nil nonce": (*NoncePacket)(nil), "nil config": (*ClientBootstrapConfig)(nil),
		"nil bootstrap": (*ClientBootstrap)(nil), "nil link": (*BlockingClientLink)(nil),
		"nil cache": (*ArtifactCache)(nil), "nil encrypter": (*CBCEncrypter)(nil),
		"nil decrypter": (*CBCDecrypter)(nil),
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, "213 213") || strings.Contains(output, "214 214") {
				t.Fatalf("%s with %s leaked data: %s", name, format, output)
			}
		}
	}
}

func TestBlockingClientLinkReadFrameReleasesConsumedSlot(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	link := &BlockingClientLink{
		conn:      &staticNetConn{},
		bootstrap: &ClientBootstrap{},
		inbox:     []Frame{{Sequence: 7, Payload: payload}},
	}
	backing := link.inbox
	frame, err := link.ReadFrame(t.Context())
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Sequence != 7 || !bytes.Equal(frame.Payload, []byte{1, 2, 3, 4}) {
		t.Fatalf("frame = %+v", frame)
	}
	if backing[0].Payload != nil || backing[0].Sequence != 0 {
		t.Fatalf("consumed backing slot retained frame: %+v", backing[0])
	}
	if link.inbox != nil {
		t.Fatalf("drained inbox retained backing storage: %#v", link.inbox)
	}
}

func TestBlockingClientLinkCloseClearsQueuedPayloads(t *testing.T) {
	first := bytes.Repeat([]byte{0xa1}, 16)
	second := bytes.Repeat([]byte{0xa2}, 16)
	readBuffer := bytes.Repeat([]byte{0xa3}, 16)
	connection := &staticNetConn{}
	link := &BlockingClientLink{
		conn:    connection,
		inbox:   []Frame{{Payload: first}, {Payload: second}},
		readBuf: readBuffer,
	}
	backing := link.inbox
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !allZero(first) || !allZero(second) || !allZero(readBuffer) {
		t.Fatal("Close retained queued payload or read-buffer bytes")
	}
	if backing[0].Sequence != 0 || backing[0].Payload != nil ||
		backing[1].Sequence != 0 || backing[1].Payload != nil || link.inbox != nil {
		t.Fatal("Close retained queued frame slots")
	}
	if !connection.closed {
		t.Fatal("Close did not close connection")
	}
}

func allZero(data []byte) bool {
	return bytes.Equal(data, make([]byte, len(data)))
}

type staticNetConn struct {
	closed bool
}

func (*staticNetConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*staticNetConn) Write(data []byte) (int, error)   { return len(data), nil }
func (c *staticNetConn) Close() error                   { c.closed = true; return nil }
func (*staticNetConn) LocalAddr() net.Addr              { return dummyNetAddr("local") }
func (*staticNetConn) RemoteAddr() net.Addr             { return dummyNetAddr("remote") }
func (*staticNetConn) SetDeadline(time.Time) error      { return nil }
func (*staticNetConn) SetReadDeadline(time.Time) error  { return nil }
func (*staticNetConn) SetWriteDeadline(time.Time) error { return nil }

type dummyNetAddr string

func (address dummyNetAddr) Network() string { return "test" }
func (address dummyNetAddr) String() string  { return string(address) }
