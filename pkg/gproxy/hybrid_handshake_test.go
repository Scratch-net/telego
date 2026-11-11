package gproxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/tlsfront"
	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// The hybrid ServerHello from a real TLS 1.3 mask host must echo the client
// session ID and validate with the client digest check.
func TestHybridServerHelloFromRealMaskEchoesSessionAndValidates(t *testing.T) {
	mask := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	mask.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	mask.StartTLS()
	t.Cleanup(mask.Close)
	address := mask.Listener.Addr().(*net.TCPAddr)
	fetcher := tlsfront.NewServerHelloFetcher(address.IP.String(), address.Port)
	if err := fetcher.Refresh(); err != nil {
		t.Fatal(err)
	}

	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{})
	handler.serverHelloFetcher = fetcher

	var responses [][]byte
	for _, session := range [][]byte{bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)} {
		payload := buildValidClientHello(key, "example.com", session)
		connection := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.SetState(StateReadTLSPayload)
		ctx.tlsPayloadLen = len(payload)
		connection.SetContext(ctx)
		connection.SetReadData(buildTLSRecord(faketls.RecordTypeHandshake, payload))
		handler.handleTLSPayload(connection, ctx)
		if ctx.State() != StateReadO2Frame {
			t.Fatalf("state = %v, want ReadO2Frame", ctx.State())
		}
		response := connection.GetWrittenData()

		echoed := response[44 : 44+int(response[43])]
		if !bytes.Equal(echoed, session) {
			t.Fatalf("session echo = %x, want %x", echoed, session)
		}
		clientRandom := payload[6:38]
		check := bytes.Clone(response)
		clear(check[faketls.WelcomePacketRandomOffset : faketls.WelcomePacketRandomOffset+32])
		mac := hmac.New(sha256.New, key)
		mac.Write(clientRandom)
		mac.Write(check)
		if !bytes.Equal(mac.Sum(nil), response[faketls.WelcomePacketRandomOffset:faketls.WelcomePacketRandomOffset+32]) {
			t.Fatal("client digest check failed on hybrid ServerHello")
		}
		recordEnd := 5 + int(binary.BigEndian.Uint16(response[3:5]))
		responses = append(responses, response[:recordEnd])
	}
	// Same record length, different key share.
	if len(responses[0]) != len(responses[1]) {
		t.Fatalf("ServerHello lengths differ: %d and %d", len(responses[0]), len(responses[1]))
	}
	if bytes.Equal(responses[0][76:], responses[1][76:]) {
		t.Fatal("ServerHello extensions are identical across connections")
	}
}
