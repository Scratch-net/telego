package gproxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

func signReplayClientHello(payload, key []byte, timestamp uint32) []byte {
	result := bytes.Clone(payload)
	clear(result[6:38])
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(buildTLSRecord(faketls.RecordTypeHandshake, result))
	random := mac.Sum(nil)
	binary.LittleEndian.PutUint32(random[28:], binary.LittleEndian.Uint32(random[28:])^timestamp)
	copy(result[6:38], random)
	return result
}

func handleReplayClientHello(handler *ProxyHandler, payload []byte) (ConnState, gnet.Action) {
	conn := newTestMockGnetConn()
	ctx := NewConnContext()
	conn.SetContext(ctx)
	conn.SetReadData(buildTLSRecord(faketls.RecordTypeHandshake, payload))
	action := handler.handleDetectProtocol(conn, ctx)
	return ctx.State(), action
}

func TestFakeTLSReplayIdentity(t *testing.T) {
	key := []byte("0123456789abcdef")
	const host = "example.com"
	for _, test := range []struct {
		name      string
		sessionID []byte
	}{
		{name: "empty-session"},
		{name: "reused-session", sessionID: bytes.Repeat([]byte{3}, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := buildValidClientHello(key, host, test.sessionID)
			distinct := bytes.Clone(first)
			distinct[42+len(test.sessionID)] = 2 // Change the first offered TLS cipher.
			distinct = signReplayClientHello(distinct, key, uint32(time.Now().Unix()))
			variant := bytes.Clone(first)
			variant[34] ^= 1 // Change one timestamp bit without signing again.
			handler := NewProxyHandler(&Config{
				Secrets:           []Secret{{Name: "test", Key: key, Host: host}},
				TimeSkewTolerance: time.Minute,
			}, &testLogger{})
			for i, payload := range [][]byte{first, distinct, first, distinct, variant} {
				hello, err := faketls.ParseClientHello(key, payload)
				if err != nil {
					t.Fatal(err)
				}
				if err := hello.Valid(host, time.Minute); err != nil {
					t.Fatal(err)
				}
				state, action := handleReplayClientHello(handler, payload)
				if i < 2 && (state != StateReadO2Frame || action != gnet.None) {
					t.Fatalf("distinct valid hello %d rejected: state=%v action=%v", i, state, action)
				}
				if i >= 2 && action != gnet.Close {
					t.Fatalf("replay %d admitted: state=%v action=%v", i, state, action)
				}
			}
		})
	}
}

func TestFakeTLSReplayInvalidHelloDoesNotPoison(t *testing.T) {
	key := []byte("0123456789abcdef")
	valid := buildValidClientHello(key, "example.com", bytes.Repeat([]byte{4}, 32))
	invalid := bytes.Clone(valid)
	invalid[42+32] ^= 1 // Alter an authenticated cipher-suite byte without signing.
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{})
	_, action := handleReplayClientHello(handler, invalid)
	if action != gnet.Close || handler.replayCache.Len() != 0 {
		t.Fatal("invalid authentication polluted replay state")
	}
	state, action := handleReplayClientHello(handler, valid)
	if action != gnet.None || state != StateReadO2Frame {
		t.Fatal("invalid attempt prevented valid hello")
	}
}

func TestFakeTLSReplayConcurrentTimestampVariants(t *testing.T) {
	key := []byte("0123456789abcdef")
	first := buildValidClientHello(key, "example.com", bytes.Repeat([]byte{5}, 32))
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{})
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			payload := bytes.Clone(first)
			payload[34] ^= byte(i)
			state, action := handleReplayClientHello(handler, payload)
			if state == StateReadO2Frame && action == gnet.None {
				admitted.Add(1)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 1 {
		t.Fatalf("concurrent admissions=%d; want one", admitted.Load())
	}
}
