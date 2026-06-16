package faketls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// buildClientHelloPayload builds a minimal ClientHello handshake payload (the
// bytes after the 5-byte TLS record header) with the given extensions block. It
// returns the payload suitable for the extension-walk parsers.
func buildClientHelloPayload(t *testing.T, sessionID []byte, extensions []byte) []byte {
	t.Helper()
	body := []byte{}
	body = append(body, 0x03, 0x03)             // legacy_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, byte(len(sessionID)))   // session_id len
	body = append(body, sessionID...)           // session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: len 2, TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression: len 1, null
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(extensions)))
	body = append(body, extLen...)
	body = append(body, extensions...)

	payload := []byte{handshakeTypeClient, 0, 0, 0}
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(body))) // 3-byte len; high byte stays 0
	payload = append(payload, body...)
	return payload
}

// keyShareExt builds a key_share extension offering a single group with a
// key of the given length (zeros).
func keyShareExt(group uint16, keyLen int) []byte {
	entry := make([]byte, 4+keyLen)
	binary.BigEndian.PutUint16(entry[0:2], group)
	binary.BigEndian.PutUint16(entry[2:4], uint16(keyLen))
	list := make([]byte, 2+len(entry))
	binary.BigEndian.PutUint16(list[0:2], uint16(len(entry)))
	copy(list[2:], entry)
	ext := make([]byte, 4+len(list))
	binary.BigEndian.PutUint16(ext[0:2], 0x0033) // key_share
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(list)))
	copy(ext[4:], list)
	return ext
}

func TestClientOffersPQKeyShare(t *testing.T) {
	pq := buildClientHelloPayload(t, make([]byte, 32), keyShareExt(pqNamedGroup, 1216))
	if !clientOffersPQKeyShare(pq) {
		t.Fatal("expected PQ key_share to be detected")
	}

	classical := buildClientHelloPayload(t, make([]byte, 32), keyShareExt(0x001d, 32))
	if clientOffersPQKeyShare(classical) {
		t.Fatal("classical x25519 must not be detected as PQ")
	}

	// Truncated input must never panic (detection may flip to false once the
	// group bytes are cut off; either result is acceptable, a panic is not).
	for i := range pq {
		_ = clientOffersPQKeyShare(pq[:i])
	}
}

// findExtension locates an extension of extType inside a ServerHello handshake
// message and returns its body, or nil.
func findServerHelloExtension(t *testing.T, response []byte, extType uint16) []byte {
	t.Helper()
	// response: record header(5) + handshake header(4) + version(2) + random(32)
	// + session_id(1+n) + cipher(2) + comp(1) + ext_len(2) + extensions
	pos := 5 + 4 + 2 + 32
	sidLen := int(response[pos])
	pos += 1 + sidLen
	pos += 2 + 1 // cipher + compression
	extTotal := int(binary.BigEndian.Uint16(response[pos:]))
	pos += 2
	end := pos + extTotal
	for pos+4 <= end {
		et := binary.BigEndian.Uint16(response[pos:])
		el := int(binary.BigEndian.Uint16(response[pos+2:]))
		pos += 4
		if et == extType {
			return response[pos : pos+el]
		}
		pos += el
	}
	return nil
}

func TestSyntheticServerHelloPQKeyShare(t *testing.T) {
	secret := make([]byte, 16)
	helloPQ := &ClientHello{SessionID: make([]byte, 32), CipherSuite: 0x1301, OffersPQ: true}
	resp, err := BuildServerHello(secret, helloPQ)
	if err != nil {
		t.Fatal(err)
	}
	ks := findServerHelloExtension(t, resp, 0x0033)
	if ks == nil {
		t.Fatal("no key_share extension in ServerHello")
	}
	group := binary.BigEndian.Uint16(ks[0:2])
	keyLen := int(binary.BigEndian.Uint16(ks[2:4]))
	if group != pqNamedGroup {
		t.Fatalf("group = 0x%04x, want 0x11ec", group)
	}
	if keyLen != 1120 || len(ks) != 4+1120 {
		t.Fatalf("PQ key length = %d (ext body %d), want 1120 (1124)", keyLen, len(ks))
	}

	// Classical client still gets x25519.
	helloClassic := &ClientHello{SessionID: make([]byte, 32), CipherSuite: 0x1301}
	respC, err := BuildServerHello(secret, helloClassic)
	if err != nil {
		t.Fatal(err)
	}
	ksC := findServerHelloExtension(t, respC, 0x0033)
	if binary.BigEndian.Uint16(ksC[0:2]) != 0x001d {
		t.Fatal("classical client must get x25519 0x001d key_share")
	}

	// HMAC over the PQ response (random zeroed) must validate.
	check := make([]byte, len(resp))
	copy(check, resp)
	for i := range 32 {
		check[WelcomePacketRandomOffset+i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(helloPQ.Random[:])
	mac.Write(check)
	want := mac.Sum(nil)
	for i := range 32 {
		if resp[WelcomePacketRandomOffset+i] != want[i] {
			t.Fatal("server-random HMAC mismatch on PQ ServerHello")
		}
	}
}

// firstAppDataLen returns the payload length of the first ApplicationData (0x17)
// record in a TLS stream, or -1.
func firstAppDataLen(data []byte) int {
	pos := 0
	for pos+5 <= len(data) {
		rl := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
		if data[pos] == RecordTypeApplicationData {
			return rl
		}
		pos += 5 + rl
	}
	return -1
}

func TestFakeCertSize(t *testing.T) {
	secret := make([]byte, 16)
	hello := &ClientHello{SessionID: make([]byte, 32), CipherSuite: 0x1301}

	// Explicit size within a single record produces an exact-size AppData record.
	resp, err := BuildServerHelloWithOptions(secret, hello, &ServerHelloOptions{FakeCertSize: 2878})
	if err != nil {
		t.Fatal(err)
	}
	if got := firstAppDataLen(resp); got != 2878 {
		t.Fatalf("first AppData record = %d, want 2878", got)
	}

	// Below the clamp floor is raised to minFakeCertSize.
	resp2, err := BuildServerHelloWithOptions(secret, hello, &ServerHelloOptions{FakeCertSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := firstAppDataLen(resp2); got != minFakeCertSize {
		t.Fatalf("clamped AppData record = %d, want %d", got, minFakeCertSize)
	}
}

func TestClockOffsetAppliedInValid(t *testing.T) {
	defer clockOffsetSeconds.Store(0)

	// A ClientHello timestamped ~1 hour in the past is out of a 3s tolerance...
	past := time.Now().Add(-1 * time.Hour)
	hello := &ClientHello{Time: past}
	if err := hello.Valid("", 3*time.Second); err == nil {
		t.Fatal("expected timestamp out of range without correction")
	}

	// ...but a clock offset that says our local clock is 1 hour fast brings it in.
	clockOffsetSeconds.Store(-3600)
	if err := hello.Valid("", 3*time.Second); err != nil {
		t.Fatalf("expected valid with clock correction, got %v", err)
	}
}
