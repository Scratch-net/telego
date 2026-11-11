package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// signClientHello fills the random of a ClientHello payload the way a
// Telegram client does: HMAC over the record with a zero random, then XOR the
// little-endian timestamp into the last four bytes.
func signClientHello(secret, payload []byte, timestamp uint32) []byte {
	payload = bytes.Clone(payload)
	clear(payload[clientHelloRandomOffset : clientHelloRandomOffset+randomLen])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte{RecordTypeHandshake, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))})
	mac.Write(payload)
	random := mac.Sum(nil)
	var ts [4]byte
	binary.LittleEndian.PutUint32(ts[:], timestamp)
	for i := range 4 {
		random[28+i] ^= ts[i]
	}
	copy(payload[clientHelloRandomOffset:], random)
	return payload
}

// buildOfferClientHello builds a ClientHello payload with the given cipher
// suites and key_share groups (x25519 32 bytes, PQ 1216 bytes, else 65 bytes).
func buildOfferClientHello(sessionID []byte, suites []uint16, groups []uint16) []byte {
	var shares []byte
	for _, group := range groups {
		keyLen := 65
		switch group {
		case 0x001d:
			keyLen = 32
		case pqNamedGroup:
			keyLen = 1216
		}
		shares = binary.BigEndian.AppendUint16(shares, group)
		shares = binary.BigEndian.AppendUint16(shares, uint16(keyLen))
		shares = append(shares, make([]byte, keyLen)...)
	}
	var ext []byte
	ext = binary.BigEndian.AppendUint16(ext, 0x0033)
	ext = binary.BigEndian.AppendUint16(ext, uint16(2+len(shares)))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(shares)))
	ext = append(ext, shares...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = binary.BigEndian.AppendUint16(body, uint16(2*len(suites)))
	for _, suite := range suites {
		body = binary.BigEndian.AppendUint16(body, suite)
	}
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	payload := []byte{handshakeTypeClient, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(payload, body...)
}

type testExtension struct {
	typ  uint16
	data []byte
}

// buildCapturedServerHello builds a mask-host ServerHello record.
func buildCapturedServerHello(sessionID []byte, suite uint16, extensions []testExtension) []byte {
	body := []byte{0x03, 0x03}
	for i := range 32 {
		body = append(body, byte(0xc0+i))
	}
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0x00)
	var exts []byte
	for _, extension := range extensions {
		exts = binary.BigEndian.AppendUint16(exts, extension.typ)
		exts = binary.BigEndian.AppendUint16(exts, uint16(len(extension.data)))
		exts = append(exts, extension.data...)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	message := append([]byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := []byte{RecordTypeHandshake, 0x03, 0x03, byte(len(message) >> 8), byte(len(message))}
	return append(record, message...)
}

func keyShareServerData(group uint16, key []byte) []byte {
	data := binary.BigEndian.AppendUint16(nil, group)
	data = binary.BigEndian.AppendUint16(data, uint16(len(key)))
	return append(data, key...)
}

type parsedServerHello struct {
	sessionID  []byte
	suite      uint16
	extensions []testExtension
}

func parseServerHelloRecord(t *testing.T, response []byte) parsedServerHello {
	t.Helper()
	recordLen := int(binary.BigEndian.Uint16(response[3:5]))
	record := response[:5+recordLen]
	pos := 5 + 4 + 2 + 32
	sidLen := int(record[pos])
	parsed := parsedServerHello{sessionID: bytes.Clone(record[pos+1 : pos+1+sidLen])}
	pos += 1 + sidLen
	parsed.suite = binary.BigEndian.Uint16(record[pos:])
	pos += 3
	end := pos + 2 + int(binary.BigEndian.Uint16(record[pos:]))
	if end != len(record) {
		t.Fatalf("extensions end %d, record end %d", end, len(record))
	}
	pos += 2
	for pos < end {
		typ := binary.BigEndian.Uint16(record[pos:])
		length := int(binary.BigEndian.Uint16(record[pos+2:]))
		parsed.extensions = append(parsed.extensions, testExtension{typ, bytes.Clone(record[pos+4 : pos+4+length])})
		pos += 4 + length
	}
	return parsed
}

func assertServerRandomDigest(t *testing.T, secret []byte, hello *ClientHello, response []byte) {
	t.Helper()
	check := bytes.Clone(response)
	clear(check[WelcomePacketRandomOffset : WelcomePacketRandomOffset+32])
	mac := hmac.New(sha256.New, secret)
	mac.Write(hello.Random[:])
	mac.Write(check)
	if !bytes.Equal(mac.Sum(nil), response[WelcomePacketRandomOffset:WelcomePacketRandomOffset+32]) {
		t.Fatal("server random HMAC does not validate")
	}
}

func buildHybridForTest(t *testing.T, secret []byte, hello *ClientHello, captured []byte) []byte {
	t.Helper()
	template, err := ParseServerHelloTemplate(captured)
	if err != nil {
		t.Fatalf("ParseServerHelloTemplate: %v", err)
	}
	response, err := BuildServerHelloWithOptions(secret, hello, &ServerHelloOptions{Template: template})
	if err != nil {
		t.Fatalf("BuildServerHelloWithOptions: %v", err)
	}
	return response
}

func TestHybridServerHelloIsBuiltPerClient(t *testing.T) {
	secret := []byte("0123456789abcdef")
	templateKey := bytes.Repeat([]byte{0x55}, 32)
	captured := buildCapturedServerHello(bytes.Repeat([]byte{0xaa}, 32), 0x1302, []testExtension{
		{0x0033, keyShareServerData(0x001d, templateKey)},
		{0x002b, []byte{0x03, 0x04}},
	})

	clientSession := bytes.Repeat([]byte{0x11}, 32)
	payload := signClientHello(secret,
		buildOfferClientHello(clientSession, []uint16{0x1a1a, 0x1301, 0x1302}, []uint16{0x001d}),
		uint32(time.Now().Unix()))
	hello, err := ParseClientHello(secret, payload)
	if err != nil {
		t.Fatal(err)
	}

	first := buildHybridForTest(t, secret, hello, captured)
	second := buildHybridForTest(t, secret, hello, captured)
	assertServerRandomDigest(t, secret, hello, first)
	assertServerRandomDigest(t, secret, hello, second)

	a, b := parseServerHelloRecord(t, first), parseServerHelloRecord(t, second)
	if !bytes.Equal(a.sessionID, clientSession) {
		t.Fatalf("legacy_session_id_echo = %x, want client session %x", a.sessionID, clientSession)
	}
	if a.suite != 0x1302 {
		t.Fatalf("cipher = 0x%04x, want template cipher 0x1302 (offered by client)", a.suite)
	}
	if len(a.extensions) != 2 || a.extensions[0].typ != 0x0033 || a.extensions[1].typ != 0x002b {
		t.Fatalf("extension order not kept: %+v", a.extensions)
	}
	if !bytes.Equal(a.extensions[1].data, []byte{0x03, 0x04}) {
		t.Fatalf("supported_versions = %x", a.extensions[1].data)
	}
	keyA, keyB := a.extensions[0].data, b.extensions[0].data
	if binary.BigEndian.Uint16(keyA) != 0x001d || len(keyA) != 4+32 {
		t.Fatalf("key_share = %x, want fresh x25519 share", keyA)
	}
	if bytes.Equal(keyA[4:], templateKey) || bytes.Equal(keyA, keyB) {
		t.Fatal("key_share is not fresh per connection")
	}
}

func TestHybridServerHelloChoosesFromClientOffer(t *testing.T) {
	secret := []byte("0123456789abcdef")
	captured := buildCapturedServerHello(bytes.Repeat([]byte{0xaa}, 32), 0x1302, []testExtension{
		{0x002b, []byte{0x03, 0x04}},
		{0x0033, keyShareServerData(0x001d, make([]byte, 32))},
	})

	tests := []struct {
		name   string
		suites []uint16
		groups []uint16
		suite  uint16
		group  uint16
		keyLen int
	}{
		{"PQ only", []uint16{0x1301}, []uint16{0x2a2a, pqNamedGroup}, 0x1301, pqNamedGroup, 1120},
		{"P-256 only", []uint16{0x1303, 0x1301}, []uint16{0x0017}, 0x1303, 0x0017, 65},
		{"template group offered", []uint16{0x1301}, []uint16{pqNamedGroup, 0x001d}, 0x1301, 0x001d, 32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := signClientHello(secret,
				buildOfferClientHello(make([]byte, 32), test.suites, test.groups),
				uint32(time.Now().Unix()))
			hello, err := ParseClientHello(secret, payload)
			if err != nil {
				t.Fatal(err)
			}
			response := buildHybridForTest(t, secret, hello, captured)
			assertServerRandomDigest(t, secret, hello, response)
			parsed := parseServerHelloRecord(t, response)
			if parsed.suite != test.suite {
				t.Fatalf("cipher = 0x%04x, want 0x%04x", parsed.suite, test.suite)
			}
			share := parsed.extensions[1].data
			if parsed.extensions[1].typ != 0x0033 || binary.BigEndian.Uint16(share) != test.group ||
				int(binary.BigEndian.Uint16(share[2:])) != test.keyLen || len(share) != 4+test.keyLen {
				t.Fatalf("key_share = type 0x%04x group 0x%04x len %d, want group 0x%04x len %d",
					parsed.extensions[1].typ, binary.BigEndian.Uint16(share), len(share)-4, test.group, test.keyLen)
			}
		})
	}
}

func TestParseServerHelloTemplateRejectsTLS12(t *testing.T) {
	captured := buildCapturedServerHello(bytes.Repeat([]byte{0xaa}, 32), 0xc02f, []testExtension{
		{0xff01, []byte{0x00}},
	})
	if _, err := ParseServerHelloTemplate(captured); err == nil {
		t.Fatal("TLS 1.2 ServerHello accepted as a template")
	}
}

// A cached certificate must not appear as plaintext DER in an ApplicationData
// record: TLS 1.3 encrypts the Certificate message.
func TestSyntheticServerHelloDoesNotLeakCertificate(t *testing.T) {
	secret := []byte("0123456789abcdef")
	cert := bytes.Repeat([]byte("CERTIFICATE-DER-"), 64)
	hello := &ClientHello{SessionID: make([]byte, 32), CipherSuite: 0x1301}
	response, err := BuildServerHelloWithOptions(secret, hello, &ServerHelloOptions{CertChain: [][]byte{cert}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(response, cert[:64]) {
		t.Fatal("certificate DER is visible in the synthetic response")
	}
	if got := firstAppDataLen(response); got < len(cert) {
		t.Fatalf("first ApplicationData record = %d bytes, want at least the certificate size %d", got, len(cert))
	}
	assertServerRandomDigest(t, secret, hello, response)
}

// Telegram clients expect the response to start with a 0x0303 record. A
// template with another record version must fall back to the synthetic
// ServerHello instead of breaking every handshake.
func TestParseServerHelloTemplateRejectsRecordVersion(t *testing.T) {
	captured := buildCapturedServerHello(bytes.Repeat([]byte{0xaa}, 32), 0x1302, []testExtension{
		{0x0033, keyShareServerData(0x001d, bytes.Repeat([]byte{0x55}, 32))},
		{0x002b, []byte{0x03, 0x04}},
	})
	if _, err := ParseServerHelloTemplate(captured); err != nil {
		t.Fatalf("valid template rejected: %v", err)
	}
	captured[2] = 0x01 // record version 0x0301
	if _, err := ParseServerHelloTemplate(captured); err == nil {
		t.Fatal("template with record version 0x0301 accepted")
	}
}
