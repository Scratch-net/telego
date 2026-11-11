package tlsfront

import (
	"encoding/binary"
	"testing"
)

// rec builds a TLS record with the given type and a zero payload of payloadLen.
func rec(recType byte, payloadLen int) []byte {
	r := make([]byte, 5+payloadLen)
	r[0] = recType
	r[1], r[2] = 0x03, 0x03
	binary.BigEndian.PutUint16(r[3:5], uint16(payloadLen))
	return r
}

func TestFirstAppDataRecordLen(t *testing.T) {
	// ServerHello, then ChangeCipherSpec, then the encrypted cert AppData record.
	stream := append(rec(recordTypeHandshake, 90), rec(recordTypeChangeCipherSpec, 1)...)
	stream = append(stream, rec(recordTypeApplicationData, 2878)...)
	stream = append(stream, rec(recordTypeApplicationData, 50)...) // smaller later record ignored

	if got := certAppDataRecordLen(stream); got != 2878 {
		t.Fatalf("certAppDataRecordLen = %d, want 2878", got)
	}

	// No ApplicationData record -> 0.
	none := append(rec(recordTypeHandshake, 90), rec(recordTypeChangeCipherSpec, 1)...)
	if got := certAppDataRecordLen(none); got != 0 {
		t.Fatalf("certAppDataRecordLen (no appdata) = %d, want 0", got)
	}

	// Truncated input must not panic.
	for i := range stream {
		_ = certAppDataRecordLen(stream[:i])
	}
}

// OpenSSL-based servers send EncryptedExtensions in its own small record
// before the Certificate record (measured 2026-11-11: www.microsoft.com
// 36, 8268, 281, 69; github.com 36, 2765, 95, 53). The fake certificate
// record must match the Certificate record, not EncryptedExtensions.
func TestCertAppDataRecordLenSkipsEncryptedExtensions(t *testing.T) {
	stream := append(rec(recordTypeHandshake, 1210), rec(recordTypeChangeCipherSpec, 1)...)
	for _, size := range []int{36, 8268, 281, 69} {
		stream = append(stream, rec(recordTypeApplicationData, size)...)
	}
	if got := certAppDataRecordLen(stream); got != 8268 {
		t.Fatalf("certAppDataRecordLen = %d, want 8268", got)
	}
}
