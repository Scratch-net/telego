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
	stream = append(stream, rec(recordTypeApplicationData, 50)...) // later record ignored

	if got := firstAppDataRecordLen(stream); got != 2878 {
		t.Fatalf("firstAppDataRecordLen = %d, want 2878", got)
	}

	// No ApplicationData record -> 0.
	none := append(rec(recordTypeHandshake, 90), rec(recordTypeChangeCipherSpec, 1)...)
	if got := firstAppDataRecordLen(none); got != 0 {
		t.Fatalf("firstAppDataRecordLen (no appdata) = %d, want 0", got)
	}

	// Truncated input must not panic.
	for i := range stream {
		_ = firstAppDataRecordLen(stream[:i])
	}
}
