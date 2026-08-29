package middleend

import (
	"bytes"
	"testing"
)

func FuzzClientBootstrapServerNonce(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, NoncePacketSize+FullFrameOverhead))
	f.Add([]byte{44, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		bootstrap, err := NewClientBootstrap(testBootstrapConfig())
		if err != nil {
			t.Fatalf("NewClientBootstrap: %v", err)
		}
		if _, err := bootstrap.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		consumed, _, _ := bootstrap.Feed(data)
		if consumed < 0 || consumed > len(data) {
			t.Fatalf("consumed = %d for %d input bytes", consumed, len(data))
		}
	})
}

func FuzzClientBootstrapCiphertext(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 16))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		client, initial := newStartedFuzzBootstrap(t)
		serverNonce := newFuzzServerNonce(t, initial)
		if _, _, err := client.Feed(serverNonce); err != nil {
			t.Fatalf("Feed valid nonce: %v", err)
		}
		consumed, _, _ := client.Feed(data)
		if consumed < 0 || consumed > len(data) {
			t.Fatalf("consumed = %d for %d input bytes", consumed, len(data))
		}
	})
}

func newStartedFuzzBootstrap(t *testing.T) (*ClientBootstrap, []byte) {
	t.Helper()
	bootstrap, err := NewClientBootstrap(testBootstrapConfig())
	if err != nil {
		t.Fatalf("NewClientBootstrap: %v", err)
	}
	initial, err := bootstrap.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return bootstrap, initial
}

func newFuzzServerNonce(t *testing.T, clientWire []byte) []byte {
	t.Helper()
	frame, err := DecodeFrame(clientWire, -2, ChecksumCRC32, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	clientNonce, err := ParseNoncePacket(frame.Payload)
	if err != nil {
		t.Fatalf("ParseNoncePacket: %v", err)
	}
	payload, err := (NoncePacket{
		KeySelector: clientNonce.KeySelector,
		Timestamp:   clientNonce.Timestamp,
		Nonce:       [16]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	wire, err := EncodeFrame(-2, payload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	return wire
}
