package gproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// buildPaddedClientHello returns a signed ClientHello payload of about size
// bytes: SNI plus a padding extension.
func buildPaddedClientHello(secret []byte, host string, size int) []byte {
	return buildPaddedClientHelloAt(secret, host, size, uint32(time.Now().Unix()))
}

func buildPaddedClientHelloAt(secret []byte, host string, size int, unix uint32) []byte {
	sni := buildSNIExtension(host)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00)
	padding := max(0, size-4-len(body)-2-len(sni)-4)
	extensions := append([]byte{}, sni...)
	extensions = binary.BigEndian.AppendUint16(extensions, 0x0015)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(padding))
	extensions = append(extensions, make([]byte, padding)...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	payload := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte{0x16, 0x03, 0x01, byte(len(payload) >> 8), byte(len(payload))})
	mac.Write(payload)
	random := mac.Sum(nil)
	var timestamp [4]byte
	binary.LittleEndian.PutUint32(timestamp[:], unix)
	for i := range 4 {
		random[28+i] ^= timestamp[i]
	}
	copy(payload[6:38], random)
	return payload
}

// BenchmarkClientHelloAuth matches a hello whose secret is the last one
// configured. All secrets share the mask host, as in a normal deployment.
func BenchmarkClientHelloAuth(b *testing.B) {
	for _, secrets := range []int{1, 50} {
		for _, size := range []int{512, 16 << 10} {
			b.Run(fmt.Sprintf("secrets=%d/size=%d", secrets, size), func(b *testing.B) {
				config := &Config{TimeSkewTolerance: time.Hour}
				for i := range secrets {
					key := make([]byte, 16)
					key[0], key[1] = byte(i), 0xa5
					config.Secrets = append(config.Secrets, Secret{Name: fmt.Sprint(i), Key: key, Host: "example.com"})
				}
				handler := NewProxyHandler(config, &testLogger{})
				payload := buildPaddedClientHello(config.Secrets[secrets-1].Key, "example.com", size)
				b.SetBytes(int64(len(payload)))
				b.ReportAllocs()
				for b.Loop() {
					if hello, _, _ := handler.matchClientHello(payload, faketls.ExtractSNI(payload)); hello == nil {
						b.Fatal("hello did not authenticate")
					}
				}
			})
		}
	}
}
