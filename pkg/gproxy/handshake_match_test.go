package gproxy

import (
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// The SNI filter in matchClientHello must keep the old first-valid-secret
// order, including secrets that share a key and differ only by host.
func TestMatchClientHelloKeepsSecretOrderBySNI(t *testing.T) {
	key := []byte("0123456789abcdef")
	other := []byte("fedcba9876543210")
	handler := NewProxyHandler(&Config{
		TimeSkewTolerance: time.Minute,
		Secrets: []Secret{
			{Name: "other", Key: other, Host: "b.example"},
			{Name: "a", Key: key, Host: "a.example"},
			{Name: "b", Key: key, Host: "b.example"},
			{Name: "nohost", Key: key},
		},
	}, &testLogger{})
	for _, test := range []struct{ sni, want string }{
		{"a.example", "a"},
		{"b.example", "b"},
		{"", "a"},
		{"c.example", ""},
	} {
		payload := buildPaddedClientHello(key, test.sni, 512)
		if test.sni == "" {
			payload = buildValidClientHello(key, "", make([]byte, 32))
		}
		sni := faketls.ExtractSNI(payload)
		if sni != test.sni {
			t.Fatalf("fixture SNI = %q, want %q", sni, test.sni)
		}
		_, secret, _ := handler.matchClientHello(payload, sni)
		got := ""
		if secret != nil {
			got = secret.Name
		}
		if got != test.want {
			t.Fatalf("SNI %q matched %q, want %q", test.sni, got, test.want)
		}
	}
}
