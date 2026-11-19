package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/scratch-net/telego/pkg/gproxy"
)

const domainsBase = `[secrets]
alice = "0123456789abcdef0123456789abcdef"
bob = "fedcba9876543210fedcba9876543210"
carol = "00112233445566778899aabbccddeeff"

[tls-fronting]
mask-host = "www.google.com"
splice-host = "127.0.0.1"
splice-port = 8080
splice-proxy-protocol = 1
`

func TestLoadTLSDomains(t *testing.T) {
	cfg, err := Load(writeConfigTestFile(t, domainsBase+`
[[tls-fronting.domains]]
host = "www.microsoft.com"
secrets = ["bob"]

[[tls-fronting.domains]]
host = "www.apple.com"
secrets = ["carol"]
cert-host = "127.0.0.1"
cert-port = 8443
splice-host = "127.0.0.1"
splice-port = 8444
splice-proxy-protocol = 2
fake-cert-size = 3000
`))
	if err != nil {
		t.Fatal(err)
	}
	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	wantDomains := []gproxy.TLSDomain{
		{Host: "www.microsoft.com", CertHost: "www.microsoft.com", CertPort: 443, SpliceHost: "www.microsoft.com", SplicePort: 443},
		{Host: "www.apple.com", CertHost: "127.0.0.1", CertPort: 8443, SpliceHost: "127.0.0.1", SplicePort: 8444, SpliceProxyProtocol: 2, FakeCertSize: 3000},
	}
	if !reflect.DeepEqual(gCfg.Domains, wantDomains) {
		t.Fatalf("domains = %+v", gCfg.Domains)
	}
	wantHosts := map[string]string{"alice": "www.google.com", "bob": "www.microsoft.com", "carol": "www.apple.com"}
	for _, secret := range gCfg.Secrets {
		if secret.Host != wantHosts[secret.Name] {
			t.Fatalf("%s host = %q, want %q", secret.Name, secret.Host, wantHosts[secret.Name])
		}
		if secret.RawHex != BuildFullSecret(secret.Key, wantHosts[secret.Name]) {
			t.Fatalf("%s ee secret does not embed %q", secret.Name, wantHosts[secret.Name])
		}
	}
	// The default domain keeps its settings.
	if gCfg.MaskHost != "www.google.com" || gCfg.SpliceHost != "127.0.0.1" || gCfg.SplicePort != 8080 || gCfg.SpliceProxyProtocol != 1 {
		t.Fatalf("default domain changed: %+v", gCfg)
	}
}

func TestLoadWithoutTLSDomainsKeepsMaskHost(t *testing.T) {
	cfg, err := Load(writeConfigTestFile(t, domainsBase))
	if err != nil {
		t.Fatal(err)
	}
	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	if gCfg.Domains != nil {
		t.Fatalf("domains = %+v, want nil", gCfg.Domains)
	}
	for _, secret := range gCfg.Secrets {
		if secret.Host != "www.google.com" || secret.RawHex != BuildFullSecret(secret.Key, "www.google.com") {
			t.Fatalf("%s host = %q", secret.Name, secret.Host)
		}
	}
}

func TestLoadRejectsInvalidTLSDomains(t *testing.T) {
	for _, tc := range []struct {
		name, domains, want string
	}{
		{"missing host", "secrets = [\"bob\"]", "host must be a DNS hostname"},
		{"bad host", "host = \"bad host\"\nsecrets = [\"bob\"]", "host must be a DNS hostname"},
		{"host with port", "host = \"a.example:443\"\nsecrets = [\"bob\"]", "host must be a DNS hostname"},
		{"empty label", "host = \"a..example\"\nsecrets = [\"bob\"]", "host must be a DNS hostname"},
		{"mask host", "host = \"WWW.Google.com\"\nsecrets = [\"bob\"]", "repeats mask-host"},
		{"no secrets", "host = \"a.example\"", "at least one secret"},
		{"unknown secret", "host = \"a.example\"\nsecrets = [\"dave\"]", "unknown secret \"dave\""},
		{"cert port", "host = \"a.example\"\nsecrets = [\"bob\"]\ncert-port = 70000", "cert-port"},
		{"splice port", "host = \"a.example\"\nsecrets = [\"bob\"]\nsplice-port = -1", "splice-port"},
		{"proxy protocol", "host = \"a.example\"\nsecrets = [\"bob\"]\nsplice-proxy-protocol = 3", "splice-proxy-protocol"},
		{"fake cert size", "host = \"a.example\"\nsecrets = [\"bob\"]\nfake-cert-size = -1", "fake-cert-size"},
		{"unknown field", "host = \"a.example\"\nsecrets = [\"bob\"]\nmask-port = 443", "tls-fronting.domains.mask-port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfigTestFile(t, domainsBase+"\n[[tls-fronting.domains]]\n"+tc.domains+"\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name, domains, want string
	}{
		{"duplicate host", "host = \"a.example\"\nsecrets = [\"bob\"]\n[[tls-fronting.domains]]\nhost = \"A.example\"\nsecrets = [\"carol\"]", "repeats mask-host or another domain"},
		{"secret twice", "host = \"a.example\"\nsecrets = [\"bob\"]\n[[tls-fronting.domains]]\nhost = \"b.example\"\nsecrets = [\"bob\"]", "secret \"bob\" is listed for both"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfigTestFile(t, domainsBase+"\n[[tls-fronting.domains]]\n"+tc.domains+"\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// ToGProxyConfig validates domains too, for configs built without Load.
func TestToGProxyConfigRejectsInvalidTLSDomains(t *testing.T) {
	cfg := &Config{
		Secrets:     map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
		TLSFronting: TLSFrontingConfig{MaskHost: "www.google.com", Domains: []TLSDomainConfig{{Host: "a.example", Secrets: []string{"bob"}}}},
	}
	if _, err := cfg.ToGProxyConfig(); err == nil || !strings.Contains(err.Error(), "unknown secret") {
		t.Fatalf("error = %v", err)
	}
}
