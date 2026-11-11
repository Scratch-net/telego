package config

import (
	"net/netip"
	"slices"
	"testing"
)

func TestGeneralTrustedProxyCIDRs(t *testing.T) {
	const base = "secrets.test = \"0123456789abcdef0123456789abcdef\"\ntls-fronting.mask-host = \"example.com\"\n"
	cfg, err := Load(writeConfigTestFile(t, base+"general.trusted-proxy-cidrs = [\"127.0.0.1/32\", \"172.16.0.0/12\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("172.16.0.0/12")}
	if !slices.Equal(runtime.TrustedProxyPrefixes, want) {
		t.Fatalf("prefixes = %v, want %v", runtime.TrustedProxyPrefixes, want)
	}
	cfg, err = Load(writeConfigTestFile(t, base+"general.trusted-proxy-cidrs = [\"10.1.2.3/8\"]\n"))
	if err == nil {
		_, err = cfg.ToGProxyConfig()
	}
	if err == nil {
		t.Fatal("noncanonical CIDR accepted")
	}
}
