package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoctorTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second, 31 * time.Second} {
		if err := (&DoctorCmd{Timeout: timeout}).Run(); err == nil {
			t.Fatal("invalid timeout passed", timeout)
		}
	}
}

func TestDoctorPublicIP(t *testing.T) {
	stun := func() (string, error) { return "198.51.100.2", nil }
	ip, source, err := doctorPublicIP(t.Context(), " 203.0.113.7 ", stun)
	if err != nil || ip != netip.MustParseAddr("203.0.113.7") || source != "middle-end.nat-ip" {
		t.Fatal(ip, source, err)
	}
	ip, source, err = doctorPublicIP(t.Context(), "", stun)
	if err != nil || ip != netip.MustParseAddr("198.51.100.2") || source != "stun" {
		t.Fatal(ip, source, err)
	}
	if _, _, err = doctorPublicIP(t.Context(), "", func() (string, error) { return "", errors.New("stun failed") }); err == nil {
		t.Fatal("STUN failure passed")
	}
	block := make(chan struct{})
	defer close(block)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err = doctorPublicIP(ctx, "", func() (string, error) { <-block; return "", nil })
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("stalled STUN discovery was not bounded:", err)
	}
}

func TestDoctorTargetScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(`secrets.test = "0123456789abcdef0123456789abcdef"
[tls-fronting]
mask-host = "example.com"
splice-host = "127.0.0.1"
splice-port = 1
cert-host = "127.0.0.2"
cert-port = 1
`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []bool{false, true} {
		scope, address := "probe_fallback", "127.0.0.1:1"
		if source {
			scope, address = "certificate_source", "127.0.0.2:1"
		}
		err := (&DoctorCmd{Config: path, Timeout: time.Second, CertSource: source}).Run()
		if err == nil || !strings.Contains(err.Error(), scope) || !strings.Contains(err.Error(), address) || !strings.Contains(err.Error(), "SNI example.com") {
			t.Fatalf("source=%v: %v", source, err)
		}
	}
}
