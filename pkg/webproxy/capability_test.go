package webproxy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCapabilityVectors(t *testing.T) {
	t.Parallel()

	base := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	profiles, err := DeriveProfiles("desktop", "proxy.example.com", base)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		mode       SecretMode
		secret     string
		capability string
	}{
		{SecretPlain, "000102030405060708090a0b0c0d0e0f", "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"},
		{SecretDD, "dd000102030405060708090a0b0c0d0e0f", "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"},
	}
	for i, test := range tests {
		profile := profiles[i]
		if profile.Name() != "desktop" || profile.Mode() != test.mode {
			t.Fatalf("profile %d identity is %q/%s", i, profile.Name(), profile.Mode())
		}
		if got := profile.SecretHex(); got != test.secret {
			t.Errorf("profile %d secret = %q, want %q", i, got, test.secret)
		}
		if got := profile.Capability().String(); got != test.capability {
			t.Errorf("profile %d capability = %q, want %q", i, got, test.capability)
		}
		derived, deriveErr := DeriveCapability("proxy.example.com", profile.SecretBytes())
		if deriveErr != nil || !derived.Equal(profile.Capability()) {
			t.Errorf("profile %d direct derivation = %q, %v", i, derived, deriveErr)
		}
	}
}

func TestProfileSecretBytesReturnsCopy(t *testing.T) {
	t.Parallel()

	base := bytes.Repeat([]byte{0x42}, baseSecretSize)
	profiles, err := DeriveProfiles("copy", "proxy.example.com", base)
	if err != nil {
		t.Fatal(err)
	}
	first := profiles[1].SecretBytes()
	first[0] = 0
	if got := profiles[1].SecretBytes()[0]; got != ddSecretPrefix {
		t.Fatalf("profile secret was mutated through returned slice: %#x", got)
	}
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()

	valid := []string{
		"site.example",
		"xn--bcher-kva.example",
		"a.b.example",
		strings.Repeat("a", 63) + ".example",
		"site.0xzz",
	}
	for _, hostname := range valid {
		if err := ValidateHostname(hostname); err != nil {
			t.Errorf("ValidateHostname(%q): %v", hostname, err)
		}
	}

	invalid := []string{
		"",
		"localhost",
		"127.0.0.1",
		"127.1",
		"0x7f.1",
		"0177.0.0.1",
		"1.2.3",
		"site.123",
		"site.0x7f",
		"site.0x",
		"[::1]",
		"HTTPS://site.example",
		"Site.example",
		"bücher.example",
		" site.example",
		"site.example ",
		"site.example.",
		"site.example:443",
		"user@site.example",
		"site/example",
		"site\\example",
		"site?query.example",
		"site#fragment.example",
		"site..example",
		"-site.example",
		"site-.example",
		"site_example.com",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 127) + "aa",
	}
	for _, hostname := range invalid {
		if err := ValidateHostname(hostname); !errors.Is(err, ErrInvalidHostname) {
			t.Errorf("ValidateHostname(%q) error = %v, want ErrInvalidHostname", hostname, err)
		}
	}
}

func TestDerivationRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	base := bytes.Repeat([]byte{1}, baseSecretSize)
	for _, secret := range [][]byte{
		nil,
		bytes.Repeat([]byte{1}, baseSecretSize-1),
		append([]byte{0xee}, base...),
		append([]byte{0xdd}, append(base, 0)...),
	} {
		if _, err := DeriveCapability("proxy.example.com", secret); !errors.Is(err, ErrInvalidSecret) {
			t.Errorf("DeriveCapability secret length %d error = %v", len(secret), err)
		}
	}
	if _, err := DeriveCapability("Proxy.example.com", base); !errors.Is(err, ErrInvalidHostname) {
		t.Fatalf("invalid host error = %v", err)
	}
	if _, err := DeriveProfiles("desktop", "proxy.example.com", base[:15]); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("invalid base secret error = %v", err)
	}
}

func TestParseCapabilityRequiresCanonicalEncoding(t *testing.T) {
	t.Parallel()

	const value = "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"
	parsed, err := ParseCapability(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != value || !parsed.Equal(parsed) {
		t.Fatalf("capability did not round-trip: %q", parsed)
	}

	invalid := []string{
		"",
		value[:len(value)-1],
		value + "=",
		"MHLEY5PmW1GWqJkSrlmJpvJUiLhBH/QKy6yKg8a0JPk",
		value[:42] + "l", // Same decoded tail bits, but not canonical base64url.
		value[:42] + "!",
	}
	for _, candidate := range invalid {
		if _, parseErr := ParseCapability(candidate); !errors.Is(parseErr, ErrInvalidCapability) {
			t.Errorf("ParseCapability(%q) error = %v", candidate, parseErr)
		}
	}

	other := parsed
	other[0] ^= 1
	if parsed.Equal(other) {
		t.Fatal("distinct capabilities compare equal")
	}
}
