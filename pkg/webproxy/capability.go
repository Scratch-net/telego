package webproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	baseSecretSize    = 16
	ddSecretSize      = baseSecretSize + 1
	ddSecretPrefix    = byte(0xdd)
	capabilityLength  = 43
	capabilityContext = "tdesktop-web-proxy-bridge-v1\n"
)

var (
	// ErrInvalidHostname reports a hostname that is not the canonical lowercase
	// ASCII/IDNA form required by the WEB proxy protocol.
	ErrInvalidHostname = errors.New("invalid WEB proxy hostname")
	// ErrInvalidSecret reports a secret that is neither a 16-byte base secret nor
	// the same secret with the WEB-compatible dd prefix.
	ErrInvalidSecret = errors.New("invalid WEB proxy secret")
	// ErrInvalidCapability reports a non-canonical bridge capability string.
	ErrInvalidCapability = errors.New("invalid WEB proxy capability")
)

// Capability is the binary HMAC-SHA256 bridge capability.
type Capability [sha256.Size]byte

// String returns the canonical unpadded base64url representation.
func (c Capability) String() string {
	return base64.RawURLEncoding.EncodeToString(c[:])
}

// Equal compares two capabilities in constant time.
func (c Capability) Equal(other Capability) bool {
	return subtle.ConstantTimeCompare(c[:], other[:]) == 1
}

// ParseCapability decodes one canonical 43-character unpadded base64url
// capability.
func ParseCapability(value string) (Capability, error) {
	var capability Capability
	if len(value) != capabilityLength {
		return capability, fmt.Errorf("%w: must contain %d characters", ErrInvalidCapability, capabilityLength)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(capability) {
		return capability, ErrInvalidCapability
	}
	copy(capability[:], decoded)
	if capability.String() != value {
		return Capability{}, fmt.Errorf("%w: encoding is not canonical", ErrInvalidCapability)
	}
	return capability, nil
}

// SecretMode identifies the MTProxy secret spelling used to derive a WEB
// profile capability.
type SecretMode uint8

const (
	SecretPlain SecretMode = iota
	SecretDD
)

func (m SecretMode) String() string {
	switch m {
	case SecretPlain:
		return "plain"
	case SecretDD:
		return "dd"
	default:
		return "unknown"
	}
}

// Profile is one immutable WEB credential derived from a named Telego secret.
// A single 16-byte base secret produces a plain profile and a dd profile.
type Profile struct {
	name       string
	mode       SecretMode
	secret     [ddSecretSize]byte
	secretSize uint8
	capability Capability
}

func (p Profile) Name() string { return p.name }

func (p Profile) Mode() SecretMode { return p.mode }

// SecretBytes returns a copy of the decoded credential, including the leading
// dd byte for a SecretDD profile.
func (p Profile) SecretBytes() []byte {
	result := make([]byte, p.secretSize)
	copy(result, p.secret[:p.secretSize])
	return result
}

// SecretHex returns the credential in the form accepted by Telegram proxy
// links.
func (p Profile) SecretHex() string {
	return hex.EncodeToString(p.secret[:p.secretSize])
}

func (p Profile) Capability() Capability { return p.capability }

// DeriveProfiles creates the plain and dd WEB credentials for an existing
// Telego 16-byte base secret. The returned order is always plain, then dd.
func DeriveProfiles(name, hostname string, baseSecret []byte) ([2]Profile, error) {
	var profiles [2]Profile
	if err := ValidateHostname(hostname); err != nil {
		return profiles, err
	}
	if len(baseSecret) != baseSecretSize {
		return profiles, fmt.Errorf("%w: base secret must contain %d bytes", ErrInvalidSecret, baseSecretSize)
	}

	profiles[0] = newProfile(name, SecretPlain, baseSecret)
	ddSecret := [ddSecretSize]byte{ddSecretPrefix}
	copy(ddSecret[1:], baseSecret)
	profiles[1] = newProfile(name, SecretDD, ddSecret[:])
	for i := range profiles {
		profiles[i].capability = deriveCapability(hostname, profiles[i].secret[:profiles[i].secretSize])
	}
	return profiles, nil
}

func newProfile(name string, mode SecretMode, secret []byte) Profile {
	var profile Profile
	profile.name = name
	profile.mode = mode
	profile.secretSize = uint8(len(secret))
	copy(profile.secret[:], secret)
	return profile
}

// DeriveCapability derives a bridge capability from a canonical hostname and a
// decoded 16-byte plain or 17-byte dd-prefixed secret.
func DeriveCapability(hostname string, secret []byte) (Capability, error) {
	if err := ValidateHostname(hostname); err != nil {
		return Capability{}, err
	}
	if len(secret) != baseSecretSize && (len(secret) != ddSecretSize || secret[0] != ddSecretPrefix) {
		return Capability{}, fmt.Errorf("%w: expected 16 bytes or 17 bytes prefixed with dd", ErrInvalidSecret)
	}
	return deriveCapability(hostname, secret), nil
}

func deriveCapability(hostname string, secret []byte) Capability {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(capabilityContext + hostname))
	var capability Capability
	copy(capability[:], mac.Sum(nil))
	return capability
}

// ValidateHostname requires the already-canonical hostname spelling used in
// capability derivation. It deliberately does not trim, lowercase, or convert
// Unicode input because doing so would silently derive a different URL than the
// configured value.
func ValidateHostname(hostname string) error {
	if hostname == "" || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return fmt.Errorf("%w: expected a DNS hostname without a trailing dot", ErrInvalidHostname)
	}
	if strings.ContainsAny(hostname, ":/@?#[]") {
		return fmt.Errorf("%w: scheme, port, path, query, and fragment are not allowed", ErrInvalidHostname)
	}
	if net.ParseIP(hostname) != nil || !strings.Contains(hostname, ".") {
		return fmt.Errorf("%w: IP addresses and single-label names are not allowed", ErrInvalidHostname)
	}

	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: invalid DNS label", ErrInvalidHostname)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return fmt.Errorf("%w: use lowercase ASCII/IDNA A-label form", ErrInvalidHostname)
			}
		}
	}
	if lastLabelIsNumeric(labels[len(labels)-1]) {
		return fmt.Errorf("%w: numeric final labels are IP-address forms", ErrInvalidHostname)
	}
	return nil
}

// lastLabelIsNumeric mirrors the WHATWG URL "ends in a number" check used by
// Telegram Desktop before it accepts a WEB proxy hostname.
func lastLabelIsNumeric(label string) bool {
	digits := label
	hexadecimal := strings.HasPrefix(label, "0x")
	if hexadecimal {
		digits = label[2:]
	}
	for _, character := range digits {
		decimal := character >= '0' && character <= '9'
		hexLetter := character >= 'a' && character <= 'f'
		if !decimal && (!hexadecimal || !hexLetter) {
			return false
		}
	}
	return true
}
