package middleend

import (
	"crypto/md5"  //nolint:gosec // Required by Telegram's Middle-End protocol.
	"crypto/sha1" //nolint:gosec // Required by Telegram's Middle-End protocol.
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Role identifies which side of a Middle-End connection derives the keys.
type Role uint8

const (
	RoleClient Role = iota
	RoleServer
)

// KDFParams contains the address-sensitive inputs to Telegram's Middle-End
// AES key derivation. ClientAddr must be the address observed by the server.
type KDFParams struct {
	ServerNonce     [16]byte
	ClientNonce     [16]byte
	ClientTimestamp int32
	ServerAddr      netip.AddrPort
	ClientAddr      netip.AddrPort
	Secret          []byte
}

// String prevents accidental disclosure of secret and nonce material.
func (KDFParams) String() string {
	return "middleend.KDFParams{redacted}"
}

// GoString prevents accidental disclosure of secret and nonce material.
func (KDFParams) GoString() string {
	return "middleend.KDFParams{redacted}"
}

// Keys contains the independent continuous CBC states used in each direction.
type Keys struct {
	ReadKey  [32]byte
	ReadIV   [16]byte
	WriteKey [32]byte
	WriteIV  [16]byte
}

// String prevents accidental disclosure of derived keys and IVs.
func (Keys) String() string {
	return "middleend.Keys{redacted}"
}

// GoString prevents accidental disclosure of derived keys and IVs.
func (Keys) GoString() string {
	return "middleend.Keys{redacted}"
}

// SecretKeySelector returns the least-significant 32 bits of the infrastructure
// secret as represented by Telegram on its little-endian wire.
func SecretKeySelector(secret []byte) (uint32, error) {
	if err := validateSecret(secret); err != nil {
		return 0, err
	}

	selector := binary.LittleEndian.Uint32(secret[:4])
	if selector == 0 {
		return 0, fmt.Errorf("%w: selector is zero", ErrInvalidSecret)
	}
	return selector, nil
}

// DeriveKeys derives the client or server read/write AES-256-CBC material.
//
// The byte order and pre-key layout are defined by aes_create_keys in
// TelegramMessenger/MTProxy net/net-crypto-aes.c at commit
// f36d8af769ffaeac36978d38c2c0f6d1104c2137.
func DeriveKeys(params KDFParams, role Role) (Keys, error) {
	var keys Keys
	if err := validateSecret(params.Secret); err != nil {
		return keys, err
	}
	if err := validateAddressTuple(params.ServerAddr, params.ClientAddr); err != nil {
		return keys, err
	}

	var writeLabel, readLabel string
	switch role {
	case RoleClient:
		writeLabel, readLabel = "CLIENT", "SERVER"
	case RoleServer:
		writeLabel, readLabel = "SERVER", "CLIENT"
	default:
		return keys, fmt.Errorf("%w: %d", ErrInvalidRole, role)
	}

	keys.WriteKey, keys.WriteIV = deriveDirection(params, writeLabel)
	keys.ReadKey, keys.ReadIV = deriveDirection(params, readLabel)
	return keys, nil
}

func deriveDirection(params KDFParams, label string) ([32]byte, [16]byte) {
	prekey := buildPrekey(params, label)
	defer clear(prekey)

	firstMD5 := md5.Sum(prekey[1:]) //nolint:gosec // Protocol-mandated KDF.
	sha1Sum := sha1.Sum(prekey)     //nolint:gosec // Protocol-mandated KDF.
	iv := md5.Sum(prekey[2:])       //nolint:gosec // Protocol-mandated KDF.

	var key [32]byte
	copy(key[:12], firstMD5[:12])
	copy(key[12:], sha1Sum[:])
	return key, iv
}

func buildPrekey(params KDFParams, label string) []byte {
	serverAddr := params.ServerAddr
	clientAddr := params.ClientAddr
	serverIP := serverAddr.Addr().Unmap()
	clientIP := clientAddr.Addr().Unmap()

	capacity := 16 + 16 + 4 + 4 + 2 + len(label) + 4 + 2 + len(params.Secret) + 16 + 16
	if serverIP.Is6() {
		capacity += 32
	}
	prekey := make([]byte, 0, capacity)
	prekey = append(prekey, params.ServerNonce[:]...)
	prekey = append(prekey, params.ClientNonce[:]...)
	prekey = binary.LittleEndian.AppendUint32(prekey, uint32(params.ClientTimestamp))

	if serverIP.Is4() {
		serverV4 := serverIP.As4()
		prekey = binary.LittleEndian.AppendUint32(prekey, binary.BigEndian.Uint32(serverV4[:]))
	} else {
		prekey = append(prekey, 0, 0, 0, 0)
	}
	prekey = binary.LittleEndian.AppendUint16(prekey, clientAddr.Port())
	prekey = append(prekey, label...)
	if clientIP.Is4() {
		clientV4 := clientIP.As4()
		prekey = binary.LittleEndian.AppendUint32(prekey, binary.BigEndian.Uint32(clientV4[:]))
	} else {
		prekey = append(prekey, 0, 0, 0, 0)
	}
	prekey = binary.LittleEndian.AppendUint16(prekey, serverAddr.Port())
	prekey = append(prekey, params.Secret...)
	prekey = append(prekey, params.ServerNonce[:]...)

	if serverIP.Is6() {
		clientV6 := clientIP.As16()
		serverV6 := serverIP.As16()
		prekey = append(prekey, clientV6[:]...)
		prekey = append(prekey, serverV6[:]...)
	}

	prekey = append(prekey, params.ClientNonce[:]...)
	return prekey
}

func validateSecret(secret []byte) error {
	if len(secret) < MinimumSecretSize || len(secret) > MaximumSecretSize {
		return fmt.Errorf("%w: length %d is outside %d..%d", ErrInvalidSecret, len(secret), MinimumSecretSize, MaximumSecretSize)
	}
	return nil
}

func validateAddressTuple(serverAddr, clientAddr netip.AddrPort) error {
	if !serverAddr.IsValid() || !clientAddr.IsValid() {
		return fmt.Errorf("%w: both endpoints must be valid", ErrInvalidAddress)
	}
	if serverAddr.Port() == 0 || clientAddr.Port() == 0 {
		return fmt.Errorf("%w: both ports must be nonzero", ErrInvalidAddress)
	}

	serverIP := serverAddr.Addr().Unmap()
	clientIP := clientAddr.Addr().Unmap()
	if serverIP.IsUnspecified() || clientIP.IsUnspecified() {
		return fmt.Errorf("%w: unspecified endpoint", ErrInvalidAddress)
	}
	if serverIP.Is4() != clientIP.Is4() {
		return fmt.Errorf("%w: mixed IPv4 and IPv6 endpoints", ErrInvalidAddress)
	}
	return nil
}
