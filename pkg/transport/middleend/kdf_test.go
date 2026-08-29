package middleend

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestDeriveKeysGoldenIPv4(t *testing.T) {
	params := goldenKDFParams(
		netip.MustParseAddrPort("192.0.2.10:8888"),
		netip.MustParseAddrPort("198.51.100.20:54321"),
	)

	keys, err := DeriveKeys(params, RoleClient)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	assertHex(t, "write key", keys.WriteKey[:], "08449b7ce836e32835542882c26b834378d1969bbd7ee8084905769b0fe20d68")
	assertHex(t, "write IV", keys.WriteIV[:], "a4d3a131e3f8fcf613e17e9388de8593")
	assertHex(t, "read key", keys.ReadKey[:], "5c39f7bf7d3f60f1a9df34ef2bf93e6cc28bd3fff35f7bcc704f70ed561b2179")
	assertHex(t, "read IV", keys.ReadIV[:], "9854ff253a09d8563469aa21b58990e3")

	serverKeys, err := DeriveKeys(params, RoleServer)
	if err != nil {
		t.Fatalf("DeriveKeys server: %v", err)
	}
	if serverKeys.WriteKey != keys.ReadKey || serverKeys.WriteIV != keys.ReadIV {
		t.Error("server write material does not equal client read material")
	}
	if serverKeys.ReadKey != keys.WriteKey || serverKeys.ReadIV != keys.WriteIV {
		t.Error("server read material does not equal client write material")
	}
}

func TestDeriveKeysGoldenIPv6(t *testing.T) {
	params := goldenKDFParams(
		netip.MustParseAddrPort("[2001:db8::a]:8888"),
		netip.MustParseAddrPort("[2001:db8:1::14]:54321"),
	)

	keys, err := DeriveKeys(params, RoleClient)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	assertHex(t, "write key", keys.WriteKey[:], "20ba9297ba57368cb38988cf339a5eedfd8ca64df2b0fcb70e685b45a323de3f")
	assertHex(t, "write IV", keys.WriteIV[:], "f1fba8e5b47bf8bf347fa4b69250df9a")
	assertHex(t, "read key", keys.ReadKey[:], "66a753eb83a5d092a815b78d444918adfd435426aac9dba28a26fc458bcaa873")
	assertHex(t, "read IV", keys.ReadIV[:], "55d374f646399c16def66499c22caf4e")
}

func TestSecretKeySelector(t *testing.T) {
	secret := make([]byte, 128)
	copy(secret, []byte{1, 2, 3, 4})

	selector, err := SecretKeySelector(secret)
	if err != nil {
		t.Fatalf("SecretKeySelector: %v", err)
	}
	if selector != 0x04030201 {
		t.Fatalf("selector = %08x, want 04030201", selector)
	}
}

func TestKDFRejectsInvalidInputs(t *testing.T) {
	valid := goldenKDFParams(
		netip.MustParseAddrPort("192.0.2.10:8888"),
		netip.MustParseAddrPort("198.51.100.20:54321"),
	)

	tests := []struct {
		name   string
		mutate func(*KDFParams)
		role   Role
		want   error
	}{
		{
			name: "secret too short",
			mutate: func(params *KDFParams) {
				params.Secret = make([]byte, MinimumSecretSize-1)
			},
			role: RoleClient,
			want: ErrInvalidSecret,
		},
		{
			name: "secret too long",
			mutate: func(params *KDFParams) {
				params.Secret = make([]byte, MaximumSecretSize+1)
			},
			role: RoleClient,
			want: ErrInvalidSecret,
		},
		{
			name: "mixed address families",
			mutate: func(params *KDFParams) {
				params.ClientAddr = netip.MustParseAddrPort("[2001:db8::1]:54321")
			},
			role: RoleClient,
			want: ErrInvalidAddress,
		},
		{
			name: "zero server port",
			mutate: func(params *KDFParams) {
				params.ServerAddr = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), 0)
			},
			role: RoleClient,
			want: ErrInvalidAddress,
		},
		{
			name: "unspecified client",
			mutate: func(params *KDFParams) {
				params.ClientAddr = netip.MustParseAddrPort("0.0.0.0:54321")
			},
			role: RoleClient,
			want: ErrInvalidAddress,
		},
		{
			name:   "invalid role",
			mutate: func(*KDFParams) {},
			role:   Role(10),
			want:   ErrInvalidRole,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params := valid
			params.Secret = slices.Clone(valid.Secret)
			tc.mutate(&params)
			_, err := DeriveKeys(params, tc.role)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSecretKeySelectorRejectsZero(t *testing.T) {
	_, err := SecretKeySelector(make([]byte, MinimumSecretSize))
	if !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidSecret)
	}
}

func goldenKDFParams(serverAddr, clientAddr netip.AddrPort) KDFParams {
	var serverNonce, clientNonce [16]byte
	for i := range 16 {
		serverNonce[i] = byte(i)
		clientNonce[i] = byte(0xf0 + i)
	}
	secret := make([]byte, 128)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return KDFParams{
		ServerNonce:     serverNonce,
		ClientNonce:     clientNonce,
		ClientTimestamp: 0x66332211,
		ServerAddr:      serverAddr,
		ClientAddr:      clientAddr,
		Secret:          secret,
	}
}

func assertHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if encoded := hex.EncodeToString(got); encoded != want {
		t.Errorf("%s = %s, want %s", name, encoded, want)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return decoded
}
