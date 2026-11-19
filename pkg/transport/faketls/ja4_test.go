package faketls

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The vectors come from the JA4 reference implementation.
func TestJA4ReferenceVectors(t *testing.T) {
	file, err := os.Open("testdata/ja4_vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(nil, 1<<20)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			t.Fatalf("bad vector line %q", line)
		}
		payload, err := hex.DecodeString(fields[3])
		if err != nil {
			t.Fatal(err)
		}
		fp, ok := ComputeJA4(payload)
		if !ok || fp.String() != fields[2] {
			t.Errorf("%s %s: JA4 = %s (%v), want %s", fields[0], fields[1], fp, ok, fields[2])
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 8 {
		t.Fatalf("only %d vectors", count)
	}
}

type ja4Extension struct {
	typ  uint16
	data []byte
}

func u16s(values ...uint16) []byte {
	out := make([]byte, 0, 2*len(values))
	for _, value := range values {
		out = binary.BigEndian.AppendUint16(out, value)
	}
	return out
}

func vector16(values ...uint16) []byte {
	return append(u16s(uint16(2*len(values))), u16s(values...)...)
}

func alpnExtension(protocols ...string) ja4Extension {
	var list []byte
	for _, protocol := range protocols {
		list = append(list, byte(len(protocol)))
		list = append(list, protocol...)
	}
	return ja4Extension{0x0010, append(u16s(uint16(len(list))), list...)}
}

// buildJA4Hello returns a ClientHello handshake message.
func buildJA4Hello(version uint16, suites []uint16, extensions []ja4Extension) []byte {
	body := u16s(version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, vector16(suites...)...)
	body = append(body, 1, 0)
	var list []byte
	for _, extension := range extensions {
		list = append(list, u16s(extension.typ, uint16(len(extension.data)))...)
		list = append(list, extension.data...)
	}
	if extensions != nil {
		body = append(body, u16s(uint16(len(list)))...)
		body = append(body, list...)
	}
	return append([]byte{handshakeTypeClient, 0, byte(len(body) >> 8), byte(len(body))}, body...)
}

var (
	specSuites = []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	specSigAlg = []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
)

// specExtensions returns the extension order of the JA4 specification example.
func specExtensions(signatureAlgorithms []uint16) []ja4Extension {
	var extensions []ja4Extension
	for _, typ := range []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015} {
		switch typ {
		case 0x0010:
			extensions = append(extensions, alpnExtension("h2", "http/1.1"))
		case 0x002b:
			extensions = append(extensions, ja4Extension{typ, append([]byte{4}, u16s(0x0304, 0x0303)...)})
		case 0x000d:
			extensions = append(extensions, ja4Extension{typ, vector16(signatureAlgorithms...)})
		default:
			extensions = append(extensions, ja4Extension{typ: typ})
		}
	}
	return extensions
}

// The example of the JA4 specification (technical_details/JA4.md).
func TestJA4SpecificationExample(t *testing.T) {
	for _, tc := range []struct {
		name       string
		suites     []uint16
		extensions []ja4Extension
		want       string
	}{
		{"example", specSuites, specExtensions(specSigAlg), "t13d1516h2_8daaf6152771_e5627efa2ab1"},
		{"no signature algorithms", specSuites, specExtensions(nil), "t13d1516h2_8daaf6152771_6d807ffa2a79"},
		{"grease", append([]uint16{0x0a0a}, append(specSuites, 0xfafa)...),
			append([]ja4Extension{{typ: 0x1a1a}}, specExtensions(append([]uint16{0x2a2a}, specSigAlg...))...),
			"t13d1516h2_8daaf6152771_e5627efa2ab1"},
		{"no ciphers or extensions", nil, nil, "t12i000000_000000000000_000000000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fp, ok := ComputeJA4(buildJA4Hello(0x0303, tc.suites, tc.extensions))
			if !ok || fp.String() != tc.want {
				t.Fatalf("JA4 = %s (%v), want %s", fp, ok, tc.want)
			}
		})
	}
}

func TestJA4ALPN(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  string
	}{
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"h", "hh"},
		{"\xab", "ab"},
		{"\x20", "20"},
		{"\xab\xcd", "ad"},
		{"\x20\x61", "21"},
		{"\x30\xab", "3b"},
		{"\x61\x20", "60"},
		{"\x30\x31\xab\xcd", "3d"},
		{"\x30\xab\xcd\x31", "01"},
		{"", "00"},
	} {
		fp, ok := ComputeJA4(buildJA4Hello(0x0303, specSuites, []ja4Extension{alpnExtension(tc.value)}))
		if !ok || string(fp[8:10]) != tc.want {
			t.Errorf("ALPN %x: JA4 = %s, want %s", tc.value, fp, tc.want)
		}
	}
	fp, _ := ComputeJA4(buildJA4Hello(0x0303, specSuites, []ja4Extension{{typ: 0x0010}}))
	if string(fp[8:10]) != "00" {
		t.Errorf("empty ALPN extension: %s", fp)
	}
}

func TestJA4VersionAndCounts(t *testing.T) {
	many := make([]uint16, 120)
	for i := range many {
		many[i] = uint16(0x0100 + i)
	}
	fp, ok := ComputeJA4(buildJA4Hello(0x0301, many, []ja4Extension{{typ: 0x002b, data: append([]byte{4}, u16s(0x3a3a, 0x0302)...)}}))
	if !ok || string(fp[:8]) != "t11i9901" {
		t.Fatalf("JA4 = %s", fp)
	}
	fp, _ = ComputeJA4(buildJA4Hello(0x0300, specSuites, nil))
	if string(fp[1:3]) != "s3" {
		t.Fatalf("SSL 3.0 JA4 = %s", fp)
	}
	fp, _ = ComputeJA4(buildJA4Hello(0x1234, specSuites, nil))
	if string(fp[1:3]) != "00" {
		t.Fatalf("unknown version JA4 = %s", fp)
	}
}

// No prefix of a hello can make ComputeJA4 panic, and a cut hello is
// rejected or keeps the declared length.
func TestJA4Malformed(t *testing.T) {
	hello := buildJA4Hello(0x0303, specSuites, specExtensions(specSigAlg))
	for n := range len(hello) {
		if _, ok := ComputeJA4(hello[:n]); ok {
			t.Fatalf("prefix %d accepted", n)
		}
	}
	bad := append([]byte(nil), hello...)
	bad[0] = 2
	if _, ok := ComputeJA4(bad); ok {
		t.Fatal("ServerHello accepted")
	}
	// An extension length past the end of the list.
	bad = buildJA4Hello(0x0303, specSuites, []ja4Extension{{typ: 0x0017, data: []byte{1}}})
	bad[len(bad)-3]++
	if _, ok := ComputeJA4(bad); ok {
		t.Fatal("bad extension length accepted")
	}
}

func TestJA4DoesNotAllocate(t *testing.T) {
	hello := buildJA4Hello(0x0303, specSuites, specExtensions(specSigAlg))
	if allocs := testing.AllocsPerRun(100, func() { _, _ = ComputeJA4(hello) }); allocs != 0 {
		t.Fatalf("ComputeJA4 allocates %.0f times", allocs)
	}
}

func BenchmarkComputeJA4(b *testing.B) {
	for _, tc := range []struct {
		name  string
		hello []byte
	}{
		{"spec", buildJA4Hello(0x0303, specSuites, specExtensions(specSigAlg))},
		{"chrome-pq", mustVectorPayload(b, "t13d1517h2_8daaf6152771_cb7bf5808d99")},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_, _ = ComputeJA4(tc.hello)
			}
		})
	}
}

func mustVectorPayload(b *testing.B, ja4 string) []byte {
	b.Helper()
	data, err := os.ReadFile("testdata/ja4_vectors.txt")
	if err != nil {
		b.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) == 4 && fields[2] == ja4 {
			payload, err := hex.DecodeString(fields[3])
			if err != nil {
				b.Fatal(err)
			}
			return payload
		}
	}
	b.Fatalf("no vector %s", ja4)
	return nil
}
