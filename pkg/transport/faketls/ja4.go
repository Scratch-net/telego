package faketls

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
)

// JA4Len is the length of a JA4 fingerprint, for example
// "t13d1516h2_8daaf6152771_e5627efa2ab1".
const JA4Len = 36

// JA4 is the JA4 TLS client fingerprint of a ClientHello. See
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md.
type JA4 [JA4Len]byte

func (f JA4) String() string { return string(f[:]) }

const (
	extensionServerName          = 0x0000
	extensionALPN                = 0x0010
	extensionSignatureAlgorithms = 0x000d
)

// ComputeJA4 returns the JA4 fingerprint of a ClientHello handshake message
// (the record payload: type, 24-bit length, body) received over TCP. It does
// not authenticate the hello. It reports false for a malformed hello. It does
// not allocate for ordinary hellos.
func ComputeJA4(payload []byte) (JA4, bool) {
	var fp JA4
	if len(payload) < 4 || payload[0] != handshakeTypeClient {
		return fp, false
	}
	length := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if length > len(payload)-4 {
		return fp, false
	}
	body := payload[4 : 4+length]

	// legacy_version(2) random(32) session_id
	if len(body) < 2+32+1 {
		return fp, false
	}
	version := binary.BigEndian.Uint16(body)
	pos := 2 + 32
	pos += 1 + int(body[pos])
	if pos+2 > len(body) {
		return fp, false
	}
	suitesLen := int(binary.BigEndian.Uint16(body[pos:]))
	pos += 2
	if suitesLen%2 != 0 || pos+suitesLen > len(body) {
		return fp, false
	}
	var suiteStack [64]uint16
	suites := suiteStack[:0]
	for i := pos; i < pos+suitesLen; i += 2 {
		if suite := binary.BigEndian.Uint16(body[i:]); !isGREASE(suite) {
			suites = append(suites, suite)
		}
	}
	pos += suitesLen
	if pos+1 > len(body) {
		return fp, false
	}
	pos += 1 + int(body[pos])
	if pos > len(body) {
		return fp, false
	}
	var extensions []byte
	if pos+2 <= len(body) {
		extensionsLen := int(binary.BigEndian.Uint16(body[pos:]))
		pos += 2
		if pos+extensionsLen > len(body) {
			return fp, false
		}
		extensions = body[pos : pos+extensionsLen]
	}

	var typeStack [32]uint16
	types := typeStack[:0] // without GREASE, SNI and ALPN
	extensionCount := 0
	hasSNI := false
	var alpn, signatureAlgorithms []byte
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return fp, false
		}
		typ := binary.BigEndian.Uint16(extensions)
		dataLen := int(binary.BigEndian.Uint16(extensions[2:]))
		if 4+dataLen > len(extensions) {
			return fp, false
		}
		data := extensions[4 : 4+dataLen]
		extensions = extensions[4+dataLen:]
		if isGREASE(typ) {
			continue
		}
		extensionCount++
		switch typ {
		case extensionServerName:
			hasSNI = true
			continue
		case extensionALPN:
			alpn = firstALPN(data)
			continue
		case extensionSupportedVersions:
			if highest := highestVersion(data); highest != 0 {
				version = highest
			}
		case extensionSignatureAlgorithms:
			if len(data) >= 2 {
				signatureAlgorithms = data[2:min(2+int(binary.BigEndian.Uint16(data)), len(data))]
			}
		}
		types = append(types, typ)
	}

	fp[0] = 't'
	copy(fp[1:3], ja4Version(version))
	fp[3] = 'i'
	if hasSNI {
		fp[3] = 'd'
	}
	putTwoDigits(fp[4:6], len(suites))
	putTwoDigits(fp[6:8], extensionCount)
	putALPN(fp[8:10], alpn)
	fp[10] = '_'
	fp[23] = '_'

	var textStack [512]byte
	if len(suites) == 0 {
		copy(fp[11:23], "000000000000")
	} else {
		slices.Sort(suites)
		text := appendHexList(textStack[:0], suites)
		putHash12(fp[11:23], text)
	}
	if len(types) == 0 {
		copy(fp[24:36], "000000000000")
	} else {
		slices.Sort(types)
		text := appendHexList(textStack[:0], types)
		separator := byte('_')
		for i := 0; i+2 <= len(signatureAlgorithms); i += 2 {
			algorithm := binary.BigEndian.Uint16(signatureAlgorithms[i:])
			if isGREASE(algorithm) {
				continue
			}
			text = append(text, separator)
			text = appendHex4(text, algorithm)
			separator = ','
		}
		putHash12(fp[24:36], text)
	}
	return fp, true
}

// isGREASE reports an RFC 8701 GREASE value: 0x?a?a with equal bytes.
func isGREASE(value uint16) bool {
	return byte(value>>8) == byte(value) && value&0x0f0f == 0x0a0a
}

// highestVersion returns the highest non-GREASE value of a ClientHello
// supported_versions extension, or 0.
func highestVersion(data []byte) uint16 {
	if len(data) < 1 {
		return 0
	}
	list := data[1:min(1+int(data[0]), len(data))]
	var highest uint16
	for i := 0; i+2 <= len(list); i += 2 {
		if version := binary.BigEndian.Uint16(list[i:]); !isGREASE(version) && version > highest {
			highest = version
		}
	}
	return highest
}

// firstALPN returns the first protocol of an ALPN extension, or nil.
func firstALPN(data []byte) []byte {
	if len(data) < 3 {
		return nil
	}
	list := data[2:min(2+int(binary.BigEndian.Uint16(data)), len(data))]
	if len(list) < 1 || 1+int(list[0]) > len(list) {
		return nil
	}
	return list[1 : 1+int(list[0])]
}

func ja4Version(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func putTwoDigits(dst []byte, n int) {
	n = min(n, 99)
	dst[0] = byte('0' + n/10)
	dst[1] = byte('0' + n%10)
}

// putALPN writes the first and last characters of the first ALPN value.
// A value that does not start and end with an ASCII letter or digit uses
// the first and last characters of its hex form.
func putALPN(dst []byte, value []byte) {
	if len(value) == 0 {
		dst[0], dst[1] = '0', '0'
		return
	}
	first, last := value[0], value[len(value)-1]
	if isAlphanumeric(first) && isAlphanumeric(last) {
		dst[0], dst[1] = first, last
		return
	}
	const digits = "0123456789abcdef"
	dst[0], dst[1] = digits[first>>4], digits[last&0x0f]
}

func isAlphanumeric(b byte) bool {
	return '0' <= b && b <= '9' || 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z'
}

func appendHex4(dst []byte, value uint16) []byte {
	return hex.AppendEncode(dst, []byte{byte(value >> 8), byte(value)})
}

func appendHexList(dst []byte, values []uint16) []byte {
	for i, value := range values {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendHex4(dst, value)
	}
	return dst
}

// putHash12 writes the first 12 hex characters of the SHA-256 of text.
func putHash12(dst []byte, text []byte) {
	sum := sha256.Sum256(text)
	hex.Encode(dst, sum[:6])
}
