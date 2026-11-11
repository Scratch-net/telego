package faketls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"slices"
)

const (
	extensionSupportedVersions = 0x002b
	extensionKeyShare          = 0x0033
	extensionPreSharedKey      = 0x0029

	groupX25519    = 0x001d
	groupSecp256r1 = 0x0017
	groupSecp384r1 = 0x0018
	groupSecp521r1 = 0x0019

	// X25519MLKEM768 server share: ML-KEM-768 ciphertext (1088) || X25519 (32).
	pqServerKeyLen = 1120
)

var errServerHelloTemplate = errors.New("invalid ServerHello template")

// ServerHelloTemplate is the shape of a captured TLS 1.3 ServerHello: record
// version, cipher suite, key_share group, and the extension list in captured
// order. It holds no per-connection value. The session ID echo, the cipher
// suite, and the key share are chosen for each client when the template is
// built. A template is immutable after parsing and safe for concurrent use.
type ServerHelloTemplate struct {
	recordVersion [2]byte
	cipherSuite   uint16
	group         uint16
	extensions    []templateExtension // key_share data is rebuilt per client
}

type templateExtension struct {
	typ  uint16
	data []byte
}

// ParseServerHelloTemplate parses the first TLS record of a mask host's
// response. It accepts only a TLS 1.3 ServerHello with a key_share: a
// TLS 1.2 ServerHello followed by our ChangeCipherSpec and ApplicationData
// would not match a real TLS 1.2 handshake.
func ParseServerHelloTemplate(record []byte) (*ServerHelloTemplate, error) {
	// RFC 8446 section 5.1: a server's records carry version 0x0303, and the
	// Telegram client checks this prefix.
	if len(record) < RecordHeaderSize || record[0] != RecordTypeHandshake || record[1] != 0x03 || record[2] != 0x03 {
		return nil, errServerHelloTemplate
	}
	if int(binary.BigEndian.Uint16(record[3:5])) != len(record)-RecordHeaderSize {
		return nil, errServerHelloTemplate
	}
	message := record[RecordHeaderSize:]
	if len(message) < 4+2+32+1 || message[0] != 0x02 ||
		int(message[1])<<16|int(message[2])<<8|int(message[3]) != len(message)-4 {
		return nil, errServerHelloTemplate
	}
	pos := 4 + 2 + 32
	sessionLen := int(message[pos])
	pos += 1 + sessionLen
	if sessionLen > 32 || pos+2+1+2 > len(message) || message[pos+2] != 0 {
		return nil, errServerHelloTemplate
	}
	template := &ServerHelloTemplate{
		recordVersion: [2]byte{record[1], record[2]},
		cipherSuite:   binary.BigEndian.Uint16(message[pos:]),
	}
	pos += 3
	if int(binary.BigEndian.Uint16(message[pos:])) != len(message)-pos-2 {
		return nil, errServerHelloTemplate
	}
	pos += 2
	tls13, keyShare := false, false
	for pos < len(message) {
		if len(message)-pos < 4 {
			return nil, errServerHelloTemplate
		}
		typ := binary.BigEndian.Uint16(message[pos:])
		length := int(binary.BigEndian.Uint16(message[pos+2:]))
		pos += 4
		if length > len(message)-pos {
			return nil, errServerHelloTemplate
		}
		data := message[pos : pos+length]
		pos += length
		switch typ {
		case extensionSupportedVersions:
			tls13 = bytes.Equal(data, []byte{0x03, 0x04})
		case extensionKeyShare:
			if length < 4 || int(binary.BigEndian.Uint16(data[2:])) != length-4 {
				return nil, errServerHelloTemplate
			}
			template.group = binary.BigEndian.Uint16(data)
			keyShare = true
			data = nil
		case extensionPreSharedKey:
			// The client never offered a PSK to this server.
			continue
		}
		template.extensions = append(template.extensions, templateExtension{typ, bytes.Clone(data)})
	}
	if !tls13 || !keyShare {
		return nil, errServerHelloTemplate
	}
	return template, nil
}

// selectCipherSuite returns the template suite when the client offered it,
// else the first TLS 1.3 suite the client offered.
func (t *ServerHelloTemplate) selectCipherSuite(offered []uint16) uint16 {
	if slices.Contains(offered, t.cipherSuite) {
		return t.cipherSuite
	}
	for _, suite := range offered {
		if suite >= 0x1301 && suite <= 0x1305 {
			return suite
		}
	}
	return t.cipherSuite
}

// selectGroup returns the template group when the client sent a share for
// it, else the first client share group that a key share can be built for.
func (t *ServerHelloTemplate) selectGroup(offered []uint16) uint16 {
	if slices.Contains(offered, t.group) && keyShareLen(t.group) > 0 {
		return t.group
	}
	for _, group := range offered {
		if keyShareLen(group) > 0 {
			return group
		}
	}
	if keyShareLen(t.group) > 0 {
		return t.group
	}
	return groupX25519
}

// keyShareLen returns the server key_share length for a group, or 0 when
// no share can be built for it.
func keyShareLen(group uint16) int {
	switch group {
	case groupX25519:
		return 32
	case groupSecp256r1:
		return 65
	case groupSecp384r1:
		return 97
	case groupSecp521r1:
		return 133
	case pqNamedGroup:
		return pqServerKeyLen
	}
	return 0
}

// generateKeyShare returns a fresh server key share for a group that
// keyShareLen supports. Classical groups use a valid curve point. The PQ
// share is high-entropy bytes, as in the synthetic ServerHello.
func generateKeyShare(group uint16) []byte {
	var curve ecdh.Curve
	switch group {
	case groupX25519:
		return generateX25519Key()
	case groupSecp256r1:
		curve = ecdh.P256()
	case groupSecp384r1:
		curve = ecdh.P384()
	case groupSecp521r1:
		curve = ecdh.P521()
	default:
		key := make([]byte, keyShareLen(group))
		rand.Read(key)
		return key
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fallback := make([]byte, keyShareLen(group))
		rand.Read(fallback)
		return fallback
	}
	return key.PublicKey().Bytes()
}

// appendServerHelloRecord appends the ServerHello record for one client with
// a zero random at WelcomePacketRandomOffset.
func (t *ServerHelloTemplate) appendServerHelloRecord(buf *bytes.Buffer, hello *ClientHello) {
	group := t.selectGroup(hello.KeyShareGroups)
	key := generateKeyShare(group)

	body := make([]byte, 0, 128+len(key))
	body = append(body, 0x03, 0x03)
	body = append(body, emptyRandom...)
	body = append(body, byte(len(hello.SessionID)))
	body = append(body, hello.SessionID...)
	body = binary.BigEndian.AppendUint16(body, t.selectCipherSuite(hello.CipherSuites))
	body = append(body, 0x00)
	lengthAt := len(body)
	body = append(body, 0, 0)
	for _, extension := range t.extensions {
		body = binary.BigEndian.AppendUint16(body, extension.typ)
		if extension.typ == extensionKeyShare {
			body = binary.BigEndian.AppendUint16(body, uint16(4+len(key)))
			body = binary.BigEndian.AppendUint16(body, group)
			body = binary.BigEndian.AppendUint16(body, uint16(len(key)))
			body = append(body, key...)
			continue
		}
		body = binary.BigEndian.AppendUint16(body, uint16(len(extension.data)))
		body = append(body, extension.data...)
	}
	binary.BigEndian.PutUint16(body[lengthAt:], uint16(len(body)-lengthAt-2))

	messageLen := 4 + len(body)
	buf.Write([]byte{
		RecordTypeHandshake, t.recordVersion[0], t.recordVersion[1],
		byte(messageLen >> 8), byte(messageLen),
		0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
	})
	buf.Write(body)
}
