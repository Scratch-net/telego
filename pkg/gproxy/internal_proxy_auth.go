package gproxy

import (
	"crypto/rand"
	"crypto/subtle"
)

const internalProxyAuthTokenSize = 32

var internalProxyPrefaceMagic = []byte("TELEGO-WEB-PROXY/1\x00")

// InternalProxyAuth authenticates the private in-process WEB-to-MTProxy hop.
// Its token is generated once, remains only in memory, and is never formatted.
type InternalProxyAuth struct {
	token [internalProxyAuthTokenSize]byte
}

// NewInternalProxyAuth creates one process-local authentication token.
func NewInternalProxyAuth() (*InternalProxyAuth, error) {
	auth := new(InternalProxyAuth)
	if _, err := rand.Read(auth.token[:]); err != nil {
		return nil, err
	}
	return auth, nil
}

// AppendPreface appends the private authentication preface to dst.
func (a *InternalProxyAuth) AppendPreface(dst []byte) []byte {
	if a == nil {
		return dst
	}
	dst = append(dst, internalProxyPrefaceMagic...)
	return append(dst, a.token[:]...)
}

func (a *InternalProxyAuth) prefaceStatus(data []byte) internalPrefaceStatus {
	if a == nil {
		return internalPrefaceNoMatch
	}
	compared := min(len(data), len(internalProxyPrefaceMagic))
	if subtle.ConstantTimeCompare(data[:compared], internalProxyPrefaceMagic[:compared]) != 1 {
		return internalPrefaceNoMatch
	}
	if len(data) < len(internalProxyPrefaceMagic)+internalProxyAuthTokenSize {
		return internalPrefaceIncomplete
	}
	start := len(internalProxyPrefaceMagic)
	if subtle.ConstantTimeCompare(data[start:start+internalProxyAuthTokenSize], a.token[:]) != 1 {
		return internalPrefaceRejected
	}
	return internalPrefaceAccepted
}

func (a *InternalProxyAuth) prefaceLen() int {
	return len(internalProxyPrefaceMagic) + internalProxyAuthTokenSize
}

// String prevents accidental token disclosure through ordinary formatting.
func (*InternalProxyAuth) String() string {
	return "[redacted]"
}

// GoString prevents accidental token disclosure through Go-syntax formatting.
func (*InternalProxyAuth) GoString() string {
	return "gproxy.InternalProxyAuth([redacted])"
}

type internalPrefaceStatus uint8

const (
	internalPrefaceNoMatch internalPrefaceStatus = iota
	internalPrefaceIncomplete
	internalPrefaceAccepted
	internalPrefaceRejected
)
