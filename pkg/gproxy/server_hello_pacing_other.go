//go:build !linux

package gproxy

import (
	"io"

	"github.com/panjf2000/gnet/v2"
)

const serverHelloPacingSupported = false

func serverHelloSocketBusy(gnet.Conn) (bool, error) { return false, nil }

func writeServerHelloChunk(conn gnet.Conn, chunk []byte) (int, error) {
	n, err := conn.Write(chunk)
	if err == nil && n != len(chunk) {
		err = io.ErrShortWrite
	}
	return n, err
}
