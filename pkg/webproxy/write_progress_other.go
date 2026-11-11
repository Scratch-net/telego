//go:build !linux

package webproxy

import "github.com/panjf2000/gnet/v2"

func socketBytesAcked(gnet.Conn) (uint64, bool) { return 0, false }
