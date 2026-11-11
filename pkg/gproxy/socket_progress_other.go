//go:build !linux

package gproxy

func socketAckedBytes(clientEndpoint) (uint64, bool) { return 0, false }
