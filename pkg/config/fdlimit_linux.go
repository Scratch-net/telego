//go:build linux

package config

import "golang.org/x/sys/unix"

func currentFileDescriptorSoftLimit() (uint64, bool) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return 0, false
	}
	return limit.Cur, true
}
