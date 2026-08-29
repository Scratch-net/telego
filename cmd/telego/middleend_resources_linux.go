//go:build linux

package main

import "golang.org/x/sys/unix"

func currentFileDescriptorLimit() (fileDescriptorLimit, error) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fileDescriptorLimit{}, err
	}
	return fileDescriptorLimit{soft: limit.Cur, hard: limit.Max}, nil
}
