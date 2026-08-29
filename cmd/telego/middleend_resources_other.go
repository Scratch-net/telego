//go:build !linux

package main

func currentFileDescriptorLimit() (fileDescriptorLimit, error) {
	return fileDescriptorLimit{}, errFileDescriptorLimitUnavailable
}
