//go:build !linux

package config

func currentFileDescriptorSoftLimit() (uint64, bool) { return 0, false }
