// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.
// Telego local modification: keep pending TCP recovery Linux-specific. See TELEGO.md.

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package gnet

func isPendingTCPAcceptError(string, error) bool { return false }
