// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.

package gnet

// ReadController is the optional Unix stream backpressure API. Both methods
// must run on the connection owner, like Write. PauseRead stops socket reads
// without stopping writes. ResumeRead schedules buffered input before it
// restores socket reads, so an exhausted consumer can pause again safely.
// Close and engine shutdown remain available while reads are paused.
// Windows connections do not implement this interface.
type ReadController interface {
	PauseRead() error
	ResumeRead() error
}
