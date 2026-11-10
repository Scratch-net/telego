// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.
// Telego local modification: bounded socket read suspension. See TELEGO.md.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package gnet

import (
	"net"

	errorx "github.com/panjf2000/gnet/v2/pkg/errors"
	"github.com/panjf2000/gnet/v2/pkg/queue"
)

var _ ReadController = (*conn)(nil)

func (c *conn) PauseRead() error {
	if !c.opened || c.loop.connections.getConn(c.fd) != c {
		return net.ErrClosed
	}
	if c.isDatagram {
		return errorx.ErrUnsupportedOp
	}
	c.readPauseVersion++
	if c.readPaused {
		return nil
	}
	c.readPaused = true
	if err := c.updateReadPause(); err != nil {
		c.readPaused = false
		return err
	}
	return nil
}

func (c *conn) ResumeRead() error {
	if !c.opened || c.loop.connections.getConn(c.fd) != c {
		return net.ErrClosed
	}
	if c.isDatagram {
		return errorx.ErrUnsupportedOp
	}
	if !c.readPaused {
		return c.Wake(nil)
	}
	return c.loop.poller.Trigger(queue.LowPriority, c.resumeRead, nil)
}

func (c *conn) resumeRead(any) error {
	if !c.opened || c.loop.connections.getConn(c.fd) != c || !c.readPaused {
		return nil
	}
	// Leave kernel reads suspended during every buffered retry. A repeated
	// PauseRead records a blocked consumer even when the interest was already off.
	version, before := c.readPauseVersion, c.InboundBuffered()
	if err := c.loop.wake(c); err != nil {
		return err
	}
	if !c.opened || c.loop.connections.getConn(c.fd) != c || c.readPauseVersion != version {
		return nil
	}
	after := c.InboundBuffered()
	if after > 0 && after < before {
		// A progressing callback can consume only a prefix. Yield to the owner
		// queue before retrying it, without admitting another socket read.
		return c.loop.poller.Trigger(queue.LowPriority, c.resumeRead, nil)
	}
	// No retained input, or a parser that needs more bytes without requesting
	// backpressure. Restore readiness and explicitly read for preexisting ET data.
	c.readPaused = false
	if err := c.updateReadPause(); err != nil {
		return c.loop.close(c, err)
	}
	return c.loop.read(c)
}

func (c *conn) updateReadPause() error {
	edge := c.loop.engine.opts.EdgeTriggeredIO
	return c.loop.poller.ModReadPaused(&c.pollAttachment, c.readPaused, edge || !c.outboundBuffer.IsEmpty(), edge)
}

func (c *conn) modReadWrite() error {
	if c.readPaused {
		return c.updateReadPause()
	}
	return c.loop.poller.ModReadWrite(&c.pollAttachment, c.loop.engine.opts.EdgeTriggeredIO)
}

func (c *conn) modRead() error {
	if c.readPaused {
		return c.updateReadPause()
	}
	return c.loop.poller.ModRead(&c.pollAttachment, c.loop.engine.opts.EdgeTriggeredIO)
}
