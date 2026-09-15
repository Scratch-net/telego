package gproxy

import (
	"time"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func (c *middleEndClient) observeResponseOutputWait(wait middleend.ResponseOutputWait) {
	c.observeResponseOutputWaitAt(wait, time.Now())
}

func (c *middleEndClient) observeResponseOutputWaitAt(wait middleend.ResponseOutputWait, now time.Time) {
	if wait >= middleend.ResponseOutputWaitCount {
		return
	}
	if c.responseOutputWait != wait {
		if previous := c.responseOutputWait; previous != middleend.ResponseOutputNotWaiting {
			stats := &c.frontend.responseWaits[previous]
			stats.duration.Add(uint64(max(0, now.Sub(c.responseOutputWaitSince).Microseconds())))
			stats.completed.Add(1)
			stats.active.Add(-1)
		}
		c.responseOutputWait = wait
		c.responseOutputWaitSince = time.Time{}
		if wait != middleend.ResponseOutputNotWaiting {
			c.responseOutputWaitSince = now
			stats := &c.frontend.responseWaits[wait]
			stats.entered.Add(1)
			stats.active.Add(1)
		}
		c.reportResponseProgress(now, int(c.outputAccounted.Load()))
	}
}

func (c *middleEndClient) recordResponseStallClosure() {
	if !c.responseStallClosed {
		c.responseStallClosed = true
		c.frontend.responseStallClosures.Add(1)
	}
}

// The owner captures live buffer size before terminal handling. OnClose uses
// cached accounting because transport teardown may already have drained buffers.
func (c *middleEndClient) reportResponsePressureOutput(connection clientEndpoint, maximum int, closing bool) {
	_, web := connection.(*LogicalStream)
	output := middleend.ResponsePressureOutput{
		At: time.Now(), Closing: closing, Web: web,
		AccountedBytes: c.outputAccounted.Load(), BufferLimit: maximum,
		SharedAccountedBytes: c.frontend.outputBudget.current.Load(), SharedLimit: c.frontend.outputBudget.limit,
		LastWriteAt: c.responseLastWriteAt, LastBufferDecreaseAt: c.responseLastBufferDecreaseAt,
		WriteBytes: c.responseWriteBytes, WriteEvents: c.responseWriteEvents,
		Wait: c.responseOutputWait, WaitSince: c.responseOutputWaitSince,
		StallDeadline:        c.outputStallDeadline,
		SharedResponseBudget: c.frontend.responseBudget != nil,
		ResponseBudget:       c.frontend.responseBudget.Snapshot(),
	}
	if output.SharedResponseBudget {
		output.SharedAccountedBytes, output.SharedLimit = 0, 0
	}
	if !closing {
		output.BufferedAvailable = true
		output.BufferedBytes = connection.OutboundBuffered()
	}
	c.retryMu.Lock()
	output.RetryPending = c.retryTimer != nil
	c.retryMu.Unlock()
	c.binding.ReportResponsePressureOutput(output)
}
