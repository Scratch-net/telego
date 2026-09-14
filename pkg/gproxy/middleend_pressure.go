package gproxy

import (
	"time"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func (c *middleEndClient) observeResponseOutputWait(wait middleend.ResponseOutputWait) {
	if c.responseOutputWait != wait {
		c.responseOutputWait = wait
		c.responseOutputWaitSince = time.Time{}
		if wait != middleend.ResponseOutputNotWaiting {
			c.responseOutputWaitSince = time.Now()
		}
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
		StallDeadline: c.outputStallDeadline,
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
