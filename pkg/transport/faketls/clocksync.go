package faketls

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// clockOffsetSeconds is a process-wide correction (server_time - local_time)
// applied to the handshake time-skew check. A grossly wrong VPS clock would
// otherwise reject every client's timestamped ClientHello. Set once at startup
// by SyncClock; 0 when no correction is configured.
var clockOffsetSeconds atomic.Int64

// maxClockOffset clamps the correction to +-1 day, matching upstream, so a
// malformed or hostile Date header can't push the skew window arbitrarily.
const maxClockOffset = int64(24 * 60 * 60)

// ClockOffset returns the current clock correction in seconds.
func ClockOffset() int64 { return clockOffsetSeconds.Load() }

// correctedNow returns the local time adjusted by the configured clock offset.
func correctedNow() time.Time {
	off := clockOffsetSeconds.Load()
	if off == 0 {
		return time.Now()
	}
	return time.Now().Add(time.Duration(off) * time.Second)
}

// SyncClock fetches url and derives a clock correction from its HTTP Date
// header (RFC 7231 IMF-fixdate, parsed by net/http). The offset is clamped to
// +-1 day and stored for use by the handshake time-skew check. Returns the
// applied offset in seconds.
func SyncClock(url string, timeout time.Duration) (int64, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	dateHdr := resp.Header.Get("Date")
	if dateHdr == "" {
		return 0, fmt.Errorf("no Date header from %s", url)
	}
	serverTime, err := http.ParseTime(dateHdr)
	if err != nil {
		return 0, fmt.Errorf("parse Date %q: %w", dateHdr, err)
	}

	offset := int64(time.Until(serverTime).Round(time.Second) / time.Second)
	if offset > maxClockOffset {
		offset = maxClockOffset
	} else if offset < -maxClockOffset {
		offset = -maxClockOffset
	}
	clockOffsetSeconds.Store(offset)
	return offset, nil
}
