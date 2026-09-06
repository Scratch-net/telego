// Package goroutineleak adds Go's reachability-based leak check to TestMain.
// Production code must not import this test helper. Existing resource and
// goroutine-count assertions still cover leaks that this profile cannot find.
package goroutineleak

import (
	"fmt"
	"io"
	"runtime/pprof"
	"strconv"
	"strings"
)

// Run checks for leaked goroutines after run returns and all test cleanups
// finish. It preserves an existing failure code and never filters leaks.
func Run(run func() int, diagnostics io.Writer) int {
	code := run()
	if err := check(); err != nil {
		_, _ = fmt.Fprintln(diagnostics, "goroutine leak check:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func check() error {
	profile := pprof.Lookup("goroutineleak")
	if profile == nil {
		return fmt.Errorf("runtime does not provide the goroutineleak profile")
	}
	var output strings.Builder
	// WriteTo triggers the special leak-detection GC. Count alone is stale.
	// debug >= 2 includes non-leaked goroutines, so use the filtered text form.
	if err := profile.WriteTo(&output, 1); err != nil {
		return fmt.Errorf("collect fresh goroutineleak profile: %w", err)
	}
	return inspect(output.String())
}

func inspect(profile string) error {
	header, _, newline := strings.Cut(profile, "\n")
	value, prefix := strings.CutPrefix(header, "goroutineleak profile: total ")
	count, err := strconv.Atoi(value)
	if !newline || !prefix || err != nil || count < 0 {
		return fmt.Errorf("invalid goroutineleak profile header: %q", header)
	}
	if count != 0 {
		return fmt.Errorf("%d permanently blocked goroutines after test cleanup:\n%s", count, profile)
	}
	return nil
}
