package gproxy

import (
	"os"
	"testing"

	"github.com/scratch-net/telego/internal/testutil/goroutineleak"
)

func TestMain(m *testing.M) {
	os.Exit(goroutineleak.Run(m.Run, os.Stderr))
}
