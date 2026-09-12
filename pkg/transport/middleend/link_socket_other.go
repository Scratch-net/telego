//go:build !linux

package middleend

import (
	"time"

	"github.com/panjf2000/gnet/v2"
)

func captureOwnerSocket(gnet.Conn) LinkSocketSnapshot {
	return LinkSocketSnapshot{Status: LinkSocketUnsupported, At: time.Now()}
}
