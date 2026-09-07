#!/bin/sh
set -eu

export GOMAXPROCS=2
# This is a soft Go runtime limit, not an operating-system memory boundary.
export GOMEMLIMIT=512MiB

# Go accepts these flags after the package list. Keep the normal gates bounded.
exec go test "$@" -count=1 -p=1 -parallel=2 -timeout=120s
