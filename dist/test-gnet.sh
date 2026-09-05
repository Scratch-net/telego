#!/bin/sh
set -eu

test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_workspace=$(mktemp -d)
cleanup() {
    rm -f "$test_workspace/go.work" "$test_workspace/go.work.sum"
    rmdir "$test_workspace"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Use the application dependency versions without changing either module file.
(
    cd "$test_workspace"
    GOWORK=off go work init "$test_root" "$test_root/third_party/gnet"
)
export GOWORK="$test_workspace/go.work"
cd "$test_root/third_party/gnet"

go test -mod=readonly -race -timeout 20m ./...
go test -mod=readonly -race -tags=gc_opt -timeout 20m ./...
# poll_opt uses unsafe attachments that are incompatible with race checkptr.
go test -mod=readonly -tags=poll_opt,gc_opt -timeout 20m ./...
