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

# Run only the regressions for Telego's local patches, not the upstream suite.
test_names='TestTelegoClientStartFailureCompletesOnce
TestTelegoServerPartialStartFailureClosesPreparedPoller
TestTelegoClientConcurrentStopAndAutomaticDone
TestTelegoClientStopBeforeAndDuringStart
TestTelegoEnrollmentOnOpenActions
TestTelegoEnrollmentPreCanceledContext
TestTelegoRegistrationReportsPollerError
TestTelegoPostDuplicationFailuresDisposeDescriptor
TestTelegoClientDialCanceledByStop
TestTelegoRegistrationCancellationReleasesPendingDescriptor
TestTelegoClientExplicitStopRetiresEnrollmentBeforeOwnerJoin
TestTelegoClientTerminalErrorIsRetained
TestTelegoAcceptedEnrollmentOwnerExitDisposesSocket
TestOwnedWriteRealPartialSocketDrainRetainsAllocation
TestOwnedWriteReleaseReentryDoesNotRepeatWrittenBatch
TestPollerCloseWaitsForAcceptedTrigger
TestPollerCloseRejectsLateTriggerAndPreservesReusedFDs
TestPollerTriggerPreservesPriorityAndDiscardsBothQueues
TestPollerEventfdFailurePreservesStdin
TestOwnedBufferMixedOrderAndPartialDisposal
TestOwnedBufferReleaseUnlinksBeforeReentry
TestOwnedBufferReadAndWriteToKeepPartialAllocation'
test_filter="^($(printf '%s' "$test_names" | tr '\n' '|'))$"
set -- -mod=readonly -run="$test_filter"

sh "$test_root/dist/test-go.sh" "$@" -race . ./pkg/netpoll ./pkg/buffer/elastic
sh "$test_root/dist/test-go.sh" "$@" -race -tags=gc_opt . ./pkg/netpoll ./pkg/buffer/elastic
# poll_opt uses unsafe attachments that are incompatible with race checkptr.
sh "$test_root/dist/test-go.sh" "$@" -tags=poll_opt,gc_opt . ./pkg/netpoll ./pkg/buffer/elastic
