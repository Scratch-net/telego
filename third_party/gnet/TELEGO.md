# Telego gnet patch

This directory contains the local Telego copy of [gnet v2.10.0](https://github.com/panjf2000/gnet/tree/v2.10.0).

| Source | Recorded value |
|---|---|
| Module | `github.com/panjf2000/gnet/v2` |
| Upstream revision | `58b59a11350707153f8c48369693ab9beba7b2fa` |
| Module checksum | `h1:rC4jNF+jtXj/FH+8JOIQ3XxjD+yBunYBLKg9TE3dc4g=` |
| License | [Apache License 2.0](LICENSE) |

The root module uses this directory through a local `replace` directive.
The upstream copyright notices, license, and tests remain in this copy.
The local module files use Go 1.27.3 and updated dependencies, including the test dependencies.
Reviewed Go 1.27 `go fix` updates use integer-range loops, typed atomics, and standard-library helpers.
The updates cover both the default and optimized build variants.

## Local changes

Telego maintains local changes for client shutdown completion, enrollment ownership, and registration errors.
Poller changes serialize notifications with descriptor closure and discard queued tasks after the owner stops.
Modified source files identify the Telego changes. The upstream copyright notices remain.

Linux TCP listeners recover from pending-connection network errors without stopping the engine.
Resource exhaustion and permanent listener errors retain their existing shutdown behavior.
The accept regression gate injects errors through temporary source overlays; production syscalls have no test hooks.

The optional `OwnedWriter` API retains caller-owned output slices until socket drain or disposal.
Telego charges each complete allocation until its release callback runs. Partial writes do not release that charge.
Buffer operations unlink the complete processed batch before release callbacks run. These callbacks can reenter the connection without duplicate writes.
Ordinary `Write` and `AsyncWrite` retain their existing copy semantics.

Unix write and close operations collect at most 1,024 descriptors before each system call.
Each event loop has one fixed descriptor array: 24KiB on 64-bit systems and 12KiB on 32-bit systems.
The owner clears its descriptor references before release callbacks run, so reentrant writes reuse the array safely.
Public buffer `Peek` methods retain their existing behavior.
Close still disposes all remaining output nodes synchronously. This change bounds descriptor collection, not total close work.

`ExecuteHighPriority` submits owned writes through the Unix high-priority FIFO queue.
Unsupported owners, including the Windows owner, return an error instead of an unordered fallback.

Test-only changes restrict the default-poller example to its supported build and remove a guaranteed-reuse assumption from the `sync.Pool` test.
UDP proxy tests use ephemeral backend ports and clean up partial setup.
Device-specific IPv6 tests skip only when the selected interface has no IPv6 address.

The release targets are Linux amd64, arm64, and arm/v7.

The optional Unix `ReadController` API pauses socket reads while output capacity is exhausted.
The connection owner calls both methods. Pending writes remain active during a read pause.
Resume retries retained input before it enables new reads. Peer EOF waits until the consumer resumes.
Read suspension applies to both pollers and both readiness modes. Windows retains its existing read path.

## Verification

Root `go test ./...` does not include this nested module.
`make test-gnet` runs only the named regressions for Telego's local patches, not the upstream test suite.
The three builds use default race, `gc_opt` race, and `poll_opt,gc_opt` production tags.
The script limits package parallelism to one, test parallelism to two, and each package to 120 seconds.
The test script creates a temporary workspace that uses the root dependency versions. Neither module file changes.
`make test` runs the dependency gates and the Telego gates.

The optimized poller uses unsafe attachments that are incompatible with the race detector's pointer checks.
Its gate uses a non-race build.

`read_control_unix_test.go` covers paused writes, repeated pressure, peer EOF, shutdown, and a stale resume after close.

`registration_shutdown_regression_test.go` checks accepted enrollment during owner shutdown through the upstream public APIs.
The test fails on the recorded upstream revision and passes with this patch.

The `owned_write_*_test.go` tests cover real partial socket writes, disposal, and reentrant release callbacks.
The buffer tests cover mixed ordinary and owned output, partial consumption, and release on close.

## Update

1. Compare the new upstream source with the revision in this document.
2. Preserve the upstream license, copyright notices, and tests.
3. Reapply the local lifecycle and owned-buffer changes with their regression tests.
4. Update the module requirements, replacements, and this provenance together.
5. Run `make test` from the repository root.
6. Build the Linux release targets with `poll_opt,gc_opt`.

If upstream includes the required lifecycle and owned-buffer APIs, remove the local replacement in the same reviewed change.
The upstream implementation must pass the local regression tests.

## Rollback

Restore the prior Telego source and local dependency together.
Do not remove only the replacement directives. The Telego integration uses the local lifecycle and owned-buffer APIs.
