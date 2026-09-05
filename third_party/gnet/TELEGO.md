# Telego gnet patch

This directory contains the local Telego copy of [gnet v2.10.0](https://github.com/panjf2000/gnet/tree/v2.10.0).

| Source | Recorded value |
|---|---|
| Module | `github.com/panjf2000/gnet/v2` |
| Upstream revision | `58b59a11350707153f8c48369693ab9beba7b2fa` |
| Module checksum | `h1:rC4jNF+jtXj/FH+8JOIQ3XxjD+yBunYBLKg9TE3dc4g=` |
| License | [Apache License 2.0](LICENSE) |

The root module and `benchmark/gnet_vs_uring` use this directory through local `replace` directives.
The upstream module files, copyright notices, license, and tests remain in this copy.

## Local changes

Telego maintains local changes for client shutdown completion, enrollment ownership, and registration errors.
Poller changes serialize notifications with descriptor closure and discard queued tasks after the owner stops.
Modified source files identify the Telego changes. The upstream copyright notices remain.

Test-only changes restrict the default-poller example to its supported build and remove a guaranteed-reuse assumption from the `sync.Pool` test.
UDP proxy tests use ephemeral backend ports and clean up partial setup.
Device-specific IPv6 tests skip only when the selected interface has no IPv6 address.

The release targets are Linux amd64, arm64, and arm/v7.

## Verification

Root `go test ./...` does not include this nested module.
`make test-gnet` runs its complete test suite with default race, `gc_opt` race, and `poll_opt,gc_opt` production builds.
The test script creates a temporary workspace that uses the root dependency versions. Neither module file changes.
`make test` runs the dependency gates and the Telego gates.

The optimized poller uses unsafe attachments that are incompatible with the race detector's pointer checks.
Its gate uses a non-race build.

`registration_shutdown_regression_test.go` checks accepted enrollment during owner shutdown through the upstream public APIs.
The test fails on the recorded upstream revision and passes with this patch.

## Update

1. Compare the new upstream source with the revision in this document.
2. Preserve the upstream license, copyright notices, and tests.
3. Reapply the local lifecycle changes and their regression tests.
4. Update the module requirements, replacements, and this provenance together.
5. Run `make test` from the repository root.
6. Build the Linux release targets with `poll_opt,gc_opt`.

If upstream includes the required lifecycle APIs and regression fixes, remove both local replacements in the same reviewed change.

## Rollback

Restore the prior Telego source and local dependency together.
Do not remove only the replacement directives. The Telego integration uses the local lifecycle APIs.
