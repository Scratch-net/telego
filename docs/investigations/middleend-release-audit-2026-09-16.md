# Middle-End release audit: 2026-09-16

The audit covered `v0.6.4..29ab4c25ff57d414e940e2568213039f5761cd0a`, including the response diagnostics and shared memory implementation.
Three independent reviews covered memory accounting, frontend output, and ME ingress.
The release checks also covered configuration, monitoring, and all published build architectures.

The audit found three defects. The subsequent correction and review cycle resolved all three.
The wider 32-bit gate found one additional test compilation defect, which the same cycle resolved.

## Corrections

### Connection counter alignment

`ProxyHandler.activeConns` was a plain `int64` at offset 84 on ARM and 386.
The first connection used an atomic increment without the required eight-byte alignment.
The connection test reproduced the panic on HEAD and an isolated `v0.6.4` archive, including production build tags.
ARMv7 compiler output used the same offset. This defect preceded the shared response implementation.

The counter now uses `atomic.Int64`. Every counter access uses its typed methods.
Existing connection admission, closure, and logical stream tests pass on 386.

### Cleanup before asynchronous reclamation

The fixed limit of 8,192 events released only 985,088 bytes from an ACK backlog on 386.
Maximum admission required 1,045,775 bytes. Admission failed before the cleanup worker supplied the remaining capacity.
A deterministic regression reproduced closure of a healthy incoming binding after eviction of the backlog owner.
The same regression passed on amd64 before the correction.

The event limit now derives from the maximum admission cost and the smallest queued allocation charge.
The byte limit still stops cleanup after enough actual ownership releases.
The calculation ignores chunk credit, so smaller architecture-specific metadata cannot cause premature termination.
The existing full-queue test now releases 1,045,842 bytes synchronously on 386.
The new regression preserves the healthy incoming binding before the worker runs.

### Response rejection during candidate preparation

Refresh and repair candidates previously installed their response sink after the probe.
Unexpected responses before installation entered a separate link channel without a shared response charge.
The probe rejected these responses later. Until rejection, candidates retained packets under their separate link-event allowance.

Both replacement paths now arm a response guard before startup, after they establish candidate ownership.
The guard rejects application responses before packet copying. Ping and Pong retain their channel behavior.
A rejection latches under the link mutex and prevents a simultaneous sink installation before owner closure.
Successful publication retains the existing single sink installation and incarnation checks.
Standalone links retain their channel contract.

Four encrypted-wire cases cover refresh and repair, at startup and during probing.
They require protocol rejection, zero candidate event retention, and continued incumbent service after failed refresh.
Removing the guard calls through a temporary overlay makes all four cases fail.
Those failures record 8,236 through 12,336 response bytes in the candidate channel.
Additional tests cover publication races, keepalives, setup failure, cancellation, and successful sink routing.

### Permanent 32-bit gate

`make test-32` runs the complete Telego suite on `linux/386` with production build tags.
The test and release workflows require this gate. Both workflows install Node 24 for the WEB bridge tests.
The gate found eight test diagnostic arguments whose untyped protocol constants exceeded the 32-bit `int` range.
Those arguments now use `uint32`. Public constants and test assertions retain their previous types and behavior.

## Final evidence

| Check | Result |
| --- | --- |
| Independent review of counter conversion and cleanup bound | No remaining findings |
| Independent review of candidate guard and wire coverage | No remaining findings |
| Follow-up review of diagnostic casts and release gate | No remaining findings |
| `make test` | Passed all three Telego modes and local gnet patch regressions |
| `make test-32` | Passed the complete Telego suite |
| Linux amd64, arm64, and ARMv7 production builds | Passed with `CGO_ENABLED=0` |
| Lint with `me_pressure_investigation` enabled | Passed |

The sandbox rejects 32-bit system calls. The 386 execution checks ran outside that sandbox.
ARM runtime execution was unavailable. Cross-compilation does not replace an ARM runtime test.
This correction cycle did not repeat the previous memory-cap load matrix or change the configured response budget.
The corrections remain local. This cycle did not push, publish, or deploy a release.
