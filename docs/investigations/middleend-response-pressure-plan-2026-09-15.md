This plan changes ME response admission and memory ownership.
Its target is recovery from temporary client pauses within a fixed memory budget.
At exhaustion, close selected bindings and preserve service for other clients.
Do not discard response bytes from a connection that remains open.

The [investigation](middleend-response-pressure-2026-09-15.md) records the incident, experiments, and current limitations.
The production baseline for this work is diagnostic commit `ed886efd3410828d6075bf86b7d3eb3f16055d8a`.
Phases 1 through 5 are implemented and passed their independent audit gates.
Local Phase 6 acceptance checks passed. Memory-cap measurements support the selected final default. Deployment and production validation remain pending.
The original phase instructions below remain acceptance criteria. Discovery statements describe the code before implementation.
The [implementation report](middleend-response-implementation-2026-09-15.md) records completed changes, audit corrections, and test evidence.

**Policy and memory scope**

Use one service-wide response budget across the frontend, active generation, retiring generation, and replacement candidates.
Each binding borrows available capacity instead of receiving a fixed allocation.
Keep local output caps as admission controls that defer work.
Remove the response policy that immediately evicts a binding at 2 MiB or 768 events.
Keep the existing 100-second no-progress timeout when the shared budget permits it.
Memory exhaustion can require an earlier closure.

Validation started with a provisional total of twice the existing queue budget, called `2Q` below.
That total was 64 MiB plus 32 KiB, including the processing reserve. It failed the synchronized 1,000-client burst.
The measured final default keeps `2Q` as ordinary capacity and adds the derived processing reserve inside the total pool.
On the current 64-bit build, ordinary capacity is 67,141,632 bytes and the reserve is 2,089,486 bytes. The total is 69,231,118 bytes.
Explicit nonzero `queue-budget-mb` values retain a total of `2Q`, including the reserve.
The response pool is not a process memory limit or a general capacity guarantee.
Preserve the existing request and input budget derivation.
Document the combined response meaning of explicit `queue-budget-mb` settings.
Do not add per-binding tuning settings.

Charge retained response allocations, queue metadata, and overlapping copies before allocation.
Keep bounded processing and control reserves inside the response budget.
Derive reserve sizes from maximum frame costs and bounded processing concurrency.
If a minimum configuration cannot support those reserves, report the configuration error explicitly.
Account separately for request buffers, input buffers, WEB carrier storage, runtime overhead, and kernel socket buffers.
Use these categories to explain the complete memory envelope during validation.

**Phase 0 — completed discovery**

Two read-only discovery tasks checked the budget and output APIs against current code.
The following capabilities already exist:

| Existing capability | Source | Reuse |
| --- | --- | --- |
| Service and generation construction | [service.go](../../pkg/transport/middleend/service.go), [generation_factory.go](../../pkg/transport/middleend/generation_factory.go) | Pass one budget through every generation. |
| Response routing and readiness tokens | [binding_manager.go](../../pkg/transport/middleend/binding_manager.go) | Preserve routing, ordering, cancellation, and stale-token checks. |
| Owner-loop writes with allocation release callbacks | [owned_write.go](../../third_party/gnet/owned_write.go), [relay_output.go](../../pkg/gproxy/relay_output.go) | Retain native output charges until the allocation is released. |
| Variable logical stream reservation | [logical_stream.go](../../pkg/gproxy/logical_stream.go) | Reserve the actual response bound for WEB output. |
| Non-mutating FakeTLS record sizing | [drs.go](../../pkg/transport/faketls/drs.go) | Plan output size without advancing record state. |
| Capacity snapshots and pressure diagnostics | [service.go](../../pkg/transport/middleend/service.go), [response_pressure.go](../../pkg/transport/middleend/response_pressure.go) | Extend existing monitoring. |

New capabilities are required for allocation ownership, queue-head sizing, shared progress observations, and production link event handoff.
`TryNextEvent()` currently removes the event and releases queue accounting immediately.
It does not expose a reservation or queue-head inspection API.
`ReportResponsePressureOutput` reports after eviction and cannot supply live victim-selection data.
There is no current ME read-pause API.

**Phase 1 — establish allocation ownership — complete and audited**

Implement a service-owned budget and explicit ownership handles for response allocations.
Pass the same budget through factories, managers, and frontend configuration.
Keep queued-byte statistics separate from retained-allocation charges.
Transfer ownership when an event leaves its queue.
Release charges only when the allocation is no longer retained.
Charge queue backing arrays, including temporary overlap during growth.

Define a bounded processing reserve that lets a full queue make progress.
Prevent stalled client output from consuming all processing or control capacity.
Write the ownership and lock-order contract before integrating the policy.
Never invoke client callbacks or wait for lifecycle completion while holding manager or budget locks.

References: [configuration](../../pkg/config/middleend.go), [binding manager](../../pkg/transport/middleend/binding_manager.go), and [generation supervisor](../../pkg/transport/middleend/generation_supervisor.go).
Verification: exercise allocation rejection, dequeue, cancellation, queue growth, shutdown, repair, and overlapping generations.
Prove that every charge releases exactly once and that combined usage never exceeds the service budget.
Reuse the shutdown, retirement, and two-generation tests.
Do not create an independent response pool for each generation.

**Phase 2 — reserve output by response size — complete and audited**

Add a safe queue-head descriptor or admission operation that preserves token validation and ordering.
Compute a pure framing bound for that response before changing encoder state.
Include the maximum padding for the actual packet and use `DRSState.PlanSize` for FakeTLS overhead.
Change shared, native, and WEB admission to use that bound.
Keep the current whole-response encryption path for this change.

Use native `gnet.OwnedWriter.WriteOwned` to retain the output allocation without another gnet copy.
Its callback can run synchronously and reenter the connection.
Make release handling safe for immediate completion, rejection, partial writes, and shutdown.
Add equivalent owned-buffer handling to logical WEB output, or explicitly charge all copy overlap until each owner releases it.
Preserve the existing carrier budget at the HTTP or WebSocket handoff.
Use unread bytes for progress detection and retained allocation capacity for memory accounting.

References: [frontend](../../pkg/gproxy/middleend_frontend.go), [output budget](../../pkg/gproxy/middleend_budget.go), [endpoint](../../pkg/gproxy/client_endpoint.go), and [packet encoder](../../pkg/transport/middleend/client_packet.go).
Verification: turn the three small-ACK failures into recovery tests.
Check DD and EE bytes, padding, record boundaries, single encryption after a wait, partial drains, and callback reentry.
Reuse the native owned-write capacity tests and logical-stream reservation tests.
Do not release a backing allocation because part of it drained or because its event left a queue.

**Phase 3 — remove the earlier production response bottleneck — complete and audited**

The physical ME event queue currently closes its shared link at its own limit.
The post-decode investigation harness does not test that path.
Integrate production gnet links with a bounded manager-owned event sink and shared response admission.
Treat this sink as a new API, with an implementation gate before policy rollout.

First prove sink installation and teardown for bootstrap, repair, candidate probes, publication, and generation closure.
Deliver outside the link lock, with bounded routing work and no wait for a slow client.
Reserve decode and event storage before allocation and avoid unbounded frame batches.
Keep the standalone channel contract explicit and test both delivery modes.
If the sink cannot satisfy these lifecycle and memory rules, resolve its design before continuing.

References: [gnet engine](../../pkg/transport/middleend/gnet_engine.go), [link contract](../../pkg/transport/middleend/link.go), [bootstrap decoder](../../pkg/transport/middleend/bootstrap.go), and [slot refresh](../../pkg/transport/middleend/slot_refresh.go).
Verification: use framed, encrypted ME traffic through the real link engine.
Exercise response bursts during repair, candidate probes, cancellation, and shutdown.
Require that client response pressure leaves the shared link and healthy bindings available.
Do not simulate read suspension by returning from `OnTraffic`, or solve the problem by enlarging every link queue.

**Phase 4 — admit bursts and evict under real pressure — complete and audited**

Replace fixed response byte and item cutoffs with borrowing from the shared budget.
Keep an explicit metadata bound for many small events.
Use bounded processing turns so one binding cannot monopolize an event loop.
Do not change request or control queue limits as a side effect.

Publish immutable or atomic per-binding observations of retained memory and output progress.
Use these observations across active and retiring generations.
At exhaustion, prefer bindings with a backlog and no recent progress.
Then prefer the largest consumers above their soft fair share.
Define stable tie-breaking, observation freshness, and bounded victim-selection work.
Reclaim only charges whose owners have released their allocations.
If closure is asynchronous, reject or defer admission until actual capacity is available.

Verification: convert the avoidable burst and small-event evictions into recovery assertions.
Test stalled, slowly progressing, and fast clients together.
Force actual exhaustion and verify bounded memory, selected binding closure, and continued traffic for healthy neighbors.
Test competition across generations and stale progress observations.
Do not treat a fair share as a hard per-binding limit or promise the full timeout at exhaustion.

**Phase 5 — expose the decisions — complete and audited**

Extend metrics with shared usage, limit, high-water mark, reserve usage, and retained bytes by stage.
Record admission waits and their duration, stall closures, and pressure evictions by reason.
Include pool occupancy, victim backlog, progress age, and reclaimed bytes in bounded diagnostic events.
Keep client and binding identifiers out of metric labels.
Keep existing lifetime eviction counters interpretable across rotation.

Update capacity reporting to count the shared pool once across overlapping generations.
Explain separately bounded storage outside the response pool.
Add pool occupancy, waiting duration, and eviction reasons to the existing NAS Grafana dashboards.
Update [ME documentation](../middle-end.md) with budget scope and exhaustion behavior.

References: [metrics](../../pkg/metrics/metrics.go), [capacity reporting](../../cmd/telego/middleend_monitor.go), and existing pressure diagnostics.
Verification: check metric names and bounded labels, capacity totals, diagnostic snapshots, and dashboard queries.
Do not represent the response limit as the process RSS limit.

**Phase 6 — local validation complete, release pending**

Run these acceptance groups after integration:

1. Repeat the DD, EE, logical WEB, and real HTTP recovery cases with exact payload and order checks.
2. Exercise actual HTTP and WebSocket output, including paused consumers and maximum-size responses.
3. Run 100 and 1,000 connections with staggered traffic, synchronized bursts, and mixed drain speeds.
4. Run full-budget exhaustion with concurrent generation rotation and confirm healthy-client progress.
5. Test cancellation, partial writes, synchronous callbacks, queue growth, and shutdown under the race detector.
6. Measure the server separately from the load generator under proposed 512 MiB, 1 GiB, and 2 GiB memory caps.

Record retained response usage, live heap, RSS, container memory, allocation rate, latency, and eviction reasons.
These memory profiles are test targets, not established support guarantees.
Require recovery when the retained allocation cost fits the budget and processing reserve.
Require controlled closure and bounded memory when it does not fit.
The synchronized 1,000-client native gate passed with the selected default under 512MiB, 1GiB, and 2GiB server caps.
Each run recovered all 3,000 responses with zero evictions and zero OOM events.
The [implementation report](middleend-response-implementation-2026-09-15.md#separate-process-native-memory-caps) records the matrix, memory peaks, socket constraints, and binary hashes.
Local carrier, topology, combined-pressure, audit, and repository checks also passed. Deployment and production validation remain pending.

Run the repository checks from [Makefile](../../Makefile): vendored gnet tests, race tests, `gc_opt` race tests, and production-tag tests.
Run the configured lint checks.
Promote essential investigation cases into regular regression coverage.
Keep expensive load characterization separate and reproducible.
Do not use the Go soft memory limit as proof against OOM.

After the gates pass, commit locally without pushing and deploy the validated build to the VPS.
Retain the current diagnostic image and deployment files for rollback.
Verify version, readiness, pool accounting, eviction metrics, and client recovery after deployment.
Compare memory and pressure behavior over representative traffic before declaring the production result complete.
Rollback on protocol corruption, shared-link failures from client pressure, accounting breaches, or sustained memory regression.

The implementation remains unreleased. The selected default passed the recorded local profiles. These profiles do not establish universal production capacity.
