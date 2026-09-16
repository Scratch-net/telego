# Middle-End response implementation: 2026-09-15

This report records the September 15 checkpoint.
The [September 16 release audit](middleend-release-audit-2026-09-16.md) records subsequent corrections to candidate preparation and the cleanup limit.

Phases 1 through 5 of the [accepted plan](middleend-response-pressure-plan-2026-09-15.md) passed implementation and independent audit gates.
Phase 5 includes telemetry, capacity reporting, documentation, and dashboard preparation.
Local Phase 6 acceptance checks passed. Memory-cap measurements support the selected final default. Deployment and production validation remain pending.
The [incident investigation](middleend-response-pressure-2026-09-15.md) retains the original observations and experiments.

## Implemented behavior

One service-owned pool covers response allocations across generation managers and frontend output.
The default `Q` is 32MiB plus 16KiB. Ordinary response capacity is `2Q`, or 67,141,632 bytes.
The total adds `MiddleEndResponseProcessingBytes()`: 2,089,486 bytes on the current 64-bit build. The selected total is 69,231,118 bytes.
Explicit nonzero `queue-budget-mb` values retain a total response limit of `2Q`, including the reserve.
Request and frontend input allowances retain their existing derivation and permitted range.

The pool charges retained response capacity and metadata before allocation.
Dequeue transfers ownership to the consumer. Partial drain does not return the charge for an allocation that remains retained.
Native and logical WEB output release their charges through their actual allocation owners.
Processing reservations cover plaintext and encrypted output together, before the encoder advances.

Production gnet links deliver responses through a synchronous manager sink.
The sink carries `ProxyAnswer`, `SimpleAck`, and `CloseExternal`. Ping and Pong retain their channel ordering.
Initial installation precedes link startup. Repair and refresh installation occurs after the probe and before publication.
Routing checks the physical incarnation inside the manager critical section.
Standalone links retain their public `Events` channel contract.

Shared response queues use fixed chunks of 16 events. Growth adds one charged chunk without copying existing entries.
Each physical-owner cleanup turn releases at most one maximum admission cost, plus the final event or chunk that crosses that amount.
A second bound limits synchronous cleanup to 8,192 events.
One worker per manager releases the remaining detached queue. Shutdown waits for this worker.
Detached storage stays charged until the worker clears and releases it.

Shared-mode admission replaces the fixed response byte and item cutoffs.
Global selection occurs only after actual ordinary-capacity exhaustion.
The selector prefers sufficient queued backlog, then uses fresh progress, soft fair shares, retained size, and stable ties.
An empty healthy binding or an encode-only owner cannot supply a victim.
An inline `CloseExternal` marker preserves order without another allocation, including at full capacity.

## Audit corrections

The audit loop corrected these ownership and concurrency cases:

- The pool checks current free capacity atomically with selection. A stale shortage cannot evict another binding after capacity becomes available.
- Adopted handles contribute existing ordinary credit only. A processing allocation cannot reduce the ordinary admission requirement.
- Invalid, released, undersized, or foreign-owner handles fail before global selection, including while the pool is full.
- Both copied and adopted payloads remain in flight until queue attachment. Unattached data cannot appear as reclaimable queue storage.
- Selected targets recheck actual backlog. Incoming admission rechecks cancellation and physical incarnation after each unlocked callback.
- Closing and empty terminal bindings detach their participants immediately. Allocation handles retain the participant charge until actual release.
- Binding objects remove their detached participant pointers. This prevents persistent references after the participant charge ends.
- Async output closure supplies no assumed capacity credit. Pending output closure prevents a cascade through other output-only owners.
- Callback reentry and synchronous release preserve output ownership. Processing reservations acquire the plaintext and output pair atomically.
- Forced incoming fallback rechecks terminal state and physical incarnation before mutation. Concurrent terminal responses retain their accepted order.
- Native output now collects at most 1,024 descriptors before traversal and allocation. Previously, it collected the entire backlog before applying that limit.

These corrections passed focused race tests and independent code review.

## Local test evidence

The completed gates include ownership transfer, rejection, cancellation, queue growth, repair, refresh, shutdown, and overlapping generations.
Frontend coverage includes DD, EE, logical WEB output, response-sized admission, partial drain, callback reentry, and the three earlier ACK regressions.
Real encrypted traffic exercises the production sink beyond the old physical event queue limit.

| Test or gate | Observed result |
|---|---|
| `TestSharedResponseBorrowingExceedsLegacyLimitsAndRecovers` | Two bursts each retained 2,000 ACKs and five 512KiB responses, then drained in order |
| `TestGnetResponseSinkSharedPressurePreservesHealthyBinding` | Existing healthy binding survived real encrypted shared pressure. The regression is no longer skipped |
| Cross-generation pressure | A queued owner in the older manager supplied capacity while an existing healthy response remained intact |
| Full-pool ordered close | Blocking and token consumers received accepted data before `CloseExternal` and terminal state |
| Output-only pressure | Close supplied no immediate credit and did not cascade through the second output owner |
| Invalid ownership | Foreign-owner, released, and undersized handles caused no unrelated eviction with free or full capacity |
| Full Middle-End race suite | Passed in 39.341s before the final narrow audit corrections |
| Focused race suite after final corrections | Passed in 2.448s |
| Middle-End vet and formatting | Passed |

### Queue scale evidence

These measurements use local test execution, not VPS load characterization.
The maximum-queue test supplies **64MiB of ordinary capacity with no encode reserve**.
It does not use the production split between ordinary and processing capacity.

| Measurement | Observed result |
|---|---:|
| Maximum retained ACK count | 331,397 |
| Queue fill time | 30.9ms |
| Bounded synchronous cleanup time | 175µs |
| Actual charge released in that cleanup turn | 1,046,520 bytes |
| One queue chunk, including its handle | 1,096 bytes |
| One participant record | 200 bytes |
| 1,000 bindings, each with one ACK | 1,430,000 bytes total |
| Queue metadata for those bindings | 1,096,000 bytes |
| Participant metadata for those bindings | 200,000 bytes |

The scale test checks remaining cleanup ownership and joins the worker at shutdown.
Its counts describe this code and architecture at the Phase 4 gate. Later metadata changes can alter the measured sizes.
The test does not establish throughput or synchronized-burst capacity for 1,000 real clients.

### Phase 6 in-process acceptance

The revised investigation harness uses one production-sized response pool for the manager and frontend.
Its controlled ME event source starts after decoding. Native and logical clients use real transport owners and codecs.
The optional recovery-pass switch is removed. Fitting bursts must recover every response in order.

The finite-burst, ACK, progress, pressure-isolation, and HTTP matrix passed under the race detector in 14.834s.
The ACK cases recover 2,048 ordered acknowledgements beyond the former 768-item cutoff.
The progress case reads 32KiB every 75ms and survives more than two 500ms stall intervals.
A separate no-progress case closes after its deadline.
The missing four-byte carrier-headroom ACK check now runs in the regular suite.

The first native count run used the provisional 67,141,632-byte total, including a 2,089,486-byte processing reserve.
Its ordinary limit was 65,052,146 bytes.
Each successful count case completed three response waves and released all response charges during cleanup.

| Clients and schedule | Response payload | Result |
|---|---:|---|
| 100, synchronized and staggered | 64KiB draining, 60KiB retained | All four cases passed |
| 1,000, synchronized | 64KiB draining | Failed in wave one: 30 pressure evictions, 970 responses verified |
| 1,000, synchronized | 60KiB retained | All 3,000 responses verified; no pressure |
| 1,000, staggered in batches of 32 | 64KiB draining, 60KiB retained | Both cases verified all 3,000 responses without pressure |

The synchronized 64KiB failure followed actual ordinary-capacity exhaustion, with EOF errors after eviction.
It was not a read-deadline failure.
Its exact all-retained admission cost was 67,024,000 bytes, including envelopes, queue chunks, and participants.
The strict check remained enabled. That provisional total did not pass the synchronized-burst release gate.
The race run reproduced this failure with 29 evictions and 971 verified responses.
The other seven count cases passed under the race detector. No race reports or response-charge leaks occurred.

The 60KiB case holds all processing capacity until each batch is queued.
Its synchronized 1,000-client admission cost was 62,928,000 bytes, which fits the ordinary limit.
Its combined high-water charge was 65,017,486 bytes.
This guaranteed-fit case supplements the 64KiB release check.

These measurements share one process with their load generator.
They do not establish the server RSS or container memory requirement.
The separate-process results below selected the larger default. These earlier results preserve the provisional failure for comparison.
The investigation rig now uses the same derived final default, with no literal processing-reserve value.
All eight strict `TestInvestigationClientCount` cases passed under the race detector in 53.847s after this change.

The final frontend audit found the native descriptor-collection issue described above.
The fix adds allocation-free collection into fixed owner storage and clears references before release callbacks.
A 100,000-entry regression checks bounded collection, ordered drain, and exactly-once release.
A real socket regression checks multiple descriptor batches with reentrant flush and close callbacks.
The three vendored gnet gates passed: default race, `gc_opt` race, and `poll_opt,gc_opt`.

The [public protocol canary](../monitoring/middleend-public-canary.md) passed local fixtures and independent source review.
The fixtures validate official MTProto examples and DD/EE pause recovery.
The reviewed helper then passed against the unchanged diagnostic VPS service in its network namespace.
DD verified three ordered responses with a 250ms pause in 345ms. EE verified the same sequence in 335ms.
Both paths verified an ME route commit and unchanged direct-fallback count. Total execution took 0.79s.
The executed helper's SHA-256 was `93d1f0d752e31d6c14e04aedfde5a21f488e6f46dff0d480cf102c873f75fe88`.
This establishes the pre-release protocol baseline. It does not validate the unreleased binary against Telegram.
No configuration or production binary changed during this check.

### Separate-process native memory caps

The peer, driver, and runner stayed outside the server cgroup. Only the proxy server entered a transient systemd user scope.
Each scope enforced its memory cap, zero swap, a 200% CPU quota, and a 512-task limit.
Every child used `GOMAXPROCS=2`. The runner removed inherited `GOMEMLIMIT` and checked actual kernel limits and cgroup identities.
The workload used four real encrypted ME links, with a maximum-size response through every link before measurement.
Each finite case requested three 64KiB response waves. Paused readers waited 500ms before drain.

The stress server requested a 4KiB send buffer. All-paused cases requested a 4KiB receive buffer, reported as 8KiB by Linux.
Mixed cases used a 64KiB receive-buffer request and equal fast and paused client groups.
All-paused cases retained application output at every pause boundary. These socket constraints do not reproduce the production socket defaults or every mobile network.

All memory columns use MiB. RSS HWM and cgroup peak use the largest observed kernel counters. Heap values are sampled allocation peaks.

| ID | Cap and pool | Clients / schedule / readers | Verified responses | Closures | Cgroup peak | RSS HWM | Heap peak | Pool HWM |
|---|---|---|---:|---:|---:|---:|---:|---:|
| A | 512MiB, provisional | 1,000 / synchronized / all paused | 986 | 14 | 195.74 | 158.79 | 129.88 | 62.25 |
| B | 512MiB, final | 1,000 / synchronized / all paused | 3,000 | 0 | 191.65 | 183.83 | 148.89 | 62.96 |
| C | 1GiB, final | 1,000 / synchronized / all paused | 3,000 | 0 | 208.42 | 190.58 | 139.57 | 63.12 |
| D | 2GiB, final | 1,000 / synchronized / all paused | 3,000 | 0 | 195.79 | 186.91 | 149.07 | 63.09 |
| E | 512MiB, final | 100 / synchronized / mixed | 300 | 0 | 39.17 | 44.93 | 21.40 | 4.98 |
| F | 512MiB, final | 100 / batches of 32 / mixed | 300 | 0 | 34.22 | 42.22 | 22.48 | 4.32 |
| G | 512MiB, final | 1,000 / synchronized / mixed | 3,000 | 0 | 105.11 | 102.46 | 72.08 | 26.95 |
| H | 512MiB, final | 1,000 / batches of 32 / mixed | 3,000 | 0 | 54.28 | 57.55 | 39.88 | 6.29 |

The provisional total closed 14 bindings after actual ordinary-capacity exhaustion. The final default delivered every requested response with zero evictions.
Every case recorded zero OOM events and zero memory-limit events. Server shutdown released all response bytes, handles, and participant records.
Each case produced 36–84 successful resource samples with zero sampling errors. The largest gap was 71.8ms.
Periodic observations do not establish an exact processing-reserve high-water mark. The atomic reservation tests establish its derived capacity and admission guarantee.

All-paused p99 response latency was 796.0–809.7ms, including the 500ms pause.
For 100 mixed clients, fast-reader p99 was 17.2ms synchronized and 15.7ms staggered.
For 1,000 mixed clients, these values were 157.5ms and 18.8ms. Paused-reader p99 was 504.2–868.8ms across the mixed cases.

Raw artifacts remain under `/tmp/telego-pressure`. The directories contain manifests, identities, phase snapshots, resource samples, process logs, and final cleanup results.
The directory timestamp prefixes for A through H are:

```text
A 20260915T180001045095
B 20260915T180003919570
C 20260915T180210496747
D 20260915T180214812767
E 20260915T180347299554
F 20260915T180349895551
G 20260915T180352588013
H 20260915T180356204506
```

All eight cases used these immutable binaries, built with `poll_opt,gc_opt,me_pressure_investigation` after the bounded-descriptor fix:

- Peer SHA-256: `aec30005858873d654ab5296ca84cfa054d1a385035dc5dbbb169b0bdf0e1f82`.
- Server and driver SHA-256: `3ef31e1abf579ec53564300873e2592f4e6846ed98c0b3073c2a398900a1222d`.

The [runner](run-middleend-response-pressure.py) reproduces the isolated profiles. This command runs the provisional and final 512MiB comparison:

```sh
rtk proxy python3 docs/investigations/run-middleend-response-pressure.py \
  --profiles 512M --pool baseline --pool candidate --links 4 --clients 1000 \
  --batch 0 --size 65536 --waves 3 --all-paused --receive-buffer 4096 \
  --pause 500ms --gproxy-binary /tmp/telego-pressure/gproxy-finite.test
```

These native profiles select the response default. The following profiles cover carriers and 48-link rotation. Their scope remains the recorded finite workloads.

### Carrier, topology, and combined-pressure caps

Seven further profiles passed with the final response budget and a 512MiB server cap.
HTTP and WebSocket readers stopped between waves. Each carrier pump consumed one complete wave and joined before the next wave started.
The maximum-packet cases used two clients and three waves of 1,044,480-byte responses.
The 1,000-client carrier cases used three 64KiB waves, with all payloads and ordering checked.

Both rotation cases exercised 48 links per generation and warmed 96 actual slots with maximum-size responses.
An old binding retained eight maximum-size responses through replacement. A separate active-generation client triggered the combined exhaustion case.
This avoided the intentional input pause on the old, response-blocked client.
Both selected bindings closed explicitly during exhaustion. All 98 healthy neighbors in both generations received their complete responses.
The number of explicit closures matched the pressure-eviction counter. No physical ME link failed.

All memory columns use MiB and the largest observed kernel counters.

| Profile | Verified result | Cgroup peak | RSS HWM | Pool HWM |
|---|---|---:|---:|---:|
| HTTP maximum packet | 6 complete responses, zero closures | 31.89 | 39.09 | 3.99 |
| WebSocket maximum packet | 6 complete responses, zero closures | 30.14 | 38.57 | 3.99 |
| HTTP, 1,000 clients | 3,000 complete responses, zero closures | 268.98 | 274.75 | 5.24 |
| WebSocket, 1,000 clients | 3,000 complete responses, zero closures | 280.65 | 282.28 | 43.16 |
| 48-link finite rotation | 300 responses plus eight old responses, zero closures | 244.08 | 250.53 | 10.98 |
| 48-link rotation and exhaustion | 98 healthy neighbors survived, two selected closures | 267.06 | 274.89 | 63.80 |
| Native, production send-buffer default | 3,000 complete responses, zero closures | 77.45 | 74.28 | 10.51 |

The last row used 1,000 mixed native readers and omitted the server send-buffer override.
It complements the constrained-socket stress cases. It does not reproduce every production network or workload.
All seven profiles recorded zero OOM events, memory-limit events, and sampling errors. Shutdown released all response charges and carrier state.
The largest cgroup peak across the complete matrix was 294,281,216 bytes. The largest observed RSS HWM was 295,993,344 bytes.
Both came from the 1,000-client WebSocket profile.

Paused-reader p99 was 813.3ms for HTTP and 618.4ms for WebSocket, including the 500ms pause.
The native production-socket profile recorded fast-reader p99 of 150.7ms and paused-reader p99 of 529.9ms.
Empty latency groups mean that the group does not apply.

Allocation rates use the server `TotalAlloc` change from the connected snapshot through final drain or recovery, divided by that interval.
Observed rates were 610.37MiB/s for HTTP, 821.06MiB/s for WebSocket, and 504.57MiB/s for native production sockets.
These rates describe allocations across the measured interval. They are not retained-memory or RSS measurements.

Raw results reside under these `/tmp/telego-pressure` directory prefixes:

```text
final-http-max/20260915T180950375488
final-ws-max/20260915T180953070839
final-http-1000/20260915T180955621371
final-ws-1000/20260915T180959722990
final-rotation-48/20260915T181002610633
final-rotation-exhaustion-48/20260915T181006723685
final-native-default-socket/20260915T181009923264
```

The peer binary retained SHA-256 `aec30005858873d654ab5296ca84cfa054d1a385035dc5dbbb169b0bdf0e1f82`.
The final measured server and driver used SHA-256 `838e13792d26b717226e9ada258648fceda631b592911b03c26bacbd4552433f`.
The runner now selects the final candidate budget by default. Explicit `--pool baseline` preserves the historical comparison.
With the updated harness binary, `--send-buffer 0` selects the production socket default.

These results cover the stated profiles. They do not establish a universal 512MiB process limit or a general guarantee against OOM.

## Memory outside the response pool

Let `M = MaxMEFrameSize = 1,044,576` bytes.
Each physical link has at most `M` bytes of persistent decoder capacity.
Each concurrently active ME owner can add at most `M` bytes of old storage during growth and 64KiB of CBC plaintext.
The decoder uses exact bounded capacity growth. This category covers active, retiring, and candidate links separately from the response pool.

WEB retains a separate default 512MiB global carrier allowance.
Carrier storage can remain after logical output releases its response allocation.
Request queues, frontend input, connection state, runtime overhead, allocator retention, and kernel buffers also remain outside the response pool.
Neither the pool limit nor the Go soft memory limit provides a process RSS bound or an absolute guarantee against OOM.

Unix gnet event loops also retain one fixed array of 1,024 write descriptors.
The array costs 24KiB per 64-bit event loop, or 12KiB per 32-bit event loop, outside the response pool.
Bounded collection prevents an ACK backlog from creating a descriptor slice for every retained response before each socket write.
The owner clears these references before release callbacks run.
Connection close still disposes its remaining output nodes synchronously.

## Local completion and release status

Phase 5 passed independent review, package race tests, vet, and the configured lint checks.
The [dashboard bundle](../monitoring/middleend-response-panels.md) contains only new panels and a reproducible merge script.
Its 16 queries passed read-only Prometheus execution. The live dashboard files remain unchanged.
All required local acceptance profiles and independent audit loops passed.
The complete `make test` gate passed after the descriptor fix, including all required repository and vendored modes.
The final default then passed all eight strict client-count cases under race in 53.847s.
Targeted response-budget and frontend configuration checks passed in 1.012s. Default and override-range checks passed in 1.010s.
The final lint run included `me_pressure_investigation` and reported zero issues.
Formatting and `git diff --check` passed.

The source remains uncommitted and unreleased at this checkpoint.
Deployment and production validation remain pending. No NAS dashboard write or VPS deployment forms part of these completed local gates.
