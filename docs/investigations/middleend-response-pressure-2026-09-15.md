The response-pressure investigation reproduced avoidable client evictions at telego commit `ed886efd3410828d6075bf86b7d3eb3f16055d8a`.
The immediate causes are fixed binding limits and maximum-frame output reservations.
A larger fixed binding limit moves the failure point.
The experiments support a change to admission policy before any change to production defaults.

This investigation changes only an opt-in test file and this report.
The deployed diagnostic build remains unchanged.

The VPS evidence separates two events on September 15, 2026:

| UTC time | Evidence | Conclusion |
| --- | --- | --- |
| 05:36:09–13 | Five DC ±2 links reported `ECONNRESET`. Two links had one and two bindings. | These resets account for the three affected bindings. Their external cause is unknown. |
| 13:07:44.869 | One `binding_bytes` eviction on DC -2, slot 18, generation 3 | A response exceeded the binding queue limit. The shared link remained available. |

The evicted binding held 1,773,948 bytes in 15 events.
The incoming event required 524,420 bytes, including ME event overhead.
Their total, 2,298,368 bytes, exceeded the 2,097,152-byte binding limit by 201,216 bytes.
The manager held only 1,913,204 bytes against its 33,570,816-byte budget.

The owner follow-up arrived about 50 ms after the eviction.
It recorded 3,657,590 client output bytes, a `client_buffer` wait, and a pending retry.
The last observed output decrease occurred about 545 ms before that follow-up.
The 100-second stall deadline was still in the future.
These observations establish output pressure but do not identify a mobile device or prove the reason for its slow drain.
The two snapshots describe different times and cannot establish the exact output headroom at the eviction instant.

The response path contains several independent budgets:

| Stage | Default bound or admission rule | Exhaustion behavior |
| --- | --- | --- |
| Physical ME link event queue | 2 MiB and 4,096 events per link | Closes the shared link |
| Binding response queue | 2 MiB and 768 events | Immediately evicts the incoming binding |
| Slot and manager response queues | Each uses the manager budget, normally 32 MiB plus 16 KiB, and 4,096 events | Evicts a selected binding |
| Native client output | 4 MiB. Requires 1,044,847 free bytes before any response. | Defers the response |
| Shared frontend output | Independent budget of 32 MiB plus 16 KiB. Requires the same maximum-frame reservation. | Can evict the largest buffered client |
| Default WEB backend output | 1,114,112 bytes. Requires the same maximum-frame reservation. | Defers the response until carrier credit is available |

The [configuration derivation](../../pkg/config/middleend.go) reuses `middleEndLinkQueueBytes` as the binding response limit.
Its comment derives that constant from a telemt writer formula.
That formula does not establish a suitable response backlog for a slow client.

The [frontend](../../pkg/gproxy/middleend_frontend.go) checks all three output budgets before it takes the next event.
Thus, a four-byte ACK requires credit for a maximum encoded response.
The frontend already stops request processing while a response token waits for output space.
It still needs space for responses to previously accepted requests.

The [binding manager](../../pkg/transport/middleend/binding_manager.go) checks binding limits before shared limits.
It does not consult output progress or the stall deadline when a queue limit fails.
For shared pressure, its victim selection uses queue size and available space, not recent drain progress.

The [test harness](../../pkg/gproxy/middleend_slow_reader_investigation_test.go) supplies controlled events after ME decoding.
It uses the production binding manager, frontend, encryption, framing, retry code, and client output implementations.
Native tests use real TCP sockets with constrained socket buffers.
Logical WEB tests stop the backend consumer and use the default backend output cap.
A separate HTTP test exercises the actual WEB manager and its budget callbacks.

Each burst contains 512 KiB response packets with sequence markers.
The slow client stops consumption during the burst and waits another 100 ms before recovery.
The paced case consumes each response after a 25 ms delay.
A fast client on the same ME slot receives a separate response after every slow-client event.
Recovered responses must match every payload byte and their original order.

All four transport variants produced the same recovery outcomes in three race-detector runs:

| Experiment | Binding byte limit | Native DD / EE | Logical WEB DD / EE |
| --- | --- | --- | --- |
| 2 MiB burst, then resume | 2 MiB | Recovered | Recovered |
| 8 MiB burst, then resume | 2 MiB | Evicted | Evicted |
| 8 MiB burst, then resume | 8 MiB | Recovered | Recovered |
| 16 MiB burst, then resume | 8 MiB | Evicted | Evicted |
| 16 MiB burst, then resume | Entire shared response budget | Recovered | Recovered |
| 12 MiB paced transfer | 2 MiB | Recovered | Recovered |

The larger limits exist only in the experiments.
The shared budget remains unchanged in every row.
This comparison shows that unused shared capacity can absorb these finite bursts.
It does not establish a complete allocation policy for many competing clients.

The experiments also established these boundaries:

| Experiment | Observed result |
| --- | --- |
| Four-byte ACK with 536,714 native output bytes free | Deferred for `client_buffer` |
| Four-byte ACK with 65,536 shared output bytes free | Evicted another buffered client |
| Four-byte ACK with 589,820 WEB backend bytes free | Deferred for `carrier_budget` |
| 769 small events while the owner is parked | Evicted at the 768-item cap, with only 61,440 queued bytes |
| No drain, with a 500 ms test stall deadline | Closed at approximately 500 ms |
| A 32 KiB drain every 75 ms, with the same deadline | Preserved the response for approximately 1.3 seconds and completed it |
| Three paused clients fill the shared response queue | One eviction. Queue peak 33,555,536 bytes. Fast client continued. |
| HTTP download pauses before three maximum-sized responses | Recovered all 3,133,452 framed bytes with the default WEB budget |

The fast client continued in every burst experiment, including after a response-queue eviction.
The maximum measured fast response latency was 20.74 ms across the repeated matrix.
This local measurement is not a production latency guarantee.
Manager and frontend output accounting stayed within their separate shared limits.
The tests checked queue and frontend cleanup after client closure.
WEB fixture cleanup also checked its retained allocation budgets.

The 32 experiment cases passed three times with the race detector: 96 case executions, with no reported data race.
Here, a passing characterization test can record an eviction.
The optional recovery assertions exposed 11 failures on the current policy: eight burst cases and three ACK admission cases.
They distinguish successful observation from acceptable client behavior.

Run the repeatable characterization from the repository root:

```sh
rtk proxy env GOMAXPROCS=2 GOMEMLIMIT=512MiB go test \
  -race -tags=me_pressure_investigation ./pkg/gproxy \
  -run TestInvestigation -count=3 -p=1 -parallel=2 -timeout=120s -v
```

Run the recovery assertions against the current policy:

```sh
rtk proxy env ME_PRESSURE_REQUIRE_RECOVERY=1 GOMAXPROCS=2 GOMEMLIMIT=512MiB go test \
  -tags=me_pressure_investigation ./pkg/gproxy \
  -run 'TestInvestigation(SlowReaderMatrix|OutputAdmission)' \
  -count=1 -p=1 -parallel=2 -timeout=120s -v
```

The repository test wrapper forces `-count=1`, so the repeated command calls `go test` directly.
The normal build excludes the investigation file through its build tag.
Logs from this investigation are in `/tmp/telego-incident-20260915/`.
The final repeated run is `investigation-final-race.log`.
The recovery assertions are in `investigation-acceptance.log`.

The existing gnet link conformance suite also passed.
Its `event_backpressure_fails_closed` cases confirm that event queue overflow terminates the physical link.
The existing binding saturation and queue-ring tests passed as well.
A proposal that blocks the manager consumer must account for this earlier link boundary.

Telemt provides a useful comparison, but its defaults do not prove lossless slow-client behavior.
The inspected revision was `935b5a3527035ed7c62ffa2191205e46972b997e`.
Its [normal defaults](https://github.com/telemt/telemt/blob/935b5a3527035ed7c62ffa2191205e46972b997e/src/config/defaults.rs) use 768 route items, with fairness and route backpressure disabled.
Its [registry](https://github.com/telemt/telemt/blob/935b5a3527035ed7c62ffa2191205e46972b997e/src/transport/middle_proxy/registry.rs) derives 48 MiB of byte permits per route from that capacity.
That is an admission allowance, not an immediate allocation.

Its [reader](https://github.com/telemt/telemt/blob/935b5a3527035ed7c62ffa2191205e46972b997e/src/transport/middle_proxy/reader.rs) tries data routing three times, with a configured 2 ms wait inside each attempt.
Permit acquisition and channel delivery can each wait, so six milliseconds is not a strict total deadline.
With normal defaults, final queue-full results discard the response and can leave the connection open.
ACK routing can also discard an ACK when its route queue is full.

Its [CryptoWriter](https://github.com/telemt/telemt/blob/935b5a3527035ed7c62ffa2191205e46972b997e/src/stream/crypto_stream.rs) accepts partial input into a bounded buffer and drains partial writes.
That mechanism avoids telego's maximum-response reservation for each small event.
The useful design reference is bounded partial output with preserved cipher state.
The response-discard policy is unsuitable for telego's desired behavior.

The supported implementation direction is:

1. Base output admission on the next response or a bounded output chunk. Keep the event charged until ownership transfers successfully.
2. Permit a binding to use spare shared capacity. Treat per-binding byte and item allowances as fairness targets within hard shared bounds.
3. Use observed drain progress when the policy selects a victim. Keep an explicit terminal outcome for true exhaustion or a stalled client.
4. Preserve fast-client service and ME link progress. A slow binding must not cause an unbounded wait in the shared ME reader.

The output change must preserve ordering, padding, DRS state, and encryption across retries and partial writes.
An exact-size reservation alone does not fix the independent binding queue limit.
An elastic binding limit alone does not fix unnecessary frontend output evictions.
Finite memory also requires a defined failure policy when accepted backlog exceeds all available capacity.

A future implementation needs these release checks:

- Recover the finite bursts in this matrix whenever shared capacity is available, without installation-specific queue overrides.
- Cover abridged, intermediate, and padded-intermediate framing, ACK ordering, maximum packets, and fragmented output.
- Cover competing clients, shared byte and item exhaustion, and progress that continues across multiple stall intervals.
- Cover real ME wire input, HTTP and WebSocket carriers, CPU contention, and different event-loop counts.
- Cover cancellation, generation retirement, partial writes, and owner shutdown with each possible outstanding reservation.
- Measure retained allocations and process memory under sustained load, including decoder buffers, output copies, and carrier queues.
- Record required output credit, available credit, queue age, progress age, and the eviction reason with bounded metric labels.

The current experiments do not measure RSS, kernel delivery, or a real mobile network.
The repeated matrix covers intermediate framing.
The HTTP case uses DD.
The 500 ms timeout experiment exercises production timer logic with a shorter duration.
These limits prevent a claim of universal reliability from this investigation alone.
They do not weaken the reproduced causes or justify a larger fixed queue as the complete correction.

The connection-count follow-up used 100 and 1,000 simultaneous native DD connections on one client event loop.
It kept the current response limits and used the default resident limits of 10,000 overall and 2,500 per slot.
Each response contained 64 KiB, with a planned three responses per connection.
The fixture now uses handshake identities that remain unique beyond 256 connections.

| Connected clients | Delivery pattern | Observed result |
| --- | --- | --- |
| 100 | All clients receive a response in each wave | All 300 responses arrived intact. No eviction. |
| 1,000 | Responses arrive in batches of 32 clients, with each batch consumed before the next | All 3,000 responses arrived intact. No eviction. |
| 1,000 | All clients receive a response in one wave | 526 of the first 1,000 responses arrived. The manager evicted 474 bindings. Later waves did not run. |

The simultaneous 1,000-client wave reached 33,562,624 queued bytes against the 33,570,816-byte shared queue limit.
The frontend reported no output-budget eviction, and the ME slot did not fail.
The staggered test reached 2,097,664 queued bytes and 7,730,335 bytes in frontend output accounting.
Eviction counts can change with scheduling, so these numbers describe the recorded run.

Both patterns established all 1,000 connections before response delivery began.
This separates connection admission from tolerance for a simultaneous response burst.
The source still supplies events after ME decoding, and the clients use loopback TCP.
These experiments do not establish live Telegram throughput, production RSS, or behavior when 1,000 mobile clients stop reading.
The reported heap delta includes the load generator and must not be treated as production memory per client.
The extended characterization suite also passed with the race detector and the staggered connection-count workload.

Run the connection-count characterization:

```sh
rtk proxy sh dist/test-go.sh -tags=me_pressure_investigation ./pkg/gproxy \
  -run TestInvestigationClientCount -v
```

Run the staggered workload with recovery required:

```sh
rtk proxy env ME_PRESSURE_STAGGER=1 ME_PRESSURE_REQUIRE_RECOVERY=1 \
  sh dist/test-go.sh -tags=me_pressure_investigation ./pkg/gproxy \
  -run TestInvestigationClientCount -v
```

The corresponding logs are `investigation-client-count-burst.log` and `investigation-client-count-stagger.log` in the same investigation directory.
The proposed combined 64 MiB response budget remains a test target.
It does not allocate 64 MiB to each connection or establish a total process memory bound.
If every connection needs buffering, 64 MiB averages 655.36 KiB across 100 connections or 65.536 KiB across 1,000, before overhead.
If 1,000 connections each retain 1 MiB, their payload alone requires 1,000 MiB.
The release criteria therefore need both connection-count coverage and explicit limits on the aggregate backlog.
