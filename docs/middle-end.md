# Telegram Middle-End

Telego can send authenticated MTProxy sessions through Telegram Middle-End (ME) servers. The public listener and the ME client runtime both use gnet.

ME is disabled by default. Existing configurations keep the direct Telegram DC path.

## Why ME is opt-in

Telegram proxy registration and `proxy-tag` are not prerequisites. If the tag is empty, Telego omits it from each ME request. This does not disable ME.

ME changes the outbound network topology. It also reserves persistent gnet links and bounded queues for each signed DC. Telego does not make these changes during an upgrade unless the operator enables ME.

Before you enable ME, make sure that:

- Telego can resolve DNS and fetch all three artifacts from `core.telegram.org` over HTTPS.
- Telego can open TCP connections to the signed ME endpoints in those artifacts.
- Telego can send UDP to the built-in STUN pool for private direct sockets, or `nat-ip` contains the correct public IP.
- NAT for a direct ME link preserves the kernel-assigned TCP source port.
- The process file-descriptor and memory limits cover the public connections, ME links, and bounded queues.

SOCKS5 links do not use STUN. The SOCKS5 server must return its public `BND.ADDR:BND.PORT` tuple.

## Configuration

Add this section to the configuration:

```toml
[middle-end]
enabled = true

# Optional. Set this only if Telegram issued a tag for this proxy.
# proxy-tag = "0123456789abcdef0123456789abcdef"

# Route ME links and artifact requests through this SOCKS5 proxy.
# socks5 = "127.0.0.1:1080"
# socks5-username = "proxy-user"
# socks5-password = "proxy-password"

# Override the proxy for artifact requests only.
# artifact-proxy = "http://127.0.0.1:3128"

# Usually, leave this value empty. See "Direct links and NAT."
# nat-ip = "YOUR_PUBLIC_IP"

# These expert values can only reduce the derived defaults.
# max-connections = 0
# queue-budget-mb = 0
```

Restart Telego after a change to this section. The hot reload does not change the ME runtime.

Do not publish the proxy tag or the SOCKS5 credentials in an issue or log.

## Direct links and NAT

Direct ME links use the address and port that the Telegram ME server sees. These values are inputs to the ME key derivation.

Each client request also carries the public proxy endpoint. The endpoint combines the selected ME link IP with the client-facing listener port.

If the TCP socket has a public IP, Telego uses the exact socket tuple. Telego does not run a NAT probe.

If a direct ME socket has a private IP, Telego gets its public IP from a fixed STUN pool. This behavior supports Docker bridge networks.

Telego keeps the kernel-assigned TCP source port. It does not use the UDP port from the STUN response.

Telego caches a successful STUN result for 10 minutes. Telego starts a background refresh after 5 minutes.

The refresh does not depend on a new client connection. Concurrent ME links share one probe.

A failed refresh retries with bounded exponential backoff. The verified IP stays valid until its original 10-minute expiry.

The verified IP remains available for 5 seconds after expiry while a probe completes.

If no verified IP is available after that grace period, new connections use direct fallback during the retry backoff.

The ME handshake validates the complete tuple. If NAT changes the TCP source port, the handshake fails and direct fallback stays available.

Set `nat-ip` only when automatic discovery returns the wrong public IP. The value must be a public IPv4 or IPv6 address.

The `nat-ip` value replaces only a private socket IP from the same address family. It cannot replace a port.

SOCKS5 links use the exact public `BND.ADDR:BND.PORT` for their ME key derivation. They do not use STUN data.

Each request on a SOCKS5 link uses `BND.ADDR` as its proxy IP. It retains the client-facing listener port as its proxy port.

Different links can use different source IPs. This behavior supports SOCKS5 egress and hosts with more than one public IP.

## Connection routing

Each public TCP connection selects one route after authentication. This selection does not change during that TCP connection.

An authenticated native WEB stream does not have a client TCP source port. Telego follows official MTProxy behavior and sends remote port zero to ME.

The proxy address still contains the public listener port. Unauthenticated public connections cannot supply a zero remote port.

- Telego selects ME when the active generation can bind the exact signed DC.
- Telego selects a direct DC connection when ME setup fails before the bind.
- Telego does not move a direct connection to ME after the active generation becomes ready.
- Telego does not move an ME connection to a different physical ME link.

Telegram reconnects a client after its selected physical link fails. The new TCP connection can select a healthy ME link.

## Link topology

Telego keeps one active generation. This generation has four gnet links for each signed DC in Telegram's current artifacts.

The pool selects a least-loaded healthy link for each new binding. The binding stays on that physical link until the binding closes.

## Artifact refresh and generation rotation

Telego fetches the three official Telegram artifacts once per day. Failed candidate attempts do not prevent the next scheduled fetch.

A failed fetch does not discard the active generation or the last valid artifacts. Telego can still retry a pending candidate from those artifacts.

New artifact content replaces the pending candidate plan. Recovery uses the latest valid plan, even after a failed rotation attempt.

If the artifacts return to the applied content, Telego restores that content as the recovery source. An already matching healthy generation needs no replacement.

If artifact content changes, Telego prepares and probes one candidate generation. The active generation continues to accept bindings during this work.

After a successful probe, Telego publishes the candidate in one operation. New bindings use this active generation.

The previous generation accepts no new bindings. Its healthy links keep their existing bindings and independent probes without a retirement deadline.

Telego closes each unused old link after its bindings, queues, and pending work are empty. Retiring generations do not repair failed links or refresh unused links.

Telego applies the same retirement policy to healthy links that remain after a generation failure.

Telego permits at most two live generation managers, including an unpublished candidate. Before another candidate needs this capacity, Telego closes the oldest retiring manager and waits for its cleanup.

This capacity retirement can interrupt old bindings. The current active generation stays available during candidate preparation.

If the candidate fails, the active generation stays unchanged. The failure cannot restore bindings that capacity retirement already closed.

Shutdown closes the remaining managers and waits for cleanup. It does not wait indefinitely for client bindings to drain.

## Unused-link refresh

Telego prepares replacements for unused links before it retires the current links. Candidate preparation does not remove an admitted slot.

An unused link has no client bindings or pending client work. This state also includes a previously used link after its last binding leaves.

The refresh starts after 45–60s of unused time. Different slots have different deadlines to spread the work.

Candidate preparation has a 10s deadline. A candidate must complete the ME handshake and return a matching RPC pong before Telego publishes it.

The current link stays available during preparation. If a client binds to that link, Telego discards the candidate and preserves the client binding.

Telego also requires empty client queues and exclusive probe ownership before publication. Existing client bindings never move to a different physical link.

A failed candidate leaves the current link unchanged. Telego retries with a bounded positive delay.

Each manager permits at most one candidate reservation per signed DC and eight reservations in total. A reservation remains active through candidate cleanup or old-link cleanup.

Rotation and shutdown cancel candidate work. The link probe schedule remains independent of this refresh schedule.

This refresh manages connection turnover. It does not establish Telegram's private timeout policy or guarantee that a peer keeps an unused connection open.

## Link repair

Each physical slot has an independent probe and repair worker. The normal probe interval is 5s, with a 100s response deadline.

A slow probe or repair does not stop probes or failure detection on other slots.

An ordinary link failure in the active generation starts an in-place replacement of that slot. Telego does not replace the complete generation for this failure.

Bindings on the failed slot close. Bindings on other slots and other DC pools stay on their current links.

Each replacement has 10s to complete preparation, including the handshake and a matching RPC pong. Only then can new bindings use the repaired slot.

Failed replacements use bounded retries with positive jitter. Each failed slot permits one repair attempt at a time.

A manager-wide failure removes ME admission. New connections use direct fallback while Telego builds a new active generation.

## Derived limits

Telego derives the operational limits below. Most installations do not need an override.

| Limit | Default | Behavior |
|---|---:|---|
| Links for each signed DC | 4 | Fixed from the minimum in the official implementation |
| Refresh reservations for each manager | 8 | At most one for each signed DC, including cleanup |
| Unused-link refresh delay | 45–60s | Staggered across physical slots |
| Replacement preparation deadline | 10s | Bounds repair and refresh preparation, including the handshake and matching pong |
| Public connections | 10,000 | `max-connections` can only reduce this value |
| Link request queue | 4,096 items and 2MiB | Fixed for each physical link |
| Link response queue | 4,096 items and 2MiB | Fixed for each physical link |
| Manager request budget | 32MiB plus 16KiB | `queue-budget-mb` can reduce this budget |
| Manager response budget | 32MiB plus 16KiB | `queue-budget-mb` can reduce this budget |
| Frontend input budget | 32MiB plus 16KiB | Uses the same derived value |
| Frontend output budget | 32MiB plus 16KiB | Uses the same derived value |
| Response items for each binding | 768 | Fixed from the telemt route limit |
| Endpoint dial timeout | 3s | Fixed from the official implementation |
| NAT probe timeout | 5s | One shared STUN batch for private direct sockets |
| NAT result cache | 10 minutes | Matches the public telemt cache period |
| NAT proactive refresh | 5 minutes after success | Does not depend on client traffic |
| Generation preparation timeout | 100s | Covers construction, startup, and the first all-DC probe |
| Live generation managers | 2 | Includes an unpublished candidate and managers with unfinished cleanup |
| Retiring generation deadline | None | Healthy bindings remain until natural closure, failure, capacity retirement, or shutdown |

The byte budgets are independent ceilings. Do not add them together as one shared queue.

The reported payload capacity includes the link queues for eight extra candidates per manager. Rotation reserves capacity for at most two managers.

For an artifact set with 48 admitted links, the logical link allowance is 56 for one manager and 112 during rotation.

These values are not process file-descriptor limits. Socket closure, bootstrap, listeners, and runtime resources also use descriptors.

For enrolled ME sockets, gnet can retain one descriptor per ME event loop after logical closure and before physical closure.

This allowance covers only that close-completion interval. Bootstrap and enrollment can temporarily duplicate descriptors and require separate capacity.

The `queue-budget-mb` range is 2 through 32. A value of `0` selects the default and its extra 16KiB permit.

## Metrics and logs

Enable the Prometheus listener to inspect ME state. Start with these metrics:

| Metric | Meaning |
|---|---|
| `telego_middleend_admitting` | A value of `1` means that new bindings can use the active generation |
| `telego_middleend_frontend_routes_active` | Current `middleend` and `direct_fallback` public routes |
| `telego_middleend_frontend_route_commits_total` | Lifetime route selections |
| `telego_middleend_links` | Physical links by generation role, signed DC, and state |
| `telego_middleend_slot_failure_total` | Physical-link failures during the service lifetime |
| `telego_middleend_slot_failure_affected_bindings_total` | Bindings that physical-link failures terminated |
| `telego_middleend_forced_retirement_total` | Capacity retirements by `reason`: `artifact_capacity` or `recovery_capacity` |
| `telego_middleend_forced_retirement_affected_bindings_total` | Bindings that capacity retirements interrupted, by `reason` |
| `telego_middleend_diagnostic_records_dropped_total` | Diagnostic records rejected because the journal was full. This metric has no labels. |
| `telego_middleend_slot_repairs_active` | Physical slots that Telego currently replaces |
| `telego_middleend_slot_repair_total` | Successful and failed physical-slot replacements |
| `telego_middleend_slot_refreshes_active` | Candidate reservations by generation role and signed DC, including cleanup |
| `telego_middleend_slot_refresh_total` | Service-lifetime refresh outcomes by signed DC: `success`, `failure`, or `canceled` |
| `telego_middleend_zero_ready_transitions_total` | Service-lifetime losses of all ready slots in an admitting manager, by signed DC |
| `telego_middleend_artifact_state` | Applied and pending artifact state |
| `telego_middleend_artifact_refresh_total` | Artifact refresh results |
| `telego_middleend_generation_apply_total` | Coordinator results for generation application, including adoption after background recovery |

The queue metrics report current use, capacity, and lifetime high-water values. Telego logs thresholds at 80%, 95%, and 100%.

The ready-link metric counts the current link during candidate preparation. Candidate reservations appear separately in `telego_middleend_slot_refreshes_active`.

The refresh and zero-ready counters persist across generation rotation. The zero-ready counter excludes initial startup, intentional retirement, and shutdown.

The manager records each zero-ready transition directly. A gap can increase this counter even if the next metrics sample already shows a recovered pool.

Canceled refreshes include new client use and intentional lifecycle changes. They do not count as failed replacements.

Capacity retirements have separate counters from physical-link failures. Natural retirement and shutdown do not increase the capacity-retirement counters.

The affected-binding count includes only bindings that the capacity retirement actually interrupts. Already terminal bindings and bindings with a close in progress do not count.

The generation-application counter does not count every background publication. A return to already matching active content does not increase its success count.

Telego logs route fallback, artifact failure, generation failure, failed physical-link replacement, and binding eviction events.

### Failure diagnostics

Telego keeps a service-wide journal for physical-link failures and capacity retirements. The journal retains the first 256 unacknowledged records.

If the journal is full, Telego rejects new records and increases the dropped-record counter. Failure totals and the last-failure summary still advance.

The monitor emits at most 256 records per observation, with a normal interval of 5s. Records without client impact use INFO.

Records with client impact and increases in dropped records use WARN. Successful link replacements still use DEBUG.

Each record identifies the generation and its role at the event, not at log emission. Physical-link records also identify the signed DC, slot ordinal, and incarnation.

The slot ordinal starts at zero and stays fixed within its manager. The incarnation increases after a successful repair or refresh.

Physical-link records contain the failure reason, affected-binding count, safe error classification, link age, peer EOF status, and previous client use.

The manager starts the age clock at initialization of the ready link. This age does not measure the full TCP connection lifetime.

The probe history includes local queue acceptance, link submission acceptance, the deadline, and the last matching pong. Submission acceptance does not prove transmission on the network.

Queue counts and byte counts describe the manager slot before failure cleanup. They do not describe the engine queues before failure.

Record timestamps describe local observations, not exact remote failure times. Sequence numbers describe arrival order at the supervisor.

Diagnostic records exclude raw errors, addresses, credentials, client identities, and packet contents. Unknown errors use a fixed redacted description.

The monitor acknowledges the copied journal boundary after log emission. Records that arrive during emission remain available for the next observation.

Independent journal reads do not remove records. Acknowledgement does not prove durable log storage, and process failure can lose unacknowledged records.

The journal and its counters survive generation changes. A service restart resets them.

Generation identities, slot incarnations, probe identities, and error text do not become Prometheus labels.

### Other events

Each direct-fallback commit log reports the new, active, and total session counts.

Telego logs NAT discovery results, the selected public IP, responder agreement, and the retry time.

Telego also logs aggregated ME session commits and the current number of active ME bindings.

## Troubleshooting

If direct fallback stays active, read the latest artifact or generation error. Then make sure that the artifact URLs and ME endpoints are reachable.

If the error reports NAT discovery, make sure that the container can send UDP to the STUN pool.

If STUN reports the wrong IP, set `nat-ip` to the public IP that carries the ME TCP connections.

If the ME handshake still fails, inspect the host NAT rules. The rules must keep the TCP source port for each ME connection.

If you add a SOCKS5 proxy, make sure that it accepts remote DNS and the configured credentials. Restart Telego after the change.

If ME becomes ready after clients connect, reconnect those clients. Existing direct routes stay direct by design.

If repair failures increase, inspect `telego_middleend_links` by signed DC. A healthy DC pool stays available during repair of another pool.

If the zero-ready counter increases, inspect the affected signed DC and the refresh outcomes. A recovered gauge does not erase the recorded gap.

If capacity retirements interrupt bindings, inspect the retirement reason and artifact or recovery events. This counter does not indicate a physical-link failure.

If diagnostic drops increase, treat the interval as incomplete evidence. A later failure record cannot reconstruct the missing records.

If a queue reaches 80%, inspect its high-water metric and capacity. Reduce `max-connections` before you reduce `queue-budget-mb`.

At startup, Telego reports the process file-descriptor limit. The direct-fallback minimum is two descriptors for each allowed public connection.
