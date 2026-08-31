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

Telego keeps one active generation in steady state. This generation has four gnet links for each signed DC in Telegram's current artifacts.

The pool selects a least-loaded healthy link for each new binding. The binding stays on that physical link until the binding closes.

Telego fetches the three official Telegram artifacts once per day. A failed refresh keeps the last known good generation.

If artifact content changes, Telego prepares and probes one candidate generation. The active generation continues to accept bindings during this work.

After a successful probe, Telego publishes the candidate in one operation. The previous active generation drains for a maximum of 90s.

Steady state contains one generation. Artifact rotation contains a maximum of two generations.

## Link repair

Telego sends a probe to every physical link every 5s. A link fails when a valid response does not arrive within 100s.

An ordinary link failure starts an in-place replacement of that slot. Telego does not replace the complete generation for this failure.

Bindings on the failed slot close. Bindings on other slots and other DC pools stay on their current links.

New bindings can use the repaired slot after its replacement passes startup. Failed replacements use bounded retries with positive jitter.

A manager-wide failure removes ME admission. New connections use direct fallback while Telego builds a new active generation.

## Derived limits

Telego derives the operational limits below. Most installations do not need an override.

| Limit | Default | Behavior |
|---|---:|---|
| Links for each signed DC | 4 | Fixed from the minimum in the official implementation |
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
| Retiring generation drain | 90s | Closes remaining bindings after the deadline |

The byte budgets are independent ceilings. Do not add them together as one shared queue.

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
| `telego_middleend_slot_repairs_active` | Physical slots that Telego currently replaces |
| `telego_middleend_slot_repair_total` | Successful and failed physical-slot replacements |
| `telego_middleend_artifact_state` | Applied and pending artifact state |
| `telego_middleend_artifact_refresh_total` | Artifact refresh results |
| `telego_middleend_generation_apply_total` | Generation startup and rotation results |

The queue metrics report current use, capacity, and lifetime high-water values. Telego logs thresholds at 80%, 95%, and 100%.

Telego logs route fallback, artifact failure, generation failure, failed physical-link replacement, and binding eviction events.

Telego writes a warning when a physical-link failure closes client bindings. The warning includes the signed DC, error, and affected binding count.

Failures without client impact and successful replacements use the debug log level.

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

If a queue reaches 80%, inspect its high-water metric and capacity. Reduce `max-connections` before you reduce `queue-budget-mb`.

At startup, Telego reports the process file-descriptor limit. The direct-fallback minimum is two descriptors for each allowed public connection.
