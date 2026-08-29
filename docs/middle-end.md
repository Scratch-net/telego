# Telegram Middle-End

Telego can send authenticated MTProxy sessions through Telegram Middle-End (ME) servers. The public listener and the ME client runtime both use gnet.

ME is disabled by default. Existing configurations keep the direct Telegram DC path.

## Configuration

Add this section to the configuration:

```toml
[middle-end]
enabled = true

# Use the tag that Telegram issued for this proxy.
# proxy-tag = "0123456789abcdef0123456789abcdef"

# Route ME links and artifact requests through this SOCKS5 proxy.
# socks5 = "127.0.0.1:1080"
# socks5-username = "proxy-user"
# socks5-password = "proxy-password"

# Override the proxy for artifact requests only.
# artifact-proxy = "http://127.0.0.1:3128"

# These expert values can only reduce the derived defaults.
# max-connections = 0
# queue-budget-mb = 0
```

Restart Telego after a change to this section. The hot reload does not change the ME runtime.

Do not publish the proxy tag or the SOCKS5 credentials in an issue or log.

## Connection routing

Each public TCP connection selects one route after authentication. This selection does not change during that TCP connection.

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
| `telego_middleend_slot_repairs_active` | Physical slots that Telego currently replaces |
| `telego_middleend_slot_repair_total` | Successful and failed physical-slot replacements |
| `telego_middleend_artifact_state` | Applied and pending artifact state |
| `telego_middleend_artifact_refresh_total` | Artifact refresh results |
| `telego_middleend_generation_apply_total` | Generation startup and rotation results |

The queue metrics report current use, capacity, and lifetime high-water values. Telego logs thresholds at 80%, 95%, and 100%.

Telego also logs route fallback, artifact failure, generation failure, physical-link repair, and binding eviction events.

## Troubleshooting

If direct fallback stays active, read the latest artifact or generation error. Then make sure that the artifact URLs and ME endpoints are reachable.

If you add a SOCKS5 proxy, make sure that it accepts remote DNS and the configured credentials. Restart Telego after the change.

If ME becomes ready after clients connect, reconnect those clients. Existing direct routes stay direct by design.

If repair failures increase, inspect `telego_middleend_links` by signed DC. A healthy DC pool stays available during repair of another pool.

If a queue reaches 80%, inspect its high-water metric and capacity. Reduce `max-connections` before you reduce `queue-budget-mb`.

At startup, Telego reports the process file-descriptor limit. The direct-fallback minimum is two descriptors for each allowed public connection.
