# Public Middle-End protocol canary

This opt-in helper checks the public DD and EE protocol paths on the VPS.
It reads the existing local configuration privately. It does not change configuration or create a Telegram account.
Output contains protocol counts, timing, and sanitized failure stages.
The helper does not print secrets, endpoint URLs, or response payloads.

For each path, it sends three sequential `req_pq_multi` requests.
It validates each `resPQ` constructor, message envelope, and matching nonce.
It pauses reads for 250ms before the second response, then verifies a third response after reading resumes.
This checks protocol continuity. It does not replace the slow-reader load tests.

The wire format follows Telegram's [authorization procedure](https://core.telegram.org/mtproto/auth_key),
[official byte examples](https://core.telegram.org/mtproto/samples-auth_key),
[message identifier rules](https://core.telegram.org/mtproto/description#message-identifier-msg-id),
and [TL serialization rules](https://core.telegram.org/mtproto/serialize).

The helper requires an admitting ME service and an active ready DC 2 link.
Each successful path must increase the ME commit counter without increasing the direct-fallback counter.
Concurrent fallback traffic makes the route check inconclusive and causes failure.
For wildcard listeners, the helper connects through the corresponding loopback address.
This checks the public listener's protocol handler, not external firewall reachability.

Build the helper for the VPS operating system and architecture:

```sh
go test -c -tags=me_pressure_investigation -o /tmp/telego-public-canary.test ./pkg/gproxy
```

After review, verify the copied helper's SHA-256 against the local build.
Run it in the current Telego network namespace. Keep the host filesystem so the helper can read the configuration.

```sh
nsenter -t "$(docker inspect --format '{{.State.Pid}}' telego)" -n /tmp/telego-public-canary.test -test.run='^TestMiddleEndPublicCanary$' -test.v -test.timeout=45s -me-public-canary-config=/root/telego/config.toml
```

Each protocol path has a 15-second deadline. Metrics requests have a two-second deadline.
Configuration reads, metric responses, and protocol responses have explicit size bounds.
An empty configuration flag skips the live test.
The fixture tests require no VPS or Telegram connection.
