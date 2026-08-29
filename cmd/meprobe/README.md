# meprobe

`meprobe` performs one read-only Telegram Middle-End connectivity check. It
fetches and validates one complete current artifact generation, selects one
endpoint, opens one TCP link, completes the encrypted RPC handshake, sends one
ping, requires the matching pong, and closes. It does not listen on a port,
register a proxy, send a proxy tag, retry, or write artifact and key material
to disk.

Direct check from a host whose TCP source address is already a public address:

```text
go run ./cmd/meprobe -dc=-203 -family=4
```

Check through a SOCKS5 proxy and use the same local service as an HTTP proxy
for the HTTPS artifact requests:

```text
go run ./cmd/meprobe \
  -http-proxy=http://127.0.0.1:10808 \
  -socks=127.0.0.1:10808
```

The SOCKS5 CONNECT reply must contain the actual public outbound
`BND.ADDR:BND.PORT`. A reply that contains `0.0.0.0`, a loopback address, a
private address, or a domain fails before nonce generation because Telegram's
key derivation binds to the exact tuple. This failure is expected from many
local desktop proxy applications.

For SOCKS5 username/password authentication, set both variables in the process
environment. Do not put the values in command-line arguments:

```text
TELEGO_MEPROBE_SOCKS_USERNAME=... \
TELEGO_MEPROBE_SOCKS_PASSWORD=... \
go run ./cmd/meprobe -socks=127.0.0.1:10808
```

Use `-help` for signed DC, address-family, endpoint-index, and timeout options.
Success prints only the selected signed DC, address family, and transport.

## Phase 3 performance prerequisite

Do not select the blocking or gnet link engine from framing-only benchmarks.
Phase 3 must measure the complete `ClientBootstrap.Encode` and
`ClientBootstrap.Feed` paths, including full-frame encoding, continuous CBC,
checksum state, fragmentation/coalescing, decoded-frame delivery, allocations,
throughput, and tail latency. Run the same payload-size and concurrency matrix
through both candidate engines. Select gnet only from those end-to-end results
and the recovery/correctness gates; this probe does not make that engine choice.
