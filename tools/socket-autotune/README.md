# Socket buffer experiment

This Linux experiment compares change #3: kernel TCP autotuning versus the previous 512 KiB buffer requests.
It carries synthetic data through Telego's native HTTP WEB server and direct DC transport.
It does not contact Telegram or use a deployed Telego service.

The two executables use the same source and build flags.
Only the fixed executable adds `SO_RCVBUF=512*1024` and `SO_SNDBUF=512*1024` in `pkg/netx/conn_linux.go`.
Go build overlays keep the product source unchanged.
The `.go.txt` fixture compiles only through the overlay into `cmd/telego`.

## Requirements

- Linux with user and network namespaces enabled.
- The repository's Go toolchain, Python 3.9 or later, and its Go dependencies.
- `unshare`, `nsenter`, `ip`, `tc`, `ethtool`, `sysctl`, `ping`, `ss`, and `taskset`.
- Optional: Matplotlib for PNG and SVG charts. The report also works without charts.

## Run

From the repository root, build both executables:

```sh
python3 tools/socket-autotune/build.py
```

Run a short pilot:

```sh
unshare -Urn python3 tools/socket-autotune/run.py \
  --pilot --output .local/socket-autotune/pilot
```

Run six alternating pairs for each of the 20 cases:

```sh
unshare -Urn python3 tools/socket-autotune/run.py \
  --repeats 6 --output .local/socket-autotune/matrix
```

Use a new output directory for each run.
The runner stops on the first failed transfer or cleanup check.
It retains the failed case and its logs.
With `--continue-on-failure`, the runner records failures and runs the remaining cases.
It still returns a failure status after the matrix.
It deletes the temporary network namespaces after the run.
The build and result files remain in `.local`.

For a focused run, select the network, direction, and stream count:

```sh
unshare -Urn python3 tools/socket-autotune/run.py \
  --scenario long-1000 --direction upload --streams 8 \
  --repeats 6 --output .local/socket-autotune/long-upload
```

The `--cpus 0,1,2,3,4,5` option restricts the lab to the listed CPU IDs.
With six or more CPUs, the runner assigns two CPUs each to the relay, peer, and client.
These assignments restrict affinity but do not reserve CPUs against unrelated host processes.
The client, peer, and relay share the host CPU capacity.
CPU quotas can limit the generator before the simulated link reaches its rate ceiling.
The VPS experiment bounds the full process tree in one cgroup and records its quota and throttling counters.
Its throughput results describe that recorded resource budget.

If new namespaces inherit different TCP defaults, copy the intended relay values into a JSON file:

```json
{
  "net.ipv4.tcp_rmem": "4096 131072 6291456",
  "net.ipv4.tcp_wmem": "4096 16384 4194304",
  "net.ipv4.tcp_congestion_control": "cubic"
}
```

Pass this file with `--tcp-sysctls path/to/tcp.json`.
The runner applies these three controls to both disposable endpoint namespaces.
It reads each value again to check the result.
The host and deployed network namespaces keep their existing values.
The recorded environment includes both endpoint values and the supplied controls.
Some kernels expose `net.core.rmem_max` and `net.core.wmem_max` only in the host namespace.
The runner records `null` for these unavailable namespace controls.

Generate the report:

```sh
python3 tools/socket-autotune/report.py .local/socket-autotune/matrix \
  --output .local/socket-autotune/report
```

The report contains HTML, JSON, CSV, and optional charts.
For multiple result directories, list each directory before `--output`.
The report rejects duplicate cases and different executable hashes.

## Test cases

| Profile | RTT | Rate ceiling | Random packet loss per direction |
|---|---:|---:|---:|
| `short-100` | 20 ms | 100 Mb/s | 0 |
| `short-1000` | 20 ms | 1 Gb/s | 0 |
| `wan-1000` | 80 ms | 1 Gb/s | 0 |
| `long-1000` | 160 ms | 1 Gb/s | 0 |
| `lossy-1000` | 80 ms | 1 Gb/s | 0.1% |

Each profile covers upload and download, with one or eight concurrent streams.
Each stream first transfers 1 MiB for warmup.
The timed phase transfers 64 MiB total across all streams, or 16 MiB for `lossy-1000`.
The measured time includes the checksum acknowledgement.
The `--bytes` option overrides the payload size for all selected profiles.
The client checks every payload byte and the SHA-256 digest.
The server must release all sessions, streams, backend dials, pending items, and pending bytes after shutdown.

The topology uses three temporary network namespaces:

```text
synthetic client + real Telego -> router -> synthetic DC peer
```

The router applies `netem` before each receiver interface.
This placement avoids the sender TCP Small Queues effect on an endpoint egress qdisc.
The experiment disables TSO, GSO, GRO, and endpoint TCP metric caching in these namespaces.
It does not change the host network configuration.

The runner records throughput, relay CPU cost, client CPU cost, relay RSS, socket limits, queued socket memory, and retransmissions.
It also records HTTP admission retries, cleanup counters, ping RTT, and qdisc configuration and counters.
The synthetic client replays retryable HTTP requests with the same body and sequence after `Retry-After`.
Its retry deadline is 30 seconds per request.

## Limits

This experiment isolates the impaired DC leg.
The frontend uses private HTTP without TLS, NGINX, a browser, or client WAN delay.
The peer implements the transport handshake and synthetic exchange, not Telegram RPCs or middle-end pooling.
The client pauses 1 ms between download polls to limit tiny HTTP responses.
The `--down-poll-ms` option changes this interval for download-pressure tests (0 to 1000 ms).
WINDOW updates accumulate in one bounded counter per stream, so uplink retries do not block download polls.
The client serializes uplink requests instead of the complete native carrier scheduling.
These choices apply equally to both executables.

Results describe finite transfers after a short warmup.
They do not establish steady-state throughput, long-term leak freedom, or production performance.
CPU capacity, kernel defaults, and TCP windows can limit throughput before the configured rate ceiling.
Socket and RSS samples occur every 200 ms, so recorded peaks are lower bounds.
Kernel socket values describe configured budgets, not reserved allocations or strict memory bounds.
The reported socket memory sums receive and queued-send skb allocations for the relay DC sockets.

The runner supports older `tc` versions without a loss seed.
Loss cases therefore use independent random draws with alternating control order.
Paired ranges describe the observations and are not confidence intervals.

The local results require a separate run on the VPS kernel before a production decision.
The same commands can run in disposable namespaces on that VPS.

References: [Linux TCP controls](https://docs.kernel.org/networking/ip-sysctl.html),
[netem limitations](https://man7.org/linux/man-pages/man8/tc-netem.8.html).
