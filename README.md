<p align="center">
  <img src="docs/logo.jpg" alt="telEgo Logo" width="200">
</p>

<h1 align="center">telEgo</h1> <!-- Название проекта читается "ТелЕго", см https://ru.wikipedia.org/wiki/%D0%96%D0%B0%D1%80%D0%B3%D0%BE%D0%BD_%D0%BF%D0%B0%D0%B4%D0%BE%D0%BD%D0%BA%D0%BE%D0%B2 -->

<p align="center">
  <strong>High-performance Telegram MTProxy in Go with TLS fronting and WEB protocol support</strong>
</p>

<p align="center">
  <a href="https://github.com/Scratch-net/telego/actions/workflows/test.yml"><img src="https://github.com/Scratch-net/telego/actions/workflows/test.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="https://github.com/Scratch-net/telego/actions/workflows/lint.yml"><img src="https://github.com/Scratch-net/telego/actions/workflows/lint.yml/badge.svg?branch=main" alt="Lint"></a>
  <a href="https://codecov.io/gh/Scratch-net/telego"><img src="https://codecov.io/gh/Scratch-net/telego/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://goreportcard.com/report/github.com/Scratch-net/telego"><img src="https://goreportcard.com/badge/github.com/Scratch-net/telego" alt="Go Report Card"></a>
  <a href="https://github.com/Scratch-net/telego/releases/latest"><img src="https://img.shields.io/github/v/release/Scratch-net/telego?color=blue&label=release" alt="Release"></a>
  <a href="https://pkg.go.dev/github.com/scratch-net/telego"><img src="https://pkg.go.dev/badge/github.com/scratch-net/telego.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Scratch-net/telego" alt="License"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#native-telegram-web-proxy">WEB Proxy</a> •
  <a href="#docker">Docker</a> •
  <a href="#nginx--lets-encrypt-real-certificate-tls">Nginx + LE</a> •
  <a href="#performance">Performance</a>
</p>

<p align="center">
  <b>English</b> | <a href="README.ru.md">Русский</a>
</p>

---

> **Telegram blocked in your country?** telEgo's TLS fronting makes your proxy indistinguishable from regular HTTPS traffic to censors. [Get started in 2 minutes](#quick-start)

---

## Features

### Networking
- **Event-driven I/O** — Built on [gnet](https://github.com/panjf2000/gnet) with epoll/kqueue for maximum efficiency
- **Native WEB Proxy** — Optional gnet HTTPS carrier for Telegram Desktop behind Nginx
- **Zero-copy relaying** — Direct buffer manipulation without intermediate copies
- **Buffer pooling** — Striped sync.Pool design eliminates allocations in hot paths
- **Optimized TCP** — `TCP_NODELAY`, `TCP_QUICKACK`, 64KB buffers, `SO_REUSEPORT`

### Security
- **TLS Fronting** — Fetches real certificates from mask host for perfect camouflage
- **Probe Resistance** — Forwards unrecognized clients to mask host (indistinguishable from HTTPS)
- **Replay Protection** — 64-shard LRU cache with TTL expiration ([hashicorp/golang-lru](https://github.com/hashicorp/golang-lru))
- **Key Zeroization** — Sensitive data (session IDs, random bytes) zeroed on connection close
- **Desync Detection** — Detects crypto state divergence via abnormal frame sizes
- **Dual Protocol Support** — FakeTLS (ee) and raw Obfuscated2 (dd) with auto-detection on single port
- **Dynamic Record Sizer (DRS)** — Outbound TLS ApplicationData starts with 1369-byte records and ramps to full size after 8 records or 128 KB, mimicking Chrome/Firefox steady-state record patterns
- **Split-TLS** — First outbound ApplicationData record is emitted as a 1-byte record to defeat passive signatures keyed on the first record
- **Profile-matched cert record** — The fake certificate record in the FakeTLS ServerHello is sized to match the mask host's real certificate record, so the accept path and the probe (splice) path present identical TLS record lengths
- **Post-quantum key share** — When a client offers the hybrid X25519MLKEM768 group, the synthetic ServerHello answers with a matching key share instead of downgrading to classical x25519 (a passive group-downgrade tell)
- **SNI-following mask** — Optional safelist of domains; an unrecognized probe whose SNI is safelisted is forwarded to that domain's own server, so the on-wire conversation matches the SNI it claimed

### Operations
- **Multi-user Support** — Named secrets with per-user tracking and logging
- **Connection Tracking** — Unique connection IDs for easy log correlation
- **Connection Limits** — Per-IP connection limits and per-user IP limits with smart blocking (only blocks IPs with active connections when evicted, allowing legitimate reconnections)
- **Prometheus Metrics** — Per-user connection counts, traffic, and blocked IP statistics
- **DC Probing** — Automatic RTT-based DC address sorting at startup
- **Config Hot-Reload** — SIGHUP and file watching for runtime config changes
- **Clock Self-Correction** — Optional startup sync of the handshake time-skew window from a remote HTTP `Date` header, so a wrong server clock doesn't reject every client
- **Stale-Connection Recovery** — Optional close of relays whose server reply goes unanswered by the client, recovering iOS clients stuck on "Updating" after a long background
- **Graceful Shutdown** — Clean connection draining on SIGTERM/SIGINT
- **Structured Logging** — JSON and text output with configurable levels

### Deployment
- **Unix Socket Support** — Bind to Unix sockets for reverse proxy setups
- **PROXY Protocol** — Accept v1/v2 headers from HAProxy/nginx to preserve client IPs
- **SOCKS5 Upstream** — Route DC connections through SOCKS5 proxy (Hysteria2, VLESS, etc.)

---

## Installation

### From Source

```bash
git clone https://github.com/Scratch-net/telego.git
cd telego
make build
```

### Pre-built Binaries

Download from [Releases](https://github.com/Scratch-net/telego/releases/latest).

### Go Install

```bash
go install github.com/scratch-net/telego/cmd/telego@latest
```

---

## Quick Start

**1. Generate a secret:**

```bash
telego generate www.google.com
# secret=0123456789abcdef0123456789abcdef  <- put this in config
# ee_link=tg://proxy?server=YOUR_IP&port=443&secret=ee...  <- FakeTLS (recommended)
# dd_link=tg://proxy?server=YOUR_IP&port=443&secret=dd...  <- raw Obfuscated2
```

**2. Create `config.toml`:**

```toml
[general]
bind-to = "0.0.0.0:443"

[secrets]
alice = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
```

**3. Run:**

```bash
telego run -c config.toml -l
```

The `-l` flag prints Telegram proxy links with auto-detected public IP.

---

## Protocol Modes

telEgo supports two MTProxy protocol variants on a single port with auto-detection:

| Mode | Secret Prefix | Description | Best For |
|------|---------------|-------------|----------|
| **FakeTLS (ee)** | `ee...` | TLS-wrapped Obfuscated2 | Maximum stealth, censorship bypass |
| **Raw (dd)** | `dd...` | Plain Obfuscated2 | Compatibility, lower overhead |

**FakeTLS (ee)** wraps traffic in TLS 1.3 records, making it indistinguishable from HTTPS. The secret includes the mask hostname for SNI validation. Unrecognized connections are forwarded to the mask host for probe resistance.

**Raw (dd)** sends Obfuscated2 directly without TLS wrapping. Lower overhead but easier to fingerprint. Useful for compatibility with older clients or when TLS fronting isn't needed.

Both modes use the same 16-byte secret key. The `ee` or `dd` prefix in the client link determines which mode the client uses. telEgo auto-detects the protocol from the first bytes of each connection.

---

## Native Telegram WEB Proxy

Telego includes an optional WEB proxy for Telegram Desktop. It uses a separate private gnet HTTP/1.1 listener behind Nginx.

Nginx keeps the real TLS certificate and the ordinary website. The existing MTProxy listener stays on public port 443.

Add this section to enable WEB for existing secrets:

```toml
[web-proxy]
enabled = true
hostname = "proxy.example.com"
carrier = "https-lanes"
bind-to = "127.0.0.1:8080"
trusted-proxy-cidrs = ["127.0.0.1/32"]
```

You must route every request from the Nginx TLS server to this listener. This rule prevents carrier headers from bypassing Telego.

The setup uses two private fallback statuses.

- Status 418 preserves an ordinary website request.
- Status 419 removes carrier credentials before public-site delivery.

Run Telego with `-l` to print the plain and `dd` WEB links. Telego derives both links from each existing base secret.

Use `--web-host` to print WEB links when you generate a new secret:

```bash
telego generate www.google.com --web-host proxy.example.com
```

The positional hostname is the FakeTLS mask hostname. The `--web-host` value is the public WEB proxy hostname.

The `--web-host` value must match `[web-proxy].hostname` and the TLS certificate in Nginx.

Read the [native WEB proxy setup guide](docs/web-proxy.md) for the complete Nginx configuration, Docker setup, and rollback procedure.

The WEB configuration is inactive by default. Configurations without `[web-proxy]` continue to use the existing MTProxy startup path.

The recommended `https-lanes` carrier gives each Telegram stream an independent HTTP carrier. It requires HTTP/2 on the public Nginx server.

Existing configurations that omit `carrier` continue to use serialized `https`. This default prevents an upgrade from changing the Nginx requirements.

---

## Configuration

### Config Reference

```toml
[general]
# Network binding (TCP or Unix socket)
bind-to = "0.0.0.0:443"
# bind-to = "/run/telego/telego.sock"  # Unix socket

# Log level: trace, debug, info, warn, error
log-level = "info"

# Accept incoming PROXY protocol headers (from HAProxy/nginx)
# proxy-protocol = false

# Maximum connections per IP (0 = unlimited)
# Applies to ALL connections (including unauthenticated) from a single IP
# max-connections-per-ip = 100

# Max time for handshake before dropping connection (default: 5s)
# handshake-timeout = "5s"

# Maximum unique IPs per user (0 = unlimited)
# Prevents secret sharing - limits how many devices/locations can use one secret
# max-ips-per-user = 3

# How long blocked IPs stay blocked (for max-ips-per-user)
# ip-block-timeout = "5m"

# Correct a skewed server clock at startup from a remote HTTP Date header
# (offset clamped to +-1 day). A wrong VPS clock otherwise rejects every client.
# clock-sync-url = "https://www.cloudflare.com"

# Named secrets (hex format, 32 chars = 16 bytes)
# Generate with: telego generate <hostname>
[secrets]
user1 = "0123456789abcdef0123456789abcdef"
user2 = "fedcba9876543210fedcba9876543210"

# TLS fronting configuration
[tls-fronting]
mask-host = "www.google.com"  # Host to mimic (SNI validation, proxy links)
# mask-port = 443             # Port for mask-host (default: 443)
# cert-host = "127.0.0.1"     # Where to fetch TLS cert (default: mask-host)
# cert-port = 8443            # Cert fetch port (default: mask-port)
# splice-host = "127.0.0.1"   # Forward unrecognized clients here (default: mask-host)
# splice-port = 8080          # Splice port (default: mask-port)
# splice-proxy-protocol = 1   # PROXY protocol to splice: 0=off, 1=v1(text), 2=v2(binary)
# splice-idle-timeout = "30s" # Idle timeout for spliced connections (default: 30s)
# fake-cert-size = 0          # Fake cert record size; 0 = auto-match mask host (clamp 256..16384)
# mask-sni-safelist = ["www.microsoft.com"]  # Probes with these SNIs front to that domain (off = empty)

# Anti-DPI record shaping (proxy -> client direction)
# enable-drs = true        # Probe-then-ramp record sizing (1369 -> 16384 bytes after 8 records or 128 KB)
# enable-split-tls = true  # Emit first ApplicationData record as 1 byte

# Native Telegram Desktop WEB proxy (optional; requires Nginx with real TLS)
[web-proxy]
enabled = false
# carrier = "https-lanes"                  # Recommended. Requires public HTTP/2.
# hostname = "proxy.example.com"            # Required public certificate hostname
# bind-to = "127.0.0.1:8080"               # Private HTTP/1.1 listener
# backend = "127.0.0.1:443"                # Derived TCP or Unix MTProxy backend
# trusted-proxy-cidrs = ["127.0.0.1/32"]   # Nginx peers allowed to send X-Forwarded-For
# num-event-loops = 0                       # 0 = automatic

# Performance tuning (all optional)
[performance]
prefer-ip = "prefer-ipv4"    # prefer-ipv4, prefer-ipv6, only-ipv4, only-ipv6
idle-timeout = "5m"          # Connection idle timeout (hot-reloadable)
num-event-loops = 0          # 0 = auto (all CPU cores)
# client-silence-close = "12s"  # Close relays whose server reply stays unanswered (fixes iOS "Updating"); 0 = off

# Upstream (DC connection) settings
[upstream]
# socks5 = "127.0.0.1:1080"  # Route DC traffic through SOCKS5 proxy

# Prometheus metrics (optional)
[metrics]
# bind-to = "127.0.0.1:9090"  # Metrics endpoint (empty = disabled)
# path = "/metrics"           # Metrics path
```

---

## CLI Reference

```
telego run       Start the proxy server
  -c, --config   Path to config file (required)
  -b, --bind     Override bind address
  -l, --link     Print Telegram proxy links on startup (both ee and dd)

telego generate <mask-host> [--web-host <hostname>]
                             Generate a new secret
                             Print ee (FakeTLS) and dd (raw) MTProxy links
  --web-host <hostname>      Print plain and dd WEB proxy links

telego version   Show version information
```

---

## Docker

### Docker Hub

```bash
docker run -d \
  --name telego \
  -p 443:443 \
  -v /path/to/config.toml:/config.toml \
  scratchnet/telego:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  telego:
    image: scratchnet/telego:latest
    container_name: telego
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./config.toml:/config.toml:ro
    cap_add:
      - NET_BIND_SERVICE
```

### Build Locally

```bash
docker build -f dist/Dockerfile.build -t telego .
docker run -d -p 443:443 -v ./config.toml:/config.toml telego
```

---

## Behind a Reverse Proxy

telEgo can run behind HAProxy or nginx using Unix sockets and PROXY protocol:

**config.toml:**
```toml
[general]
bind-to = "/run/telego/telego.sock"
proxy-protocol = true
max-connections-per-ip = 100  # DoS protection
max-ips-per-user = 3          # Sharing protection

[secrets]
user1 = "..."

[tls-fronting]
mask-host = "www.google.com"
```

**HAProxy example:**
```
backend telego
    mode tcp
    server telego /run/telego/telego.sock send-proxy-v2
```

**nginx example:**
```nginx
upstream telego {
    server unix:/run/telego/telego.sock;
}

server {
    listen 443;
    proxy_pass telego;
    proxy_protocol on;
}
```

---

## Nginx + Let's Encrypt (Real Certificate TLS)

Some censorship systems (e.g., TSPU) validate the TLS certificate against the SNI hostname. If your proxy gets blocked on mobile or connects intermittently, you may need a **real** certificate for your domain instead of borrowing one from a mask host.

The `deploy-nginx.sh` script sets up nginx with a Let's Encrypt certificate alongside telego in Docker:

```
Port 443 (host) --> telego (MTProxy TLS fronting)
                      |-- valid client  --> Telegram DCs
                      |-- cert fetch    --> nginx:8443 (real LE cert)
                      +-- probe/unknown --> nginx:8443 (decoy website)
Port 80  (host) --> nginx (ACME challenges + HTTPS redirect)
```

Censors and probes see a valid certificate for your domain and a real HTTPS website.

### Prerequisites

- VPS with Docker
- A domain pointing to your VPS IP (e.g., via [FreeDNS](https://freedns.afraid.org/))
- Ports 80 and 443 free
- Telego config file already in place

### Usage

```bash
./deploy-nginx.sh -d <domain> -e <email> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Domain name (required) | |
| `-e` | Email for Let's Encrypt (required) | |
| `-D` | Telego directory | `~/telego` |
| `-c` | Telego config filename | `config.toml` |
| `-p` | Telego port | `443` |

Example:

```bash
./deploy-nginx.sh -d myproxy.example.com -e admin@example.com -c config.toml
```

### What it does

1. If no telego config exists, creates one with the correct `[tls-fronting]` settings and exits -- add your secrets and re-run
2. Stops any existing `telego` and `telego-nginx` containers
3. Obtains a Let's Encrypt certificate (standalone mode, skips if cert exists)
4. Starts nginx (port 80 for ACME, internal port 8443 with the real cert)
5. Pulls and starts telego on a shared Docker network with nginx
6. Adds a daily cron job for certificate renewal

### First run

On a fresh server, the first run creates the config and exits:

```bash
./deploy-nginx.sh -d myproxy.example.com -e admin@example.com
# Config created at: ~/telego/config.toml
# Add at least one secret before running again
```

Generate a secret and add it to the config:

```bash
docker run --rm scratchnet/telego:latest generate myproxy.example.com
# Paste the hex string into [secrets] section of config.toml
```

Then run the script again to deploy:

---

## Systemd

Install as a systemd service:

```bash
sudo make install CONFIG=/etc/telego/config.toml
sudo systemctl enable telego
sudo systemctl start telego
```

Service file is installed to `/etc/systemd/system/telego.service`.

---

## Config Hot-Reload

telEgo supports runtime configuration reloading without restart:

**Via SIGHUP:**
```bash
kill -HUP $(pidof telego)
```

**Automatic:** Config file changes are detected via fsnotify (Linux inotify).

**Hot-reloadable fields:**
- `log-level` — Applied immediately
- `idle-timeout` — Applies to new connections

**Require restart:**
- `bind-to`, `secrets`, `tls-fronting.*`, `proxy-protocol`, `web-proxy.*`, `max-connections-per-ip`, `max-ips-per-user`, `handshake-timeout`

---

## Performance

### Benchmarks

Tested on Intel i9-12900K, Linux 6.6:

| Benchmark | Throughput | Allocations |
|-----------|------------|-------------|
| Raw TCP loopback | 6.0 GB/s | 0 B/op |
| AES-CTR encrypt | 10.5 GB/s | 0 B/op |
| AES-CTR encrypt+decrypt | 5.3 GB/s | 0 B/op |
| Full pipeline (TLS+O2) | 4.6 GB/s | 5 B/op |
| TLS frame parse (pooled) | 35.5 GB/s | 0 B/op |
| Replay cache lookup | 40 ns | 32 B/op |

### Optimizations

- **Striped locking** — 64-shard replay cache, 64-shard user IP limiter
- **Buffer pools** — 64KB DC buffers, 16KB TLS record buffers
- **Zero-copy crypto** — XORKeyStream directly into output buffers
- **Batched writes** — Multiple TLS records coalesced into single syscall
- **Lock-free state** — Atomic state machine for connection handling
- **Backpressure** — Flow control with hysteresis (soft/hard limits) prevents OOM on slow clients without oscillation

---

## Logging

Connections are tracked with unique IDs for easy correlation:

```
INF gnet proxy started on 0.0.0.0:443
INF Connection limiter enabled: max 100 connections per IP
INF User IP limiter enabled: max 3 IPs per user, block timeout 5m0s
INF [#1:alice] 203.0.113.5:54321 -> DC 2
INF [#2:bob] 198.51.100.10:12345 -> DC 4
INF [#1:alice] DC 2 closed (45.2s) (active: 1)
WRN [#2:bob] DC 4 closed (30s): i/o timeout (active: 0)
```

- `#N` — Connection ID (incremental, unique per session)
- `#N:user` — Connection ID with matched secret name
- Duration shown on close
- Errors on authenticated connections logged as WARN

---

## Metrics

telEgo exposes Prometheus metrics when configured:

```toml
[metrics]
bind-to = "127.0.0.1:9090"
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `telego_connections_active` | Gauge | Active connections per user |
| `telego_ips_active` | Gauge | IPs with active connections per user |
| `telego_ips_tracked` | Gauge | Unique IPs in LRU cache per user |
| `telego_ips_blocked` | Gauge | Currently blocked IPs per user |
| `telego_blocked_total` | Counter | Total IP block events per user |
| `telego_traffic_in_bytes_total` | Counter | Bytes received from clients |
| `telego_traffic_out_bytes_total` | Counter | Bytes sent to clients |
| `telego_handshake_failures_total` | Counter | MTProxy handshake failures by `stage` |
| `telego_web_sessions_active` | Gauge | Active WEB sessions |
| `telego_web_streams_active` | Gauge | Active WEB backend streams |
| `telego_web_backend_dials_active` | Gauge | WEB backend dials in progress |
| `telego_web_pending_bytes` | Gauge | Bytes charged to WEB pending queues |
| `telego_web_pending_items` | Gauge | Items charged to WEB pending queues |
| `telego_web_sessions_created_total` | Counter | WEB sessions created |
| `telego_web_sessions_closed_total` | Counter | WEB sessions closed by `reason` |
| `telego_web_carrier_retries_total` | Counter | WEB retries and replays by `operation` |
| `telego_web_backpressure_total` | Counter | WEB backpressure events by `operation` |

Connection, IP, block, and traffic metrics include a `user` label. Diagnostic metrics use the labels in the table.

---

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌──────────┐
│   Client    │────▶│              telEgo                  │────▶│ Telegram │
│ (Telegram)  │◀────│      Auto-detect ee/dd protocol      │◀────│    DC    │
└─────────────┘     │                                      │     └──────────┘
                    │  ee: FakeTLS ─▶ Obfuscated2 ─▶ Relay │
                    │  dd: Obfuscated2 ─▶ Relay            │
                    └──────────────────────────────────────┘
                                     │
                                     ▼ (unrecognized ee)
                               ┌──────────┐
                               │   Mask   │
                               │   Host   │
                               └──────────┘
```

---

## Contributing

PRs are welcome! Please ensure:

1. Tests pass: `go test -race ./...`
2. Benchmarks don't regress: `go test -bench=. ./...`

**Note:** Middle-End (ME) protocol and ad-tags will not be supported.

---

## License

[Apache License 2.0](LICENSE)

---

## Acknowledgments

This project was inspired by and builds upon ideas from:

- **[mtg](https://github.com/9seconds/mtg)** by Sergey Arkhipov — The original Go MTProxy implementation
- **[mtprotoproxy](https://github.com/alexbers/mtprotoproxy)** by Alexander Borzunov — Python reference implementation
- **[telemt](https://github.com/nicksnet/telemt)** — High-performance Rust MTProxy implementation

---
