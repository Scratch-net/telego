<p align="center">
  <img src="docs/logo.jpg" alt="TeleGO Logo" width="200">
</p>

<h1 align="center">TeleGO</h1>

<p align="center">
  <strong>High-performance Telegram MTProxy in Go with TLS fronting</strong>
</p>

<p align="center">
  <a href="https://github.com/Scratch-net/telego/actions/workflows/test.yml"><img src="https://github.com/Scratch-net/telego/actions/workflows/test.yml/badge.svg?branch=main" alt="Tests"></a>
  <a href="https://codecov.io/gh/Scratch-net/telego"><img src="https://codecov.io/gh/Scratch-net/telego/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://goreportcard.com/report/github.com/Scratch-net/telego"><img src="https://goreportcard.com/badge/github.com/Scratch-net/telego" alt="Go Report Card"></a>
  <a href="https://github.com/Scratch-net/telego/releases/latest"><img src="https://img.shields.io/github/v/release/Scratch-net/telego" alt="Release"></a>
  <a href="https://pkg.go.dev/github.com/scratch-net/telego"><img src="https://pkg.go.dev/badge/github.com/scratch-net/telego.svg" alt="Go Reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Scratch-net/telego" alt="License"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#docker">Docker</a> •
  <a href="#performance">Performance</a>
</p>

---

## Features

### Networking
- **Event-driven I/O** — Built on [gnet](https://github.com/panjf2000/gnet) with epoll/kqueue for maximum efficiency
- **Zero-copy relaying** — Direct buffer manipulation without intermediate copies
- **Buffer pooling** — Striped sync.Pool design eliminates allocations in hot paths
- **Optimized TCP** — `TCP_NODELAY`, `TCP_QUICKACK`, 768KB buffers, `SO_REUSEPORT`

### Security
- **TLS Fronting** — Fetches real certificates from mask host for perfect camouflage
- **Probe Resistance** — Forwards unrecognized clients to mask host (indistinguishable from HTTPS)
- **Replay Protection** — Sharded cache with 32 stripes for low-contention replay detection
- **Obfuscated2 + FakeTLS** — Full protocol support with streaming encryption

### Operations
- **Multi-user Support** — Named secrets with per-user tracking and logging
- **Connection Tracking** — Unique connection IDs for easy log correlation
- **Connection Limits** — Per IP+secret limits using blake3 hashing with sharded maps
- **DC Probing** — Automatic RTT-based DC address sorting at startup
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
# link=tg://proxy?server=YOUR_IP&port=443&secret=ee...  <- share with clients
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

# Maximum connections per IP+secret (0 = unlimited)
# max-connections-per-ip = 10

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

# Performance tuning (all optional)
[performance]
prefer-ip = "prefer-ipv4"    # prefer-ipv4, prefer-ipv6, only-ipv4, only-ipv6
idle-timeout = "5m"          # Connection idle timeout
num-event-loops = 0          # 0 = auto (all CPU cores)

# Upstream (DC connection) settings
[upstream]
# socks5 = "127.0.0.1:1080"  # Route DC traffic through SOCKS5 proxy
```

---

## CLI Reference

```
telego run       Start the proxy server
  -c, --config   Path to config file (required)
  -b, --bind     Override bind address
  -l, --link     Print Telegram proxy links on startup

telego generate <hostname>   Generate a new FakeTLS secret for hostname

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

TeleGO can run behind HAProxy or nginx using Unix sockets and PROXY protocol:

**config.toml:**
```toml
[general]
bind-to = "/run/telego/telego.sock"
proxy-protocol = true
max-connections-per-ip = 10

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

## Systemd

Install as a systemd service:

```bash
sudo make install CONFIG=/etc/telego/config.toml
sudo systemctl enable telego
sudo systemctl start telego
```

Service file is installed to `/etc/systemd/system/telego.service`.

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

- **Striped locking** — 32-shard replay cache, 64-shard connection limiter
- **Buffer pools** — 768KB DC buffers, 256KB read buffers, pooled blake3 hashers
- **Zero-copy crypto** — XORKeyStream directly into output buffers
- **Batched writes** — Multiple TLS records coalesced into single syscall
- **Lock-free state** — Atomic state machine for connection handling

---

## Logging

Connections are tracked with unique IDs for easy correlation:

```
INF gnet proxy started on 0.0.0.0:443
INF Connection limiter enabled: max 10 per IP+secret
INF [#1:alice] 203.0.113.5:54321 -> DC 2
INF [#2:bob] 198.51.100.10:12345 -> DC 4
INF [#1:alice] closed (45.2s)
WRN [#2:bob] closed (30s): i/o timeout
```

- `#N` — Connection ID (incremental, unique per session)
- `#N:user` — Connection ID with matched secret name
- Duration shown on close
- Errors on authenticated connections logged as WARN

---

## Architecture

```
┌─────────────┐     ┌──────────────────────────────────────┐     ┌──────────┐
│   Client    │────▶│              TeleGO                  │────▶│ Telegram │
│ (Telegram)  │◀────│  FakeTLS ─▶ Obfuscated2 ─▶ Relay    │◀────│    DC    │
└─────────────┘     └──────────────────────────────────────┘     └──────────┘
                                     │
                                     ▼ (unrecognized)
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

<p align="center">
  Made with Go
</p>
