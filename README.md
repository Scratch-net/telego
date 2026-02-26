<p align="center">
  <img src="logo.jpg" alt="TeleGO Logo" width="200">
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
- **DC Probing** — Automatic RTT-based DC address sorting at startup
- **Graceful Shutdown** — Clean connection draining on SIGTERM/SIGINT
- **Structured Logging** — JSON and text output with configurable levels

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
# Output: ee1234567890abcdef1234567890abcdef777777772e676f6f676c652e636f6d
```

**2. Create `config.toml`:**

```toml
bind-to = "0.0.0.0:443"

[secrets]
alice = "1234567890abcdef1234567890abcdef"
bob   = "fedcba0987654321fedcba0987654321"

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
# Network binding
bind-to = "0.0.0.0:443"

# Log level: debug, info, warn, error
log-level = "info"

# Named secrets (hex format, 32 chars = 16 bytes)
# Generate with: telego generate <hostname>
[secrets]
user1 = "0123456789abcdef0123456789abcdef"
user2 = "fedcba9876543210fedcba9876543210"

# TLS fronting configuration
[tls-fronting]
mask-host = "www.google.com"  # Host to mimic (cert fetching, SNI validation)
# mask-port = 443             # Port to fetch cert from (default: 443)
# splice-host = "127.0.0.1"   # Forward unrecognized clients here (default: mask-host)
# splice-port = 8080          # Splice port (default: mask-port)
# splice-proxy-protocol = 1   # PROXY protocol: 0=off, 1=v1(text), 2=v2(binary)

# Performance tuning (all optional)
[performance]
prefer-ip = "prefer-ipv4"    # prefer-ipv4, prefer-ipv6, only-ipv4, only-ipv6
idle-timeout = "5m"          # Connection idle timeout
num-event-loops = 0          # 0 = auto (all CPU cores)
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
docker build -f Dockerfile.build -t telego .
docker run -d -p 443:443 -v ./config.toml:/config.toml telego
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

- **Striped locking** — 32-shard replay cache reduces lock contention
- **Buffer pools** — 768KB DC buffers, 256KB read buffers, 16KB crypto buffers
- **Zero-copy crypto** — XORKeyStream directly into output buffers
- **Batched writes** — Multiple TLS records coalesced into single syscall
- **Lock-free state** — Atomic state machine for connection handling

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
