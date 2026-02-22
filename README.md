# telego

Production-grade Telegram MTProxy in Go with high-performance networking, advanced TLS fronting, and Middle-End support.

## Features

- **High-Performance Networking**
  - Zero-copy data relay using Linux `splice(2)` syscall
  - 256KB TCP buffers for high throughput
  - `TCP_NODELAY` and `TCP_QUICKACK` for low latency
  - `SO_REUSEPORT` for kernel-level load balancing

- **Advanced TLS Fronting**
  - Fetches real certificates from mask host
  - Splices unrecognized clients to mask host (probe resistance)
  - Indistinguishable from legitimate HTTPS traffic

- **Middle-End Support**
  - Connection pooling to Telegram ME servers (port 8888)
  - Health checks with automatic reconnection
  - STUN-based public IP detection
  - Fallback to direct DC on ME failure

- **Optimized Transport Layer**
  - Fixed buffer sizes to avoid per-operation allocations
  - Optimal TLS record chunking (8KB vs random sizing)
  - Buffer pooling throughout hot paths

- **Reliability**
  - Latency-weighted DC selection
  - Replay attack detection
  - Graceful shutdown with connection draining

## Installation

```bash
go install github.com/Scratch-net/telego/cmd/telego@latest
```

Or build from source:

```bash
git clone https://github.com/Scratch-net/telego.git
cd telego
go build -o telego ./cmd/telego
```

## Quick Start

1. Generate a secret for your proxy:

```bash
telego generate www.google.com
```

2. Run the proxy:

```bash
telego run -s "ee..." -b 0.0.0.0:443
```

3. Connect your Telegram client using the generated link:

```
tg://proxy?server=YOUR_SERVER&port=443&secret=ee...
```

## Configuration

Create a `config.toml` file (see `config.example.toml`):

```toml
secret = "ee..."
bind-to = "0.0.0.0:443"

[middle-end]
enabled = true
pool-size = 16
fallback-to-direct = true

[tls-fronting]
mask-host = "www.google.com"
mask-port = 443
fetch-real-cert = true
splice-unrecognized = true

[performance]
tcp-buffer-kb = 256
concurrency = 8192
prefer-ip = "prefer-ipv4"
```

Run with config:

```bash
telego run -c config.toml
```

## Architecture

```
telego/
├── cmd/telego/          # CLI entry point
├── pkg/
│   ├── netx/            # High-performance networking
│   │   ├── conn.go      # Socket tuning (buffers, TCP_NODELAY)
│   │   ├── dialer.go    # Fast TCP dialing
│   │   └── splice.go    # Zero-copy relay with splice(2)
│   │
│   ├── transport/       # Protocol implementations
│   │   ├── obfuscated2/ # AES-CTR encryption layer
│   │   └── faketls/     # TLS record framing
│   │
│   ├── tlsfront/        # TLS fronting
│   │   ├── certfetch.go # Real certificate fetching
│   │   └── splice.go    # Transparent forwarding
│   │
│   ├── middleend/       # Middle-End support
│   │   ├── pool.go      # Connection pooling
│   │   ├── handshake.go # ME protocol handshake
│   │   └── nat.go       # STUN for public IP
│   │
│   ├── dc/              # Datacenter management
│   │   ├── addrs.go     # DC addresses
│   │   └── pool.go      # Latency-weighted routing
│   │
│   ├── proxy/           # Core proxy logic
│   │   └── proxy.go     # Connection handling
│   │
│   └── config/          # TOML configuration
```

## Protocol Support

| Protocol | Prefix | Status |
|----------|--------|--------|
| FakeTLS | `ee` | Supported |
| Padded Intermediate | `dd` | Planned |

## Performance

telego is designed for high throughput:

- **Zero-copy relay**: Data moves directly between sockets in kernel space
- **Large buffers**: 256KB per direction vs typical 16KB
- **Minimal allocations**: Buffer pooling in hot paths
- **Optimal chunking**: Fixed 8KB TLS records vs random sizing

## CLI Reference

```
telego run [flags]        Run the proxy server
  -c, --config            Path to config file
  -s, --secret            Proxy secret (overrides config)
  -b, --bind              Address to bind to (default: 0.0.0.0:443)

telego generate <host>    Generate a new secret

telego version            Show version information
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

This project was inspired by and builds upon ideas from:

- **[mtg](https://github.com/9seconds/mtg)** by Sergey Arkhipov ([@9seconds](https://github.com/9seconds)) - The original Go MTProxy implementation with clean interface-based architecture. telego's transport layer design is influenced by mtg's obfuscated2 and faketls implementations.

- **[mtprotoproxy](https://github.com/alexbers/mtprotoproxy)** by Alexander Borzunov ([@alexbers](https://github.com/alexbers)) - Python reference implementation that helped understand the MTProto proxy protocol.

- **Telegram** - For the MTProto protocol documentation and proxy specifications.

Special thanks to the MTProxy community for protocol research and documentation.

---

*telego is not affiliated with Telegram.*
