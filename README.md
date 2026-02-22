# TeleGO

(Very) fast Telegram MTProxy in Go with TLS fronting.

## Features

- **High-Performance Networking**
  - Event-driven architecture with [gnet](https://github.com/panjf2000/gnet) (epoll/kqueue)
  - 512KB TCP buffers for maximum throughput
  - `TCP_NODELAY` and `TCP_QUICKACK` for low latency
  - `SO_REUSEPORT` for kernel-level load balancing
  - Buffer pooling to minimize allocations

- **TLS Fronting (inspired by Telemt)**
  - Fetches real certificates from mask host
  - Forwards unrecognized clients to mask host (probe resistance)
  - Indistinguishable from legitimate HTTPS traffic

- **Multi-User Support**
  - Multiple named secrets (per-user tracking)

## Installation

```bash
git clone https://github.com/scratch-net/telego.git
cd telego
make build
```

## Quick Start

1. Generate a secret:

```bash
telego generate www.google.com
```

2. Create `config.toml`:

```toml
bind-to = "0.0.0.0:443"

[secrets]
user1 = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
```

3. Run:

```bash
telego run -c config.toml -l
```

The `-l` flag prints Telegram proxy links with auto-detected public IP.

## Docker

```bash
docker run -d -p 443:443 -v /path/to/config.toml:/config.toml scratchnet/telego:latest
```

Or build locally:

```bash
docker build -t telego .
```

## Systemd

```bash
make install CONFIG=/etc/telego/config.toml
systemctl enable telego
systemctl start telego
```

## CLI

```
telego run -c config.toml    Run proxy server
  -c, --config               Path to config file (required)
  -b, --bind                 Override bind address
  -l, --link                 Print Telegram links on startup

telego generate <host>       Generate a new secret key
telego version               Show version
```

## Contributing

PRs are welcome. Note that Middle-End (ME) protocol and ad-tags will not be supported.

## License

Apache License 2.0

## Acknowledgments

This project was inspired by and builds upon ideas from:

- **[mtg](https://github.com/9seconds/mtg)** by Sergey Arkhipov - The original Go MTProxy implementation
- **[mtprotoproxy](https://github.com/alexbers/mtprotoproxy)** by Alexander Borzunov - Python reference implementation
- **[telemt](https://github.com/nicksnet/telemt)** - High-performance Rust MTProxy implementation
