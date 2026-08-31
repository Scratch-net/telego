# telEgo

High-performance Telegram MTProxy in Go with Telegram Middle-End, TLS fronting, and native WEB protocol support.

- Source: [github.com/Scratch-net/telego](https://github.com/Scratch-net/telego)
- Releases: [github.com/Scratch-net/telego/releases](https://github.com/Scratch-net/telego/releases)
- WEB proxy guide: [docs/web-proxy.md](https://github.com/Scratch-net/telego/blob/main/docs/web-proxy.md)
- Docker examples: [examples](https://github.com/Scratch-net/telego/tree/main/examples)
- License: Apache-2.0

The image uses `telego` as its entry point. It contains a static binary and no shell.

## Supported image tags

Release `v0.6.0` publishes these tags:

- `scratchnet/telego:v0.6.0` — fixed release;
- `scratchnet/telego:v0.6` — latest `v0.6.x` release;
- `scratchnet/telego:v0` — latest `v0.x` release;
- `scratchnet/telego:latest` — latest stable release.

The current manifests support Linux on AMD64, ARM64, and ARMv7.

Use a fixed release tag when you need repeatable deployments. Use `latest` when you want each pull to select the newest stable release.

## Generate a secret

Replace `www.google.com` with the FakeTLS mask hostname:

```bash
docker run --rm scratchnet/telego:v0.6.0 \
  generate www.google.com
```

To also print Telegram WEB proxy links, add the public WEB hostname:

```bash
docker run --rm scratchnet/telego:v0.6.0 \
  generate www.google.com --web-host proxy.example.com
```

The command prints one base secret. Store the 32-character hexadecimal value in the configuration without the `ee` or `dd` prefix.

## Run MTProxy

Create `config.toml`:

```toml
[general]
bind-to = "0.0.0.0:443"

[secrets]
alice = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
```

Start the container:

```bash
docker run -d \
  --name telego \
  --restart unless-stopped \
  -p 443:443 \
  -v "$PWD/config.toml:/config.toml:ro" \
  scratchnet/telego:v0.6.0 \
  run -c /config.toml -l
```

The `-l` option prints the Telegram proxy links during startup:

```bash
docker logs telego
```

## Docker Compose for MTProxy

```yaml
services:
  telego:
    image: scratchnet/telego:v0.6.0
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./config.toml:/config.toml:ro
    command: ["run", "-c", "/config.toml", "-l"]
```

Start the service:

```bash
docker compose config --quiet
docker compose up -d
docker compose logs telego
```

## Run MTProxy and WEB proxy on port 443

The native WEB proxy needs a DNS hostname, a valid TLS certificate, and Nginx. The Telego container keeps public port 443. Nginx uses private ports for TLS termination and sends authenticated WEB traffic back to Telego.

Do not publish the private WEB listener to the Internet.

### Managed gateway

Use the managed gateway for a new VPS. It stores configuration and certificates on the host and renews the certificate automatically.

```bash
curl -fsSL https://raw.githubusercontent.com/Scratch-net/telego/main/examples/gateway/install.sh \
  | sh -s -- --domain proxy.example.com --email admin@example.com
```

The script generates the secret, requests the first certificate, starts the services, and prints the WEB links.

Read the [managed gateway guide](https://github.com/Scratch-net/telego/blob/main/examples/gateway/README.md) for updates, backups, and removal.

### Manual Compose setup

The repository contains a complete Compose stack for all four WEB carrier modes:

```bash
git clone https://github.com/Scratch-net/telego.git
cd telego/examples/web-proxy
```

Replace `proxy.example.com` in these files:

- `docker-compose.yml`;
- `telego.toml`;
- `nginx/nginx.conf`.

Generate the secret and WEB links:

```bash
docker run --rm scratchnet/telego:v0.6.0 \
  generate proxy.example.com --web-host proxy.example.com
```

Add the base secret to `telego.toml`. Then issue the first certificate while port 80 is free:

```bash
mkdir -p certbot/conf certbot/lib certbot/www

docker run --rm -p 80:80 \
  -v "$PWD/certbot/conf:/etc/letsencrypt" \
  -v "$PWD/certbot/lib:/var/lib/letsencrypt" \
  certbot/certbot certonly --standalone --non-interactive --agree-tos \
  --email admin@example.com -d proxy.example.com
```

Start and validate the services:

```bash
docker compose config --quiet
docker compose up -d nginx
docker compose exec -T nginx nginx -t
docker compose up -d
docker compose ps
docker compose logs telego
```

The log must contain `WEB proxy started`.

The example defaults to `https-lanes`. Set `[web-proxy].carrier` to one of these values:

- `https`;
- `https-lanes`;
- `websocket`;
- `websocket-lanes`.

Read the [complete WEB proxy guide](https://github.com/Scratch-net/telego/blob/main/docs/web-proxy.md) before you adapt the Nginx configuration or add an existing website.

## Update the container

For a Compose installation:

```bash
docker compose pull telego
docker compose up -d --force-recreate telego
docker compose logs telego
```

An existing configuration without `[web-proxy]` keeps the existing MTProxy behavior. WEB proxy support is disabled until you set `[web-proxy].enabled = true`.
