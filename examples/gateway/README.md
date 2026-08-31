# Managed WEB gateway example

This example installs Telego, Nginx, and automatic certificate renewal on a new VPS.

Nginx and Telego share one private network namespace. This design removes fixed Docker subnets and private container addresses.

## Contents

- [Requirements](#requirements)
- [Traffic flow](#traffic-flow)
- [Install the gateway](#install-the-gateway)
- [Reuse existing users](#reuse-existing-users)
- [Persistent state](#persistent-state)
- [Change the configuration](#change-the-configuration)
- [Update the services](#update-the-services)
- [Stop or remove the gateway](#stop-or-remove-the-gateway)
- [Limits](#limits)

## Requirements

Make sure that the VPS meets these requirements:

- A DNS hostname points to the VPS.
- Public TCP ports 80 and 443 are free.
- The firewall permits inbound TCP connections on ports 80 and 443.
- Docker Engine and Docker Compose are available.

The setup script uses the HTTP-01 ACME challenge. Port 80 must be reachable during installation and renewal.

## Traffic flow

The gateway keeps the existing public TLS boundary:

```text
Internet :443
    |
    v
Telego MTProxy :443
    |-- authenticated MTProxy --> Telegram
    |
    `-- ordinary TLS --> Nginx :8443 --> Telego WEB :8080
                                              |
                                              `--> local Telego MTProxy :443
```

The private ports use the shared network namespace. Docker does not publish these ports.

## Install the gateway

Run the installer from the directory that will contain the gateway:

```bash
curl -fsSL https://raw.githubusercontent.com/Scratch-net/telego/main/examples/gateway/install.sh \
  | sh -s -- --domain proxy.example.com --email admin@example.com
```

The installer creates `telego-gateway/` in the current directory. It downloads the gateway files and runs the setup script.

Open the installation directory before you run management commands:

```bash
cd telego-gateway
```

The default carrier is `https-lanes`. Select a different carrier with `--carrier`:

```bash
curl -fsSL https://raw.githubusercontent.com/Scratch-net/telego/main/examples/gateway/install.sh \
  | sh -s -- \
      --domain proxy.example.com \
      --email admin@example.com \
      --carrier websocket-lanes
```

Telegram Desktop always connects to public HTTPS port 443. The setup script does not provide a public port option.

The official [WEB proxy reference](https://github.com/telegramdesktop/tproxy-server) documents the fixed port.

The script completes these actions:

1. Generates a random 16-byte secret.
2. Writes the Telego and Nginx configuration to `state/`.
3. Requests the first certificate from Let's Encrypt.
4. Starts Nginx, Telego, and the certificate-renewal service.
5. Prints the plain and `dd` WEB proxy links.

Run this command to display the links again:

```bash
sed -n '1,4p' state/links.txt
```

## Reuse existing users

If an older Telego installation has users, copy only the named entries from its `[secrets]` section.

Open the old configuration and `state/telego/config.toml`. Copy each user name and 32-character secret into the new `[secrets]` section.

CAUTION: Do not replace the complete gateway configuration. The generated `[tls-fronting]` and `[web-proxy]` sections are required.

For example:

```toml
[secrets]
gateway = "generated_gateway_secret"
alice = "old_alice_secret"
bob = "old_bob_secret"
```

If you do not need the generated credential, delete the `gateway` entry.

Recreate Telego after you change the secrets:

```bash
docker compose up -d --force-recreate telego
```

Display the WEB links for all configured users:

```bash
docker compose logs --no-color telego | grep 'Telegram WEB proxy links'
```

This command displays proxy credentials. Do not publish its output.

Manual changes do not update `state/links.txt`. This file continues to contain only the initially generated links.

## Persistent state

Docker does not store the gateway configuration or certificates in container layers or named volumes.

The setup script creates this host layout:

```text
state/
├── telego/config.toml
├── nginx/nginx.conf
├── nginx/watch-certificate.sh
├── site/index.html
├── letsencrypt/conf/
├── letsencrypt/lib/
├── letsencrypt/www/
├── runtime/
└── links.txt
```

Back up the complete `state/` directory. The `config.toml` and `links.txt` files contain the proxy secret.

## Change the configuration

Edit `state/telego/config.toml` to change the carrier or Telego options.

Recreate Telego after a configuration change:

```bash
docker compose up -d --force-recreate telego
```

Edit `state/site/index.html` to replace the default website.

Make sure that the Nginx configuration is valid before a reload:

```bash
docker compose exec -T nginx nginx -t
docker compose exec -T nginx nginx -s reload
```

## Update the services

Run the installation command again to update the gateway files. Use the same domain, email, and carrier values.

The installer preserves `.env` and the complete `state/` directory.

Pull the current images. Then recreate the services:

```bash
docker compose pull
docker compose up -d --force-recreate
docker compose ps
```

The Certbot service runs certificate renewal every 12 hours. Nginx reloads only after a successful renewal.

## Stop or remove the gateway

Stop the services:

```bash
docker compose down
```

This command does not remove the `state/` directory.

CAUTION: Back up `state/` before you remove it. This directory contains the certificate and proxy secret.

## Limits

Telegram Desktop fixes the public WEB endpoint to HTTPS port 443. A WEB proxy link cannot select a different port.

This example must own public ports 80 and 443. Use the manual example for an existing Nginx site or custom network layout.
