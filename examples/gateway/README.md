# Managed Telego gateway example

This example installs Telego, Nginx, and automatic certificate renewal on a new VPS.

Nginx and Telego share one private network namespace. This design removes fixed Docker subnets and private container addresses.

## Contents

- [Requirements](#requirements)
- [Select a port layout](#select-a-port-layout)
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
- The selected MTProxy port is free.
- The firewall permits inbound TCP connections on all selected public ports.
- Docker Engine and Docker Compose are available.

The setup script uses the HTTP-01 ACME challenge. Port 80 must be reachable during installation and renewal.

## Select a port layout

The WEB proxy always uses `proxy.example.com:443`. The `--mtproxy-port` option changes only the MTProxy port.

| Layout | Command option | WEB client address | MTProxy client address |
|---|---|---|---|
| Shared port | None | `proxy.example.com:443` | `proxy.example.com:443` |
| Separate ports | `--mtproxy-port 9443` | `proxy.example.com:443` | `proxy.example.com:9443` |
| MTProxy only | `--no-web` | Disabled | `proxy.example.com:443` by default |
| MTProxy only on 9443 | `--no-web --mtproxy-port 9443` | Disabled | `proxy.example.com:9443` |

Use any free TCP port from 1 through 65535 for `--mtproxy-port`, except port 80.

Replace `proxy.example.com` with your domain in these addresses.

Telegram Desktop always uses port 443 for WEB. The WEB link does not contain a configurable port.

The script creates the Docker port mappings. Do not publish private ports 8080, 8090, 8443, or 8444.

In the shared layout, private port 9443 is not a public firewall port. Docker maps public port 443 to it.

The setup script fixes the selected layout in `state/`. Use a new state directory to select a different layout.

## Traffic flow

The default layout shares public port 443:

```text
Internet :443
    |
    v
Telego MTProxy :9443 (private target of public port 443)
    |-- authenticated MTProxy --> Telegram
    |
    `-- ordinary TLS --> Nginx :8443 --> Telego WEB :8080
                                              |
                                              `--> local Telego MTProxy :9443
```

The separate-port layout sends public WEB traffic directly to Nginx:

```text
Internet :443  --> Nginx :443 --> Telego WEB :8080 --> Telego MTProxy :9443
Internet :9443 -------------------------------------> Telego MTProxy :9443
```

In both layouts, Telego sends unrecognized MTProxy TLS probes to Nginx on private port 8443.

With `--no-web`, Nginx serves only the ordinary site. Telego still sends unrecognized TLS probes to this site.

The private ports use the shared network namespace. Docker does not publish these ports directly.

The private Nginx listener on port 8444 supplies the certificate and ServerHello template to Telego.

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

To keep WEB on port 443 and move MTProxy to port 9443, run:

```bash
curl -fsSL https://raw.githubusercontent.com/Scratch-net/telego/main/examples/gateway/install.sh \
  | sh -s -- \
      --domain proxy.example.com \
      --email admin@example.com \
      --mtproxy-port 9443
```

For this example, permit inbound TCP connections on ports 80, 443, and 9443.

To install MTProxy without WEB, add `--no-web`:

```bash
curl -fsSL https://raw.githubusercontent.com/Scratch-net/telego/main/examples/gateway/install.sh \
  | sh -s -- \
      --domain proxy.example.com \
      --email admin@example.com \
      --no-web
```

You can combine `--no-web` with `--mtproxy-port`.

The no-WEB layout still needs the domain and email. Nginx supplies the TLS certificate and ordinary probe site.

The official [WEB proxy reference](https://github.com/telegramdesktop/tproxy-server) documents the fixed port.

The script completes these actions:

1. Generates a random 16-byte secret.
2. Writes the Telego and Nginx configuration to `state/`.
3. Requests the first certificate from Let's Encrypt.
4. Selects the public MTProxy and WEB port mappings.
5. Starts Nginx, Telego, and the certificate-renewal service.
6. Prints the public endpoints, firewall ports, MTProxy links, and enabled WEB links.

The script reports each phase and the destination of each generated file. Progress messages do not contain the proxy secret. The final proxy links contain it.

Run this command to display the links again:

```bash
sed -n '1,10p' state/links.txt
```

## Reuse existing users

If an older Telego installation has users, copy only the named entries from its `[secrets]` section.

Open the old configuration and `state/telego/config.toml`. Copy each user name and 32-character secret into the new `[secrets]` section.

CAUTION: Do not replace the complete gateway configuration. The generated `[tls-fronting]` section is required.

If WEB is enabled, the generated `[web-proxy]` section is also required.

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

Existing client links stay valid when the hostname and public MTProxy port do not change.

Manual changes do not update `state/links.txt`. This file contains only the initially generated links.

## Persistent state

Docker does not store the gateway configuration or certificates in container layers or named volumes.

The setup script creates this host layout:

```text
state/
├── telego/config.toml
├── nginx/nginx.conf
├── nginx/gateway-server.conf
├── nginx/watch-certificate.sh
├── site/index.html
├── letsencrypt/conf/
├── letsencrypt/lib/
├── letsencrypt/www/
├── runtime/
├── domain
├── carrier (WEB only)
├── web-enabled
├── mtproxy-port
├── internal-mtproxy-port
└── links.txt
```

The setup script also creates `compose.override.yaml`. This file contains the selected public port mappings.

Back up the complete `state/` directory. The `config.toml` and `links.txt` files contain the proxy secret.

## Change the configuration

Edit `state/telego/config.toml` to change Telego options. If WEB is enabled, you can also change the carrier.

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

Run the installation command again to update the gateway files. Use the same domain, carrier, port, and WEB options.

The installer preserves the complete `state/` directory. The setup script writes the selected Telego image to `.env`.

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

This example always owns public ports 80 and 443. Port 80 is necessary for certificate renewal.

Use the manual example for an existing Nginx site or custom network layout.
