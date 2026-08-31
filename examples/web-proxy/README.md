# Manual WEB proxy example

This example gives full control of the Nginx, Telego, and certificate configuration.

Use the [managed gateway](../gateway/README.md) for a new VPS with no existing website configuration.

## Contents

- [Purpose](#purpose)
- [Files](#files)
- [Installation](#installation)
- [Persistent data](#persistent-data)
- [Certificate renewal](#certificate-renewal)

## Purpose

When you add Telego to an existing Nginx site or a custom Docker network, use this example.

The example keeps Telego on public port 443. Nginx uses private ports for TLS and website traffic.

## Files

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Defines the Nginx, Telego, and Certbot services |
| `telego.toml` | Contains the Telego configuration |
| `nginx/nginx.conf` | Contains the complete Nginx configuration |
| `renew-certificate.sh` | Renews the certificate and reloads Nginx |
| `systemd/` | Runs the renewal script two times each day |

## Installation

Read the [Docker procedure](../../docs/web-proxy.md#docker) in the complete WEB proxy guide.

Replace all example hostnames and secrets before you start the services.

## Persistent data

The Compose file stores certificates in these host directories:

- `certbot/conf`
- `certbot/lib`
- `certbot/www`

Back up these directories with `telego.toml` and `nginx/nginx.conf`.

## Certificate renewal

Install the included systemd timer after the first certificate is available.

The renewal script reloads Nginx only after Certbot renews a certificate.
