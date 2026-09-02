# Native Telegram WEB proxy

Telego includes an optional WEB proxy for Telegram Desktop. It supports four carrier values.

The WEB listener uses gnet and accepts private HTTP/1.1 traffic. Nginx keeps the real TLS certificate and the public website.

Existing MTProxy configurations do not start this listener. You must set `[web-proxy].enabled = true` to enable it.

## Contents

- [Select a deployment](#select-a-deployment)
- [Traffic flow](#traffic-flow)
- [Requirements](#requirements)
- [Configure Telego](#configure-telego)
- [Configure Nginx](#configure-nginx)
- [Check the configuration](#check-the-configuration)
- [Docker](#docker)
- [Existing installations](#existing-installations)
- [Rollback](#rollback)
- [Current scope](#current-scope)

## Select a deployment

Select the deployment that matches the host:

| Deployment | Use case | Public port 443 owner | Certificate renewal |
|---|---|---|---|
| [Managed gateway](../examples/gateway/README.md) | A new VPS with shared or separate MTProxy and WEB ports | Telego or Nginx | Automatic Certbot service |
| [Manual shared-port setup](../examples/web-proxy/README.md) | An existing website or a custom Nginx layout | Telego | Existing operator job |
| Existing TLS proxy | Synology, Nginx Proxy Manager, or another managed TLS service | Existing TLS proxy | Existing TLS service |

The managed gateway keeps all configuration and certificate files in a host `state/` directory. Its setup script generates the private configuration.

By default, MTProxy and WEB share public port 443. Set `--mtproxy-port` to give MTProxy a different public port.

With separate ports, Nginx owns public port 443. Telego owns the selected MTProxy port.

For `--mtproxy-port 9443`, WEB clients use `proxy.example.com:443`. MTProxy clients use `proxy.example.com:9443`.

An existing TLS proxy can send decrypted HTTP to the private Telego WEB listener. Native MTProxy must use a different public port.

The TLS proxy must send every request for the hostname through the WEB listener. It must also implement the [fallback contract](#fallback-contract).

If the TLS proxy cannot implement this contract, put an adapter Nginx between the TLS proxy and Telego.

Telegram Desktop fixes a WEB endpoint to HTTPS port 443. The client ignores a `port` parameter in a WEB proxy link.

The official [WEB proxy reference](https://github.com/telegramdesktop/tproxy-server) documents this fixed port.

## Traffic flow

The default managed gateway and manual shared-port setup use the following traffic flow.

The deployment has one public listener and four private listeners or targets:

| Port | Owner | Purpose |
|------|-------|---------|
| `443` | Telego | Public MTProxy and WEB TLS entry point. |
| `8443` | Nginx | TLS termination for connections that Telego splices with PROXY protocol v2. |
| `8444` | Nginx | Certificate source for Telego. This port does not carry client requests. |
| `8080` | Telego | Private HTTP/1.1 listener for WEB carrier requests and website classification. |
| `8090` | Nginx | Private ordinary website listener. |

The managed gateway maps public port 443 to private Telego port 9443. The manual example uses Telego port 443 directly.

The same Telego and Nginx processes appear more than once in these flows. This is intentional.

An authenticated MTProxy connection uses the direct proxy path:

```text
Telegram MTProxy client
          |
          | MTProxy or FakeTLS
          v
Telego public listener :443
          |
          | Middle-End or direct DC route
          v
Telegram DC
```

A WEB carrier request first follows the TLS splice loop:

```text
Telegram Desktop
          |
          | HTTPS or WSS to the public hostname
          v
Telego public listener :443
          |
          | ordinary TLS splice with PROXY protocol v2
          v
Nginx TLS listener :8443
          |
          | decrypted HTTP/1.1 request
          v
Telego WEB listener :8080
```

When the WEB carrier sends an `OPEN` frame, Telego creates one private backend connection:

```text
Telego WEB listener :8080
          |
          | authenticated internal PROXY header and MTProxy stream
          v
Telego MTProxy backend :443 or :9443
          |
          | Middle-End or direct DC route
          v
Telegram DC
```

Thus, one WEB stream enters Telego twice. The public entry terminates the carrier. The private backend entry terminates the MTProxy stream.

An ordinary website request follows the same splice loop before Telego classifies it:

```text
Browser
   |
   v
Telego :443 --> Nginx TLS :8443 --> Telego WEB :8080
                                             |
                                             | status 418
                                             v
                                  Nginx public site :8090
```

Nginx intercepts status `418` and sends the original request to its public-site listener. The response returns through Nginx and the Telego splice.

If a carrier-shaped request fails authentication, Telego returns status `419`. Nginx removes carrier credentials before it sends a safe `GET` to port `8090`.

The managed gateway also supports separate public ports:

```text
Telegram Desktop --> Nginx public TLS :443 --> Telego WEB :8080
                                                    |
                                                    v
                                         Telego MTProxy :9443

MTProxy client :9443 -------------------> Telego MTProxy :9443
```

The WEB backend always uses the private Telego listener. It does not connect through the public MTProxy port mapping.

Unrecognized TLS probes on the MTProxy port still go to Nginx port 8443.

Certificate collection is a separate control path:

```text
Telego certificate fetcher --> Nginx TLS :8444 --> certificate chain
```

Telego uses this path at startup and during certificate refresh. Port `8444` does not receive spliced TLS or website traffic.

Do not publish the WEB listener to the Internet. Nginx is the only permitted client of this listener.

## Requirements

All deployments have these requirements:

- Use a DNS hostname that points to the public host.
- Install a valid TLS certificate for that hostname in the TLS terminator.
- Keep the public WEB endpoint on port 443.
- Send every request for the hostname through the WEB listener.
- Use request buffering for requests to the WEB listener.
- Use HTTP/2 on the public TLS server with `https-lanes`.
- Forward HTTP/1.1 upgrade headers for both WebSocket modes.
- Use HTTP/1.1 between the TLS terminator and the WEB listener.

The shared-port deployments have these additional requirements:

- Keep port 443 assigned to Telego.
- Configure Nginx as the TLS splice target.

The WEB carrier does not terminate TLS. It does not replace Nginx or certificate renewal.

## Configure Telego

The following configuration is for Nginx and Telego on the same host:

```toml
[general]
bind-to = "0.0.0.0:443"

[secrets]
alice = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "proxy.example.com"
cert-host = "127.0.0.1"
cert-port = 8444
splice-host = "127.0.0.1"
splice-port = 8443
splice-proxy-protocol = 2

[web-proxy]
enabled = true
hostname = "proxy.example.com"
carrier = "https-lanes"
bind-to = "127.0.0.1:8080"
trusted-proxy-cidrs = ["127.0.0.1/32"]
```

Replace the hostname and secret. The `hostname` value must match the public TLS certificate.

The `carrier` value selects one of these transports:

| Value | Transport | Compatibility and use |
|-------|-----------|-----------------------|
| `https` | One serialized fetch and long-poll carrier | This value has the least Nginx requirements. It is the default when `carrier` is empty or absent. |
| `https-lanes` | One fetch and long-poll lane for each Telegram stream | Enable public HTTP/2. This value is the conservative recommendation until comparative benchmarks exist. |
| `websocket` | One multiplexed WebSocket for the WEB session | Forward HTTP/1.1 `Upgrade` and `Connection` headers to Telego. |
| `websocket-lanes` | One WebSocket for each Telegram stream | Use this value for the official WebSocket lane option. Forward HTTP/1.1 upgrade headers to Telego. |

If `carrier` is absent, Telego uses serialized `https`. Existing configurations keep their current behavior after an upgrade.

### Telegram Desktop carrier

Current Telegram Desktop manages the WEB carrier. The user does not need to open or keep a browser tab.

Telego supplies the carrier document during the authenticated WEB setup. This document is an internal protocol component.

In `websocket` mode, the carrier opens one same-host `wss` connection. In `websocket-lanes` mode, it opens one connection for each active lane.

The WebSocket target is `wss://<WEB host>/api/v1/ws`. The bridge sends the bearer credential in `Sec-WebSocket-Protocol`.

In `https` mode, the carrier uses serialized fetch requests and long polls. In `https-lanes` mode, it uses independent fetch and long-poll lanes.

Telego derives `127.0.0.1:443` from the wildcard MTProxy bind. A Unix MTProxy bind produces the same Unix socket as the backend.

```toml
[web-proxy]
backend = "127.0.0.1:443"
```

The managed gateway sets this backend to `127.0.0.1:9443`. Docker maps the selected public MTProxy port to that private listener.

Telego adds an authenticated internal PROXY header to every WEB backend stream.

Telego creates a random token at each process start. The token stays in memory and is not part of the configuration.

Telego accepts the internal header only after a constant-time token check.

With `proxy-protocol = false`, a different loopback or Unix peer cannot supply the client IP.

The header contains the client IP that Nginx supplied. Connection and user limits use this IP instead of the loopback address.

If `trusted-proxy-cidrs` is empty, Telego ignores `X-Forwarded-For`. All WEB sessions then use the Nginx peer IP for limits and statistics.

The public `[general].proxy-protocol` behavior does not change.

With `proxy-protocol = true`, legacy mode intentionally trusts PROXY headers from each peer that can reach the MTProxy listener.

Restrict these legacy peers at the network boundary. Direct public connections do not accept the authenticated internal PROXY path.

## Configure Nginx

This example uses four private upstreams or listeners:

- `127.0.0.1:8443` accepts spliced TLS with PROXY protocol v2.
- `127.0.0.1:8444` supplies the certificate without PROXY protocol.
- `127.0.0.1:8080` is the Telego WEB listener.
- `127.0.0.1:8090` is the ordinary public website.

Define the upstreams in the Nginx `http` block:

```nginx
map $http_upgrade $telego_connection_upgrade {
    default upgrade;
    ''      '';
}

upstream telego_web {
    server 127.0.0.1:8080;
    keepalive 64;
}

upstream public_site {
    server 127.0.0.1:8090;
    keepalive 16;
}
```

Create `/etc/nginx/snippets/telego-web-ingress.conf` with this content:

```nginx
proxy_pass http://telego_web;
proxy_http_version 1.1;
proxy_request_buffering on;
proxy_buffering off;
proxy_read_timeout 40s;
proxy_send_timeout 40s;

proxy_intercept_errors on;
recursive_error_pages off;
error_page 418 = @telego_ordinary;
error_page 419 = @telego_sanitized;

proxy_set_header Host $http_host;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header Forwarded "";
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $telego_connection_upgrade;
```

These directives keep the private upstream on HTTP/1.1 and forward WebSocket upgrades to Telego.

The 40-second read timeout is longer than the 25-second WebSocket ping cycle. Telego closes an inactive WebSocket after two missed cycles.

CAUTION: Do not log `$request`, `$request_uri`, `$args`, or `$http_sec_websocket_protocol`.

The bridge capability can appear in query arguments. `Sec-WebSocket-Protocol` contains the WEB session credential.

Use `$request_method $uri $server_protocol` in the access log. This format excludes query arguments.

The WEB listener checks the actual client `Host` value. Never replace `$http_host` with a trusted constant.

Send every TLS request to this listener. This rule prevents WEB bearer and carrier headers from bypassing Telego on other paths.

Add these locations to the public TLS server:

```nginx
server {
    listen 127.0.0.1:8443 ssl proxy_protocol default_server;
    ssl_reject_handshake on;
}

server {
    listen 127.0.0.1:8443 ssl proxy_protocol;
    http2 on;
    server_name proxy.example.com;
    client_max_body_size 16m;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    location / {
        include /etc/nginx/snippets/telego-web-ingress.conf;
    }

    location @telego_ordinary {
        internal;
        proxy_pass http://public_site;
        proxy_http_version 1.1;
        proxy_pass_request_body on;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header Forwarded $http_forwarded;
        proxy_set_header Connection $http_connection;
        proxy_set_header Upgrade $http_upgrade;
    }

    location @telego_sanitized {
        internal;
        proxy_pass http://public_site$uri;
        proxy_http_version 1.1;
        proxy_method GET;
        proxy_pass_request_body off;
        proxy_set_header Host $http_host;
        proxy_set_header Content-Length "";
        proxy_set_header Content-Type "";
        proxy_set_header Transfer-Encoding "";
        proxy_set_header Authorization "";
        proxy_set_header Cookie "";
        proxy_set_header X-Up-Seq "";
        proxy_set_header X-Down-Cursor "";
        proxy_set_header X-Session-Token "";
        proxy_set_header X-Carrier-Mode "";
        proxy_set_header X-Up-Ack "";
        proxy_set_header X-Lane-ID "";
        proxy_set_header Sec-WebSocket-Key "";
        proxy_set_header Sec-WebSocket-Protocol "";
        proxy_set_header Sec-WebSocket-Version "";
        proxy_set_header Sec-WebSocket-Extensions "";
        proxy_set_header X-Forwarded-For "";
        proxy_set_header Forwarded "";
        proxy_set_header Connection "";
        proxy_set_header Upgrade "";
    }
}
```

The `http2 on;` directive requires Nginx 1.25.1 or later. With an older Nginx version, add `http2` to the `listen` directive.

The private Nginx connection to Telego stays on HTTP/1.1. Only the public TLS connection uses HTTP/2.

Set `client_max_body_size` to the public-site upload limit. The value must be at least `2m`.

Do not use `2m` as a WEB-only hard limit. Telego enforces its 2 MiB carrier limit after Nginx forwards the request.

Add a second TLS listener for Telego certificate collection:

```nginx
server {
    listen 127.0.0.1:8444 ssl default_server;
    ssl_reject_handshake on;
}

server {
    listen 127.0.0.1:8444 ssl;
    server_name proxy.example.com;

    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    location / {
        return 204;
    }
}
```

Keep the existing port 80 server for ACME challenges and HTTPS redirects. Keep the existing certificate-renewal job.

### Fallback contract

Telego uses status 418 for ordinary website traffic. The `@telego_ordinary` location preserves these request properties:

- The original method.
- The complete request URI and query.
- The buffered request body.
- The actual `Host` value from `$http_host`.
- Cookies and authorization.
- The original `Forwarded`, `X-Forwarded-For`, `Connection`, and `Upgrade` headers.
- All other site request headers.

Telego uses status 419 for a carrier-shaped request that did not authenticate. The `@telego_sanitized` location changes the request before public-site delivery:

- It changes the method to `GET`.
- It removes the query and request body.
- It preserves the actual `Host` value from `$http_host`.
- It removes WEB credentials and sequence headers.
- It removes `Cookie` and `Authorization`.
- It removes `Forwarded` and `X-Forwarded-For`.
- It removes `Connection` and `Upgrade`.
- It removes all `Sec-WebSocket-*` handshake headers.

The WEB listener adds `X-Telego-Fallback` to each sentinel response. Nginx consumes both sentinel statuses and never sends them to the public client.

Do not replace the named 418 location with a URI error page. A URI error page changes non-GET methods to `GET`.

## Check the configuration

Make sure that the Nginx configuration is valid before you restart the services:

```bash
nginx -t
```

If systemd manages Telego, restart Telego after `nginx -t` succeeds. Telego rejects an invalid WEB configuration during startup.

Then reload Nginx. Make sure that the Telego log contains `WEB proxy started`.

For a new secret, use `--web-host` to print the MTProxy and WEB links:

```bash
telego generate proxy.example.com --web-host proxy.example.com
```

The positional hostname is the FakeTLS mask hostname. The `--web-host` value is the public WEB proxy hostname.

The `--web-host` value must match `[web-proxy].hostname` and the TLS certificate in Nginx.

For configured secrets, add `-l` to the Telego service command. This option prints the links during startup:

```bash
telego run -c /etc/telego/config.toml -l
```

The output contains these link forms:

```text
tg://webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
https://t.me/webproxy?server=proxy.example.com&secret=0123456789abcdef0123456789abcdef
tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
https://t.me/webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef
```

Telego derives the plain and `dd` WEB credentials from each existing base secret. Do not add a second `desktop-dd` secret.

## Docker

### Managed gateway

Use the managed gateway for a new VPS. The gateway automates the first certificate, renewal, configuration generation, and service startup.

```bash
curl -fsSL https://raw.githubusercontent.com/Scratch-net/telego/main/examples/gateway/install.sh \
  | sh -s -- --domain proxy.example.com --email admin@example.com
```

The installer creates `telego-gateway/` in the current directory. It stores all persistent files under `telego-gateway/state/`.

To keep WEB on port 443 and publish MTProxy on port 9443, add `--mtproxy-port 9443`.

To run the managed gateway without WEB, add `--no-web`. Nginx still provides the certificate and ordinary probe site.

Read the [gateway README](../examples/gateway/README.md) for the complete procedure.

### Manual Compose example

The complete example is in [`examples/web-proxy`](../examples/web-proxy). It uses a private `172.28.0.0/24` bridge network.

The example has these network properties:

- Only Telego port 443 and Nginx port 80 are published.
- Nginx listens on container ports 8443 and 8444, not its loopback interface.
- Telego uses `nginx:8443` for splice traffic.
- Telego uses the `proxy.example.com:8444` Docker alias for certificate collection and the correct TLS SNI.
- Nginx uses Telego's fixed private address `172.28.0.3:8080` for WEB HTTP traffic.
- Telego uses its own `127.0.0.1:443` listener for WEB backend streams.
- Telego trusts only the fixed Nginx address `172.28.0.2/32` for `X-Forwarded-For`.
- Port 8080 stays private and is not published on the VPS.
- Nginx and Telego use the Docker `local` log driver. Each service keeps three 10 MB log files.

Complete these actions before the first start:

1. Replace every `proxy.example.com` value in the example.
2. Replace the example secret in `telego.toml`.
3. Update the certificate paths in `nginx/nginx.conf`.
4. Make sure that subnet `172.28.0.0/24` is free on the Docker host.
5. Make sure that no service uses public port 80.
6. Make sure that the public DNS record points to this host.
7. Make sure that the internet can reach port 80 on this host.

Generate a new secret and all link types through the Telego image:

```bash
docker run --rm scratchnet/telego:latest \
  generate proxy.example.com --web-host proxy.example.com
```

Put the reported base secret in `telego.toml`. Telego derives both WEB credentials from this base secret.

Create the certificate directories:

```bash
cd examples/web-proxy
mkdir -p certbot/conf certbot/lib certbot/www
```

Before you start Nginx, issue the first certificate with the standalone challenge:

```bash
docker run --rm -p 80:80 \
  -v "$PWD/certbot/conf:/etc/letsencrypt" \
  -v "$PWD/certbot/lib:/var/lib/letsencrypt" \
  certbot/certbot certonly --standalone --non-interactive --agree-tos \
  --email admin@example.com -d proxy.example.com
```

Replace the email address and hostname in this command. The command must finish before Nginx starts.

Run these commands in order:

```bash
cd examples/web-proxy
docker compose config --quiet
docker compose up -d nginx
docker compose exec -T nginx nginx -t
docker compose up -d
```

The Nginx health check uses the private website listener. Compose starts Telego only after this health check succeeds.

Nginx can start before Telego. TLS requests return an upstream error until the Telego WEB listener starts.

Inspect the service state and logs:

```bash
docker compose ps
docker compose logs telego
```

After you change `telego.toml`, recreate the Telego container:

```bash
docker compose up -d --force-recreate telego
```

Nginx serves `/.well-known/acme-challenge/` from `certbot/www`. The renewal script uses this webroot while Nginx stays online.

Run one real renewal check:

```bash
./renew-certificate.sh
```

The script runs `certbot renew`. If Certbot renews a certificate, the script runs `nginx -t` and reloads Nginx.

If Nginx validation or reload fails, the renewal marker stays in place. The next timer run tries the reload again.

The example includes a systemd service and timer. These files use `/opt/telego/examples/web-proxy` as the installation directory.

If your installation uses a different directory, edit both paths in `systemd/telego-cert-renew.service`.

Install and start the timer:

```bash
sudo install -m 0644 systemd/telego-cert-renew.service /etc/systemd/system/
sudo install -m 0644 systemd/telego-cert-renew.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now telego-cert-renew.timer
sudo systemctl start telego-cert-renew.service
```

For rollback, restore the previous Nginx website route first. Then run these commands:

```bash
docker compose exec -T nginx nginx -t
docker compose exec -T nginx nginx -s reload
```

After Nginx no longer sends requests to port 8080, set `enabled = false`. Then run this command:

```bash
docker compose up -d --force-recreate telego
```

## Existing installations

An existing MTProxy installation needs no secret migration. Complete these actions:

1. Add the `[web-proxy]` section with `carrier = "https-lanes"`.
2. Enable HTTP/2 on the public Nginx TLS server.
3. Add the Nginx map, WEB ingress, and fallback locations.
4. Restart Telego.
5. Reload Nginx.
6. Add one of the printed WEB links to Telegram Desktop.

The existing `ee` and `dd` MTProxy links continue to use the public gnet listener. WEB configuration changes require a Telego restart.

## Rollback

First, restore the previous Nginx website location. Then validate and reload Nginx:

```bash
nginx -t
nginx -s reload
```

Set `enabled = false` and restart Telego. This action does not change existing MTProxy secrets or links.

If you migrate from `tproxy-server`, keep its old Nginx upstream during the first test period. Restore that upstream to roll back.

## Current scope

The native implementation supports `https`, `https-lanes`, `websocket`, and `websocket-lanes`.

The default remains `https`. `https-lanes` remains the conservative recommendation until comparative benchmarks exist.

`websocket-lanes` is the official WebSocket lane option. This documentation makes no speed claim for either WebSocket mode.
