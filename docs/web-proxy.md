# Native Telegram WEB proxy

Telego includes an optional WEB proxy for Telegram Desktop. The first release supports the serialized `https` carrier.

The WEB listener uses gnet and accepts private HTTP/1.1 traffic. Nginx keeps the real TLS certificate and the public website.

Existing MTProxy configurations do not start this listener. You must set `[web-proxy].enabled = true` to enable it.

## Traffic flow

```text
Internet :443
    |
    v
Telego MTProxy :443
    |-- authenticated MTProxy ----------> Telegram DC
    |
    `-- ordinary TLS --------------------> Nginx TLS :8443
                                               |
                                               `-- all requests --> Telego WEB :8080
                                                                      |
                                                                      |-- 418 --> public site
                                                                      `-- 419 --> sanitized public request

Telego WEB stream OPEN --> local Telego MTProxy TCP or Unix socket --> Telegram DC
```

Do not publish the WEB listener to the Internet. Nginx is the only permitted client of this listener.

## Requirements

- Use a DNS hostname that points to the VPS.
- Install a valid TLS certificate for that hostname in Nginx.
- Keep port 443 assigned to Telego.
- Configure Nginx as the TLS splice target.
- Use Nginx request buffering for all requests to the WEB listener.
- Use HTTP/1.1 between Nginx and the WEB listener.

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
bind-to = "127.0.0.1:8080"
trusted-proxy-cidrs = ["127.0.0.1/32"]
```

Replace the hostname and secret. The `hostname` value must match the public TLS certificate.

Telego derives `127.0.0.1:443` from the wildcard MTProxy bind. A Unix MTProxy bind produces the same Unix socket as the backend.

```toml
[web-proxy]
backend = "127.0.0.1:443"
```

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
proxy_set_header Connection "";
proxy_set_header Upgrade "";
```

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
        proxy_set_header X-Forwarded-For "";
        proxy_set_header Forwarded "";
        proxy_set_header Connection "";
        proxy_set_header Upgrade "";
    }
}
```

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

The WEB listener adds `X-Telego-Fallback` to each sentinel response. Nginx consumes both sentinel statuses and never sends them to the public client.

Do not replace the named 418 location with a URI error page. A URI error page changes non-GET methods to `GET`.

## Check the configuration

Make sure that the Nginx configuration is valid before you restart the services:

```bash
nginx -t
```

If systemd manages Telego, restart Telego after `nginx -t` succeeds. Telego rejects an invalid WEB configuration during startup.

Then reload Nginx. Make sure that the Telego log contains `WEB proxy started`.

Add `-l` to the Telego service command to print both WEB links during startup:

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

Complete these actions before the first start:

1. Replace every `proxy.example.com` value in the example.
2. Replace the example secret in `telego.toml`.
3. Update the certificate paths in `nginx/nginx.conf`.
4. Make sure that subnet `172.28.0.0/24` is free on the Docker host.
5. Make sure that no service uses public port 80.
6. Make sure that the public DNS record points to this host.
7. Make sure that the internet can reach port 80 on this host.

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

The script runs `certbot renew`. If renewal succeeds, it runs `nginx -t` and reloads Nginx.

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

1. Add the `[web-proxy]` section.
2. Add the Nginx WEB ingress and fallback locations.
3. Restart Telego.
4. Reload Nginx.
5. Add one of the printed WEB links to Telegram Desktop.

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

The native implementation supports the `https` carrier. It does not support `https-lanes`, `websocket`, or `websocket-lanes`.
