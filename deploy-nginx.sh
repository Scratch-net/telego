#!/bin/bash
set -euo pipefail

# --- Defaults ---
DOMAIN=""
EMAIL=""
TELEGO_DIR="$HOME/telego"
TELEGO_CONFIG="config.toml"
PORT=443

# --- Parse arguments ---
usage() {
    echo "Usage: $0 -d <domain> -e <email> [options]"
    echo ""
    echo "Required:"
    echo "  -d    Domain name (e.g., example.mooo.com)"
    echo "  -e    Email for Let's Encrypt"
    echo ""
    echo "Optional:"
    echo "  -D    Telego directory (default: ~/telego)"
    echo "  -c    Telego config filename (default: config.toml)"
    echo "  -p    Telego port (default: 443)"
    echo ""
    echo "Example: $0 -d myproxy.example.com -e admin@example.com"
    echo "         $0 -d myproxy.example.com -e admin@example.com -p 8443"
    exit 1
}

while getopts "d:e:D:c:p:" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        e) EMAIL="$OPTARG" ;;
        D) TELEGO_DIR="$OPTARG" ;;
        c) TELEGO_CONFIG="$OPTARG" ;;
        p) PORT="$OPTARG" ;;
        *) usage ;;
    esac
done

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
    usage
fi

# --- Prereq checks ---
command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running or current user has no access"; exit 1; }

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Invalid port: $PORT"
    exit 1
fi

CONFIG_PATH="$TELEGO_DIR/$TELEGO_CONFIG"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "=== Config not found, creating $CONFIG_PATH ==="
    mkdir -p "$TELEGO_DIR"
    cat > "$CONFIG_PATH" <<TOML
[general]
bind-to = "0.0.0.0:443"
log-level = "info"

[secrets]
# Add at least one user. Generate a secret:
#   docker run --rm scratchnet/telego:latest generate $DOMAIN
# Then add it here:
# user1 = "paste_secret_here"

[tls-fronting]
mask-host = "$DOMAIN"
cert-host = "telego-nginx"
cert-port = 8443
splice-host = "telego-nginx"
splice-port = 8443

[performance]
prefer-ip = "prefer-ipv4"
idle-timeout = "5m"
num-event-loops = 0
TOML
    echo ""
    echo "Config created at: $CONFIG_PATH"
    echo "Add at least one secret before running again:"
    echo ""
    echo "  docker run --rm scratchnet/telego:latest generate $DOMAIN"
    echo ""
    echo "Paste the hex string into [secrets] section, then re-run this script."
    exit 0
fi

echo "=== Setting up nginx + certbot for $DOMAIN (port $PORT) ==="

# Create directory structure
mkdir -p "$TELEGO_DIR/nginx/html"
mkdir -p "$TELEGO_DIR/certbot/conf"
mkdir -p "$TELEGO_DIR/certbot/www"

# Write nginx config
cat > "$TELEGO_DIR/nginx/default.conf" <<NGINX
server {
    listen 80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 8443 ssl;
    server_name $DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    location / {
        root /var/www/html;
        index index.html;
    }
}
NGINX

# Write decoy page
cat > "$TELEGO_DIR/nginx/html/index.html" <<HTML
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>$DOMAIN</title></head>
<body><h1>Welcome</h1><p>Nothing to see here.</p></body>
</html>
HTML

# --- Step 1: Stop old containers (frees ports for certbot) ---
echo "=== Stopping old containers ==="
docker stop telego 2>/dev/null || true
docker rm telego 2>/dev/null || true
docker stop telego-nginx 2>/dev/null || true
docker rm telego-nginx 2>/dev/null || true

# Create docker network (ignore if exists)
docker network create telego-net 2>/dev/null || true

# --- Step 2: Get Let's Encrypt cert (standalone, needs port 80 free) ---
if [ ! -d "$TELEGO_DIR/certbot/conf/live/$DOMAIN" ]; then
    echo "=== Getting Let's Encrypt certificate ==="
    docker run --rm \
        -p 80:80 \
        -v "$TELEGO_DIR/certbot/conf:/etc/letsencrypt" \
        -v "$TELEGO_DIR/certbot/www:/var/www/certbot" \
        certbot/certbot certonly --standalone \
        -d "$DOMAIN" --agree-tos -m "$EMAIL" --non-interactive
else
    echo "=== Certificate already exists, skipping ==="
fi

# --- Step 3: Start nginx ---
echo "=== Starting nginx ==="
docker run -d \
    --name telego-nginx \
    --network telego-net \
    -p 80:80 \
    -v "$TELEGO_DIR/nginx/default.conf:/etc/nginx/conf.d/default.conf:ro" \
    -v "$TELEGO_DIR/nginx/html:/var/www/html:ro" \
    -v "$TELEGO_DIR/certbot/conf:/etc/letsencrypt:ro" \
    -v "$TELEGO_DIR/certbot/www:/var/www/certbot:ro" \
    --log-driver local \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    --restart unless-stopped \
    nginx:alpine

# --- Step 4: Start telego ---
echo "=== Starting telego ==="
docker pull scratchnet/telego:latest
docker run -d \
    --name telego \
    --network telego-net \
    -p "$PORT:443" \
    --cap-add=NET_BIND_SERVICE \
    -v "$CONFIG_PATH:/config.toml:ro" \
    --log-driver local \
    --log-opt max-size=10m \
    --log-opt max-file=3 \
    --restart unless-stopped \
    scratchnet/telego:latest

# --- Step 5: Add cert renewal cron ---
# Certbot sets a marker only after it renews a certificate. The marker stays
# in place if Nginx validation or reload fails, so the next run tries again.
RENEW_MARKER="$TELEGO_DIR/certbot/conf/.telego-renewed"
CRON_CMD="0 3 * * * docker run --rm -v \"$TELEGO_DIR/certbot/conf:/etc/letsencrypt\" -v \"$TELEGO_DIR/certbot/www:/var/www/certbot\" certbot/certbot renew --webroot -w /var/www/certbot --quiet --deploy-hook \"touch /etc/letsencrypt/.telego-renewed\" && if [ -f \"$RENEW_MARKER\" ]; then docker exec telego-nginx nginx -t && docker exec telego-nginx nginx -s reload && rm -f \"$RENEW_MARKER\"; fi # telego-cert-renew"
(crontab -l 2>/dev/null | grep -v -E 'docker stop telego-nginx.*certbot/certbot renew|# telego-cert-renew$' || true; echo "$CRON_CMD") | crontab -
echo "=== Installed cert renewal cron job ==="

echo ""
echo "=== Done ==="
echo "nginx:  port 80  (ACME + redirect)"
echo "telego: port $PORT (MTProxy)"
echo ""
echo "Make sure your telego config has:"
echo "  [tls-fronting]"
echo "  mask-host = \"$DOMAIN\""
echo "  cert-host = \"telego-nginx\""
echo "  cert-port = 8443"
echo "  splice-host = \"telego-nginx\""
echo "  splice-port = 8443"
echo ""
echo "Generate a secret: docker run --rm scratchnet/telego:latest generate $DOMAIN"
echo ""
echo "Verify: docker ps"
echo "Logs:   docker logs telego"
echo "        docker logs telego-nginx"
