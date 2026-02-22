#!/bin/bash
# Run telego locally for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Configuration
PORT="${PORT:-14434}"
MASK_HOST="${MASK_HOST:-www.google.com}"
SECRET_FILE="/tmp/telego-secret.txt"
CONFIG_FILE="/tmp/telego-local.toml"

# Generate secret if not exists
if [ ! -f "$SECRET_FILE" ]; then
    echo "Generating new secret..."
    cd "$PROJECT_DIR"
    go run ./cmd/telego generate "$MASK_HOST" | grep "Secret:" | awk '{print $2}' > "$SECRET_FILE"
fi

SECRET=$(cat "$SECRET_FILE")
echo "Using secret: $SECRET"

# Create config
cat > "$CONFIG_FILE" << EOF
secret = "$SECRET"
bind-to = "127.0.0.1:$PORT"

[tls-fronting]
mask-host = "$MASK_HOST"
mask-port = 443
fetch-real-cert = false
splice-unrecognized = true

[performance]
concurrency = 1024
EOF

echo "Config written to $CONFIG_FILE"
echo ""
echo "Starting telego on 127.0.0.1:$PORT"
echo "Mask host: $MASK_HOST"
echo ""
echo "To connect from Telegram client, use:"
echo "  tg://proxy?server=127.0.0.1&port=$PORT&secret=$SECRET"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Build and run
cd "$PROJECT_DIR"
go build -o /tmp/telego ./cmd/telego
exec /tmp/telego run -c "$CONFIG_FILE"
