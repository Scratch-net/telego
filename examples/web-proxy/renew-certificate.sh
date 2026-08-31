#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

renewed_marker="$script_dir/certbot/lib/.telego-renewed"

docker compose run --rm certbot renew --webroot \
  -w /var/www/certbot --quiet \
  --deploy-hook "touch /var/lib/letsencrypt/.telego-renewed"

if [ -f "$renewed_marker" ]; then
  docker compose exec -T nginx nginx -t
  docker compose exec -T nginx nginx -s reload
  rm -f "$renewed_marker"
fi
