#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

docker compose run --rm certbot renew --webroot -w /var/www/certbot --quiet
docker compose exec -T nginx nginx -t
docker compose exec -T nginx nginx -s reload
