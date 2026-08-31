#!/bin/sh
set -eu

gateway_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
state_root="$gateway_root/state"
domain=
email=
carrier=https-lanes
telego_image=scratchnet/telego:latest

usage() {
    printf '%s\n' \
        "Usage: ./setup.sh --domain HOSTNAME --email ADDRESS [options]" \
        "" \
        "Options:" \
        "  --carrier MODE   https, https-lanes, websocket, or websocket-lanes" \
        "  --image IMAGE    Telego image (default: scratchnet/telego:latest)" \
        "  --help           Show this help"
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

need_value() {
    if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        fail "$1 requires a value"
    fi
}

valid_hostname() {
    gateway_hostname=$1
    if [ -z "$gateway_hostname" ] || [ "${#gateway_hostname}" -gt 253 ]; then
        return 1
    fi
    case "$gateway_hostname" in
        *[!A-Za-z0-9.-]* | .* | *. | *..*) return 1 ;;
    esac

    gateway_old_ifs=$IFS
    IFS=.
    set -- $gateway_hostname
    IFS=$gateway_old_ifs
    for gateway_label do
        if [ -z "$gateway_label" ] || [ "${#gateway_label}" -gt 63 ]; then
            return 1
        fi
        case "$gateway_label" in
            -* | *-) return 1 ;;
        esac
    done
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --domain)
            need_value "$@"
            domain=$2
            shift 2
            ;;
        --email)
            need_value "$@"
            email=$2
            shift 2
            ;;
        --carrier)
            need_value "$@"
            carrier=$2
            shift 2
            ;;
        --image)
            need_value "$@"
            telego_image=$2
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown option: $1"
            ;;
    esac
done

if ! valid_hostname "$domain"; then
    fail "--domain must be a valid DNS hostname"
fi
case "$email" in
    *@*.*) ;;
    *) fail "--email must be a valid email address" ;;
esac
case "$email" in
    *[!A-Za-z0-9._+@-]*) fail "--email contains an unsupported character" ;;
esac
case "$carrier" in
    https | https-lanes | websocket | websocket-lanes) ;;
    *) fail "--carrier has an unsupported value" ;;
esac
case "$telego_image" in
    '' | *[!A-Za-z0-9._/:@-]*) fail "--image contains an unsupported character" ;;
esac
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "Docker Compose is not available"
docker info >/dev/null 2>&1 || fail "the Docker daemon is not available"

umask 077
mkdir -p \
    "$state_root/telego" \
    "$state_root/nginx" \
    "$state_root/site" \
    "$state_root/letsencrypt/conf" \
    "$state_root/letsencrypt/lib" \
    "$state_root/letsencrypt/www" \
    "$state_root/runtime"

domain_file="$state_root/domain"
carrier_file="$state_root/carrier"
config_file="$state_root/telego/config.toml"

if [ -f "$domain_file" ]; then
    IFS= read -r configured_domain < "$domain_file"
    if [ "$configured_domain" != "$domain" ]; then
        fail "state belongs to domain $configured_domain"
    fi
fi
if [ -f "$carrier_file" ]; then
    IFS= read -r configured_carrier < "$carrier_file"
    if [ "$configured_carrier" != "$carrier" ]; then
        fail "state uses carrier $configured_carrier"
    fi
fi

if [ ! -f "$config_file" ]; then
    gateway_secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    if [ "${#gateway_secret}" -ne 32 ]; then
        fail "secret generation failed"
    fi

    config_temp=$(mktemp "$state_root/telego/config.toml.XXXXXX")
    nginx_temp=$(mktemp "$state_root/nginx/nginx.conf.XXXXXX")

    sed \
        -e "s|__DOMAIN__|$domain|g" \
        -e "s|__SECRET__|$gateway_secret|g" \
        -e "s|__CARRIER__|$carrier|g" \
        "$gateway_root/templates/telego.toml" > "$config_temp"
    sed \
        -e "s|__DOMAIN__|$domain|g" \
        "$gateway_root/templates/nginx.conf" > "$nginx_temp"

    mv "$config_temp" "$config_file"
    mv "$nginx_temp" "$state_root/nginx/nginx.conf"
    cp "$gateway_root/templates/index.html" "$state_root/site/index.html"
    printf '%s\n' "$domain" > "$domain_file"
    printf '%s\n' "$carrier" > "$carrier_file"
    printf '%s\n' \
        "tg://webproxy?server=$domain&secret=$gateway_secret" \
        "https://t.me/webproxy?server=$domain&secret=$gateway_secret" \
        "tg://webproxy?server=$domain&secret=dd$gateway_secret" \
        "https://t.me/webproxy?server=$domain&secret=dd$gateway_secret" \
        > "$state_root/links.txt"

    chmod 600 "$config_file" "$state_root/links.txt"
    chmod 644 \
        "$state_root/nginx/nginx.conf" \
        "$state_root/site/index.html"
fi

cp "$gateway_root/nginx/watch-certificate.sh" "$state_root/nginx/watch-certificate.sh"
chmod 755 \
    "$state_root/site" \
    "$state_root/nginx/watch-certificate.sh"

printf '%s\n' "TELEGO_IMAGE=$telego_image" > "$gateway_root/.env"

cd "$gateway_root"
docker compose config --quiet

certificate_root="$state_root/letsencrypt/conf/live/$domain"
if [ ! -s "$certificate_root/fullchain.pem" ] || [ ! -s "$certificate_root/privkey.pem" ]; then
    printf 'Requesting the first certificate for %s.\n' "$domain"
    docker compose --profile setup run --rm -p 80:80 certbot-init \
        certonly --standalone --non-interactive --agree-tos \
        --email "$email" -d "$domain"
fi

docker compose up -d nginx
docker compose exec -T nginx nginx -t
docker compose up -d
docker compose ps

printf '\nWEB proxy links:\n'
sed 's/^/  /' "$state_root/links.txt"
printf '\nState directory: %s\n' "$state_root"
printf 'Logs: docker compose logs -f nginx telego certbot\n'
