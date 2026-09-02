#!/bin/sh
set -eu

repository_url=https://github.com/Scratch-net/telego
source_ref=${TELEGO_GATEWAY_REF:-main}
archive_url=${TELEGO_GATEWAY_ARCHIVE_URL:-$repository_url/archive/$source_ref.tar.gz}
install_root=${TELEGO_GATEWAY_DIR:-$PWD/telego-gateway}
download_root=

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

cleanup() {
    if [ -n "$download_root" ] && [ -d "$download_root" ]; then
        rm -rf -- "$download_root"
    fi
}

install_file() {
    source_file=$1
    destination_file=$2
    destination_mode=$3
    destination_temp=$(mktemp "$destination_file.XXXXXX") || fail "cannot create a temporary installation file"

    if ! cp "$source_file" "$destination_temp"; then
        rm -f -- "$destination_temp"
        fail "cannot copy $source_file"
    fi
    chmod "$destination_mode" "$destination_temp"
    mv -f "$destination_temp" "$destination_file"
}

case "$source_ref" in
    '' | *[!A-Za-z0-9._-]*) fail "TELEGO_GATEWAY_REF contains an unsupported character" ;;
esac
if [ -z "$install_root" ] || [ "$install_root" = / ]; then
    fail "TELEGO_GATEWAY_DIR must identify a gateway directory"
fi

for command_name in curl tar mktemp find cp chmod mv; do
    command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is not installed"
done

download_root=$(mktemp -d "${TMPDIR:-/tmp}/telego-gateway-install.XXXXXX")
trap cleanup 0 1 2 15

archive_file=$download_root/source.tar.gz
extract_root=$download_root/source
mkdir -p "$extract_root"

printf 'Downloading Telego gateway source %s.\n' "$source_ref"
curl --fail --show-error --silent --location --retry 3 \
    --output "$archive_file" "$archive_url"
tar -xzf "$archive_file" -C "$extract_root"

gateway_source=$(find "$extract_root" -type d -path '*/examples/gateway' -print -quit)
if [ -z "$gateway_source" ]; then
    fail "the downloaded archive does not contain examples/gateway"
fi

for required_file in \
    install.sh \
    setup.sh \
    compose.yaml \
    README.md \
    .gitignore \
    templates/telego.toml \
    templates/mtproxy.toml \
    templates/nginx.conf \
    templates/nginx-web-server.conf \
    templates/nginx-site-server.conf \
    templates/index.html \
    nginx/watch-certificate.sh
do
    if [ ! -f "$gateway_source/$required_file" ]; then
        fail "the downloaded gateway package does not contain $required_file"
    fi
done

mkdir -p "$install_root/templates" "$install_root/nginx"
printf 'Installing the setup program, Docker Compose file, templates, and documentation.\n'
install_file "$gateway_source/install.sh" "$install_root/install.sh" 755
install_file "$gateway_source/setup.sh" "$install_root/setup.sh" 755
install_file "$gateway_source/compose.yaml" "$install_root/compose.yaml" 644
install_file "$gateway_source/README.md" "$install_root/README.md" 644
install_file "$gateway_source/.gitignore" "$install_root/.gitignore" 644
install_file "$gateway_source/templates/telego.toml" "$install_root/templates/telego.toml" 644
install_file "$gateway_source/templates/mtproxy.toml" "$install_root/templates/mtproxy.toml" 644
install_file "$gateway_source/templates/nginx.conf" "$install_root/templates/nginx.conf" 644
install_file "$gateway_source/templates/nginx-web-server.conf" "$install_root/templates/nginx-web-server.conf" 644
install_file "$gateway_source/templates/nginx-site-server.conf" "$install_root/templates/nginx-site-server.conf" 644
install_file "$gateway_source/templates/index.html" "$install_root/templates/index.html" 644
install_file "$gateway_source/nginx/watch-certificate.sh" "$install_root/nginx/watch-certificate.sh" 755

cleanup
download_root=
trap - 0 1 2 15

printf 'Gateway program files are ready in %s.\n' "$install_root"
if [ -d "$install_root/state" ]; then
    printf 'Existing persistent state remains in %s/state.\n' "$install_root"
else
    printf 'The setup will create persistent state in %s/state.\n' "$install_root"
fi
printf 'Starting gateway setup.\n'
cd "$install_root"
./setup.sh "$@"
