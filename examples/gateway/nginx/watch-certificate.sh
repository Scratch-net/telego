#!/bin/sh
set -eu

marker=/var/run/telego-gateway/certificate-renewed

(
    while sleep 60; do
        if [ ! -f "$marker" ]; then
            continue
        fi

        if nginx -t; then
            nginx -s reload
            rm -f "$marker"
        fi
    done
) &
