# WEB bot transfer check

This harness uploads a random file to Telegram and downloads it through the deployed WEB browser bridge.
It compares the byte count and SHA-256 hash, then deletes its WEB session.
The default file size is 1 MiB.

Telethon connects to a local TCP adapter.
The adapter forwards MTProxy frames through a local Chromium page and the deployed bridge iframe.
The bridge uses the carrier from the server configuration.
The harness stops if the carrier changes or the bridge reconnects during the transfer.

## Install

Python 3.11 or newer and Chromium system libraries are required.
Run these commands from the repository root:

```sh
rtk proxy python3 -m venv .local/web-transfer/venv
rtk proxy .local/web-transfer/venv/bin/pip install -r tools/web-transfer/requirements.txt
rtk proxy env PLAYWRIGHT_BROWSERS_PATH="$PWD/.local/web-transfer/browsers" \
  .local/web-transfer/venv/bin/playwright install chromium
```

## Prepare the endpoint

The endpoint file contains a private WEB URL and MTProxy secret.
The `.local/` directory is excluded from Git and Docker builds.

For a local Telego configuration, save the endpoint with restricted permissions:

```sh
rtk proxy bash -c '
  umask 077
  python3 tools/web-transfer/export_endpoint.py /path/to/telego/config.toml \
    > .local/web-transfer/endpoint.json
'
```

For a remote trial, run the exporter through SSH:

```sh
rtk proxy bash -c '
  umask 077
  ssh user@trial-host python3 - /path/to/trial/config.toml \
    < tools/web-transfer/export_endpoint.py > .local/web-transfer/endpoint.json
'
```

The exporter selects the first named secret in the configuration.
It includes the configured custom path and computes the corresponding bridge capability.
It does not change the server configuration.

## Run

The credentials file uses the existing VKDL TOML fields:
`bot_token`, `mtproto.api_id`, `mtproto.api_hash`, and `allowed.admin`.
The configured admin must already have a conversation with the bot.

```sh
rtk proxy .local/web-transfer/venv/bin/python tools/web-transfer/run.py \
  --credentials /path/to/vkdl/config.toml \
  --endpoint .local/web-transfer/endpoint.json
```

The harness reads the credentials file without changing it.
It stores its own Telethon session and sanitized result in `.local/web-transfer/`.
It does not use or change the VKDL session.
Run one process per state directory.

For a larger transfer, add `--mib 8` (maximum 64).
For a visible bot message, add `--send`.
This flag sends the verified file to the configured admin after the download succeeds.
The default run does not send a message.

The transfer timeout defaults to 120 seconds.
Use `--timeout` to select 30–300 seconds.
Cleanup can take additional time after a timeout.
The harness reports Telegram flood waits and stops without retrying the transfer.

## Results

Exit status zero means that authentication, upload, download, hash comparison, and WEB session deletion succeeded.
The JSON result includes transfer times, byte counts, observed carrier, WebSocket count, and session counts.
The result omits credentials, private URLs, session tokens, and account identifiers.

The transfer times exclude authentication and browser startup.
Telethon performs its own connection checks during startup.
These timings describe one bot transfer from the test host.
They do not measure desktop ping or establish a throughput comparison between carriers.

The browser ignores explicit HTTP proxy settings.
The host network can still pass traffic through a VPN or TUN interface.
