#!/usr/bin/env python3
"""Read a Telego config and emit private endpoint JSON. Redirect stdout to a file."""

import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tomllib


def endpoint(config):
    web = config['web-proxy']
    if not web.get('enabled'):
        raise ValueError('WEB is disabled')
    host = web['hostname']
    path = web.get('base-path', '')
    raw = bytes.fromhex(next(iter(config['secrets'].values())))
    if len(raw) != 16:
        raise ValueError('expected a 16-byte secret')
    context = 'tdesktop-web-proxy-bridge-v1\n' + host
    if path:
        context = 'tdesktop-web-proxy-bridge-v2\n' + host + '\n' + path
    capability = base64.urlsafe_b64encode(hmac.new(raw, context.encode(), hashlib.sha256).digest()).decode().rstrip('=')
    prefix = '/' + path + '/' if path else '/'
    return {'url': 'https://' + host + prefix + '?bridge=' + capability,
            'raw_secret': raw.hex(), 'carrier': web.get('carrier') or 'https'}


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.stdout.isatty():
        raise SystemExit('Redirect output to a private file and supply one Telego config path.')
    try:
        value = endpoint(tomllib.loads(Path(sys.argv[1]).read_text()))
    except Exception:
        raise SystemExit('Endpoint export failed; no configuration values were printed.')
    print(json.dumps(value))
