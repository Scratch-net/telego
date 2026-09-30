#!/usr/bin/env python3
"""Verify a bot file round trip through the deployed WEB browser bridge."""

import argparse
import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import struct
import time
import tomllib
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from playwright.async_api import async_playwright
from telethon import TelegramClient, errors, functions, types
from telethon.network.connection import tcpmtproxy


ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local' / 'web-transfer'
WINDOW = 4 << 20
MAX_PAYLOAD = 1 << 20


def frame(kind, stream=0, payload=b''):
    return struct.pack('!II', kind << 24 | stream, len(payload)) + payload


def frames(data):
    offset = 0
    count = 0
    while offset < len(data):
        if len(data) - offset < 8 or count >= 4096:
            raise ValueError('invalid frame batch')
        tag, size = struct.unpack_from('!II', data, offset)
        offset += 8
        if size > MAX_PAYLOAD or size > len(data) - offset:
            raise ValueError('invalid frame size')
        yield tag >> 24, tag & 0xffffff, data[offset:offset + size]
        offset += size
        count += 1
    if not count:
        raise ValueError('empty frame batch')


class NativeCTR:
    def __init__(self, key, iv):
        self.worker = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    def encrypt(self, data):
        return self.worker.update(data)


def use_native_ctr():
    # Verify chunked byte equivalence before replacing Telethon's slow CTR.
    from telethon.crypto import AESModeCTR
    key, iv = bytes(range(32)), bytes(range(16))
    native, reference = NativeCTR(key, iv), AESModeCTR(key, iv)
    for size in (1, 15, 33, 1024):
        data = bytes(i % 251 for i in range(size))
        if native.encrypt(data) != reference.encrypt(data):
            raise RuntimeError('CTR equivalence failed')
    tcpmtproxy.AESModeCTR = NativeCTR


class BrowserBridge:
    def __init__(self, endpoint):
        self.endpoint = endpoint
        parsed = urlsplit(endpoint['url'])
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
                parsed.fragment or not parsed.path.endswith('/')):
            raise ValueError('endpoint must be an HTTPS bridge URL')
        if len(bytes.fromhex(endpoint['raw_secret'])) != 16:
            raise ValueError('endpoint secret must contain 16 bytes')
        self.origin = f'https://{parsed.netloc}'
        self.session_url = self.origin + parsed.path + 'api/v1/session'
        self.ready = asyncio.Event()
        self.condition = asyncio.Condition()
        self.send_lock = asyncio.Lock()
        self.streams = {}
        self.credit = {}
        self.tasks = set()
        self.response_tasks = set()
        self.tokens = set()
        self.closing = False
        self.failure = None
        self.next_id = 0
        self.ws = self.runner = self.listener = self.pw = self.browser = self.page = None
        self.stats = dict(up_bytes=0, down_bytes=0, streams_opened=0,
                          remote_websockets=0, sessions_created=0, sessions_deleted=0,
                          carrier=None, statuses={}, cleanup_ok=False)

    def fail(self, reason):
        self.failure = self.failure or reason
        self.ready.set()
        for writer in self.streams.values():
            writer.close()

    async def send(self, data):
        async with self.send_lock:
            if self.ws is None or self.ws.closed or self.failure:
                raise ConnectionError('browser bridge unavailable')
            await self.ws.send_bytes(data)

    async def parent(self, request):
        if request.host != self.local_host or request.match_info['token'] != self.local_token:
            raise web.HTTPNotFound()
        config = json.dumps({'url': self.endpoint['url'],
                             'socket': f'ws://{self.local_host}/{self.local_token}/socket'})
        source = Path(__file__).with_name('parent.html').read_text()
        return web.Response(text=source.replace('__BOOTSTRAP_JSON__', config.replace('<', '\\u003c')),
                            content_type='text/html', headers={'Cache-Control': 'no-store'})

    async def parent_socket(self, request):
        if (request.host != self.local_host or request.match_info['token'] != self.local_token or
                request.headers.get('Origin') != f'http://{self.local_host}' or self.ws is not None):
            raise web.HTTPForbidden()
        self.ws = web.WebSocketResponse(max_msg_size=8 << 20)
        await self.ws.prepare(request)
        try:
            async for message in self.ws:
                if message.type == WSMsgType.BINARY:
                    await self.receive(message.data)
                elif message.type == WSMsgType.TEXT:
                    event = json.loads(message.data)
                    if event.get('t') == 'status':
                        state = event.get('state')
                        if state in ('connecting', 'connected', 'reconnecting', 'failed'):
                            counts = self.stats['statuses']
                            counts[state] = counts.get(state, 0) + 1
                        if state in ('reconnecting', 'failed') and not self.closing:
                            self.fail('carrier interrupted')
                    elif event.get('t') in ('close', 'error') and not self.closing:
                        self.fail('browser bridge closed')
                elif message.type == WSMsgType.ERROR:
                    self.fail('local websocket error')
        except Exception:
            self.fail('invalid browser output')
        finally:
            if not self.closing:
                self.fail('local websocket closed')
            async with self.condition:
                self.condition.notify_all()
        return self.ws

    async def receive(self, data):
        for kind, stream, payload in frames(data):
            if kind == 17 and stream == 0 and not payload:
                self.ready.set()
            elif kind == 2 and stream in self.streams and payload:
                writer = self.streams[stream]
                writer.write(payload)
                await writer.drain()
                self.stats['down_bytes'] += len(payload)
                await self.send(frame(4, stream, struct.pack('!I', len(payload))))
            elif kind == 4 and stream in self.credit:
                if len(payload) != 4:
                    raise ValueError('invalid WINDOW')
                delta = struct.unpack('!I', payload)[0]
                if not delta or self.credit[stream] + delta > WINDOW:
                    raise ValueError('invalid WINDOW credit')
                async with self.condition:
                    self.credit[stream] += delta
                    self.condition.notify_all()
            elif kind == 3 and stream in self.streams:
                self.streams[stream].close()
                self.credit.pop(stream, None)
                async with self.condition:
                    self.condition.notify_all()
            elif kind == 5 and stream == 0 and len(payload) <= 64:
                await self.send(frame(6, payload=payload))
            elif kind == 31:
                self.fail('relay ended session')
            elif kind not in (2, 3, 4):
                raise ValueError('unexpected relay frame')

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        stream = None
        try:
            if self.closing or self.failure or len(self.streams) >= 16:
                return
            self.next_id += 1
            stream = self.next_id
            if stream > 0xffffff:
                raise ValueError('stream IDs exhausted')
            self.streams[stream] = writer
            self.credit[stream] = WINDOW
            self.stats['streams_opened'] += 1
            await self.send(frame(1, stream))
            while not self.closing and not self.failure:
                async with self.condition:
                    await self.condition.wait_for(lambda: self.closing or self.failure or
                                                  stream not in self.credit or self.credit[stream] > 0)
                    if self.closing or self.failure or stream not in self.credit:
                        break
                    allowance = min(65536, self.credit[stream])
                data = await reader.read(allowance)
                if not data or stream not in self.credit:
                    break
                self.credit[stream] -= len(data)
                await self.send(frame(2, stream, data))
                self.stats['up_bytes'] += len(data)
        except (ConnectionError, OSError):
            if not self.closing:
                self.fail('stream transport failed')
        finally:
            if stream is not None:
                self.streams.pop(stream, None)
                self.credit.pop(stream, None)
                if not self.closing and not self.failure:
                    try:
                        await self.send(frame(3, stream))
                    except (ConnectionError, OSError):
                        pass
            writer.close()
            self.tasks.discard(task)

    async def capture_response(self, response):
        if response.url != self.session_url or response.request.method != 'POST':
            return
        headers = await response.all_headers()
        token = headers.get('x-session-token')
        if token:
            self.tokens.add(token)
            self.stats['sessions_created'] += 1
            self.stats['carrier'] = headers.get('x-carrier-mode')

    def response(self, response):
        task = asyncio.create_task(self.capture_response(response))
        self.response_tasks.add(task)
        task.add_done_callback(self.response_tasks.discard)
        task.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)

    async def __aenter__(self):
        try:
            self.local_token = secrets.token_hex(24)
            app = web.Application()
            app.router.add_get('/{token}', self.parent)
            app.router.add_get('/{token}/socket', self.parent_socket)
            self.runner = web.AppRunner(app, access_log=None)
            await self.runner.setup()
            site = web.TCPSite(self.runner, '127.0.0.1', 0)
            await site.start()
            port = self.runner.addresses[0][1]
            self.local_host = f'127.0.0.1:{port}'
            self.pw = await async_playwright().start()
            self.browser = await self.pw.chromium.launch(headless=True, args=[
                '--no-sandbox', '--disable-dev-shm-usage', '--no-proxy-server'])
            context = await self.browser.new_context(service_workers='block')

            async def route(request):
                url = urlsplit(request.request.url)
                allowed = f'{url.scheme}://{url.netloc}' in (self.origin, f'http://{self.local_host}')
                if allowed:
                    await request.continue_()
                else:
                    await request.abort()

            await context.route('**/*', route)
            self.page = await context.new_page()
            self.page.on('response', self.response)
            self.page.on('pageerror', lambda _: self.fail('browser script error'))

            def socket_opened(socket):
                if socket.url.startswith(self.origin.replace('https:', 'wss:') + '/'):
                    self.stats['remote_websockets'] += 1

            self.page.on('websocket', socket_opened)
            await self.page.goto(f'http://{self.local_host}/{self.local_token}', timeout=30000)
            await asyncio.wait_for(self.ready.wait(), 30)
            if self.failure:
                raise ConnectionError(self.failure)
            if self.response_tasks:
                await asyncio.gather(*list(self.response_tasks))
            if self.stats['carrier'] != self.endpoint['carrier']:
                raise ValueError('trial carrier changed')
            self.listener = await asyncio.start_server(self.accept, '127.0.0.1', 0)
            self.tcp_port = self.listener.sockets[0].getsockname()[1]
            return self
        except BaseException:
            await self.close()
            raise

    async def __aexit__(self, *_):
        await self.close()

    async def close(self):
        if self.closing:
            return
        self.closing = True
        if self.listener:
            self.listener.close()
            await self.listener.wait_closed()
        async with self.condition:
            self.condition.notify_all()
        for writer in self.streams.values():
            writer.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        if self.page:
            try:
                await asyncio.wait_for(self.page.evaluate('window.closeBridge()'), 3)
            except Exception:
                pass
        if self.response_tasks:
            await asyncio.gather(*list(self.response_tasks), return_exceptions=True)
        # DELETE is idempotent for recently closed session tokens. This also
        # cleans up when browser startup or its keepalive request failed.
        async with ClientSession(trust_env=False, timeout=ClientTimeout(total=5)) as http:
            for token in self.tokens:
                try:
                    async with http.delete(self.session_url, allow_redirects=False,
                                           headers={'Authorization': 'Bearer ' + token}) as response:
                        if response.status == 204:
                            self.stats['sessions_deleted'] += 1
                except Exception:
                    pass
        self.stats['cleanup_ok'] = self.stats['sessions_deleted'] == len(self.tokens)
        if self.browser:
            await self.browser.close()
        if self.pw:
            await self.pw.stop()
        if self.ws:
            await self.ws.close()
        if self.runner:
            await self.runner.cleanup()


async def transfer(args, endpoint, credentials, result):
    use_native_ctr()
    bridge = BrowserBridge(endpoint)
    result['bridge'] = bridge.stats
    result['stage'] = 'browser_startup'
    async with bridge:
        result['stage'] = 'bot_authentication'
        client = TelegramClient(
            str(args.state_dir / 'bot'), credentials['mtproto']['api_id'], credentials['mtproto']['api_hash'],
            connection=tcpmtproxy.ConnectionTcpMTProxyRandomizedIntermediate,
            proxy=('127.0.0.1', bridge.tcp_port, 'dd' + endpoint['raw_secret']),
            timeout=10, connection_retries=1, request_retries=1, auto_reconnect=False,
            receive_updates=False, flood_sleep_threshold=0, device_model='Telego WEB transfer test')
        try:
            await client.connect()
            if not await client.is_user_authorized():
                await client.sign_in(bot_token=credentials['bot_token'])
            me = await client.get_me()
            if not me.bot or str(me.id) != credentials['bot_token'].split(':', 1)[0]:
                raise ValueError('session belongs to a different bot')
            result['bot_authenticated'] = True
            admin = int(credentials['allowed']['admin'])
            user = await client.get_entity(types.InputUser(admin, 0))
            if user.id != admin:
                raise ValueError('admin mismatch')
            peer = types.InputPeerUser(user.id, user.access_hash or 0)
            payload = secrets.token_bytes(args.mib << 20)
            expected = hashlib.sha256(payload).hexdigest()
            name = 'telego-web-transfer-check.bin'
            result['stage'] = 'upload'
            started = time.perf_counter()
            uploaded = await client.upload_file(payload, file_name=name)
            result['upload_seconds'] = round(time.perf_counter() - started, 3)
            media = await client(functions.messages.UploadMediaRequest(
                peer=peer, media=types.InputMediaUploadedDocument(file=uploaded,
                    mime_type='application/octet-stream', attributes=[types.DocumentAttributeFilename(name)])))
            result['stage'] = 'download'
            started = time.perf_counter()
            received = await client.download_media(media, file=bytes)
            result['download_seconds'] = round(time.perf_counter() - started, 3)
            result['bytes'] = len(received)
            result['sha256'] = hashlib.sha256(received).hexdigest()
            result['sha256_match'] = len(received) == len(payload) and result['sha256'] == expected
            if not result['sha256_match']:
                raise ValueError('round-trip bytes differ')
            result['message_sent'] = False
            if args.send:
                result['stage'] = 'send_verified_file'
                await client.send_file(peer, media.document,
                    caption=f'Telego WEB trial check: {args.mib} MiB uploaded and downloaded; SHA-256 matched.')
                result['message_sent'] = True
            if bridge.failure:
                raise ConnectionError('bridge failed during transfer')
        finally:
            await asyncio.wait_for(client.disconnect(), 5)
    if not bridge.stats['cleanup_ok']:
        raise RuntimeError('WEB session cleanup failed')
    result['stage'] = 'complete'
    result['ok'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True, help='VKDL TOML configuration')
    parser.add_argument('--endpoint', type=Path, required=True, help='Private endpoint JSON from export_endpoint.py')
    parser.add_argument('--state-dir', type=Path, default=STATE)
    parser.add_argument('--mib', type=int, choices=range(1, 65), default=1, metavar='1..64')
    parser.add_argument('--timeout', type=int, choices=range(30, 301), default=120, metavar='30..300')
    parser.add_argument('--send', action='store_true', help='Send the verified document to the configured admin')
    args = parser.parse_args()
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.state_dir.chmod(0o700)
    os.environ.setdefault('PLAYWRIGHT_BROWSERS_PATH', str(STATE / 'browsers'))
    result = {'ok': False, 'stage': 'configuration'}
    started = time.perf_counter()
    try:
        credentials = tomllib.loads(args.credentials.read_text())
        endpoint = json.loads(args.endpoint.read_text())

        async def bounded():
            async with asyncio.timeout(args.timeout):
                await transfer(args, endpoint, credentials, result)

        asyncio.run(bounded())
    except errors.FloodWaitError as error:
        result.update(error='FloodWaitError', wait_seconds=error.seconds)
    except (Exception, KeyboardInterrupt) as error:
        # Raw exceptions can contain credential URLs. Keep output structural.
        result['error'] = type(error).__name__
    result['elapsed_seconds'] = round(time.perf_counter() - started, 3)
    output = json.dumps(result, indent=2) + '\n'
    (args.state_dir / 'last-result.json').write_text(output)
    print(output, end='')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
