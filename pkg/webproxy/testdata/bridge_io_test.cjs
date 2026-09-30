'use strict';
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const { getEventListeners } = require('node:events');
const vm = require('node:vm');

const carriers = ['https', 'https-lanes', 'websocket', 'websocket-lanes'];
const budget = 90000;
const batchLimit = 2 * 1024 * 1024;
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };

function harness(carrier, smallBatch = false, diagnostics = true) {
  const html = readFileSync(join(process.env.TELEGO_BRIDGE_FIXTURES, carrier + (!diagnostics ? '.quiet.html' : smallBatch ? '.small.html' : '.html')), 'utf8');
  const match = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(match, 'rendered script exists');
  let now = 0, nextTimer = 0;
  const timers = new Map(), sockets = [], events = new Map(), messages = [], requests = [], uplinks = [];
  class Socket extends EventTarget {
    static CONNECTING = 0; static OPEN = 1; static CLOSED = 3;
    readyState = Socket.CONNECTING; bufferedAmount = 0; sent = []; closeCalls = 0; closes = [];
    constructor(url, protocol) { super(); this.url = url; this.protocol = protocol; sockets.push(this); }
    emit(type, data) {
      const event = new Event(type);
      if (data !== undefined) event.data = data;
      this['on' + type]?.(event);
      this.dispatchEvent(event);
    }
    open() { this.readyState = Socket.OPEN; this.emit('open'); }
    close(code, reason) { this.closeCalls++; this.closes.push({ code, reason }); this.readyState = Socket.CLOSED; }
    send(data) { assert.equal(this.readyState, Socket.OPEN); this.sent.push(data); uplinks.push(data); }
  }
  const sandbox = {
    ArrayBuffer, Uint8Array, DataView, AbortController, DOMException, URL, TextDecoder,
    performance: { now() { return now; } },
    Date: class extends Date { static now() { return now; } },
    WebSocket: Socket, queueMicrotask,
    location: { hash: '', pathname: '/', search: '?bridge=' + 'A'.repeat(43) }, history: { replaceState() {} }, parent: {},
    addEventListener(name, callback) { events.set(name, callback); },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { at: now + delay, callback }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) {
      requests.push({ url, options });
      if (url.endsWith('/api/v1/up')) uplinks.push(options.body);
      if (options.method === 'DELETE') return Promise.resolve(new Response(null, { status: 204 }));
      if (url.endsWith('/api/v1/diagnostic')) return Promise.resolve(new Response(null, { status: 204 }));
      return sandbox.respond(url, options);
    },
    respond() { throw new Error('unexpected fetch'); },
    testPort: { postMessage(value) { messages.push(value); }, close() {}, start() {} },
  };
  // Expose existing functions only inside the test VM. Production exports stay unchanged.
  const hooks = `
globalThis.bridgeTest={request,options,close,createSession,activatePort,poll,pollLane,ensureLane,fail,beginRecovery,deliver,
  state:()=>({closed,sessionToken,queuedBytes,queuedItems,lanes,downCursor,recovering,epoch,activeStreams,welcomed}),
  signal:lifecycleController.signal,
  setSession:()=>{sessionToken='test-token';port=globalThis.testPort},
  ${carrier.startsWith('websocket') ? 'openWebSocket,queueWebSocketLane,' : ''}
};\n`;
  const script = match[1].replace(/\}\)\(\);\s*$/, hooks + '})();');
  assert.notEqual(script, match[1], 'test hooks were inserted');
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  const h = {
    api: sandbox.bridgeTest, sandbox, sockets, timers, messages, requests, uplinks,
    async advance(milliseconds, runTimers = true) {
      now += milliseconds;
      if (runTimers) {
        for (const [id, timer] of [...timers]) {
          if (timers.has(id) && timer.at <= now) { timers.delete(id); timer.callback(); }
        }
      }
      await flush();
    },
    pagehide() { events.get('pagehide')(); },
    online() { events.get('online')(); },
  };
  return h;
}

function streamResponse({ status = 200, headers = {}, chunks = [], end = true } = {}) {
  let cancelled = false, controller;
  const body = new ReadableStream({
    start(value) { controller = value; for (const chunk of chunks) value.enqueue(chunk); if (end) value.close(); },
    cancel() { cancelled = true; },
  });
  return { response: new Response(body, { status, headers }), body, controller, cancelled: () => cancelled };
}

function observe(promise) {
  const result = { settled: false };
  result.done = promise.then(value => { result.settled = true; result.value = value; }, error => { result.settled = true; result.error = error; });
  return result;
}

function assertClean(h) {
  assert.equal(h.timers.size, 0, 'all timers released');
  assert.equal(getEventListeners(h.api.signal, 'abort').length, 0, 'lifecycle listeners released');
  for (const socket of h.sockets) {
    for (const event of ['open', 'close', 'error']) assert.equal(getEventListeners(socket, event).length, 0);
  }
}

function dataFrame(id, size = 1) {
  const data = new ArrayBuffer(8 + size), view = new DataView(data);
  view.setUint32(0, 0x02000000 | id); view.setUint32(4, size);
  return new Uint8Array(data);
}

function streamFrame(id, type = 1) {
  if (type === 2) return dataFrame(id).buffer;
  const data = new ArrayBuffer(type === 4 ? 12 : 8), view = new DataView(data);
  view.setUint32(0, (type << 24) | id);
  if (type === 4) { view.setUint32(4, 4); view.setUint32(8, 1024); }
  return data;
}

function streamBatch(...frames) {
  return Uint8Array.from(Buffer.concat(frames.map(frame => Buffer.from(frame)))).buffer;
}

function nativeFrame(h, id, type = 1) {
  const data = streamFrame(id, type);
  h.sandbox.testPort.onmessage({ data });
  return data;
}

function parked(options) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new DOMException('aborted', 'AbortError'));
    options.signal.addEventListener('abort', abort, { once: true });
    if (options.signal.aborted) abort();
  });
}

async function liveBridge(carrier, diagnostics = false) {
  const h = harness(carrier, false, diagnostics);
  let sessions = 0;
  h.recoveryResponse = () => new Response(JSON.stringify({ version: 1, bootstrap: 'B'.repeat(43), carrier, batch: batchLimit, streams: 128 }), {
    headers: { 'Content-Type': 'application/vnd.telego.web-recovery+json' },
  });
  h.sandbox.respond = async (url, options) => {
    if (url.includes('/?bridge=')) return h.recoveryResponse();
    if (url.endsWith('/api/v1/session')) {
      const welcome = new Uint8Array(8); welcome[0] = 17;
      return new Response(welcome, { headers: { 'X-Carrier-Mode': carrier, 'X-Session-Token': (++sessions === 1 ? 'C' : 'D').repeat(43) } });
    }
    if (url.endsWith('/api/v1/up')) return new Response(null, { status: 204, headers: { 'X-Up-Ack': options.headers['X-Up-Seq'] } });
    return parked(options);
  };
  h.api.activatePort(h.sandbox.testPort);
  const hello = new ArrayBuffer(9); new DataView(hello).setUint32(0, 0x10000000); new DataView(hello).setUint32(4, 1);
  h.sandbox.testPort.onmessage({ data: hello }); await flush();
  if (carrier === 'websocket') { h.sockets[0].open(); await flush(); }
  assert.equal(h.api.state().welcomed, true);
  return h;
}

for (const carrier of carriers) {
  for (const diagnostics of [false, true]) {
    test(carrier + ': recovery retires old streams, fences late callbacks, and sends WELCOME only once; diagnostics=' + diagnostics, async () => {
      const h = await liveBridge(carrier, diagnostics);
      nativeFrame(h, 1); await flush();
      if (carrier === 'websocket-lanes') { h.sockets[0].open(); await flush(); }
      const oldSockets = [...h.sockets];
      let resume;
      const respond = h.sandbox.respond;
      h.sandbox.respond = (url, options) => url.includes('/?bridge=') ? new Promise(resolve => { resume = resolve; }) : respond(url, options);
      const before = h.requests.length;
      h.api.fail('down_poll', Object.assign(new Error('downlink rejected'), { recoverable: true })); await flush();
      h.api.beginRecovery(); h.online();
      assert.equal(h.api.state().recovering, true);
      assert.equal(h.api.state().closed, false);
      assert.equal(h.requests.slice(before).filter(r => r.url.includes('/?bridge=')).length, 1, 'concurrent triggers share one recovery');
      const close = h.messages.filter(value => value instanceof ArrayBuffer && new DataView(value).getUint32(0) === 0x03000001);
      assert.equal(close.length, 1);
      nativeFrame(h, 1, 2); nativeFrame(h, 1, 3); nativeFrame(h, 2);
      for (const socket of oldSockets) { socket.emit('close'); socket.emit('message', dataFrame(1).buffer); }
      resume(h.recoveryResponse()); await flush();
      for (const socket of h.sockets.filter(s => !oldSockets.includes(s))) socket.open();
      await flush();
      assert.equal(h.api.state().recovering, false);
      assert.equal(h.api.state().closed, false);
      assert.equal(h.messages.filter(value => value instanceof ArrayBuffer && new DataView(value).getUint8(0) === 17).length, 1);
      assert.equal(h.messages.some(value => value.t === 'close' || value.state === 'failed'), false);
      assert.equal(h.api.state().activeStreams.has(1), false);
      assert.equal(h.api.state().activeStreams.has(2), true);
      assert.equal(h.api.state().queuedBytes, 0);
      const newBatches = h.requests.slice(before).filter(r => r.url.endsWith('/api/v1/up')).map(r => r.options.body);
      for (const socket of h.sockets.filter(s => !oldSockets.includes(s))) newBatches.push(...socket.sent);
      assert.ok(newBatches.length);
      for (const batch of newBatches) assert.equal(new DataView(batch).getUint32(0), 0x01000002, 'only replacement OPEN crosses the new session');
      h.pagehide(); await flush(); assertClean(h);
    });
  }

  for (const origin of ['local', 'remote']) {
    test(carrier + ': recovery discards in-flight frames for a previously ' + origin + '-closed stream', async () => {
      const h = await liveBridge(carrier);
      nativeFrame(h, 1); await flush();
      if (carrier === 'websocket-lanes') { h.sockets[0].open(); await flush(); }
      const close = streamFrame(1, 3);
      if (origin === 'local') {
        const before = h.uplinks.length;
        h.sandbox.testPort.onmessage({ data: close }); await flush();
        assert.deepEqual(Buffer.concat(h.uplinks.slice(before).map(value => Buffer.from(value))), Buffer.from(close), 'the original CLOSE still reaches the carrier');
      } else h.api.deliver(close);
      assert.equal(h.api.state().activeStreams.has(1), false);
      let resume;
      const respond = h.sandbox.respond, oldSockets = [...h.sockets], before = h.uplinks.length;
      h.sandbox.respond = (url, options) => url.includes('/?bridge=') ? new Promise(resolve => { resume = resolve; }) : respond(url, options);
      h.api.beginRecovery(); await flush();
      for (const type of [2, 4, 3]) nativeFrame(h, 1, type);
      const replacement = streamBatch(streamFrame(2), streamFrame(2, 2));
      h.sandbox.testPort.onmessage({ data: streamBatch(streamFrame(1, 2), streamFrame(2), streamFrame(1, 4), streamFrame(2, 2), streamFrame(1, 3)) });
      assert.equal(h.api.state().queuedBytes, replacement.byteLength, 'only replacement stream bytes enter the recovery queue');
      resume(h.recoveryResponse()); await flush();
      for (const socket of h.sockets.filter(socket => !oldSockets.includes(socket))) socket.open();
      await flush();
      assert.equal(h.api.state().closed, false);
      assert.equal(h.api.state().recovering, false);
      assert.deepEqual(Buffer.concat(h.uplinks.slice(before).map(value => Buffer.from(value))), Buffer.from(replacement));
      const after = h.uplinks.length;
      for (const type of [2, 4, 3]) nativeFrame(h, 1, type);
      await flush();
      assert.equal(h.uplinks.length, after, 'late old-stream frames remain fenced after recovery');
      assert.equal(h.api.state().activeStreams.has(2), true);
      h.pagehide(); await flush(); assertClean(h);
    });
  }

  test(carrier + ': excess native OPEN closes only that stream and closed streams release capacity', async () => {
    const h = await liveBridge(carrier);
    for (let id = 1; id <= 128; id++) {
      nativeFrame(h, id); await flush();
      if (carrier === 'websocket-lanes') { h.sockets.at(-1).open(); await flush(); }
    }
    const before = h.uplinks.length, siblingData = streamFrame(1, 2);
    h.sandbox.testPort.onmessage({ data: streamBatch(streamFrame(129), streamFrame(129, 2), streamFrame(129, 4), streamFrame(129, 3), siblingData) });
    await flush();
    assert.equal(h.api.state().closed, false);
    assert.equal(h.api.state().activeStreams.size, 128);
    assert.equal(h.messages.filter(value => value instanceof ArrayBuffer && new DataView(value).getUint32(0) === 0x03000081).length, 1);
    assert.deepEqual(Buffer.concat(h.uplinks.slice(before).map(value => Buffer.from(value))), Buffer.from(siblingData), 'rejected stream frames are filtered while sibling traffic continues');
    nativeFrame(h, 2, 3); await flush();
    if (carrier === 'websocket-lanes') h.sockets[1].emit('close');
    const replacement = nativeFrame(h, 130); await flush();
    if (carrier === 'websocket-lanes') { h.sockets.at(-1).open(); await flush(); }
    assert.equal(h.api.state().closed, false);
    assert.equal(h.api.state().activeStreams.size, 128);
    assert.equal(h.api.state().activeStreams.has(130), true);
    assert.deepEqual(Buffer.from(h.uplinks.at(-1)), Buffer.from(replacement));
    assert.equal(h.messages.some(value => value.t === 'close' || value.state === 'failed'), false);
    h.pagehide(); await flush(); assertClean(h);
  });

  test(carrier + ': stalled recovery has one 15-second deadline and page shutdown releases it', async () => {
    const h = await liveBridge(carrier);
    h.sandbox.respond = (url, options) => parked(options);
    h.api.beginRecovery(); await flush();
    await h.advance(15000);
    assert.equal(h.api.state().closed, true);
    assert.equal(h.messages.filter(value => value.t === 'close').length, 1);
    assertClean(h);
  });

  test(carrier + ': delayed recovery response cannot outrun its wall-clock deadline', async () => {
    const h = await liveBridge(carrier); let resume;
    h.sandbox.respond = () => new Promise(resolve => { resume = resolve; });
    h.api.beginRecovery(); await flush(); await h.advance(15000, false);
    resume(h.recoveryResponse()); await flush();
    assert.equal(h.api.state().closed, true);
    assertClean(h);
  });

  test(carrier + ': shutdown while recovering cancels requests and ignores late completion', async () => {
    const h = await liveBridge(carrier); let resume;
    h.sandbox.respond = () => new Promise(resolve => { resume = resolve; });
    h.api.beginRecovery(); await flush(); h.pagehide();
    const before = h.messages.length;
    resume(h.recoveryResponse()); await flush();
    assert.equal(h.messages.length, before);
    assertClean(h);
  });
}

for (const origin of ['local', 'remote']) {
  for (const diagnostics of [false, true]) {
    test('WebSocket lane capacity isolates replacement OPEN while a ' + origin + ' CLOSE awaits socket closure; diagnostics=' + diagnostics, async () => {
      const h = await liveBridge('websocket-lanes', diagnostics);
      for (let id = 1; id <= 128; id++) {
        nativeFrame(h, id); await flush();
        h.sockets.at(-1).open(); await flush();
      }
      if (origin === 'local') nativeFrame(h, 2, 3);
      else h.sockets[1].emit('message', streamFrame(2, 3));
      await flush();
      assert.equal(h.api.state().activeStreams.size, 127);
      const before = h.uplinks.length;
      nativeFrame(h, 130); await flush();
      assert.equal(h.api.state().closed, false, 'a closing socket must not turn replacement OPEN into bridge failure');
      assert.equal(h.api.state().activeStreams.size, 127, 'rejected OPEN must release its native stream reservation');
      const siblingData = streamFrame(1, 2);
      h.sandbox.testPort.onmessage({ data: streamBatch(streamFrame(130, 2), streamFrame(130, 4), streamFrame(130, 3), streamFrame(131), streamFrame(131, 2), streamFrame(131, 4), streamFrame(131, 3), siblingData) });
      await flush();
      assert.equal(h.api.state().closed, false);
      assert.equal(h.api.state().activeStreams.size, 127);
      assert.equal(h.api.state().lanes.size, 128);
      assert.equal(h.sockets.length, 128, 'physical socket reservations remain bounded until socket closure');
      for (const id of [130, 131]) assert.equal(h.messages.filter(value => value instanceof ArrayBuffer && new DataView(value).getUint32(0) === (0x03000000 | id)).length, 1);
      assert.deepEqual(Buffer.concat(h.uplinks.slice(before).map(value => Buffer.from(value))), Buffer.from(siblingData), 'rejected stream data cannot reach healthy lanes');
      assert.equal(h.messages.some(value => value.t === 'close' || value.state === 'failed'), false);
      h.pagehide(); await flush(); assertClean(h);
    });
  }
}

test('native OPEN and CLOSE in one batch still cancel a pending WebSocket lane', async () => {
  const h = await liveBridge('websocket-lanes');
  h.sandbox.testPort.onmessage({ data: streamBatch(streamFrame(1), streamFrame(1, 3)) });
  await flush();
  assert.equal(h.api.state().closed, false);
  assert.equal(h.api.state().activeStreams.size, 0);
  assert.equal(h.api.state().lanes.size, 0);
  assert.equal(h.api.state().queuedBytes, 0);
  assert.equal(h.sockets[0].closeCalls > 0, true);
  h.sockets[0].open(); h.sockets[0].emit('close'); await flush();
  assert.equal(h.uplinks.length, 0);
  h.pagehide(); await flush(); assertClean(h);
});

test('replacement WebSocket failure retries within one deadline and its late close cannot retire the successor', async () => {
  const h = await liveBridge('websocket');
  h.api.beginRecovery(); await flush();
  const failed = h.sockets[1]; failed.emit('error'); await flush();
  assert.equal(h.api.state().closed, false);
  assert.equal(h.api.state().recovering, true);
  await h.advance(250);
  const successor = h.sockets[2]; successor.open(); await flush();
  failed.emit('close'); failed.open(); failed.emit('message', dataFrame(1).buffer); await flush();
  assert.equal(h.api.state().closed, false);
  assert.equal(h.api.state().recovering, false);
  assert.equal(successor.closeCalls, 0);
  assert.equal(h.requests.filter(r => r.url.includes('/?bridge=')).length, 2);
  h.pagehide(); await flush(); assertClean(h);
});

for (const status of [408, 429, 502, 503, 504]) {
  test('recovery retries temporary gateway status ' + status + ' within the original deadline', async () => {
    const h = await liveBridge('websocket-lanes'), respond = h.sandbox.respond;
    let failures = 1;
    h.sandbox.respond = (url, options) => url.includes('/?bridge=') && failures-- > 0 ?
      Promise.resolve(new Response(null, { status, headers: { 'Retry-After': '1' } })) : respond(url, options);
    h.api.beginRecovery(); await flush();
    assert.equal(h.api.state().recovering, true);
    assert.equal(h.api.state().closed, false);
    await h.advance(1000);
    assert.equal(h.api.state().recovering, false);
    assert.equal(h.api.state().closed, false);
    assert.equal(h.requests.filter(r => r.url.includes('/?bridge=')).length, 2);
    h.pagehide(); await flush(); assertClean(h);
  });
}

for (const carrier of carriers) {
  test(carrier + ': response deadline includes a stalled body', async () => {
    const h = harness(carrier), response = streamResponse({ end: false });
    h.sandbox.respond = async () => response.response;
    const result = observe(h.api.request('/api/v1/session', () => h.api.options('POST', 'bootstrap', null)));
    await flush();
    assert.equal(result.settled, false, 'headers alone must not complete the request');
    await h.advance(budget);
    assert.equal(result.settled, true);
    assert.ok(result.error);
    assert.equal(response.cancelled(), true);
    assert.equal(response.body.locked, false);
    assert.equal(h.timers.size, 0);
    assertClean(h);
  });

  test(carrier + ': page shutdown cancels body consumption', async () => {
    const h = harness(carrier), response = streamResponse({ end: false });
    h.sandbox.respond = async () => response.response;
    const result = observe(h.api.request('/api/v1/session', () => h.api.options('POST', 'bootstrap', null)));
    await flush(); h.pagehide(); await flush();
    assert.ok(result.error);
    assert.equal(response.cancelled(), true);
    assert.equal(response.body.locked, false);
    assert.equal(h.timers.size, 0);
    assertClean(h);
  });

  test(carrier + ': failed session body retains the server cleanup token', async () => {
    const h = harness(carrier), response = streamResponse({ end: false, headers: { 'X-Carrier-Mode': carrier, 'X-Session-Token': 'issued-token' } });
    h.sandbox.respond = async () => response.response;
    h.api.activatePort(h.sandbox.testPort);
    const result = observe(h.api.createSession(new ArrayBuffer(8)));
    await flush(); h.pagehide(); await result.done;
    const deletes = h.requests.filter(request => request.options.method === 'DELETE');
    assert.equal(deletes.length, 1);
    assert.equal(deletes[0].options.headers.Authorization, 'Bearer issued-token');
    assert.equal(h.messages.some(value => value instanceof ArrayBuffer), false);
    assert.equal(h.sockets.length, 0);
    assertClean(h);
  });
}

test('external downlink cancellation interrupts the body and releases its reader', async () => {
  const h = harness('https'), response = streamResponse({ end: false }), external = new AbortController();
  h.sandbox.respond = async () => response.response;
  const result = observe(h.api.request('/api/v1/down', () => h.api.options('POST', 'token', null, null, external.signal)));
  await flush(); external.abort(); await result.done;
  assert.ok(result.error);
  assert.equal(response.cancelled(), true);
  assert.equal(response.body.locked, false);
  assert.equal(getEventListeners(external.signal, 'abort').length, 0);
  assertClean(h);
});

test('late body completion cannot outrun a delayed deadline callback', async () => {
  const h = harness('https'), response = streamResponse({ end: false });
  h.sandbox.respond = async () => response.response;
  const result = observe(h.api.request('/api/v1/session', () => h.api.options('POST', 'bootstrap', null)));
  await flush(); await h.advance(budget, false);
  response.controller.enqueue(new Uint8Array(8)); response.controller.close();
  await result.done;
  assert.ok(result.error);
  assertClean(h);
});

for (const scenario of [
  { name: 'oversized declared session', path: 'session', headers: { 'Content-Length': '9' }, chunks: [], end: false },
  { name: 'oversized streamed session', path: 'session', chunks: [new Uint8Array(5), new Uint8Array(4)], end: false },
  { name: 'truncated session', path: 'session', chunks: [new Uint8Array(7)], end: true },
  { name: 'invalid declared length', path: 'session', headers: { 'Content-Length': '8x' }, chunks: [], end: false },
  { name: 'oversized declared downlink', path: 'down', headers: { 'Content-Length': String(batchLimit + 1) }, chunks: [], end: false },
  { name: 'oversized streamed downlink', path: 'down', chunks: [new Uint8Array(batchLimit), new Uint8Array(1)], end: false },
  { name: 'downlink exceeds declared length', path: 'down', headers: { 'Content-Length': '8' }, chunks: [new Uint8Array(9)], end: false },
  { name: 'downlink shorter than declared length', path: 'down', headers: { 'Content-Length': '9' }, chunks: [new Uint8Array(8)], end: true },
]) {
  test(scenario.name + ' is terminal and bounded', async () => {
    const h = harness('https'), response = streamResponse(scenario);
    h.sandbox.respond = async () => response.response;
    const result = observe(h.api.request('/api/v1/' + scenario.path, () => h.api.options('POST', 'token', null)));
    await result.done;
    assert.ok(result.error);
    assert.equal(h.requests.length, 1, 'invalid body must not be retried');
    if (!scenario.end) assert.equal(response.cancelled(), true);
    assert.equal(response.body.locked, false);
    assertClean(h);
  });
}

for (const scenario of [
  { name: 'exact session', path: 'session', chunks: [new Uint8Array([17, 0, 0, 0]), new Uint8Array(4)], headers: { 'Content-Length': '0008' }, size: 8 },
  { name: 'decoded session with encoded length', path: 'session', chunks: [new Uint8Array(8)], headers: { 'Content-Encoding': 'gzip', 'Content-Length': '28' }, size: 8 },
  { name: 'downlink at byte limit', path: 'down', chunks: [new Uint8Array(batchLimit / 2), new Uint8Array(batchLimit / 2)], size: batchLimit },
  { name: 'many small downlink chunks', path: 'down', chunks: Array.from({ length: 4100 }, () => new Uint8Array([7])), size: 4100 },
]) {
  test(scenario.name + ' succeeds without leaking timers', async () => {
    const h = harness('https'), response = streamResponse(scenario);
    h.sandbox.respond = async () => response.response;
    const result = await h.api.request('/api/v1/' + scenario.path, () => h.api.options('POST', 'token', null));
    assert.equal(result.body.byteLength, scenario.size);
    assert.equal(response.body.locked, false);
    assert.ok(Buffer.from(result.body).equals(Buffer.concat(scenario.chunks)), 'response bytes match');
    assertClean(h);
  });
}

test('503 discards its body and preserves Retry-After and the total retry budget', async () => {
  const h = harness('https'), first = streamResponse({ status: 503, headers: { 'Retry-After': '2' }, end: false });
  const second = streamResponse({ end: false });
  h.sandbox.respond = async () => h.requests.length === 1 ? first.response : second.response;
  const result = observe(h.api.request('/api/v1/session', () => h.api.options('POST', 'bootstrap', null)));
  await flush();
  assert.equal(first.cancelled(), true);
  await h.advance(1999); assert.equal(h.requests.length, 1);
  await h.advance(1); assert.equal(h.requests.length, 2);
  await h.advance(budget - 2000);
  assert.ok(result.error);
  assert.equal(second.cancelled(), true);
  assertClean(h);
});

test('unexpected HTTP status discards its body without waiting for it', async () => {
  const h = harness('https'), response = streamResponse({ status: 502, end: false });
  h.sandbox.respond = async () => response.response;
  const result = await h.api.request('/api/v1/down', () => h.api.options('POST', 'token', null));
  assert.equal(result.status, 502);
  assert.equal(response.cancelled(), true);
  assert.equal(h.requests.length, 1);
  assertClean(h);
});

test('late empty response cannot outrun a delayed deadline callback', async () => {
  const h = harness('https'); let resolve;
  h.sandbox.respond = () => new Promise(value => { resolve = value; });
  const result = observe(h.api.request('/api/v1/up', () => h.api.options('POST', 'token', null)));
  await h.advance(budget, false); resolve(new Response(null, { status: 204 }));
  await result.done;
  assert.ok(result.error);
  assertClean(h);
});

test('session headers arriving after page closure still trigger credential cleanup', async () => {
  const h = harness('websocket'); let resolve;
  h.sandbox.respond = () => new Promise(value => { resolve = value; });
  const result = observe(h.api.createSession(new ArrayBuffer(8)));
  await flush(); h.pagehide();
  const response = streamResponse({ end: false, headers: { 'X-Carrier-Mode': 'websocket', 'X-Session-Token': 'late-token' } });
  resolve(response.response); await result.done;
  assert.equal(h.sockets.length, 0);
  const deletes = h.requests.filter(request => request.options.method === 'DELETE');
  assert.equal(deletes.length, 1);
  assert.equal(deletes[0].options.headers.Authorization, 'Bearer late-token');
  assert.equal(response.cancelled(), true);
  assertClean(h);
});

for (const carrier of carriers) {
  test(carrier + ': successful session consumes the bounded welcome response', async () => {
    const h = harness(carrier), welcome = new Uint8Array([17, 0, 0, 0, 0, 0, 0, 0]);
    const response = streamResponse({ chunks: [welcome], headers: { 'X-Carrier-Mode': carrier, 'X-Session-Token': 'issued-token' } });
    const downlink = streamResponse({ end: false });
    h.sandbox.respond = async url => url.endsWith('/session') ? response.response : downlink.response;
    h.api.activatePort(h.sandbox.testPort);
    const result = observe(h.api.createSession(new ArrayBuffer(8)));
    await flush();
    if (carrier === 'websocket') { assert.equal(result.settled, false); h.sockets[0].open(); }
    await result.done;
    const forwarded = h.messages.filter(value => value instanceof ArrayBuffer);
    assert.equal(forwarded.length, 1);
    assert.deepEqual(new Uint8Array(forwarded[0]), welcome);
    assert.equal(h.api.state().closed, false);
    assert.equal(h.api.state().sessionToken, 'issued-token');
    h.pagehide(); await flush(); assertClean(h);
  });
}

for (const carrier of ['https', 'https-lanes']) {
  test(carrier + ': downlink delivers bytes and advances its cursor only after body completion', async () => {
    const h = harness(carrier), frame = dataFrame(1);
    const response = streamResponse({ end: false, headers: { 'X-Down-Cursor': '1' } });
    const next = streamResponse({ end: false });
    h.sandbox.respond = async () => h.requests.length === 1 ? response.response : next.response;
    h.api.setSession();
    const lane = h.api.ensureLane(1);
    const result = observe(carrier === 'https' ? h.api.poll() : h.api.pollLane(lane));
    await flush();
    assert.equal(h.messages.some(value => value instanceof ArrayBuffer), false);
    assert.equal(carrier === 'https' ? h.api.state().downCursor : lane.cursor, '0');
    response.controller.enqueue(frame); response.controller.close(); await flush();
    assert.equal(carrier === 'https' ? h.api.state().downCursor : lane.cursor, '1');
    assert.equal(h.requests[1].options.headers['X-Down-Cursor'], '1');
    assert.deepEqual(new Uint8Array(h.messages.find(value => value instanceof ArrayBuffer)), frame);
    h.pagehide(); await result.done; assertClean(h);
  });
}

for (const carrier of ['https', 'https-lanes']) {
  for (const multiple of [false, true]) {
    test(carrier + ': small batch ' + (multiple ? 'rejects multiple oversized frames' : 'preserves a single whole frame'), async () => {
      const h = harness(carrier, true), bytes = dataFrame(1, 32);
      const response = streamResponse({ chunks: multiple ? [bytes, bytes] : [bytes] });
      h.sandbox.respond = async () => response.response;
      const result = observe(h.api.request('/api/v1/down', () => h.api.options('POST', 'token', null)));
      await result.done;
      if (multiple) assert.ok(result.error); else assert.deepEqual(new Uint8Array(result.value.body), bytes);
      assertClean(h);
    });
  }
}

for (const carrier of ['websocket', 'websocket-lanes']) {
  function open(h) {
    h.api.setSession();
    if (carrier === 'websocket') return observe(h.api.openWebSocket());
    const frame = new ArrayBuffer(8); new DataView(frame).setUint8(0, 1); new DataView(frame).setUint8(3, 1);
    h.api.queueWebSocketLane({ type: 1, id: 1, data: frame });
    return null;
  }
  test(carrier + ': opening timeout and late events cannot revive the socket', async () => {
    const h = harness(carrier), pending = open(h), socket = h.sockets[0];
    await h.advance(budget);
    assert.ok(socket.closeCalls, 'opening timeout closes the socket');
    if (pending) assert.ok(pending.error); else assert.equal(h.api.state().closed, true);
    const previous = h.messages.length;
    socket.open(); socket.emit('message', new ArrayBuffer(8)); await flush();
    assert.equal(h.messages.length, previous);
    assert.equal(socket.sent.length, 0);
    assert.equal(h.timers.size, 0);
    assertClean(h);
  });
  test(carrier + ': healthy idle socket outlives its opening deadline', async () => {
    const h = harness(carrier), pending = open(h), socket = h.sockets[0];
    socket.open(); await flush();
    if (pending) assert.equal(pending.error, undefined);
    await h.advance(2 * budget);
    assert.equal(socket.closeCalls, 0);
    assert.equal(h.api.state().closed, false);
    assert.equal(h.timers.size, 0);
    h.pagehide(); await flush();
    assertClean(h);
  });
  test(carrier + ': page shutdown settles pending socket establishment', async () => {
    const h = harness(carrier), pending = open(h);
    h.pagehide(); await flush();
    if (pending) assert.ok(pending.error);
    assert.ok(h.sockets[0].closeCalls);
    assert.equal(h.api.state().closed, true);
    assertClean(h);
  });
  test(carrier + ': late open cannot outrun a delayed deadline callback', async () => {
    const h = harness(carrier), pending = open(h);
    await h.advance(budget, false); h.sockets[0].open(); await flush();
    if (pending) assert.ok(pending.error); else assert.equal(h.api.state().closed, true);
    assert.ok(h.sockets[0].closeCalls);
    assert.equal(h.sockets[0].sent.length, 0);
    assertClean(h);
  });
  for (const event of ['error', 'close']) {
    test(carrier + ': ' + event + ' before open releases establishment ownership', async () => {
      const h = harness(carrier), pending = open(h);
      h.sockets[0].emit(event); await flush();
      if (pending) assert.ok(pending.error); else assert.equal(h.api.state().closed, true);
      assertClean(h);
    });
  }
}

test('established WebSocket lane closure preserves its healthy sibling', async () => {
  const h = harness('websocket-lanes'); h.api.setSession();
  for (const id of [1, 2]) {
    const frame = new ArrayBuffer(8), view = new DataView(frame);
    view.setUint32(0, 0x01000000 | id);
    h.api.queueWebSocketLane({ type: 1, id, data: frame });
  }
  for (const socket of h.sockets) socket.open();
  await flush();
  h.sockets[0].readyState = 3; h.sockets[0].emit('close'); await flush();
  assert.equal(h.api.state().closed, false);
  assert.equal(h.api.state().lanes.size, 1);
  assert.ok(h.api.state().lanes.has(2));
  assert.equal(h.sockets[1].closeCalls, 0);
  const reports = h.requests.filter(request => request.url.endsWith('/api/v1/diagnostic'));
  assert.equal(reports.length, 1);
  assert.equal(JSON.parse(reports[0].options.body).reason, 'ws_lane_closed_transport');
  assert.equal(JSON.parse(reports[0].options.body).lane_id, 1);
  await h.advance(2 * budget);
  assert.equal(h.sockets[1].closeCalls, 0);
  h.pagehide(); await flush(); assertClean(h);
});

for (const diagnostics of [false, true]) {
  test('diagnostics=' + diagnostics + ': CLOSE cancels a pending lane without waiting for socket events', async () => {
    const h = harness('websocket-lanes', false, diagnostics); h.api.setSession();
    const queue = (id, type) => {
      const data = new ArrayBuffer(8); new DataView(data).setUint32(0, (type << 24) | id);
      h.api.queueWebSocketLane({ id, type, data });
    };
    queue(1, 1); queue(1, 3); await flush();
    assert.equal(h.api.state().closed, false);
    assert.equal(h.api.state().lanes.size, 0);
    assert.equal(h.api.state().queuedBytes, 0);
    assert.equal(h.api.state().queuedItems, 0);
    assertClean(h);
    const messages = h.messages.length;
    h.sockets[0].open(); h.sockets[0].emit('error'); h.sockets[0].emit('close'); await flush();
    assert.equal(h.messages.length, messages);
    assert.equal(h.sockets[0].sent.length, 0);
    queue(2, 1); h.sockets[1].open(); await flush();
    assert.equal(h.sockets[1].sent.length, 1);
    assert.equal(h.requests.length, 0);
    h.pagehide(); await flush(); assertClean(h);
  });

  for (const failure of ['error', 'close', 'timeout']) {
    test('diagnostics=' + diagnostics + ': lane opening ' + failure + ' preserves established traffic and permits a replacement', async () => {
      const h = harness('websocket-lanes', false, diagnostics); h.api.setSession();
      const queue = (id, type = 1, data) => {
        if (!data) { data = new ArrayBuffer(8); new DataView(data).setUint32(0, (type << 24) | id); }
        h.api.queueWebSocketLane({ id, type, data });
      };
      queue(1); h.sockets[0].open(); await flush();
      queue(2);
      const sibling = h.sockets[0], failed = h.sockets[1];
      if (failure === 'timeout') await h.advance(budget);
      else { failed.emit(failure); await flush(); }
      // Browsers can deliver both an error and a later close for one attempt.
      failed.emit('close'); await flush();
      assert.equal(h.api.state().closed, false, 'one opening failure must not discard the bridge');
      assert.equal(sibling.closeCalls, 0);
      assert.equal(h.api.state().lanes.size, 1);
      assert.equal(h.api.state().queuedBytes, 0);
      assert.equal(h.api.state().queuedItems, 0);
      assert.equal(h.messages.some(value => value.state === 'failed'), false);
      assert.equal(h.requests.filter(request => request.url.endsWith('/api/v1/diagnostic')).length, diagnostics ? 1 : 0);
      const closed = h.messages.filter(value => value instanceof ArrayBuffer && new DataView(value).getUint8(0) === 3);
      assert.equal(closed.length, 1, 'Telegram gets one CLOSE for only the failed attempt');
      assert.equal(new DataView(closed[0]).getUint32(0), 0x03000002);
      const up = dataFrame(1, 8).buffer;
      queue(1, 2, up); await flush();
      assert.deepEqual(new Uint8Array(sibling.sent.at(-1)), new Uint8Array(up));
      const down = dataFrame(1, 8).buffer;
      sibling.emit('message', down); await flush();
      assert.ok(h.messages.includes(down), 'sibling still delivers downstream traffic');
      queue(3); h.sockets[2].open(); await flush();
      assert.equal(h.sockets[2].sent.length, 1, 'replacement OPEN is forwarded');
      assert.equal(h.api.state().lanes.size, 2);
      h.pagehide(); await flush(); assertClean(h);
    });
  }

  for (const state of ['connecting', 'closing', 'locally closed', 'remotely closed']) {
    test('diagnostics=' + diagnostics + ': opening failure retains bridge recovery when its only sibling is ' + state, async () => {
      const h = harness('websocket-lanes', false, diagnostics); h.api.setSession();
      for (const id of [1, 2]) {
        const data = new ArrayBuffer(8); new DataView(data).setUint32(0, 0x01000000 | id);
        h.api.queueWebSocketLane({ id, type: 1, data });
      }
      if (state !== 'connecting') { h.sockets[0].open(); await flush(); }
      if (state === 'closing') h.sockets[0].readyState = 2;
      if (state === 'locally closed') h.api.state().lanes.get(1).localClosed = true;
      if (state === 'remotely closed') h.api.state().lanes.get(1).remoteClosed = true;
      h.sockets[1].emit('error'); await flush();
      assert.equal(h.api.state().closed, true);
      assert.equal(h.messages.filter(value => value.state === 'failed').length, 1);
      assertClean(h);
    });
  }

}

for (const origin of ['client', 'server', 'transport']) {
  test('established lane records ' + origin + ' closure without failing the bridge', async () => {
    const h = harness('websocket-lanes'); h.api.setSession();
    const frame = type => { const data = new ArrayBuffer(8); new DataView(data).setUint32(0, (type << 24) | 7); return data; };
    h.api.queueWebSocketLane({ type: 1, id: 7, data: frame(1) });
    const socket = h.sockets[0]; socket.open(); await flush();
    await h.advance(1234);
    if (origin === 'client') h.api.queueWebSocketLane({ type: 3, id: 7, data: frame(3) });
    if (origin === 'server') socket.onmessage({ data: frame(3) });
    socket.readyState = 3;
    socket.onclose({ code: 1001, wasClean: true, reason: 'private reason text' });
    socket.onclose({ code: 1001, wasClean: true });
    await flush();
    const requests = h.requests.filter(request => request.url.endsWith('/api/v1/diagnostic'));
    assert.equal(requests.length, 1);
    const report = JSON.parse(requests[0].options.body);
    assert.equal(report.reason, 'ws_lane_closed_' + origin);
    assert.equal(report.close_code, 1001);
    assert.equal(report.was_clean, true);
    assert.equal(report.operation_ms, 1234);
    assert.equal(requests[0].options.body.includes('private'), false);
    assert.equal(h.api.state().closed, false);
    h.api.fail('carrier_queue', new Error('later failure')); await flush();
    assert.equal(h.requests.filter(request => request.url.endsWith('/api/v1/diagnostic')).length, 2);
    assertClean(h);
  });
}

test('lane diagnostic delivery failure cannot prevent lane cleanup', async () => {
  const h = harness('websocket-lanes'); h.api.setSession();
  const frame = new ArrayBuffer(8); new DataView(frame).setUint32(0, 0x01000007);
  h.api.queueWebSocketLane({ type: 1, id: 7, data: frame });
  h.sockets[0].open(); await flush();
  const fetch = h.sandbox.fetch;
  h.sandbox.fetch = (url, options) => { if (url.endsWith('/api/v1/diagnostic')) throw new Error('offline'); return fetch(url, options); };
  h.sockets[0].readyState = 3; h.sockets[0].emit('close'); await flush();
  assert.equal(h.api.state().closed, false);
  assert.equal(h.api.state().lanes.size, 0);
  h.pagehide(); await flush(); assertClean(h);
});

for (const carrier of carriers) {
  test(carrier + ': diagnostics are disabled by default without changing failure cleanup', async () => {
    const h = harness(carrier, false, false); h.api.setSession();
    if (carrier === 'websocket') {
      const pending = h.api.openWebSocket(); h.sockets[0].open(); await pending;
    } else if (carrier === 'websocket-lanes') {
      const data = new ArrayBuffer(8); new DataView(data).setUint32(0, 0x01000001);
      h.api.queueWebSocketLane({ id: 1, type: 1, data }); h.sockets[0].open(); await flush();
    }
    h.api.fail('carrier_queue', new Error('failure')); await flush();
    assert.equal(h.api.state().closed, true);
    assert.equal(h.messages.filter(value => value.state === 'failed').length, 1);
    assert.equal(h.requests.some(request => request.url.endsWith('/api/v1/diagnostic')), false);
    assert.equal(h.requests.filter(request => request.options.method === 'DELETE').length, 1);
    for (const socket of h.sockets) assert.equal(socket.closes.some(close => close.code === 4000), false);
    assertClean(h);
  });

  test(carrier + ': failure is reported once before native teardown without exception text', async () => {
    const h = harness(carrier); h.api.setSession();
    let reportedBeforeFailure = false;
    h.sandbox.testPort.postMessage = value => {
      if (value.state === 'failed') reportedBeforeFailure = h.requests.some(request => request.url.endsWith('/api/v1/diagnostic'));
    };
    await h.advance(1250);
    h.api.fail('carrier_queue', new TypeError('private-token https://example.invalid/?secret=private'), 9);
    h.api.fail('carrier_queue', new Error('second error'), 10);
    await flush();
    const requests = h.requests.filter(request => request.url.endsWith('/api/v1/diagnostic'));
    assert.equal(requests.length, 1);
    assert.equal(reportedBeforeFailure, true);
    const { options } = requests[0], report = JSON.parse(options.body);
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    assert.equal(options.keepalive, true);
    assert.equal(options.signal, undefined, 'cleanup must not abort diagnostic delivery');
    assert.equal(report.reason, 'carrier_queue');
    assert.equal(report.error, 'type_error');
    assert.equal(report.lane_id, 9);
    assert.equal(report.elapsed_ms, 1250);
    assert.ok(options.body.length <= 512);
    assert.equal(options.body.includes('private'), false);
    assert.equal(options.body.includes('test-token'), false);
    assert.equal(h.api.state().closed, true);
    assertClean(h);
  });

  test(carrier + ': failed session creation uses bootstrap authentication and records HTTP status', async () => {
    const h = harness(carrier);
    h.sandbox.respond = async () => new Response(null, { status: 400 });
    await h.api.createSession(new ArrayBuffer(8)); await flush();
    const request = h.requests.find(request => request.url.endsWith('/api/v1/diagnostic'));
    assert.ok(request);
    assert.match(request.options.headers.Authorization, /^Bearer [A-Za-z0-9_-]{43}$/);
    const report = JSON.parse(request.options.body);
    assert.equal(report.reason, 'session_create');
    assert.equal(report.error, 'session_rejected');
    assert.equal(report.http_status, 400);
    assert.equal(h.api.state().closed, true);
    assertClean(h);
  });

  test(carrier + ': diagnostic delivery failure cannot block cleanup', async () => {
    const h = harness(carrier); h.api.setSession();
    const fetch = h.sandbox.fetch;
    h.sandbox.fetch = (url, options) => {
      if (url.endsWith('/api/v1/diagnostic')) throw new TypeError('offline');
      return fetch(url, options);
    };
    h.api.fail('carrier_queue', new Error('failure')); await flush();
    assert.equal(h.api.state().closed, true);
    assert.equal(h.requests.filter(request => request.options.method === 'DELETE').length, 1);
    assertClean(h);
  });

  test(carrier + ': ordinary page closure does not report a failure', async () => {
    const h = harness(carrier); h.api.setSession(); h.pagehide(); await flush();
    assert.equal(h.requests.some(request => request.url.endsWith('/api/v1/diagnostic')), false);
    assertClean(h);
  });
}

test('WebSocket lane opening failure retains close code and operation duration', async () => {
  const h = harness('websocket-lanes'); h.api.setSession();
  const frame = new ArrayBuffer(8); new DataView(frame).setUint32(0, 0x01000007);
  h.api.queueWebSocketLane({ type: 1, id: 7, data: frame });
  await h.advance(40);
  const socket = h.sockets[0]; socket.readyState = 3;
  const event = new Event('close'); event.code = 1006; event.reason = 'private close reason';
  socket.onclose(event); socket.dispatchEvent(event); await flush();
  const request = h.requests.find(request => request.url.endsWith('/api/v1/diagnostic'));
  const report = JSON.parse(request.options.body);
  assert.equal(report.reason, 'ws_lane_open');
  assert.equal(report.error, 'ws_close');
  assert.equal(report.lane_id, 7);
  assert.equal(report.close_code, 1006);
  assert.equal(report.ready_state, 3);
  assert.equal(report.operation_ms, 40);
  assert.equal(request.options.body.includes('private'), false);
  assertClean(h);
});

for (const carrier of ['websocket', 'websocket-lanes']) {
  for (const delivery of ['pending', 'throws']) {
    test(carrier + ': close messages retain failure before native teardown when HTTP ' + delivery, async () => {
      const h = harness(carrier); h.api.setSession();
      if (carrier === 'websocket') {
        const opened = h.api.openWebSocket(); h.sockets[0].open(); await opened;
      } else {
        for (const id of [7, 8, 9]) {
          const data = new ArrayBuffer(8); new DataView(data).setUint32(0, 0x01000000 | id);
          h.api.queueWebSocketLane({ type: 1, id, data });
          if (id !== 9) h.sockets.at(-1).open();
        }
        await flush();
      }
      const active = h.sockets.filter(socket => socket.readyState === 1);
      const fetch = h.sandbox.fetch;
      h.sandbox.fetch = (url, options) => {
        if (url.endsWith('/api/v1/diagnostic')) {
          if (delivery === 'throws') throw new TypeError('private network error');
          return new Promise(() => {});
        }
        return fetch(url, options);
      };
      let observed = false;
      h.sandbox.testPort.postMessage = value => {
        if (value.state !== 'failed') return;
        for (const socket of active) {
          const { code, reason } = socket.closes[0];
          assert.equal(code, 4000);
          assert.ok(Buffer.byteLength(reason) <= 123);
          assert.deepEqual(JSON.parse(reason), { r: 'ws_lane_open', e: 'ws_close', l: 9, t: 10042, c: 1006, s: 0 });
          assert.equal(reason.includes('private'), false);
        }
        observed = true;
      };
      h.api.fail('ws_lane_open', Object.assign(new Error('websocket closed'), { operationMS: 10042, closeCode: 1006 }), 9);
      await flush();
      assert.equal(observed, true);
      assertClean(h);
    });
  }
}

test('failure close diagnostic stays within control frame size at numeric limits', async () => {
  const h = harness('websocket'); h.api.setSession();
  const opened = h.api.openWebSocket(); h.sockets[0].open(); await opened;
  h.api.fail('ws_lane_receive_type', Object.assign(new Error('carrier retry deadline reached'), { operationMS: 2592000000, closeCode: 4999 }), 16777215, h.sockets[0]);
  await flush();
  const reason = h.sockets[0].closes[0].reason;
  assert.ok(Buffer.byteLength(reason) <= 123);
  assert.equal(JSON.parse(reason).e, 'retry_deadline');
  assertClean(h);
});
