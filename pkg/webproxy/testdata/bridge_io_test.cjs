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

function harness(carrier, smallBatch = false) {
  const html = readFileSync(join(process.env.TELEGO_BRIDGE_FIXTURES, carrier + (smallBatch ? '.small.html' : '.html')), 'utf8');
  const match = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html);
  assert.ok(match, 'rendered script exists');
  let now = 0, nextTimer = 0;
  const timers = new Map(), sockets = [], events = new Map(), messages = [], requests = [];
  class Socket extends EventTarget {
    static CONNECTING = 0; static OPEN = 1; static CLOSED = 3;
    readyState = Socket.CONNECTING; bufferedAmount = 0; sent = []; closeCalls = 0;
    constructor(url, protocol) { super(); this.url = url; this.protocol = protocol; sockets.push(this); }
    emit(type, data) {
      const event = new Event(type);
      if (data !== undefined) event.data = data;
      this['on' + type]?.(event);
      this.dispatchEvent(event);
    }
    open() { this.readyState = Socket.OPEN; this.emit('open'); }
    close() { this.closeCalls++; this.readyState = Socket.CLOSED; }
    send(data) { assert.equal(this.readyState, Socket.OPEN); this.sent.push(data); }
  }
  const sandbox = {
    ArrayBuffer, Uint8Array, DataView, AbortController, DOMException, URL,
    Date: class extends Date { static now() { return now; } },
    WebSocket: Socket, queueMicrotask,
    location: { hash: '', pathname: '/' }, history: { replaceState() {} }, parent: {},
    addEventListener(name, callback) { events.set(name, callback); },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { at: now + delay, callback }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) {
      requests.push({ url, options });
      if (options.method === 'DELETE') return Promise.resolve(new Response(null, { status: 204 }));
      return sandbox.respond(url, options);
    },
    respond() { throw new Error('unexpected fetch'); },
    testPort: { postMessage(value) { messages.push(value); }, close() {}, start() {} },
  };
  // Expose existing functions only inside the test VM. Production exports stay unchanged.
  const hooks = `
globalThis.bridgeTest={request,options,close,createSession,activatePort,poll,pollLane,ensureLane,
  state:()=>({closed,sessionToken,queuedBytes,queuedItems,lanes,downCursor}),
  signal:lifecycleController.signal,
  setSession:()=>{sessionToken='test-token';port=globalThis.testPort},
  ${carrier.startsWith('websocket') ? 'openWebSocket,queueWebSocketLane,' : ''}
};\n`;
  const script = match[1].replace(/\}\)\(\);\s*$/, hooks + '})();');
  assert.notEqual(script, match[1], 'test hooks were inserted');
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  const h = {
    api: sandbox.bridgeTest, sandbox, sockets, timers, messages, requests,
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
  await h.advance(2 * budget);
  assert.equal(h.sockets[1].closeCalls, 0);
  h.pagehide(); await flush(); assertClean(h);
});
