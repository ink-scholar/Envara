import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import test from 'node:test';
import { promisify } from 'node:util';
import { createProxyCompatibilityBridge } from '../electron/proxy-compatibility-bridge.mjs';

const fixtureAuth = `Basic ${Buffer.from('upstream-user:upstream-private-password').toString('base64')}`;
const localAuth = bridge => `Basic ${Buffer.from(`${bridge.username}:${bridge.password}`).toString('base64')}`;
const quietResolver = () => ({ resolve: async () => { throw new Error('Unexpected DNS request'); }, close() {} });
const execute = promisify(execFile);

async function tlsFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'envara-proxy-compatibility-tls-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const keyPath = join(directory, 'fixture.key');
  const certPath = join(directory, 'fixture.crt');
  await execute('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout', keyPath, '-out', certPath], { timeout: 10000, maxBuffer: 16384 });
  await Promise.all([chmod(keyPath, 0o600), chmod(certPath, 0o600)]);
  const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
  return { key, cert };
}

async function listen(t, server) {
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { for (const socket of sockets) socket.destroy(); server.close(resolve); }));
  return server.address().port;
}
async function fixture(t, handler, options = {}) {
  const attempts = []; const bodies = [];
  const server = http.createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks); bodies.push(body);
    await handler({ request, response, body });
  });
  server.on('connect', (request, socket, head) => { attempts.push({ target: request.url, auth: request.headers['proxy-authorization'], head }); handler({ request, socket, head }); });
  const port = await listen(t, server);
  const proxy = { protocol: 'http', host: '127.0.0.1', port, username: 'upstream-user', password: 'upstream-private-password' };
  const bridge = await createProxyCompatibilityBridge(proxy, { resolver: quietResolver(), ...options });
  t.after(() => bridge.close());
  return { bridge, attempts, bodies, server, proxy };
}
function reply(socket, status, headers = {}, body = '') {
  const bytes = Buffer.from(body);
  socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Length: ${bytes.length}\r\n${Object.entries(headers).map(([key, value]) => `${key}: ${value}\r\n`).join('')}\r\n${body}`);
}
async function raw(bridge, text) {
  const socket = net.connect(bridge.port, bridge.host); socket.on('error', () => {});
  await once(socket, 'connect'); const chunks = [];
  socket.on('data', chunk => chunks.push(chunk)); socket.write(text); await once(socket, 'close');
  return Buffer.concat(chunks);
}
function connectBytes(bridge, target = 'target.invalid:443', tail = Buffer.alloc(0)) {
  return Buffer.concat([Buffer.from(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: ${localAuth(bridge)}\r\n\r\n`), tail]);
}
function httpRequest(bridge, { target = 'http://target.invalid/path', method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: bridge.host, port: bridge.port, path: target, method,
      headers: { 'Proxy-Authorization': localAuth(bridge), ...headers }, agent: false });
    request.on('error', reject); request.on('response', response => {
      const chunks = []; response.on('data', chunk => chunks.push(chunk)); response.on('error', reject);
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks) }));
    }); request.end(body);
  });
}
async function until(predicate) {
  const deadline = performance.now() + 2000;
  while (!predicate()) { if (performance.now() > deadline) throw new Error('Fixture condition timed out'); await new Promise(resolve => setTimeout(resolve, 5)); }
}

test('HTTP preserves method, opaque path/query, end-to-end headers and body exactly once', async t => {
  const seen = [];
  const { bridge, bodies } = await fixture(t, ({ request, response, body }) => {
    seen.push({ path: request.url, method: request.method, headers: request.headers, body });
    response.writeHead(201, { 'X-Origin': 'kept', Connection: 'x-remove', 'X-Remove': 'secret-hop' }); response.end('created');
  });
  const result = await httpRequest(bridge, { target: 'http://target.invalid/a/../b%2Fc?signature=a%2Bb&x=1', method: 'POST', body: 'one-body',
    headers: { Connection: 'x-remove', 'X-Remove': 'secret-hop', Authorization: 'Bearer target-only', 'Content-Type': 'text/plain' } });
  assert.equal(result.status, 201); assert.equal(result.body.toString(), 'created'); assert.equal(result.headers['x-origin'], 'kept'); assert.equal(result.headers['x-remove'], undefined);
  assert.equal(seen.length, 1); assert.equal(bodies.length, 1); assert.equal(seen[0].path, 'http://target.invalid/a/../b%2Fc?signature=a%2Bb&x=1');
  assert.equal(seen[0].method, 'POST'); assert.equal(seen[0].body.toString(), 'one-body'); assert.equal(seen[0].headers.authorization, 'Bearer target-only');
  assert.equal(seen[0].headers['proxy-authorization'], fixtureAuth); assert.equal(seen[0].headers['x-remove'], undefined); assert.equal(seen[0].headers.host, 'target.invalid');
});

test('HTTP refusals, including POST 502, retain status and never invoke resolver or replay', async t => {
  for (const status of [401, 403, 407, 429, 502]) {
    const { bridge, bodies } = await fixture(t, ({ response }) => { response.writeHead(status, { 'Retry-After': '60' }); response.end('upstream refusal'); });
    const result = await httpRequest(bridge, { method: 'POST', body: 'non-idempotent' });
    assert.equal(result.status, status); if (status !== 407) assert.equal(result.headers['retry-after'], '60'); assert.equal(bodies.length, 1);
  }
});

test('CONNECT keeps hostname first, then at most two public IPv4s; target bytes wait for success', async t => {
  const diagnostic = []; const received = []; let resolveCalls = 0;
  const payload = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x04, 0xfa, 0x00, 0x81, 0xff]);
  const { bridge, attempts } = await fixture(t, ({ request, socket, head }) => {
    assert.equal(request.headers['proxy-authorization'], fixtureAuth); assert.equal(head.length, 0);
    if (request.url !== '8.8.4.4:443') return reply(socket, 502, {}, 'upstream DNS connection failed');
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    socket.once('data', chunk => { received.push(chunk); socket.end(chunk); });
  }, { onDiagnostic: value => diagnostic.push(value), resolver: { close() {}, async resolve(name, { signal, timeoutMs }) {
    resolveCalls++; assert.equal(name, 'target.invalid'); assert.equal(signal.aborted, false); assert.ok(timeoutMs > 0 && timeoutMs <= 10000);
    return { addresses: ['127.0.0.1', '8.8.8.8', '8.8.4.4', '1.1.1.1'], ttlMs: 1000 };
  } } });
  const response = await raw(bridge, connectBytes(bridge, undefined, payload));
  assert.match(response.toString('latin1'), /^HTTP\/1\.1 200 /);
  assert.deepEqual(response.subarray(response.indexOf('\r\n\r\n') + 4), payload);
  assert.equal(resolveCalls, 1); assert.deepEqual(attempts.map(item => item.target), ['target.invalid:443', '8.8.8.8:443', '8.8.4.4:443']);
  assert.deepEqual(Buffer.concat(received), payload); assert.equal(bridge.snapshot().recoveredConnections, 1);
  assert.deepEqual(diagnostic.map(item => item.status), [200]);
  assert.ok(diagnostic.every(item => Object.keys(item).sort().join() === 'code,recovery,stage,status'));
  assert.doesNotMatch(JSON.stringify(diagnostic), /target|8\.8|password|user/);
});

test('CONNECT 200 streams both opaque heads and remains alive beyond handshake deadline', async t => {
  const { bridge } = await fixture(t, ({ socket }) => {
    socket.write(Buffer.concat([Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n'), Buffer.from([0xff, 0x00])]));
    socket.on('data', chunk => socket.write(chunk));
  }, { connectTimeoutMs: 100 });
  const socket = net.connect(bridge.port, bridge.host); t.after(() => socket.destroy()); await once(socket, 'connect');
  const chunks = []; socket.on('data', chunk => chunks.push(chunk)); socket.write(connectBytes(bridge));
  await until(() => Buffer.concat(chunks).includes(Buffer.from([0xff, 0x00])));
  await new Promise(resolve => setTimeout(resolve, 130)); assert.equal(socket.destroyed, false);
  socket.write('still-opaque'); await until(() => Buffer.concat(chunks).includes(Buffer.from('still-opaque')));
});

test('only a complete non-policy 502 without Retry-After qualifies for CONNECT recovery', async t => {
  const cases = [
    [401, {}, ''], [403, {}, ''], [407, {}, ''], [429, {}, ''],
    [502, { 'Retry-After': '0' }, 'DNS failed'], [502, {}, 'Access denied by policy'],
    [502, { 'X-Squid-Error': 'ERR_ACCESS_DENIED' }, ''],
    [502, { 'Proxy-Status': 'proxy; error=destination_ip_prohibited' }, ''],
  ];
  for (const [status, headers, body] of cases) {
    let calls = 0;
    const { bridge, attempts } = await fixture(t, ({ socket }) => reply(socket, status, headers, body),
      { resolver: { close() {}, async resolve() { calls++; return { addresses: ['8.8.8.8'] }; } } });
    const response = await raw(bridge, connectBytes(bridge));
    assert.match(response.toString(), new RegExp(`^HTTP/1.1 ${status} `)); assert.equal(calls, 0); assert.equal(attempts.length, 1);
  }
});

test('second candidate 407/429/policy 502 is final and unsafe DNS answers cannot open a tunnel', async t => {
  for (const nextStatus of [407, 429, 502]) {
    const { bridge, attempts } = await fixture(t, ({ request, socket }) => reply(socket, request.url === 'target.invalid:443' ? 502 : nextStatus, {}, request.url === 'target.invalid:443' ? '' : 'blocked by policy'),
      { resolver: { close() {}, async resolve() { return { addresses: ['8.8.8.8', '8.8.4.4'] }; } } });
    const response = await raw(bridge, connectBytes(bridge)); assert.match(response.toString(), new RegExp(`^HTTP/1.1 ${nextStatus} `)); assert.equal(attempts.length, 2);
  }
  const { bridge, attempts } = await fixture(t, ({ socket }) => reply(socket, 502), { resolver: { close() {}, async resolve() { return { addresses: ['10.1.1.1', '127.0.0.1', '::1', '192.0.0.8', '169.254.1.2'] }; } } });
  assert.match((await raw(bridge, connectBytes(bridge))).toString(), /^HTTP\/1.1 502 /); assert.equal(attempts.length, 1);
});

test('IP-literal CONNECT failures do not invoke destination DNS', async t => {
  const { bridge, attempts } = await fixture(t, ({ socket }) => reply(socket, 502));
  assert.match((await raw(bridge, connectBytes(bridge, '8.8.8.8:443'))).toString(), /^HTTP\/1.1 502 /); assert.equal(attempts.length, 1);
});

test('missing, wrong and duplicate local credentials are refused before contacting upstream', async t => {
  const { bridge, attempts, bodies } = await fixture(t, () => assert.fail('unauthorized traffic reached upstream'));
  for (const headers of ['', 'Proxy-Authorization: Basic wrong\r\n', `Proxy-Authorization: ${localAuth(bridge)}\r\nProxy-Authorization: ${localAuth(bridge)}\r\n`]) {
    const result = await raw(bridge, `CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n${headers}\r\n`);
    assert.match(result.toString(), /^HTTP\/1.1 407 /);
  }
  const result = await raw(bridge, 'GET http://target.invalid/ HTTP/1.1\r\nHost: target.invalid\r\nConnection: close\r\n\r\n');
  assert.match(result.toString(), /^HTTP\/1.1 407 /); assert.equal(attempts.length, 0); assert.equal(bodies.length, 0);
});

test('strict destination, duplicate sensitive headers and early head byte bounds reject locally', async t => {
  const { bridge, attempts } = await fixture(t, () => assert.fail('invalid traffic reached upstream'), { maxConnectHeadBytes: 4 });
  for (const target of ['target.invalid', 'target.invalid:0', 'user@target.invalid:443', 'target.invalid:65536', 'target.invalid:0443', 'target.invalid:443/path', '[fe80::1%lo0]:443']) {
    assert.match((await raw(bridge, connectBytes(bridge, target))).toString(), /^HTTP\/1.1 400 /);
  }
  assert.match((await raw(bridge, connectBytes(bridge, undefined, Buffer.alloc(5)))).toString(), /^HTTP\/1.1 413 /);
  assert.equal(attempts.length, 0);
});

test('total CONNECT deadline aborts a pending resolver and close destroys owned tunnels and pending work', async t => {
  let aborted = false; let closed = 0;
  const resolver = { close() { closed++; }, resolve(_host, { signal }) { return new Promise((_resolve, reject) => {
    signal.addEventListener('abort', () => { aborted = true; reject(new Error('private resolver detail')); }, { once: true });
  }); } };
  const { bridge } = await fixture(t, ({ socket }) => reply(socket, 502), { resolver, connectTimeoutMs: 60 });
  const response = await raw(bridge, connectBytes(bridge)); assert.match(response.toString(), /^HTTP\/1.1 502 /); assert.equal(aborted, true);
  await bridge.close(); await bridge.close(); assert.equal(closed, 1); assert.equal(bridge.snapshot().pendingConnections, 0);
  await until(() => bridge.snapshot().ownedSockets === 0);

  const established = await fixture(t, ({ socket }) => socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'));
  const socket = net.connect(established.bridge.port, established.bridge.host); socket.on('error', () => {}); await once(socket, 'connect');
  socket.write(connectBytes(established.bridge)); await once(socket, 'data');
  const end = once(socket, 'close'); await established.bridge.close(); await end;
  await until(() => established.bridge.snapshot().ownedSockets === 0);
});

test('reusable local credentials remain distinct from upstream auth and never enter safe snapshots', async t => {
  const { bridge } = await fixture(t, ({ socket }) => reply(socket, 403), { credentials: { username: 'reused-user', password: 'reused-private-password' } });
  assert.equal(bridge.username, 'reused-user'); assert.equal(bridge.password, 'reused-private-password'); assert.equal(bridge.protocol, 'http');
  assert.match((await raw(bridge, connectBytes(bridge))).toString(), /^HTTP\/1.1 403 /);
  assert.doesNotMatch(JSON.stringify(bridge.snapshot()), /private|password|username|127\.0/);
});

test('limits and unsafe upstream settings fail without including supplied private values', async () => {
  const proxy = { protocol: 'http', host: '127.0.0.1', port: 12345, username: 'u', password: 'private-password' };
  for (const invalid of [{ ...proxy, protocol: 'socks5' }, { ...proxy, host: 'bad/private-password' }, { ...proxy, username: 'bad:user' }, { ...proxy, port: 0 }]) {
    await assert.rejects(createProxyCompatibilityBridge(invalid), error => error instanceof TypeError && !error.message.includes('private-password'));
  }
  for (const options of [{ maxConnections: 0 }, { upstreamAddress: '127.0.0.2' }, { localAddress: 'invalid' }, { earlyConnectAck: 'true' }, { credentials: { username: 'u', password: '' } }]) {
    await assert.rejects(createProxyCompatibilityBridge(proxy, options), TypeError);
  }
});

test('HTTPS upstream keeps original SNI and rejects an untrusted certificate without insecure fallback', async t => {
  const { key, cert } = await tlsFixture(t);
  const names = []; let hits = 0; let fatal = 0;
  const server = https.createServer({ key, cert, SNICallback(name, callback) { names.push(name); callback(null, tls.createSecureContext({ key, cert })); } });
  server.on('secureConnection', () => { hits++; });
  server.on('tlsClientError', () => {});
  server.on('connection', socket => socket.on('error', () => {}));
  server.addContext('localhost', { key, cert });
  server.on('tlsClientError', (_error, socket) => { if (socket.servername) names.push(socket.servername); });
  const port = await listen(t, server);
  const bridge = await createProxyCompatibilityBridge({ protocol: 'https', host: 'localhost', port }, {
    resolver: quietResolver(), onError: () => fatal++, connectTimeoutMs: 1000,
  });
  t.after(() => bridge.close());
  const response = await raw(bridge, connectBytes(bridge));
  assert.match(response.toString(), /^HTTP\/1\.1 502 /);
  assert.equal(hits, 0); assert.equal(fatal, 0);
  assert.equal(bridge.snapshot().lastErrorCode, 'TLS_FAILED');
  assert.ok(names.includes('localhost')); assert.ok(names.every(name => name === 'localhost'));
});

test('CONNECT request framing is rejected before dial and upstream auth challenges remain private', async t => {
  const { bridge, attempts } = await fixture(t, ({ socket }) => reply(socket, 407, { 'Proxy-Authenticate': 'Basic realm="upstream fixture"' }));
  for (const framing of ['Content-Length: 1', 'Transfer-Encoding: chunked']) {
    const bytes = `CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\nProxy-Authorization: ${localAuth(bridge)}\r\n${framing}\r\n\r\n`;
    assert.match((await raw(bridge, bytes)).toString(), /^HTTP\/1\.1 400 /);
  }
  assert.equal(attempts.length, 0);
  const response = await raw(bridge, connectBytes(bridge));
  assert.match(response.toString(), /^HTTP\/1\.1 407 /);
  assert.match(response.toString(), /proxy-authenticate: Basic realm="Envara"/i); assert.doesNotMatch(response.toString(), /upstream fixture/);
});

test('pending target bytes remain bounded, and closing during a proxy handshake leaves no owned socket', async t => {
  const { bridge, attempts } = await fixture(t, () => {}, { maxConnectHeadBytes: 4, connectTimeoutMs: 500 });
  const socket = net.connect(bridge.port, bridge.host); socket.on('error', () => {}); await once(socket, 'connect');
  const chunks = []; socket.on('data', chunk => chunks.push(chunk)); socket.write(connectBytes(bridge));
  await until(() => attempts.length === 1);
  socket.write(Buffer.alloc(5)); await once(socket, 'close');
  assert.match(Buffer.concat(chunks).toString(), /^HTTP\/1\.1 413 /);
  await until(() => bridge.snapshot().pendingConnections === 0);
  const waiting = net.connect(bridge.port, bridge.host); waiting.on('error', () => {}); await once(waiting, 'connect');
  waiting.resume(); waiting.write(connectBytes(bridge)); await until(() => attempts.length === 2);
  const end = once(waiting, 'close'); await bridge.close(); await end;
  await until(() => bridge.snapshot().ownedSockets === 0);
});

test('verified HTTPS upstream forwards HTTP and opaque CONNECT using its original SNI', async t => {
  const { key, cert } = await tlsFixture(t);
  const names = []; const targets = []; const seen = [];
  const server = https.createServer({ key, cert, SNICallback(name, callback) { names.push(name); callback(null, tls.createSecureContext({ key, cert })); } }, (request, response) => {
    seen.push(request.url); response.end('verified HTTP');
  });
  server.on('tlsClientError', () => {});
  server.on('connect', (request, socket, head) => {
    targets.push(request.url); assert.equal(head.length, 0);
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); socket.once('data', bytes => socket.end(bytes));
  });
  const port = await listen(t, server);
  const bridge = await createProxyCompatibilityBridge({ protocol: 'https', host: 'localhost', port }, { ca: cert, resolver: quietResolver(), localAddress: '127.0.0.1' });
  t.after(() => bridge.close());
  assert.equal((await httpRequest(bridge)).body.toString(), 'verified HTTP');
  const opaque = Buffer.from([0x16, 0x03, 0x04, 0xfe, 0xaa]);
  const result = await raw(bridge, connectBytes(bridge, undefined, opaque));
  assert.match(result.toString('latin1'), /^HTTP\/1\.1 200 /); assert.deepEqual(result.subarray(result.indexOf('\r\n\r\n') + 4), opaque);
  assert.deepEqual(seen, ['http://target.invalid/path']); assert.deepEqual(targets, ['target.invalid:443']); assert.deepEqual(names, ['localhost', 'localhost']);
});

test('unbounded or encoded CONNECT error bodies and oversized upstream headers never trigger recovery', async t => {
  const cases = [
    'HTTP/1.1 502 Bad Gateway\r\nConnection: keep-alive\r\n\r\n',
    'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 10000\r\n\r\n',
    'HTTP/1.1 502 Bad Gateway\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n',
    'HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
    `HTTP/1.1 502 Bad Gateway\r\nX-Large: ${'a'.repeat(17000)}\r\n\r\n`,
  ];
  for (const bytes of cases) {
    const { bridge, attempts } = await fixture(t, ({ socket }) => socket.write(bytes));
    assert.match((await raw(bridge, connectBytes(bridge))).toString(), /^HTTP\/1\.1 502 /); assert.equal(attempts.length, 1);
  }
});

test('pending request limits reject additional work and upstream transport errors are not fatal bridge failures', async t => {
  let fatal = 0;
  const { bridge, attempts } = await fixture(t, () => {}, { maxRequests: 1, connectTimeoutMs: 1000, onError: () => fatal++ });
  const pending = net.connect(bridge.port, bridge.host); pending.on('error', () => {}); pending.resume(); await once(pending, 'connect');
  pending.write(connectBytes(bridge)); await until(() => attempts.length === 1);
  assert.match((await raw(bridge, connectBytes(bridge))).toString(), /^HTTP\/1\.1 503 /); assert.equal(attempts.length, 1);
  pending.destroy(); await until(() => bridge.snapshot().pendingConnections === 0); assert.equal(fatal, 0);
});

test('private early ACK outlives a five-second upstream handshake without forwarding target bytes early', { timeout: 8000 }, async t => {
  const initial = Buffer.from([0x16, 0x03, 0x01, 0xfa]);
  const later = Buffer.from([0x00, 0x80, 0xff]);
  const expected = Buffer.concat([initial, later]); const received = [];
  let upstreamAck = false; let acceptUpstream;
  const { bridge, attempts } = await fixture(t, ({ socket, head }) => {
    assert.equal(head.length, 0);
    socket.on('data', chunk => {
      assert.equal(upstreamAck, true); received.push(chunk);
      if (Buffer.concat(received).length === expected.length) socket.end(Buffer.concat(received));
    });
    acceptUpstream = () => { upstreamAck = true; socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); };
  }, { earlyConnectAck: true, connectTimeoutMs: 7000 });
  const socket = net.connect(bridge.port, bridge.host); socket.on('error', () => {}); t.after(() => socket.destroy());
  await once(socket, 'connect'); const chunks = []; socket.on('data', chunk => chunks.push(chunk));
  const started = performance.now(); socket.write(connectBytes(bridge, undefined, initial));
  await until(() => Buffer.concat(chunks).includes(Buffer.from('\r\n\r\n')));
  assert.ok(performance.now() - started < 5000); assert.equal(upstreamAck, false); assert.equal(received.length, 0);
  socket.write(later); await until(() => attempts.length === 1);
  await new Promise(resolve => setTimeout(resolve, 5200));
  assert.equal(upstreamAck, false); assert.equal(received.length, 0); assert.equal(bridge.snapshot().pendingConnections, 1);
  acceptUpstream();
  await once(socket, 'close'); const result = Buffer.concat(chunks);
  assert.deepEqual(result.subarray(result.indexOf('\r\n\r\n') + 4), expected);
  assert.equal((result.toString('latin1').match(/HTTP\/1\.1 200 /g) ?? []).length, 1);
  assert.deepEqual(Buffer.concat(received), expected); assert.ok(performance.now() - started > 5000);
  assert.equal(bridge.snapshot().failedConnections, 0);
});

test('early ACK refuses invalid local requests before acknowledgement and never appends an HTTP refusal afterward', async t => {
  for (const status of [401, 403, 407, 429, 502]) {
    const { bridge, attempts } = await fixture(t, ({ socket }) => reply(socket, status,
      { 'Proxy-Authenticate': 'Basic realm="private-upstream"', 'Retry-After': '60' }, 'private upstream refusal body'), { earlyConnectAck: true });
    const result = await raw(bridge, connectBytes(bridge, undefined, Buffer.from([0x16, 0x03])));
    assert.equal(result.toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n');
    assert.equal(attempts[0].head.length, 0); assert.equal(attempts.length, 1);
    assert.equal(bridge.snapshot().failedConnections, 1); assert.equal(bridge.snapshot().lastUpstreamStatus, status);
    assert.equal(bridge.snapshot().lastErrorCode, status === 401 || status === 407 ? 'AUTH_REQUIRED' : status === 403 ? 'DENIED' : status === 429 ? 'RATE_LIMITED' : 'CONNECT_FAILED');
  }
  const { bridge, attempts } = await fixture(t, () => assert.fail('invalid early-ACK request reached upstream'), { earlyConnectAck: true });
  const missingAuth = await raw(bridge, 'CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\n\r\n');
  assert.match(missingAuth.toString(), /^HTTP\/1\.1 407 /); assert.doesNotMatch(missingAuth.toString(), /200 Connection/);
  assert.match((await raw(bridge, connectBytes(bridge, 'target.invalid:0'))).toString(), /^HTTP\/1\.1 400 /);
  assert.equal(attempts.length, 0);
});

test('early ACK timeout records the actual resolver phase/status and closes without TLS-stream HTTP bytes', async t => {
  const diagnostic = []; let aborted = false;
  const { bridge } = await fixture(t, ({ socket }) => reply(socket, 502), { earlyConnectAck: true, connectTimeoutMs: 60,
    onDiagnostic: value => diagnostic.push(value), resolver: { close() {}, resolve(_name, { signal }) {
      return new Promise((_resolve, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error('private resolver detail')); }, { once: true }));
    } } });
  const result = await raw(bridge, connectBytes(bridge, undefined, Buffer.from([0x16, 0x03])));
  assert.equal(result.toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n'); assert.equal(aborted, true);
  assert.equal(bridge.snapshot().failedConnections, 1); assert.equal(bridge.snapshot().lastUpstreamStatus, 502);
  assert.equal(bridge.snapshot().lastErrorCode, 'DESTINATION_DNS_FAILED');
  assert.deepEqual(diagnostic, [{ stage: 'resolve', status: 502, recovery: false, code: 'DESTINATION_DNS_FAILED' }]);
  await until(() => bridge.snapshot().pendingConnections === 0 && bridge.snapshot().ownedSockets === 0);
});

test('early ACK buffer overflow and normal bridge close discard all buffered bytes and pending sockets', async t => {
  const { bridge, attempts } = await fixture(t, () => {}, { earlyConnectAck: true, maxConnectHeadBytes: 4 });
  const socket = net.connect(bridge.port, bridge.host); socket.on('error', () => {}); await once(socket, 'connect');
  const chunks = []; socket.on('data', chunk => chunks.push(chunk)); socket.write(connectBytes(bridge));
  await until(() => attempts.length === 1 && chunks.length > 0);
  socket.write(Buffer.alloc(5)); await once(socket, 'close');
  assert.equal(Buffer.concat(chunks).toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n');
  assert.equal(attempts[0].head.length, 0); assert.equal(bridge.snapshot().failedConnections, 1);
  await until(() => bridge.snapshot().pendingConnections === 0 && bridge.snapshot().ownedSockets === 0);

  const pending = net.connect(bridge.port, bridge.host); pending.on('error', () => {}); await once(pending, 'connect');
  const data = []; pending.on('data', chunk => data.push(chunk)); pending.write(connectBytes(bridge, undefined, Buffer.alloc(4)));
  await until(() => attempts.length === 2 && data.length > 0);
  const end = once(pending, 'close'); await bridge.close(); await end;
  assert.equal(Buffer.concat(data).toString(), 'HTTP/1.1 200 Connection Established\r\n\r\n');
  assert.equal(bridge.snapshot().failedConnections, 1); await until(() => bridge.snapshot().ownedSockets === 0);
});
