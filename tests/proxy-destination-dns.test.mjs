import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import dns from 'node:dns';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { createProxyDestinationResolver, destinationDNSQuestion, isPublicDestinationIPv4,
  parseDestinationDNSAnswer, PROXY_DESTINATION_DOH_ENDPOINTS } from '../electron/proxy-destination-dns.mjs';

const proxy = { protocol: 'https', host: 'upstream.example.test', port: 8443, username: 'fixture-user', password: 'fixture-secret' };
const unavailable = error => error.code === 'PROXY_DESTINATION_DNS_UNAVAILABLE';
const invalid = error => error.code === 'PROXY_DESTINATION_DNS_INVALID_RESPONSE';
const wireName = name => Buffer.concat([...name.split('.').flatMap(label => [Buffer.from([label.length]), Buffer.from(label)]), Buffer.from([0])]);
function answer(query, { records = [{ address: '93.184.215.14', ttl: 60 }], flags = 0x8180, questionType = 1, questionClass = 1, extra = [] } = {}) {
  const header = Buffer.from(query.subarray(0, 12)), question = Buffer.from(query.subarray(12));
  header.writeUInt16BE(flags, 2); header.writeUInt16BE(records.length, 6); header.writeUInt16BE(extra.length, 10);
  question.writeUInt16BE(questionType, question.length - 4); question.writeUInt16BE(questionClass, question.length - 2);
  const record = ({ owner, address, alias, ttl = 60, type = alias ? 5 : 1, klass = 1, data }) => {
    const bytes = data ?? (alias ? wireName(alias) : Buffer.from(address.split('.').map(Number))), fields = Buffer.alloc(10);
    fields.writeUInt16BE(type, 0); fields.writeUInt16BE(klass, 2); fields.writeUInt32BE(ttl, 4); fields.writeUInt16BE(bytes.length, 8);
    return Buffer.concat([owner === '' ? Buffer.from([0]) : owner ? wireName(owner) : Buffer.from([0xc0, 0x0c]), fields, bytes]);
  };
  return Buffer.concat([header, question, ...records.map(record), ...extra.map(record)]);
}

test('DNS answer binds ID, question, class, A records and one unambiguous CNAME chain with the minimum TTL', () => {
  const question = destinationDNSQuestion('Checkout.Example.Test.');
  assert.equal(question.name, 'checkout.example.test');
  assert.deepEqual(parseDestinationDNSAnswer(answer(question.bytes, { records: [
    { alias: 'cdn.example.test', ttl: 11 },
    { owner: 'cdn.example.test', address: '1.1.1.1', ttl: 60 },
    { owner: 'cdn.example.test', address: '8.8.8.8', ttl: 15 },
    { owner: 'cdn.example.test', address: '9.9.9.9', ttl: 30 },
    { owner: 'unrelated.test', address: '127.0.0.1', ttl: 1 },
  ] }), question), { addresses: ['1.1.1.1', '8.8.8.8'], ttlMs: 11000 });
  for (const ttl of [0, 2147483648]) assert.equal(parseDestinationDNSAnswer(answer(question.bytes, { records: [{ address: '1.1.1.1', ttl }] }), question).ttlMs, 0);
  const cases = [
    packet => { packet[0] ^= 1; return packet; },
    packet => { packet[13] ^= 1; return packet; },
    () => answer(question.bytes, { questionType: 28 }),
    () => answer(question.bytes, { questionClass: 3 }),
    () => answer(question.bytes, { flags: 0x8380 }),
    () => answer(question.bytes, { flags: 0x8183 }),
    packet => { packet.writeUInt16BE(129, 6); return packet; },
    packet => packet.subarray(0, packet.length - 1),
    packet => Buffer.concat([packet, Buffer.from([0])]),
    () => Buffer.alloc(16385),
    () => answer(question.bytes, { records: [] }),
    () => answer(question.bytes, { records: [{ owner: 'other.test', address: '1.1.1.1' }] }),
    () => answer(question.bytes, { records: [{ address: '1.1.1.1', klass: 3 }] }),
    () => answer(question.bytes, { records: [{ alias: 'a.test' }, { alias: 'b.test' }, { owner: 'a.test', address: '1.1.1.1' }] }),
    () => answer(question.bytes, { records: [{ alias: question.name }, { address: '1.1.1.1' }] }),
    () => answer(question.bytes, { records: [{ alias: 'a.test' }, { owner: 'a.test', alias: question.name }] }),
    () => answer(question.bytes, { records: [{ type: 5, data: Buffer.from([0xc0, 0xff]) }] }),
    () => answer(question.bytes, { extra: [{ owner: '', type: 41, ttl: 1 << 24, data: Buffer.alloc(0) }] }),
    () => answer(question.bytes, { extra: [{ owner: '', type: 41, ttl: 1 << 16, data: Buffer.alloc(0) }] }),
    () => answer(question.bytes, { extra: [{ owner: '', type: 41, ttl: 0, data: Buffer.from([0, 1, 0, 1]) }] }),
  ];
  for (const alter of cases) assert.throws(() => parseDestinationDNSAnswer(alter(answer(question.bytes)), question), invalid);
});

test('only ordinary public IPv4 answers are eligible; invalid input never starts a transport', async () => {
  const question = destinationDNSQuestion('checkout.example.test');
  for (const address of ['127.0.0.1', '10.0.0.1', '100.64.0.1', '169.254.1.1', '192.0.0.8', '192.168.1.1', '198.18.0.1', '203.0.113.42', '0.0.0.0', '224.0.0.1']) {
    assert.equal(isPublicDestinationIPv4(address), false, address);
    assert.throws(() => parseDestinationDNSAnswer(answer(question.bytes, { records: [{ address }] }), question), invalid);
    assert.throws(() => parseDestinationDNSAnswer(answer(question.bytes, { records: [{ address }, { address: '1.1.1.1' }] }), question), invalid);
  }
  for (const address of [null, undefined, '::1', '2001:4860:4860::8888', 'invalid']) assert.equal(isPublicDestinationIPv4(address), false);
  let calls = 0;
  const resolver = createProxyDestinationResolver(proxy, { transport: () => { calls++; } });
  for (const host of ['', '127.0.0.1', '::1', 'bad\n.test', 'a/b', '-bad.test', '.bad', `${'a'.repeat(64)}.test`]) {
    await assert.rejects(resolver.resolve(host), { code: 'PROXY_DESTINATION_DNS_INVALID_HOST' });
  }
  assert.equal(calls, 0); resolver.close();
  for (const route of [null, { ...proxy, protocol: 'socks5' }, { ...proxy, username: 'a:b' }, { ...proxy, port: 0 }]) {
    assert.throws(() => createProxyDestinationResolver(route), { code: 'PROXY_DESTINATION_DNS_INVALID_OPTIONS' });
  }
});

test('the first valid peer wins; fixed endpoints use selected proxy auth and cancel losing transports', async () => {
  const calls = [];
  const resolver = createProxyDestinationResolver(proxy, { transport: async options => {
    calls.push(options);
    if (options.url === PROXY_DESTINATION_DOH_ENDPOINTS[0]) return answer(options.question, { flags: 0x8183 });
    await delay(5); return answer(options.question);
  } });
  assert.deepEqual(await resolver.resolve('checkout.example.test'), { addresses: ['93.184.215.14'], ttlMs: 60000 });
  assert.deepEqual(calls.map(call => call.url), PROXY_DESTINATION_DOH_ENDPOINTS);
  assert.equal(calls.every(call => call.signal.aborted), true);
  assert.equal(calls.every(call => call.agent.proxy.host === 'upstream.example.test:8443'), true);
  assert.equal(calls.every(call => call.agent.proxyHeaders()['Proxy-Authorization'] === `Basic ${Buffer.from('fixture-user:fixture-secret').toString('base64')}`), true);
  assert.equal(calls.every(call => !call.agent.proxy.href.includes('fixture-secret')), true);
  resolver.close();
});

test('route-local bounded cache honors shortest TTL, HTTP Age, zero TTL and maximum TTL', async () => {
  let now = 1000, calls = 0, ttl = 60, age = 59;
  const options = { nowMs: () => now, transport: params => { calls++; return { bytes: answer(params.question, { records: [{ address: '1.1.1.1', ttl }] }), ageSeconds: age }; } };
  const resolver = createProxyDestinationResolver(proxy, options);
  assert.equal((await resolver.resolve('cached.test')).ttlMs, 1000); assert.equal(calls, 2);
  now += 500;
  const cached = await resolver.resolve('CACHED.TEST.'); assert.equal(cached.ttlMs, 500); cached.addresses[0] = '127.0.0.1';
  assert.equal((await resolver.resolve('cached.test')).addresses[0], '1.1.1.1'); assert.equal(calls, 2);
  now += 500; await resolver.resolve('cached.test'); assert.equal(calls, 4);
  age = 60;
  assert.equal((await resolver.resolve('aged.test')).ttlMs, 0); await resolver.resolve('aged.test'); assert.equal(calls, 8);
  ttl = 0; age = 0; await resolver.resolve('zero.test'); await resolver.resolve('zero.test'); assert.equal(calls, 12);
  ttl = 3600; assert.equal((await resolver.resolve('bounded.test')).ttlMs, 300000);
  const secondRoute = createProxyDestinationResolver({ ...proxy, password: 'other-secret' }, options);
  await secondRoute.resolve('cached.test'); assert.equal(calls, 16);
  resolver.close(); secondRoute.close();
});

test('negative backoff and bounded LRU prevent repeated failed requests and unbounded cache growth', async () => {
  let now = 0, calls = 0, fail = true;
  const resolver = createProxyDestinationResolver(proxy, { maxEntries: 2, nowMs: () => now, negativeTtlMs: 100,
    transport: params => { calls++; if (fail) throw new Error('fixture-secret private URL'); return answer(params.question); } });
  await assert.rejects(resolver.resolve('a.test'), unavailable); await assert.rejects(resolver.resolve('a.test'), unavailable); assert.equal(calls, 2);
  now = 100; fail = false;
  await resolver.resolve('a.test'); await resolver.resolve('b.test'); await resolver.resolve('a.test'); await resolver.resolve('c.test'); assert.equal(calls, 8);
  await resolver.resolve('b.test'); assert.equal(calls, 10);
  resolver.close();
});

test('deduplicated callers cancel independently; the last cancellation aborts all owned work', async () => {
  const calls = []; let release;
  const gate = new Promise(resolve => { release = resolve; });
  const resolver = createProxyDestinationResolver(proxy, { transport: async params => { calls.push(params); await gate; return answer(params.question); } });
  const controller = new AbortController();
  const cancelled = resolver.resolve('shared.test', { signal: controller.signal }), kept = resolver.resolve('shared.test');
  await delay(1); controller.abort(); await assert.rejects(cancelled, { code: 'PROXY_DESTINATION_DNS_ABORTED' });
  assert.equal(calls.length, 2); assert.equal(calls.every(call => !call.signal.aborted), true);
  release(); assert.equal((await kept).addresses[0], '93.184.215.14'); resolver.close();
  const pendingCalls = [], cancelledResolver = createProxyDestinationResolver(proxy, { transport: params => { pendingCalls.push(params); return new Promise(() => {}); } });
  const last = new AbortController(), pending = cancelledResolver.resolve('cancelled.test', { signal: last.signal });
  await delay(1); last.abort(); await assert.rejects(pending, { code: 'PROXY_DESTINATION_DNS_ABORTED' });
  assert.equal(pendingCalls.every(call => call.signal.aborted), true); cancelledResolver.close();
});

test('hard deadlines, close and concurrency limits bound hung providers without leaking their errors', async () => {
  const calls = [], resolver = createProxyDestinationResolver(proxy, { timeoutMs: 100, maxInflight: 1,
    transport: params => { calls.push(params); return new Promise(() => {}); } });
  const pending = resolver.resolve('hung.test', { timeoutMs: 20 });
  await assert.rejects(resolver.resolve('extra.test'), unavailable);
  const at = Date.now(); await assert.rejects(pending, { code: 'PROXY_DESTINATION_DNS_TIMEOUT' });
  assert.ok(Date.now() - at < 500); assert.equal(calls.every(call => call.signal.aborted), true);
  const closing = resolver.resolve('closing.test'); await delay(1); resolver.close();
  await assert.rejects(closing, { code: 'PROXY_DESTINATION_DNS_CLOSED' });
  await assert.rejects(resolver.resolve('closed.test'), { code: 'PROXY_DESTINATION_DNS_CLOSED' });
  const rejecting = createProxyDestinationResolver(proxy, { transport: () => { throw new Error('https://fixture-user:fixture-secret@private.invalid'); } });
  await assert.rejects(rejecting.resolve('hidden.test'), error => unavailable(error) && !/fixture|hidden|private/.test(error.message)); rejecting.close();
});

test('entry address override retains original proxy TLS identity and never handles DoH host DNS', async () => {
  const calls = [], resolver = createProxyDestinationResolver(proxy, { upstreamAddress: '93.184.215.14', localAddress: '192.0.2.10', transport: params => { calls.push(params); return answer(params.question); } });
  await resolver.resolve('checkout.test');
  const options = calls[0].agent.connectOpts;
  assert.equal(options.servername, proxy.host); assert.equal(options.rejectUnauthorized, true); assert.equal(options.localAddress, '192.0.2.10'); assert.equal(options.family, 4);
  options.lookup(proxy.host, { all: true }, (error, value) => { assert.ifError(error); assert.deepEqual(value, [{ address: '93.184.215.14', family: 4 }]); });
  options.lookup('cloudflare-dns.com', {}, error => assert.equal(error.code, 'PROXY_DESTINATION_DNS_UNAVAILABLE'));
  resolver.close();
  for (const options of [{ upstreamAddress: '127.0.0.1' }, { upstreamAddress: '198.18.0.1' }, { localAddress: '::1' }]) {
    assert.throws(() => createProxyDestinationResolver(proxy, options), { code: 'PROXY_DESTINATION_DNS_INVALID_OPTIONS' });
  }
});

// Generate one ephemeral certificate per test process. Keep both fixed DNS
// endpoint names so the actual nested TLS connections still verify identity.
let certificatePromise;
function fixtureCertificate() {
  certificatePromise ??= (async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-destination-dns-tls-'));
    try {
      const keyPath = path.join(directory, 'fixture.key'), certPath = path.join(directory, 'fixture.crt');
      await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes',
        '-keyout', keyPath, '-out', certPath, '-subj', '/CN=cloudflare-dns.com',
        '-addext', 'subjectAltName=DNS:cloudflare-dns.com,DNS:dns.google,DNS:localhost,IP:127.0.0.1'], { timeout: 10000, maxBuffer: 16384 });
      const [key, cert] = await Promise.all([readFile(keyPath, 'utf8'), readFile(certPath, 'utf8')]);
      return { key, cert };
    } finally { await rm(directory, { recursive: true, force: true }); }
  })();
  return certificatePromise;
}

async function listen(server, own) {
  const sockets = new Set();
  server.on('connection', socket => { own(socket); sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  // HTTPS has a separate TLS wrapper; CONNECT releases its HTTP error owner.
  server.on('secureConnection', own);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, sockets };
}

async function fixture(t, { protocol = 'http', proxyHost = '127.0.0.1', response = (query, reply) => { reply.writeHead(200, { 'Content-Type': 'application/dns-message' }); reply.end(answer(query)); }, handshake } = {}) {
  const { key, cert } = await fixtureCertificate();
  let targetHits = 0; const observations = [], servers = [], resolvers = [], connections = new Map(), errors = [];
  const own = socket => {
    if (connections.has(socket)) return socket;
    connections.set(socket, new Promise(resolve => socket.once('close', () => { connections.delete(socket); resolve(); })));
    socket.on('error', error => {
      // A winning answer cancels the other peer. Other errors remain failures.
      if (!['ECONNRESET', 'EPIPE'].includes(error.code)) errors.push(error);
      socket.destroy();
    });
    return socket;
  };
  t.after(async () => {
    for (const resolver of resolvers) resolver.close();
    const listenersClosed = servers.map(server => new Promise(resolve => server.close(resolve)));
    const pending = [...connections];
    for (const [socket] of pending) socket.unpipe();
    // Close TLS before its raw socket so no wrapper writes to a released fd.
    for (const [socket] of pending.filter(([socket]) => socket.encrypted)) socket.destroy();
    for (const [socket] of pending) socket.destroy();
    await Promise.all([...listenersClosed, ...pending.map(([, closed]) => closed)]);
    assert.deepEqual(errors, [], 'fixture connection errors');
  });
  const target = https.createServer({ key, cert }, (request, reply) => {
    targetHits++; const chunks = [];
    assert.equal(request.method, 'POST'); assert.equal(request.url, '/dns-query'); assert.equal(request.headers['content-type'], 'application/dns-message');
    request.on('data', chunk => chunks.push(chunk)); request.on('end', () => response(Buffer.concat(chunks), reply));
  });
  servers.push(target);
  const destination = await listen(target, own), server = protocol === 'https' ? https.createServer({ key, cert }) : http.createServer();
  servers.push(server);
  server.on('connect', (request, socket, head) => {
    observations.push({ host: request.url, auth: request.headers['proxy-authorization'], servername: socket.servername });
    if (handshake) { socket.resume(); socket.once('end', () => socket.end()); return handshake(socket); }
    assert.equal(head.length, 0);
    const remote = own(net.connect(destination.port, '127.0.0.1', () => { socket.write('HTTP/1.1 200 Connection Established\r\n\r\n'); socket.pipe(remote); remote.pipe(socket); }));
    remote.on('error', () => socket.destroy());
    socket.once('close', () => { socket.unpipe(remote); remote.unpipe(socket); remote.destroy(); });
  });
  const upstream = await listen(server, own);
  return { resolver: options => {
    const resolver = createProxyDestinationResolver({ protocol, host: proxyHost, port: upstream.port, username: 'fixture-user', password: 'fixture-secret' }, { ca: cert, timeoutMs: 500, ...options });
    resolvers.push(resolver); return resolver;
  },
    observations, hits: () => targetHits, sockets: upstream.sockets };
}

for (const protocol of ['http', 'https']) test(`real DNS-wire HTTPS uses authenticated ${protocol} proxy CONNECT and never system target DNS`, async t => {
  const local = await fixture(t, { protocol });
  const originalLookup = dns.lookup, previousNoProxy = process.env.NO_PROXY;
  dns.lookup = () => { throw new Error('system DNS forbidden in fixture'); }; process.env.NO_PROXY = '*';
  t.after(() => { dns.lookup = originalLookup; if (previousNoProxy == null) delete process.env.NO_PROXY; else process.env.NO_PROXY = previousNoProxy; });
  const resolver = local.resolver(); t.after(() => resolver.close());
  assert.deepEqual(await resolver.resolve('checkout.example.test'), { addresses: ['93.184.215.14'], ttlMs: 60000 });
  assert.equal(local.hits() > 0, true);
  assert.deepEqual(local.observations.map(item => item.host).sort(), ['cloudflare-dns.com:443', 'dns.google:443']);
  assert.equal(local.observations.every(item => item.auth === `Basic ${Buffer.from('fixture-user:fixture-secret').toString('base64')}`), true);
});

test('IPv4 source binding chooses IPv4 proxy resolution while preserving HTTPS proxy SNI', async t => {
  const local = await fixture(t, { protocol: 'https', proxyHost: 'localhost' }), originalLookup = dns.lookup, families = [];
  dns.lookup = (hostname, options, callback) => {
    assert.equal(hostname, 'localhost'); families.push(options.family);
    // Deterministically emulate a host resolver that prefers IPv6 otherwise.
    callback(null, options.family === 4 ? '127.0.0.1' : '::1', options.family === 4 ? 4 : 6);
  };
  t.after(() => { dns.lookup = originalLookup; });
  const resolver = local.resolver({ localAddress: '127.0.0.1' }); t.after(() => resolver.close());
  assert.equal((await resolver.resolve('bound-source.test')).addresses[0], '93.184.215.14');
  assert.deepEqual(families, [4, 4]);
  assert.equal(local.observations.every(item => item.servername === 'localhost'), true);
});

test('real transport subtracts HTTP Age and rejects malformed or duplicate Age headers', async t => {
  for (const age of ['59', '60', '61', 'invalid', ['1', '2']]) {
    const local = await fixture(t, { response: (query, reply) => {
      reply.writeHead(200, { 'Content-Type': 'application/dns-message', Age: age }); reply.end(answer(query));
    } });
    const resolver = local.resolver();
    if (age === 'invalid' || Array.isArray(age)) await assert.rejects(resolver.resolve('age.test'), unavailable);
    else assert.equal((await resolver.resolve('age.test')).ttlMs, age === '59' ? 1000 : 0);
    resolver.close();
  }
});

test('bounded proxy headers, origin headers/body, auth refusal, redirects and wrong content types fail closed', async t => {
  const cases = [
    { handshake: socket => socket.end('HTTP/1.1 502 Bad Gateway\r\nX-Oversize: ' + 'a'.repeat(9000) + '\r\n\r\n') },
    { handshake: socket => socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n') },
    { response: (_query, reply) => { reply.writeHead(200, { 'Content-Type': 'application/dns-message', 'X-Oversize': 'a'.repeat(9000) }); reply.end('x'); } },
    { response: (_query, reply) => { reply.writeHead(200, { 'Content-Type': 'application/dns-message' }); reply.end(Buffer.alloc(16385)); } },
    { response: (_query, reply) => { reply.writeHead(302, { Location: 'https://outside.invalid/' }); reply.end(); } },
    { response: (query, reply) => { reply.writeHead(200, { 'Content-Type': 'application/json' }); reply.end(answer(query)); } },
  ];
  for (const options of cases) {
    const local = await fixture(t, options), resolver = local.resolver();
    await assert.rejects(resolver.resolve('rejected.test'), unavailable); resolver.close();
    assert.equal(local.observations.length, 2); if (options.handshake) assert.equal(local.hits(), 0);
  }
});

test('untrusted proxy TLS fails before CONNECT; hung handshakes and body streams close owned sockets', async t => {
  const untrusted = await fixture(t, { protocol: 'https' }), denied = untrusted.resolver({ ca: undefined });
  await assert.rejects(denied.resolve('tls.test'), unavailable); assert.equal(untrusted.observations.length, 0); denied.close();
  for (const options of [{ handshake: () => {} }, { response: () => {} }]) {
    const local = await fixture(t, options), resolver = local.resolver({ timeoutMs: 40 });
    await assert.rejects(resolver.resolve('hung.test'), error => ['PROXY_DESTINATION_DNS_TIMEOUT', 'PROXY_DESTINATION_DNS_UNAVAILABLE'].includes(error.code));
    resolver.close(); await delay(20); assert.equal(local.sockets.size, 0);
  }
});
