import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { SocketReader, openSocksStream } from '../native/macos-local-routing/socks-stream.mjs';
import { validateDnsQuery, validateDnsResponse } from '../native/macos-local-routing/dns-wire.mjs';
import { ACCEPTANCE_IDENTIFIERS, createFixtureSocksServer, createUnboundLoopbackControl,
  inspectOwnedFixtureSocket, cleanupOwnedFixtureSocket, requestOwnedFixture, makeCachedFixtureDnsResponse,
  runMacOSAppProxyFixtureMatrix } from '../scripts/macos-app-proxy-fixture-matrix.mjs';

const diagnostic = result => ({ ready: false, acceptanceOnly: true, productionReceiptAllowed: false, ...result });
const routeId = () => randomUUID().toUpperCase();
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
function query(hostname, type = 1) {
  const labels = hostname.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)]));
  const header = Buffer.alloc(12); header.writeUInt16BE(2026); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4); tail.writeUInt16BE(type); tail.writeUInt16BE(1, 2);
  return Buffer.concat([header, ...labels, Buffer.from([0]), tail]);
}
async function dnsClient(proxy, bytes) {
  const socket = net.createConnection({ host: proxy.host, port: proxy.port }); socket.on('error', () => {});
  const reader = new SocketReader(socket, 8192);
  const timer = setTimeout(() => socket.destroy(), 2500);
  try {
    await once(socket, 'connect'); socket.write(Buffer.from([5, 1, 2])); assert.deepEqual(await reader.read(2), Buffer.from([5, 2]));
    const username = Buffer.from(proxy.username), password = Buffer.from(proxy.password);
    socket.write(Buffer.concat([Buffer.from([1, username.length]), username, Buffer.from([password.length]), password]));
    assert.deepEqual(await reader.read(2), Buffer.from([1, 0]));
    socket.write(Buffer.from([5, 1, 0, 1, 1, 1, 1, 1, 0, 53]));
    assert.deepEqual(await reader.read(10), Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
    const prefix = Buffer.alloc(2); prefix.writeUInt16BE(bytes.length); socket.write(Buffer.concat([prefix, bytes]));
    const length = (await reader.read(2)).readUInt16BE(0); return await reader.read(length);
  } finally { clearTimeout(timer); if (reader.pending) reader.fail(new Error('closed')); try { reader.release(); } catch {} socket.destroy(); }
}
async function roundtrip(proxy, { port = 44441, halfClose = false, payload = Buffer.alloc(2048, 0x41) } = {}) {
  const { socket, buffered } = await openSocksStream(proxy, { host: '198.51.100.42', port }, 1500);
  assert.equal(buffered.length, 0); socket.on('error', () => {});
  const chunks = [];
  try {
    const result = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { socket.destroy(); reject(new Error('echo deadline')); }, 1500);
      const finish = () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); };
      socket.on('data', data => { chunks.push(data); if (!halfClose && Buffer.concat(chunks).length >= payload.length) finish(); });
      socket.once('end', finish); socket.once('error', error => { clearTimeout(timer); reject(error); });
    });
    if (halfClose) socket.end(payload); else socket.write(payload);
    socket.resume(); return await result;
  } finally { socket.destroy(); }
}

test('local authenticated SOCKS answers exact reserved echo and preserves upload half-close', async () => {
  const proxy = await createFixtureSocksServer({ slot: 'one', ttlMs: 10000, dnsDelayMs: 0 });
  try {
    assert.deepEqual(await roundtrip(proxy.route), Buffer.alloc(2048, 0x41));
    assert.deepEqual(await roundtrip(proxy.route, { port: 44442, halfClose: true }), Buffer.alloc(2048, 0x41));
    assert.equal(proxy.snapshot().authenticated, 2); assert.equal(proxy.snapshot().echoPayloadBytes, 2048); assert.equal(proxy.snapshot().halfClosePayloadBytes, 2048);
  } finally { assert.equal(await proxy.close(), true); }
});

test('local SOCKS refuses wrong credentials and arbitrary remote destinations without opening a remote socket', async () => {
  const proxy = await createFixtureSocksServer({ slot: 'one', ttlMs: 10000, dnsDelayMs: 0 });
  try {
    await assert.rejects(openSocksStream({ ...proxy.route, password: 'wrong' }, { host: '198.51.100.42', port: 44441 }, 1500));
    await assert.rejects(openSocksStream(proxy.route, { host: '8.8.8.8', port: 44441 }, 1500));
    assert.equal(proxy.snapshot().echoConnections, 0); assert.equal(proxy.snapshot().rejected, 2);
  } finally { await proxy.close(); }
});

test('synthetic DNS A/AAAA answers differ by route and carry validated 30-second TTL', async () => {
  const proxies = await Promise.all(['one', 'two'].map(slot => createFixtureSocksServer({ slot, ttlMs: 10000, dnsDelayMs: 0 })));
  try {
    const hostname = 'isolated.envara-fixture.test';
    const replies = [];
    for (const proxy of proxies) {
      proxy.allowHostname(hostname);
      for (const type of [1, 28]) {
        const asked = query(hostname, type), response = await dnsClient(proxy.route, asked), descriptor = validateDnsQuery(asked);
        validateDnsResponse(response, descriptor); assert.equal(response.readUInt32BE(descriptor.questionEnd + 6), 30); replies.push(response);
      }
      assert.equal(proxy.snapshot().dnsAReplies, 1); assert.equal(proxy.snapshot().dnsAAAAReplies, 1);
    }
    assert.notDeepEqual(replies[0], replies[2]); assert.notDeepEqual(replies[1], replies[3]);
    const unknown = await dnsClient(proxies[0].route, query('not-owned.envara-fixture.test')).catch(() => null);
    assert.equal(unknown, null); assert.equal(proxies[0].snapshot().invalidDnsQueries, 1);
    assert.throws(() => makeCachedFixtureDnsResponse(query(hostname), { address4: '203.0.113.42', address6: '2001:db8::42', ttl: 0 }));
  } finally { await Promise.all(proxies.map(proxy => proxy.close())); }
});

test('private core closes pending authenticated flow, expires listener, and enforces connection budget', async () => {
  const proxy = await createFixtureSocksServer({ slot: 'one', ttlMs: 10000, maximumConnections: 1, dnsDelayMs: 0 });
  const { socket } = await openSocksStream(proxy.route, { host: '198.51.100.42', port: 44443 }, 1500); socket.on('error', () => {});
  socket.resume(); socket.write(Buffer.alloc(2048));
  assert.equal(await proxy.waitForHeldPayload({ timeoutMs: 1000 }), true);
  await assert.rejects(openSocksStream(proxy.route, { host: '198.51.100.42', port: 44441 }, 1500));
  const ended = once(socket, 'end'); assert.equal(await proxy.stopCore(), true); await ended; socket.destroy();
  await assert.rejects(openSocksStream(proxy.route, { host: '198.51.100.42', port: 44441 }, 500));
  const expiring = await createFixtureSocksServer({ slot: 'two', ttlMs: 200, dnsDelayMs: 0 }); await wait(250);
  assert.equal(expiring.snapshot().closed, true); await assert.rejects(openSocksStream(expiring.route, { host: '198.51.100.42', port: 44441 }, 500)); await expiring.close();
});

test('unbound controller control preserves existing and new local connections', async () => {
  const control = await createUnboundLoopbackControl();
  try { assert.equal(await control.existing(), true); assert.equal(await control.fresh(), true); assert.equal(await control.existing(), true); }
  finally { assert.equal(await control.close(), true); }
});

function simulatedHarness(options = {}) {
  const calls = [], entries = new Map(), proxies = [], removed = [], realm = { one: routeId(), two: routeId() }; let nextPID = 60000;
  const createProxy = async ({ slot }) => {
    const counters = { authenticated: 0, echoPayloadBytes: 0, halfClosePayloadBytes: 0, udpCommands: 0, dnsAReplies: 0, dnsAAAAReplies: 0, closed: false };
    const seen = new Set(); let heldResolve;
    const proxy = { slot, route: { protocol: 'socks5', host: '127.0.0.1', port: 50000 + proxies.length, username: 'private', password: 'runtime', udp: false, udpPolicy: 'block' },
      answers: slot === 'one' ? ['203.0.113.42', '2001:db8::42'] : ['203.0.113.43', '2001:db8::43'],
      allowHostname: () => {}, snapshot: () => ({ ...counters }),
      close: async () => { counters.closed = true; heldResolve?.(options.zeroReply ? { ok: true, sentBytes: 2048, receivedBytes: 0, payloadBase64: '', matches: false, eof: true } : { ok: false, code: 'PROBE_TRANSPORT_FAILED' }); return true; },
      waitForHeldPayload: async () => true, counters, seen, hold: () => new Promise(resolve => { heldResolve = resolve; }),
    }; proxy.stopCore = proxy.close; proxies.push(proxy); return proxy;
  };
  const call = async (method, params) => {
    calls.push({ method, params });
    if (method === 'status') return diagnostic({ authorized: options.authorized !== false, extensionEnabled: true, ...ACCEPTANCE_IDENTIFIERS, fixtures: ['one', 'two'], ...(options.status || {}) });
    if (method === 'prepareFixture') {
      if (options.prepareError) throw Object.assign(new Error('not logged'), { code: 'PREPARE_UNCERTAIN' });
      const id = routeId(), entry = { slot: params.fixture, proxy: proxies.find(value => value.route.port === params.route.port), pid: nextPID++, routeId: id, vpnUUID: realm[params.fixture] };
      entries.set(id, entry); return diagnostic({ routeId: id, vpnUUID: entry.vpnUUID });
    }
    const entry = entries.get(params.routeId); assert.ok(entry);
    if (method === 'launchFixture') return diagnostic({ pid: entry.pid, sessionId: routeId(), socketPath: `/private/tmp/envara-ac-Fake00/acceptance-${entry.routeId}.sock` });
    if (method === 'stopFixture') return diagnostic({ stopped: options.stopConfirmed !== false });
    if (method === 'revokeFixture') return diagnostic({ revoked: true, mappingRetained: options.mappingRetained !== false });
    throw new Error('unexpected method');
  };
  const requestFixture = async (launch, request) => {
    const entry = entries.get(launch.routeId), child = request.op === 'child_probe', inner = child ? request.request : request;
    const pid = child ? request.pid : entry.pid;
    const base = { id: request.id, op: inner.op, pid, ok: true };
    let result;
    if (inner.op === 'status') result = { ...base, protocolVersion: 1, fixtureIdentity: 'envara-routing-acceptance-fixture', bundleIdentifier: `io.envara.routing.fixture.${entry.slot}`,
      parentPID: child ? entry.pid : 50000, child, maximumLifetimeSeconds: 120, children: [], unverifiedChildren: [], ownedChildScopeVerified: true, nativeRoutingAcceptance: false };
    else if (inner.op === 'spawn_child') result = { ...base, childPID: entry.pid + 100, childStartedSeconds: 2026, childStartedMicroseconds: 123 };
    else if (inner.op === 'udp') result = { ...base, ok: false, code: 'PROBE_TIMEOUT' };
    else if (inner.op === 'tcp') {
      if (entry.proxy.counters.closed) result = options.zeroReply ? { ...base, sentBytes: 2048, receivedBytes: 0, payloadBase64: '', matches: false, eof: true } : { ...base, ok: false, code: 'PROBE_TRANSPORT_FAILED' };
      else {
        entry.proxy.counters.authenticated++; const bytes = Buffer.from(inner.payloadBase64, 'base64');
        if (inner.port === 44443) result = { ...base, ...await entry.proxy.hold() };
        else {
          entry.proxy.counters[inner.halfClose ? 'halfClosePayloadBytes' : 'echoPayloadBytes'] += bytes.length;
          result = { ...base, matches: true, sentBytes: bytes.length, receivedBytes: bytes.length, payloadBase64: inner.payloadBase64, eof: inner.halfClose, halfClose: inner.halfClose };
        }
      }
    } else if (inner.op === 'resolve') {
      if (!entry.proxy.seen.has(inner.host) || options.neverWarm) { entry.proxy.counters.dnsAReplies++; entry.proxy.counters.dnsAAAAReplies++; entry.proxy.seen.add(inner.host); }
      const coalesced = options.coalescedAnswers && entry.slot === 'two' && !inner.host.includes('-two.');
      result = { ...base, systemGetaddrinfo: true, resolved: true, addresses: coalesced ? proxies[0].answers : entry.proxy.answers };
    } else throw new Error('unexpected request');
    return child ? { id: request.id, op: request.op, pid: entry.pid, ok: true, childResult: result } : result;
  };
  const dependencies = { call, createProxy, requestFixture,
    createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => true }),
    inspectSocket: async (socketPath, id) => ({ socketPath, routeId: id, directoryIdentity: {}, socketIdentity: {} }),
    cleanupSocket: async token => { removed.push(token.routeId); return true; }, evidenceMode: 'simulation' };
  return { dependencies, calls, proxies, removed, entries };
}

test('unsigned, disabled, or wrong diagnostic identity refuses before all listeners and route mutations', async () => {
  for (const options of [{ authorized: false }, { status: { extensionEnabled: false } }, { status: { ready: true } }, { status: { providerIdentifier: 'org.other.extension' } }]) {
    const mock = simulatedHarness(options); const report = await runMacOSAppProxyFixtureMatrix(mock.dependencies);
    assert.equal(report.fixtureProcessesStarted, false); assert.equal(mock.proxies.length, 0); assert.deepEqual(mock.calls.map(call => call.method), ['status']);
    assert.ok(report.error); assert.equal(report.productionReady, false); assert.equal(report.nativeAcceptancePassed, false);
  }
});

test('modeled orchestration covers two realms, independent child probes, same-name warm cache, failure and same-realm rebind', async () => {
  const mock = simulatedHarness(), report = await runMacOSAppProxyFixtureMatrix(mock.dependencies);
  assert.equal(report.error, undefined); assert.equal(report.testedFixtureSubsetPassed, true); assert.equal(report.cleanup.complete, true);
  assert.equal(report.routes.length, 3); assert.equal(report.routes[0].vpnUUID, report.routes[2].vpnUUID); assert.notEqual(report.routes[0].vpnUUID, report.routes[1].vpnUUID);
  assert.equal(report.checks.one_child_halfClose.passed, true); assert.equal(report.checks.two_concurrentSameHostname.passed, true);
  assert.equal(report.checks.two_child_warmDNS_2.servedWithoutNewOwnCoreQuery, true); assert.equal(report.checks.coreFailureExistingFlow.passed, true); assert.equal(report.checks.sameRealmRebind.passed, true);
  assert.equal(report.checks.one_parent_udpBlock.passed, false); assert.equal(report.checks.one_parent_udpBlock.boundedRefusalObserved, true);
  assert.equal(Object.values(report.nativeChecks).some(Boolean), false); assert.equal(report.productionReceiptAllowed, false); assert.equal(report.nativeAcceptancePassed, false);
  assert.equal(mock.removed.length, 3); assert.ok(mock.calls.filter(call => call.method === 'stopFixture' || call.method === 'revokeFixture').every(call => mock.entries.has(call.params.routeId)));
});

test('modeled same-name cross-realm coalescing fails cache evidence rather than reporting native DNS success', async () => {
  const mock = simulatedHarness({ coalescedAnswers: true }), report = await runMacOSAppProxyFixtureMatrix(mock.dependencies);
  assert.equal(report.checks.two_parent_isolatedDNS.passed, true); assert.equal(report.checks.two_concurrentSameHostname.passed, false);
  assert.equal(report.checks.two_child_warmDNS_2.passed, false); assert.equal(report.testedFixtureSubsetPassed, false); assert.equal(report.nativeChecks.sameHostnameCache, false);
  assert.equal(report.cleanup.complete, true);
});

test('modeled repeat resolutions without a cache hit do not prove the warm-cache fixture scope', async () => {
  const mock = simulatedHarness({ neverWarm: true }), report = await runMacOSAppProxyFixtureMatrix(mock.dependencies);
  assert.equal(report.checks.two_parent_warmDNS_2.passed, true); assert.equal(report.checks.two_parent_warmDNS_2.servedWithoutNewOwnCoreQuery, false);
  assert.equal(report.fixtureWarmCacheObserved, false); assert.equal(report.testedFixtureSubsetPassed, false); assert.equal(report.nativeChecks.sameHostnameCache, false);
});

test('modeled core closure with EOF and zero reply counts as refusal, without claiming direct packet capture', async () => {
  const mock = simulatedHarness({ zeroReply: true }), report = await runMacOSAppProxyFixtureMatrix(mock.dependencies);
  assert.equal(report.checks.coreFailureExistingFlow.passed, true); assert.equal(report.checks.coreFailureNewFlow.passed, true);
  assert.equal(report.checks.coreFailureNewFlow.directPacketCapturePerformed, false); assert.equal(report.checks.coreFailureNewFlow.ownCoreNewPayloadBytes, 0);
  assert.equal(report.productionReady, false); assert.equal(report.nativeAcceptancePassed, false);
});

test('failed prepare retains unknown mutation and unconfirmed stop never revokes or removes a route', async () => {
  const prepare = simulatedHarness({ prepareError: true }), first = await runMacOSAppProxyFixtureMatrix(prepare.dependencies);
  assert.equal(first.error, 'PREPARE_UNCERTAIN'); assert.equal(first.cleanup.uncertainMutation, true); assert.equal(first.cleanup.complete, false);
  assert.equal(first.cleanup.localServersClosed, true); assert.equal(prepare.calls.some(call => call.method === 'launchFixture'), false);
  const stop = simulatedHarness({ stopConfirmed: false }), second = await runMacOSAppProxyFixtureMatrix(stop.dependencies);
  assert.equal(second.cleanup.complete, false); assert.equal(stop.calls.some(call => call.method === 'revokeFixture'), false); assert.equal(stop.removed.length, 0);
  assert.ok(second.cleanup.routeResults.every(result => result.error === 'FIXTURE_EXIT_UNVERIFIED'));
});

test('an unauthorized profile cannot borrow readiness or receipt from a status result', async () => {
  const mock = simulatedHarness({ status: { productionReceiptAllowed: true } }), report = await runMacOSAppProxyFixtureMatrix(mock.dependencies);
  assert.equal(report.error, 'INVALID_ACCEPTANCE_RESULT'); assert.equal(mock.proxies.length, 0);
});

test('private fixture IPC checks ownership, response identity, deadline and conservative file cleanup', { skip: process.platform !== 'darwin' }, async () => {
  const id = routeId(), directory = await fs.mkdtemp('/private/tmp/envara-ac-'), socketPath = path.join(directory, `acceptance-${id}.sock`);
  await fs.chmod(directory, 0o700); let behavior = 'valid'; const connections = new Set();
  const server = net.createServer(socket => {
    connections.add(socket); socket.once('close', () => connections.delete(socket)); socket.on('error', () => {});
    socket.once('data', bytes => {
      const request = JSON.parse(bytes.toString()); if (behavior === 'silent') return;
      const response = { id: request.id, op: request.op, pid: behavior === 'wrongPID' ? 124 : 123, ok: true };
      socket.end(behavior === 'oversized' ? Buffer.alloc(8193, 65) : JSON.stringify(response) + '\n' + (behavior === 'multiple' ? '{}\n' : ''));
    });
  });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); }); await fs.chmod(socketPath, 0o600);
    const token = await inspectOwnedFixtureSocket(socketPath, id), launch = { pid: 123, routeId: id, socketPath, socketToken: token };
    assert.equal((await requestOwnedFixture(launch, { id: 'status1', op: 'status' })).ok, true);
    behavior = 'wrongPID'; await assert.rejects(requestOwnedFixture(launch, { id: 'status2', op: 'status' }), error => error.code === 'FIXTURE_RESPONSE_REJECTED');
    behavior = 'multiple'; await assert.rejects(requestOwnedFixture(launch, { id: 'multiple', op: 'status' }), error => error.code === 'FIXTURE_RESPONSE_REJECTED');
    behavior = 'oversized'; await assert.rejects(requestOwnedFixture(launch, { id: 'oversized', op: 'status' }), error => error.code === 'FIXTURE_RESPONSE_SIZE_LIMIT');
    behavior = 'silent'; await assert.rejects(requestOwnedFixture(launch, { id: 'status3', op: 'status' }, { timeoutMs: 50 }), error => error.code === 'FIXTURE_DEADLINE');
    assert.equal(await cleanupOwnedFixtureSocket(token, { exitConfirmed: false }), false); assert.equal((await fs.lstat(socketPath)).isSocket(), true);
    const foreign = path.join(directory, 'preserve-user-file'); await fs.writeFile(foreign, 'owned by test, not cleanup token');
    for (const socket of connections) socket.destroy(); await new Promise(resolve => server.close(resolve));
    assert.equal(await cleanupOwnedFixtureSocket(token, { exitConfirmed: true }), false); assert.equal(await fs.readFile(foreign, 'utf8'), 'owned by test, not cleanup token');
    await fs.unlink(foreign); assert.equal(await cleanupOwnedFixtureSocket(token, { exitConfirmed: true }), true);
  } finally {
    for (const socket of connections) socket.destroy(); if (server.listening) await new Promise(resolve => server.close(resolve));
    // Only this test-created known file/directory are removed; no recursive rm.
    await fs.unlink(path.join(directory, 'preserve-user-file')).catch(() => {}); await fs.unlink(socketPath).catch(() => {}); await fs.rmdir(directory).catch(() => {});
  }
});

test('private socket paths reject traversal, arbitrary locations, loose permissions and symlink aliases', { skip: process.platform !== 'darwin' }, async () => {
  const id = routeId();
  for (const value of ['/tmp/envara-ac-123456/acceptance-' + id + '.sock', '/private/tmp/other/acceptance-' + id + '.sock', '/private/tmp/envara-ac-123456/../acceptance-' + id + '.sock']) {
    await assert.rejects(inspectOwnedFixtureSocket(value, id), error => error.code === 'FIXTURE_SOCKET_REJECTED');
  }
  const directory = await fs.mkdtemp('/private/tmp/envara-ac-'); await fs.chmod(directory, 0o755);
  try { await assert.rejects(inspectOwnedFixtureSocket(path.join(directory, `acceptance-${id}.sock`), id), error => error.code === 'FIXTURE_SOCKET_REJECTED'); }
  finally { await fs.rmdir(directory); }
  const original = await fs.mkdtemp('/private/tmp/envara-ac-'), alias = await fs.mkdtemp('/private/tmp/envara-ac-');
  await fs.chmod(original, 0o700); await fs.rmdir(alias); await fs.symlink(original, alias);
  try { await assert.rejects(inspectOwnedFixtureSocket(path.join(alias, `acceptance-${id}.sock`), id), error => error.code === 'FIXTURE_SOCKET_REJECTED'); }
  finally { await fs.unlink(alias); await fs.rmdir(original); }
});
