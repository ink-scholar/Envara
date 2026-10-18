/** Real bundled-core transport checks, exclusively against owned loopback fixtures. */
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { ProxyCoreManager } from '../electron/proxy-core-manager.mjs';
import { createProxyCompatibilityBridge } from '../electron/proxy-compatibility-bridge.mjs';
import { terminalFenceProfile } from '../electron/terminal-network-fence.mjs';
import { openSocksStream } from '../native/macos-local-routing/socks-stream.mjs';
import { createFixtureSocksServer } from './macos-app-proxy-fixture-matrix.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.umask(0o077);
const runDir = await mkdtemp(path.join(os.tmpdir(), 'envara-ordinary-proxy-'));
const checks = [], managers = [], fixtures = [], pids = [], bridges = [], resolverStates = [];
const observations = {};
const check = name => { checks.push(name); console.log(`PASS ${name}`); };
const credentials = { username: randomBytes(12).toString('hex'), password: randomBytes(24).toString('hex') };
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const listen = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; };
const sockets = new Set();
const track = socket => { sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket; };
let directConnections = 0;
const directCanary = net.createServer(socket => { directConnections++; socket.destroy(); });
const canaryPort = await listen(directCanary);
const target = { host: '127.0.0.1', port: canaryPort };

async function httpFixture(tlsOptions) {
  let authenticated = 0, rejected = 0;
  const server = tlsOptions ? https.createServer(tlsOptions) : http.createServer();
  server.on('connection', track); server.on('tlsClientError', () => {});
  server.on('connect', (request, socket, head) => {
    const valid = request.headers['proxy-authorization'] === `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`;
    if (!valid || request.url !== `127.0.0.1:${canaryPort}`) { rejected++; socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n'); return; }
    authenticated++; socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    // Echo in the upstream itself. The reachable destination is a canary:
    // it must receive zero connections, including after authentication fails.
    socket.on('data', data => socket.write(data)); if (head.length) socket.write(head);
  });
  const port = await listen(server);
  const fixture = { proxy: { protocol: tlsOptions ? 'https' : 'http', host: '127.0.0.1', port, ...credentials },
    snapshot: () => ({ authenticated, rejected }), close: async () => { for (const socket of sockets) socket.destroy(); if (server.listening) await new Promise(resolve => server.close(resolve)); } };
  fixtures.push(fixture); return fixture;
}

function manager({ certificate, resolverFactory } = {}) {
  const instance = new ProxyCoreManager({ dataDir: path.join(runDir, `manager-${managers.length}`), resourcesDir: path.join(root, 'build/proxy-core'),
    startupTimeoutMs: 5000, stopTimeoutMs: 1000,
    async createCompatibilityBridge(settings, options) {
      assert.equal(settings.host, '127.0.0.1', 'This smoke may only contact its own numeric-loopback upstreams');
      const state = { calls: 0, closed: 0 };
      const custom = resolverFactory?.();
      const resolver = { async resolve(host, parameters) {
        state.calls++;
        if (!custom) throw new Error('UNEXPECTED_FIXTURE_DNS');
        return await custom.resolve(host, parameters);
      }, close() { state.closed++; custom?.close?.(); } };
      resolverStates.push(state);
      // This CA is trusted only by the real bridge's fixture TLS hop; no core
      // config rewrite, host trust change, or certificate bypass is involved.
      const bridge = await createProxyCompatibilityBridge(settings, { ...options, resolver, ...(certificate ? { ca: certificate } : {}) });
      bridges.push(bridge); return bridge;
    },
    spawn(binary, args, options) {
      const config = JSON.parse(readFileSync(args[3], 'utf8'));
      assert.equal(config.proxies.length, 1); assert.equal(config.proxies[0].server, '127.0.0.1');
      if (config.proxies[0].type === 'http') assert.equal(config.proxies[0].tls, false, 'TLS must terminate at the fixture compatibility bridge');
      const child = process.platform === 'darwin'
        ? spawn('/usr/bin/sandbox-exec', ['-p', terminalFenceProfile(), binary, ...args], options)
        : spawn(binary, args, options);
      pids.push(child.pid); return child;
    },
  });
  managers.push(instance); return instance;
}

function reply(socket, status, body = '') {
  const bytes = Buffer.from(body);
  socket.end(Buffer.concat([Buffer.from(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Length: ${bytes.length}\r\n\r\n`), bytes]));
}

/** Public candidates remain CONNECT text: this fixture never dials them. */
async function recoveryFixture() {
  const hostname = 'checkout.ordinary-proxy.invalid', candidates = ['8.8.8.8', '8.8.4.4'];
  const attempts = [], plainPosts = [];
  const expectedBody = randomBytes(48).toString('hex'), responseBody = randomBytes(48).toString('hex');
  const targetPayload = Buffer.from(`POST /checkout%2Fsession?signature=a%2Bb HTTP/1.1\r\nHost: ${hostname}\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(expectedBody)}\r\nConnection: close\r\n\r\n${expectedBody}`);
  let postCount = 0, acceptedBytes = 0, fixtureFailure = false;
  const server = http.createServer((request, response) => {
    const parts = []; let bytes = 0;
    request.on('data', chunk => { bytes += chunk.length; if (bytes > 4096) request.destroy(); else parts.push(chunk); });
    request.on('end', () => {
      const body = Buffer.concat(parts);
      if (request.headers['proxy-authorization'] !== `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`) {
        fixtureFailure = true; response.writeHead(407); response.end(); return;
      }
      plainPosts.push({ method: request.method, target: request.url, body: body.toString() });
      response.writeHead(502, { 'Content-Length': '0', Connection: 'close' }); response.end();
    });
  });
  server.on('connection', track);
  server.on('connect', (request, socket, head) => {
    const attempt = { target: request.url, headBytes: head.length, payloadBytes: 0 };
    attempts.push(attempt);
    if (request.headers['proxy-authorization'] !== `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`) {
      fixtureFailure = true; reply(socket, 407); return;
    }
    if ([`${hostname}:${canaryPort}`, `${candidates[0]}:${canaryPort}`].includes(request.url)) {
      socket.on('data', bytes => { attempt.payloadBytes += bytes.length; });
      reply(socket, 502, 'upstream DNS connection failed'); return;
    }
    if (request.url !== `${candidates[1]}:${canaryPort}`) { fixtureFailure = true; reply(socket, 403); return; }
    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const parts = []; let length = 0, replied = false;
    const consume = bytes => {
      attempt.payloadBytes += bytes.length; acceptedBytes += bytes.length; parts.push(bytes); length += bytes.length;
      if (length > targetPayload.length || replied) { fixtureFailure = true; socket.destroy(); return; }
      if (length !== targetPayload.length) return;
      if (!Buffer.concat(parts).equals(targetPayload)) { fixtureFailure = true; socket.destroy(); return; }
      postCount++; replied = true; reply(socket, 201, responseBody);
    };
    socket.on('data', consume); if (head.length) consume(head);
  });
  const port = await listen(server);
  const fixture = { proxy: { protocol: 'http', host: '127.0.0.1', port, ...credentials }, hostname, candidates, targetPayload, responseBody,
    snapshot: () => ({ attempts: attempts.map(value => ({ ...value })), plainPosts: [...plainPosts], postCount, acceptedBytes, fixtureFailure }),
    close: async () => { for (const socket of sockets) socket.destroy(); if (server.listening) await new Promise(resolve => server.close(resolve)); } };
  fixtures.push(fixture); return fixture;
}

async function exchange(proxy, bytes, timeoutMs = 4000) {
  const socket = track(net.connect(proxy.port, proxy.host));
  try {
    await once(socket, 'connect');
    return await new Promise((resolve, reject) => {
      let settled = false, length = 0; const chunks = [];
      const timer = setTimeout(() => finish(new Error('FIXTURE_EXCHANGE_TIMEOUT')), timeoutMs);
      const finish = error => {
        if (settled) return; settled = true; clearTimeout(timer);
        error ? reject(error) : resolve(Buffer.concat(chunks));
      };
      socket.on('data', chunk => { length += chunk.length; if (length > 65536) finish(new Error('FIXTURE_RESPONSE_BOUND')); else chunks.push(chunk); });
      socket.once('error', () => finish(new Error('FIXTURE_EXCHANGE_CLOSED')));
      socket.once('end', () => finish()); socket.once('close', () => finish());
      socket.write(bytes);
    });
  } finally { socket.destroy(); }
}

async function recoveredPost(manager, fixture, id, resolverDelayMs = 0) {
  const wire = await manager.ensure({ ...fixture.proxy, id });
  const localAuth = Buffer.from(`${wire.username}:${wire.password}`).toString('base64');
  // The mixed listener may send its own 200 early: only the complete origin
  // response and exact body counter establish end-to-end recovery here.
  const before = performance.now();
  const response = await exchange(wire, Buffer.concat([Buffer.from(`CONNECT ${fixture.hostname}:${canaryPort} HTTP/1.1\r\nHost: ${fixture.hostname}:${canaryPort}\r\nProxy-Authorization: Basic ${localAuth}\r\n\r\n`), fixture.targetPayload]), resolverDelayMs + 5000);
  const elapsedMs = Math.round(performance.now() - before);
  assert.match(response.toString(), /^HTTP\/1\.1 200 /);
  const origin = response.subarray(response.indexOf('\r\n\r\n') + 4);
  if (!/^HTTP\/1\.1 201 /.test(origin.toString())) throw Object.assign(new Error('Fixture target response missing'), { code: 'RECOVERY_ORIGIN_MISSING', elapsedMs });
  assert.equal(origin.subarray(origin.indexOf('\r\n\r\n') + 4).toString(), fixture.responseBody);
  const state = fixture.snapshot();
  assert.equal(state.fixtureFailure, false); assert.equal(state.postCount, 1); assert.equal(state.acceptedBytes, fixture.targetPayload.length);
  assert.deepEqual(state.attempts.map(item => item.target), [fixture.hostname, ...fixture.candidates].map(host => `${host}:${canaryPort}`));
  assert.ok(state.attempts.slice(0, 2).every(item => item.headBytes === 0 && item.payloadBytes === 0));
  assert.equal(manager.routes.get(id).compatibilityBridge.snapshot().recoveredConnections, 1);
  assert.equal(directConnections, 0);
  return { elapsedMs, postCount: state.postCount, acceptedBytes: state.acceptedBytes, failedAttemptsPayloadBytes: 0 };
}

async function echo(wire, destination = target) {
  const payload = randomBytes(256);
  const { socket, buffered } = await openSocksStream({ ...wire, protocol: 'socks5' }, destination, 2000);
  try {
    const data = await new Promise((resolve, reject) => {
      let received = buffered;
      const timer = setTimeout(() => { reject(new Error('ECHO_TIMEOUT')); socket.destroy(); }, 2000);
      const finish = error => { clearTimeout(timer); error ? reject(error) : resolve(received); };
      socket.once('error', finish); socket.once('end', () => finish(new Error('ECHO_CLOSED')));
      socket.on('data', chunk => { received = Buffer.concat([received, chunk]); if (received.length >= payload.length) finish(); });
      socket.write(payload); socket.resume();
    });
    assert.deepEqual(data, payload);
  } finally { socket.destroy(); }
}

function fixtureResolver(fixture, delayMs = 0) {
  let calls = 0, closed = 0;
  return { snapshot: () => ({ calls, closed }),
    factory: () => ({ async resolve(host, { signal, timeoutMs }) {
      calls++; assert.equal(host, fixture.hostname); assert.equal(signal.aborted, false);
      assert.ok(timeoutMs > delayMs, 'The real bridge must retain enough budget for the delayed resolver');
      if (delayMs) await delay(delayMs, undefined, { signal });
      return { addresses: [...fixture.candidates], ttlMs: 1000 };
    }, close() { closed++; } }) };
}

let operationFailure = null, cleanupFailure = null, phase = 'ordinary-routes';

try {
  const owned = manager(), httpProxy = await httpFixture();
  let wire = await owned.ensure({ ...httpProxy.proxy, id: 'fixture-http' });
  await echo(wire); assert.equal(httpProxy.snapshot().authenticated, 1); assert.equal(directConnections, 0);
  assert.equal(owned.routingIdentity('fixture-http').nodeType, 'http');
  check('Authenticated HTTP CONNECT upstream carries application SOCKS traffic through the owned core');
  const beforeWrongListener = httpProxy.snapshot().authenticated;
  await assert.rejects(echo({ ...wire, password: 'wrong-owned-listener-secret' }));
  assert.equal(httpProxy.snapshot().authenticated, beforeWrongListener);
  check('Wrong private listener credentials never reach the upstream');
  wire = await owned.ensure({ ...httpProxy.proxy, id: 'fixture-http', password: 'wrong-upstream-secret' });
  await assert.rejects(echo(wire)); assert.ok(httpProxy.snapshot().rejected > 0); assert.equal(directConnections, 0);
  check('HTTP upstream authentication refusal cannot fall back to the reachable direct canary');
  wire = await owned.ensure({ ...httpProxy.proxy, id: 'fixture-http' }); await echo(wire);
  await httpProxy.close(); await assert.rejects(echo(wire)); assert.equal(directConnections, 0);
  check('HTTP upstream shutdown fails closed without direct target traffic');

  const socks = await createFixtureSocksServer({ slot: 'one', ttlMs: 60000, dnsDelayMs: 0 }); fixtures.push(socks);
  const socksTarget = { host: '198.51.100.42', port: 44441 };
  let socksWire = await owned.ensure({ ...socks.route, id: 'fixture-socks5' });
  await echo(socksWire, socksTarget); assert.equal(socks.snapshot().authenticated, 1); assert.equal(socks.snapshot().echoPayloadBytes, 256);
  assert.equal(owned.routingIdentity('fixture-socks5').nodeType, 'socks5');
  check('Authenticated SOCKS5 upstream returns exact bytes through the owned application route');
  socksWire = await owned.ensure({ ...socks.route, id: 'fixture-socks5', password: 'wrong-upstream-secret' });
  await assert.rejects(echo(socksWire, socksTarget)); assert.ok(socks.snapshot().rejected > 0);
  check('SOCKS5 upstream authentication refusal is returned to the application');

  phase = 'https-fixture-verification';
  await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1', '-nodes',
    '-keyout', path.join(runDir, 'fixture.key'), '-out', path.join(runDir, 'fixture.crt'), '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { timeout: 10000, maxBuffer: 16384 });
  const certificate = await readFile(path.join(runDir, 'fixture.crt'), 'utf8'), key = await readFile(path.join(runDir, 'fixture.key'), 'utf8');
  const secure = await httpFixture({ cert: certificate, key });
  const untrusted = await owned.ensure({ ...secure.proxy, id: 'fixture-https-untrusted', skipCertVerify: true });
  await assert.rejects(echo(untrusted)); assert.equal(secure.snapshot().authenticated, 0); assert.equal(directConnections, 0);
  check('HTTPS upstream rejects the untrusted local certificate even when caller requests a bypass');
  const trusted = manager({ certificate }), secureWire = await trusted.ensure({ ...secure.proxy, id: 'fixture-https-trusted' });
  await echo(secureWire); assert.equal(secure.snapshot().authenticated, 1); assert.equal(directConnections, 0);
  assert.equal(trusted.routingIdentity('fixture-https-trusted').nodeType, 'https');
  check('HTTPS CONNECT verifies the fixture CA and IP identity at the real compatibility bridge without modifying core config or host trust');

  phase = 'hostname-recovery';
  const recovery = await recoveryFixture(), resolution = fixtureResolver(recovery);
  const recovering = manager({ resolverFactory: resolution.factory });
  observations.recovery = await recoveredPost(recovering, recovery, 'fixture-recovery');
  assert.equal(resolution.snapshot().calls, 1);
  check('Real Mihomo hostname CONNECT 502 recovers via two fixture public IPv4 candidates; failed attempts receive zero target bytes');
  check('The recovered tunnel carries one exact POST and full origin response, including an eagerly buffered request body');

  phase = 'plain-http-no-replay';
  const bridge = recovering.routes.get('fixture-recovery').compatibilityBridge;
  const plainBody = 'one-non-idempotent-fixture-request';
  const plainTarget = `http://${recovery.hostname}/payment%2Fintent?signature=a%2Bb`;
  const response = await exchange(bridge, Buffer.from(`POST ${plainTarget} HTTP/1.1\r\nHost: ${recovery.hostname}\r\nProxy-Authorization: Basic ${Buffer.from(`${bridge.username}:${bridge.password}`).toString('base64')}\r\nContent-Length: ${Buffer.byteLength(plainBody)}\r\nConnection: close\r\n\r\n${plainBody}`));
  assert.match(response.toString(), /^HTTP\/1\.1 502 /);
  assert.deepEqual(recovery.snapshot().plainPosts, [{ method: 'POST', target: plainTarget, body: plainBody }]);
  assert.equal(resolution.snapshot().calls, 1); assert.equal(recovery.snapshot().postCount, 1); assert.equal(directConnections, 0);
  check('The real bridge preserves a plain HTTP POST 502 without invoking destination DNS or replaying the request');

  phase = 'core-death';
  const dying = owned.routes.get('fixture-http'), identity = owned.routingIdentity('fixture-http');
  dying.child.kill('SIGKILL');
  const deadline = Date.now() + 3000;
  while (owned.routingIdentity('fixture-http') && Date.now() < deadline) await delay(20);
  assert.ok(identity); assert.equal(owned.routingIdentity('fixture-http'), null);
  await assert.rejects(echo(wire)); assert.equal(directConnections, 0);
  check('Core death revokes managed identity and the old authenticated listener');

  phase = 'recovery-beyond-five-seconds';
  const slow = await recoveryFixture(), slowResolution = fixtureResolver(slow, 5500);
  const slowManager = manager({ resolverFactory: slowResolution.factory });
  observations.delayedRecovery = await recoveredPost(slowManager, slow, 'fixture-slow-recovery', 5500);
  assert.ok(observations.delayedRecovery.elapsedMs >= 5500);
  assert.equal(slowResolution.snapshot().calls, 1);
  check('Real Mihomo retains a private-hop tunnel during recovery beyond its five-second dial budget and delivers one complete target POST');
} catch (error) {
  operationFailure = { phase, code: /^[A-Z][A-Z0-9_]{0,63}$/.test(error?.code ?? '') ? error.code : 'FIXTURE_CHECK_FAILED',
    ...(Number.isFinite(error?.elapsedMs) ? { elapsedMs: error.elapsedMs } : {}) };
  console.error(`FAIL ${operationFailure.phase}: ${operationFailure.code}`);
} finally {
  const failures = [];
  const closed = await Promise.allSettled(managers.map(instance => instance.close()));
  if (closed.some(value => value.status !== 'fulfilled')) failures.push('MANAGER_CLOSE');
  const fixtureClosed = await Promise.allSettled(fixtures.map(fixture => fixture.close()));
  if (fixtureClosed.some(value => value.status !== 'fulfilled')) failures.push('FIXTURE_CLOSE');
  const bridgeClosed = await Promise.allSettled(bridges.map(bridge => bridge.close()));
  if (bridgeClosed.some(value => value.status !== 'fulfilled')) failures.push('BRIDGE_CLOSE');
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => directCanary.close(resolve));
  const deadline = Date.now() + 2000;
  while ((sockets.size || pids.some(alive) || bridges.some(bridge => bridge.snapshot().ownedSockets)) && Date.now() < deadline) await delay(10);
  const remainingPids = pids.filter(alive);
  if (remainingPids.length) failures.push('CORE_REMAINS');
  for (const instance of managers) {
    try { if ((await readdir(instance.baseDir)).length) failures.push('ROUTE_FILES_REMAIN'); }
    catch (error) { if (error?.code !== 'ENOENT') failures.push('ROUTE_FILES_UNKNOWN'); }
  }
  if (bridges.some(bridge => { const state = bridge.snapshot(); return state.status !== 'closed' || state.activeConnections || state.pendingConnections || state.ownedSockets; })) failures.push('BRIDGE_RESOURCES_REMAIN');
  if (resolverStates.some(state => state.closed !== 1)) failures.push('RESOLVER_NOT_CLOSED_EXACTLY_ONCE');
  if (sockets.size) failures.push('FIXTURE_SOCKETS_REMAIN');
  if (directConnections) failures.push('DIRECT_CANARY_REACHED');
  try { await rm(runDir, { recursive: true, force: true }); } catch { failures.push('TEMPORARY_DATA_REMAINS'); }
  observations.cleanup = { ownedCores: pids.length, remainingCoreCount: remainingPids.length, bridgeCount: bridges.length,
    remainingBridgeCount: bridges.filter(bridge => bridge.snapshot().ownedSockets).length, fixtureSocketsRemaining: sockets.size,
    resolversClosed: resolverStates.filter(state => state.closed === 1).length, directCanaryConnections: directConnections,
    temporaryDirectoryRemoved: !failures.includes('TEMPORARY_DATA_REMAINS'), coreLoopbackFence: process.platform === 'darwin' };
  if (failures.length) cleanupFailure = { code: 'OWNED_CLEANUP_FAILED', stages: failures };
}
if (!cleanupFailure) check('Every owned core, bridge, resolver, fixture socket, credential file and temporary directory is removed');
console.log(JSON.stringify({ passed: !operationFailure && !cleanupFailure, checks, operationFailure, cleanupFailure, observations,
  scope: 'Owned loopback fixtures and unchanged bundled Mihomo; injected destination DNS, no public egress, GUI, authorization, user configuration or payment acceptance claim.' }, null, 2));
if (operationFailure || cleanupFailure) process.exitCode = 1;
