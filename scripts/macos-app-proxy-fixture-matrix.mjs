import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';
import { validateDnsQuery, validateDnsResponse } from '../native/macos-local-routing/dns-wire.mjs';
import { makeDiagnosticDnsResponse } from '../native/macos-local-routing/diagnostic-dns-fixture.mjs';

// This module never installs or activates an extension. Its only native callers
// are the dedicated acceptance helper and the two sealed, self-owned fixtures.
// It cannot create a production receipt or attest a user application.
export const ACCEPTANCE_IDENTIFIERS = Object.freeze({
  hostIdentifier: 'io.envara.app-routing.acceptance',
  providerIdentifier: 'io.envara.app-routing.acceptance.proxy',
  applicationGroup: 'group.io.envara.app-routing.acceptance',
});
const uuidPattern = /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/;
const ownHostnamePattern = /^[a-z0-9-]{1,63}\.envara-fixture\.test$/;
const fixtureIdentity = 'envara-routing-acceptance-fixture';
const echoTarget = '198.51.100.42';
const ports = Object.freeze({ echo: 44441, halfClose: 44442, hold: 44443, udp: 44444 });
const safeProbeFailures = new Set(['PROBE_TIMEOUT', 'PROBE_TRANSPORT_FAILED']);
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
const clock = () => performance.now();
function failure(code) { return Object.assign(new Error('Owned AppProxy fixture operation failed'), { code }); }
function deadline(signal, timeoutMs, finish) {
  const timer = setTimeout(() => finish(failure('FIXTURE_DEADLINE')), timeoutMs);
  const aborted = () => finish(failure('FIXTURE_ABORTED'));
  signal?.addEventListener('abort', aborted, { once: true });
  if (signal?.aborted) queueMicrotask(aborted);
  return () => { clearTimeout(timer); signal?.removeEventListener('abort', aborted); };
}
function diagnostic(result) {
  if (!result || result.acceptanceOnly !== true || result.ready !== false || result.productionReceiptAllowed !== false) throw failure('INVALID_ACCEPTANCE_RESULT');
  return result;
}
function requireAuthorizedStatus(result, identifiers) {
  diagnostic(result);
  if (result.authorized !== true || result.extensionEnabled !== true) throw failure('NATIVE_ACCEPTANCE_AUTHORIZATION_REQUIRED');
  for (const key of Object.keys(ACCEPTANCE_IDENTIFIERS)) if (result[key] !== identifiers[key]) throw failure('NATIVE_ACCEPTANCE_IDENTITY_MISMATCH');
  if (!Array.isArray(result.fixtures) || result.fixtures.length !== 2 || !['one', 'two'].every(value => result.fixtures.includes(value))) throw failure('NATIVE_ACCEPTANCE_FIXTURES_REQUIRED');
}
function safeCode(error, fallback) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code) ? error.code : fallback;
}
function refusedOrZeroReply(result, payloadBytes = 2048) {
  return (result.ok === false && safeProbeFailures.has(result.code)) ||
    (result.ok === true && result.sentBytes === payloadBytes && result.receivedBytes === 0 &&
      result.payloadBase64 === '' && result.matches === false && result.eof === true);
}
function sameFile(a, b) { return a.dev === b.dev && a.ino === b.ino && a.uid === b.uid; }

function socketPathParts(socketPath, routeId) {
  if (!uuidPattern.test(routeId) || typeof socketPath !== 'string' || Buffer.byteLength(socketPath) >= 104 ||
      path.normalize(socketPath) !== socketPath || !socketPath.startsWith('/private/tmp/')) throw failure('FIXTURE_SOCKET_REJECTED');
  const directory = path.dirname(socketPath);
  if (path.dirname(directory) !== '/private/tmp' || !/^envara-ac-[A-Za-z0-9]{6}$/.test(path.basename(directory)) ||
      path.basename(socketPath) !== `acceptance-${routeId}.sock`) throw failure('FIXTURE_SOCKET_REJECTED');
  return { socketPath, directory, routeId };
}

/** Capture device/inode ownership inside the fixture's private directory. */
export async function inspectOwnedFixtureSocket(socketPath, routeId, { timeoutMs = 3000, signal } = {}) {
  const parsed = socketPathParts(socketPath, routeId), expires = clock() + timeoutMs;
  while (true) {
    if (signal?.aborted) throw failure('FIXTURE_ABORTED');
    try {
      const directory = await fs.lstat(parsed.directory);
      if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid() || (directory.mode & 0o777) !== 0o700 ||
          await fs.realpath(parsed.directory) !== parsed.directory) throw failure('FIXTURE_SOCKET_REJECTED');
      const socket = await fs.lstat(socketPath);
      if (!socket.isSocket() || socket.isSymbolicLink() || socket.uid !== process.getuid() || (socket.mode & 0o777) !== 0o600 ||
          await fs.realpath(socketPath) !== socketPath) throw failure('FIXTURE_SOCKET_REJECTED');
      return { ...parsed, directoryIdentity: { dev: directory.dev, ino: directory.ino, uid: directory.uid },
        socketIdentity: { dev: socket.dev, ino: socket.ino, uid: socket.uid } };
    } catch (error) {
      if (error.code !== 'ENOENT' || clock() >= expires) throw error.code === 'ENOENT' ? failure('FIXTURE_SOCKET_UNAVAILABLE') : error;
      await delay(Math.min(40, Math.max(1, expires - clock())));
    }
  }
}

/** No recursive deletion; retain everything unless the owned guardian confirms exit. */
export async function cleanupOwnedFixtureSocket(token, { exitConfirmed = false } = {}) {
  if (!exitConfirmed || !token?.directoryIdentity || !token?.socketIdentity) return false;
  try {
    const parsed = socketPathParts(token.socketPath, token.routeId), directory = await fs.lstat(parsed.directory);
    if (!directory.isDirectory() || (directory.mode & 0o777) !== 0o700 || !sameFile(directory, token.directoryIdentity) ||
        await fs.realpath(parsed.directory) !== parsed.directory) return false;
    try {
      const socket = await fs.lstat(parsed.socketPath);
      if (!socket.isSocket() || (socket.mode & 0o777) !== 0o600 || !sameFile(socket, token.socketIdentity)) return false;
      await fs.unlink(parsed.socketPath);
    } catch (error) { if (error.code !== 'ENOENT') return false; }
    // rmdir refuses unknown files or a new socket. Never delete those entries.
    await fs.rmdir(parsed.directory);
    return true;
  } catch (error) { return error.code === 'ENOENT'; }
}

/** One bounded request per private Unix socket; no commands or arbitrary paths. */
export async function requestOwnedFixture(launch, request, { timeoutMs = 6000, signal } = {}) {
  if (!Number.isInteger(launch?.pid) || launch.pid <= 0 || !launch.socketToken ||
      !request || typeof request.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(request.id)) throw failure('FIXTURE_REQUEST_REJECTED');
  const current = await inspectOwnedFixtureSocket(launch.socketPath, launch.routeId, { timeoutMs: Math.min(timeoutMs, 1000), signal });
  if (!sameFile(current.directoryIdentity, launch.socketToken.directoryIdentity) || !sameFile(current.socketIdentity, launch.socketToken.socketIdentity)) throw failure('FIXTURE_SOCKET_REPLACED');
  const bytes = Buffer.from(JSON.stringify(request) + '\n');
  if (bytes.length > 8192) throw failure('FIXTURE_REQUEST_REJECTED');
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: launch.socketPath });
    let received = Buffer.alloc(0), finished = false;
    let cancel = () => {};
    const finish = (error, response) => {
      if (finished) return; finished = true; cancel(); socket.destroy();
      error ? reject(error) : resolve(response);
    };
    cancel = deadline(signal, timeoutMs, error => finish(error));
    socket.once('connect', () => socket.write(bytes));
    socket.on('error', () => finish(failure('FIXTURE_SOCKET_TRANSPORT_FAILED')));
    socket.once('end', () => finish(failure('FIXTURE_RESPONSE_TRUNCATED')));
    socket.on('data', data => {
      received = Buffer.concat([received, data]);
      if (received.length > 8192) return finish(failure('FIXTURE_RESPONSE_SIZE_LIMIT'));
      const end = received.indexOf(10);
      if (end < 0) return;
      try {
        if (end !== received.length - 1) throw failure('FIXTURE_RESPONSE_REJECTED');
        const response = JSON.parse(received.subarray(0, end).toString('utf8'));
        if (response?.id !== request.id || response.op !== request.op || response.pid !== launch.pid || typeof response.ok !== 'boolean') throw failure('FIXTURE_RESPONSE_REJECTED');
        finish(null, response);
      } catch (error) { finish(failure(safeCode(error, 'FIXTURE_RESPONSE_REJECTED'))); }
    });
  });
}

export function makeCachedFixtureDnsResponse(query, { address4, address6, ttl = 30 } = {}) {
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 30) throw failure('FIXTURE_DNS_TTL_REJECTED');
  const descriptor = validateDnsQuery(query), response = makeDiagnosticDnsResponse(query, { address4, address6 });
  // makeDiagnosticDnsResponse emits exactly one pointer-owned A/AAAA answer.
  // Verify the framing before changing its TTL; preserve the validated EDNS OPT.
  const answer = descriptor.questionEnd;
  if (response.readUInt16BE(6) !== 1 || response.readUInt16BE(answer) !== 0xc00c ||
      ![1, 28].includes(response.readUInt16BE(answer + 2)) || response.readUInt16BE(answer + 4) !== 1) throw failure('FIXTURE_DNS_FRAMING_REJECTED');
  response.writeUInt32BE(ttl, answer + 6);
  validateDnsResponse(response, descriptor);
  return response;
}

function dnsHostname(query, descriptor) {
  let offset = 12; const labels = [];
  while (offset < descriptor.questionEnd - 4) {
    const size = query[offset++]; if (!size) break;
    labels.push(query.subarray(offset, offset + size).toString('ascii').toLowerCase()); offset += size;
  }
  return labels.join('.');
}
async function listen(server) {
  return await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(server.address().port); });
  });
}
async function closeServer(server, sockets) {
  for (const socket of sockets) socket.destroy();
  if (!server.listening) return true;
  return await new Promise(resolve => {
    const timer = setTimeout(() => resolve(false), 1000);
    server.close(error => { clearTimeout(timer); resolve(!error); });
  });
}

/** Local protocol emulation only. No requested destination is ever connected. */
export async function createFixtureSocksServer({ slot, ttlMs = 115000, maximumConnections = 32, dnsDelayMs = 150 } = {}) {
  if (!['one', 'two'].includes(slot) || !Number.isInteger(ttlMs) || ttlMs < 200 || ttlMs > 118000 ||
      !Number.isInteger(maximumConnections) || maximumConnections < 1 || maximumConnections > 64 ||
      !Number.isInteger(dnsDelayMs) || dnsDelayMs < 0 || dnsDelayMs > 300) throw failure('FIXTURE_PROXY_OPTIONS_REJECTED');
  const credentials = { username: randomBytes(12).toString('hex'), password: randomBytes(24).toString('hex') };
  const answer4 = slot === 'one' ? '203.0.113.42' : '203.0.113.43', answer6 = slot === 'one' ? '2001:db8::42' : '2001:db8::43';
  const names = new Set(), sockets = new Set();
  const counters = { connections: 0, authenticated: 0, rejected: 0, echoConnections: 0, halfCloseConnections: 0,
    heldConnections: 0, heldPayloadBytes: 0, udpCommands: 0, dnsConnections: 0, dnsAReplies: 0, dnsAAAAReplies: 0,
    echoPayloadBytes: 0, halfClosePayloadBytes: 0, invalidDnsQueries: 0, closed: false };
  const server = net.createServer({ allowHalfOpen: true }, socket => {
    counters.connections++;
    if (counters.closed || counters.connections > maximumConnections || sockets.size >= 8) { counters.rejected++; socket.destroy(); return; }
    sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {});
    socket.setTimeout(10000, () => socket.destroy());
    void handle(socket).catch(() => { counters.rejected++; socket.destroy(); });
  });
  async function handle(socket) {
    const reader = new SocketReader(socket, 16384);
    let released = false;
    try {
      const greeting = await reader.read(2), methods = await reader.read(greeting[1]);
      if (greeting[0] !== 5 || greeting[1] < 1 || greeting[1] > 8 || !methods.includes(2)) throw failure('FIXTURE_PROXY_AUTH_REQUIRED');
      socket.write(Buffer.from([5, 2]));
      const auth = await reader.read(2), username = await reader.read(auth[1]), passwordLength = (await reader.read(1))[0], password = await reader.read(passwordLength);
      const expectedUsername = Buffer.from(credentials.username), expectedPassword = Buffer.from(credentials.password);
      if (auth[0] !== 1 || username.length !== expectedUsername.length || password.length !== expectedPassword.length ||
          !timingSafeEqual(username, expectedUsername) || !timingSafeEqual(password, expectedPassword)) {
        socket.end(Buffer.from([1, 1])); counters.rejected++; return;
      }
      counters.authenticated++; socket.write(Buffer.from([1, 0]));
      const header = await reader.read(4);
      if (header[0] !== 5 || header[2] !== 0 || header[3] !== 1) throw failure('FIXTURE_PROXY_ENDPOINT_REJECTED');
      const endpoint = await reader.read(6), host = [...endpoint.subarray(0, 4)].join('.'), port = endpoint.readUInt16BE(4);
      if (header[1] === 3) { counters.udpCommands++; socket.end(Buffer.from([5, 7, 0, 1, 127, 0, 0, 1, 0, 0])); return; }
      if (header[1] !== 1) throw failure('FIXTURE_PROXY_COMMAND_REJECTED');
      const dns = ['1.1.1.1', '1.0.0.1'].includes(host) && port === 53;
      if (!dns && (host !== echoTarget || ![ports.echo, ports.halfClose, ports.hold].includes(port))) {
        socket.end(Buffer.from([5, 2, 0, 1, 127, 0, 0, 1, 0, 0])); counters.rejected++; return;
      }
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
      if (dns) {
        counters.dnsConnections++;
        for (let index = 0; index < 8 && !socket.destroyed; index++) {
          const size = (await reader.read(2)).readUInt16BE(0);
          if (size < 12 || size > 4096) throw failure('FIXTURE_DNS_SIZE_REJECTED');
          const query = await reader.read(size), descriptor = validateDnsQuery(query), name = dnsHostname(query, descriptor);
          const type = query.readUInt16BE(descriptor.questionEnd - 4);
          if (!names.has(name) || !ownHostnamePattern.test(name) || ![1, 28].includes(type)) { counters.invalidDnsQueries++; throw failure('FIXTURE_DNS_NAME_REJECTED'); }
          const response = makeCachedFixtureDnsResponse(query, { address4: answer4, address6: answer6 });
          if (dnsDelayMs) await delay(dnsDelayMs);
          if (socket.destroyed || counters.closed) return;
          const prefix = Buffer.alloc(2); prefix.writeUInt16BE(response.length);
          if (type === 1) counters.dnsAReplies++; else counters.dnsAAAAReplies++;
          socket.write(Buffer.concat([prefix, response]));
        }
        socket.end(); return;
      }
      if (port === ports.echo) counters.echoConnections++;
      if (port === ports.halfClose) counters.halfCloseConnections++;
      if (port === ports.hold) counters.heldConnections++;
      const buffered = reader.release(), chunks = []; let length = 0; released = true;
      const consume = data => {
        length += data.length;
        if (length > 4096) { socket.destroy(); return; }
        if (port === ports.echo) { counters.echoPayloadBytes += data.length; socket.write(data); }
        else if (port === ports.halfClose) { counters.halfClosePayloadBytes += data.length; chunks.push(data); }
        else counters.heldPayloadBytes += data.length;
      };
      socket.on('data', consume);
      socket.once('end', () => { if (port === ports.halfClose) socket.end(Buffer.concat(chunks, length)); else socket.end(); });
      if (buffered.length) consume(buffered);
      // EOF may have been consumed by SocketReader together with upload bytes.
      if (reader.ended) { if (port === ports.halfClose) socket.end(Buffer.concat(chunks, length)); else socket.end(); }
      socket.resume();
    } finally { if (reader.pending) reader.fail(failure('FIXTURE_PROXY_CLOSED')); if (!released) { try { reader.release(); } catch {} } }
  }
  const port = await listen(server);
  const timer = setTimeout(() => { counters.closed = true; void closeServer(server, sockets); }, ttlMs);
  const close = async () => { clearTimeout(timer); counters.closed = true; return await closeServer(server, sockets); };
  return {
    route: { protocol: 'socks5', host: '127.0.0.1', port, ...credentials, udp: false, udpPolicy: 'block' },
    answers: Object.freeze([answer4, answer6]),
    allowHostname(name) { if (!ownHostnamePattern.test(name) || names.size >= 16) throw failure('FIXTURE_DNS_NAME_REJECTED'); names.add(name); },
    snapshot: () => ({ ...counters }), close, stopCore: close,
    async waitForHeldPayload({ timeoutMs = 2000, signal } = {}) {
      const expires = clock() + timeoutMs;
      while (clock() < expires && !signal?.aborted) { if (counters.heldPayloadBytes >= 2048) return true; await delay(20); }
      return false;
    },
  };
}

export async function createUnboundLoopbackControl() {
  const sockets = new Set(), clients = new Set();
  const server = net.createServer(socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {}); socket.pipe(socket); });
  const port = await listen(server);
  const open = () => new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port }); clients.add(socket); socket.on('error', () => {}); socket.once('close', () => clients.delete(socket));
    const timer = setTimeout(() => { socket.destroy(); reject(failure('UNBOUND_CONTROL_DEADLINE')); }, 2000);
    socket.once('connect', () => { clearTimeout(timer); resolve(socket); }); socket.once('error', () => { clearTimeout(timer); reject(failure('UNBOUND_CONTROL_FAILED')); });
  });
  let existing;
  try { existing = await open(); }
  catch (error) { for (const socket of clients) socket.destroy(); await closeServer(server, sockets); throw error; }
  async function echo(socket) {
    const payload = randomBytes(64); let bytes = Buffer.alloc(0);
    return await new Promise(resolve => {
      let done = false;
      const finish = passed => { if (done) return; done = true; clearTimeout(timer); socket.removeListener('data', consume); socket.removeListener('error', failed); if (!passed) socket.destroy(); resolve(passed); };
      const consume = data => { bytes = Buffer.concat([bytes, data]); if (bytes.length >= payload.length) finish(bytes.equals(payload)); };
      const failed = () => finish(false), timer = setTimeout(failed, 2000);
      socket.on('data', consume); socket.once('error', failed); socket.write(payload);
    });
  }
  return { existing: () => echo(existing), async fresh() { const socket = await open(); try { return await echo(socket); } finally { socket.destroy(); } },
    async close() { for (const socket of clients) socket.destroy(); return await closeServer(server, sockets); } };
}

/** Native matrix work is bounded to 90 s; cleanup has the remaining 25 s. */
export async function runMacOSAppProxyFixtureMatrix({
  call, identifiers = ACCEPTANCE_IDENTIFIERS, requestFixture = requestOwnedFixture,
  inspectSocket = inspectOwnedFixtureSocket, cleanupSocket = cleanupOwnedFixtureSocket,
  createProxy = createFixtureSocksServer, createControl = createUnboundLoopbackControl,
  evidenceMode = 'native', workTimeoutMs = 90000, cleanupTimeoutMs = 25000,
} = {}) {
  if (typeof call !== 'function' || !['native', 'simulation'].includes(evidenceMode) ||
      !Number.isInteger(workTimeoutMs) || workTimeoutMs < 1000 || workTimeoutMs > 90000 ||
      !Number.isInteger(cleanupTimeoutMs) || cleanupTimeoutMs < 1000 || cleanupTimeoutMs > 25000 ||
      Object.keys(identifiers).length !== 3 || Object.keys(ACCEPTANCE_IDENTIFIERS).some(key => typeof identifiers[key] !== 'string' || !/^([a-z][a-z0-9]*\.)+[a-z][a-z0-9.-]*$/.test(identifiers[key]))) throw failure('FIXTURE_MATRIX_OPTIONS_REJECTED');
  const expectedIdentifiers = Object.freeze({ ...identifiers });
  const started = clock(), startedAt = new Date().toISOString(), workDeadline = started + workTimeoutMs, overallDeadline = workDeadline + cleanupTimeoutMs;
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), workTimeoutMs);
  const report = { schemaVersion: 1, operation: 'runOwnedAppProxyFixtures', startedAt,
    acceptanceOnly: true, productionReady: false, productionReceiptAllowed: false, userApplicationsTested: false,
    nativeRoutingAttempted: false, nativeRoutingInvoked: false, fixtureLaunchAttempted: false,
    evidenceMode, authorized: false, extensionEnabled: false,
    changesVPNOrTUN: false, modifiesHostDNSOrTimeZone: false, fixtureProcessesStarted: false,
    fixtureLifetimeSeconds: 120, maximumMatrixSeconds: (workTimeoutMs + cleanupTimeoutMs) / 1000,
    checks: {}, routes: [], cleanup: { routeResults: [], uncertainMutation: false, localServersClosed: false, complete: false },
    nativeChecks: { tcp: false, halfClose: false, dnsPerRealm: false, sameHostnameCache: false, childProcesses: false,
      udp: false, udpBlock: false, coreFailure: false, rebind: false, firstPacket: false, guardCrash: false,
      providerCrash: false, detachedHelpers: false, unaffectedApplications: false },
    requiredUntestedScopes: ['first packet atomicity', 'whole guardian crash', 'provider crash', 'detached helpers',
      'UDP proxy', 'UDP kernel block proof', 'unrelated desktop application network', 'Notion'],
  };
  const entries = [], proxies = []; let control;
  const remaining = () => Math.max(1, Math.ceil(workDeadline - clock()));
  const invoke = async (method, params = {}, cap = 20000, cleanup = false) => {
    if (!cleanup && controller.signal.aborted) throw failure('FIXTURE_MATRIX_DEADLINE');
    const timeoutMs = Math.min(cap, cleanup ? Math.max(1, Math.ceil(overallDeadline - clock())) : remaining());
    if (timeoutMs <= 1) throw failure('FIXTURE_MATRIX_DEADLINE');
    return diagnostic(await call(method, params, { timeoutMs, signal: cleanup ? undefined : controller.signal }));
  };
  const probe = async (entry, request, child = false) => {
    const id = randomUUID().replaceAll('-', ''), timeoutMs = Math.min(6000, remaining());
    const response = await requestFixture(entry.launch, child ? { id, op: 'child_probe', pid: entry.childPID, request } : { id, ...request },
      { timeoutMs, signal: controller.signal });
    if (response?.id !== id || response.op !== (child ? 'child_probe' : request.op) || response.pid !== entry.launch.pid || typeof response.ok !== 'boolean') throw failure('FIXTURE_RESPONSE_REJECTED');
    if (!child) return response;
    if (!response.ok) return response;
    const result = response.childResult;
    if (!result || result.id !== id || result.op !== request.op || result.pid !== entry.childPID || typeof result.ok !== 'boolean') throw failure('FIXTURE_CHILD_RESPONSE_REJECTED');
    return result;
  };
  const addCheck = (name, passed, scope, evidence = {}) => { report.checks[name] = { passed: passed === true, scope, ...evidence }; };
  const prepare = async (slot, proxy, phase) => {
    let route;
    report.nativeRoutingAttempted = evidenceMode === 'native';
    try { route = await invoke('prepareFixture', { fixture: slot, route: proxy.route }); }
    catch (error) { report.cleanup.uncertainMutation = true; throw error; }
    if (!uuidPattern.test(route.routeId) || !uuidPattern.test(route.vpnUUID) || entries.some(entry => entry.routeId === route.routeId)) {
      report.cleanup.uncertainMutation = true; throw failure('FIXTURE_ROUTE_REJECTED');
    }
    const entry = { slot, phase, routeId: route.routeId, vpnUUID: route.vpnUUID, proxy, attemptedLaunch: false, stopped: false, revoked: false };
    entries.push(entry); report.routes.push({ slot, phase, routeId: entry.routeId, vpnUUID: entry.vpnUUID });
    report.nativeRoutingInvoked = evidenceMode === 'native';
    entry.attemptedLaunch = true; report.fixtureLaunchAttempted = true;
    const launch = await invoke('launchFixture', { routeId: entry.routeId });
    if (!Number.isInteger(launch.pid) || launch.pid <= 0 || !uuidPattern.test(launch.sessionId)) throw failure('FIXTURE_LAUNCH_REJECTED');
    entry.launch = { ...launch, routeId: entry.routeId };
    report.fixtureProcessesStarted = true;
    entry.launch.socketToken = await inspectSocket(launch.socketPath, entry.routeId, { timeoutMs: Math.min(3000, remaining()), signal: controller.signal });
    const status = await probe(entry, { op: 'status', timeoutMs: 1000 });
    if (!status.ok || status.protocolVersion !== 1 || status.fixtureIdentity !== fixtureIdentity || status.bundleIdentifier !== `io.envara.routing.fixture.${slot}` ||
        status.child !== false || status.maximumLifetimeSeconds !== 120 || status.ownedChildScopeVerified !== true ||
        status.nativeRoutingAcceptance !== false || !Array.isArray(status.children) || status.children.length !== 0 ||
        !Array.isArray(status.unverifiedChildren) || status.unverifiedChildren.length !== 0) throw failure('FIXTURE_IDENTITY_REJECTED');
    return entry;
  };
  const stopAndRevoke = async (entry, cleanup = false) => {
    if (!entry.stopped && entry.attemptedLaunch) {
      const stopped = await invoke('stopFixture', { routeId: entry.routeId }, 10000, cleanup);
      entry.stopped = stopped.stopped === true;
      if (!entry.stopped) throw failure('FIXTURE_EXIT_UNVERIFIED');
    }
    if (!entry.revoked) {
      const revoked = await invoke('revokeFixture', { routeId: entry.routeId }, 10000, cleanup);
      entry.revoked = revoked.revoked === true && revoked.mappingRetained === true;
      if (!entry.revoked) throw failure('FIXTURE_REVOCATION_UNVERIFIED');
    }
    return entry;
  };
  try {
    const status = await invoke('status', {}, 10000);
    requireAuthorizedStatus(status, expectedIdentifiers); report.authorized = true; report.extensionEnabled = true;
    control = await createControl();
    addCheck('unboundBeforeRoutes', await control.existing(), 'one owned controller loopback socket opened before fixture routes');
    for (const slot of ['one', 'two']) {
      const proxy = await createProxy({ slot, ttlMs: Math.min(115000, Math.max(200, Math.ceil(overallDeadline - clock()))) }); proxies.push(proxy);
      const entry = await prepare(slot, proxy, 'initial');
      if (slot === 'two' && entry.vpnUUID === entries[0].vpnUUID) throw failure('FIXTURE_REALM_COLLISION');
      const spawned = await probe(entry, { op: 'spawn_child' });
      if (!spawned.ok || !Number.isInteger(spawned.childPID) || spawned.childPID <= 0 || spawned.childPID === entry.launch.pid ||
          !Number.isInteger(spawned.childStartedSeconds) || !Number.isInteger(spawned.childStartedMicroseconds)) throw failure('FIXTURE_CHILD_IDENTITY_REJECTED');
      entry.childPID = spawned.childPID;
      const childStatus = await probe(entry, { op: 'status', timeoutMs: 1000 }, true);
      if (!childStatus.ok || childStatus.parentPID !== entry.launch.pid || childStatus.child !== true ||
          childStatus.bundleIdentifier !== `io.envara.routing.fixture.${slot}` || childStatus.fixtureIdentity !== fixtureIdentity ||
          childStatus.protocolVersion !== 1 || childStatus.ownedChildScopeVerified !== true) throw failure('FIXTURE_CHILD_IDENTITY_REJECTED');
    }
    const initial = entries.slice();
    addCheck('twoExactPathRealms', initial.length === 2 && initial[0].vpnUUID !== initial[1].vpnUUID,
      'two sealed helper-owned exact-path fixtures prepared and launched in different realm UUIDs; simultaneous traffic is checked below');
    addCheck('unboundExistingDuringRoutes', await control.existing(), 'one owned unbound controller loopback connection opened before the routes');
    addCheck('unboundNewDuringRoutes', await control.fresh(), 'one new owned unbound controller loopback connection');
    const payload = randomBytes(2048);
    for (const entry of initial) for (const child of [false, true]) {
      const role = child ? 'child' : 'parent';
      for (const halfClose of [false, true]) {
        const before = entry.proxy.snapshot();
        const result = await probe(entry, { op: 'tcp', host: echoTarget, port: halfClose ? ports.halfClose : ports.echo,
          payloadBase64: payload.toString('base64'), halfClose, timeoutMs: 3000 }, child);
        const after = entry.proxy.snapshot(), counter = halfClose ? 'halfClosePayloadBytes' : 'echoPayloadBytes';
        addCheck(`${entry.slot}_${role}_${halfClose ? 'halfClose' : 'tcp2048'}`,
          result.ok && result.matches === true && result.sentBytes === 2048 && result.receivedBytes === 2048 &&
          result.payloadBase64 === payload.toString('base64') && (!halfClose || (result.eof === true && result.halfClose === true)) &&
          after.authenticated > before.authenticated && after[counter] - before[counter] === 2048,
          'real sealed fixture TCP payload to a reserved destination, answered only by its authenticated local core',
          { payloadBytes: 2048, authenticatedOwnCoreObserved: after.authenticated > before.authenticated, halfClose });
      }
      const before = entry.proxy.snapshot(), result = await probe(entry, { op: 'udp', host: echoTarget, port: ports.udp,
        payloadBase64: Buffer.alloc(32, 0x45).toString('base64'), timeoutMs: 600 }, child), after = entry.proxy.snapshot();
      addCheck(`${entry.slot}_${role}_udpBlock`, false,
        'bounded UDP fixture refusal and no UDP ASSOCIATE on the owned core; no kernel packet observation, so native blocking remains unproven',
        { boundedRefusalObserved: result.ok === false && safeProbeFailures.has(result.code), unexpectedSuccess: result.ok === true,
          ownCoreUDPCommands: after.udpCommands - before.udpCommands, nativeBlockProof: false });
    }
    // Each nonce belongs only to this run. A 30-second TTL deliberately warms
    // the system resolver; identical names across realms test cache/coalescing.
    const isolatedNames = initial.map(entry => `${randomBytes(12).toString('hex')}-${entry.slot}.envara-fixture.test`);
    for (let index = 0; index < initial.length; index++) {
      const entry = initial[index], hostname = isolatedNames[index]; entry.proxy.allowHostname(hostname);
      for (const child of [false, true]) {
        const before = entry.proxy.snapshot(), result = await probe(entry, { op: 'resolve', host: hostname, timeoutMs: 5000 }, child), after = entry.proxy.snapshot();
        const answersMatch = result.ok && result.systemGetaddrinfo === true && result.resolved === true &&
          Array.isArray(result.addresses) && result.addresses.length === 2 && [...result.addresses].sort().join('|') === [...entry.proxy.answers].sort().join('|');
        addCheck(`${entry.slot}_${child ? 'child' : 'parent'}_isolatedDNS`, answersMatch,
          'real system getaddrinfo on an owned random synthetic name; the ordinary child may use this realm warm cache',
          { ownReservedAnswers: answersMatch, ownCoreAReplies: after.dnsAReplies - before.dnsAReplies,
            ownCoreAAAAReplies: after.dnsAAAAReplies - before.dnsAAAAReplies, dnsTTLSeconds: 30 });
      }
    }
    const sharedHostname = `${randomBytes(12).toString('hex')}.envara-fixture.test`;
    const sharedStarted = clock();
    for (const entry of initial) entry.proxy.allowHostname(sharedHostname);
    const cold = await Promise.all(initial.map(async entry => {
      const before = entry.proxy.snapshot(), result = await probe(entry, { op: 'resolve', host: sharedHostname, timeoutMs: 5000 }), after = entry.proxy.snapshot();
      return { entry, result, before, after };
    }));
    for (const { entry, result, before, after } of cold) {
      const answersMatch = result.ok && result.systemGetaddrinfo === true && result.resolved === true &&
        Array.isArray(result.addresses) && result.addresses.length === 2 && [...result.addresses].sort().join('|') === [...entry.proxy.answers].sort().join('|');
      addCheck(`${entry.slot}_concurrentSameHostname`, answersMatch && after.dnsAReplies > before.dnsAReplies && after.dnsAAAAReplies > before.dnsAAAAReplies,
        'two concurrently active exact-path realms resolve the identical owned hostname with different authenticated A/AAAA answers',
        { ownReservedAnswers: answersMatch, ownCoreAReplies: after.dnsAReplies - before.dnsAReplies, ownCoreAAAAReplies: after.dnsAAAAReplies - before.dnsAAAAReplies });
    }
    for (const round of [1, 2]) for (const child of [false, true]) {
      await Promise.all(initial.map(async entry => {
        const before = entry.proxy.snapshot(), result = await probe(entry, { op: 'resolve', host: sharedHostname, timeoutMs: 5000 }, child), after = entry.proxy.snapshot();
        const answersMatch = result.ok && result.systemGetaddrinfo === true && result.resolved === true &&
          Array.isArray(result.addresses) && result.addresses.length === 2 && [...result.addresses].sort().join('|') === [...entry.proxy.answers].sort().join('|');
        const withinTTL = clock() - sharedStarted < 30000;
        addCheck(`${entry.slot}_${child ? 'child' : 'parent'}_warmDNS_${round}`, answersMatch && withinTTL,
          'repeat system getaddrinfo inside the 30-second answer TTL for the same hostname in each realm',
          { ownReservedAnswers: answersMatch, ownCoreQueries: after.dnsAReplies + after.dnsAAAAReplies - before.dnsAReplies - before.dnsAAAAReplies,
            servedWithoutNewOwnCoreQuery: after.dnsAReplies + after.dnsAAAAReplies === before.dnsAReplies + before.dnsAAAAReplies,
            observedWithinAnswerTTL: withinTTL, dnsTTLSeconds: 30 });
      }));
    }
    // Keep a reserved flow pending, then stop only that realm's local core.
    // No real remote destination exists in this harness and no direct-route
    // success is inferred from a timeout. First-packet/crash gates stay false.
    const failedEntry = initial[0];
    const pending = probe(failedEntry, { op: 'tcp', host: echoTarget, port: ports.hold, payloadBase64: payload.toString('base64'), timeoutMs: 5000 })
      .then(value => ({ value }), error => ({ error }));
    const held = await failedEntry.proxy.waitForHeldPayload({ timeoutMs: 2000, signal: controller.signal });
    await failedEntry.proxy.stopCore();
    const pendingResult = await pending;
    if (pendingResult.error) throw pendingResult.error;
    const active = pendingResult.value;
    addCheck('coreFailureExistingFlow', held && refusedOrZeroReply(active),
      'one authenticated reserved fixture flow receives no reply after its owned local core is closed',
      { uploadedToOwnCore: held, zeroReplyOrTransportRefusal: refusedOrZeroReply(active), unexpectedReply: active.ok === true && active.receivedBytes > 0 });
    const failedBefore = failedEntry.proxy.snapshot(), fresh = await probe(failedEntry, { op: 'tcp', host: echoTarget,
      port: ports.echo, payloadBase64: payload.toString('base64'), timeoutMs: 1500 }), failedAfter = failedEntry.proxy.snapshot();
    addCheck('coreFailureNewFlow', refusedOrZeroReply(fresh) && failedAfter.echoPayloadBytes === failedBefore.echoPayloadBytes,
      'new reserved fixture flow fails with the owned core offline; this does not prove all possible direct egress is blocked',
      { zeroReplyOrTransportRefusal: refusedOrZeroReply(fresh), unexpectedReply: fresh.ok === true && fresh.receivedBytes > 0,
        ownCoreNewPayloadBytes: failedAfter.echoPayloadBytes - failedBefore.echoPayloadBytes, directPacketCapturePerformed: false });
    // The other realm and unbound controls continue while one core has failed.
    const survivingBefore = initial[1].proxy.snapshot();
    const surviving = await probe(initial[1], { op: 'tcp', host: echoTarget, port: ports.echo, payloadBase64: payload.toString('base64'), timeoutMs: 3000 });
    const survivingAfter = initial[1].proxy.snapshot();
    addCheck('otherRealmSurvivesCoreFailure', surviving.ok && surviving.matches === true && surviving.receivedBytes === 2048 &&
      surviving.payloadBase64 === payload.toString('base64') && survivingAfter.authenticated > survivingBefore.authenticated &&
      survivingAfter.echoPayloadBytes - survivingBefore.echoPayloadBytes === 2048,
      'one other sealed fixture realm retains its own reserved TCP route');
    addCheck('unboundExistingAfterFailure', await control.existing(), 'one owned controller loopback connection survives fixture core failure');
    addCheck('unboundNewAfterFailure', await control.fresh(), 'one new owned controller loopback connection after fixture core failure');
    await stopAndRevoke(failedEntry);
    const replacement = await createProxy({ slot: failedEntry.slot, ttlMs: Math.min(115000, Math.max(200, Math.ceil(overallDeadline - clock()))) }); proxies.push(replacement);
    const rebound = await prepare(failedEntry.slot, replacement, 'rebind');
    const reboundResult = await probe(rebound, { op: 'tcp', host: echoTarget, port: ports.echo, payloadBase64: payload.toString('base64'), timeoutMs: 3000 });
    addCheck('sameRealmRebind', rebound.vpnUUID === failedEntry.vpnUUID && rebound.routeId !== failedEntry.routeId &&
      reboundResult.ok && reboundResult.matches === true && reboundResult.receivedBytes === 2048 && replacement.snapshot().echoPayloadBytes === 2048,
      'stop and revoke only the first owned route, then rebind the exact same fixture realm to new private core credentials');
  } catch (error) { report.error = safeCode(error, 'NATIVE_FIXTURE_MATRIX_FAILED'); }
  finally {
    clearTimeout(timer); controller.abort();
    for (const entry of [...entries].reverse()) {
      const result = { slot: entry.slot, phase: entry.phase, routeId: entry.routeId, stopped: entry.stopped, revoked: entry.revoked, socketRemoved: !entry.launch };
      try { await stopAndRevoke(entry, true); result.stopped = entry.stopped; result.revoked = entry.revoked; }
      catch (error) { result.error = safeCode(error, 'OWNED_ROUTE_CLEANUP_UNVERIFIED'); }
      if (entry.launch?.socketToken && entry.stopped) {
        try { result.socketRemoved = await cleanupSocket(entry.launch.socketToken, { exitConfirmed: true }); }
        catch { result.socketRemoved = false; }
      } else if (entry.attemptedLaunch && !entry.launch?.socketToken) result.socketRemoved = false;
      report.cleanup.routeResults.push(result);
    }
    const localClosures = await Promise.allSettled([...proxies.map(proxy => proxy.close()), ...(control ? [control.close()] : [])]);
    report.cleanup.localServersClosed = localClosures.every(result => result.status === 'fulfilled' && result.value === true);
    report.cleanup.complete = !report.cleanup.uncertainMutation && report.cleanup.localServersClosed &&
      report.cleanup.routeResults.every(result => (!result.error && result.stopped && result.revoked && result.socketRemoved));
    const all = predicate => Object.entries(report.checks).filter(([name]) => predicate(name)).every(([, check]) => check.passed);
    const has = predicate => Object.keys(report.checks).some(predicate);
    const checked = predicate => has(predicate) && all(predicate);
    const warmCacheObserved = ['one', 'two'].every(slot => Object.entries(report.checks).some(([name, check]) =>
      name.startsWith(`${slot}_`) && name.includes('_warmDNS_') && check.passed && check.servedWithoutNewOwnCoreQuery));
    report.fixtureWarmCacheObserved = warmCacheObserved;
    if (evidenceMode === 'native') {
      report.nativeChecks.tcp = checked(name => name.endsWith('_tcp2048')) && Object.keys(report.checks).filter(name => name.endsWith('_tcp2048')).length === 4;
      report.nativeChecks.halfClose = checked(name => name.endsWith('_halfClose')) && Object.keys(report.checks).filter(name => name.endsWith('_halfClose')).length === 4;
      report.nativeChecks.dnsPerRealm = checked(name => name.endsWith('_isolatedDNS')) && Object.keys(report.checks).filter(name => name.endsWith('_isolatedDNS')).length === 4;
      report.nativeChecks.sameHostnameCache = checked(name => name.includes('concurrentSameHostname') || name.includes('_warmDNS_')) &&
        Object.keys(report.checks).filter(name => name.includes('concurrentSameHostname') || name.includes('_warmDNS_')).length === 10 &&
        warmCacheObserved;
      report.nativeChecks.childProcesses = report.nativeChecks.tcp && report.nativeChecks.halfClose && report.nativeChecks.dnsPerRealm;
      report.nativeChecks.coreFailure = report.checks.coreFailureExistingFlow?.passed === true && report.checks.coreFailureNewFlow?.passed === true;
      report.nativeChecks.rebind = report.checks.sameRealmRebind?.passed === true;
    }
    // A successful fixture subset is never enough to open the production gate.
    report.testedFixtureSubsetPassed = !report.error && report.cleanup.complete && warmCacheObserved && Object.entries(report.checks)
      .filter(([name]) => !name.endsWith('_udpBlock')).every(([, check]) => check.passed) && Object.keys(report.checks).length >= 32;
    report.nativeAcceptancePassed = false;
    report.finishedAt = new Date().toISOString(); report.durationMs = Math.ceil(clock() - started);
  }
  return report;
}
