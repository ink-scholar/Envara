import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import { spawn, execFile as execFileCallback } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { MacOSLocalRoutingAdapter } from '../native/macos-local-routing/controller.mjs';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';
import { makeDiagnosticDnsResponse } from '../native/macos-local-routing/diagnostic-dns-fixture.mjs';
import { validateDnsQuery } from '../native/macos-local-routing/dns-wire.mjs';

// Explicit component acceptance with owned fixtures only. Captured DNS uses
// private DoH endpoints; the unbound fixture keeps the current system resolver.
// No user application, host trust/configuration change or readiness grant.
const root = fileURLToPath(new URL('../', import.meta.url));
const adapterOptions = {
  peerVerifierPath: path.join(root, 'build/app-routing/macos-local/EnvaraPeerVerifier'),
  bundledAppPath: path.join(root, 'build/app-routing/macos-local/Resources/Mitmproxy Redirector.app'),
  activationTimeoutMs: 180000,
};

export const DNS_MATRIX_PHASES = Object.freeze([
  { id: 'concurrentSameQuestion', simultaneous: true, order: ['one', 'two'] },
  { id: 'serialOneThenTwo', simultaneous: false, order: ['one', 'two', 'one'] },
  { id: 'serialTwoThenOne', simultaneous: false, order: ['two', 'one', 'two'] },
  { id: 'concurrentWithUnbound', simultaneous: true, order: ['one', 'two', 'unbound'] },
  { id: 'serialWithUnbound', simultaneous: false, order: ['one', 'unbound', 'two'] },
].map(value => Object.freeze({ ...value, order: Object.freeze(value.order) })));

const safeCode = value => /^[A-Z][A-Z0-9_]{1,63}$/.test(value ?? '') ? value : 'FIXTURE_UNAVAILABLE';
const negativeResolverCodes = new Set(['ENOTFOUND', 'EAI_NONAME', 'EAI_NODATA']);
const deadlineError = code => Object.assign(new Error('owned diagnostic deadline'), { code });
async function withDeadline(operation, timeoutMs, code) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(operation), new Promise((_, reject) => {
      timer = setTimeout(() => reject(deadlineError(code)), timeoutMs);
    })]);
  } finally { clearTimeout(timer); }
}

// runQuery uses each owned process's system getaddrinfo. Injectable callbacks
// let local tests exercise counterexamples without opening native capture.
// No domain, resolved address or endpoint credential is returned by this API.
export async function runSystemResolverIsolationMatrix({ routes, unbound, runQuery, observeReplies,
  markSequence = () => 0, newQuestion = () => `${randomBytes(16).toString('hex')}.example.com`,
  family = 4, queryTimeoutMs = 8000, matrixTimeoutMs = 160000 } = {}) {
  assert.equal(routes?.length, 2);
  assert.deepEqual(routes.map(value => value.name).sort(), ['one', 'two']);
  assert.equal(unbound?.name, 'unbound');
  assert.ok(family === 4 || family === 6);
  assert.ok(Number.isInteger(queryTimeoutMs) && queryTimeoutMs >= 100 && queryTimeoutMs <= 15000);
  assert.ok(Number.isInteger(matrixTimeoutMs) && matrixTimeoutMs > 0);
  assert.equal(typeof runQuery, 'function'); assert.equal(typeof observeReplies, 'function');
  const endpoints = new Map([...routes, unbound].map(value => [value.name, value]));
  const allAddresses = routes.flatMap(value => [value.address4, value.address6]);
  assert.deepEqual([...allAddresses].sort(), ['203.0.113.42', '203.0.113.43', '2001:db8::42', '2001:db8::43'].sort());
  const checks = {}, phases = [], usedQuestions = new Set();
  const deadlineAt = Date.now() + matrixTimeoutMs;
  let matrixComplete = true;
  for (const phase of DNS_MATRIX_PHASES) {
    const hostname = newQuestion();
    assert.ok(typeof hostname === 'string' && /^[a-f0-9]{16,63}\.example\.com$/i.test(hostname) && !usedQuestions.has(hostname));
    usedQuestions.add(hostname);
    const counts = new Map(), phaseKeys = [], nativeProvenRoutes = new Set();
    const execute = async (name, position) => {
      const remaining = deadlineAt - Date.now();
      if (remaining <= 0) { matrixComplete = false; return; }
      const endpoint = endpoints.get(name), bound = name !== 'unbound';
      const occurrence = (counts.get(name) ?? 0) + 1; counts.set(name, occurrence);
      const key = `family${family}_${phase.id}_${name}${occurrence > 1 ? `_repeat${occurrence}` : ''}`;
      phaseKeys.push(key);
      const own = bound ? [family === 4 ? endpoint.address4 : endpoint.address6] : [];
      const request = { id: key, type: 'dns', hostname, family, timeoutMs: Math.min(queryTimeoutMs, Math.max(100, remaining)),
        ...(bound ? family === 4 ? { expectedAddress4: endpoint.address4 } : { expectedAddress6: endpoint.address6 } : {}),
        diagnosticFixtureAddresses: allAddresses,
        otherFixtureAddresses: allAddresses.filter(value => ![endpoint.address4, endpoint.address6].includes(value)) };
      let result, replyCount = 0, nativeEvidenceAvailable = false;
      const sequence = markSequence();
      try { result = await withDeadline(() => runQuery({ endpoint, request }), Math.min(queryTimeoutMs + 1000, remaining), 'FIXTURE_IPC_TIMEOUT'); }
      catch (error) { result = { code: safeCode(error?.code), resolved: false }; }
      try {
        const evidence = await withDeadline(() => observeReplies({ endpoint, sequence, result }), Math.max(1, Math.min(1500, deadlineAt - Date.now())), 'FIXTURE_EVIDENCE_TIMEOUT');
        if (Number.isInteger(evidence?.replyCount) && evidence.replyCount >= 0) {
          replyCount = evidence.replyCount; nativeEvidenceAvailable = true;
        }
      } catch { /* A missing native reply cannot grant bound-query acceptance. */ }
      const classificationAvailable = ['own', 'other', 'unexpected'].includes(result?.answerSource) &&
        ['ownFixtureAnswerObserved', 'otherFixtureAnswerObserved', 'unexpectedAnswersObserved'].every(key => typeof result[key] === 'boolean');
      const answerSource = classificationAvailable ? result.answerSource : 'unexpected';
      const ownFixtureAnswerObserved = classificationAvailable && result.ownFixtureAnswerObserved;
      const otherFixtureAnswerObserved = classificationAvailable && result.otherFixtureAnswerObserved;
      const unexpectedAnswersObserved = classificationAvailable && result.unexpectedAnswersObserved;
      const formatEvidenceAvailable = typeof result?.canonicalFixtureAnswerObserved === 'boolean' && typeof result?.fixtureIpv4TailObserved === 'boolean' &&
        Array.isArray(result?.actualAddressFamilies) && result.actualAddressFamilies.every(value => value === 4 || value === 6);
      const canonicalFixtureAnswerObserved = formatEvidenceAvailable && result.canonicalFixtureAnswerObserved;
      const fixtureIpv4TailObserved = formatEvidenceAvailable && result.fixtureIpv4TailObserved;
      const resolverCode = safeCode(result?.code), resolved = result?.resolved === true;
      const familyAcknowledged = result?.family === family;
      const completedResolverCall = (resolved && (ownFixtureAnswerObserved || otherFixtureAnswerObserved || unexpectedAnswersObserved)) || negativeResolverCodes.has(resolverCode);
      const matchedOwnRouteAnswers = result?.matchedExpectedAddresses === true;
      const ownAnswerValidated = classificationAvailable && familyAcknowledged && resolved && matchedOwnRouteAnswers && answerSource === 'own' &&
        ownFixtureAnswerObserved && !otherFixtureAnswerObserved && !unexpectedAnswersObserved;
      // A repeat within this exact question/phase may hit a legitimate cache.
      // Only a prior authenticated native reply for this same route can supply
      // that proof; another route or an earlier random question cannot do so.
      const cacheConsistentWithOwnRoute = bound && ownAnswerValidated && nativeEvidenceAvailable && replyCount === 0 && nativeProvenRoutes.has(name);
      if (bound && ownAnswerValidated && nativeEvidenceAvailable && replyCount > 0) nativeProvenRoutes.add(name);
      checks[key] = { passed: bound ? ownAnswerValidated && nativeEvidenceAvailable && (replyCount > 0 || cacheConsistentWithOwnRoute) :
          classificationAvailable && formatEvidenceAvailable && familyAcknowledged && completedResolverCall && nativeEvidenceAvailable &&
          !ownFixtureAnswerObserved && !otherFixtureAnswerObserved && !canonicalFixtureAnswerObserved && !fixtureIpv4TailObserved && replyCount === 0,
        family, systemGetaddrinfo: true, sameRandomQuestionAcrossRoutes: true, simultaneousRequests: phase.simultaneous,
        queryPosition: position + 1,
        unboundOwnedFixture: !bound, resolverCode, resolved, completedResolverCall, classificationAvailable, familyAcknowledged,
        answerSource, ownFixtureAnswerObserved, otherFixtureAnswerObserved, unexpectedAnswersObserved,
        formatEvidenceAvailable, actualAddressFamilies: formatEvidenceAvailable ? [...new Set(result.actualAddressFamilies)].sort() : [],
        canonicalFixtureAnswerObserved, fixtureIpv4TailObserved,
        ...(bound ? { matchedOwnRouteAnswers, cacheConsistentWithOwnRoute } : { noCurrentFixtureAnswerObserved:
          formatEvidenceAvailable && !ownFixtureAnswerObserved && !otherFixtureAnswerObserved && !canonicalFixtureAnswerObserved && !fixtureIpv4TailObserved }),
        nativeEvidenceAvailable, signedDNSReplyCount: replyCount };
    };
    if (phase.simultaneous) await Promise.all(phase.order.map(execute));
    else for (const [position, name] of phase.order.entries()) await execute(name, position);
    phases.push({ id: phase.id, family, simultaneousRequests: phase.simultaneous, order: [...phase.order],
      freshQuestion: true, queriesCompleted: phaseKeys.length, requiredQueries: phase.order.length,
      passed: phaseKeys.length === phase.order.length && phaseKeys.every(key => checks[key]?.passed === true) });
    if (Date.now() >= deadlineAt) { matrixComplete = false; break; }
  }
  const unboundChecks = Object.values(checks).filter(value => value.unboundOwnedFixture);
  return { checks, resolverMatrix: { family, complete: matrixComplete && phases.length === DNS_MATRIX_PHASES.length,
      phases, answerSourceScope: 'only the current synthetic reserved fixture answers',
      queryContentsStored: false, answerAddressesStored: false, unboundScope: 'one unbound owned diagnostic process only' },
    systemResolverIsolationPassed: matrixComplete && phases.length === DNS_MATRIX_PHASES.length && phases.every(value => value.passed),
    unaffectedResolverPassed: matrixComplete && unboundChecks.length === 2 && unboundChecks.every(value => value.passed) };
}

export function aggregateDnsFamilyChecks(checks) {
  const keys = new Set(Object.keys(checks).map(key => /^family[46]_(.+)$/.exec(key)?.[1]).filter(Boolean));
  const aggregates = {};
  for (const key of keys) {
    const entries = [4, 6].map(family => checks[`family${family}_${key}`]);
    const every = field => entries.every(value => value?.[field] === true);
    aggregates[key] = { families: [4, 6], passed: every('passed'), systemGetaddrinfo: every('systemGetaddrinfo'),
      resolved: every('resolved'), resolverCodes: Object.fromEntries([4, 6].map((family, index) => [family, entries[index]?.resolverCode ?? 'FIXTURE_UNAVAILABLE'])),
      answerSource: entries.every(value => value?.answerSource === 'own') ? 'own' : entries.some(value => value?.answerSource === 'other') ? 'other' : 'unexpected',
      ownFixtureAnswerObserved: entries.some(value => value?.ownFixtureAnswerObserved === true),
      otherFixtureAnswerObserved: entries.some(value => value?.otherFixtureAnswerObserved === true),
      unexpectedAnswersObserved: entries.some(value => value?.unexpectedAnswersObserved === true),
      actualAddressFamilies: [...new Set(entries.flatMap(value => value?.actualAddressFamilies ?? []))].sort(),
      canonicalFixtureAnswerObserved: entries.some(value => value?.canonicalFixtureAnswerObserved === true),
      fixtureIpv4TailObserved: entries.some(value => value?.fixtureIpv4TailObserved === true),
      matchedOwnRouteAnswers: every('matchedOwnRouteAnswers'),
      ...(key.endsWith('_parent') || key.endsWith('_child') ? { matchedReservedIPv4AndIPv6: every('matchedOwnFamilyAnswer'),
        signedDNSReplyObserved: every('signedDNSReplyObserved'), dnsReplyCount: entries.reduce((sum, value) => sum + (value?.dnsReplyCount ?? 0), 0),
        errors: entries.flatMap(value => value?.errors ?? []) } : {
        unboundOwnedFixture: every('unboundOwnedFixture'), completedResolverCall: every('completedResolverCall'),
        sameRandomQuestionAcrossRoutes: every('sameRandomQuestionAcrossRoutes'), simultaneousRequests: every('simultaneousRequests'),
        signedDNSReplyCount: entries.reduce((sum, value) => sum + (value?.signedDNSReplyCount ?? 0), 0) }) };
  }
  return aggregates;
}

async function main(args = process.argv.slice(2)) {
if (args.some(value => value !== '--activate') || args.length > 1) throw new Error('Use explicit --activate; default is read-only.');
if (!args.includes('--activate')) {
  const adapter = new MacOSLocalRoutingAdapter(adapterOptions);
  try {
    const state = await adapter.status();
    console.log(JSON.stringify({ operation: 'plan', authorized: state.authorized, component: state.component,
      tests: 'two bound owned process families and one unbound owned process; concurrent and both serial cache orders; private authenticated SOCKS and local TLS DoH',
      launchesNotion: false, changesVPNOrTUN: false, productionReady: false }));
  } finally { await adapter.shutdown(); }
} else {
  assert.equal(process.platform, 'darwin');
  const workspace = await fs.mkdtemp('/tmp/envara-native-dns-');
  const servers = new Set(), sockets = new Set(), fixtures = [];
  let adapter;
  const report = { schemaVersion: 3, startedAt: new Date().toISOString(), platform: process.platform, resolverFamilies: [4, 6],
    osRelease: os.release(), originalComponentVersion: '0.12.11', productionReady: false,
    fullApplicationAcceptance: false, notionTested: false, scopeAcknowledged: false,
    automaticChildren: false, steadyStateObservationDelayMs: 2000,
    usesPrivateTLSFixtureOnly: true, modifiesHostCertificateTrust: false, queryContentsStored: false, answerAddressesStored: false,
    checks: {}, routes: [], cleanup: {} };
  const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {}); return socket; };
  async function listen(server) {
    servers.add(server); server.on('connection', track); server.listen({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening'); return server.address().port;
  }
  async function privateProxy(port, credentials, state) {
    const server = net.createServer({ allowHalfOpen: true }, socket => {
      (async () => {
        const reader = new SocketReader(socket);
        assert.ok((await reader.read(3)).equals(Buffer.from([5, 1, 2]))); socket.write(Buffer.from([5, 2]));
        const auth = await reader.read(2), user = (await reader.read(auth[1])).toString();
        const password = (await reader.read((await reader.read(1))[0])).toString();
        assert.equal(auth[0], 1); assert.equal(user, credentials.username); assert.equal(password, credentials.password);
        socket.write(Buffer.from([1, 0]));
        let request; try { request = await reader.read(4); } catch { return; } // private auth probe
        assert.ok(request.equals(Buffer.from([5, 1, 0, 1])));
        assert.equal([...await reader.read(4)].join('.'), '198.51.100.43');
        assert.equal((await reader.read(2)).readUInt16BE(), 44443);
        state.authenticatedConnects++;
        const upstream = track(net.createConnection({ host: '127.0.0.1', port }));
        socket.once('close', () => upstream.destroy()); upstream.once('close', () => socket.destroy());
        await once(upstream, 'connect');
        socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]));
        const buffered = reader.release(); if (buffered.length) upstream.write(buffered);
        socket.pipe(upstream); upstream.pipe(socket); socket.resume();
      })().catch(() => { state.proxyErrors++; socket.destroy(); });
    });
    return { server, port: await listen(server) };
  }
  async function spawnFixture({ withChild = true } = {}) {
    const child = spawn(process.execPath, [path.join(root, 'native/macos-local-routing/diagnostic-child.mjs')], {
      cwd: workspace, env: { PATH: '/usr/bin:/bin' }, detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const messages = [], waiters = new Set();
    const receive = (predicate, timeoutMs = 20000) => {
      const old = messages.find(predicate); if (old) return Promise.resolve(old);
      return new Promise((resolve, reject) => {
        const waiter = { predicate, finish: value => { clearTimeout(timer); waiters.delete(waiter); resolve(value); },
          cancel: () => { clearTimeout(timer); waiters.delete(waiter); reject(Object.assign(new Error('fixture stopped'), { code: 'FIXTURE_STOPPED' })); } };
        const timer = setTimeout(() => { waiters.delete(waiter); reject(Object.assign(new Error('fixture IPC deadline'), { code: 'FIXTURE_IPC_TIMEOUT' })); }, timeoutMs);
        waiters.add(waiter);
      });
    };
    child.on('message', value => { messages.push(value); for (const waiter of [...waiters]) if (waiter.predicate(value)) waiter.finish(value); });
    child.once('exit', () => { for (const waiter of [...waiters]) waiter.cancel(); });
    const fixture = { child, receive, command: request => {
      const result = receive(value => value.id === request.id && ['children-ready', 'dns-result', 'child-result', 'fixture-error'].includes(value.type),
        (request.timeoutMs ?? request.request?.timeoutMs ?? 15000) + 2000);
      if (child.connected) child.send(request, error => { if (error) for (const waiter of [...waiters]) waiter.cancel(); });
      else for (const waiter of [...waiters]) waiter.cancel();
      return result;
    } };
    fixtures.push(fixture);
    const ready = await receive(value => value.type === 'ready');
    assert.equal(ready.pid, child.pid); assert.equal(ready.parentPid, process.pid);
    if (withChild) {
      const spawned = await fixture.command({ id: 'spawn', type: 'spawn-children', count: 1 });
      assert.equal(spawned.type, 'children-ready'); assert.equal(spawned.processes.length, 1);
      fixture.childPid = spawned.processes[0].pid;
    }
    return fixture;
  }
  async function echo(socket) {
    const payload = randomBytes(64), received = [];
    return new Promise((resolve, reject) => {
      const finish = error => { clearTimeout(timer); socket.removeListener('data', data); socket.removeListener('error', failed); error ? reject(error) : resolve(true); };
      const failed = () => finish(Object.assign(new Error('unowned TCP error'), { code: 'UNOWNED_TCP_FAILED' }));
      const data = bytes => { received.push(bytes); if (Buffer.concat(received).length >= payload.length) finish(Buffer.concat(received).equals(payload) ? null : new Error('echo mismatch')); };
      const timer = setTimeout(failed, 5000); socket.on('data', data); socket.once('error', failed); socket.write(payload);
    });
  }
  async function stopFixture(fixture) {
    const child = fixture.child;
    if (child.exitCode !== null || child.signalCode !== null) return true;
    const exited = new Promise(resolve => child.once('exit', () => resolve(true)));
    try { process.kill(-child.pid, 'SIGKILL'); }
    catch (error) { if (error?.code !== 'ESRCH') return false; }
    try { return await withDeadline(() => exited, 5000, 'FIXTURE_CLEANUP_TIMEOUT'); }
    catch { return child.exitCode !== null || child.signalCode !== null; }
  }
  try {
    const key = path.join(workspace, 'fixture-key.pem'), certificate = path.join(workspace, 'fixture-cert.pem');
    await promisify(execFileCallback)('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', certificate], { maxBuffer: 16384 });
    const cert = await fs.readFile(certificate), privateKey = await fs.readFile(key);
    adapter = new MacOSLocalRoutingAdapter({ ...adapterOptions, dnsResolverOptions: {
      bootstrapIP: '198.51.100.43', port: 44443, servername: 'localhost', path: '/dns-query', testCa: cert,
    } });
    const echoPort = await listen(net.createServer(socket => socket.pipe(socket)));
    const oldSocket = track(net.createConnection({ host: '127.0.0.1', port: echoPort })); await once(oldSocket, 'connect');
    const baseline = await echo(oldSocket); assert.equal(baseline, true);
    const cases = [];
    for (const [name, address4, address6] of [['one', '203.0.113.42', '2001:db8::42'], ['two', '203.0.113.43', '2001:db8::43']]) {
      const state = { authenticatedConnects: 0, proxyErrors: 0, tlsQueries: 0, questionTypes: {}, invalidQueries: 0, diagnosticDelayMs: 0 };
      const tlsPort = await listen(https.createServer({ key: privateKey, cert, minVersion: 'TLSv1.2' }, (request, response) => {
        const chunks = []; let total = 0;
        request.on('data', bytes => { total += bytes.length; if (total > 4096) request.destroy(); else chunks.push(bytes); });
        request.on('end', () => {
          try {
            assert.equal(request.method, 'POST'); assert.equal(request.url, '/dns-query'); assert.equal(request.headers['content-type'], 'application/dns-message');
            const query = Buffer.concat(chunks), parsed = validateDnsQuery(query), type = query.readUInt16BE(parsed.questionEnd - 4);
            const answer = makeDiagnosticDnsResponse(query, { address4, address6 });
            state.tlsQueries++; state.questionTypes[type] = (state.questionTypes[type] ?? 0) + 1;
            const send = () => { if (!response.destroyed) { response.writeHead(200, { 'Content-Type': 'application/dns-message', 'Content-Length': answer.length }); response.end(answer); } };
            if (state.diagnosticDelayMs) setTimeout(send, state.diagnosticDelayMs); else send();
          } catch { state.invalidQueries++; response.writeHead(400); response.end(); }
        });
      }));
      const credentials = { username: randomBytes(12).toString('hex'), password: randomBytes(24).toString('hex') };
      const proxy = await privateProxy(tlsPort, credentials, state);
      const route = await adapter.prepareRoute({ application: { id: `app_dns_${name}`, profileId: `dns_${name}`, executablePath: process.execPath },
        workspace: { cwd: workspace }, route: { host: '127.0.0.1', port: proxy.port, ...credentials, udpPolicy: 'block' } });
      cases.push({ name, address4, address6, state, route });
    }
    console.log('Starting the authorized Mac DNS component diagnostic; only owned fixtures are launched.');
    await adapter.startCapture({ activationAuthorized: true });
    for (const entry of cases) {
      entry.fixture = await spawnFixture();
      entry.family = await adapter.bindDiagnosticFamily({ routeId: entry.route.routeId, ownerPid: process.pid,
        processes: [{ pid: entry.fixture.child.pid }, { pid: entry.fixture.childPid }] });
    }
    await adapter.setDiagnosticOptions({ dnsForwarding: true });
    await new Promise(resolve => setTimeout(resolve, report.steadyStateObservationDelayMs));
    report.checks.existingUnownedTCP = { passed: await echo(oldSocket), scope: 'one owned diagnostic controller socket established before capture' };
    const newSocket = track(net.createConnection({ host: '127.0.0.1', port: echoPort })); await once(newSocket, 'connect');
    report.checks.newUnownedTCP = { passed: await echo(newSocket), scope: 'one owned diagnostic controller socket created after capture' }; newSocket.destroy();
    for (const entry of cases) {
      for (const [role, pid] of [['parent', entry.fixture.child.pid], ['child', entry.fixture.childPid]]) {
       for (const family of [4, 6]) {
        const id = `family${family}_${entry.name}_${role}`, sequence = adapter.diagnosticSnapshot().sequence;
        const request = { id, type: 'dns', hostname: `${randomBytes(16).toString('hex')}.example.com`, family, timeoutMs: 8000,
          ...(family === 4 ? { expectedAddress4: entry.address4 } : { expectedAddress6: entry.address6 }),
          diagnosticFixtureAddresses: cases.flatMap(value => [value.address4, value.address6]),
          otherFixtureAddresses: cases.filter(value => value !== entry).flatMap(value => [value.address4, value.address6]) };
        const response = await entry.fixture.command(role === 'parent' ? request : { id, type: 'forward-child', pid, request });
        const result = response.type === 'child-result' ? response.result : response;
        const session = entry.family.sessions.find(value => value.pid === pid);
        let evidence;
        try { evidence = await adapter.waitForDiagnosticEvent({ sessionId: session.sessionId, kind: 'dns-response', afterSequence: sequence, timeoutMs: 1000 }); }
        catch { evidence = { observed: false }; }
        const events = adapter.diagnosticSnapshot().events.filter(value => value.sequence > sequence && value.pid === pid && value.routeId === entry.route.routeId && value.birth === session.birth);
        report.checks[id] = { passed: result.family === family && result.resolved === true && result.matchedExpectedAddresses === true && result.answerSource === 'own' && evidence.observed,
          family, familyAcknowledged: result.family === family, systemGetaddrinfo: true, resolverCode: result.code ?? 'FIXTURE_UNAVAILABLE', resolved: result.resolved === true,
          answerSource: ['own', 'other', 'unexpected'].includes(result.answerSource) ? result.answerSource : 'unexpected',
          ownFixtureAnswerObserved: result.ownFixtureAnswerObserved === true, otherFixtureAnswerObserved: result.otherFixtureAnswerObserved === true,
          unexpectedAnswersObserved: result.unexpectedAnswersObserved === true,
          actualAddressFamilies: Array.isArray(result.actualAddressFamilies) ? result.actualAddressFamilies.filter(value => value === 4 || value === 6) : [],
          canonicalFixtureAnswerObserved: result.canonicalFixtureAnswerObserved === true, fixtureIpv4TailObserved: result.fixtureIpv4TailObserved === true,
          matchedOwnFamilyAnswer: result.matchedExpectedAddresses === true, matchedOwnRouteAnswers: result.matchedExpectedAddresses === true,
          signedDNSReplyObserved: evidence.observed,
          dnsReplyCount: events.filter(value => value.kind === 'dns-response').length,
          errors: events.filter(value => value.kind === 'dns-error').map(value => value.code) };
       }
      }
    }
    // The macOS resolver may share caches or coalesce identical outstanding
    // questions across clients. Unique per-process names do not prove isolation.
    for (const entry of cases) entry.state.diagnosticDelayMs = 200;
    const unbound = { name: 'unbound', fixture: await spawnFixture({ withChild: false }) };
    const matrices = [];
    for (const family of [4, 6]) {
    const matrix = await runSystemResolverIsolationMatrix({ routes: cases, unbound, family,
      markSequence: () => adapter.diagnosticSnapshot().sequence,
      runQuery: ({ endpoint, request }) => endpoint.fixture.command(request),
      observeReplies: async ({ endpoint, sequence }) => {
        const pid = endpoint.fixture.child.pid;
        const session = endpoint.family?.sessions.find(value => value.pid === pid);
        if (session) {
          try { await adapter.waitForDiagnosticEvent({ sessionId: session.sessionId, kind: 'dns-response', afterSequence: sequence, timeoutMs: 1000 }); }
          catch { /* Preserve zero evidence for cache/coalescing diagnostics. */ }
        } else await new Promise(resolve => setTimeout(resolve, 150));
        const events = adapter.diagnosticSnapshot().events.filter(value => value.sequence > sequence && value.pid === pid &&
          value.kind === 'dns-response' && (!session || (value.routeId === endpoint.route.routeId && value.birth === session.birth)));
        return { replyCount: events.length };
      } });
    Object.assign(report.checks, matrix.checks);
    matrices.push(matrix);
    }
    Object.assign(report.checks, aggregateDnsFamilyChecks(report.checks));
    report.resolverMatrix = { families: matrices.map(value => value.resolverMatrix),
      complete: matrices.every(value => value.resolverMatrix.complete), queryContentsStored: false, answerAddressesStored: false,
      answerSourceScope: 'only the current synthetic reserved fixture answers', unboundScope: 'one unbound owned diagnostic process only' };
    report.systemResolverIsolationPassed = matrices.every(value => value.systemResolverIsolationPassed);
    report.unaffectedResolverPassed = matrices.every(value => value.unaffectedResolverPassed);
    for (const entry of cases) report.routes.push({ name: entry.name, ...entry.state });
    report.capture = (await adapter.status()).capture;
    report.decoderRejections = adapter.diagnosticSnapshot().rejections;
  } catch (error) { report.error = /^[A-Z][A-Z0-9_]{1,63}$/.test(error?.code ?? '') ? error.code : 'NATIVE_DNS_ACCEPTANCE_FAILED'; }
  finally {
    const cleanupResults = await Promise.all(fixtures.map(stopFixture));
    report.cleanup.fixtureParentsExited = cleanupResults.every(Boolean) && fixtures.every(value => value.child.exitCode !== null || value.child.signalCode !== null);
    try { if (adapter) await adapter.shutdown(); report.cleanup.captureClosed = true; } catch { report.cleanup.captureClosed = false; }
    for (const socket of sockets) socket.destroy();
    report.cleanup.privateFixtureServersClosed = true;
    for (const server of servers) if (server.listening) {
      try { await withDeadline(() => new Promise(resolve => server.close(resolve)), 3000, 'FIXTURE_SERVER_CLEANUP_TIMEOUT'); }
      catch { report.cleanup.privateFixtureServersClosed = false; }
    }
    await fs.rm(workspace, { recursive: true, force: true });
    report.cleanup.privateFixtureWorkspaceRemoved = true;
    report.finishedAt = new Date().toISOString();
    report.isolatedQueriesPassed = ['one_parent', 'one_child', 'two_parent', 'two_child', 'existingUnownedTCP', 'newUnownedTCP'].every(key => report.checks[key]?.passed === true) &&
      report.routes.length === 2 && report.routes.every(value => value.authenticatedConnects > 0 && value.tlsQueries > 0 && value.invalidQueries === 0) &&
      report.cleanup.fixtureParentsExited && report.cleanup.captureClosed && report.cleanup.privateFixtureServersClosed;
    report.systemResolverIsolationPassed = report.systemResolverIsolationPassed === true;
    report.unaffectedResolverPassed = report.unaffectedResolverPassed === true;
    report.nativeDNSComponentPassed = report.isolatedQueriesPassed && report.systemResolverIsolationPassed && report.unaffectedResolverPassed;
    const output = path.join(root, 'test-artifacts/mac-routing'); await fs.mkdir(output, { recursive: true });
    const data = JSON.stringify(report, null, 2) + '\n';
    await fs.writeFile(path.join(output, `native-dns-${report.startedAt.replaceAll(':', '-')}.json`), data, { flag: 'wx', mode: 0o600 });
    await fs.writeFile(path.join(output, 'native-dns.json'), data, { mode: 0o600 });
    console.log(JSON.stringify(report));
    if (!report.nativeDNSComponentPassed) process.exitCode = 1;
  }
}
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
