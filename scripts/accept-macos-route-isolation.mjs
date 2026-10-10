import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { MacOSLocalRoutingAdapter } from '../native/macos-local-routing/controller.mjs';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';

// Native diagnostic only. Default mode inspects status; only --activate starts
// the original signed component and these owned, inert-until-command fixtures.
const root = fileURLToPath(new URL('../', import.meta.url));
const target = Object.freeze({ host: '198.51.100.42', port: 40443 });
const payloadBytes = 2048;
const timeout = code => Object.assign(new Error('owned diagnostic did not complete'), { code });
const safeCode = value => /^[A-Z][A-Z0-9_]{1,95}$/.test(value ?? '') ? value : 'ROUTE_ISOLATION_FAILED';
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function deadline(operation, ms, code) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(operation), new Promise((_, reject) => {
      timer = setTimeout(() => reject(timeout(code)), ms);
    })]);
  } finally { clearTimeout(timer); }
}

function adapterOptions(onEvent) {
  return {
    peerVerifierPath: path.join(root, 'build/app-routing/macos-local/EnvaraPeerVerifier'),
    bundledAppPath: path.join(root, 'build/app-routing/macos-local/Resources/Mitmproxy Redirector.app'),
    activationTimeoutMs: 180000,
    onEvent,
  };
}

export async function main(args = process.argv.slice(2)) {
  if (args.length > 1 || args.some(value => value !== '--activate')) throw timeout('FIXTURE_ARGUMENT_INVALID');
  const peerRejections = [];
  const adapter = new MacOSLocalRoutingAdapter(adapterOptions(event => {
    if (event.type === 'capture-peer-rejected') peerRejections.push({ code: safeCode(event.code) });
  }));
  if (!args.includes('--activate')) {
    try {
      const state = await adapter.status();
      console.log(JSON.stringify({ operation: 'plan', platform: process.platform, component: state.component,
        installed: state.installed, authorized: state.authorized, explicitActivationRequired: true,
        target, ownedFamilies: 2, ownedProcesses: 4, independentAuthenticatedRoutes: 2,
        checks: ['four simultaneous same-destination streams', 'route A revocation', 'route B continuity', 'unbound old and new loopback streams'],
        changesVPNOrTUN: false, launchesUserApplications: false, scopeAcknowledged: false,
        productionReady: false, automaticChildren: false, entireGuardCrashTested: false }));
    } finally { await adapter.shutdown(); }
    return;
  }
  if (process.platform !== 'darwin') throw timeout('FIXTURE_PLATFORM_UNSUPPORTED');

  const workspace = await fs.mkdtemp('/tmp/envara-route-isolation-');
  const servers = new Set(), sockets = new Set(), fixtures = [], owned = new Map();
  const report = { schemaVersion: 1, operation: 'native-route-isolation', startedAt: new Date().toISOString(),
    platform: process.platform, osRelease: os.release(), originalComponentVersion: '0.12.11', target,
    productionReady: false, fullApplicationAcceptance: false, automaticChildren: false,
    entireGuardCrashTested: false, scopeAcknowledged: false, atomicFamilyCapture: false,
    changesVPNOrTUN: false, launchesUserApplications: false, payloadsStored: false, credentialsStored: false,
    steadyStateObservationDelayMs: 2000, checks: {}, families: [], routes: [], cleanup: {} };
  let oldLoopback;
  let interrupted = false;
  const track = socket => {
    sockets.add(socket); socket.on('error', () => {}); socket.once('close', () => sockets.delete(socket)); return socket;
  };
  const interrupt = () => {
    interrupted = true;
    for (const fixture of fixtures) fixture.cancel();
    for (const socket of sockets) socket.destroy();
  };
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  const requireRunning = () => { if (interrupted) throw timeout('FIXTURE_INTERRUPTED'); };
  async function listen(server) {
    servers.add(server);
    server.on('error', () => {});
    return deadline(() => new Promise((resolve, reject) => {
      const failed = () => { server.removeListener('listening', listening); reject(timeout('FIXTURE_LISTEN_FAILED')); };
      const listening = () => { server.removeListener('error', failed); resolve(server.address().port); };
      server.once('error', failed); server.once('listening', listening);
      server.listen({ host: '127.0.0.1', port: 0 });
    }), 5000, 'FIXTURE_LISTEN_TIMEOUT');
  }
  const routeFixtures = ['A', 'B'].map(name => ({ name, credentials: {
    username: randomBytes(12).toString('hex'), password: randomBytes(24).toString('hex'),
  }, payloads: new Map(['parent_initial', 'child_initial', 'parent_retry', 'child_retry'].map(key => [key, randomBytes(payloadBytes)])),
  counters: { authenticated: 0, authenticatedConnects: 0, acceptedPayloads: 0, crossRouteRejected: 0,
    unexpectedPayloadRejected: 0, authenticationRejected: 0, unexpectedDestinationRejected: 0 },
  accepted: new Map(), active: new Map() }));

  async function createSocks(route) {
    const other = routeFixtures.find(value => value !== route);
    const server = net.createServer({ allowHalfOpen: true }, socket => {
      track(socket);
      const reader = new SocketReader(socket);
      let acceptedKey, readerReleased = false;
      const timer = setTimeout(() => socket.destroy(), 8000);
      socket.once('close', () => { clearTimeout(timer); if (acceptedKey && route.active.get(acceptedKey) === socket) route.active.delete(acceptedKey); });
      (async () => {
        if (!(await reader.read(3)).equals(Buffer.from([5, 1, 2]))) throw timeout('FIXTURE_GREETING_INVALID');
        socket.write(Buffer.from([5, 2]));
        const auth = await reader.read(2), username = (await reader.read(auth[1])).toString();
        const password = (await reader.read((await reader.read(1))[0])).toString();
        if (auth[0] !== 1 || username !== route.credentials.username || password !== route.credentials.password) {
          route.counters.authenticationRejected++; throw timeout('FIXTURE_AUTHENTICATION_REJECTED');
        }
        route.counters.authenticated++; socket.write(Buffer.from([1, 0]));
        let connect;
        try { connect = await reader.read(4); } catch { return; } // Adapter's authentication-only probe.
        if (!connect.equals(Buffer.from([5, 1, 0, 1]))) { route.counters.unexpectedDestinationRejected++; throw timeout('FIXTURE_DESTINATION_REJECTED'); }
        const host = [...await reader.read(4)].join('.'), port = (await reader.read(2)).readUInt16BE();
        if (host !== target.host || port !== target.port) { route.counters.unexpectedDestinationRejected++; throw timeout('FIXTURE_DESTINATION_REJECTED'); }
        route.counters.authenticatedConnects++;
        socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]));
        const payload = await reader.read(payloadBytes);
        acceptedKey = [...route.payloads].find(([, expected]) => expected.equals(payload))?.[0];
        if (!acceptedKey) {
          if ([...other.payloads.values()].some(expected => expected.equals(payload))) route.counters.crossRouteRejected++;
          else route.counters.unexpectedPayloadRejected++;
          throw timeout('FIXTURE_PAYLOAD_REJECTED');
        }
        const extra = reader.release(); readerReleased = true;
        if (extra.length || route.accepted.has(acceptedKey)) { route.counters.unexpectedPayloadRejected++; throw timeout('FIXTURE_PAYLOAD_REJECTED'); }
        clearTimeout(timer); route.counters.acceptedPayloads++;
        route.accepted.set(acceptedKey, 1); route.active.set(acceptedKey, socket);
        // Echo only after this route's entire pre-generated payload matched.
        // No direct destination connection or DNS operation exists here.
        socket.write(payload);
        socket.on('data', () => { route.counters.unexpectedPayloadRejected++; socket.destroy(); });
        socket.once('end', () => socket.end()); socket.resume();
      })().catch(() => socket.destroy()).finally(() => {
        if (!readerReleased) {
          if (reader.pending) reader.fail(timeout('FIXTURE_SOCKET_CLOSED'));
          try { reader.release(); } catch {}
        }
      });
    });
    route.port = await listen(server);
  }

  async function spawnFixture(route) {
    const child = spawn(process.execPath, [path.join(root, 'native/macos-local-routing/diagnostic-child.mjs')], {
      cwd: workspace, env: { PATH: '/usr/bin:/bin' }, detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const messages = [], waiters = new Set();
    let gone = false;
    function receive(predicate, ms = 15000) {
      const existing = messages.find(predicate);
      if (existing) return Promise.resolve(existing);
      if (gone || interrupted) return Promise.reject(timeout(interrupted ? 'FIXTURE_INTERRUPTED' : 'FIXTURE_STOPPED'));
      return new Promise((resolve, reject) => {
        const waiter = { predicate, finish: value => { clearTimeout(timer); waiters.delete(waiter); resolve(value); },
          cancel: () => { clearTimeout(timer); waiters.delete(waiter); reject(timeout('FIXTURE_STOPPED')); } };
        const timer = setTimeout(() => { waiters.delete(waiter); reject(timeout('FIXTURE_IPC_TIMEOUT')); }, ms);
        waiters.add(waiter);
      });
    }
    const fixture = { child, route, messages, receive, cancel: () => { for (const waiter of [...waiters]) waiter.cancel(); },
      command: async request => {
        requireRunning();
        const result = receive(value => value.id === request.id && ['children-ready', 'tcp-result', 'child-result', 'fixture-error'].includes(value.type));
        child.send(request, error => { if (error) fixture.cancel(); });
        return result;
      } };
    fixtures.push(fixture);
    child.on('message', value => { messages.push(value); for (const waiter of [...waiters]) if (waiter.predicate(value)) waiter.finish(value); });
    child.once('exit', () => { gone = true; fixture.cancel(); });
    child.once('error', () => { gone = true; fixture.cancel(); });
    const ready = await receive(value => value?.type === 'ready', 6000);
    if (ready.pid !== child.pid || ready.parentPid !== process.pid) throw timeout('FIXTURE_OWNERSHIP_MISMATCH');
    const parentIdentity = await adapter.native.identity(child.pid);
    owned.set(child.pid, { ...parentIdentity, role: `${route.name}_parent` });
    const descendants = await fixture.command({ id: `spawn_${route.name}`, type: 'spawn-children', count: 1 });
    const descendant = descendants.processes?.[0];
    if (descendants.type !== 'children-ready' || descendants.processes.length !== 1 || descendant.parentPid !== child.pid) throw timeout('FIXTURE_OWNERSHIP_MISMATCH');
    const childIdentity = await adapter.native.identity(descendant.pid);
    owned.set(descendant.pid, { ...childIdentity, role: `${route.name}_child` });
    if ([parentIdentity, childIdentity].some(value => value.alive !== true || value.uid !== process.getuid()) ||
        parentIdentity.parentPid !== process.pid || childIdentity.parentPid !== child.pid) throw timeout('FIXTURE_OWNERSHIP_MISMATCH');
    const family = await adapter.bindDiagnosticFamily({ routeId: route.routeId, ownerPid: process.pid,
      processes: [{ pid: child.pid, birth: parentIdentity.birth }, { pid: descendant.pid, birth: childIdentity.birth }] });
    if (!family.explicitFamilyBound || family.automaticChildren !== false || family.atomic !== false) throw timeout('FIXTURE_FAMILY_CONTRACT_INVALID');
    route.sessions = family.sessions; route.fixture = fixture; route.childPid = descendant.pid;
    report.families.push({ name: route.name, explicitFamilyBound: true, automaticChildren: false,
      sessions: family.sessions.map(value => ({ pid: value.pid, birth: value.birth, routeId: value.routeId })) });
  }

  function tcp(route, role, phase, mode = 'normal') {
    const id = `${route.name}_${role}_${phase}`, pid = role === 'parent' ? route.fixture.child.pid : route.childPid;
    const request = { id, type: 'tcp', target, payload: route.payloads.get(`${role}_${phase}`).toString('hex'), mode };
    const command = role === 'parent' ? request : { id, type: 'forward-child', pid, request };
    const result = route.fixture.command(command).then(value => value.type === 'child-result' ? value.result : value);
    // Held streams deliberately finish later; attach a handler immediately.
    result.catch(() => {});
    const progress = mode === 'hold' ? route.fixture.receive(value => value.id === id &&
      (value.type === 'tcp-progress' || value.type === 'child-progress')).then(value => value.result ?? value) : null;
    return { id, pid, role, route, result, progress, session: route.sessions.find(value => value.pid === pid) };
  }
  const isEvidence = (event, stream) => event?.kind === 'tcp-response' && event.pid === stream.pid &&
    event.birth === stream.session.birth && event.routeId === stream.route.routeId &&
    event.host === target.host && event.port === target.port;
  const observe = (stream, afterSequence) => adapter.waitForDiagnosticEvent({ sessionId: stream.session.sessionId,
    kind: 'tcp-response', afterSequence, timeoutMs: 12000 });

  async function connectLoopback(port) {
    const socket = track(net.createConnection({ host: '127.0.0.1', port }));
    await deadline(() => new Promise((resolve, reject) => {
      const cleanup = () => { socket.removeListener('connect', connected); socket.removeListener('error', failed); socket.removeListener('close', failed); };
      const connected = () => { cleanup(); resolve(); }, failed = () => { cleanup(); reject(timeout('FIXTURE_LOOPBACK_FAILED')); };
      socket.once('connect', connected); socket.once('error', failed); socket.once('close', failed);
    }), 5000, 'FIXTURE_LOOPBACK_TIMEOUT');
    return socket;
  }
  async function loopbackExchange(socket) {
    const payload = randomBytes(128), reader = new SocketReader(socket);
    try { socket.write(payload); const bytes = await deadline(() => reader.read(payload.length), 3000, 'FIXTURE_LOOPBACK_TIMEOUT'); return bytes.equals(payload); }
    finally { if (reader.pending) reader.fail(timeout('FIXTURE_SOCKET_CLOSED')); try { reader.release(); } catch {}; socket.resume(); }
  }
  async function waitUntil(predicate, ms = 3000) {
    const end = Date.now() + ms;
    while (Date.now() < end) { if (await predicate()) return true; await delay(30); }
    return false;
  }

  try {
    const echo = net.createServer(socket => { track(socket); socket.pipe(socket); });
    const echoPort = await listen(echo);
    oldLoopback = await connectLoopback(echoPort);
    report.checks.unboundOldBeforeCapture = { passed: await loopbackExchange(oldLoopback), processSelected: false };
    for (const route of routeFixtures) {
      await createSocks(route);
      const prepared = await adapter.prepareRoute({ application: { id: `app_isolation_${route.name}`, profileId: `isolation_${route.name}`, executablePath: process.execPath },
        workspace: { cwd: workspace }, route: { host: '127.0.0.1', port: route.port, ...route.credentials, udpPolicy: 'block' } });
      route.routeId = prepared.routeId;
    }
    report.checks.independentAuthenticatedRoutes = { passed: routeFixtures[0].port !== routeFixtures[1].port &&
      routeFixtures[0].credentials.username !== routeFixtures[1].credentials.username &&
      routeFixtures[0].credentials.password !== routeFixtures[1].credentials.password,
      listeners: 2, credentialsDistinct: true, loopbackOnly: true };
    requireRunning(); await adapter.startCapture({ activationAuthorized: true });
    report.signedControlConnected = true;
    for (const route of routeFixtures) await spawnFixture(route);
    await delay(report.steadyStateObservationDelayMs); requireRunning();

    const baseline = adapter.diagnosticSnapshot().sequence;
    const streams = routeFixtures.flatMap(route => ['parent', 'child'].map(role => tcp(route, role, 'initial', 'hold')));
    const outcomes = await Promise.all(streams.map(async stream => {
      const [progress, witness] = await Promise.all([stream.progress, observe(stream, baseline)]);
      return { stream, passed: progress.passed === true && progress.receivedBytes === payloadBytes && witness.observed === true && isEvidence(witness.event, stream), witness };
    }));
    report.checks.concurrentFourSameDestination = { passed: outcomes.every(value => value.passed) &&
      routeFixtures.every(route => route.active.has('parent_initial') && route.active.has('child_initial')),
      processes: 4, simultaneouslyOpenStreams: routeFixtures.reduce((sum, route) => sum + route.active.size, 0),
      signedResponses: outcomes.map(({ stream, witness }) => ({ pid: stream.pid, birth: stream.session.birth,
        routeId: stream.route.routeId, observed: witness.observed, sequence: witness.event.sequence,
        observedAt: witness.event.observedAt, receivedBytes: payloadBytes })) };
    if (!report.checks.concurrentFourSameDestination.passed) throw timeout('FIXTURE_CONCURRENT_WITNESS_FAILED');

    const [routeA, routeB] = routeFixtures;
    const metricsBeforeRevoke = { ...adapter.bridge.metrics };
    const revocation = await adapter.revoke({ routeId: routeA.routeId });
    const endedA = await Promise.all(streams.filter(stream => stream.route === routeA).map(stream => stream.result));
    const oldAClosed = await waitUntil(() => routeA.active.size === 0);
    report.checks.routeAExistingStreamsRevoked = { passed: revocation.revoked === true && revocation.interceptionRetained === true && oldAClosed &&
      endedA.every(value => ['FIXTURE_EOF', 'FIXTURE_CLOSED', 'FIXTURE_ERROR'].includes(value.code)),
      interceptionRetained: revocation.interceptionRetained === true, closedStreams: endedA.length,
      processesTerminated: false };

    const retryBaseline = adapter.diagnosticSnapshot().sequence;
    const connectCountsBeforeRetry = routeFixtures.map(route => route.counters.authenticatedConnects);
    const retries = routeFixtures.flatMap(route => ['parent', 'child'].map(role => tcp(route, role, 'retry')));
    const retryResults = await Promise.all(retries.map(async stream => {
      const response = await stream.result;
      if (stream.route === routeA) return { stream, response };
      const witness = await observe(stream, retryBaseline);
      return { stream, response, witness };
    }));
    const rejectedA = retryResults.filter(value => value.stream.route === routeA);
    const continuedB = retryResults.filter(value => value.stream.route === routeB);
    report.checks.routeANewStreamsBlocked = { passed: rejectedA.every(({ response }) => response.type === 'tcp-result' &&
      response.passed === false && response.receivedBytes === 0 && ['FIXTURE_EOF', 'FIXTURE_CLOSED', 'FIXTURE_ERROR'].includes(response.code)) &&
      adapter.bridge.metrics.unknownBlocked - metricsBeforeRevoke.unknownBlocked >= 2 &&
      adapter.bridge.metrics.tcpObserved - metricsBeforeRevoke.tcpObserved >= 4 &&
      routeA.counters.authenticatedConnects === connectCountsBeforeRetry[0],
      refusedProcesses: rejectedA.length, receivedBytes: rejectedA.reduce((sum, value) => sum + (value.response.receivedBytes ?? 0), 0),
      signedBridgeUnknownBlockedDelta: adapter.bridge.metrics.unknownBlocked - metricsBeforeRevoke.unknownBlocked,
      noNewRouteAUpstreamConnect: routeA.counters.authenticatedConnects === connectCountsBeforeRetry[0] };
    report.checks.routeBNewStreamsContinue = { passed: continuedB.every(({ stream, response, witness }) => response.passed === true &&
      response.receivedBytes === payloadBytes && witness.observed === true && isEvidence(witness.event, stream)),
      successfulProcesses: continuedB.length, signedResponses: continuedB.map(({ stream, witness }) => ({ pid: stream.pid,
        birth: stream.session.birth, routeId: stream.route.routeId, observed: witness.observed,
        sequence: witness.event.sequence, observedAt: witness.event.observedAt })) };
    report.checks.routeBExistingStreamsContinue = { passed: routeB.active.has('parent_initial') && routeB.active.has('child_initial') &&
      streams.filter(stream => stream.route === routeB).every(stream => !routeB.fixture.messages.some(value => value.id === stream.id &&
        ['tcp-result', 'child-result'].includes(value.type))), retainedOpenStreams: ['parent_initial', 'child_initial'].filter(key => routeB.active.has(key)).length,
      scope: 'existing streams remain open while new route B requests complete' };

    const connectsBeforeUnbound = routeFixtures.map(route => route.counters.authenticatedConnects);
    const sequenceBeforeUnbound = adapter.diagnosticSnapshot().sequence;
    const oldPassed = await loopbackExchange(oldLoopback);
    const newLoopback = await connectLoopback(echoPort);
    const newPassed = await loopbackExchange(newLoopback); newLoopback.destroy();
    report.checks.unboundOldAndNewLoopbackUnaffected = { passed: oldPassed && newPassed &&
      routeFixtures.every((route, index) => route.counters.authenticatedConnects === connectsBeforeUnbound[index]) &&
      !adapter.diagnosticSnapshot().events.some(event => event.sequence > sequenceBeforeUnbound && event.pid === process.pid),
      oldConnectionPassed: oldPassed, newConnectionPassed: newPassed, processSelected: false,
      scope: 'this unbound diagnostic parent and its owned loopback echo only' };
    report.checks.noCrossRoutePayload = { passed: routeFixtures.every(route => route.counters.crossRouteRejected === 0 &&
      route.counters.unexpectedPayloadRejected === 0 && route.counters.authenticationRejected === 0 &&
      route.counters.unexpectedDestinationRejected === 0) &&
      routeA.accepted.size === 2 && routeB.accepted.size === 4,
      expectedAcceptedPayloads: { A: 2, B: 4 }, payloadContentsStored: false };
    report.capture = { controlConnected: !!adapter.bridge?.control && !adapter.bridge.control.destroyed && !adapter.bridge.faulted,
      metrics: { ...adapter.bridge.metrics } };
    report.peerRejections = peerRejections;
  } catch (error) { report.error = interrupted ? 'FIXTURE_INTERRUPTED' : safeCode(error?.code); }
  finally {
    // Ask owned handles to exit first. Any forced PID signal additionally needs
    // the saved birth identity; never signal the original signed provider.
    for (const fixture of fixtures) if (fixture.child.connected) {
      try { fixture.child.send({ id: 'exit', type: 'exit' }, () => {}); } catch {}
    }
    await delay(200);
    const terminationErrors = [];
    for (const entry of [...owned.values()].reverse()) {
      try {
        const actual = await adapter.native.identity(entry.pid);
        if (actual.alive === true && actual.birth === entry.birth && actual.uid === entry.uid && actual.path === entry.path) process.kill(entry.pid, 'SIGKILL');
        else if (actual.alive !== false && !(actual.alive === true && actual.birth !== entry.birth)) terminationErrors.push('FIXTURE_IDENTITY_UNCERTAIN');
      } catch (error) { if (error?.code !== 'ESRCH') terminationErrors.push('FIXTURE_TERMINATION_UNVERIFIED'); }
    }
    report.cleanup.ownedProcessesExited = await waitUntil(async () => {
      const identities = await Promise.all([...owned.values()].map(entry => adapter.native.identity(entry.pid).then(actual =>
        actual.alive === false || (actual.alive === true && actual.birth !== entry.birth)).catch(() => false)));
      return identities.every(Boolean) && fixtures.every(fixture => fixture.child.exitCode !== null || fixture.child.signalCode !== null);
    }, 5000);
    report.cleanup.terminationErrors = terminationErrors;
    for (const fixture of fixtures) fixture.cancel();
    try { await adapter.shutdown(); report.cleanup.captureClosed = true; } catch (error) {
      report.cleanup.captureClosed = false; report.cleanup.captureCloseCode = safeCode(error?.code);
    }
    for (const socket of sockets) socket.destroy();
    report.cleanup.listenersClosed = true;
    for (const server of servers) {
      try {
        if (server.listening) await deadline(() => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())), 3000, 'FIXTURE_LISTENER_CLOSE_TIMEOUT');
        if (server.listening) report.cleanup.listenersClosed = false;
      } catch { report.cleanup.listenersClosed = false; }
    }
    try { await fs.rm(workspace, { recursive: true, force: true }); report.cleanup.temporaryDirectoryRemoved = true; }
    catch { report.cleanup.temporaryDirectoryRemoved = false; }
    report.routes = routeFixtures.map(route => ({ name: route.name, routeId: route.routeId ?? null,
      ...route.counters, acceptedPayloadCount: route.accepted.size }));
    report.finishedAt = new Date().toISOString();
    const required = ['unboundOldBeforeCapture', 'independentAuthenticatedRoutes', 'concurrentFourSameDestination',
      'routeAExistingStreamsRevoked', 'routeANewStreamsBlocked', 'routeBNewStreamsContinue', 'routeBExistingStreamsContinue',
      'unboundOldAndNewLoopbackUnaffected', 'noCrossRoutePayload'];
    report.diagnosticIsolationPassed = !report.error && required.every(key => report.checks[key]?.passed === true) &&
      report.cleanup.ownedProcessesExited && report.cleanup.captureClosed && report.cleanup.listenersClosed &&
      report.cleanup.temporaryDirectoryRemoved && terminationErrors.length === 0;
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
    const output = path.join(root, 'test-artifacts/mac-routing'); await fs.mkdir(output, { recursive: true });
    const filename = `route-isolation-${report.startedAt.replaceAll(':', '-')}.json`;
    await fs.writeFile(path.join(output, filename), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    console.log(JSON.stringify(report));
    if (!report.diagnosticIsolationPassed) process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.log(JSON.stringify({ operation: 'route-isolation', error: safeCode(error?.code),
      productionReady: false, automaticChildren: false, entireGuardCrashTested: false }));
    process.exitCode = 1;
  });
}
