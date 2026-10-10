import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { MacOSLocalRoutingAdapter } from '../native/macos-local-routing/controller.mjs';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';

// This is an explicit native diagnostic, never a production readiness grant.
const root = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
if (args.some(value => !['--activate', '--dns'].includes(value))) throw new Error('Use explicit --activate, optionally --dns; default is read-only.');
const adapter = new MacOSLocalRoutingAdapter({
  peerVerifierPath: path.join(root, 'build/app-routing/macos-local/EnvaraPeerVerifier'),
  bundledAppPath: path.join(root, 'build/app-routing/macos-local/Resources/Mitmproxy Redirector.app'),
  activationTimeoutMs: 180000,
});
if (!args.includes('--activate')) {
  const state = await adapter.status();
  console.log(JSON.stringify({ operation: 'plan', component: state.component, authorized: state.authorized,
    target: 'owned parent and child Node fixtures', testsNotion: false, changesVPNOrTUN: false,
    observesSystemDNS: args.includes('--dns'), productionReady: false }));
  await adapter.shutdown();
} else {
  const workspace = await fs.mkdtemp('/tmp/envara-native-matrix-');
  const user = randomBytes(12).toString('hex'), password = randomBytes(24).toString('hex');
  const connections = new Set(), destinations = [], waiters = new Set(), messages = [];
  let fixture, socksClosed = false;
  const report = { schemaVersion: 1, startedAt: new Date().toISOString(), platform: process.platform,
    osRelease: os.release(), originalComponentVersion: '0.12.11', productionReady: false,
    fullApplicationAcceptance: false, notionTested: false, scopeAcknowledged: false,
    steadyStateObservationDelayMs: 2000, checks: {}, cleanup: {} };
  const socks = net.createServer({ allowHalfOpen: true }, socket => {
    connections.add(socket); socket.once('close', () => connections.delete(socket)); socket.on('error', () => {});
    (async () => {
      const reader = new SocketReader(socket);
      if (!(await reader.read(3)).equals(Buffer.from([5, 1, 2]))) throw new Error('fixture greeting');
      socket.write(Buffer.from([5, 2]));
      const auth = await reader.read(2), actualUser = (await reader.read(auth[1])).toString();
      const actualPass = (await reader.read((await reader.read(1))[0])).toString();
      if (auth[0] !== 1 || actualUser !== user || actualPass !== password) throw new Error('fixture auth');
      socket.write(Buffer.from([1, 0]));
      let request;
      try { request = await reader.read(4); } catch { return; } // owned private authentication probe
      if (!request.equals(Buffer.from([5, 1, 0, 1]))) throw new Error('fixture CONNECT');
      const host = [...await reader.read(4)].join('.'), port = (await reader.read(2)).readUInt16BE();
      if (host !== '198.51.100.42' || port !== 40443) throw new Error('unexpected fixture destination');
      destinations.push({ host, port });
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]));
      const buffered = reader.release();
      if (buffered.length) socket.write(buffered);
      socket.pipe(socket); socket.resume();
    })().catch(() => socket.destroy());
  });
  function arrive(value) {
    messages.push(value);
    for (const waiter of [...waiters]) if (waiter.predicate(value)) waiter.finish(value);
  }
  function receive(predicate, timeoutMs = 15000) {
    const existing = messages.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const waiter = { predicate, finish: value => { clearTimeout(timer); waiters.delete(waiter); resolve(value); },
        cancel: () => { clearTimeout(timer); waiters.delete(waiter); reject(Object.assign(new Error('fixture stopped'), { code: 'FIXTURE_STOPPED' })); } };
      const timer = setTimeout(() => { waiters.delete(waiter); reject(Object.assign(new Error('fixture IPC deadline'), { code: 'FIXTURE_IPC_TIMEOUT' })); }, timeoutMs);
      waiters.add(waiter);
    });
  }
  const command = request => {
    const result = receive(value => value.id === request.id && ['children-ready', 'tcp-result', 'udp-result', 'dns-result', 'child-result', 'fixture-error'].includes(value.type),
      request.type === 'dns' || request.request?.type === 'dns' ? 20000 : 15000);
    fixture.send(request); return result;
  };
  const observe = (session, kind, afterSequence) => adapter.waitForDiagnosticEvent({ sessionId: session.sessionId, kind, afterSequence, timeoutMs: 15000 });
  try {
    socks.listen({ host: '127.0.0.1', port: 0 }); await once(socks, 'listening');
    const route = await adapter.prepareRoute({ application: { id: 'app_matrix_fixture', profileId: 'matrix_fixture', executablePath: process.execPath },
      workspace: { cwd: workspace }, route: { host: '127.0.0.1', port: socks.address().port, username: user, password, udpPolicy: 'block' } });
    console.log('Starting the authorized native diagnostic. No user application is launched.');
    await adapter.startCapture({ activationAuthorized: true });
    fixture = spawn(process.execPath, [path.join(root, 'native/macos-local-routing/diagnostic-child.mjs')], {
      cwd: workspace, env: { PATH: '/usr/bin:/bin' }, detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    fixture.on('message', arrive); fixture.once('exit', () => { for (const waiter of [...waiters]) waiter.cancel(); });
    const waiting = await receive(value => value.type === 'ready');
    if (waiting.pid !== fixture.pid || waiting.parentPid !== process.pid) throw new Error('fixture ownership');
    const children = await command({ id: 'spawn', type: 'spawn-children', count: 1 });
    if (children.type !== 'children-ready' || children.processes.length !== 1) throw new Error('child startup');
    const childPid = children.processes[0].pid;
    const family = await adapter.bindDiagnosticFamily({ routeId: route.routeId, ownerPid: process.pid,
      processes: [{ pid: fixture.pid }, { pid: childPid }] });
    report.explicitFamilyBound = family.explicitFamilyBound;
    report.automaticChildren = family.automaticChildren; report.atomicFamilyCapture = family.atomic;
    await adapter.setDiagnosticOptions({ sampleUdp: true });
    await new Promise(resolve => setTimeout(resolve, report.steadyStateObservationDelayMs));
    const session = pid => family.sessions.find(value => value.pid === pid);
    const target = { host: '198.51.100.42', port: 40443 };
    for (const [name, pid] of [['parentTCP', fixture.pid], ['childTCP', childPid]]) {
      const sequence = adapter.diagnosticSnapshot().sequence;
      const payload = randomBytes(2048).toString('hex');
      const request = { id: name, type: 'tcp', target, payload, mode: 'normal' };
      const response = await command(pid === fixture.pid ? request : { id: name, type: 'forward-child', pid, request });
      const result = response.type === 'child-result' ? response.result : response;
      const evidence = await observe(session(pid), 'tcp-response', sequence);
      report.checks[name] = { passed: result.passed === true && result.receivedBytes === 2048 && evidence.observed,
        receivedBytes: result.receivedBytes, signedFlowObserved: evidence.observed };
    }
    const sequence = adapter.diagnosticSnapshot().sequence;
    const udpResponse = await command({ id: 'udp', type: 'udp', target: { host: '198.51.100.42', port: 40444 }, payload: randomBytes(32).toString('hex') });
    const udpEvidence = await observe(session(fixture.pid), 'udp-blocked', sequence);
    const sample = udpEvidence.event.sample;
    report.checks.ownedUDPBlocked = { passed: udpEvidence.observed && sample?.host === '198.51.100.42' && sample.port === 40444 && sample.bytes === 32 && udpResponse.receivedBytes === 0,
      signedFlowObserved: udpEvidence.observed, firstDatagram: sample, forwarded: false };
    if (args.includes('--dns')) {
      report.systemDNSObservation = { testsUserData: false, usesNonSensitiveRandomExampleDomain: true,
        forwardsDNS: false, checks: {} };
      for (const [name, pid] of [['parent', fixture.pid], ['child', childPid]]) {
        const baseline = adapter.diagnosticSnapshot().sequence;
        const request = { id: `dns_${name}`, type: 'dns', hostname: `${randomBytes(16).toString('hex')}.example.com` };
        const response = await command(pid === fixture.pid ? request : { id: request.id, type: 'forward-child', pid, request });
        const result = response.type === 'child-result' ? response.result : response;
        const events = adapter.diagnosticSnapshot().events.filter(value => value.sequence > baseline && value.kind === 'udp-blocked' && value.pid === pid && value.sample?.port === 53);
        report.systemDNSObservation.checks[name] = { signedDNSFlowObserved: events.length > 0,
          capturedQueryCount: events.length, resolverCode: result.code ?? 'FIXTURE_UNAVAILABLE', resolved: result.resolved === true,
          // Failure/NXDOMAIN alone never proves interception, and interception is not DNS forwarding.
          endToEndDNSPassed: false };
      }
    }
    const holdSequence = adapter.diagnosticSnapshot().sequence;
    const heldResult = command({ id: 'hold', type: 'tcp', target, payload: randomBytes(2048).toString('hex'), mode: 'hold' });
    const progress = await receive(value => value.id === 'hold' && value.type === 'tcp-progress');
    if (!progress.passed || progress.receivedBytes !== 2048) throw new Error('held fixture not live');
    for (const socket of connections) socket.destroy();
    await new Promise(resolve => socks.close(resolve)); socksClosed = true;
    const held = await heldResult;
    const closure = await observe(session(fixture.pid), 'upstream-closed', holdSequence);
    report.checks.liveUpstreamDisconnect = { passed: closure.observed && ['FIXTURE_EOF', 'FIXTURE_CLOSED', 'FIXTURE_ERROR'].includes(held.code),
      signedFlowObserved: closure.observed, code: closure.event.code, entireGuardCrashTested: false };
    const retrySequence = adapter.diagnosticSnapshot().sequence;
    const retry = await command({ id: 'retry', type: 'tcp', target, payload: randomBytes(2048).toString('hex') });
    const refusal = await observe(session(fixture.pid), 'upstream-error', retrySequence);
    report.checks.newFlowProxyUnavailable = { passed: refusal.observed && retry.receivedBytes === 0 && retry.passed === false,
      signedFlowObserved: refusal.observed, receivedBytes: retry.receivedBytes, code: refusal.event.code,
      entireGuardCrashTested: false };
    report.authenticatedDestinations = destinations;
    report.capture = (await adapter.status()).capture;
    report.decoderRejections = adapter.diagnosticSnapshot().rejections;
  } catch (error) { report.error = error?.code ?? 'NATIVE_MATRIX_FAILED'; }
  finally {
    if (fixture && fixture.exitCode === null && fixture.signalCode === null) {
      const exited = once(fixture, 'exit'); process.kill(-fixture.pid, 'SIGKILL'); await exited;
    }
    report.cleanup.fixtureParentExited = !fixture || fixture.exitCode !== null || fixture.signalCode !== null;
    for (const waiter of [...waiters]) waiter.cancel();
    try { await adapter.shutdown(); report.cleanup.captureClosed = true; } catch { report.cleanup.captureClosed = false; }
    for (const socket of connections) socket.destroy();
    if (!socksClosed && socks.listening) await new Promise(resolve => socks.close(resolve));
    await fs.rm(workspace, { recursive: true, force: true });
    report.finishedAt = new Date().toISOString();
    report.diagnosticMatrixPassed = ['parentTCP', 'childTCP', 'ownedUDPBlocked', 'liveUpstreamDisconnect', 'newFlowProxyUnavailable'].every(key => report.checks[key]?.passed === true) && report.cleanup.captureClosed;
    const output = path.join(root, 'test-artifacts/mac-routing'); await fs.mkdir(output, { recursive: true });
    await fs.writeFile(path.join(output, 'native-matrix.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    await fs.writeFile(path.join(output, `native-matrix-${report.startedAt.replaceAll(':', '-')}.json`), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
    console.log(JSON.stringify(report));
    if (!report.diagnosticMatrixPassed) process.exitCode = 1;
  }
}
