import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { MacOSLocalRoutingAdapter } from '../native/macos-local-routing/controller.mjs';
import { SocketReader } from '../native/macos-local-routing/socks-stream.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const diagnostics = [];
const adapter = new MacOSLocalRoutingAdapter({
  peerVerifierPath: path.join(root, 'build/app-routing/macos-local/EnvaraPeerVerifier'),
  bundledAppPath: path.join(root, 'build/app-routing/macos-local/Resources/Mitmproxy Redirector.app'),
  activationTimeoutMs: 180000,
  onEvent: event => { if (event.type === 'capture-peer-rejected') diagnostics.push({ type: event.type, code: event.code }); },
});
const argumentsForLab = process.argv.slice(2);
if (argumentsForLab.some(arg => !['--activate', '--half-close', '--half-close-after-capture'].includes(arg)) ||
    (argumentsForLab.includes('--half-close') && argumentsForLab.includes('--half-close-after-capture'))) throw new Error('Default is read-only; use explicit --activate for the native fixture and one half-close mode.');
const delayedHalfClose = argumentsForLab.includes('--half-close-after-capture');
if (!argumentsForLab.includes('--activate')) {
  const status = await adapter.status();
  console.log(JSON.stringify({ operation: 'plan', installed: status.installed, component: status.component,
    systemApprovalRequired: true, target: 'owned Node fixture', testsNotion: false, changesVPNOrTUN: false }));
  await adapter.shutdown();
} else {
  const directory = await fs.mkdtemp('/tmp/envara-native-capture-');
  const password = randomBytes(24).toString('hex'), username = randomBytes(12).toString('hex');
  const connections = new Set(); const destinations = []; let child, routeId;
  const report = { schemaVersion: 1, platform: process.platform, osRelease: os.release(),
    startedAt: new Date().toISOString(), originalComponentVersion: '0.12.11', fixtureMode: delayedHalfClose ? 'half-close-after-capture' : argumentsForLab.includes('--half-close') ? 'half-close' : 'normal-stream', fixtureTCP: { passed: false },
    notionTested: false, fullApplicationAcceptance: false, cleanup: { childExited: false, captureClosed: false } };
  const socks = net.createServer({ allowHalfOpen: true }, socket => {
    connections.add(socket); socket.once('close', () => connections.delete(socket)); socket.on('error', () => {});
    (async () => {
      const reader = new SocketReader(socket);
      if (!(await reader.read(3)).equals(Buffer.from([5, 1, 2]))) throw new Error('fixture greeting');
      socket.write(Buffer.from([5, 2]));
      const auth = await reader.read(2), user = (await reader.read(auth[1])).toString();
      const pass = (await reader.read((await reader.read(1))[0])).toString();
      if (auth[0] !== 1 || user !== username || pass !== password) { socket.end(Buffer.from([1, 1])); return; }
      socket.write(Buffer.from([1, 0]));
      let request;
      try { request = await reader.read(4); } catch { return; } // private authentication probe
      if (!request.equals(Buffer.from([5, 1, 0, 1]))) throw new Error('fixture CONNECT');
      const host = [...await reader.read(4)].join('.'), port = (await reader.read(2)).readUInt16BE();
      if (host !== '198.51.100.42' || port !== 40443) throw new Error('unexpected fixture destination');
      destinations.push({ host, port });
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 1]));
      const buffered = reader.release();
      if (delayedHalfClose) {
        // Echo a prefix as a capture witness; retain the response tail until
        // client FIN. A normal echo could reply before the half-close occurs.
        let prefixSent = 0; const tail = [];
        const consume = bytes => {
          const count = Math.min(1024 - prefixSent, bytes.length);
          if (count > 0) { socket.write(bytes.subarray(0, count)); prefixSent += count; }
          if (count < bytes.length) tail.push(bytes.subarray(count));
        };
        if (buffered.length) consume(buffered);
        socket.on('data', consume);
        socket.once('end', () => { report.upstreamClientFINObserved = true; report.upstreamTailBytes = Buffer.concat(tail).length; socket.end(Buffer.concat(tail)); });
        if (reader.ended) { report.upstreamClientFINObserved = true; report.upstreamTailBytes = Buffer.concat(tail).length; socket.end(Buffer.concat(tail)); }
        else socket.resume();
        return;
      }
      if (reader.ended) socket.end(buffered);
      else { if (buffered.length) socket.write(buffered); socket.pipe(socket); socket.resume(); }
    })().catch(() => socket.destroy());
  });
  try {
    socks.listen({ host: '127.0.0.1', port: 0 }); await once(socks, 'listening');
    const prepared = await adapter.prepareRoute({
      application: { id: 'app_native_fixture', profileId: 'native_fixture', executablePath: process.execPath },
      workspace: { cwd: directory }, route: { host: '127.0.0.1', port: socks.address().port, username, password, udpPolicy: 'block' },
    }); routeId = prepared.routeId;
    console.log('Waiting for macOS network-extension approval. No user application has started.');
    await adapter.startCapture({ activationAuthorized: true });
    report.signedControlConnected = true;
    child = spawn(process.execPath, [path.join(root, 'scripts/macos-routing-fixture-child.mjs')], {
      cwd: directory, env: { PATH: '/usr/bin:/bin' }, detached: true, stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const message = () => new Promise((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); reject(new Error('native fixture IPC deadline')); }, 12000);
      const arrived = value => { cleanup(); resolve(value); }, exited = () => { cleanup(); reject(new Error('native fixture exited')); };
      const cleanup = () => { clearTimeout(timer); child.removeListener('message', arrived); child.removeListener('exit', exited); };
      child.once('message', arrived); child.once('exit', exited);
    });
    const waiting = await message(); if (waiting.type !== 'waiting') throw new Error('native fixture not waiting');
    await adapter.bindPid({ routeId, pid: child.pid });
    report.scopeAcknowledged = false;
    report.steadyStateObservationDelayMs = 2000;
    await new Promise(resolve => setTimeout(resolve, report.steadyStateObservationDelayMs));
    // Upstream offers no scope ACK. The actual captured payload below is the
    // evidence; writing the scope itself never grants a successful check.
    const result = message(); child.send({ type: 'tcp', payload: randomBytes(2048).toString('hex'), halfClose: argumentsForLab.includes('--half-close'), halfCloseAfterCapture: delayedHalfClose });
    const response = await result; const status = await adapter.status();
    report.fixtureTCP = { passed: response.type === 'tcp-result' && response.passed === true && destinations.length === 1 && status.capture.metrics.tcpConnected === 1,
      receivedBytes: response.receivedBytes ?? 0, captureWitnessObserved: response.captureWitnessObserved === true,
      authenticatedDestinations: destinations, metrics: status.capture.metrics };
  } catch (error) { report.error = error?.code ?? 'NATIVE_CAPTURE_FAILED'; }
  finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit'); child.kill('SIGKILL'); await exited;
    }
    report.cleanup.childExited = !child || child.exitCode !== null || child.signalCode !== null;
    try { await adapter.shutdown(); report.cleanup.captureClosed = true; } catch { report.cleanup.captureClosed = false; }
    for (const socket of connections) socket.destroy();
    if (socks.listening) await new Promise(resolve => socks.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
    report.finishedAt = new Date().toISOString();
    report.diagnostics = diagnostics;
    const output = path.join(root, 'test-artifacts/mac-routing'); await fs.mkdir(output, { recursive: true });
    await fs.writeFile(path.join(output, 'native-capture.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    await fs.writeFile(path.join(output, `native-capture-${report.startedAt.replaceAll(':', '-')}.json`), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    console.log(JSON.stringify(report));
    if (!report.fixtureTCP.passed || !report.cleanup.captureClosed) process.exitCode = 1;
  }
}
