/** Real Electron/node-pty verification in a disposable workspace; no CLI login or installation. */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { createServer as createHttpServer } from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const filename = fileURLToPath(import.meta.url);
const root = path.resolve(path.dirname(filename), '..');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const isAlive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const loopbackPortOpen = port => new Promise(resolve => {
  const socket = net.connect({ host: '127.0.0.1', port });
  let settled = false;
  const finish = open => { if (!settled) { settled = true; socket.destroy(); resolve(open); } };
  socket.once('connect', () => finish(true));
  socket.once('error', () => finish(false));
  socket.setTimeout(500, () => finish(false));
});
const shellQuote = value => process.platform === 'win32' ? `"${value.replaceAll('"', '""')}"` : `'${value.replaceAll("'", "'\\''")}'`;
const fixtureSource = `
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { spawn } from 'node:child_process';
const mode = process.argv[2];
const nonce = process.argv[3];
const output = value => process.stdout.write('__ENVARA_TERMINAL_RESULT__' + JSON.stringify({ nonce, ...value }) + '\\n');
if (mode === 'sleep') setInterval(() => {}, 1000);
else if (mode === 'environment' || mode === 'write-config') {
  const observed = Object.fromEntries(['HOME','USERPROFILE','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME','XDG_STATE_HOME','HISTFILE','CLAUDE_CONFIG_DIR','TZ','ZDOTDIR','GIT_CONFIG_GLOBAL','NPM_CONFIG_USERCONFIG'].map(key => [key, process.env[key] ?? null]));
  observed.cwd = process.cwd();
  observed.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  observed.hostSecretPresent = 'ENVARA_SYNTHETIC_HOST_SECRET' in process.env;
  observed.hostSshAgentPresent = 'SSH_AUTH_SOCK' in process.env;
  observed.hostApiKeyPresent = 'ANTHROPIC_API_KEY' in process.env;
  observed.nodeOptionsPresent = 'NODE_OPTIONS' in process.env;
  observed.electronFlagPresent = 'ELECTRON_RUN_AS_NODE' in process.env;
  observed.envHookPresent = 'BASH_ENV' in process.env || 'ENV' in process.env;
  observed.proxyConfigured = !!process.env.HTTP_PROXY && !!process.env.HTTPS_PROXY;
  observed.configMarkerPresent = fs.existsSync(path.join(process.env.XDG_CONFIG_HOME, 'envara-smoke-marker'));
  observed.claudeMarkerPresent = fs.existsSync(path.join(process.env.CLAUDE_CONFIG_DIR, 'envara-smoke-marker'));
  if (mode === 'write-config') {
    fs.writeFileSync(path.join(process.env.XDG_CONFIG_HOME, 'envara-smoke-marker'), nonce, { mode: 0o600 });
    fs.writeFileSync(path.join(process.env.CLAUDE_CONFIG_DIR, 'envara-smoke-marker'), nonce, { mode: 0o600 });
  }
  output({ ok: true, observed });
} else if (mode === 'spawn-child') {
  const child = spawn(process.execPath, [process.argv[1], 'sleep'], { stdio: 'ignore' });
  child.unref();
  output({ ok: true, childPid: child.pid });
  // Leave time for the metadata-only monitor to attribute this descendant.
  setTimeout(() => process.exit(0), 600);
} else if (mode === 'proxy') {
  try {
    const proxy = new URL(process.env.HTTP_PROXY);
    const request = http.request({ hostname: proxy.hostname, port: proxy.port, method: 'GET', path: process.argv[4], headers: { 'Proxy-Authorization': 'Basic ' + Buffer.from(decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)).toString('base64') } }, response => {
      let body = '';
      response.on('data', chunk => body += chunk);
      response.on('end', () => output({ ok: true, status: response.statusCode, routeBody: body, proxyIsLoopback: proxy.hostname === '127.0.0.1', proxyProtocol: proxy.protocol }));
    });
    request.setTimeout(8000, () => request.destroy());
    request.on('error', () => { output({ ok: false, error: 'Proxy fixture request failed' }); process.exitCode = 1; });
    request.end();
  } catch { output({ ok: false, error: 'Proxy fixture configuration unavailable' }); process.exitCode = 1; }
} else { output({ ok: false, error: 'Unknown verification fixture' }); process.exitCode = 1; }
`;

async function socksFixture(originPort) {
  const username = `fixture-${randomUUID()}`;
  const password = randomUUID();
  const sockets = new Set();
  const requests = [];
  let authenticated = 0;
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
    let buffer = Buffer.alloc(0);
    let wake;
    let dead = false;
    const onData = chunk => { buffer = Buffer.concat([buffer, chunk]); wake?.(); };
    socket.on('data', onData);
    socket.once('close', () => { dead = true; wake?.(); });
    const bytes = async length => {
      while (buffer.length < length) {
        if (dead) throw new Error('Fixture connection closed');
        await new Promise(resolve => { wake = resolve; });
        wake = undefined;
      }
      const selected = buffer.subarray(0, length);
      buffer = buffer.subarray(length);
      return selected;
    };
    void (async () => {
      const hello = await bytes(2);
      assert.equal(hello[0], 5);
      const methods = await bytes(hello[1]);
      assert.ok(methods.includes(2));
      socket.write(Buffer.from([5, 2]));
      const auth = await bytes(2);
      assert.equal(auth[0], 1);
      const suppliedUser = (await bytes(auth[1])).toString();
      const passwordLength = (await bytes(1))[0];
      const suppliedPassword = (await bytes(passwordLength)).toString();
      if (suppliedUser !== username || suppliedPassword !== password) { socket.end(Buffer.from([1, 1])); return; }
      authenticated++;
      socket.write(Buffer.from([1, 0]));
      const connect = await bytes(4);
      assert.equal(connect[0], 5);
      assert.equal(connect[1], 1);
      assert.equal(connect[3], 3, 'The unresolvable hostname must reach SOCKS as a domain');
      const domainLength = (await bytes(1))[0];
      const hostname = (await bytes(domainLength)).toString();
      const port = (await bytes(2)).readUInt16BE();
      assert.equal(hostname, 'origin.envara.invalid');
      assert.equal(port, originPort);
      requests.push({ hostname, port, domainType: connect[3] });
      const upstream = net.connect({ host: '127.0.0.1', port: originPort });
      sockets.add(upstream);
      upstream.on('error', () => socket.destroy());
      upstream.once('close', () => sockets.delete(upstream));
      await once(upstream, 'connect');
      socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
      socket.removeListener('data', onData);
      if (buffer.length) upstream.write(buffer);
      socket.pipe(upstream); upstream.pipe(socket);
      socket.once('close', () => upstream.destroy());
    })().catch(() => socket.destroy());
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    proxy: { protocol: 'socks5', host: '127.0.0.1', port: server.address().port, username, password },
    get authenticated() { return authenticated; }, requests,
    async close() { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); },
  };
}

async function waitUntil(predicate, message, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await delay(25);
  }
  throw new Error(message);
}

if (!process.versions.electron) {
  const { default: electron } = await import('electron');
  const child = spawn(electron, [filename], {
    cwd: root,
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', ENVARA_TERMINAL_SMOKE_NODE: process.execPath },
    stdio: 'inherit',
  });
  const timer = setTimeout(() => { console.error('Terminal smoke exceeded its 90-second limit.'); child.kill('SIGTERM'); }, 90_000);
  child.once('error', error => { console.error(error.message); process.exitCode = 1; });
  const code = await new Promise(resolve => child.once('exit', resolve));
  clearTimeout(timer);
  process.exitCode = code === 0 ? 0 : 1;
} else {
  const { TerminalService } = await import('../electron/terminal-service.mjs');
  const artifactDir = path.join(root, 'test-artifacts/terminal-smoke');
  await mkdir(artifactDir, { recursive: true, mode: 0o700 });
  const runDir = await mkdtemp(path.join(artifactDir, 'run-'));
  const result = {
    passed: false, runDir, platform: `${process.platform}-${process.arch}`,
    electron: process.versions.electron, node: process.versions.node, modulesAbi: process.versions.modules,
    checks: [],
    limitations: ['These checks verify configuration separation and cleanup, not an OS sandbox.', 'CLI programs must honor proxy variables; no Claude CLI installation, account or remote request is exercised.'],
  };
  const check = message => { result.checks.push(message); console.log(`PASS ${message}`); };
  let service;
  let socks;
  let origin;
  let unrelated;
  const ownedChildren = new Set();
  const ownedRoots = new Set();
  try {
    const nativeNode = process.env.ENVARA_TERMINAL_SMOKE_NODE;
    assert.ok(nativeNode && path.isAbsolute(nativeNode), 'Invoke this harness with normal Node so fixtures use a normal Node executable');
    const fixture = path.join(runDir, 'terminal-fixture.mjs');
    await writeFile(fixture, fixtureSource, { mode: 0o600 });
    const selectedA = path.join(runDir, 'selected-working-directory-a');
    const selectedB = path.join(runDir, 'selected-working-directory-b');
    await Promise.all([mkdir(selectedA, { mode: 0o700 }), mkdir(selectedB, { mode: 0o700 })]);
    let sinkRequests = 0;
    let leakedProxyAuthorization = false;
    origin = createHttpServer((request, response) => {
      sinkRequests++;
      leakedProxyAuthorization ||= !!request.headers['proxy-authorization'];
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('envara-authenticated-socks-route');
    });
    await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
    socks = await socksFixture(origin.address().port);
    const profiles = new Map([
      ['fixture_a', { id: 'fixture_a', name: 'Disposable terminal A', timezone: 'Asia/Shanghai', timezoneSource: 'manual', proxy: null }],
      ['fixture_b', { id: 'fixture_b', name: 'Disposable terminal B', timezone: 'America/New_York', timezoneSource: 'manual', proxy: socks.proxy }],
    ]);
    const output = new Map();
    const events = [];
    const contextResolutions = new Map();
    process.env.ENVARA_SYNTHETIC_HOST_SECRET = randomUUID();
    process.env.SSH_AUTH_SOCK = path.join(runDir, 'synthetic-host-agent.sock');
    process.env.ANTHROPIC_API_KEY = `synthetic-${randomUUID()}`;
    process.env.NODE_OPTIONS = '--require=/nonexistent-envara-host-hook.cjs';
    process.env.BASH_ENV = path.join(runDir, 'nonexistent-host-shell-hook');
    process.env.ENV = path.join(runDir, 'nonexistent-host-shell-hook');
    service = new TerminalService({
      dataDir: path.join(runDir, 'disposable-app-data'),
      resolveContext: async id => {
        contextResolutions.set(id, (contextResolutions.get(id) ?? 0) + 1);
        return profiles.get(id);
      },
      onEvent: event => {
        events.push({ type: event.type, profileId: event.profileId, sessionId: event.sessionId, sequence: event.sequence });
        if (event.type === 'data') output.set(event.sessionId, (output.get(event.sessionId) ?? '') + event.data);
      },
    });
    await service.setDirectory({ id: 'fixture_a', path: selectedA });
    await service.setDirectory({ id: 'fixture_b', path: selectedB });
    const first = await service.create({ id: 'fixture_a', columns: 100, rows: 30 });
    const second = await service.create({ id: 'fixture_b', columns: 100, rows: 30 });
    assert.equal(first.status, 'running'); assert.equal(second.status, 'running');
    assert.notEqual(first.sessionId, second.sessionId);
    for (const session of [first, second]) ownedRoots.add(service.sessions.get(session.sessionId).pty.pid);
    const repeated = await service.create({ id: 'fixture_a' });
    assert.equal(repeated.sessionId, first.sessionId);
    check('Electron loads the actual node-pty module, starts two real interactive PTYs, and reuses each profile’s live session.');
    const executeFixture = async (session, mode, argument) => {
      const nonce = randomUUID();
      const command = [nativeNode, fixture, mode, nonce, ...(argument ? [argument] : [])].map(shellQuote).join(' ');
      await service.write({ sessionId: session.sessionId, data: `${command}\r` });
      return waitUntil(() => {
        const text = output.get(session.sessionId) ?? '';
        for (const match of text.matchAll(/__ENVARA_TERMINAL_RESULT__(\{[^\r\n]*\})/g)) {
          let candidate;
          try { candidate = JSON.parse(match[1]); } catch { continue; }
          if (candidate.nonce === nonce) return candidate;
        }
      }, `Real PTY fixture did not complete (${mode})`);
    };
    const envA = await executeFixture(first, 'write-config');
    const envB = await executeFixture(second, 'environment');
    assert.equal(envA.ok, true); assert.equal(envB.ok, true);
    for (const [environment, desiredDirectory, timezone, proxyConfigured] of [[envA.observed, selectedA, 'Asia/Shanghai', false], [envB.observed, selectedB, 'America/New_York', true]]) {
      assert.equal(environment.cwd, desiredDirectory);
      assert.equal(environment.TZ, timezone); assert.equal(environment.timezone, timezone);
      assert.equal(environment.proxyConfigured, proxyConfigured);
      for (const key of ['hostSecretPresent', 'hostSshAgentPresent', 'hostApiKeyPresent', 'nodeOptionsPresent', 'electronFlagPresent', 'envHookPresent']) assert.equal(environment[key], false, `Host setting leaked: ${key}`);
      for (const key of ['HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'HISTFILE', 'CLAUDE_CONFIG_DIR', 'GIT_CONFIG_GLOBAL', 'NPM_CONFIG_USERCONFIG']) assert.ok(environment[key].startsWith(path.join(runDir, 'disposable-app-data', 'terminal', 'profiles') + path.sep), `${key} must stay in the disposable profile config`);
      assert.equal(environment.ZDOTDIR, environment.HOME);
    }
    for (const key of ['HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'HISTFILE', 'CLAUDE_CONFIG_DIR']) assert.notEqual(envA.observed[key], envB.observed[key]);
    assert.equal(envB.observed.configMarkerPresent, false); assert.equal(envB.observed.claudeMarkerPresent, false);
    const retainedA = await executeFixture(first, 'environment');
    assert.equal(retainedA.observed.configMarkerPresent, true); assert.equal(retainedA.observed.claudeMarkerPresent, true);
    result.observedEnvironments = [{ profileId: first.profileId, ...envA.observed }, { profileId: second.profileId, ...envB.observed }];
    check('Selected working directories, HOME/XDG/history/Claude config and timezone are distinct; synthetic host credentials, SSH agent and shell/Node hooks do not enter either PTY.');
    const historyMarkers = { a: `envara_history_a_${randomUUID().replaceAll('-', '')}`, b: `envara_history_b_${randomUUID().replaceAll('-', '')}` };
    const readPrivateHistory = async filename => {
      try { return await readFile(filename, 'utf8'); } catch (error) { if (error.code === 'ENOENT') return ''; throw error; }
    };
    if (process.platform !== 'win32') {
      await service.write({ sessionId: first.sessionId, data: `printf '%s\\n' ${shellQuote(historyMarkers.a)}\r` });
      await service.write({ sessionId: second.sessionId, data: `printf '%s\\n' ${shellQuote(historyMarkers.b)}\r` });
      const histories = await waitUntil(async () => {
        const [a, b] = await Promise.all([readPrivateHistory(envA.observed.HISTFILE), readPrivateHistory(envB.observed.HISTFILE)]);
        return a.includes(historyMarkers.a) && b.includes(historyMarkers.b) ? { a, b } : undefined;
      }, 'Interactive commands were not written to the private history files');
      assert.equal(histories.a.includes(historyMarkers.b), false, 'History A must not contain environment B’s command');
      assert.equal(histories.b.includes(historyMarkers.a), false, 'History B must not contain environment A’s command');
      assert.equal((await stat(envA.observed.HISTFILE)).mode & 0o777, 0o600);
      assert.equal((await stat(envB.observed.HISTFILE)).mode & 0o777, 0o600);
      result.historyEvidence = { profileAHadOwnMarker: true, profileALackedBMarker: true, profileBHadOwnMarker: true, profileBLackedAMarker: true, filesOwnerOnly: true, persistedAfterReopen: false };
      check('Real interactive commands persist in separate owner-only history files without cross-profile markers.');
    } else {
      result.limitations.push('Persistent shell history is not exercised by this harness on Windows.');
    }
    const resized = await service.resize({ sessionId: first.sessionId, columns: 120, rows: 40 });
    assert.equal(resized.columns, 120); assert.equal(resized.rows, 40);
    const proxyResult = await executeFixture(second, 'proxy', `http://origin.envara.invalid:${origin.address().port}/route-check`);
    assert.equal(proxyResult.ok, true); assert.equal(proxyResult.status, 200); assert.equal(proxyResult.routeBody, 'envara-authenticated-socks-route');
    assert.equal(proxyResult.proxyIsLoopback, true); assert.equal(proxyResult.proxyProtocol, 'http:');
    assert.ok(socks.authenticated >= 1); assert.ok(socks.requests.length >= 1); assert.ok(sinkRequests >= 1);
    assert.equal(leakedProxyAuthorization, false);
    result.proxyEvidence = { authenticatedConnections: socks.authenticated, remoteDnsDomains: socks.requests.map(row => row.hostname), domainTypes: socks.requests.map(row => row.domainType), sinkRequests, leakedProxyAuthorization };
    const serializedSnapshot = JSON.stringify(await service.snapshot());
    assert.equal(serializedSnapshot.includes(socks.proxy.username), false); assert.equal(serializedSnapshot.includes(socks.proxy.password), false);
    check('A proxy-aware real PTY client reaches an otherwise unresolvable domain through the authenticated SOCKS bridge with remote DNS; credentials do not reach the origin or snapshot.');
    await executeFixture(second, 'write-config');
    const sourceOnlyMarker = `envara_source_output_${randomUUID().replaceAll('-', '')}`;
    const printMarker = process.platform === 'win32' ? `echo ${sourceOnlyMarker}` : `printf '%s\\n' ${shellQuote(sourceOnlyMarker)}`;
    await service.write({ sessionId: second.sessionId, data: `${printMarker}\r` });
    await waitUntil(() => (output.get(second.sessionId) ?? '').includes(sourceOnlyMarker), 'The source-only output marker was not observed');
    const resolutionsBeforeDuplicate = contextResolutions.get(second.profileId);
    const originalContextB = profiles.get(second.profileId);
    // A duplicate must use its source's captured context, even if a later
    // resolver would return a different route/timezone.
    profiles.set(second.profileId, { ...originalContextB, timezone: 'Asia/Tokyo', proxy: null });
    let duplicateB;
    try { duplicateB = await service.duplicate({ sessionId: second.sessionId, columns: 110, rows: 35 }); }
    finally { profiles.set(second.profileId, originalContextB); }
    assert.equal(duplicateB.status, 'running');
    assert.equal(duplicateB.profileId, second.profileId);
    assert.notEqual(duplicateB.sessionId, second.sessionId);
    assert.equal(duplicateB.columns, 110); assert.equal(duplicateB.rows, 35);
    assert.equal(contextResolutions.get(second.profileId), resolutionsBeforeDuplicate, 'Duplicate must not resolve a new workspace context');
    const sourcePrivateSession = service.sessions.get(second.sessionId);
    const duplicatePrivateSession = service.sessions.get(duplicateB.sessionId);
    const sourceBridge = sourcePrivateSession.bridge;
    const duplicateBridge = duplicatePrivateSession.bridge;
    const duplicateRootPid = duplicatePrivateSession.pty.pid;
    ownedRoots.add(duplicatePrivateSession.pty.pid);
    assert.equal(sourcePrivateSession.pty.pid !== duplicatePrivateSession.pty.pid, true, 'Duplicate requires an independent PTY process');
    assert.equal(!!sourcePrivateSession.bridge && !!duplicatePrivateSession.bridge, true, 'Both same-profile sessions need their own SOCKS bridge');
    assert.equal(sourcePrivateSession.bridge !== duplicatePrivateSession.bridge, true, 'Duplicate must not share the source bridge object');
    assert.equal(sourcePrivateSession.bridge.url !== duplicatePrivateSession.bridge.url, true, 'Duplicate requires an independent private bridge endpoint');
    assert.equal(duplicateB.replay.includes(sourceOnlyMarker), false, 'Duplicate must not copy the source command/output replay');
    const duplicateEnv = await executeFixture(duplicateB, 'environment');
    assert.equal(duplicateEnv.ok, true);
    for (const key of ['cwd', 'HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'HISTFILE', 'CLAUDE_CONFIG_DIR', 'TZ', 'timezone', 'ZDOTDIR', 'GIT_CONFIG_GLOBAL', 'NPM_CONFIG_USERCONFIG']) assert.equal(duplicateEnv.observed[key], envB.observed[key], `Same-profile duplicate context mismatch: ${key}`);
    for (const key of ['hostSecretPresent', 'hostSshAgentPresent', 'hostApiKeyPresent', 'nodeOptionsPresent', 'electronFlagPresent', 'envHookPresent']) assert.equal(duplicateEnv.observed[key], false, `Host setting leaked into duplicate: ${key}`);
    assert.equal(duplicateEnv.observed.configMarkerPresent, true); assert.equal(duplicateEnv.observed.claudeMarkerPresent, true);
    assert.equal(duplicateEnv.observed.proxyConfigured, true);
    if (process.platform !== 'win32') {
      const sharedHistory = await readPrivateHistory(duplicateEnv.observed.HISTFILE);
      assert.equal(sharedHistory.includes(historyMarkers.b), true, 'Duplicate must share its source profile’s existing history');
      assert.equal(sharedHistory.includes(historyMarkers.a), false, 'Duplicate must not share a different profile’s history');
    }
    assert.equal((output.get(duplicateB.sessionId) ?? '').includes(sourceOnlyMarker), false, 'Duplicate terminal output must start fresh');
    const duplicateProxyResult = await executeFixture(duplicateB, 'proxy', `http://origin.envara.invalid:${origin.address().port}/duplicate-route-check`);
    assert.equal(duplicateProxyResult.ok, true); assert.equal(duplicateProxyResult.status, 200);
    assert.equal(duplicateProxyResult.routeBody, 'envara-authenticated-socks-route');
    assert.ok(socks.authenticated >= 2 && sinkRequests >= 2);
    await assert.rejects(service.setDirectory({ id: second.profileId, path: selectedA }), error => error.code === 'TERMINAL_RUNNING');
    const duplicateSnapshot = JSON.stringify(await service.snapshot());
    for (const privateValue of [socks.proxy.username, socks.proxy.password, sourcePrivateSession.bridge.url, duplicatePrivateSession.bridge.url]) assert.equal(duplicateSnapshot.includes(privateValue), false, 'Snapshot must not expose private proxy values');
    result.duplicateEvidence = {
      sameProfileIndependentSessionAndPty: true, independentBridgeEndpoints: true,
      resolverBypassed: true, sourceResolvedTimezoneAndProxyPreserved: true,
      sameWorkingDirectoryAndConfiguration: true, sharedPrivateHistory: true,
      freshCommandAndOutputReplay: true, bothSessionsAuthenticatedThroughSocks: true,
      snapshotsHideProxySecrets: true, directoryLockedWithTwoLiveSessions: true,
      sourceClosePreservedDuplicate: false, survivorRemainsUsable: false,
      directoryLockedWithSurvivor: false, directoryAllowedAfterAllSessionsStop: false,
    };
    check('Duplicating a running terminal creates a fresh PTY and SOCKS bridge from the source context, shares only same-profile configuration/history, and keeps secrets out of snapshots.');
    unrelated = spawn(nativeNode, [fixture, 'sleep'], { stdio: 'ignore', env: { PATH: process.env.PATH, ...(process.platform === 'win32' ? { SystemRoot: process.env.SystemRoot } : {}) } });
    await once(unrelated, 'spawn');
    const sourceBackgroundB = await executeFixture(second, 'spawn-child');
    const duplicateBackgroundB = await executeFixture(duplicateB, 'spawn-child');
    ownedChildren.add(sourceBackgroundB.childPid); ownedChildren.add(duplicateBackgroundB.childPid);
    await delay(850);
    assert.equal(isAlive(sourceBackgroundB.childPid), true); assert.equal(isAlive(duplicateBackgroundB.childPid), true);
    await service.close({ sessionId: second.sessionId });
    await waitUntil(() => !isAlive(sourceBackgroundB.childPid), 'Closing the source left its owned background child running');
    await waitUntil(async () => !(await loopbackPortOpen(sourceBridge.port)), 'Closing the source left its private proxy bridge listening');
    assert.equal(isAlive(duplicateRootPid), true, 'Closing the source must leave the duplicate PTY alive');
    assert.equal(isAlive(duplicateBackgroundB.childPid), true, 'Closing the source must leave the duplicate child alive');
    assert.equal(isAlive(unrelated.pid), true);
    const survivingDuplicateEnv = await executeFixture(duplicateB, 'environment');
    assert.equal(survivingDuplicateEnv.ok, true); assert.equal(survivingDuplicateEnv.observed.timezone, 'America/New_York');
    const survivingDuplicateProxy = await executeFixture(duplicateB, 'proxy', `http://origin.envara.invalid:${origin.address().port}/survivor-route-check`);
    assert.equal(survivingDuplicateProxy.ok, true); assert.equal(survivingDuplicateProxy.status, 200);
    assert.equal(survivingDuplicateProxy.routeBody, 'envara-authenticated-socks-route');
    await assert.rejects(service.setDirectory({ id: second.profileId, path: selectedA }), error => error.code === 'TERMINAL_RUNNING');
    result.duplicateEvidence.sourceClosePreservedDuplicate = true;
    result.duplicateEvidence.survivorRemainsUsable = true;
    result.duplicateEvidence.directoryLockedWithSurvivor = true;
    check('Closing the source cleans only its process tree; the duplicate, its background child and authenticated proxy remain usable, and its working directory stays locked.');
    const backgroundA = await executeFixture(first, 'spawn-child');
    assert.equal(backgroundA.ok, true); assert.ok(Number.isSafeInteger(backgroundA.childPid));
    ownedChildren.add(backgroundA.childPid);
    await delay(850);
    const closed = await service.close({ sessionId: first.sessionId });
    assert.ok(['closed', 'exited'].includes(closed.status));
    await waitUntil(() => !isAlive(backgroundA.childPid), 'A closed PTY left its attributed background child running');
    assert.equal(isAlive(unrelated.pid), true);
    check('Closing one PTY cleans its captured background child while an unrelated process remains alive.');
    const reopenedA = await service.create({ id: 'fixture_a' });
    assert.equal(reopenedA.status, 'running');
    assert.notEqual(reopenedA.sessionId, first.sessionId);
    ownedRoots.add(service.sessions.get(reopenedA.sessionId).pty.pid);
    const reopenedEnvironmentA = await executeFixture(reopenedA, 'environment');
    assert.equal(reopenedEnvironmentA.observed.HISTFILE, envA.observed.HISTFILE);
    assert.equal(reopenedEnvironmentA.observed.configMarkerPresent, true);
    assert.equal(reopenedEnvironmentA.observed.claudeMarkerPresent, true);
    if (process.platform !== 'win32') {
      const historyAfterReopen = await readPrivateHistory(reopenedEnvironmentA.observed.HISTFILE);
      assert.equal(historyAfterReopen.includes(historyMarkers.a), true, 'Environment A history must survive terminal reopen');
      assert.equal(historyAfterReopen.includes(historyMarkers.b), false, 'Reopened environment A must not load environment B history');
      result.historyEvidence.persistedAfterReopen = true;
      check('Reopening an environment preserves its private history and tool configuration.');
    }
    await service.write({ sessionId: duplicateB.sessionId, data: 'exit\r' });
    await waitUntil(async () => (await service.snapshot({ id: 'fixture_b' })).profiles[0].sessions.find(row => row.sessionId === duplicateB.sessionId)?.status === 'exited', 'Shell exit did not update terminal state');
    await waitUntil(() => !isAlive(duplicateBackgroundB.childPid), 'Shell exit left its previously attributed background child running');
    await waitUntil(async () => !(await loopbackPortOpen(duplicateBridge.port)), 'Exiting the duplicate left its private proxy bridge listening');
    assert.equal(isAlive(unrelated.pid), true);
    check('Exiting the shell cleans previously attributed background children without killing an unrelated process.');
    await service.setDirectory({ id: second.profileId, path: selectedA });
    assert.equal((await service.snapshot({ id: second.profileId })).profiles[0].cwd, selectedA);
    await service.setDirectory({ id: second.profileId, path: selectedB });
    result.duplicateEvidence.directoryAllowedAfterAllSessionsStop = true;
    check('The profile working directory becomes editable only after every same-profile terminal has stopped.');
    const restarted = await service.create({ id: 'fixture_b' });
    ownedRoots.add(service.sessions.get(restarted.sessionId).pty.pid);
    const backgroundRestarted = await executeFixture(restarted, 'spawn-child');
    ownedChildren.add(backgroundRestarted.childPid);
    await delay(850);
    await service.shutdown();
    await waitUntil(() => [...ownedRoots, ...ownedChildren].every(pid => !isAlive(pid)), 'Shutdown left an owned shell or background process running');
    assert.equal(isAlive(unrelated.pid), true);
    const finalSnapshot = await service.snapshot();
    assert.equal(finalSnapshot.profiles.flatMap(row => row.sessions).some(row => ['running', 'starting', 'closing'].includes(row.status)), false);
    result.remainingOwnedProcesses = [...ownedRoots, ...ownedChildren].filter(isAlive).length;
    result.ownedProcessCounts = { shells: ownedRoots.size, backgroundChildren: ownedChildren.size };
    result.proxyEvidence.authenticatedConnections = socks.authenticated;
    result.proxyEvidence.remoteDnsDomains = socks.requests.map(row => row.hostname);
    result.proxyEvidence.domainTypes = socks.requests.map(row => row.domainType);
    result.proxyEvidence.sinkRequests = sinkRequests;
    result.eventEvidence = { dataEvents: events.filter(event => event.type === 'data').length, exitEvents: events.filter(event => event.type === 'exit').length };
    assert.ok(result.eventEvidence.dataEvents > 0);
    check('Shutdown cleans every recorded owned shell/background process, closes bridge sessions, and leaves zero active service sessions.');
    if (process.platform !== 'win32') {
      for (const directory of [envA.observed.HOME, envA.observed.XDG_CONFIG_HOME, envA.observed.CLAUDE_CONFIG_DIR, envB.observed.HOME, envB.observed.CLAUDE_CONFIG_DIR]) assert.equal((await stat(directory)).mode & 0o777, 0o700);
      check('Environment configuration directories use owner-only permissions.');
    }
    result.passed = true;
  } catch (error) {
    result.error = { message: error.message, code: error.code ?? 'SMOKE_FAILED' };
    process.exitCode = 1;
  } finally {
    try { await service?.shutdown(); } catch { result.shutdownFailed = true; result.passed = false; process.exitCode = 1; }
    if (unrelated) { unrelated.kill('SIGTERM'); if (unrelated.exitCode == null) await Promise.race([once(unrelated, 'exit'), delay(1000)]); }
    try { await socks?.close(); } catch { result.proxyFixtureCleanupFailed = true; result.passed = false; process.exitCode = 1; }
    if (origin) { origin.closeAllConnections(); await new Promise(resolve => origin.close(resolve)); }
    await writeFile(path.join(runDir, 'proof.json'), JSON.stringify(result, null, 2));
    console.log(`Terminal smoke report: ${path.join(runDir, 'proof.json')}`);
  }
}
