import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { TerminalService } from '../electron/terminal-service.mjs';
import { ensureClaudeInstallation } from '../electron/claude-code-installation.mjs';
import { exportEnvironment } from '../electron/environment-transfer.mjs';
import { readEnvironmentExport } from '../electron/environment-export.mjs';

const connections = [{ id: 'ssh_fixture', alias: 'envara-fixture', name: 'Synthetic server', host: 'host.invalid', port: 22, user: 'fixture',
  keyLabel: 'Synthetic identity', keyFingerprint: 'SHA256:synthetic-key', hostFingerprints: ['SHA256:synthetic-host'] }];
const publicConnections = connections.map(({ id, alias, name }) => ({ id, alias, name }));
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

class FakePty {
  constructor(options, pid) { this.options = options; this.pid = pid; this.exits = new Set(); this.written = []; this.kills = 0; }
  onData() { return { dispose() {} }; }
  onExit(fn) { this.exits.add(fn); return { dispose: () => this.exits.delete(fn) }; }
  exit() { for (const fn of this.exits) fn({ exitCode: 0 }); }
  kill() { this.kills++; this.exit(); }
  write(value) { this.written.push(value); }
}

async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-terminal-ssh-service-')));
  const cwd = path.join(root, 'project'); await mkdir(cwd);
  const privateRoot = path.join(root, 'data', 'terminal', 'ssh-private'); await mkdir(privateRoot, { recursive: true, mode: 0o700 });
  const privateKey = path.join(privateRoot, 'identity'), privateRecord = path.join(privateRoot, 'connections.json');
  await writeFile(privateKey, 'synthetic-private-key-not-a-real-key', { mode: 0o600 });
  await writeFile(privateRecord, JSON.stringify({ keyPath: privateKey }), { mode: 0o600 });
  const context = { id: 'chosen', name: 'Synthetic environment', timezone: 'UTC', locale: 'en-US', proxyId: 'route_a', managedProxy: true,
    proxy: { protocol: 'http', host: '127.0.0.1', port: 49123, username: 'fixture', password: 'synthetic-route-password' }, ...options.context };
  const fakes = [], bindings = [], browserBindings = [], wraps = [];
  const calls = { create: [], save: [], remove: [], prepare: [], close: 0, processClose: 0, installer: 0 };
  const sshManager = { ready: Promise.resolve(),
    list: async ({ id }) => ({ supported: options.supported !== false, connections: structuredClone(options.connections ?? connections) }),
    prepareIdentity: async args => { calls.prepare.push(args); return { selectionToken: 'synthetic-selection' }; },
    save: async args => { calls.save.push(args); }, remove: async args => { calls.remove.push(args); },
    close: async () => { calls.close++; },
    async createSession(args) {
      calls.create.push(args); await options.beforeBinding?.(args);
      const agentRoot = path.join(args.directories.temp, `ssh-${args.sessionId}`), binDirectory = path.join(agentRoot, 'bin');
      await mkdir(binDirectory, { recursive: true, mode: 0o700 });
      const config = path.join(agentRoot, 'config'), targets = path.join(agentRoot, 'targets.json');
      const selected = (options.connections ?? connections).length > 0;
      const agentSocket = selected ? path.join(agentRoot, 'agent.sock') : null;
      await writeFile(config, `IdentityFile ${privateKey}\n`, { mode: 0o600 });
      await writeFile(targets, JSON.stringify({ 'envara-fixture': { host: 'host.invalid', port: 22, user: 'fixture' } }), { mode: 0o600 });
      const binding = { binDirectory: selected ? binDirectory : null, agentRoot, agentSocket, allowedAgentSocket: agentSocket,
        protectedPaths: [privateRoot, privateKey, privateRecord], readablePaths: [config, targets], readOnlyPaths: [config, targets], disposed: 0,
        environment: selected ? { SSH_AUTH_SOCK: agentSocket, ENVARA_SSH_TARGETS: targets, ENVARA_SSH_PROXY_URL: args.proxyUrl } : {},
        async dispose() { binding.disposed++; await options.disposeBinding?.(binding); await rm(agentRoot, { recursive: true, force: true }); } };
      bindings.push(binding); return binding;
    },
  };
  const service = new TerminalService({ dataDir: path.join(root, 'data'), sshManager,
    availableLocales: ['C', 'en_US.UTF-8'], resolveContext: async id => ({ ...structuredClone(context), id }),
    linkChannel: { executableDirectory: async () => '/owned/link-bin', environment: () => ({ ENVARA_LINK_SOCKET: '/owned/link.sock', ENVARA_LINK_TOKEN: 'synthetic-link-token' }) },
    browserBroker: { createSession: async args => {
      const binding = { browser: { name: 'Selected browser' }, environment: { ENVARA_BROWSER_SOCKET: '/owned/browser.sock', ENVARA_BROWSER_TOKEN: `synthetic-browser-token-${browserBindings.length}` },
        mcpServer: { command: process.execPath, args: ['/owned/browser-mcp.mjs'] }, disposed: 0, dispose: async () => { binding.disposed++; } };
      browserBindings.push(binding); return binding;
    } },
    claudeExecutableResolver: async () => { throw new Error('No host executable lookup permitted'); },
    claudeInstaller: async args => { calls.installer++; return ensureClaudeInstallation({ ...args, downloadNative: async ({ destination }) => {
      await copyFile('/usr/bin/true', destination); await chmod(destination, 0o700); return { version: '2.1.296' };
    } }); },
    networkFence: options.networkFence === null ? null : { wrap: async (shell, settings) => {
      wraps.push({ shell, settings });
      await options.beforeFence?.(shell, settings);
      return { ...shell, deviceIdentifierRestrictions: settings.restrictDeviceIdentifiers === true,
        sshPrivateKeyProtection: Object.hasOwn(options, 'attestation') ? options.attestation : true };
    } },
    ptyFactory: (_shell, _args, settings) => { const pty = new FakePty(settings, 700000 + fakes.length); fakes.push(pty); return pty; },
    processControl: { capture: async pid => ({ pid }), close: async ({ pty }) => { calls.processClose++; pty.exit(); return { ok: true }; } },
  });
  t.after(async () => { try { await service.shutdown(); } finally { await rm(root, { recursive: true, force: true }); } });
  await service.ready;
  const start = (kind = 'shell', id = 'chosen') => service.create({ id, directory: cwd, fresh: true, kind, ...(kind === 'claude-code' ? { browserProfileId: id } : {}) });
  return { root, cwd, privateKey, privateRecord, privateRoot, context, service, sshManager, fakes, bindings, browserBindings, wraps, calls, start };
}

for (const kind of ['shell', 'claude-code']) {
  test(`${kind}: session SSH environment and read protection reach the fenced PTY, never the public snapshot`, async t => {
    const f = await fixture(t), result = await f.start(kind), binding = f.bindings[0], internal = f.service.sessions.get(result.sessionId);
    const env = f.fakes[0].options.env;
    for (const [key, value] of Object.entries(binding.environment)) assert.equal(env[key], value, key);
    assert.ok(env.PATH.split(path.delimiter).includes(binding.binDirectory));
    assert.equal(f.calls.create[0].sessionId, result.sessionId); assert.equal(f.calls.create[0].profileId, 'chosen');
    assert.equal(f.calls.create[0].proxyUrl, env.HTTPS_PROXY);
    assert.deepEqual(f.wraps[0].settings.sshProtection.protectedPaths, binding.protectedPaths);
    assert.equal(f.wraps[0].settings.sshProtection.agentSocket, binding.agentSocket);
    assert.equal(f.wraps[0].settings.routePort, f.context.proxy.port);
    assert.deepEqual(result.ssh, { privateKeyProtection: true, available: true, connections: publicConnections });
    const snapshot = JSON.stringify(await f.service.snapshot());
    for (const secret of [f.privateKey, binding.agentSocket, binding.environment.ENVARA_SSH_TARGETS, 'synthetic-route-password']) assert.ok(!snapshot.includes(secret));
    if (kind === 'claude-code') {
      assert.equal(result.browserProfileId, 'chosen'); assert.equal(result.deviceIdentifierRestrictions, true);
      const prepared = internal.claudeLaunch;
      const settings = JSON.parse(await readFile(prepared.args[prepared.args.indexOf('--settings') + 1], 'utf8'));
      assert.equal(settings.env.SSH_AUTH_SOCK, binding.agentSocket);
      assert.equal(settings.env.ENVARA_SSH_TARGETS, binding.environment.ENVARA_SSH_TARGETS);
      assert.equal(settings.env.ENVARA_SSH_PROXY_URL, undefined);
      assert.equal(f.calls.installer, 1);
    } else assert.equal(f.calls.installer, 0);
    await f.service.close({ sessionId: result.sessionId });
    assert.equal(binding.disposed, 1); assert.equal(internal.sshBinding, null); assert.equal(internal.sshRevocation, null);
    assert.equal(internal.launchContext, null); assert.deepEqual(internal.secrets, []);
    assert.equal(f.service.metadata(internal).ssh.available, false);
  });

  test(`${kind}: duplication creates an independently revocable SSH binding without replaying input`, async t => {
    const f = await fixture(t), first = await f.start(kind);
    await f.service.write({ sessionId: first.sessionId, data: 'fixture-input\r' });
    const second = await f.service.duplicate({ sessionId: first.sessionId });
    assert.equal(f.calls.create.length, 2); assert.notEqual(first.sessionId, second.sessionId);
    assert.notEqual(f.fakes[0].options.env.SSH_AUTH_SOCK, f.fakes[1].options.env.SSH_AUTH_SOCK);
    assert.notEqual(f.bindings[0].agentRoot, f.bindings[1].agentRoot);
    assert.equal(f.fakes[0].options.env.ENVARA_SSH_PROXY_URL, f.fakes[1].options.env.ENVARA_SSH_PROXY_URL);
    assert.deepEqual(f.fakes[1].written, []);
    await f.service.close({ sessionId: first.sessionId });
    assert.equal(f.bindings[0].disposed, 1); assert.equal(f.bindings[1].disposed, 0);
    assert.equal(f.service.sessions.get(second.sessionId).status, 'running');
    assert.equal((await stat(f.bindings[1].agentRoot)).isDirectory(), true);
  });
}

test('SSH selection forwards explicit fields, but save/remove refuse any live terminal before calling the manager', async t => {
  const f = await fixture(t);
  const selected = { id: 'chosen', host: 'host.invalid', port: 2222, user: 'fixture', keyPath: f.privateKey };
  assert.deepEqual(await f.service.prepareTerminalSshIdentity(selected), { selectionToken: 'synthetic-selection' });
  assert.deepEqual(f.calls.prepare, [selected]);
  const session = await f.start();
  await assert.rejects(f.service.saveTerminalSshConnection({ id: 'chosen', name: 'Synthetic', selectionToken: 'synthetic-selection' }), { code: 'TERMINAL_SSH_BUSY' });
  await assert.rejects(f.service.removeTerminalSshConnection({ id: 'chosen', connectionId: 'ssh_fixture' }), { code: 'TERMINAL_SSH_BUSY' });
  assert.deepEqual(f.calls.save, []); assert.deepEqual(f.calls.remove, []);
  await f.service.close({ sessionId: session.sessionId });
  await f.service.saveTerminalSshConnection({ id: 'chosen', name: 'Synthetic', selectionToken: 'synthetic-selection' });
  await f.service.removeTerminalSshConnection({ id: 'chosen', connectionId: 'ssh_fixture' });
  assert.deepEqual(f.calls.save, [{ id: 'chosen', name: 'Synthetic', selectionToken: 'synthetic-selection' }]);
  assert.deepEqual(f.calls.remove, [{ id: 'chosen', connectionId: 'ssh_fixture' }]);
});

test('configured SSH refuses unsupported or unfenced routes before binding, Claude installation or PTY creation', async t => {
  for (const kind of ['shell', 'claude-code']) for (const [name, options] of [
    ['remote upstream', { context: { proxy: { protocol: 'https', host: 'remote.invalid', port: 443 } } }],
    ['direct', { context: { proxy: null } }], ['unsupported manager', { supported: false }], ['missing fence', { networkFence: null }],
  ]) await t.test(`${kind}/${name}`, async t => {
    const f = await fixture(t, options);
    await assert.rejects(f.start(kind), { code: 'TERMINAL_SSH_ROUTE_REQUIRED' });
    assert.equal(f.calls.create.length, 0); assert.equal(f.calls.installer, 0); assert.equal(f.fakes.length, 0);
  });
});

test('SSH private-key protection requires a literal positive fence attestation and reclaims refused bindings', async t => {
  for (const attestation of [undefined, false, 'true']) await t.test(String(attestation), async t => {
    const f = await fixture(t, { attestation });
    await assert.rejects(f.start(), { code: 'TERMINAL_SSH_PROTECTION_UNAVAILABLE' });
    assert.equal(f.fakes.length, 0); assert.equal(f.bindings[0].disposed, 1);
    const internal = [...f.service.sessions.values()][0];
    assert.equal(internal.sshBinding, null); assert.equal(internal.status, 'error'); assert.equal(internal.finished, true);
  });
});

test('a supported workspace without selected connections still receives basic key protection without an agent or SSH environment', async t => {
  const f = await fixture(t, { connections: [] }), session = await f.start();
  assert.equal(f.calls.create.length, 1);
  assert.deepEqual(f.bindings[0].environment, {}); assert.equal(f.bindings[0].agentSocket, null);
  for (const key of ['SSH_AUTH_SOCK', 'ENVARA_SSH_TARGETS', 'ENVARA_SSH_PROXY_URL']) assert.equal(f.fakes[0].options.env[key], undefined);
  assert.deepEqual(f.wraps[0].settings.sshProtection.protectedPaths, f.bindings[0].protectedPaths);
  assert.deepEqual(session.ssh, { privateKeyProtection: true, available: false, connections: [] });
});

test('closing while SSH preparation is pending reclaims a late binding without ever spawning the PTY', async t => {
  const entered = deferred(), gate = deferred();
  const f = await fixture(t, { beforeBinding: async () => { entered.resolve(); await gate.promise; } });
  const creating = f.start(), rejected = assert.rejects(creating, { code: 'TERMINAL_START_CANCELLED' });
  await entered.promise;
  const internal = [...f.service.sessions.values()][0];
  try { await f.service.close({ sessionId: internal.sessionId }); }
  finally { gate.resolve(); }
  await rejected;
  assert.equal(f.fakes.length, 0); assert.equal(f.bindings[0].disposed, 1);
  assert.equal(internal.status, 'closed'); assert.equal(internal.sshBinding, null); assert.equal(internal.sshRevocation, null);
  await assert.rejects(stat(f.bindings[0].agentRoot), { code: 'ENOENT' });
});

test('a failed late-cancellation disposal retains SSH cleanup authority until an explicit close succeeds', async t => {
  const entered = deferred(), gate = deferred(); let refuse = true;
  const f = await fixture(t, { beforeBinding: async () => { entered.resolve(); await gate.promise; },
    disposeBinding: async () => { if (refuse) throw new Error('Synthetic cleanup refusal'); } });
  const creating = f.start(), rejected = assert.rejects(creating, { code: 'TERMINAL_START_CANCELLED' });
  await entered.promise;
  const internal = [...f.service.sessions.values()][0]; await f.service.close({ sessionId: internal.sessionId });
  gate.resolve(); await rejected;
  assert.equal(f.fakes.length, 0); assert.equal(internal.status, 'closing'); assert.equal(internal.finished, false);
  assert.equal(internal.errorCode, 'TERMINAL_START_CANCELLED'); assert.ok(internal.cleanupError);
  assert.equal(internal.sshBinding, f.bindings[0]); assert.equal(f.bindings[0].disposed, 1);
  refuse = false; await f.service.close({ sessionId: internal.sessionId });
  assert.equal(f.bindings[0].disposed, 2); assert.equal(internal.status, 'closed'); assert.equal(internal.sshBinding, null);
  assert.equal(internal.cleanupError, null); assert.equal(internal.errorCode, 'TERMINAL_START_CANCELLED');
});

test('a route failure during asynchronous SSH preparation rejects the late binding before PTY creation', async t => {
  const entered = deferred(), gate = deferred();
  const f = await fixture(t, { beforeBinding: async () => { entered.resolve(); await gate.promise; } });
  const creating = f.start(), rejected = assert.rejects(creating, { code: 'TERMINAL_SSH_ROUTE_LOST' });
  await entered.promise;
  try { await f.service.invalidateManagedProxy('route_a'); }
  finally { gate.resolve(); }
  await rejected;
  assert.equal(f.fakes.length, 0); assert.equal(f.bindings[0].disposed, 1);
  assert.equal([...f.service.sessions.values()][0].sshBinding, null);
});

test('a failed route revokes ordinary SSH once while preserving the shell and unrelated route bindings', async t => {
  const f = await fixture(t), first = await f.start();
  f.context.proxyId = 'route_b';
  const other = await f.start('shell', 'other');
  await f.service.invalidateManagedProxy('route_a'); await f.service.invalidateManagedProxy('route_a');
  assert.equal(f.bindings[0].disposed, 1); assert.equal(f.bindings[1].disposed, 0);
  assert.equal(f.calls.processClose, 0); assert.equal(f.fakes[0].kills, 0);
  assert.equal(f.service.sessions.get(first.sessionId).status, 'running');
  assert.equal(f.service.metadata(f.service.sessions.get(first.sessionId)).ssh.available, false);
  assert.equal(f.service.metadata(f.service.sessions.get(other.sessionId)).ssh.available, true);
  await f.service.write({ sessionId: first.sessionId, data: 'still-an-idle-shell\r' });
  assert.deepEqual(f.fakes[0].written, ['still-an-idle-shell\r']);
  await f.service.close({ sessionId: first.sessionId }); assert.equal(f.bindings[0].disposed, 1);
});

test('natural PTY exit disposes SSH and clears all sensitive session binding references', async t => {
  const f = await fixture(t), result = await f.start(), internal = f.service.sessions.get(result.sessionId);
  f.fakes[0].exit(); await internal.finishing;
  assert.equal(internal.status, 'exited'); assert.equal(f.bindings[0].disposed, 1);
  for (const key of ['sshBinding', 'sshRevocation', 'launchContext', 'pty', 'identity']) assert.equal(internal[key], null, key);
  assert.equal(f.service.metadata(internal).ssh.available, false);
});

test('terminal workspace and encrypted exports preserve user state without SSH private records, runtime environment or key references', async t => {
  const f = await fixture(t), result = await f.start('claude-code');
  await f.service.setLinkBrowser({ id: 'chosen', browserProfileId: 'chosen' });
  const directories = f.calls.create[0].directories, marker = 'synthetic-selected-Claude-state';
  await writeFile(path.join(directories.claude, 'state.json'), marker, { mode: 0o600 });
  await writeFile(path.join(directories.temp, 'ssh-environment.json'), JSON.stringify(f.bindings[0].environment), { mode: 0o600 });
  const workspace = await readFile(f.service.settingsFile, 'utf8');
  assert.deepEqual(JSON.parse(workspace).profiles, [{ id: 'chosen', cwd: f.cwd, browserProfileId: 'chosen' }]);
  await f.service.close({ sessionId: result.sessionId });
  const service = { call: async () => ({ schema: 'envara.profiles', version: 2, profiles: [{ id: 'chosen', name: 'Synthetic environment' }] }) };
  for (const scope of ['terminal', 'environment']) {
    const file = path.join(f.root, `${scope}.envara`), staging = path.join(f.root, `staging-${scope}`), password = 'synthetic-export-password';
    await exportEnvironment({ profile: { id: 'chosen', status: 'stopped' }, terminal: f.service, service, file, password, scope, dataDir: path.join(f.root, 'data') });
    const manifest = await readEnvironmentExport({ file, password, staging });
    assert.equal(await readFile(path.join(staging, 'terminal/claude/state.json'), 'utf8'), marker);
    const contents = [];
    async function scan(directory) { for (const entry of await readdir(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name); if (entry.isDirectory()) await scan(filename); else contents.push(await readFile(filename, 'utf8'));
    } }
    await scan(staging);
    const exported = [workspace, JSON.stringify(manifest), ...contents].join('\n');
    for (const privateValue of [f.privateKey, f.privateRecord, 'synthetic-private-key-not-a-real-key', 'SSH_AUTH_SOCK', 'ENVARA_SSH_CONFIG', 'ENVARA_SSH_PROXY_URL', 'synthetic-route-password']) assert.ok(!exported.includes(privateValue), `${scope}: ${privateValue}`);
  }
});
