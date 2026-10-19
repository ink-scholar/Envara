import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmod, copyFile, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { TerminalService } from '../electron/terminal-service.mjs';
import { ensureClaudeInstallation } from '../electron/claude-code-installation.mjs';
import { exportEnvironment } from '../electron/environment-transfer.mjs';
import { readEnvironmentExport } from '../electron/environment-export.mjs';
import { describeSshSession } from '../electron/terminal-ssh-command.mjs';

const connections = [{ id: 'ssh_fixture', alias: 'envara-aaaaaaaaaaaa', name: 'Synthetic server', host: 'host.invalid', port: 22, user: 'fixture',
  keyLabel: 'Synthetic identity', keyFingerprint: 'SHA256:synthetic-key', hostFingerprints: ['SHA256:synthetic-host'] }];
const publicConnections = connections.map(({ id, alias, name }) => ({ id, alias, name }));
const manifestConnections = values => values.map(({ id, alias, name, host, port, user }) => ({ id, alias, name, host, port, user }));
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
  const fakes = [], bindings = [], browserBindings = [], wraps = [], clock = { now: Date.now() };
  const savedConnections = new Map([['chosen', structuredClone(options.connections ?? connections)]]);
  const selectedConnections = id => savedConnections.get(id) ?? options.connections ?? connections;
  const calls = { list: [], describe: [], browserCreate: [], create: [], save: [], remove: [], prepare: [], preparePassword: [], setPassword: [], close: 0, processClose: 0, installer: 0 };
  const sshManager = { ready: Promise.resolve(),
    list: async ({ id }) => { calls.list.push({ id }); return { supported: options.supported !== false, connections: structuredClone(selectedConnections(id)) }; },
    prepareIdentity: async args => { calls.prepare.push(args); return { selectionToken: 'synthetic-selection' }; },
    preparePassword: async args => { calls.preparePassword.push(args); return { authType: 'password', selectionToken: 'synthetic-password-selection' }; },
    setPassword: async args => { calls.setPassword.push(args); },
    save: async args => { calls.save.push(args); }, remove: async args => { calls.remove.push(args); },
    close: async () => { calls.close++; },
    async createSession(args) {
      calls.create.push(args); await options.beforeBinding?.(args);
      const agentRoot = path.join(args.directories.temp, `ssh-${args.sessionId}`), binDirectory = path.join(agentRoot, 'bin');
      await mkdir(binDirectory, { recursive: true, mode: 0o700 });
      const config = path.join(agentRoot, 'config'), targets = path.join(agentRoot, 'targets.json'), manifestPath = path.join(agentRoot, 'connections.json');
      const selectedRecords = structuredClone(selectedConnections(args.profileId)).filter(item => item.authType !== 'password' || item.passwordReady === true);
      const loaded = manifestConnections(selectedRecords).map((record, index) => options.sessionVersion === 2
        ? { ...record, authType: selectedRecords[index].authType ?? 'publickey', expiresAt: null } : record), selected = loaded.length > 0;
      const agentSocket = selected ? path.join(agentRoot, 'agent.sock') : null;
      const manifest = { schema: 'envara.ssh-session', version: options.sessionVersion ?? 1, connections: loaded,
        expiresAt: options.sessionVersion === 2 ? null : selected ? clock.now + 3600000 : null };
      await writeFile(config, '# Synthetic protected SSH configuration\n', { mode: 0o400 });
      if (selected) await writeFile(targets, JSON.stringify(loaded.map(({ host, port }) => ({ host, port }))), { mode: 0o400 });
      await writeFile(manifestPath, JSON.stringify(manifest), { mode: 0o400 });
      for (const name of ['ssh', 'envara-ssh']) await writeFile(path.join(binDirectory, name), '#!/bin/sh\nexit 64\n', { mode: 0o500 });
      const binding = { binDirectory, agentRoot, agentSocket, allowedAgentSocket: agentSocket, allowedSockets: [path.join(agentRoot, 'command.sock')], manifest, closed: false,
        protectedPaths: [privateRoot, privateKey, privateRecord], readablePaths: [agentRoot], readOnlyPaths: [agentRoot], disposed: 0,
        environment: { ENVARA_SSH_CONFIG: config, ENVARA_SSH_CONNECTIONS: manifestPath,
          ...(selected ? { ENVARA_SSH_TARGETS: targets, SSH_AUTH_SOCK: agentSocket, ENVARA_SSH_PROXY_URL: args.proxyUrl } : {}) },
        describe() { calls.describe.push(args.sessionId); return describeSshSession(manifest, clock.now, { closed: binding.closed }); },
        async dispose() { binding.closed = true; binding.disposed++; await options.disposeBinding?.(binding); await rm(agentRoot, { recursive: true, force: true }); } };
      bindings.push(binding); return binding;
    },
  };
  const service = new TerminalService({ dataDir: path.join(root, 'data'), sshManager,
    availableLocales: ['C', 'en_US.UTF-8'], resolveContext: async id => ({ ...structuredClone(context), id }),
    linkChannel: { executableDirectory: async () => '/owned/link-bin', environment: () => ({ ENVARA_LINK_SOCKET: '/owned/link.sock', ENVARA_LINK_TOKEN: 'synthetic-link-token' }) },
    browserBroker: { createSession: async args => {
      calls.browserCreate.push(args);
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
  return { root, cwd, privateKey, privateRecord, privateRoot, context, service, sshManager, fakes, bindings, browserBindings, wraps, calls, start, savedConnections, clock };
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
    assert.deepEqual(f.wraps[0].settings.sshProtection.allowedSockets, binding.allowedSockets);
    assert.equal(f.wraps[0].settings.routePort, f.context.proxy.port);
    assert.deepEqual(result.ssh, { privateKeyProtection: true, available: true, connections: publicConnections });
    const snapshot = JSON.stringify(await f.service.snapshot());
    for (const secret of [f.privateKey, binding.agentSocket, ...['ENVARA_SSH_CONFIG', 'ENVARA_SSH_CONNECTIONS', 'ENVARA_SSH_TARGETS'].map(key => binding.environment[key]), 'synthetic-route-password']) assert.ok(!snapshot.includes(secret));
    if (kind === 'claude-code') {
      assert.equal(result.browserProfileId, 'chosen'); assert.equal(result.deviceIdentifierRestrictions, true);
      const prepared = internal.claudeLaunch;
      const settings = JSON.parse(await readFile(prepared.args[prepared.args.indexOf('--settings') + 1], 'utf8'));
      assert.equal(settings.env.SSH_AUTH_SOCK, binding.agentSocket);
      for (const key of ['ENVARA_SSH_CONFIG', 'ENVARA_SSH_CONNECTIONS', 'ENVARA_SSH_TARGETS']) assert.equal(settings.env[key], binding.environment[key], key);
      assert.equal(settings.env.ENVARA_SSH_PROXY_URL, undefined);
      assert.ok(!JSON.stringify(settings).includes('synthetic-route-password'));
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

test('password preparation and grants forward only selected fields and refuse mutation while a session is active', async t => {
  const f = await fixture(t);
  const target = { id: 'chosen', host: 'host.invalid', port: 2222, user: 'fixture' };
  const prepared = await f.service.prepareTerminalSshPassword({ ...target, password: 'not-forwarded', keyPath: '/not-forwarded' });
  assert.deepEqual(prepared, { authType: 'password', selectionToken: 'synthetic-password-selection' });
  assert.deepEqual(f.calls.preparePassword, [target]);
  const args = { id: 'chosen', connectionId: 'ssh_fixture', password: 'synthetic-ssh-secret' };
  const save = { id: 'chosen', name: 'Password server', selectionToken: prepared.selectionToken, password: args.password };
  const session = await f.start();
  await assert.rejects(f.service.setTerminalSshPassword(args), { code: 'TERMINAL_SSH_BUSY' });
  await assert.rejects(f.service.saveTerminalSshConnection(save), { code: 'TERMINAL_SSH_BUSY' });
  assert.deepEqual(f.calls.setPassword, []); assert.deepEqual(f.calls.save, []);
  await f.service.close({ sessionId: session.sessionId });
  assert.equal((await f.service.setTerminalSshPassword({ ...args, host: 'forged.invalid' })).supported, true);
  assert.deepEqual(f.calls.setPassword, [args]);
  await f.service.saveTerminalSshConnection({ ...save, keyPath: '/not-forwarded' });
  assert.deepEqual(f.calls.save, [save]);
  assert.ok(!JSON.stringify(await f.service.snapshot()).includes(args.password));
});

test('locked password metadata is not advertised as loaded SSH authority in terminal or Claude discovery', async t => {
  const locked = { ...connections[0], authType: 'password', passwordReady: false };
  const f = await fixture(t, { connections: [locked] });
  for (const kind of ['shell', 'claude-code']) {
    const started = await f.start(kind);
    assert.deepEqual(started.ssh.connections, []);
    assert.equal(started.ssh.available, false);
    if (kind === 'claude-code') {
      const description = f.calls.browserCreate.at(-1).readSshConnections();
      assert.equal(description.status, 'empty'); assert.deepEqual(description.connections, []);
    }
    await f.service.close({ sessionId: started.sessionId });
  }
  assert.equal(f.savedConnections.get('chosen')[0].authType, 'password');
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

test('empty SSH workspaces retain protected discovery shims and pinned manifests without an agent', async t => {
  for (const kind of ['shell', 'claude-code']) await t.test(kind, async subtest => {
    const f = await fixture(subtest, { connections: [] }), session = await f.start(kind), binding = f.bindings[0];
    assert.equal(f.calls.create.length, 1); assert.equal(binding.agentSocket, null);
    assert.ok(f.fakes[0].options.env.PATH.split(path.delimiter).includes(binding.binDirectory));
    for (const name of ['ssh', 'envara-ssh']) assert.ok((await stat(path.join(binding.binDirectory, name))).isFile());
    for (const key of ['ENVARA_SSH_CONFIG', 'ENVARA_SSH_CONNECTIONS']) {
      assert.equal(f.fakes[0].options.env[key], binding.environment[key]); assert.ok((await stat(binding.environment[key])).isFile());
    }
    for (const key of ['SSH_AUTH_SOCK', 'ENVARA_SSH_TARGETS', 'ENVARA_SSH_PROXY_URL']) assert.equal(f.fakes[0].options.env[key], undefined);
    assert.deepEqual(JSON.parse(await readFile(binding.environment.ENVARA_SSH_CONNECTIONS, 'utf8')), binding.manifest);
    assert.equal(binding.describe().status, 'empty'); assert.equal(binding.describe().available, false);
    assert.deepEqual(f.wraps[0].settings.sshProtection.protectedPaths, binding.protectedPaths);
    assert.deepEqual(session.ssh, { privateKeyProtection: true, available: false, connections: [] });
    if (kind === 'claude-code') {
      const view = f.calls.browserCreate[0].readSshConnections();
      assert.equal(view.status, 'empty'); assert.equal(view.available, false); assert.deepEqual(view.connections, []);
      const prepared = f.service.sessions.get(session.sessionId).claudeLaunch;
      const settings = JSON.parse(await readFile(prepared.args[prepared.args.indexOf('--settings') + 1], 'utf8'));
      for (const key of ['ENVARA_SSH_CONFIG', 'ENVARA_SSH_CONNECTIONS']) assert.equal(settings.env[key], binding.environment[key]);
      for (const key of ['SSH_AUTH_SOCK', 'ENVARA_SSH_TARGETS', 'ENVARA_SSH_PROXY_URL']) assert.equal(settings.env[key], undefined);
    }
  });
});

test('Claude SSH discovery reads only its session snapshot, reports expiry and never rereads the saved store', async t => {
  const f = await fixture(t), first = await f.start('claude-code');
  const otherConnection = { ...connections[0], id: 'ssh_other', alias: 'envara-bbbbbbbbbbbb', name: 'Other server', host: 'other.invalid' };
  f.savedConnections.set('other', [otherConnection]);
  const second = await f.start('claude-code', 'other');
  const [firstBinding, secondBinding] = f.bindings, [firstBrowser, secondBrowser] = f.calls.browserCreate;
  assert.equal(firstBrowser.sessionId, first.sessionId); assert.equal(secondBrowser.sessionId, second.sessionId);
  assert.equal(typeof firstBrowser.readSshConnections, 'function');
  const beforeList = f.calls.list.length, beforeCreate = f.calls.create.length;
  f.savedConnections.set('chosen', [otherConnection]);
  f.sshManager.list = async () => { throw new Error('Discovery must not read the mutable saved store'); };
  const a = firstBrowser.readSshConnections(), b = secondBrowser.readSshConnections();
  assert.equal(a?.then, undefined, 'the lease description must be synchronous');
  assert.equal(a.status, 'ready'); assert.equal(a.available, true); assert.deepEqual(a.connections, manifestConnections(connections));
  assert.equal(b.status, 'ready'); assert.deepEqual(b.connections, manifestConnections([otherConnection]));
  for (const secret of [f.privateKey, firstBinding.agentSocket, firstBinding.environment.ENVARA_SSH_PROXY_URL]) assert.ok(!JSON.stringify(a).includes(secret));
  const firstInternal = f.service.sessions.get(first.sessionId), secondInternal = f.service.sessions.get(second.sessionId);
  assert.equal(f.service.metadata(firstInternal).ssh.available, true);
  f.clock.now = firstBinding.manifest.expiresAt;
  assert.equal(firstBrowser.readSshConnections().status, 'expired');
  assert.equal(firstBrowser.readSshConnections().available, false);
  assert.equal(f.service.metadata(firstInternal).ssh.available, false);
  assert.equal(firstBinding.disposed, 0); assert.equal(secondBinding.disposed, 0);
  assert.equal(f.calls.create.length, beforeCreate); assert.equal(f.calls.list.length, beforeList);
  f.clock.now--;
  await f.service.close({ sessionId: first.sessionId });
  assert.equal(firstBinding.describe().status, 'closed'); assert.deepEqual(firstBinding.describe().connections, []);
  assert.equal(firstBrowser.readSshConnections().status, 'unavailable');
  assert.deepEqual(firstBrowser.readSshConnections().connections, []);
  assert.equal(f.service.metadata(firstInternal).ssh.available, false);
  assert.equal(secondBrowser.readSshConnections().status, 'ready'); assert.equal(f.service.metadata(secondInternal).ssh.available, true);
  assert.equal(f.calls.list.length, beforeList);
});

for (const kind of ['shell', 'claude-code']) {
  test(`${kind}: app-run password and key grants remain available across clock advances and duplication`, async t => {
    const password = { ...connections[0], id: 'ssh_password', alias: 'envara-bbbbbbbbbbbb', authType: 'password', passwordReady: true };
    const f = await fixture(t, { sessionVersion: 2, connections: [connections[0], password] });
    const first = await f.start(kind), firstInternal = f.service.sessions.get(first.sessionId), binding = f.bindings[0];
    for (const advance of [3600000, 86400000]) {
      f.clock.now += advance;
      const view = f.service.readSessionSshConnections(firstInternal);
      assert.equal(view.available, true); assert.equal(view.expiresAt, null);
      assert.equal(view.connections.length, 2);
      for (const connection of view.connections) {
        assert.equal(connection.expiresAt, null); assert.equal(connection.status, 'ready'); assert.equal(connection.available, true);
      }
      assert.equal(f.service.metadata(firstInternal).ssh.available, true);
      assert.equal(binding.disposed, 0); assert.equal(f.fakes[0].kills, 0);
      if (kind === 'claude-code') assert.deepEqual(f.calls.browserCreate[0].readSshConnections(), view);
    }
    const second = await f.service.duplicate({ sessionId: first.sessionId });
    assert.equal(second.ssh.available, true); assert.equal(f.bindings[1].manifest.expiresAt, null);
    assert.deepEqual(f.fakes[1].written, []);
    await f.service.close({ sessionId: first.sessionId });
    assert.equal(f.service.readSessionSshConnections(firstInternal).available, false);
    assert.equal(binding.disposed, 1); assert.equal(f.bindings[1].disposed, 0);
    assert.equal(f.service.metadata(f.service.sessions.get(second.sessionId)).ssh.available, true);
  });
}

test('discovery and public metadata refuse finishing, revoked, unfenced or unprotected session authority', async t => {
  const f = await fixture(t), started = await f.start('claude-code');
  const session = f.service.sessions.get(started.sessionId), read = f.calls.browserCreate[0].readSshConnections;
  const cases = [
    ['finished', true], ['finishing', Promise.resolve()], ['status', 'closing'], ['status', 'exited'],
    ['sshRevocation', Promise.resolve()], ['networkFence', false], ['sshPrivateKeyProtection', false], ['sshBinding', null],
    ['sshBinding', { describe: null }],
  ];
  for (const [field, value] of cases) {
    const original = session[field]; session[field] = value;
    try {
      const description = read();
      assert.equal(description.status, 'unavailable', field); assert.equal(description.available, false, field);
      assert.deepEqual(description.connections, [], field); assert.equal(description.expiresAt, null, field);
      assert.equal(f.service.metadata(session).ssh.available, false, field);
    } finally { session[field] = original; }
  }
  const binding = session.sshBinding, originalDescribe = binding.describe;
  binding.describe = () => { throw new Error('Synthetic lease failure'); };
  try { assert.equal(f.service.metadata(session).ssh.available, false, 'metadata must fail closed when describing a lease fails'); }
  finally { binding.describe = originalDescribe; }
  assert.equal(read().status, 'ready'); assert.equal(f.service.metadata(session).ssh.available, true);
  const beforeDescribe = f.calls.describe.length, wasClosed = f.service.closed; f.service.closed = true;
  try {
    assert.equal(read().status, 'unavailable'); assert.equal(f.service.metadata(session).ssh.available, false);
    assert.equal(f.calls.describe.length, beforeDescribe, 'closed service must not consult the lease');
  } finally { f.service.closed = wasClosed; }
});

test('discovery becomes unavailable before asynchronous SSH cleanup finishes', async t => {
  const entered = deferred(), release = deferred();
  const f = await fixture(t, { disposeBinding: async () => { entered.resolve(); await release.promise; } });
  const result = await f.start('claude-code'), session = f.service.sessions.get(result.sessionId), read = f.calls.browserCreate[0].readSshConnections;
  const closing = f.service.close({ sessionId: result.sessionId });
  await entered.promise;
  try {
    assert.equal(f.browserBindings[0].disposed, 0, 'browser IPC is still waiting behind SSH cleanup');
    assert.equal(f.bindings[0].describe().status, 'closed'); assert.equal(read().status, 'unavailable');
    assert.deepEqual(read().connections, []); assert.equal(f.service.metadata(session).ssh.available, false);
  } finally { release.resolve(); }
  await closing;
  assert.equal(f.browserBindings[0].disposed, 1); assert.equal(read().status, 'unavailable');
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
    for (const privateValue of [f.privateKey, f.privateRecord, 'synthetic-private-key-not-a-real-key', 'SSH_AUTH_SOCK', 'ENVARA_SSH_CONFIG', 'ENVARA_SSH_CONNECTIONS', 'ENVARA_SSH_TARGETS', 'ENVARA_SSH_PROXY_URL', 'synthetic-route-password']) assert.ok(!exported.includes(privateValue), `${scope}: ${privateValue}`);
  }
});
