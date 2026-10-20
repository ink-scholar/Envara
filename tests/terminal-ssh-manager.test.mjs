import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { TerminalSshManager } from '../electron/terminal-ssh-manager.mjs';
import { parseSshPublicKey } from '../electron/terminal-ssh-key.mjs';

const host = 'ssh-fixture.invalid';
const target = { host, port: 2222, user: 'fixture' };
const proxyUrl = 'http://fixture-user:fixture-password@127.0.0.1:12345';
const run = (command, args, options = {}) => new Promise((resolve, reject) => {
  const child = execFile(command, args, { timeout: 5000, encoding: 'utf8', ...options }, (error, stdout, stderr) => {
    if (error) { error.stdout = stdout; error.stderr = stderr; reject(error); } else resolve({ stdout, stderr });
  });
  child.stdin?.end();
});
const code = expected => error => error.code === expected;
const native = { skip: process.platform !== 'darwin' };
const publicKey = seed => {
  const fields = [Buffer.from('ssh-ed25519'), createHash('sha256').update(seed).digest()];
  const bytes = Buffer.concat(fields.flatMap(value => { const length = Buffer.alloc(4); length.writeUInt32BE(value.length); return [length, value]; }));
  return `ssh-ed25519 ${bytes.toString('base64')}`;
};

async function fixture(t, { real = false, passphrase = '', now = Date.now, execute: overrideExecute, spawn, createPasswordBroker, createDirectTransport } = {}) {
  const root = await realpath(await mkdtemp(path.join(process.platform === 'darwin' ? '/private/tmp' : os.tmpdir(), 'evssh-')));
  const dataDir = path.join(root, 'data'), hostHome = path.join(root, 'host'), keyDirectory = path.join(root, 'keys');
  await Promise.all([dataDir, hostHome, keyDirectory].map(directory => mkdir(directory, { mode: 0o700 })));
  const hostSsh = path.join(hostHome, '.ssh'); await mkdir(hostSsh, { mode: 0o700 });
  const keyPath = path.join(keyDirectory, 'fixture_ed25519'), hostKeyPath = path.join(keyDirectory, 'server_ed25519');
  if (real) {
    await run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', passphrase, '-C', 'disposable-fixture', '-f', keyPath]);
    await run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'disposable-host', '-f', hostKeyPath]);
  } else {
    await writeFile(keyPath, 'DISPOSABLE PRIVATE FIXTURE - NEVER A REAL KEY\n', { mode: 0o600 });
    await writeFile(`${keyPath}.pub`, `${publicKey('client')} fixture-comment\n`, { mode: 0o644 });
    await writeFile(`${hostKeyPath}.pub`, `${publicKey('server')} fixture-host-comment\n`, { mode: 0o644 });
  }
  const hostPublicKey = (await readFile(`${hostKeyPath}.pub`, 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ');
  const knownHosts = path.join(hostSsh, 'known_hosts');
  await writeFile(knownHosts, `[${host}]:2222 ${hostPublicKey}\n`, { mode: 0o600 });
  const calls = [], managers = [];
  const execute = overrideExecute ?? (real ? run : async (command, args, options) => {
    calls.push({ command, args, options });
    if (command === '/usr/bin/ssh' && args[0] === '-V') return { stdout: '', stderr: 'OpenSSH_10.3p1' };
    if (command === '/usr/bin/ssh-keygen' && args[0] === '-F') {
      const text = await readFile(args[3], 'utf8');
      const matches = text.split('\n').filter(line => line.split(/\s+/).includes(args[1]));
      if (!matches.length) throw new Error('No matching fixture trust');
      return { stdout: matches.join('\n') + '\n', stderr: '' };
    }
    throw new Error(`Unexpected native command ${command}`);
  });
  const nodeExecutable = await realpath(process.execPath);
  const options = { dataDir, hostHome, nodeExecutable, agentRoot: path.join(root, 'agents'), platform: 'darwin', execute, now,
    ...(spawn ? { spawn } : {}), ...(createPasswordBroker ? { createPasswordBroker } : {}), ...(createDirectTransport ? { createDirectTransport } : {}) };
  const createManager = (extra = {}) => { const manager = new TerminalSshManager({ ...options, ...extra }); managers.push(manager); return manager; };
  const manager = createManager();
  t.after(async () => { await Promise.allSettled(managers.map(value => value.close())); await rm(root, { recursive: true, force: true }); });
  await manager.ready;
  const select = (extra = {}) => manager.prepareIdentity({ id: 'profile-a', ...target, keyPath, ...extra });
  const save = async (extra = {}) => manager.save({ hostKeyConfirmed: true, id: extra.id ?? 'profile-a', name: extra.name ?? 'Fixture server', selectionToken: (await select(extra)).selectionToken });
  const session = (extra = {}) => manager.createSession({ profileId: 'profile-a', sessionId: 'session-a', directories: { home: hostHome }, proxyUrl, ...extra });
  const selectPassword = (extra = {}) => manager.preparePassword({ id: 'profile-a', ...target, ...extra });
  const savePassword = async (extra = {}) => manager.save({ hostKeyConfirmed: true, id: extra.id ?? 'profile-a', name: extra.name ?? 'Password fixture',
    selectionToken: (await selectPassword(extra)).selectionToken, password: extra.password ?? 'synthetic-password-only' });
  return { root, dataDir, hostHome, hostSsh, keyDirectory, keyPath, hostKeyPath, hostPublicKey, knownHosts, manager, createManager, calls, select, save, selectPassword, savePassword, session, nodeExecutable };
}

function passwordBrokers(t, { beforeCreate = async () => {}, beforeDispose = async () => {} } = {}) {
  const calls = [], servers = new Set();
  t.after(async () => { for (const server of servers) if (server.listening) await new Promise(resolve => server.close(resolve)); });
  const create = async options => {
    await beforeCreate(options);
    const socket = path.join(options.directory, 'command.sock'), server = createServer(client => client.destroy());
    servers.add(server);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
    await chmod(socket, 0o600);
    const call = { options, socket, passwords: new Map([...options.passwords].map(([alias, secret]) => [alias, Buffer.from(secret)])),
      disposed: false, isActive: options.isActive }; calls.push(call);
    return { socket, async dispose() {
      for (const secret of call.passwords.values()) secret.fill(0);
      await beforeDispose(call);
      if (server.listening) await new Promise(resolve => server.close(resolve));
      call.disposed = true;
    } };
  };
  return { create, calls };
}

function directTransports(t, { beforeDispose = async () => {} } = {}) {
  const calls = [], servers = new Set();
  t.after(async () => { for (const server of servers) if (server.listening) await new Promise(resolve => server.close(resolve)); });
  return { calls, create: async options => {
    const socket = path.join(options.directory, 'transport.sock'), server = createServer(client => client.destroy());
    servers.add(server);
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
    await chmod(socket, 0o600);
    const call = { options, socket, disposed: false }; calls.push(call);
    return { socket, token: 'a'.repeat(64), async dispose() {
      await beforeDispose(call);
      if (server.listening) await new Promise(resolve => server.close(resolve));
      call.disposed = true;
    } };
  } };
}

function selectedRoutes(f, { identity = () => 'stable-fixture-route', unavailable = () => false, probeHost } = {}) {
  const handles = [], probes = [];
  const manager = f.createManager({ resolveRoute: async ({ route, sessionId, signal }) => {
    if (unavailable(sessionId)) throw Object.assign(new Error('Synthetic unavailable route'), { code: 'SSH_ROUTE_UNAVAILABLE' });
    const handle = { route, routeIdentity: identity(), active: true, disposed: false, sessionId, signal,
      ...(route.kind === 'environment' ? { proxyUrl } : {}),
      isActive: () => handle.active && !handle.disposed,
      dispose: async () => { handle.disposed = true; } };
    handles.push(handle); return handle;
  }, probeHost: probeHost ?? (async options => {
    probes.push(options); return { routeBinding: options.routeBinding, unverified: true, hostKeys: [parseSshPublicKey(f.hostPublicKey)] };
  }) });
  return { manager, handles, probes };
}

test('explicit selected routes probe first-use fingerprints and require confirmation without reading host known_hosts', async t => {
  const f = await fixture(t), selected = selectedRoutes(f);
  await rm(f.knownHosts);
  const route = { kind: 'environment', profileId: 'route-b' };
  const prepared = await selected.manager.preparePassword({ id: 'profile-a', ...target, route });
  assert.equal(prepared.trustSource, 'probe'); assert.deepEqual(prepared.route, route);
  assert.equal(selected.probes.length, 1); assert.match(selected.handles[0].sessionId, /^sshprep_[a-f0-9]{24}$/);
  assert.equal(selected.handles[0].disposed, true);
  for (const hostKeyConfirmed of [undefined, false, 'true', 1])
    await assert.rejects(selected.manager.save({ id: 'profile-a', name: 'First-use host', selectionToken: prepared.selectionToken,
      password: 'synthetic', hostKeyConfirmed }), code('SSH_HOST_KEY_CONFIRMATION_REQUIRED'));
  const saved = await selected.manager.save({ id: 'profile-a', name: 'First-use host', selectionToken: prepared.selectionToken,
    password: 'synthetic', hostKeyConfirmed: true });
  assert.deepEqual(saved.route, route); assert.equal(saved.trustSource, 'probe');
  assert.match(selected.handles[1].sessionId, /^sshsave_[a-f0-9]{24}$/); assert.equal(selected.handles[1].disposed, true);
  const bytes = await readFile(selected.manager.filename, 'utf8');
  assert.doesNotMatch(bytes, /fixture-password|fixture-user|stable-fixture-route|proxyUrl|routeIdentity|synthetic/);
  assert.equal(f.calls.filter(call => call.command === '/usr/bin/ssh-keygen').length, 0);
});

test('fingerprint confirmation is bound to the selected route generation and cannot be saved after it changes', async t => {
  const f = await fixture(t); let generation = 'first-generation';
  const selected = selectedRoutes(f, { identity: () => generation });
  const prepared = await selected.manager.prepareIdentity({ id: 'profile-a', ...target, keyPath: f.keyPath, route: { kind: 'host' } });
  generation = 'second-generation';
  await assert.rejects(selected.manager.save({ id: 'profile-a', name: 'Changed route', selectionToken: prepared.selectionToken,
    hostKeyConfirmed: true }), code('SSH_ROUTE_CHANGED'));
  assert.deepEqual((await selected.manager.list({ id: 'profile-a' })).connections, []);
  assert.equal(selected.handles.every(handle => handle.disposed), true);
});

test('new sessions pin each alias to its saved route and invalidate without changing another alias route', async t => {
  const relays = directTransports(t), brokers = passwordBrokers(t);
  const f = await fixture(t, { createPasswordBroker: brokers.create, createDirectTransport: relays.create }), selected = selectedRoutes(f);
  const saved = [];
  for (const [name, route] of [['Host route', { kind: 'host' }], ['Environment route', { kind: 'environment', profileId: 'route-b' }]]) {
    const prepared = await selected.manager.preparePassword({ id: 'profile-a', ...target, route });
    saved.push(await selected.manager.save({ id: 'profile-a', name, selectionToken: prepared.selectionToken, password: 'synthetic', hostKeyConfirmed: true }));
  }
  await rm(f.knownHosts); // Probe-pinned records do not depend on personal trust files later.
  const binding = await selected.manager.createSession({ profileId: 'profile-a', sessionId: 'route-session', proxyUrl });
  assert.deepEqual(binding.describe().connections.map(record => record.route), saved.map(record => record.route));
  const contexts = selected.handles.filter(handle => handle.sessionId === 'route-session');
  assert.equal(contexts.length, 2); assert.equal(typeof relays.calls[0].options.openConnection, 'function');
  assert.equal(brokers.calls[0].options.isConnectionActive(saved[0].alias), true);
  contexts[1].active = false;
  assert.equal(relays.calls[0].options.isActive(saved[1].alias), false);
  assert.equal(relays.calls[0].options.isActive(saved[0].alias), true);
  assert.equal(binding.describe().connections[1].available, false);
  assert.equal(binding.describe().connections[0].available, true);
  assert.deepEqual(contexts.map(context => context.route), saved.map(record => record.route));
  await binding.dispose(); assert.equal(contexts.every(context => context.disposed), true);
});

test('unavailable saved routes remain in the immutable configured refusal set and never become ad-hoc targets', async t => {
  const f = await fixture(t), selected = selectedRoutes(f, { unavailable: sessionId => sessionId === 'missing-route' });
  const prepared = await selected.manager.preparePassword({ id: 'profile-a', ...target, route: { kind: 'environment', profileId: 'route-b' } });
  const saved = await selected.manager.save({ id: 'profile-a', name: 'Unavailable route', selectionToken: prepared.selectionToken, password: 'synthetic', hostKeyConfirmed: true });
  const envConfig = path.join(f.root, 'environment-config'); await mkdir(envConfig, { mode: 0o700 });
  const binding = await selected.manager.createSession({ profileId: 'profile-a', sessionId: 'missing-route', proxyUrl,
    directories: { home: f.hostHome, config: envConfig } });
  assert.equal(binding.describe().status, 'empty'); assert.equal(binding.environment.ENVARA_SSH_DIRECT_SOCKET, undefined);
  const launcher = await readFile(path.join(path.dirname(binding.binDirectory), 'launch.mjs'), 'utf8');
  assert.ok(launcher.includes(saved.alias)); assert.ok(launcher.includes('"profileId":"route-b"'));
  const result = await run(f.nodeExecutable, [path.join(path.dirname(binding.binDirectory), 'launch.mjs'), 'ssh', saved.alias],
    { env: { PATH: '/usr/bin:/bin', ENVARA_SSH_PROXY_URL: proxyUrl } }).catch(error => error);
  assert.match(result.stderr, /SSH_SAVED_CONNECTION_UNAVAILABLE/); await binding.dispose();
});

test('uncertain relay cleanup keeps selected route dependencies until the owned cleanup retry succeeds', async t => {
  let refuse = true;
  const relays = directTransports(t, { beforeDispose: async () => { if (refuse) throw new Error('Synthetic retained transport'); } });
  const brokers = passwordBrokers(t), f = await fixture(t, { createPasswordBroker: brokers.create, createDirectTransport: relays.create });
  const selected = selectedRoutes(f), prepared = await selected.manager.preparePassword({ id: 'profile-a', ...target, route: { kind: 'host' } });
  await selected.manager.save({ id: 'profile-a', name: 'Retained route', selectionToken: prepared.selectionToken, password: 'synthetic', hostKeyConfirmed: true });
  const binding = await selected.manager.createSession({ profileId: 'profile-a', sessionId: 'cleanup-route', proxyUrl });
  const context = selected.handles.find(handle => handle.sessionId === 'cleanup-route');
  await assert.rejects(binding.dispose(), code('SSH_CLEANUP_FAILED')); assert.equal(context.disposed, false);
  assert.equal(selected.manager.sessions.has('cleanup-route'), true); refuse = false;
  await binding.dispose(); assert.equal(context.disposed, true); assert.equal(selected.manager.sessions.size, 0);
});

test('closing the initiating window cancels the active probe before releasing its route dependency', async t => {
  const f = await fixture(t); let started;
  const ready = new Promise(resolve => { started = resolve; });
  const selected = selectedRoutes(f, { probeHost: async ({ signal }) => {
    started(); return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('Synthetic probe cancel'),
      { code: 'SSH_HOST_PROBE_CANCELLED' })), { once: true }));
  } });
  const controller = new AbortController();
  const pending = selected.manager.preparePassword({ id: 'profile-a', ...target, route: { kind: 'host' }, signal: controller.signal });
  const rejected = assert.rejects(pending, code('SSH_HOST_PROBE_CANCELLED')); await ready; controller.abort(); await rejected;
  assert.equal(selected.handles[0].signal.aborted, true); assert.equal(selected.handles[0].disposed, true);
  assert.equal(selected.manager.pending.size, 0); assert.equal(selected.manager.preparations.size, 0);
});

test('saved aliases use only their fixed direct transport and replaced password grants cannot revive an old session', async t => {
  const relays = directTransports(t), brokers = passwordBrokers(t);
  const f = await fixture(t, { createPasswordBroker: brokers.create, createDirectTransport: relays.create });
  const saved = await f.savePassword(), first = await f.session();
  const relay = relays.calls[0];
  assert.deepEqual(relay.options.connections, [{ alias: saved.alias, host, port: 2222 }]);
  assert.equal(relay.options.isActive(saved.alias), true); assert.equal(relay.options.isActive('envara-000000000000'), false);
  assert.equal(first.environment.ENVARA_SSH_DIRECT_SOCKET, relay.socket);
  const config = await readFile(path.join(path.dirname(first.binDirectory), 'config'), 'utf8');
  assert.ok(config.includes(`--alias ${saved.alias}`));
  assert.ok(config.includes('terminal-ssh-direct.mjs')); assert.ok(!config.includes('--host')); assert.ok(!config.includes('--environment-targets'));
  // Exercise the identity guard independently of the public mutation gate,
  // which already rejects unlocking a connection held by an active session.
  f.manager.clearPassword(saved.id);
  f.manager.grantPassword(saved.id, Buffer.from('replacement-synthetic-secret'));
  assert.equal(relay.options.isActive(saved.alias), false);
  const second = await f.session({ sessionId: 'fresh-grant' });
  assert.equal(relays.calls[1].options.isActive(saved.alias), true); assert.equal(relay.options.isActive(saved.alias), false);
  await first.dispose(); assert.equal(relay.disposed, true); assert.equal(relays.calls[1].options.isActive(saved.alias), true);
  await second.dispose(); assert.equal(relays.calls[1].disposed, true);
});

test('unknown-host configuration keeps environment trust persistent and configured locked targets in its immutable refusal set', async t => {
  const f = await fixture(t), saved = await f.savePassword();
  const unlocked = f.createManager(); await unlocked.ready;
  const envHome = path.join(f.root, 'environment-home'); await mkdir(envHome, { mode: 0o700 });
  const envConfig = path.join(envHome, '.config'); await mkdir(envConfig, { mode: 0o700 });
  const args = { profileId: 'profile-a', sessionId: 'locked-with-proxy', proxyUrl, directories: { home: envHome, config: envConfig } };
  const binding = await unlocked.createSession(args), publicDirectory = path.dirname(binding.binDirectory);
  assert.equal(binding.describe().status, 'empty'); assert.equal(binding.environment.ENVARA_SSH_PROXY_URL, proxyUrl);
  assert.equal(binding.environment.ENVARA_SSH_DIRECT_SOCKET, undefined);
  const config = await readFile(path.join(publicDirectory, 'environment-ssh-config'), 'utf8');
  for (const setting of ['StrictHostKeyChecking ask', 'IdentityAgent none', 'IdentityFile none', 'GlobalKnownHostsFile /dev/null', '--environment-targets', 'ForwardAgent no']) assert.ok(config.includes(setting), setting);
  const knownHosts = path.join(envConfig, 'ssh-known_hosts'); assert.ok(config.includes(knownHosts));
  assert.equal((await lstat(knownHosts)).mode & 0o777, 0o600);
  const launcher = await readFile(path.join(publicDirectory, 'launch.mjs'), 'utf8');
  assert.ok(launcher.includes('configuredConnections')); assert.ok(launcher.includes(saved.alias)); assert.ok(launcher.includes('adHocConfigPath'));
  assert.ok(!launcher.includes(proxyUrl)); assert.ok(launcher.includes('proxyUrl: process.env.ENVARA_SSH_PROXY_URL'));
  await writeFile(knownHosts, 'synthetic persistent host trust\n'); await binding.dispose();
  const next = await unlocked.createSession({ ...args, sessionId: 'locked-after-reopen' });
  assert.equal(await readFile(knownHosts, 'utf8'), 'synthetic persistent host trust\n'); await next.dispose();
});

test('legacy expanded IPv6 records retain their stored identity and exact trusted-host lookup spelling', async t => {
  const brokers = passwordBrokers(t), relays = directTransports(t);
  const f = await fixture(t, { createPasswordBroker: brokers.create, createDirectTransport: relays.create });
  const saved = await f.savePassword(), expanded = '2001:0db8:0000:0000:0000:0000:0000:0001';
  const document = JSON.parse(await readFile(f.manager.filename, 'utf8'));
  const stored = document.profiles[0].connections[0]; stored.host = expanded;
  const original = JSON.stringify(document); await writeFile(f.manager.filename, original);
  await writeFile(f.knownHosts, `[${expanded}]:2222 ${f.hostPublicKey}\n`);
  const reloaded = f.createManager(); await reloaded.ready;
  const entry = (await reloaded.list({ id: 'profile-a' })).connections[0];
  assert.equal(entry.host, expanded); assert.equal(entry.id, saved.id); assert.equal(entry.alias, saved.alias);
  assert.deepEqual(entry.hostFingerprints, saved.hostFingerprints); assert.equal(entry.passwordReady, false);
  await reloaded.setPassword({ id: 'profile-a', connectionId: saved.id, password: 'synthetic-reloaded-password' });
  const binding = await reloaded.createSession({ profileId: 'profile-a', sessionId: 'legacy-ipv6', proxyUrl });
  assert.equal(relays.calls.at(-1).options.connections[0].host, expanded);
  const lookups = f.calls.filter(call => call.command === '/usr/bin/ssh-keygen' && call.args[0] === '-F');
  assert.equal(lookups.at(-1).args[1], `[${expanded}]:2222`);
  const config = await readFile(path.join(path.dirname(binding.binDirectory), 'config'), 'utf8');
  assert.ok(config.includes(`HostName ${expanded}`)); assert.ok(config.includes(`HostKeyAlias ${saved.alias}`));
  assert.equal(await readFile(f.manager.filename, 'utf8'), original, 'loading/unlocking/reopening must not migrate the store or rewrite its identity');
  await binding.dispose();
});

test('direct transport cleanup failure keeps owned custody until a successful retry', async t => {
  let refuse = true;
  const relays = directTransports(t, { beforeDispose: async () => { if (refuse) throw new Error('synthetic direct cleanup failure'); } });
  const brokers = passwordBrokers(t), f = await fixture(t, { createDirectTransport: relays.create, createPasswordBroker: brokers.create });
  const saved = await f.savePassword(), binding = await f.session(), directory = path.dirname(binding.binDirectory);
  await assert.rejects(binding.dispose(), code('SSH_CLEANUP_FAILED'));
  assert.equal(relays.calls[0].options.isActive(saved.alias), false); assert.equal(f.manager.sessions.size, 1);
  assert.equal((await lstat(directory)).isDirectory(), true);
  refuse = false; await binding.dispose(); assert.equal(f.manager.sessions.size, 0); assert.equal(relays.calls[0].disposed, true);
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
});

test('selection is redacted, profile-bound, single-use, and persisted outside profile exports', async t => {
  const f = await fixture(t);
  const selected = await f.select();
  assert.match(selected.selectionToken, /^sshsel_[a-f0-9]{48}$/);
  assert.match(selected.keyFingerprint, /^SHA256:/);
  assert.equal(selected.keyLabel, 'fixture_ed25519');
  assert.ok(!JSON.stringify(selected).includes(f.keyDirectory));
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-b', name: 'Fixture server', selectionToken: selected.selectionToken }), code('SSH_SELECTION_MISMATCH'));
  const saved = await f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: '  Fixture server  ', selectionToken: selected.selectionToken });
  assert.equal(saved.name, 'Fixture server');
  assert.match(saved.alias, /^envara-[a-f0-9]{12}$/);
  assert.ok(!JSON.stringify(saved).includes(f.keyDirectory));
  assert.deepEqual(await f.manager.list({ id: 'profile-a' }), { supported: true, connections: [saved] });
  assert.deepEqual(await f.manager.list({ id: 'profile-b' }), { supported: true, connections: [] });
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Replay', selectionToken: selected.selectionToken }), code('SSH_SELECTION_EXPIRED'));
  assert.equal((await lstat(f.manager.filename)).mode & 0o777, 0o600);
  assert.equal(f.manager.root, path.join(f.dataDir, 'terminal', 'ssh-access'));
  const reopened = f.createManager(); await reopened.ready;
  assert.deepEqual(await reopened.list({ id: 'profile-a' }), { supported: true, connections: [saved] });
  const duplicate = await f.select();
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Ｆｉｘｔｕｒｅ server', selectionToken: duplicate.selectionToken }), code('SSH_NAME_EXISTS'));
  await f.manager.remove({ id: 'profile-a', connectionId: saved.id });
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.length, 0);
  assert.ok((await lstat(f.keyPath)).isFile());
});

test('selection expires and failed persistence retains the selection and previous records', async t => {
  let time = 1000;
  const f = await fixture(t, { now: () => time });
  const expired = await f.select(); time += 30 * 60 * 1000;
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Expired', selectionToken: expired.selectionToken }), code('SSH_SELECTION_EXPIRED'));
  const saved = await f.save();
  const previous = await readFile(f.manager.filename, 'utf8');
  const selected = await f.select();
  await chmod(f.manager.filename, 0o644);
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Second', selectionToken: selected.selectionToken }), code('SSH_UNSAFE_PATH'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), previous);
  assert.deepEqual((await f.manager.list({ id: 'profile-a' })).connections, [saved]);
  await chmod(f.manager.filename, 0o600);
  await f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Second', selectionToken: selected.selectionToken });
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.length, 2);
});

test('password metadata is trust-bound and persists without secrets or key references; reopening is locked', async t => {
  const f = await fixture(t, { spawn: () => { throw new Error('Password-only sessions never start ssh-agent'); } });
  await assert.rejects(f.selectPassword({ port: 22 }), code('SSH_HOST_UNTRUSTED'));
  const selected = await f.selectPassword();
  assert.equal(selected.authType, 'password'); assert.equal(Object.hasOwn(selected, 'keyLabel'), false);
  assert.deepEqual(selected.hostFingerprints.length, 1);
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-b', name: 'Wrong scope', selectionToken: selected.selectionToken, password: 'synthetic' }), code('SSH_SELECTION_MISMATCH'));
  const saved = await f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Password fixture', selectionToken: selected.selectionToken, password: 'never-persist-this-synthetic-password' });
  assert.equal(saved.authType, 'password'); assert.equal(saved.passwordReady, true);
  for (const field of ['password', 'keyLabel', 'keyFingerprint', 'keyPath', 'keyStat', 'publicKey']) assert.equal(Object.hasOwn(saved, field), false);
  const bytes = await readFile(f.manager.filename, 'utf8'), record = JSON.parse(bytes).profiles[0].connections[0];
  assert.deepEqual(Object.keys(record).sort(), ['alias', 'authType', 'host', 'hostFingerprints', 'hostKeys', 'id', 'name', 'port', 'route', 'trustSource', 'user'].sort());
  assert.ok(!bytes.includes('never-persist-this-synthetic-password')); assert.ok(!bytes.includes(f.keyDirectory));
  const reopened = f.createManager(); await reopened.ready;
  assert.deepEqual((await reopened.list({ id: 'profile-a' })).connections, [{ ...saved, passwordReady: false }]);
  const session = await reopened.createSession({ profileId: 'profile-a', sessionId: 'locked', proxyUrl, nodeExecutable: f.nodeExecutable });
  assert.equal(session.describe().status, 'empty'); assert.equal(session.agentSocket, null);
  assert.equal(session.environment.SSH_AUTH_SOCK, undefined); assert.equal(session.environment.ENVARA_SSH_PROXY_URL, undefined);
  assert.ok(session.protectedPaths.every(value => typeof value === 'string'));
  await session.dispose();
});

test('password validation and failed persistence never grant authorization or consume the selected identity', async t => {
  const f = await fixture(t); const selected = await f.selectPassword();
  for (const password of ['', 'a\0b', 'a\rb', 'a\nb', 'x'.repeat(1025), '密'.repeat(342), undefined]) {
    await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Invalid', selectionToken: selected.selectionToken, password }), code('SSH_PASSWORD_INVALID'));
  }
  await f.save(); const previous = await readFile(f.manager.filename, 'utf8');
  await chmod(f.manager.filename, 0o644);
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Password fixture', selectionToken: selected.selectionToken, password: 'synthetic' }), code('SSH_UNSAFE_PATH'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), previous);
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.filter(record => record.authType === 'password').length, 0);
  await chmod(f.manager.filename, 0o600);
  const saved = await f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Password fixture', selectionToken: selected.selectionToken, password: 'x'.repeat(1024) });
  assert.equal(saved.passwordReady, true);
});

test('password sessions use an app-lifetime private broker without key agents or persisted secrets', async t => {
  let time = 1000; const brokers = passwordBrokers(t);
  const f = await fixture(t, { now: () => time, createPasswordBroker: brokers.create,
    spawn: () => { throw new Error('Password-only session must not start a key agent'); } });
  const secret = 'synthetic-manager-password-unique', saved = await f.savePassword({ password: secret });
  time += 30 * 60 * 1000;
  const session = await f.session();
  assert.equal(session.describe().status, 'ready'); assert.equal(session.agentSocket, null);
  assert.equal(session.describe().expiresAt, null);
  assert.equal(session.describe().connections[0].expiresAt, null);
  assert.equal(session.describe().connections[0].authType, 'password');
  assert.equal(brokers.calls.length, 1); const broker = brokers.calls[0];
  assert.equal(broker.passwords.get(saved.alias).toString(), secret); assert.equal(broker.isActive(), true);
  assert.equal(broker.options.expiresAt, null);
  assert.ok(broker.options.passwords.get(saved.alias).every(value => value === 0));
  assert.equal(broker.options.proxyUrl, proxyUrl); assert.deepEqual(session.allowedSockets, [broker.socket, session.environment.ENVARA_SSH_DIRECT_SOCKET]);
  assert.equal(broker.options.transportSocket, session.environment.ENVARA_SSH_DIRECT_SOCKET);
  assert.equal(broker.options.directToken, session.environment.ENVARA_SSH_DIRECT_TOKEN);
  assert.equal(session.environment.SSH_AUTH_SOCK, undefined); assert.ok(!JSON.stringify(session.environment).includes(secret));
  const publicDirectory = path.dirname(session.binDirectory), config = await readFile(path.join(publicDirectory, 'config'), 'utf8');
  for (const line of ['IdentityFile none', 'IdentityAgent none', 'PreferredAuthentications password', 'PubkeyAuthentication no', 'PermitLocalCommand no', 'EnableEscapeCommandline no', 'EscapeChar none']) assert.ok(config.includes(line), line);
  assert.ok(!config.includes('undefined'));
  const launcher = await readFile(path.join(publicDirectory, 'launch.mjs'), 'utf8');
  assert.ok(launcher.includes(broker.socket)); assert.ok(launcher.includes(saved.alias));
  for (const entry of await readdir(publicDirectory, { withFileTypes: true })) if (entry.isFile()) assert.ok(!(await readFile(path.join(publicDirectory, entry.name), 'utf8')).includes(secret));
  await session.dispose(); assert.equal(broker.disposed, true); assert.equal(broker.isActive(), false);
  assert.ok(broker.options.passwords.get(saved.alias).every(value => value === 0));
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, true);
  time = 1000 + 30 * 24 * 60 * 60 * 1000;
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, true);
  const later = await f.session({ sessionId: 'later' });
  assert.equal(later.describe().status, 'ready'); assert.equal(brokers.calls.length, 2); await later.dispose();
});

test('password unlock cannot mutate active leases; duplicates have independent buffers and cleanup', async t => {
  const brokers = passwordBrokers(t), f = await fixture(t, { createPasswordBroker: brokers.create });
  const saved = await f.savePassword({ password: 'synthetic-first-password' });
  const first = await f.session(), second = await f.session({ sessionId: 'session-b' });
  assert.notEqual(brokers.calls[0].socket, brokers.calls[1].socket);
  assert.notEqual(brokers.calls[0].options.passwords.get(saved.alias), brokers.calls[1].options.passwords.get(saved.alias));
  await assert.rejects(f.manager.setPassword({ id: 'profile-a', connectionId: saved.id, password: 'synthetic-replacement' }), code('SSH_CONNECTION_IN_USE'));
  await assert.rejects(f.manager.remove({ id: 'profile-a', connectionId: saved.id }), code('SSH_CONNECTION_IN_USE'));
  const selected = await f.selectPassword();
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Another', selectionToken: selected.selectionToken, password: 'synthetic' }), code('SSH_CONNECTION_IN_USE'));
  await first.dispose(); assert.equal(second.describe().status, 'ready');
  assert.equal(brokers.calls[1].passwords.get(saved.alias).toString(), 'synthetic-first-password');
  await second.dispose();
  const storeBefore = await readFile(f.manager.filename, 'utf8');
  await f.manager.setPassword({ id: 'profile-a', connectionId: saved.id, password: 'synthetic-replacement' });
  assert.equal(await readFile(f.manager.filename, 'utf8'), storeBefore);
  const next = await f.session({ sessionId: 'session-c' });
  assert.equal(brokers.calls[2].passwords.get(saved.alias).toString(), 'synthetic-replacement');
  await f.manager.close(); assert.equal(next.describe().status, 'closed');
  assert.ok(brokers.calls[2].options.passwords.get(saved.alias).every(value => value === 0));
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, false);
});

test('password launch and unlock revalidate exact host trust, including changed and revoked keys', async t => {
  const brokers = passwordBrokers(t), f = await fixture(t, { createPasswordBroker: brokers.create });
  const saved = await f.savePassword();
  await writeFile(f.knownHosts, `[${host}]:2222 ${publicKey('changed-password-server')}\n`);
  await assert.rejects(f.session(), code('SSH_IDENTITY_CHANGED'));
  await assert.rejects(f.manager.setPassword({ id: 'profile-a', connectionId: saved.id, password: 'synthetic-new' }), code('SSH_IDENTITY_CHANGED'));
  await writeFile(f.knownHosts, `@revoked [${host}]:2222 ${f.hostPublicKey}\n`);
  await assert.rejects(f.session(), code('SSH_HOST_UNTRUSTED'));
  assert.equal(brokers.calls.length, 0); assert.equal(f.manager.sessions.size, 0);
});

test('password broker disposal failure retains custody and retries before deleting its owned directory', async t => {
  let rejectDispose = true;
  const brokers = passwordBrokers(t, { beforeDispose: async () => { if (rejectDispose) throw new Error('synthetic cleanup refusal'); } });
  const f = await fixture(t, { createPasswordBroker: brokers.create }); const saved = await f.savePassword();
  const session = await f.session(), directory = path.dirname(brokers.calls[0].socket);
  await assert.rejects(session.dispose(), code('SSH_CLEANUP_FAILED'));
  assert.equal(f.manager.sessions.size, 1); assert.ok((await lstat(directory)).isDirectory());
  assert.equal(brokers.calls[0].isActive(), false); assert.ok(brokers.calls[0].options.passwords.get(saved.alias).every(value => value === 0));
  rejectDispose = false; await session.dispose(); assert.equal(f.manager.sessions.size, 0);
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
});

test('closing during password broker creation cancels the new lease and drains its broker', async t => {
  let entered, release; const reached = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { release = resolve; });
  const brokers = passwordBrokers(t, { beforeCreate: async () => { entered(); await gate; } });
  const f = await fixture(t, { createPasswordBroker: brokers.create }); const saved = await f.savePassword();
  const creating = f.session(), refused = assert.rejects(creating, code('SSH_SESSION_CLOSED'));
  await reached; const closing = f.manager.close(); release(); await refused; await closing;
  assert.equal(f.manager.sessions.size, 0); assert.equal(brokers.calls[0].disposed, true);
  assert.ok(brokers.calls[0].options.passwords.get(saved.alias).every(value => value === 0));
  assert.deepEqual(await readdir(f.manager.agentRoot), []);
});

test('password store rejects injected credentials and key references while legacy public-key records remain supported', async t => {
  const f = await fixture(t); const saved = await f.savePassword(); const original = await readFile(f.manager.filename, 'utf8');
  for (const field of ['password', 'keyPath', 'publicKey', 'keyStat']) {
    const document = JSON.parse(original); document.profiles[0].connections[0][field] = 'synthetic-never-read';
    await writeFile(f.manager.filename, JSON.stringify(document));
    await assert.rejects(f.createManager().ready, code('SSH_STORAGE_INVALID'));
  }
  await writeFile(f.manager.filename, original); await f.manager.remove({ id: 'profile-a', connectionId: saved.id });
  await f.save(); const legacy = JSON.parse(await readFile(f.manager.filename, 'utf8')); delete legacy.profiles[0].connections[0].authType;
  await writeFile(f.manager.filename, JSON.stringify(legacy));
  const reopened = f.createManager(); await reopened.ready;
  assert.equal((await reopened.list({ id: 'profile-a' })).connections[0].authType, 'publickey');
  assert.equal((await reopened.list({ id: 'profile-a' })).connections[0].keyLabel, 'fixture_ed25519');
});

test('store-wide connection IDs cannot share a password grant across environments', async t => {
  const f = await fixture(t); await f.savePassword();
  const document = JSON.parse(await readFile(f.manager.filename, 'utf8'));
  document.profiles.push({ id: 'profile-b', connections: [{ ...document.profiles[0].connections[0], name: 'Another target', host: 'other-fixture.invalid' }] });
  const bytes = JSON.stringify(document); await writeFile(f.manager.filename, bytes);
  await assert.rejects(f.createManager().ready, code('SSH_STORAGE_INVALID'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), bytes);
});

test('persist projects legacy key records and refuses password records with extra plaintext fields', async t => {
  const f = await fixture(t); await f.save();
  const record = f.manager.profiles.get('profile-a')[0];
  await f.manager.persist(new Map([['profile-a', [{ ...record, password: 'synthetic-never-persist-extra' }]] ]));
  assert.ok(!(await readFile(f.manager.filename, 'utf8')).includes('synthetic-never-persist-extra'));
  const saved = await f.savePassword();
  const passwordRecord = f.manager.profiles.get('profile-a').find(record => record.id === saved.id);
  const before = await readFile(f.manager.filename, 'utf8');
  await assert.rejects(f.manager.persist(new Map([['profile-a', [{ ...passwordRecord, password: 'synthetic-reject' }]] ])), code('SSH_STORAGE_INVALID'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), before);
});

test('password broker startup cleanup remains attached to a failed setup until a successful retry', async t => {
  let cleanupCalls = 0;
  const f = await fixture(t, { createPasswordBroker: async () => {
    const error = Object.assign(new Error('synthetic setup refusal'), { code: 'SSH_AGENT_FAILED' });
    error.sshCleanup = async () => { if (++cleanupCalls === 1) throw new Error('synthetic retained cleanup'); };
    throw error;
  } });
  await f.savePassword();
  let failure;
  await assert.rejects(f.session(), error => { failure = error; return error.code === 'SSH_AGENT_FAILED' && typeof error.sshCleanup === 'function'; });
  assert.equal(f.manager.sessions.size, 1); assert.equal(cleanupCalls, 1);
  await failure.sshCleanup(); assert.equal(cleanupCalls, 2); assert.equal(f.manager.sessions.size, 0);
  assert.deepEqual(await readdir(f.manager.agentRoot), []);
});

test('a password authorization remains available across elapsed days and duplicates without renewal', async t => {
  let now = 1000; const brokers = passwordBrokers(t);
  const f = await fixture(t, { now: () => now, createPasswordBroker: brokers.create });
  const saved = await f.savePassword(), session = await f.session();
  const originalGrant = f.manager.passwordGrant(saved.id);
  now += 7 * 24 * 60 * 60 * 1000;
  assert.equal(session.describe().status, 'ready'); assert.equal(session.describe().expiresAt, null);
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, true);
  assert.equal(f.manager.passwordGrant(saved.id), originalGrant);
  assert.ok(brokers.calls[0].options.passwords.get(saved.alias).every(value => value === 0));
  await assert.rejects(f.manager.setPassword({ id: 'profile-a', connectionId: saved.id, password: 'synthetic-unlock' }), code('SSH_CONNECTION_IN_USE'));
  const duplicate = await f.session({ sessionId: 'later-copy' }); assert.equal(duplicate.describe().status, 'ready');
  assert.equal(brokers.calls.length, 2); await duplicate.dispose(); await session.dispose();
  await f.manager.setPassword({ id: 'profile-a', connectionId: saved.id, password: 'synthetic-unlock' });
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, true);
});

test('elapsed time never revokes a password grant but explicit revocation cannot be undone for an old lease', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let now = 1_000_000; const brokers = passwordBrokers(t);
  const f = await fixture(t, { now: () => now, createPasswordBroker: brokers.create });
  const saved = await f.savePassword(), session = await f.session(), original = brokers.calls[0];
  assert.equal(original.isActive(), true); assert.equal(session.describe().status, 'ready');
  const originalGrant = f.manager.passwordGrant(saved.id);
  assert.equal(originalGrant.expiresAt, null); assert.equal(Object.hasOwn(originalGrant, 'timer'), false);
  now += 30 * 24 * 60 * 60 * 1000;
  t.mock.timers.tick(30 * 24 * 60 * 60 * 1000);
  assert.equal(original.isActive(), true);
  assert.equal(session.describe().status, 'ready');
  now -= 60 * 24 * 60 * 60 * 1000;
  assert.equal(original.isActive(), true);
  f.manager.clearPassword(saved.id);
  assert.ok(originalGrant.secret.every(value => value === 0));
  assert.equal(original.isActive(), false);
  assert.equal(session.describe().status, 'unavailable'); assert.equal(session.describe().expiresAt, null);
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, false);
  // Model an independent new authorization without assigning it to the old lease.
  f.manager.grantPassword(saved.id, Buffer.from('synthetic-later-grant'));
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections[0].passwordReady, true);
  assert.equal(original.isActive(), false); assert.equal(session.describe().status, 'unavailable');
  await session.dispose();
  const replacement = await f.session({ sessionId: 'new-authorization' });
  assert.equal(brokers.calls[1].isActive(), true); assert.equal(replacement.describe().status, 'ready');
  await replacement.dispose();
});

test('empty and password bindings protect both the selected Node runtime and module code, including dynamic app overrides', async t => {
  const brokers = passwordBrokers(t), f = await fixture(t, { createPasswordBroker: brokers.create });
  const empty = await f.session();
  const base = f.manager.protection();
  assert.ok(base.runtimeReadOnlyPaths.some(directory => f.nodeExecutable.startsWith(`${directory}/`)));
  const module = fileURLToPath(new URL('../electron/terminal-ssh-manager.mjs', import.meta.url));
  assert.ok(base.runtimeReadOnlyPaths.some(directory => module.startsWith(`${directory}/`)), 'module code is also protected');
  assert.ok(base.runtimeReadOnlyPaths.every(directory => empty.readOnlyPaths.includes(directory)));
  assert.ok(!base.runtimeReadOnlyPaths.includes(f.root));
  await empty.dispose();
  const bundle = path.join(f.root, 'isolated-runtime', 'Envara.app');
  const node = path.join(bundle, 'Contents', 'Resources', 'runtime', 'node');
  await mkdir(path.dirname(node), { recursive: true, mode: 0o700 });
  await writeFile(node, 'synthetic never-executed node fixture\n', { mode: 0o500 });
  const override = await f.session({ sessionId: 'override-empty', nodeExecutable: node });
  assert.ok(override.runtimeReadOnlyPaths.includes(bundle)); assert.ok(override.readOnlyPaths.includes(bundle));
  await override.dispose();
  const optional = f.createManager({ nodeExecutable: null }); await optional.ready;
  const dynamic = await optional.createSession({ profileId: 'profile-a', sessionId: 'optional-node', nodeExecutable: node, proxyUrl });
  assert.ok(dynamic.readOnlyPaths.includes(bundle)); await dynamic.dispose();
  await f.savePassword(); const password = await f.session({ sessionId: 'password-protection' });
  assert.ok(base.runtimeReadOnlyPaths.every(directory => password.readOnlyPaths.includes(directory)));
  assert.deepEqual(brokers.calls[0].options.runtimeReadOnlyPaths, password.runtimeReadOnlyPaths);
  await password.dispose();
});

test('rejects unsafe private paths, hardlinks, permissive modes and missing public counterparts', async t => {
  const f = await fixture(t);
  for (const keyPath of ['relative-key', `${f.keyDirectory}/./fixture_ed25519`, `${f.keyDirectory}/../keys/fixture_ed25519`]) {
    await assert.rejects(f.select({ keyPath }), code('SSH_UNSAFE_PATH'));
  }
  await chmod(f.keyPath, 0o644); await assert.rejects(f.select(), code('SSH_UNSAFE_PATH')); await chmod(f.keyPath, 0o600);
  const hard = path.join(f.keyDirectory, 'hard'); await link(f.keyPath, hard);
  await assert.rejects(f.select(), code('SSH_UNSAFE_PATH')); await rm(hard);
  const linked = path.join(f.root, 'linked-key'); await symlink(f.keyPath, linked);
  await assert.rejects(f.select({ keyPath: linked }), code('SSH_UNSAFE_PATH'));
  const linkedDirectory = path.join(f.root, 'linked-keys'); await symlink(f.keyDirectory, linkedDirectory);
  await assert.rejects(f.select({ keyPath: path.join(linkedDirectory, 'fixture_ed25519') }), code('SSH_UNSAFE_PATH'));
  await rm(`${f.keyPath}.pub`); await assert.rejects(f.select(), code('SSH_PUBLIC_KEY_REQUIRED'));
  await writeFile(`${f.keyPath}.pub`, 'not a public key\n', { mode: 0o644 }); await assert.rejects(f.select(), code('SSH_KEY_INVALID'));
  assert.ok(f.calls.every(value => value.command !== '/usr/bin/ssh-add'));
});

test('requires existing exact host trust and refuses changed, revoked or CA host records', async t => {
  const f = await fixture(t);
  await assert.rejects(f.select({ port: 22 }), code('SSH_HOST_UNTRUSTED'));
  const selected = await f.select();
  await writeFile(f.knownHosts, `[${host}]:2222 ${publicKey('changed-server')}\n`);
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Changed', selectionToken: selected.selectionToken }), code('SSH_IDENTITY_CHANGED'));
  for (const marker of ['@revoked', '@cert-authority']) {
    await writeFile(f.knownHosts, `${marker} [${host}]:2222 ${f.hostPublicKey}\n`);
    await assert.rejects(f.select(), code('SSH_HOST_UNTRUSTED'));
  }
  assert.equal((await f.manager.list({ id: 'profile-a' })).connections.length, 0);
});

test('revalidates key inode and public identity before saving and all saved keys before launch', async t => {
  const f = await fixture(t);
  const selected = await f.select();
  await rename(f.keyPath, `${f.keyPath}.original`);
  await writeFile(f.keyPath, 'DISPOSABLE PRIVATE FIXTURE - NEVER A REAL KEY\n', { mode: 0o600 });
  await assert.rejects(f.manager.save({ hostKeyConfirmed: true, id: 'profile-a', name: 'Replaced', selectionToken: selected.selectionToken }), code('SSH_IDENTITY_CHANGED'));
  await f.save();
  await writeFile(`${f.keyPath}.pub`, `${publicKey('changed-client')}\n`);
  await assert.rejects(f.session(), code('SSH_IDENTITY_CHANGED'));
  assert.equal(f.manager.sessions.size, 0);
});

test('protects selected keys across environments without starting an agent for empty environments', async t => {
  const f = await fixture(t, { spawn: () => { throw new Error('Must not start an agent'); } });
  await f.save();
  const secondKey = path.join(f.keyDirectory, 'other-key');
  await writeFile(secondKey, 'DISPOSABLE SECOND FIXTURE\n', { mode: 0o600 });
  await writeFile(`${secondKey}.pub`, `${publicKey('second-client')}\n`, { mode: 0o644 });
  await f.select({ id: 'profile-b', keyPath: secondKey });
  const session = await f.session({ profileId: 'profile-c' });
  assert.ok(path.isAbsolute(session.binDirectory)); assert.equal(session.agentSocket, null);
  assert.equal(session.environment.SSH_AUTH_SOCK, undefined); assert.equal(session.environment.ENVARA_SSH_PROXY_URL, undefined);
  assert.ok(path.isAbsolute(session.environment.ENVARA_SSH_CONFIG));
  assert.ok(path.isAbsolute(session.environment.ENVARA_SSH_CONNECTIONS));
  assert.equal(session.describe().status, 'empty'); assert.equal(session.describe().available, false);
  const cli = path.join(session.binDirectory, 'envara-ssh');
  const env = { ...f.manager.nativeEnvironment(f.hostHome), ...session.environment };
  const discovery = JSON.parse((await run(cli, ['list', '--json'], { env })).stdout);
  assert.equal(discovery.schema, 'envara.ssh-session'); assert.equal(discovery.version, 2);
  assert.equal(discovery.status, 'empty'); assert.equal(discovery.expiresAt, null); assert.deepEqual(discovery.connections, []);
  for (const args of [[], ['fixture@ssh-fixture.invalid'], ['-i', f.keyPath, 'fixture@ssh-fixture.invalid']]) {
    await assert.rejects(run(path.join(session.binDirectory, 'ssh'), args, { env }), error => error.code === 2 && /SSH_CONNECTIONS_EMPTY/.test(error.stderr));
  }
  assert.equal(f.manager.sessions.size, 1);
  assert.equal([...f.manager.sessions.values()][0].child, null);
  // Discovery describes the loaded session, not later additions to the store.
  await f.save({ hostKeyConfirmed: true, id: 'profile-c', name: 'Added after session creation' });
  assert.equal((await f.manager.list({ id: 'profile-c' })).connections.length, 1);
  assert.equal(session.describe().status, 'empty');
  assert.equal(JSON.parse((await run(cli, ['list', '--json'], { env })).stdout).status, 'empty');
  for (const protectedPath of [f.hostSsh, f.manager.root, f.manager.agentRoot, f.keyPath, secondKey]) assert.ok(session.protectedPaths.includes(protectedPath));
  const publicDirectory = path.dirname(session.binDirectory);
  assert.equal((await lstat(publicDirectory)).mode & 0o777, 0o500);
  await session.dispose();
  assert.equal(session.describe().status, 'closed'); assert.deepEqual(session.describe().connections, []);
  assert.equal(f.manager.sessions.size, 0); await assert.rejects(lstat(publicDirectory), { code: 'ENOENT' });
  await assert.rejects(f.session({ proxyUrl: 'http://127.0.0.1:12345' }), code('SSH_PROXY_REQUIRED'));
  await f.manager.removeProfile({ id: 'profile-b' });
  assert.ok(!f.manager.protection().protectedPaths.includes(secondKey));
});

test('unsupported platforms do not touch disk or execute native commands', async () => {
  const manager = new TerminalSshManager({ dataDir: path.join(os.tmpdir(), 'nonexistent-envara-fixture'), hostHome: path.join(os.tmpdir(), 'nonexistent-envara-host'), platform: 'win32',
    execute: () => { throw new Error('Must not execute'); }, spawn: () => { throw new Error('Must not spawn'); } });
  await manager.ready;
  assert.deepEqual(await manager.list({ id: 'profile-a' }), { supported: false, connections: [] });
  await assert.rejects(manager.prepareIdentity({ id: 'profile-a', ...target, keyPath: '/no-key' }), code('SSH_UNSUPPORTED'));
  const session = await manager.createSession({ profileId: 'profile-a', sessionId: 'session-a' });
  assert.deepEqual(session.environment, {});
  await manager.close();
});

test('corrupt metadata or permissive store modes fail closed without replacing the store', async t => {
  const f = await fixture(t); await f.save();
  const original = await readFile(f.manager.filename, 'utf8');
  await chmod(f.manager.filename, 0o644);
  await assert.rejects(f.createManager().ready, code('SSH_STORAGE_INVALID'));
  await chmod(f.manager.filename, 0o600);
  const document = JSON.parse(original); document.profiles[0].connections[0].keyFingerprint = 'SHA256:wrong';
  const corrupted = JSON.stringify(document); await writeFile(f.manager.filename, corrupted);
  await assert.rejects(f.createManager().ready, code('SSH_STORAGE_INVALID'));
  assert.equal(await readFile(f.manager.filename, 'utf8'), corrupted);
});

test('native agent holds only the chosen identity, refuses unconstrained signing and emits secret-free runtime files', native, async t => {
  const f = await fixture(t, { real: true }); const saved = await f.save();
  const session = await f.session();
  const publicDirectory = path.dirname(session.binDirectory), config = path.join(publicDirectory, 'config');
  const description = session.describe();
  assert.equal(description.status, 'ready'); assert.equal(description.available, true);
  assert.equal(description.connections.length, 1); assert.equal(description.connections[0].alias, saved.alias);
  assert.doesNotMatch(JSON.stringify(description), /keyFingerprint|keyPath|fixture-password/);
  assert.equal(session.allowedAgentSocket, session.agentSocket);
  assert.deepEqual(session.readOnlyPaths, [publicDirectory, ...f.manager.protection().readOnlyPaths]);
  assert.deepEqual(session.readablePaths, [publicDirectory]);
  assert.equal((await lstat(publicDirectory)).mode & 0o777, 0o500);
  const agentEnv = f.manager.nativeEnvironment(publicDirectory, session.agentSocket);
  const loaded = await run('/usr/bin/ssh-add', ['-L'], { env: agentEnv });
  assert.match(loaded.stdout, /^ssh-ed25519 /); assert.equal(loaded.stdout.trim().split('\n').length, 1);
  const publicFile = path.join(publicDirectory, `${saved.id}.pub`);
  await assert.rejects(run('/usr/bin/ssh-add', ['-T', publicFile], { env: agentEnv }), error => /agent refused operation/.test(error.stderr));
  const parsed = await run('/usr/bin/ssh', ['-G', '-F', config, saved.alias], { env: agentEnv });
  assert.match(parsed.stdout, new RegExp(`^hostname ${host.replaceAll('.', '\\.')}$$`, 'm'));
  for (const required of ['stricthostkeychecking true', 'identitiesonly yes', 'forwardagent no', 'batchmode yes', 'passwordauthentication no', 'controlmaster false']) assert.ok(parsed.stdout.includes(required), required);
  for (const entry of await readdir(publicDirectory, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const filename = path.join(publicDirectory, entry.name), text = await readFile(filename, 'utf8');
    assert.equal((await lstat(filename)).mode & 0o777, 0o400);
    assert.ok(!text.includes(proxyUrl)); assert.ok(!text.includes(f.keyPath)); assert.ok(!text.includes('PRIVATE KEY'));
  }
  const targets = JSON.parse(await readFile(session.environment.ENVARA_SSH_TARGETS, 'utf8'));
  assert.deepEqual(targets, [{ host, port: 2222 }]);
  assert.equal(session.environment.ENVARA_SSH_CONFIG, config);
  const manifest = JSON.parse(await readFile(session.environment.ENVARA_SSH_CONNECTIONS, 'utf8'));
  assert.equal(manifest.schema, 'envara.ssh-session'); assert.equal(manifest.expiresAt, description.expiresAt);
  const runtimeEnvironment = { ...agentEnv, ...session.environment };
  const discovered = JSON.parse((await run(path.join(session.binDirectory, 'envara-ssh'), ['list', '--json'], { env: runtimeEnvironment })).stdout);
  assert.deepEqual(discovered, description);
  for (const args of [['-F', '/dev/null', saved.alias], ['-o', 'ProxyCommand=anything', saved.alias], ['-i', f.keyPath, saved.alias], ['unknown-alias']]) {
    await assert.rejects(run(path.join(session.binDirectory, 'ssh'), args, { env: runtimeEnvironment }), error => error.code === 2 && /SSH_OPTIONS_UNSUPPORTED|SSH_ARGUMENT_INVALID/.test(error.stderr));
  }
  await assert.rejects(f.manager.remove({ id: 'profile-a', connectionId: saved.id }), code('SSH_CONNECTION_IN_USE'));
  const directory = path.dirname(publicDirectory); await session.dispose(); await session.dispose();
  assert.equal(session.describe().status, 'closed'); assert.equal(session.describe().available, false); assert.deepEqual(session.describe().connections, []);
  await assert.rejects(lstat(directory), { code: 'ENOENT' });
  await assert.rejects(run('/usr/bin/ssh-add', ['-L'], { env: agentEnv }));
  await f.manager.remove({ id: 'profile-a', connectionId: saved.id });
});

test('a single native identity retains constraints for every saved destination', native, async t => {
  const f = await fixture(t, { real: true });
  await f.save();
  await writeFile(f.knownHosts, `[${host}]:2222 ${f.hostPublicKey}\n[second-fixture.invalid]:2200 ${f.hostPublicKey}\n`);
  await f.save({ hostKeyConfirmed: true, name: 'Second fixture', host: 'second-fixture.invalid', port: 2200, user: 'other' });
  const calls = [], execute = f.manager.execute;
  f.manager.execute = async (command, args, options) => { calls.push({ command, args, options }); return execute(command, args, options); };
  const session = await f.session();
  const additions = calls.filter(value => value.command === '/usr/bin/ssh-add' && value.args.includes('-q'));
  assert.equal(additions.length, 1); assert.equal(additions[0].args.filter(value => value === '-h').length, 2);
  assert.equal(additions[0].options.env.SSH_AUTH_SOCK, session.agentSocket);
  assert.equal(additions[0].options.env.SSH_ASKPASS_REQUIRE, 'never');
  assert.equal(Object.hasOwn(additions[0].options.env, 'DISPLAY'), false);
  await session.dispose();
});

test('mixed authentication keeps both methods available without timers and isolates adapter failures', native, async t => {
  let now = Date.now();
  const brokers = passwordBrokers(t), f = await fixture(t, { real: true, now: () => now, createPasswordBroker: brokers.create });
  const key = await f.save(), password = await f.savePassword();
  const commands = [], execute = f.manager.execute;
  f.manager.execute = async (command, args, options) => { commands.push({ command, args }); return execute(command, args, options); };
  const session = await f.session(), publicDirectory = path.dirname(session.binDirectory);
  assert.equal(session.describe().connections.length, 2); assert.ok(session.agentSocket);
  assert.equal(session.describe().expiresAt, null);
  assert.ok(session.describe().connections.every(record => record.expiresAt === null && record.available));
  assert.deepEqual(session.allowedSockets, [session.agentSocket, brokers.calls[0].socket, session.environment.ENVARA_SSH_DIRECT_SOCKET]);
  assert.equal(brokers.calls[0].passwords.size, 1); assert.ok(brokers.calls[0].passwords.has(password.alias));
  assert.deepEqual((await readdir(publicDirectory)).filter(name => name.endsWith('.pub')), [`${key.id}.pub`]);
  const additions = commands.filter(call => call.command === '/usr/bin/ssh-add' && call.args.includes('-q'));
  assert.equal(additions.length, 1); assert.equal(additions[0].args.at(-1), f.keyPath);
  assert.equal(additions[0].args.includes('-t'), false);
  assert.equal(additions[0].args.includes(`${password.user}@${password.alias}`), false);
  const loaded = await run('/usr/bin/ssh-add', ['-L'], { env: f.manager.nativeEnvironment(publicDirectory, session.agentSocket) });
  assert.equal(loaded.stdout.trim().split('\n').length, 1);
  now += 30 * 24 * 60 * 60 * 1000;
  assert.equal(session.describe().status, 'ready');
  assert.ok(session.describe().connections.every(record => record.available));
  assert.equal(brokers.calls[0].isActive(), true);
  const lease = [...f.manager.sessions.values()][0];
  lease.processError = true;
  const degraded = session.describe();
  assert.equal(degraded.status, 'ready');
  assert.equal(degraded.connections.find(record => record.alias === key.alias).status, 'unavailable');
  assert.equal(degraded.connections.find(record => record.alias === password.alias).status, 'ready');
  lease.processError = false;
  f.manager.clearPassword(password.id);
  const revoked = session.describe();
  assert.equal(revoked.status, 'ready');
  assert.equal(revoked.connections.find(record => record.alias === key.alias).status, 'ready');
  assert.equal(revoked.connections.find(record => record.alias === password.alias).status, 'unavailable');
  assert.equal(brokers.calls[0].isActive(), false);
  await session.dispose(); assert.equal(brokers.calls[0].disposed, true);
});

test('encrypted native keys fail without prompting, retain stored connections, and clean the owned agent', native, async t => {
  const f = await fixture(t, { real: true, passphrase: 'disposable-fixture-passphrase' }); const saved = await f.save();
  await assert.rejects(f.session(), code('SSH_KEY_LOCKED'));
  assert.equal(f.manager.sessions.size, 0);
  assert.deepEqual(await readdir(f.manager.agentRoot), []);
  assert.deepEqual((await f.manager.list({ id: 'profile-a' })).connections, [saved]);
  assert.ok((await lstat(f.keyPath)).isFile());
});

test('native mismatched private and public counterparts never return a usable session', native, async t => {
  const f = await fixture(t, { real: true });
  await writeFile(`${f.keyPath}.pub`, await readFile(`${f.hostKeyPath}.pub`));
  await f.save();
  await assert.rejects(f.session(), code('SSH_IDENTITY_CHANGED'));
  assert.equal(f.manager.sessions.size, 0); assert.deepEqual(await readdir(f.manager.agentRoot), []);
});

test('native key authorization has no timer and discovery only conceals explicitly stopped agents', native, async t => {
  let clock = Date.now();
  const f = await fixture(t, { real: true, now: () => clock }); const saved = await f.save();
  const commands = [], launches = [], execute = f.manager.execute, spawn = f.manager.spawn;
  f.manager.execute = async (...args) => { commands.push({ command: args[0], args: args[1] }); return execute(...args); };
  f.manager.spawn = (...args) => { launches.push({ command: args[0], args: args[1] }); return spawn(...args); };
  const session = await f.session();
  const before = commands.length;
  assert.equal(session.describe().status, 'ready');
  assert.equal(session.describe().expiresAt, null);
  for (const call of [...launches, ...commands.filter(call => call.command === '/usr/bin/ssh-add')]) assert.equal(call.args.includes('-t'), false);
  clock += 30 * 24 * 60 * 60 * 1000;
  assert.equal(session.describe().status, 'ready'); assert.equal(session.describe().available, true);
  assert.equal(commands.length, before);
  const env = { ...f.manager.nativeEnvironment(f.hostHome), ...session.environment };
  const listing = JSON.parse((await run(path.join(session.binDirectory, 'envara-ssh'), ['list', '--json'], { env })).stdout);
  assert.equal(listing.status, 'ready'); assert.equal(listing.available, true); assert.equal(listing.connections[0].alias, saved.alias);
  const loaded = await run('/usr/bin/ssh-add', ['-L'], { env });
  assert.match(loaded.stdout, /^ssh-ed25519 /);
  assert.equal(commands.length, before, 'Discovery and elapsed time never reload identities');
  const lease = [...f.manager.sessions.values()][0];
  lease.processError = true;
  assert.equal(session.describe().status, 'unavailable'); assert.deepEqual(session.describe().connections, []);
  assert.equal(session.describe().expiresAt, null);
  lease.processError = false;
  await session.dispose(); assert.equal(session.describe().status, 'closed');
});

test('revoked host trust is checked again before native agent startup', native, async t => {
  const f = await fixture(t, { real: true }); await f.save();
  await writeFile(f.knownHosts, `@revoked [${host}]:2222 ${f.hostPublicKey}\n`);
  let spawned = false; f.manager.spawn = () => { spawned = true; throw new Error('Must not spawn'); };
  await assert.rejects(f.session(), code('SSH_HOST_UNTRUSTED'));
  assert.equal(spawned, false); assert.equal(f.manager.sessions.size, 0);
});

test('cleanup refuses substituted directories and can retry without changing unrelated permissions', native, async t => {
  const f = await fixture(t, { real: true }); await f.save(); const session = await f.session();
  const publicDirectory = path.dirname(session.binDirectory), savedDirectory = `${publicDirectory}-owned`, outside = path.join(f.root, 'outside');
  await mkdir(outside, { mode: 0o500 }); await rename(publicDirectory, savedDirectory); await symlink(outside, publicDirectory);
  await assert.rejects(session.dispose(), code('SSH_CLEANUP_FAILED'));
  assert.equal((await lstat(outside)).mode & 0o777, 0o500);
  assert.equal(f.manager.sessions.size, 1);
  await rm(publicDirectory); await rename(savedDirectory, publicDirectory); await session.dispose();
  assert.equal(f.manager.sessions.size, 0);
  assert.equal((await lstat(outside)).mode & 0o777, 0o500);
});

test('close during agent loading cancels setup, waits for cleanup and cannot return a live lease', native, async t => {
  const f = await fixture(t, { real: true }); await f.save();
  const execute = f.manager.execute; let entered, release;
  const reached = new Promise(resolve => { entered = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  f.manager.execute = async (command, args, options) => {
    if (command === '/usr/bin/ssh-add' && args.includes('-q')) { entered(); await barrier; }
    return execute(command, args, options);
  };
  const setup = f.session(); const rejected = assert.rejects(setup, code('SSH_SESSION_CLOSED'));
  await reached; const closed = f.manager.close(); release(); await rejected; await closed;
  assert.equal(f.manager.sessions.size, 0); assert.deepEqual(await readdir(f.manager.agentRoot), []);
  await f.manager.close();
});
