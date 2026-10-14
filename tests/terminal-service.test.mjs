import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { chmod, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { TerminalService } from '../electron/terminal-service.mjs';

class FakePty {
  constructor(options) { this.pid = 123456; this.options = options; this.data = new Set(); this.exits = new Set(); this.written = []; this.pauses = 0; }
  onData(fn) { this.data.add(fn); return { dispose: () => this.data.delete(fn) }; }
  onExit(fn) { this.exits.add(fn); return { dispose: () => this.exits.delete(fn) }; }
  output(value) { for (const fn of this.data) fn(value); }
  exit(exitCode = 0) { for (const fn of this.exits) fn({ exitCode }); }
  write(value) { this.written.push(value); }
  resize(columns, rows) { this.lastSize = [columns, rows]; }
  pause() { this.pauses++; }
  resume() { this.resumes = (this.resumes ?? 0) + 1; }
  kill() { this.kills = (this.kills ?? 0) + 1; this.exit(); }
}
async function fixture(t, overrides = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-terminal-test-'));
  const cwd = path.join(root, 'selected'); await mkdir(cwd);
  const fakes = [], events = []; let resolutions = 0;
  const service = new TerminalService({
    dataDir: path.join(root, 'data'),
    resolveContext: async id => { resolutions++; return { id, name: id, timezone: 'Asia/Shanghai', timezoneSource: 'manual', proxy: null }; },
    ptyFactory: (_shell, _args, options) => { const pty = new FakePty(options); fakes.push(pty); return pty; },
    processControl: { capture: async pid => ({ pid }), close: async ({ pty }) => { pty.exit(); return { ok: true }; } },
    onEvent: event => { events.push(event); },
    ...overrides,
  });
  await service.ready;
  t.after(async () => { await service.shutdown().catch(() => {}); await rm(root, { recursive: true, force: true }); });
  return { root, cwd, service, fakes, events, resolutions: () => resolutions };
}

test('snapshots and folder selection never resolve the network; creation requires an explicitly selected directory', async t => {
  const f = await fixture(t);
  assert.equal((await f.service.snapshot({ id: 'profile_a' })).profiles[0].cwd, null);
  await assert.rejects(f.service.create({ id: 'profile_a' }), { code: 'TERMINAL_DIRECTORY_REQUIRED' });
  assert.equal(f.resolutions(), 0);
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  assert.equal(f.resolutions(), 0);
  const session = await f.service.create({ id: 'profile_a' });
  assert.equal(f.resolutions(), 1);
  assert.equal(session.status, 'running');
  assert.equal(session.cwd, await import('node:fs/promises').then(fs => fs.realpath(f.cwd)));
  assert.equal((await f.service.create({ id: 'profile_a' })).sessionId, session.sessionId);
  assert.equal(f.resolutions(), 1);
  await f.service.snapshot({ id: 'profile_a' });
  assert.equal(f.resolutions(), 1);
  await assert.rejects(f.service.setDirectory({ id: 'profile_a', path: f.cwd }), { code: 'TERMINAL_RUNNING' });
  const saved = JSON.parse(await readFile(path.join(f.root, 'data/terminal/workspace.json')));
  assert.deepEqual(Object.keys(saved.profiles[0]).sort(), ['cwd', 'id']);
});

test('duplicates create fresh independent PTYs from the resolved launch context while sharing profile tool configuration', async t => {
  let resolutions = 0;
  const context = { id: 'profile_a', name: 'Original', timezone: 'Asia/Shanghai', timezoneSource: 'manual', privacy: { mode: 'strict' }, geolocation: { latitude: 14.6, longitude: 121, accuracy: 50000 }, network: { ok: true, ip: '8.8.8.8', countryCode: 'PH' }, proxy: { protocol: 'https', host: 'proxy.invalid', port: 8443, username: 'fixture-user', password: 'secret-original' } };
  const f = await fixture(t, { resolveContext: async () => { resolutions++; return context; } });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const source = await f.service.create({ id: 'profile_a' });
  await f.service.resize({ sessionId: source.sessionId, columns: 132, rows: 44 });
  await f.service.write({ sessionId: source.sessionId, data: 'still-running-command\r' });
  f.fakes[0].output('output from the original only\n');
  context.timezone = 'UTC'; context.timezoneSource = 'changed'; context.proxy.password = 'changed-password';
  const duplicate = await f.service.duplicate({ sessionId: source.sessionId });
  assert.equal(duplicate.status, 'running'); assert.equal(duplicate.profileId, source.profileId);
  assert.notEqual(duplicate.sessionId, source.sessionId);
  assert.equal(duplicate.cwd, source.cwd); assert.equal(duplicate.timezone, 'Asia/Shanghai');
  assert.equal(duplicate.columns, 132); assert.equal(duplicate.rows, 44);
  assert.deepEqual(duplicate.privacy, { mode: 'strict' });
  assert.deepEqual(duplicate.geolocation, source.geolocation);
  assert.deepEqual(duplicate.network.egress, source.network.egress);
  for (const key of ['DO_NOT_TRACK', 'DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC']) assert.equal(f.fakes[1].options.env[key], '1');
  assert.equal(duplicate.replay, ''); assert.deepEqual(f.fakes[1].written, []);
  assert.equal(resolutions, 1, 'Copy must use the existing native context without network resolution');
  for (const key of ['HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'HISTFILE', 'CLAUDE_CONFIG_DIR', 'HTTP_PROXY', 'TZ']) assert.equal(f.fakes[1].options.env[key], f.fakes[0].options.env[key]);
  assert.match(f.fakes[1].options.env.HTTPS_PROXY, /secret-original@/);
  await f.service.write({ sessionId: duplicate.sessionId, data: 'duplicate-only-command\r' });
  assert.deepEqual(f.fakes[0].written, ['still-running-command\r']);
  assert.deepEqual(f.fakes[1].written, ['duplicate-only-command\r']);
  const snapshot = await f.service.snapshot({ id: 'profile_a' });
  assert.equal(snapshot.profiles[0].sessions.length, 2);
  assert.equal(snapshot.profiles[0].timezoneSource, 'manual');
  assert.equal(JSON.stringify(snapshot).includes('secret-original'), false);
  await f.service.close({ sessionId: source.sessionId });
  assert.equal(f.service.sessions.get(source.sessionId).launchContext, null);
  assert.deepEqual(f.service.sessions.get(source.sessionId).secrets, []);
  assert.equal(f.service.sessions.get(source.sessionId).pty, null);
  assert.equal(f.service.sessions.get(duplicate.sessionId).status, 'running');
  assert.equal(f.fakes[1].exits.size, 1);
  assert.equal((await f.service.create({ id: 'profile_a' })).sessionId, duplicate.sessionId);
  await assert.rejects(f.service.duplicate({ sessionId: source.sessionId }), { code: 'TERMINAL_NOT_RUNNING' });
  await assert.rejects(f.service.setDirectory({ id: 'profile_a', path: f.cwd }), { code: 'TERMINAL_RUNNING' });
  await assert.rejects(f.service.removeProfile({ id: 'profile_a' }), { code: 'TERMINAL_RUNNING' });
  await f.service.close({ sessionId: duplicate.sessionId });
  const restarted = await f.service.create({ id: 'profile_a' });
  assert.equal(resolutions, 2); assert.equal(restarted.timezone, 'UTC');
  assert.match(f.fakes[2].options.env.HTTPS_PROXY, /changed-password@/);
});

test('each SOCKS duplicate owns a separate authenticated bridge and closing it preserves the other endpoint', async t => {
  const f = await fixture(t, { resolveContext: async id => ({ id, timezone: 'UTC', proxy: { protocol: 'socks5', host: '127.0.0.1', port: 12345, username: 'fixture-user', password: 'fixture-password' } }) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const source = await f.service.create({ id: 'profile_a' });
  const duplicate = await f.service.duplicate({ sessionId: source.sessionId, columns: 110, rows: 35 });
  const sourceEndpoint = new URL(f.fakes[0].options.env.HTTP_PROXY);
  const duplicateEndpoint = new URL(f.fakes[1].options.env.HTTP_PROXY);
  assert.equal(sourceEndpoint.hostname, '127.0.0.1'); assert.equal(duplicateEndpoint.hostname, '127.0.0.1');
  assert.notEqual(sourceEndpoint.port, duplicateEndpoint.port);
  assert.notEqual(sourceEndpoint.password, duplicateEndpoint.password);
  assert.equal(duplicate.columns, 110); assert.equal(duplicate.rows, 35);
  const http = await import('node:http');
  const unauthenticatedStatus = endpoint => new Promise((resolve, reject) => {
    const request = http.get({ hostname: endpoint.hostname, port: endpoint.port, path: 'http://origin.invalid/' }, response => { response.resume(); response.once('end', () => resolve(response.statusCode)); });
    request.on('error', reject);
  });
  assert.equal(await unauthenticatedStatus(sourceEndpoint), 407);
  assert.equal(await unauthenticatedStatus(duplicateEndpoint), 407);
  await f.service.close({ sessionId: duplicate.sessionId });
  await assert.rejects(unauthenticatedStatus(duplicateEndpoint), { code: 'ECONNREFUSED' });
  assert.equal(await unauthenticatedStatus(sourceEndpoint), 407);
  const recreatedDuplicate = await f.service.duplicate({ sessionId: source.sessionId });
  assert.equal(recreatedDuplicate.status, 'running');
});

test('duplicate eligibility is checked again after queued or asynchronous startup work', async t => {
  const f = await fixture(t);
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const source = await f.service.create({ id: 'profile_a' });
  let release; const gate = new Promise(done => { release = done; });
  const waiting = f.service.serialized('profile_a', () => gate);
  const queued = f.service.duplicate({ sessionId: source.sessionId });
  f.fakes[0].exit(); await delay(5); release(); await waiting;
  await assert.rejects(queued, { code: 'TERMINAL_NOT_RUNNING' });
  assert.equal(f.fakes.length, 1);
  const next = await f.service.create({ id: 'profile_a' });
  const originalDirectories = f.service.directories.bind(f.service);
  let releaseDirectories; const directoryGate = new Promise(done => { releaseDirectories = done; });
  let entered; const directoryEntered = new Promise(done => { entered = done; });
  f.service.directories = async id => { entered(); await directoryGate; return originalDirectories(id); };
  const starting = f.service.duplicate({ sessionId: next.sessionId });
  await directoryEntered;
  f.fakes[1].exit(); await delay(5); releaseDirectories();
  await assert.rejects(starting, { code: 'TERMINAL_NOT_RUNNING' });
  assert.equal(f.fakes.length, 2, 'A source that exited before spawning cannot produce a duplicate PTY');
  const failed = (await f.service.snapshot({ id: 'profile_a' })).profiles[0].sessions.find(session => session.status === 'error');
  assert.ok(failed); assert.equal(f.service.sessions.get(failed.sessionId).launchContext, null);
});

test('same-profile duplicates and simultaneous profile launches share the global eight-session reservation', async t => {
  const f = await fixture(t);
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const source = await f.service.create({ id: 'profile_a' });
  const duplicates = await Promise.all(Array.from({ length: 7 }, () => f.service.duplicate({ sessionId: source.sessionId })));
  assert.equal(new Set([source, ...duplicates].map(session => session.sessionId)).size, 8);
  await assert.rejects(f.service.duplicate({ sessionId: source.sessionId }), { code: 'TERMINAL_LIMIT' });
  await f.service.close({ sessionId: duplicates[0].sessionId });
  assert.equal((await f.service.duplicate({ sessionId: source.sessionId })).status, 'running');
  await f.service.shutdown();
  const g = await fixture(t);
  const ids = Array.from({ length: 9 }, (_, index) => `profile_${index}`);
  await Promise.all(ids.map(id => g.service.setDirectory({ id, path: g.cwd })));
  const launches = await Promise.allSettled(ids.map(id => g.service.create({ id })));
  assert.equal(launches.filter(result => result.status === 'fulfilled').length, 8);
  assert.equal(launches.find(result => result.status === 'rejected').reason.code, 'TERMINAL_LIMIT');
  assert.equal(g.fakes.length, 8);
});

test('a duplicate shell exiting during native identity capture never becomes running and preserves the source', async t => {
  let captures = 0;
  let release; const gate = new Promise(done => { release = done; });
  const f = await fixture(t, { processControl: { capture: async pid => { if (++captures === 2) await gate; return { pid }; }, close: async () => ({ ok: true }) } });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const source = await f.service.create({ id: 'profile_a' });
  const creating = f.service.duplicate({ sessionId: source.sessionId });
  for (let attempt = 0; attempt < 20 && f.fakes.length < 2; attempt++) await delay(5);
  assert.equal(f.fakes.length, 2);
  f.fakes[1].exit(); release();
  const duplicate = await creating;
  assert.notEqual(duplicate.status, 'running');
  await delay(10);
  assert.equal(f.events.some(event => event.sessionId === duplicate.sessionId && event.type === 'status' && event.status === 'running'), false);
  const finished = f.service.sessions.get(duplicate.sessionId);
  assert.equal(finished.status, 'exited'); assert.equal(finished.launchContext, null);
  assert.equal(f.fakes[1].kills ?? 0, 0);
  assert.equal(f.service.sessions.get(source.sessionId).status, 'running');
  await f.service.write({ sessionId: source.sessionId, data: 'source-still-usable\r' });
  assert.deepEqual(f.fakes[0].written, ['source-still-usable\r']);
  await assert.rejects(f.service.duplicate({ sessionId: duplicate.sessionId }), { code: 'TERMINAL_NOT_RUNNING' });
});

test('a pending context exposes a starting reservation and blocks directory changes', async t => {
  let resolve; const pending = new Promise(done => { resolve = done; });
  const f = await fixture(t, { resolveContext: async id => { await pending; return { id, timezone: 'UTC', proxy: null }; } });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const creating = f.service.create({ id: 'profile_a' });
  await delay(10);
  assert.equal((await f.service.snapshot({ id: 'profile_a' })).profiles[0].sessions[0].status, 'starting');
  resolve(); await creating;
});

test('closing a starting session cancels resumed resolution and reclaims a late asynchronous PTY', async t => {
  let release; const gate = new Promise(done => { release = done; });
  let entered; const resolving = new Promise(done => { entered = done; });
  const f = await fixture(t, { resolveContext: async id => { entered(); await gate; return { id, timezone: 'UTC', proxy: { protocol: 'socks5', host: '127.0.0.1', port: 12345, username: 'fixture-user', password: 'fixture-password' } }; } });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const creating = f.service.create({ id: 'profile_a' });
  await resolving;
  const starting = (await f.service.snapshot({ id: 'profile_a' })).profiles[0].sessions[0];
  assert.equal(starting.status, 'starting');
  assert.equal((await f.service.close({ sessionId: starting.sessionId })).status, 'closed');
  release();
  await assert.rejects(creating, { code: 'TERMINAL_START_CANCELLED' });
  assert.equal(f.fakes.length, 0, 'A resolved configuration must not resume spawning after close');
  const cancelled = f.service.sessions.get(starting.sessionId);
  assert.equal(cancelled.status, 'closed'); assert.equal(cancelled.pty, null); assert.equal(cancelled.bridge, null); assert.equal(cancelled.launchContext, null);

  let releaseFactory; const factoryGate = new Promise(done => { releaseFactory = done; });
  let factoryEntered; const enteringFactory = new Promise(done => { factoryEntered = done; });
  const late = []; let cleanupCalls = 0;
  const g = await fixture(t, {
    ptyFactory: async (_shell, _args, options) => { factoryEntered(); await factoryGate; const pty = new FakePty(options); late.push(pty); return pty; },
    processControl: { capture: async pid => ({ pid }), close: async ({ pty }) => { cleanupCalls++; pty.exit(); return { ok: true }; } },
  });
  await g.service.setDirectory({ id: 'profile_a', path: g.cwd });
  const lateCreation = g.service.create({ id: 'profile_a' });
  await enteringFactory;
  const pending = (await g.service.snapshot({ id: 'profile_a' })).profiles[0].sessions[0];
  await g.service.close({ sessionId: pending.sessionId });
  releaseFactory();
  await assert.rejects(lateCreation, { code: 'TERMINAL_START_CANCELLED' });
  assert.equal(late.length, 1); assert.equal(cleanupCalls, 1, 'Late resources cannot reuse an empty earlier cleanup result');
  assert.equal(g.service.sessions.get(pending.sessionId).pty, null);
  assert.equal(g.service.sessions.get(pending.sessionId).status, 'closed');
});

test('per-profile child environments exclude host secrets and arbitrary PATH while retaining local CLI install search', async t => {
  const original = { key: process.env.ENVARA_HOST_TEST_API_KEY, ssh: process.env.SSH_AUTH_SOCK, path: process.env.PATH, home: process.env.HOME, timezone: process.env.TZ };
  process.env.ENVARA_HOST_TEST_API_KEY = 'synthetic-secret'; process.env.SSH_AUTH_SOCK = '/fake/host-agent'; process.env.PATH = '/fake/wrapper-only';
  try {
    const f = await fixture(t);
    await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); await f.service.create({ id: 'profile_a' });
    await f.service.setDirectory({ id: 'profile_b', path: f.cwd }); await f.service.create({ id: 'profile_b' });
    const [a, b] = f.fakes.map(pty => pty.options.env);
    for (const env of [a, b]) {
      assert.equal(env.ENVARA_HOST_TEST_API_KEY, undefined); assert.equal(env.SSH_AUTH_SOCK, undefined);
      assert.equal(env.HTTP_PROXY, undefined); assert.equal(env.NODE_OPTIONS, undefined);
      assert.equal(env.GIT_AUTHOR_EMAIL, undefined); assert.equal(env.TZ, 'Asia/Shanghai');
      assert.equal(env.PATH.includes('/fake/wrapper-only'), false);
      if (process.platform !== 'win32') assert.ok(env.PATH.includes(path.join(os.homedir(), '.local/bin')));
    }
    for (const key of ['HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'HISTFILE', 'CLAUDE_CONFIG_DIR']) assert.notEqual(a[key], b[key]);
    if (process.platform !== 'win32') assert.equal((await stat(a.HOME)).mode & 0o777, 0o700);
    assert.equal(process.env.HOME, original.home); assert.equal(process.env.TZ, original.timezone);
  } finally {
    for (const [key, value] of [['ENVARA_HOST_TEST_API_KEY', original.key], ['SSH_AUTH_SOCK', original.ssh], ['PATH', original.path]]) if (value === undefined) delete process.env[key]; else process.env[key] = value;
  }
});

test('owned configuration symlinks and invalid profile IDs cannot escape the terminal namespace', async t => {
  const f = await fixture(t);
  await assert.rejects(f.service.setDirectory({ id: '../escape', path: f.cwd }), { code: 'TERMINAL_VALIDATION_ERROR' });
  const outside = path.join(f.root, 'outside'); await mkdir(outside);
  const owned = path.join(f.root, 'data/terminal/profiles/profile_a'); await mkdir(owned);
  await symlink(outside, path.join(owned, 'home'), process.platform === 'win32' ? 'junction' : 'dir');
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  await assert.rejects(f.service.create({ id: 'profile_a' }), { code: 'TERMINAL_UNSAFE_PATH' });
  assert.equal(f.fakes.length, 0);
  assert.deepEqual(await import('node:fs/promises').then(fs => fs.readdir(outside)), []);
});

test('metadata and streaming replay redact proxy credentials even when secret output splits across PTY chunks', async t => {
  const f = await fixture(t, { resolveContext: async id => ({ id, name: 'safe', timezone: 'UTC', timezoneSource: 'proxy', proxy: { protocol: 'https', host: 'proxy.invalid', port: 8443, username: 'fixture-user', password: 'secret-password' } }) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); const session = await f.service.create({ id: 'profile_a' });
  assert.match(f.fakes[0].options.env.HTTPS_PROXY, /^https:\/\/fixture-user:secret-password@/);
  f.fakes[0].output('secret-pa'); f.fakes[0].output('ssword\n'); f.fakes[0].output(f.fakes[0].options.env.HTTP_PROXY + '\n');
  await delay(10);
  const document = JSON.stringify(await f.service.snapshot());
  assert.equal(document.includes('secret-password'), false); assert.equal(document.includes('fixture-user'), false);
  assert.ok(document.includes('[redacted]'));
  const data = f.events.filter(event => event.type === 'data').map(event => event.data).join('');
  assert.equal(data.includes('secret-password'), false);
  assert.equal(session.network.scope, 'proxy-aware-cli'); assert.equal(session.network.mode, 'https');
});

test('terminal input, resize and global session counts are bounded', async t => {
  const f = await fixture(t);
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); const session = await f.service.create({ id: 'profile_a' });
  await assert.rejects(f.service.write({ sessionId: session.sessionId, data: 'x'.repeat(65537) }), { code: 'TERMINAL_INPUT_LIMIT' });
  await f.service.write({ sessionId: session.sessionId, data: '\x03' }); assert.deepEqual(f.fakes[0].written, ['\x03']);
  await assert.rejects(f.service.resize({ sessionId: session.sessionId, columns: 0, rows: 30 }));
  await f.service.resize({ sessionId: session.sessionId, columns: 120, rows: 40 }); assert.deepEqual(f.fakes[0].lastSize, [120, 40]);
  for (let index = 1; index < 8; index++) { const id = `profile_${index}`; await f.service.setDirectory({ id, path: f.cwd }); await f.service.create({ id }); }
  await f.service.setDirectory({ id: 'profile_overflow', path: f.cwd });
  await assert.rejects(f.service.create({ id: 'profile_overflow' }), { code: 'TERMINAL_LIMIT' });
  await f.service.close({ sessionId: session.sessionId }); await f.service.close({ sessionId: session.sessionId });
  await assert.rejects(f.service.write({ sessionId: session.sessionId, data: 'echo nope\n' }), { code: 'TERMINAL_NOT_RUNNING' });
});

test('slow output consumers keep finite replay and buffers, apply PTY backpressure, and preserve event ordering', async t => {
  let unblock; const slow = new Promise(done => { unblock = done; }); const delivered = [];
  const f = await fixture(t, { onEvent: async event => { if (event.type === 'data') await slow; delivered.push(event); } });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); const session = await f.service.create({ id: 'profile_a' });
  f.fakes[0].output('汉'.repeat(200000));
  const state = (await f.service.snapshot()).profiles[0].sessions[0];
  assert.ok(Buffer.byteLength(state.replay) <= 256 * 1024);
  assert.ok(f.service.sessions.get(session.sessionId).queuedBytes <= 256 * 1024);
  assert.ok(f.fakes[0].pauses > 0);
  assert.ok(state.sequence > 2);
  unblock(); await delay(30);
  const sequences = delivered.map(event => event.sequence);
  assert.deepEqual(sequences, [...sequences].sort((a, b) => a - b));
});

test('unconfirmed timezone never spawns a shell; incomplete cleanup remains closing for mutation guards', async t => {
  const f = await fixture(t, { resolveContext: async id => ({ id, timezone: '', proxy: null }) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  await assert.rejects(f.service.create({ id: 'profile_a' }), { code: 'TERMINAL_TIMEZONE_UNAVAILABLE' });
  assert.equal(f.fakes.length, 0);
  const g = await fixture(t, { processControl: { capture: async pid => ({ pid }), close: async () => ({ ok: false }) } });
  await g.service.setDirectory({ id: 'profile_a', path: g.cwd }); const session = await g.service.create({ id: 'profile_a' });
  await assert.rejects(g.service.close({ sessionId: session.sessionId }), { code: 'TERMINAL_CLEANUP_FAILED' });
  assert.equal((await g.service.snapshot()).profiles[0].sessions[0].status, 'closing');
  await assert.rejects(g.service.setDirectory({ id: 'profile_a', path: g.cwd }), { code: 'TERMINAL_RUNNING' });
});

test('parallel directory persistence retains both profiles and deletion only removes owned configuration', async t => {
  const f = await fixture(t);
  const other = path.join(f.root, 'other'); await mkdir(other);
  await Promise.all([f.service.setDirectory({ id: 'profile_a', path: f.cwd }), f.service.setDirectory({ id: 'profile_b', path: other })]);
  const saved = JSON.parse(await readFile(path.join(f.root, 'data/terminal/workspace.json')));
  assert.deepEqual(saved.profiles.map(profile => profile.id).sort(), ['profile_a', 'profile_b']);
  const session = await f.service.create({ id: 'profile_a' });
  await assert.rejects(f.service.removeProfile({ id: 'profile_a' }), { code: 'TERMINAL_RUNNING' });
  await f.service.close({ sessionId: session.sessionId });
  await writeFile(path.join(f.cwd, 'user-file.txt'), 'untouched');
  await symlink(f.cwd, path.join(f.root, 'data/terminal/profiles/profile_a/home/user-link'), process.platform === 'win32' ? 'junction' : 'dir');
  const removed = await f.service.removeProfile({ id: 'profile_a' });
  assert.equal(removed.configRemoved, true);
  assert.equal(await readFile(path.join(f.cwd, 'user-file.txt'), 'utf8'), 'untouched');
  assert.equal((await f.service.snapshot()).profiles.some(profile => profile.profileId === 'profile_a'), false);
  await assert.rejects(stat(path.join(f.root, 'data/terminal/profiles/profile_a')), { code: 'ENOENT' });
});

test('short proxy credentials are redacted as complete credential-bearing URLs without corrupting ordinary output', async t => {
  const f = await fixture(t, { resolveContext: async id => ({ id, timezone: 'UTC', proxy: { protocol: 'http', host: 'proxy.invalid', port: 8080, username: 'user', password: 'x' } }) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); await f.service.create({ id: 'profile_a' });
  const endpoint = f.fakes[0].options.env.HTTP_PROXY;
  const normal = 'cat data, status, paths\n';
  f.fakes[0].output(normal);
  for (let offset = 0; offset < endpoint.length; offset += 3) f.fakes[0].output(endpoint.slice(offset, offset + 3));
  f.fakes[0].output('\n');
  await delay(10);
  assert.equal(f.events.filter(event => event.type === 'data').map(event => event.data).join(''), normal + '[redacted]\n');
  assert.equal(JSON.stringify(await f.service.snapshot()).includes(endpoint), false);
});

test('a shell exiting during PID capture is never announced running afterward', async t => {
  let release; const gate = new Promise(done => { release = done; });
  const f = await fixture(t, { processControl: { capture: async pid => { await gate; return { pid }; }, close: async () => ({ ok: true }) } });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const creating = f.service.create({ id: 'profile_a' });
  for (let attempt = 0; attempt < 20 && f.fakes.length === 0; attempt++) await delay(5);
  assert.equal(f.fakes.length, 1);
  f.fakes[0].exit(); release();
  const session = await creating;
  assert.notEqual(session.status, 'running');
  await delay(10);
  assert.equal(f.events.some(event => event.type === 'status' && event.status === 'running'), false);
  assert.equal(f.fakes[0].kills ?? 0, 0);
});

test('read-only app data fails explicitly without switching to a shared HOME', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-terminal-readonly-'));
  const dataDir = path.join(root, 'readonly'); await mkdir(dataDir, { mode: 0o500 });
  try {
    const service = new TerminalService({ dataDir, resolveContext: async () => { throw new Error('must not resolve'); } });
    await assert.rejects(service.ready, { code: 'TERMINAL_STORAGE_UNAVAILABLE' });
    await assert.rejects(service.snapshot(), { code: 'TERMINAL_STORAGE_UNAVAILABLE' });
  } finally { await chmod(dataDir, 0o700); await rm(root, { recursive: true, force: true }); }
});

const socksContext = async id => ({ id, timezone: 'UTC', proxy: { protocol: 'socks5', host: '127.0.0.1', port: 12345, username: 'fixture-user', password: 'fixture-password' } });
function recordingPty(launches) {
  return (executable, args, options) => { const pty = new FakePty(options); launches.push({ executable, args, env: options.env, pty }); return pty; };
}

test('a SOCKS bridge route starts only inside the network fence and Node uses the environment proxy', async t => {
  const launches = [], wraps = [];
  const networkFence = { wrap: async (shell, options) => { wraps.push({ shell, options });
    return { executable: '/usr/bin/sandbox-exec', args: ['-p', 'FIXTURE-PROFILE', shell.executable, ...shell.args], environment: shell.environment }; } };
  const f = await fixture(t, { networkFence, resolveContext: socksContext, ptyFactory: recordingPty(launches) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const session = await f.service.create({ id: 'profile_a' });
  assert.equal(session.networkFence, true);
  // What the terminal says about its network is what the fence enforces.
  assert.equal(session.network.fenced, true);
  assert.match(session.network.description, /不会直连/);
  assert.doesNotMatch(session.network.description, /本机地址直连/);
  assert.equal(launches.length, 1);
  const shell = f.service.shell({});
  assert.equal(launches[0].executable, '/usr/bin/sandbox-exec');
  assert.deepEqual(launches[0].args, ['-p', 'FIXTURE-PROFILE', shell.executable, ...shell.args]);
  // The fence admits exactly this session's bridge, the only route it receives.
  const endpoint = new URL(launches[0].env.HTTPS_PROXY);
  assert.equal(endpoint.hostname, '127.0.0.1');
  assert.equal(wraps[0].options.routePort, Number(endpoint.port));
  assert.equal(launches[0].env.NODE_USE_ENV_PROXY, '1');
  const duplicate = await f.service.duplicate({ sessionId: session.sessionId });
  assert.equal(duplicate.networkFence, true);
  assert.equal(launches[1].executable, '/usr/bin/sandbox-exec');
  assert.notEqual(wraps[1].options.routePort, wraps[0].options.routePort);
});

test('a refused network fence never spawns an unfenced terminal and releases its bridge', async t => {
  const launches = [], ports = [];
  const networkFence = { wrap: async (_shell, { routePort }) => { ports.push(routePort);
    throw Object.assign(new Error('系统网络围栏组件不可用，未启动终端。'), { code: 'TERMINAL_NETWORK_FENCE_UNAVAILABLE' }); } };
  const f = await fixture(t, { networkFence, resolveContext: socksContext, ptyFactory: recordingPty(launches) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  await assert.rejects(f.service.create({ id: 'profile_a' }), { code: 'TERMINAL_NETWORK_FENCE_UNAVAILABLE' });
  assert.equal(launches.length, 0);
  assert.equal(ports.length, 1);
  const net = await import('node:net');
  await assert.rejects(new Promise((resolve, reject) => { const socket = net.connect(ports[0], '127.0.0.1', () => { socket.destroy(); resolve(); }); socket.on('error', reject); }), { code: 'ECONNREFUSED' });
  assert.equal((await f.service.snapshot({ id: 'profile_a' })).profiles[0].sessions?.some(item => item.status === 'running') ?? false, false);
});

test('a local-network terminal needs no fence and receives no proxy variables', async t => {
  const launches = [];
  const networkFence = { wrap: async () => { throw new Error('a local-network terminal must not be wrapped'); } };
  const f = await fixture(t, { networkFence, ptyFactory: recordingPty(launches) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  const session = await f.service.create({ id: 'profile_a' });
  assert.equal(session.networkFence, false);
  assert.equal(launches[0].executable, f.service.shell({}).executable);
  for (const key of ['HTTPS_PROXY', 'ALL_PROXY', 'NODE_USE_ENV_PROXY']) assert.equal(launches[0].env[key], undefined);
});

test('the managed core listener is fenced as the only route; a remote HTTP upstream is reported unfenced', async t => {
  const wraps = [];
  const networkFence = { wrap: async (shell, options) => { wraps.push(options); return { executable: '/usr/bin/sandbox-exec', args: ['-p', 'FIXTURE-PROFILE', shell.executable, ...shell.args], environment: shell.environment }; } };
  const managedLaunches = [];
  const managed = await fixture(t, { networkFence, ptyFactory: recordingPty(managedLaunches),
    resolveContext: async id => ({ id, timezone: 'UTC', proxy: { protocol: 'http', host: '127.0.0.1', port: 51234, username: 'runtime-user', password: 'runtime-password' } }) });
  await managed.service.setDirectory({ id: 'profile_a', path: managed.cwd });
  assert.equal((await managed.service.create({ id: 'profile_a' })).networkFence, true);
  assert.deepEqual(wraps, [{ routePort: 51234 }]);
  assert.equal(managedLaunches[0].executable, '/usr/bin/sandbox-exec');
  assert.equal(managedLaunches[0].env.NODE_USE_ENV_PROXY, '1');
  const remoteLaunches = [];
  const remote = await fixture(t, { networkFence, ptyFactory: recordingPty(remoteLaunches),
    resolveContext: async id => ({ id, timezone: 'UTC', proxy: { protocol: 'http', host: 'proxy.example', port: 8080, username: 'remote-user', password: 'remote-password' } }) });
  await remote.service.setDirectory({ id: 'profile_a', path: remote.cwd });
  assert.equal((await remote.service.create({ id: 'profile_a' })).networkFence, false);
  assert.equal(remoteLaunches[0].executable, remote.service.shell({}).executable);
  assert.equal(wraps.length, 1);
});

test('a fresh terminal is a new process in its own folder; the folder becomes the next default and keeps the link browser', async t => {
  const f = await fixture(t, { networkFence: null });
  const { realpath } = await import('node:fs/promises');
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd });
  await f.service.setLinkBrowser({ id: 'profile_a', browserProfileId: 'system' });
  const first = await f.service.create({ id: 'profile_a' });
  const other = path.join(f.root, 'another'); await mkdir(other);
  // Another terminal while the first runs: a separate process, in the picked folder.
  const second = await f.service.create({ id: 'profile_a', fresh: true, directory: other });
  assert.notEqual(second.sessionId, first.sessionId);
  assert.equal(f.fakes.length, 2, 'two shells, not one shared');
  assert.equal(second.cwd, await realpath(other));
  assert.equal(first.cwd, await realpath(f.cwd), 'the running one keeps its folder');
  // Not fresh still means "show me the running one".
  assert.equal((await f.service.create({ id: 'profile_a' })).sessionId, first.sessionId);
  const saved = JSON.parse(await readFile(path.join(f.root, 'data/terminal/workspace.json')));
  assert.deepEqual(saved.profiles[0], { id: 'profile_a', cwd: await realpath(other), browserProfileId: 'system' });
  assert.equal(f.service.linkBrowser('profile_a'), 'system');
  // A folder that is not one is refused before anything starts.
  await assert.rejects(f.service.create({ id: 'profile_a', fresh: true, directory: 'relative/path' }));
  assert.equal(f.fakes.length, 2);
});

test('a typed character that could begin a secret is shown promptly, while a secret split within one burst stays hidden', async t => {
  const f = await fixture(t, { resolveContext: async id => ({ id, timezone: 'UTC', proxy: { protocol: 'http', host: '127.0.0.1', port: 8080, username: 'u', password: 'cp4ss-word' } }) });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); await f.service.create({ id: 'profile_a' });
  const shown = () => f.events.filter(event => event.type === 'data').map(event => event.data).join('');
  // The echo of "curl cip.cc": the last "c" begins the password, so it used to wait for the next key.
  for (const key of 'curl cip.cc') f.fakes[0].output(key);
  await delay(120);
  assert.ok(shown().endsWith('curl cip.cc'), `the whole line is on screen: ${JSON.stringify(shown())}`);
  // The password arriving in pieces within one burst is still masked as a whole.
  f.fakes[0].output('pw='); f.fakes[0].output('cp4'); f.fakes[0].output('ss-'); f.fakes[0].output('word\n');
  await delay(120);
  assert.ok(shown().endsWith('pw=[redacted]\n'), JSON.stringify(shown().slice(-40)));
  assert.equal(shown().includes('cp4ss-word'), false);
});

test('a terminal receives its link channel, and the channel token is masked like a credential', async t => {
  const linkChannel = {
    executableDirectory: async () => path.join(os.tmpdir(), 'envara-link-bin-test'),
    environment: () => ({ ENVARA_LINK_SOCKET: '/private/tmp/envara-link-test.sock', ENVARA_LINK_TOKEN: 'a1b2c3d4'.repeat(8) }),
  };
  const f = await fixture(t, { linkChannel });
  await f.service.setDirectory({ id: 'profile_a', path: f.cwd }); await f.service.create({ id: 'profile_a' });
  const env = f.fakes[0].options.env;
  assert.equal(env.ENVARA_LINK_SOCKET, '/private/tmp/envara-link-test.sock');
  assert.equal(env.ENVARA_LINK_TOKEN, 'a1b2c3d4'.repeat(8), 'without these the open shim can only refuse');
  assert.ok(env.PATH.startsWith(path.join(os.tmpdir(), 'envara-link-bin-test')), 'the shim comes first on PATH');
  assert.equal(env.BROWSER, path.join(os.tmpdir(), 'envara-link-bin-test', 'browser'));
  f.fakes[0].output(`ENVARA_LINK_TOKEN=${'a1b2c3d4'.repeat(8)}\n`);
  await delay(80);
  const shown = f.events.filter(event => event.type === 'data').map(event => event.data).join('');
  assert.equal(shown.includes('a1b2c3d4'.repeat(8)), false);
  assert.match(shown, /ENVARA_LINK_TOKEN=\[redacted\]/);
});
