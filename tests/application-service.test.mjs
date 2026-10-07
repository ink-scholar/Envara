import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { ApplicationService, inspectLocalApplication } from '../electron/application-service.mjs';
import { APPLICATION_ROUTING_CHECKS } from '../electron/application-routing.mjs';

const capabilities = () => Object.fromEntries(APPLICATION_ROUTING_CHECKS.map(key => [key, true]));
const verified = () => ({ passed: true, version: 'fixture-only/1', checks: capabilities() });
/** Test-only adapter controls a genuine, non-networking child; it proves lifecycle, not routing. */
class TestRouting {
  constructor() { this.state = { installed: true, authorized: true, ready: true, capabilities: capabilities(), verification: verified() }; this.children = new Map(); this.routes = new Map(); this.calls = []; }
  async status() { return { ...this.state, sessions: [...this.children].map(([sessionId, item]) => ({ sessionId, pid: item.child.pid, status: item.exited ? 'exited' : 'running', exitCode: item.exitCode })) }; }
  async setup() { return this.status(); }
  async prepareRoute(params) { this.calls.push(['prepareRoute', params]); const routeId = `route_${this.routes.size}`; this.routes.set(routeId, params); return { routeId, ready: true, failClosed: true, capabilities: capabilities(), verification: verified() }; }
  async launch(params) {
    this.calls.push(['launch', params]);
    const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { cwd: params.cwd, env: params.env, stdio: 'ignore', shell: false });
    await once(child, 'spawn');
    const sessionId = `session_${this.children.size}`, item = { child, routeId: params.routeId, exited: false };
    this.children.set(sessionId, item); child.once('exit', code => { item.exited = true; item.exitCode = code; });
    return { sessionId, pid: child.pid, startedAt: new Date().toISOString() };
  }
  async stop(params) {
    this.calls.push(['stop', params]);
    for (const [sessionId, item] of this.children) {
      if (sessionId !== params.sessionId && item.routeId !== params.routeId) continue;
      if (!item.exited) { const exit = once(item.child, 'exit'); item.child.kill(); await exit; }
    }
    return { stopped: true };
  }
  async revoke({ routeId }) { this.calls.push(['revoke', { routeId }]); this.routes.delete(routeId); return { revoked: true }; }
  async shutdown() { for (const [sessionId] of this.children) await this.stop({ sessionId }); }
}
async function fixture(t, options = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-application-test-')));
  const cwd = path.join(root, 'selected'); await mkdir(cwd);
  const routing = options.routing ?? new TestRouting();
  const context = { profileId: 'profile_a', profileName: 'Test', cwd, timezone: 'Asia/Manila', timezoneSource: 'proxy', locale: 'en-PH',
    network: { ok: true, ip: '203.0.113.8', country: 'PH' }, geolocation: { latitude: 14.6, longitude: 121, accuracy: 50000 },
    proxyId: 'node_a', proxyEndpoint: { protocol: 'socks5', host: '127.0.0.1', port: 24567, username: 'runtime-user', password: 'runtime-secret', udp: true },
    environment: { HOME: path.join(root, 'private-home'), CLAUDE_CONFIG_DIR: path.join(root, 'private-claude'), HTTP_PROXY: 'forbidden-secret', ANTHROPIC_API_KEY: 'forbidden-key' } };
  let resolutions = 0;
  const service = new ApplicationService({ dataDir: path.join(root, 'data'), platform: process.platform, routing, pollIntervalMs: 0,
    profileExists: async id => ['profile_a', 'profile_b'].includes(id),
    resolveContext: async id => { resolutions++; return { ...context, profileId: id }; }, ...options });
  await service.ready;
  t.after(async () => { await service.shutdown().catch(() => {}); await routing.shutdown?.(); await rm(root, { recursive: true, force: true }); });
  return { root, cwd, routing, context, service, resolutions: () => resolutions };
}
async function add(f, profileId = 'profile_a', extra = {}) {
  const result = await f.service.saveApplication({ application: { profileId, path: process.execPath, ...extra } }); return result.applications.at(-1);
}

test('bindings persist only explicit app fields; saving does not resolve a node or launch a process', async t => {
  const f = await fixture(t), item = await add(f);
  assert.equal(item.status, 'stopped'); assert.equal(f.resolutions(), 0); assert.equal(f.routing.calls.length, 0);
  const file = path.join(f.root, 'data/applications/applications.json'), source = await readFile(file, 'utf8');
  assert.equal(source.includes('runtime-secret'), false);
  assert.deepEqual(Object.keys(JSON.parse(source).applications[0]).sort(), ['args', 'executablePath', 'id', 'identity', 'name', 'path', 'profileId']);
  if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o600);
  const reloaded = new ApplicationService({ dataDir: path.join(f.root, 'data'), resolveContext: async () => null, routing: new TestRouting(), pollIntervalMs: 0 });
  t.after(() => reloaded.shutdown()); await reloaded.ready;
  assert.equal((await reloaded.snapshot()).applications[0].id, item.id);
});

test('one software identity binds one environment and concurrent saves cannot bypass the constraint', async t => {
  const f = await fixture(t);
  const results = await Promise.allSettled([add(f, 'profile_a'), add(f, 'profile_b')]);
  assert.equal(results.filter(item => item.status === 'fulfilled').length, 1);
  assert.equal(results.find(item => item.status === 'rejected').reason.code, 'APPLICATION_ALREADY_BOUND');
  assert.equal((await f.service.snapshot()).applications.length, 1);
});

test('missing installation, authorization, each network capability or actual verification prevents every launch', async t => {
  const f = await fixture(t), item = await add(f);
  const variants = [ { installed: false }, { authorized: false }, { ready: false }, ...APPLICATION_ROUTING_CHECKS.map(key => ({ capabilities: { ...capabilities(), [key]: false } })),
    { verification: { ...verified(), passed: false } }, ...APPLICATION_ROUTING_CHECKS.map(key => ({ verification: { ...verified(), checks: { ...capabilities(), [key]: false } } })) ];
  for (const change of variants) {
    f.routing.state = { installed: true, authorized: true, ready: true, capabilities: capabilities(), verification: verified(), ...change };
    await assert.rejects(f.service.startApplication({ id: item.id }));
  }
  assert.equal(f.routing.calls.length, 0); assert.equal(f.routing.children.size, 0); assert.equal(f.resolutions(), 0);
});

test('genuine owned child uses the shared context and literal args; no secrets appear in metadata or child environment', async t => {
  const f = await fixture(t), args = ['$(touch do-not-create)', '; echo do-not-execute', '--literal=value'];
  const item = await add(f, 'profile_a', { args });
  const result = await f.service.startApplication({ id: item.id }), live = result.applications[0];
  assert.equal(live.status, 'running'); assert.ok(live.pid > 0); assert.equal(live.timezone, 'Asia/Manila'); assert.equal(live.geolocation.latitude, 14.6);
  assert.equal(f.service.hasActiveProfile('profile_a'), true); assert.equal(f.service.hasActiveProxy('node_a'), true);
  assert.throws(() => f.service.assertProfileIdle('profile_a'), { code: 'APPLICATION_RUNNING' });
  await assert.rejects(f.service.deleteApplication({ id: item.id }), { code: 'APPLICATION_RUNNING' });
  await assert.rejects(f.service.saveApplication({ application: { ...item, name: 'Changed' } }), { code: 'APPLICATION_RUNNING' });
  const launch = f.routing.calls.find(([method]) => method === 'launch')[1];
  assert.deepEqual(launch.args, args); assert.equal(launch.cwd, f.cwd); assert.equal(launch.env.TZ, f.context.timezone);
  assert.equal(launch.env.HOME, f.context.environment.HOME); assert.equal(launch.env.CLAUDE_CONFIG_DIR, f.context.environment.CLAUDE_CONFIG_DIR);
  assert.equal(launch.env.HTTP_PROXY, undefined); assert.equal(launch.env.ANTHROPIC_API_KEY, undefined);
  assert.equal(JSON.stringify(result).includes('runtime-secret'), false); assert.equal(JSON.stringify(result).includes('runtime-user'), false);
  assert.equal((await f.service.startApplication({ id: item.id })).applications[0].pid, live.pid, 'Repeated start never creates a second instance');
  assert.equal(f.routing.children.size, 1);
  await f.service.stopApplication({ id: item.id });
  assert.equal(f.routing.children.get(live.sessionId).exited, true); assert.equal(f.routing.routes.size, 0); assert.equal(f.service.hasActiveProfile('profile_a'), false);
  await f.service.deleteApplication({ id: item.id }); assert.equal((await f.service.snapshot()).applications.length, 0);
});

test('unverified exit, bad node, missing egress, profile removal, and unknown work directory reject before native launch', async t => {
  const f = await fixture(t), item = await add(f);
  const valid = structuredClone(f.context);
  for (const change of [{ proxyEndpoint: null }, { proxyEndpoint: { ...valid.proxyEndpoint, protocol: 'http' } }, { network: { ok: false, ip: valid.network.ip } }, { network: {} }, { timezone: 'Local' }, { cwd: '' }]) {
    Object.assign(f.context, valid, change); await assert.rejects(f.service.startApplication({ id: item.id }));
  }
  assert.equal(f.routing.calls.length, 0);
  f.service.profileExists = async () => false;
  await assert.rejects(f.service.startApplication({ id: item.id }), { code: 'APPLICATION_PROFILE_NOT_FOUND' });
});

test('UDP is explicitly blocked when the chosen node has no confirmed datagram support', async t => {
  const f = await fixture(t); f.context.proxyEndpoint.udp = false;
  const item = await add(f); const result = await f.service.startApplication({ id: item.id });
  assert.equal(result.applications[0].udpPolicy, 'block');
  assert.equal(f.routing.calls.find(([method]) => method === 'prepareRoute')[1].route.udpPolicy, 'block');
});

test('ambiguous native launch failure is reclaimed by route, and failed cleanup retains blocking ownership', async t => {
  const f = await fixture(t), item = await add(f);
  f.routing.launch = async () => { throw Object.assign(new Error('runtime-secret must not escape'), { code: 'APPLICATION_ROUTING_TIMEOUT' }); };
  await assert.rejects(f.service.startApplication({ id: item.id }), { code: 'APPLICATION_ROUTING_TIMEOUT' });
  assert.deepEqual(f.routing.calls.find(([method]) => method === 'stop')[1], { routeId: 'route_0' });
  assert.equal(f.routing.routes.size, 0); assert.equal(JSON.stringify(await f.service.snapshot()).includes('runtime-secret'), false);
  f.routing.stop = async () => ({ stopped: false });
  await assert.rejects(f.service.startApplication({ id: item.id }), { code: 'APPLICATION_CLEANUP_FAILED' });
  assert.equal(f.routing.routes.size, 1); assert.equal(f.service.hasActiveProfile('profile_a'), true);
  await assert.rejects(f.service.deleteApplication({ id: item.id }), { code: 'APPLICATION_RUNNING' });
  f.routing.stop = TestRouting.prototype.stop.bind(f.routing);
  await f.service.stopApplication({ id: item.id }); assert.equal(f.routing.routes.size, 0);
});

test('external process exit and loss of verified network component are reconciled without touching unrelated children', async t => {
  const f = await fixture(t), item = await add(f); let result = await f.service.startApplication({ id: item.id });
  const first = f.routing.children.get(result.applications[0].sessionId); const exit = once(first.child, 'exit'); first.child.kill(); await exit;
  await f.service.poll(); assert.equal((await f.service.snapshot()).applications[0].status, 'stopped'); assert.equal(f.routing.routes.size, 0);
  result = await f.service.startApplication({ id: item.id }); const second = f.routing.children.get(result.applications[0].sessionId);
  f.routing.state.ready = false; await f.service.poll();
  assert.equal(second.exited, true); assert.equal((await f.service.snapshot()).applications[0].status, 'error'); assert.equal(f.routing.routes.size, 0);
});

test('an explicitly missing native session loses running status and cleans its owned process and route', async t => {
  const f = await fixture(t), item = await add(f);
  const live = (await f.service.startApplication({ id: item.id })).applications[0];
  const child = f.routing.children.get(live.sessionId);
  f.routing.status = async () => ({ ...f.routing.state, sessions: [] });

  await f.service.poll();

  const result = (await f.service.snapshot()).applications[0];
  assert.equal(result.status, 'error'); assert.equal(result.lastError.code, 'APPLICATION_ROUTING_SESSION_MISSING');
  assert.match(result.lastError.message, /无法确认/);
  assert.equal(result.sessionId, null); assert.equal(result.pid, null);
  assert.equal(child.exited, true); assert.equal(f.routing.routes.size, 0);
  assert.deepEqual(f.routing.calls.find(([method]) => method === 'stop')[1], { sessionId: live.sessionId });
  assert.deepEqual(f.routing.calls.find(([method]) => method === 'revoke')[1], { routeId: 'route_0' });
  assert.equal(f.service.hasActiveProfile('profile_a'), false); assert.equal(f.service.hasActiveProxy('node_a'), false);
});

test('cleanup failures for a missing native session retain ownership until an explicit stop succeeds', async t => {
  const f = await fixture(t), item = await add(f);
  const live = (await f.service.startApplication({ id: item.id })).applications[0];
  const child = f.routing.children.get(live.sessionId);
  f.routing.status = async () => ({ ...f.routing.state, sessions: [] });
  f.routing.stop = async params => { f.routing.calls.push(['stop', params]); return { stopped: false }; };

  await f.service.poll();

  let result = (await f.service.snapshot()).applications[0];
  assert.equal(result.status, 'error'); assert.equal(result.lastError.code, 'APPLICATION_CLEANUP_FAILED');
  assert.match(result.lastError.message, /无法确认/);
  assert.equal(result.sessionId, live.sessionId); assert.equal(child.exited, false);
  assert.equal(f.service.sessions.get(item.id).routeId, 'route_0'); assert.equal(f.routing.routes.size, 1);
  assert.equal(f.service.hasActiveProfile('profile_a'), true); assert.equal(f.service.hasActiveProxy('node_a'), true);
  await assert.rejects(f.service.deleteApplication({ id: item.id }), { code: 'APPLICATION_RUNNING' });

  f.routing.stop = TestRouting.prototype.stop.bind(f.routing);
  f.routing.revoke = async () => ({ revoked: false });
  await assert.rejects(f.service.stopApplication({ id: item.id }), { code: 'APPLICATION_CLEANUP_FAILED' });
  result = (await f.service.snapshot()).applications[0];
  assert.equal(result.sessionId, null); assert.equal(result.pid, null); assert.equal(child.exited, true);
  assert.equal(f.service.sessions.get(item.id).routeId, 'route_0'); assert.equal(f.service.hasActiveProfile('profile_a'), true);
  assert.equal(f.service.hasActiveProxy('node_a'), true);

  f.routing.revoke = TestRouting.prototype.revoke.bind(f.routing);
  await f.service.stopApplication({ id: item.id });
  assert.equal((await f.service.snapshot()).applications[0].status, 'stopped'); assert.equal(f.routing.routes.size, 0);
  assert.equal(f.service.hasActiveProfile('profile_a'), false); assert.equal(f.service.hasActiveProxy('node_a'), false);
});

test('local application inspection accepts complete bundles and rejects escaped executables, bad inputs and directories', async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-app-inspect-'))); t.after(() => rm(root, { recursive: true, force: true }));
  const bundle = path.join(root, 'Fixture.app'); await mkdir(path.join(bundle, 'Contents/MacOS'), { recursive: true });
  await writeFile(path.join(bundle, 'Contents/Info.plist'), '<plist><dict><key>CFBundleIdentifier</key><string>io.envara.fixture</string><key>CFBundleExecutable</key><string>fixture</string></dict></plist>');
  const executable = path.join(bundle, 'Contents/MacOS/fixture'); await writeFile(executable, '#!/bin/sh\nexit 0\n'); await chmod(executable, 0o700);
  const info = await inspectLocalApplication(bundle, { platform: 'darwin' }); assert.equal(info.identity, 'bundle:io.envara.fixture'); assert.equal(info.executablePath, executable);
  await rm(executable); await symlink(process.execPath, executable);
  await assert.rejects(inspectLocalApplication(bundle, { platform: 'darwin' }), { code: 'APPLICATION_INVALID_PATH' });
  for (const value of ['node', '$(touch /tmp/nope)', `${root}\0bad`, root]) await assert.rejects(inspectLocalApplication(value), { code: 'APPLICATION_INVALID_PATH' });
  await assert.rejects(inspectLocalApplication(process.execPath, { platform: 'win32' }), { code: 'APPLICATION_INVALID_PATH' });
});

test('configuration symlinks are never followed or replaced', async t => {
  const f = await fixture(t), target = path.join(f.root, 'unrelated.json'), filename = path.join(f.root, 'data/applications/applications.json');
  await writeFile(target, 'protected'); await symlink(target, filename);
  await assert.rejects(add(f), { code: 'APPLICATION_STORAGE_UNAVAILABLE' }); assert.equal(await readFile(target, 'utf8'), 'protected');
});
