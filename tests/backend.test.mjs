import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { EnvaraService } from '../electron/service.mjs';
import { EnvaraStore } from '../electron/store.mjs';
import { languages } from '../shared/interface-languages.mjs';

class FakeRuntime {
  constructor({ installed = true, startError = null, startGate = null } = {}) {
    this.installed = installed;
    this.startError = startError;
    this.startGate = startGate;
    this.sessions = new Map();
    this.starts = [];
    this.focused = [];
    this.stopped = [];
    this.installCount = 0;
  }
  isInstalled() { return this.installed; }
  snapshot() { return { installed: this.installed, version: this.installed ? 'test-engine' : null, progress: null }; }
  async install() { this.installCount += 1; this.installed = true; }
  async start(profile, proxy, profileDir, onClose) {
    this.starts.push({ profile, proxy, profileDir });
    if (this.startGate) await this.startGate;
    if (this.startError) throw this.startError;
    this.sessions.set(profile.id, { onClose });
  }
  async stop(profileId) {
    this.stopped.push(profileId);
    const session = this.sessions.get(profileId);
    this.sessions.delete(profileId);
    session?.onClose();
  }
  async focus(profileId) { this.focused.push(profileId); }
  async screenshot() { return null; }
  async getMetrics() { return {}; }
  async closeAll() { await Promise.all([...this.sessions.keys()].map((profileId) => this.stop(profileId))); }
  userClose(profileId, error) {
    const session = this.sessions.get(profileId);
    this.sessions.delete(profileId);
    session?.onClose(error);
  }
}

async function fixture(t, runtime = new FakeRuntime()) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-backend-'));
  const service = new EnvaraService(directory, runtime, { platform: 'darwin', appVersion: '0.1.0' });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { directory, service, runtime };
}

async function create(service, profile = {}) {
  return (await service.call('createProfile', { profile: { name: '环境 A', ...profile } })).profiles.at(-1);
}

test('legacy network location confirmation is bound to an authenticated probe and affects only child launch', async (t) => {
  const { service, runtime } = await fixture(t);
  const network = { ok: true, scope: 'egress', ip: '8.8.8.8', countryCode: 'PH', country: 'Philippines', city: 'Manila', timezone: 'Asia/Manila', geolocation: { latitude: 14.6, longitude: 121, accuracy: 50000 }, checkedAt: new Date().toISOString() };
  service.networkProbe = { async probe(proxy) { assert.equal(proxy.host, 'fixture.proxy.example'); return structuredClone(network); }, close() {} };
  const draft = { name: '确认位置', protocol: 'http', host: 'fixture.proxy.example', port: 8080, username: 'fixture-user', password: 'fixture-secret' };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  assert.ok(preview.locationPreviewToken); assert.equal(preview.locationRecommendation.timezone, 'Asia/Manila');
  assert.equal((await service.store.read()).proxies.length, 0);
  assert.equal(JSON.stringify(preview).includes(draft.password), false);
  await assert.rejects(service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true } } }), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
  const saved = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  const profile = await create(service, { proxyId: saved.id, timezone: 'Asia/Tokyo' });
  const original = JSON.stringify((await service.store.read()).profiles);
  await service.call('startProfile', { id: profile.id });
  assert.equal(runtime.starts[0].profile.timezone, 'Asia/Manila');
  assert.deepEqual(runtime.starts[0].profile.geolocation, network.geolocation);
  assert.equal((await service.store.read()).profiles[0].timezone, 'Asia/Tokyo');
  const launched = await service.store.read();
  assert.equal(launched.profiles[0].id, JSON.parse(original)[0].id);
});

test('legacy confirmed node blocks region changes but preserves manual pin across same-region IP rotation', async (t) => {
  const { service, runtime } = await fixture(t);
  let actual = { ok: true, scope: 'egress', ip: '8.8.8.8', countryCode: 'PH', country: 'Philippines', city: 'Manila', timezone: 'Asia/Manila', geolocation: { latitude: 14.6, longitude: 121, accuracy: 50000 }, checkedAt: new Date().toISOString() };
  service.networkProbe = { async probe() { return structuredClone(actual); }, close() {} };
  const draft = { name: '同节点', protocol: 'http', host: 'fixture.proxy.example', port: 8080 };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const saved = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'manual', confirmed: true, latitude: 14.55, longitude: 121.04, label: 'Chosen pin' } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  const profile = await create(service, { proxyId: saved.id, timezone: 'Asia/Tokyo' });
  const original = structuredClone((await service.store.read()).proxies[0]);
  actual = { ...actual, ip: '1.1.1.1', latitude: 15, longitude: 120 };
  await service.call('startProfile', { id: profile.id });
  assert.equal(runtime.starts[0].profile.timezone, 'Asia/Manila');
  assert.deepEqual(runtime.starts[0].profile.geolocation, { latitude: 14.55, longitude: 121.04, accuracy: 1000 });
  await service.call('stopProfile', { id: profile.id });
  for (const moved of [{ ...actual, timezone: 'Asia/Tokyo' }, { ...actual, countryCode: 'US' }]) {
    actual = moved;
    await assert.rejects(service.call('startProfile', { id: profile.id }), /重新检测并确认/);
    assert.equal(runtime.starts.length, 1, 'no new child process is started after region mismatch');
    assert.deepEqual((await service.store.read()).proxies[0], original);
  }
  const reconfirm = await service.call('previewProxyNetwork', { proxy: original });
  const updated = (await service.call('saveProxy', { proxy: original, locationPreviewToken: reconfirm.locationPreviewToken })).proxies[0];
  assert.equal(updated.location.timezone, actual.timezone); assert.equal(updated.location.countryCode, actual.countryCode);
  await service.call('startProfile', { id: profile.id });
  assert.equal(runtime.starts.length, 2); assert.equal(runtime.starts[1].profile.timezone, actual.timezone);
  assert.deepEqual(runtime.starts[1].profile.geolocation, runtime.starts[0].profile.geolocation);
});

test('all interface languages persist without altering an existing browser environment', async (t) => {
  const { directory, service, runtime } = await fixture(t);
  assert.equal((await service.snapshot()).settings.language, undefined);
  const profile = await create(service, { locale: 'ja-JP', timezone: 'Asia/Tokyo' });
  for (const language of languages) {
    await service.saveSettings({ settings: { closeBrowsersOnExit: true, language } });
    const snapshot = await service.snapshot();
    assert.equal(snapshot.settings.language, language);
    const unchanged = snapshot.profiles.find(row => row.id === profile.id);
    assert.equal(unchanged.locale, 'ja-JP'); assert.equal(unchanged.timezone, 'Asia/Tokyo');
  }
  const restarted = new EnvaraService(directory, runtime, { platform: 'darwin' });
  await restarted.ready;
  assert.equal((await restarted.snapshot()).settings.language, languages.at(-1));
  await restarted.shutdown();
  for (const language of ['en-US', 'ar', '__proto__', '', {}, ['en']]) {
    await assert.rejects(service.saveSettings({ settings: { closeBrowsersOnExit: true, language } }), { code: 'VALIDATION_ERROR' });
  }
  assert.equal((await service.snapshot()).settings.language, languages.at(-1));
});

test('empty first run persists defaults with private permissions and survives restart', async (t) => {
  const { directory, service, runtime } = await fixture(t);
  const first = await service.snapshot();
  assert.deepEqual(first.profiles, []);
  assert.deepEqual(first.proxies, []);
  assert.deepEqual(first.events, []);
  assert.equal(first.settings.closeBrowsersOnExit, true);
  // Windows reports synthesized POSIX mode bits for NTFS; Unix honors 0600.
  if (process.platform !== 'win32') assert.equal((await stat(path.join(directory, 'workspace.json'))).mode & 0o777, 0o600);
  const created = await create(service, { group: '工作', notes: '持久化', width: 1600 });
  assert.equal(created.platform, 'macos');
  assert.equal(created.status, 'stopped');
  assert.equal(created.dataBytes, 0);
  assert.equal(created.cpuPercent, null);
  assert.equal(created.memoryBytes, null);
  const restarted = new EnvaraService(directory, runtime, { platform: 'darwin', appVersion: '0.1.0' });
  const restored = await restarted.snapshot();
  assert.deepEqual(restored.profiles, [created]);
  assert.equal(restored.events[0].type, 'profile');
});

test('concurrent transactions persist every profile and snapshots cannot mutate storage', async (t) => {
  const { service, directory } = await fixture(t);
  await Promise.all(Array.from({ length: 12 }, (_, index) => service.call('createProfile', { profile: { name: `环境 ${index}` } })));
  const snapshot = await service.snapshot();
  assert.equal(snapshot.profiles.length, 12);
  assert.equal(new Set(snapshot.profiles.map((profile) => profile.id)).size, 12);
  snapshot.profiles[0].name = '外部修改';
  assert.notEqual((await service.snapshot()).profiles[0].name, '外部修改');
  assert.equal(JSON.parse(await readFile(path.join(directory, 'workspace.json'), 'utf8')).profiles.length, 12);
});

test('rejects invalid paths, URLs, timezone, locale, dimensions, seeds and hidden fields', async (t) => {
  const { service } = await fixture(t);
  for (const patch of [
    { startUrl: 'file:///etc/passwd' }, { startUrl: 'javascript:alert(1)' },
    { startUrl: 'https://user:secret@example.com' }, { timezone: '../../etc' },
    { locale: 'not_a_locale' }, { width: 799 }, { height: 599 },
    { seed: 0 }, { seed: 1.5 }, { id: '../../etc' }, { password: 'secret' },
    { proxyId: '00000000-0000-4000-8000-000000000000' },
  ]) {
    await assert.rejects(service.call('createProfile', { profile: { name: '无效', ...patch } }), { code: 'VALIDATION_ERROR' });
  }
  await assert.rejects(service.call('deleteProfile', { id: '../../outside' }), { code: 'VALIDATION_ERROR' });
  await assert.rejects(service.call('constructor'), { code: 'UNKNOWN_METHOD' });
  assert.equal((await service.snapshot()).profiles.length, 0);
});

test('clone generates a new identity and seed with no browser-data copy; seed cannot change on edit', async (t) => {
  const { service, directory } = await fixture(t);
  const original = await create(service, { seed: 12345 });
  const browserDir = path.join(directory, 'profiles', original.id);
  await mkdir(browserDir, { recursive: true });
  await writeFile(path.join(browserDir, 'cookies.test'), 'cookie-content');
  const cloned = (await service.call('cloneProfile', { id: original.id })).profiles.at(-1);
  assert.notEqual(cloned.id, original.id);
  assert.notEqual(cloned.seed, original.seed);
  assert.equal(cloned.dataBytes, 0);
  assert.equal(cloned.lastLaunchedAt, null);
  await assert.rejects(service.call('updateProfile', { id: original.id, profile: { seed: 23456 } }), { code: 'VALIDATION_ERROR' });
  const updated = (await service.call('updateProfile', { id: original.id, profile: { name: '已修改', seed: 12345 } })).profiles[0];
  assert.equal(updated.name, '已修改');
  assert.equal(updated.seed, original.seed);
  assert.equal(updated.dataBytes, Buffer.byteLength('cookie-content'));
});

test('start persists launch time, focus reuses session, user close restores stopped state', async (t) => {
  const { service, runtime, directory } = await fixture(t);
  const profile = await create(service);
  const started = (await service.call('startProfile', { id: profile.id })).profiles[0];
  assert.equal(started.status, 'running');
  assert.ok(started.lastLaunchedAt);
  assert.equal(runtime.starts.length, 1);
  assert.equal(runtime.starts[0].profile.seed, profile.seed);
  assert.equal(runtime.starts[0].profileDir, path.join(directory, 'profiles', profile.id));
  await service.call('startProfile', { id: profile.id });
  assert.equal(runtime.starts.length, 1);
  assert.deepEqual(runtime.focused, [profile.id]);
  runtime.userClose(profile.id);
  assert.equal((await service.snapshot()).profiles[0].status, 'stopped');
  assert.equal((await service.snapshot()).profiles[0].lastError, null);
  await service.call('startProfile', { id: profile.id });
  await service.call('stopProfile', { id: profile.id });
  assert.equal((await service.snapshot()).profiles[0].status, 'stopped');
});

test('running and starting profiles reject edit/delete/clear and a duplicate launch', async (t) => {
  let release;
  const runtime = new FakeRuntime({ startGate: new Promise((resolve) => { release = resolve; }) });
  const { service } = await fixture(t, runtime);
  const profile = await create(service);
  const starting = service.call('startProfile', { id: profile.id });
  // Let the serialized reservation and filesystem preparation complete.
  while (runtime.starts.length === 0) await new Promise((resolve) => setImmediate(resolve));
  assert.equal((await service.snapshot()).profiles[0].status, 'starting');
  for (const method of ['updateProfile', 'deleteProfile', 'clearProfile']) {
    await assert.rejects(service.call(method, { id: profile.id, profile: { name: '修改' } }), { code: 'PROFILE_RUNNING' });
  }
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'PROFILE_STARTING' });
  await assert.rejects(service.call('stopProfile', { id: profile.id }), { code: 'PROFILE_STARTING' });
  release();
  await starting;
  for (const method of ['updateProfile', 'deleteProfile', 'clearProfile']) {
    await assert.rejects(service.call(method, { id: profile.id, profile: { name: '修改' } }), { code: 'PROFILE_RUNNING' });
  }
});

test('simultaneous launch requests create only one session and serialize against deletion', async (t) => {
  const { service, runtime } = await fixture(t);
  const profile = await create(service);
  const launches = await Promise.allSettled([
    service.call('startProfile', { id: profile.id }),
    service.call('startProfile', { id: profile.id }),
  ]);
  assert.equal(runtime.starts.length, 1);
  assert.ok(launches.some((result) => result.status === 'fulfilled'));
  for (const result of launches.filter((result) => result.status === 'rejected')) assert.equal(result.reason.code, 'PROFILE_STARTING');
  await service.call('stopProfile', { id: profile.id });
  const race = await Promise.allSettled([
    service.call('startProfile', { id: profile.id }),
    service.call('deleteProfile', { id: profile.id }),
  ]);
  const snapshot = await service.snapshot();
  assert.ok(race.some((result) => result.status === 'fulfilled'));
  if (runtime.sessions.has(profile.id)) assert.ok(snapshot.profiles.some((saved) => saved.id === profile.id && saved.status === 'running'));
  else assert.equal(snapshot.profiles.some((saved) => saved.id === profile.id), false);
});

test('launch failure reports a real error without persisting running state', async (t) => {
  const { service, directory } = await fixture(t, new FakeRuntime({ startError: new Error('binary missing') }));
  const profile = await create(service);
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'BROWSER_START_FAILED', message: 'binary missing' });
  const snapshot = await service.snapshot();
  assert.equal(snapshot.profiles[0].status, 'error');
  assert.equal(snapshot.profiles[0].lastError, 'binary missing');
  assert.equal(snapshot.profiles[0].lastLaunchedAt, null);
  const saved = JSON.parse(await readFile(path.join(directory, 'workspace.json'), 'utf8'));
  assert.equal(saved.profiles[0].status, undefined);
  assert.equal(saved.events[0].type, 'error');
});

test('explicit engine installation unlocks launch and unknown telemetry remains null', async (t) => {
  const { service, runtime } = await fixture(t, new FakeRuntime({ installed: false }));
  const profile = await create(service);
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'ENGINE_NOT_INSTALLED' });
  assert.equal(runtime.starts.length, 0);
  const installed = await service.call('installEngine');
  assert.equal(runtime.installCount, 1);
  assert.equal(installed.engine.installed, true);
  assert.equal(installed.engine.installing, false);
  await service.call('startProfile', { id: profile.id });
  assert.equal((await service.snapshot()).profiles[0].memoryBytes, null);
});

test('proxy credentials persist locally, active edits are blocked, export removes proxy references', async (t) => {
  const { service, directory, runtime } = await fixture(t);
  const proxy = (await service.call('saveProxy', { proxy: { name: '本地代理', protocol: 'http', host: '127.0.0.1', port: '8080', username: 'alice', password: 'sensitive' } })).proxies[0];
  assert.equal(proxy.port, 8080);
  const profile = await create(service, { proxyId: proxy.id });
  await service.call('startProfile', { id: profile.id });
  assert.equal(runtime.starts[0].proxy.password, 'sensitive');
  await assert.rejects(service.call('saveProxy', { proxy: { ...proxy, host: 'other.example' } }), { code: 'PROFILE_RUNNING' });
  await assert.rejects(service.call('deleteProxy', { id: proxy.id }), { code: 'PROXY_IN_USE' });
  const exported = await service.call('exportProfiles');
  assert.equal(exported.schema, 'envara.profiles');
  assert.equal(exported.profiles[0].proxyId, null);
  assert.equal(JSON.stringify(exported).includes('sensitive'), false);
  assert.equal(JSON.stringify(exported).includes('alice'), false);
  assert.equal(exported.profiles[0].status, undefined);
  assert.equal(JSON.parse(await readFile(path.join(directory, 'workspace.json'), 'utf8')).proxies[0].password, 'sensitive');
  await service.call('stopProfile', { id: profile.id });
  await service.call('updateProfile', { id: profile.id, profile: { proxyId: null } });
  assert.equal((await service.call('deleteProxy', { id: proxy.id })).proxies.length, 0);
});

test('import is atomic, rejects secret fields, regenerates IDs, preserves valid seeds', async (t) => {
  const { service, directory } = await fixture(t);
  const original = await create(service, { seed: 12345 });
  const exported = await service.call('exportProfiles', { id: original.id });
  const before = await readFile(path.join(directory, 'workspace.json'), 'utf8');
  await assert.rejects(service.call('importProfiles', { profiles: [exported.profiles[0], { name: '坏配置', timezone: 'bad-timezone' }] }), { code: 'VALIDATION_ERROR' });
  assert.equal(await readFile(path.join(directory, 'workspace.json'), 'utf8'), before);
  await assert.rejects(service.call('importProfiles', { profiles: [{ ...exported.profiles[0], password: 'secret' }] }), { code: 'VALIDATION_ERROR' });
  const imported = (await service.call('importProfiles', { profiles: exported.profiles })).profiles.at(-1);
  assert.notEqual(imported.id, original.id);
  assert.equal(imported.seed, original.seed);
  assert.equal(imported.proxyId, null);
  assert.equal(imported.dataBytes, 0);
});

test('clear only removes the selected UUID directory; delete removes persistent record', async (t) => {
  const { service, directory } = await fixture(t);
  const first = await create(service, { name: '第一个' });
  const second = await create(service, { name: '第二个' });
  for (const profile of [first, second]) {
    await mkdir(path.join(directory, 'profiles', profile.id), { recursive: true });
    await writeFile(path.join(directory, 'profiles', profile.id, 'cookie.test'), 'test');
  }
  const cleared = await service.call('clearProfile', { id: first.id });
  assert.equal(cleared.profiles.find((profile) => profile.id === first.id).dataBytes, 0);
  assert.equal(cleared.profiles.find((profile) => profile.id === second.id).dataBytes, 4);
  const deleted = await service.call('deleteProfile', { id: first.id });
  assert.deepEqual(deleted.profiles.map((profile) => profile.id), [second.id]);
  assert.equal(await readFile(path.join(directory, 'profiles', second.id, 'cookie.test'), 'utf8'), 'test');
});

test('proxy check reports TCP reachability and never claims authentication or an exit IP', async (t) => {
  const { service } = await fixture(t);
  const server = net.createServer((socket) => socket.end());
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const proxy = (await service.call('saveProxy', { proxy: { name: 'TCP fixture', protocol: 'socks5', host: '127.0.0.1', port: server.address().port } })).proxies[0];
  const result = await service.call('checkProxy', { id: proxy.id });
  assert.equal(result.ok, true);
  assert.equal(result.scope, 'tcp');
  assert.ok(Number.isFinite(result.latencyMs));
  assert.match(result.message, /尚未验证/);
  assert.equal(result.exitIp, undefined);
});

test('shutdown waits for pending launch, closes contexts, and rejects subsequent operations', async (t) => {
  let release;
  const runtime = new FakeRuntime({ startGate: new Promise((resolve) => { release = resolve; }) });
  const { service } = await fixture(t, runtime);
  const profile = await create(service);
  const launch = service.call('startProfile', { id: profile.id });
  while (runtime.starts.length === 0) await new Promise((resolve) => setImmediate(resolve));
  const shutdown = service.shutdown();
  release();
  await launch;
  await shutdown;
  assert.equal(runtime.sessions.size, 0);
  await assert.rejects(service.call('createProfile', { profile: { name: '退出后' } }), { code: 'APP_CLOSING' });
  await assert.rejects(service.saveSettings({ settings: { closeBrowsersOnExit: false } }), { code: 'VALIDATION_ERROR' });
});

test('a corrupt store is preserved instead of silently resetting user data', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-corrupt-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const invalid = 'SYNTHETIC_PRIVATE_WORKSPACE_TOKEN';
  await writeFile(path.join(directory, 'workspace.json'), invalid);
  const store = new EnvaraStore(directory);
  await assert.rejects(store.ready, error => {
    assert.match(error.message, /原文件已保留/);
    assert.equal(error.message.includes('SYNTHETIC'), false, 'parser snippets may contain private proxy or account data');
    assert.equal(error.cause, undefined, 'startup diagnostics must not retain the raw parse error either');
    return true;
  });
  assert.equal(await readFile(path.join(directory, 'workspace.json'), 'utf8'), invalid);
});
