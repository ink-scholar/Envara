import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';

const descriptors = [
  { id: 'cloakbrowser', display_name: 'CloakBrowser', family: 'chromium', enabled: true, platform_supported: true, capabilities: { supports_seed_fingerprint: true, supports_structured_config: false } },
  { id: 'camoufox', display_name: 'Camoufox', family: 'firefox', enabled: true, platform_supported: true, capabilities: { supports_seed_fingerprint: false, supports_structured_config: true } },
  { id: 'browseforge-chromium', display_name: 'BrowseForge Chromium', family: 'chromium', enabled: true, platform_supported: true, capabilities: { supports_seed_fingerprint: true, supports_structured_config: true } },
];

class FakeClient {
  constructor(profilesDir) { this.profilesDir = profilesDir; this.profiles = []; this.sessions = []; this.groups = []; this.descriptors = structuredClone(descriptors); this.requests = []; this.failCreateAt = 0; this.createCount = 0; this.closedSessions = new Set(); this.healthFailure = null; this.startGates = new Map(); }
  async request(method, route, body, options) {
    this.requests.push({ method, route, body: structuredClone(body), options });
    if (route === '/api/profiles' && method === 'GET') return { data: this.profiles.length ? structuredClone(this.profiles) : null, total: this.profiles.length };
    if (route === '/api/sessions' && method === 'GET') return { data: structuredClone(this.sessions), total: this.sessions.length };
    if (route === '/api/runtimes') return { data: structuredClone(this.descriptors), default_runtime_id: 'cloakbrowser' };
    if (route === '/api/groups' && method === 'GET') return { data: structuredClone(this.groups) };
    if (route === '/api/profiles' && method === 'POST') {
      this.createCount += 1;
      if (this.createCount === this.failCreateAt) throw new Error('fixture create failed');
      const id = `prof_${String(this.createCount).padStart(12, '0')}`;
      const profile = { ...structuredClone(body), id, created_at: new Date().toISOString(), last_used: new Date().toISOString(), profile_dir: path.join(this.profilesDir, id) };
      this.profiles.push(profile);
      await mkdir(path.join(profile.profile_dir, 'browser-data'), { recursive: true });
      return { data: structuredClone(profile) };
    }
    const profile = route.match(/^\/api\/profiles\/([A-Za-z0-9_-]+)$/);
    if (profile && method === 'PUT') { const existing = this.profiles.find((item) => item.id === profile[1]); assert.ok(existing); Object.assign(existing, structuredClone(body)); return { data: structuredClone(existing) }; }
    if (profile && method === 'DELETE') { const existing = this.profiles.find((item) => item.id === profile[1]); if (existing) await rm(existing.profile_dir, { recursive: true, force: true }); this.profiles = this.profiles.filter((item) => item.id !== profile[1]); return { data: 'deleted' }; }
    if (route === '/api/sessions' && method === 'POST') { if (this.startGates.has(body.profile_id)) await this.startGates.get(body.profile_id); const session = { session_id: `sess_${body.profile_id}`, profile_id: body.profile_id, runtime_id: this.profiles.find((item) => item.id === body.profile_id).runtime_id }; this.closedSessions.delete(session.session_id); this.sessions = this.sessions.filter((item) => item.profile_id !== body.profile_id); this.sessions.push(session); return { data: session }; }
    const session = route.match(/^\/api\/sessions\/([A-Za-z0-9_-]+)(?:\/(.+))?$/);
    if (session?.[2] === 'eval') { if (this.healthFailure) throw new Error(this.healthFailure); if (this.closedSessions.has(session[1])) throw new Error('Target page, context or browser has been closed'); return { data: { url: 'about:blank', language: 'en-US', timezone: 'America/Los_Angeles', width: 1440, height: 900, platform: 'MacIntel' } }; }
    if (session?.[2] === 'screenshot') { if (this.screenshotGate) await this.screenshotGate; if (this.screenshotFailure) throw new Error('fixture screenshot failed'); this.screenshotNumber = (this.screenshotNumber ?? 0) + 1; return Buffer.from(`fixture PNG ${this.screenshotNumber}`); }
    if (session?.[2] === 'navigate' || session?.[2] === 'focus') return { data: 'ok' };
    if (session && method === 'DELETE') { this.sessions = this.sessions.filter((item) => item.session_id !== session[1]); return { data: 'closed' }; }
    const group = route.match(/^\/api\/groups\/(.+?)(\/proxy)?$/);
    if (group) { const name = decodeURIComponent(group[1]); if (method === 'PUT') { this.groups = this.groups.filter((item) => item.name !== name); this.groups.push({ name, ...body }); return { data: { name, ...body, restart_required: this.sessions.length > 0 } }; } if (group[2]) { const existing = this.groups.find((item) => item.name === name); if (existing) existing.proxy = null; } else this.groups = this.groups.filter((item) => item.name !== name); return { data: 'deleted' }; }
    if (route === '/api/shutdown') { this.sessions = []; return { data: 'shutting down' }; }
    throw new Error(`Unexpected fake route: ${method} ${route}`);
  }
}

async function fixture(t, options = {}) {
  const { mockInstalled = true, ...serviceOptions } = options;
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-browseforge-'));
  const profilesDir = path.join(directory, 'browseforge', 'profiles');
  const client = new FakeClient(profilesDir);
  if (mockInstalled) {
    await mkdir(path.join(directory, 'bin'));
    for (const descriptor of client.descriptors) { descriptor.binary_path = path.join(directory, 'bin', `${descriptor.id}${process.platform === 'win32' ? '.exe' : ''}`); await writeFile(descriptor.binary_path, 'fixture executable', { mode: 0o700 }); }
  }
  const service = new BrowseForgeService(directory, client, { platform: 'darwin' }, () => {}, { profilesDir, ...serviceOptions });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { directory, profilesDir, client, service };
}
const create = async (service, patch = {}) => (await service.call('createProfile', { profile: { name: '测试环境', engine: 'cloakbrowser', platform: 'macos', seed: 1234, locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, proxyId: null, ...patch } })).profiles.at(-1);

test('null upstream lists normalize to empty and enabled providers are not claimed installed', async (t) => {
  const { service } = await fixture(t, { mockInstalled: false });
  const snapshot = await service.snapshot();
  assert.deepEqual(snapshot.profiles, []);
  assert.equal(snapshot.engines.length, 3);
  assert.ok(snapshot.engines.every((engine) => engine.enabled && !engine.installed && engine.version === null));
  assert.equal(snapshot.engines.find((engine) => engine.id === 'camoufox').capabilities.supports_seed_fingerprint, false);
  assert.equal(snapshot.engines.find((engine) => engine.id === 'browseforge-chromium').experimental, true);
});

test('provider installation uses actual executable access with registry-provided version', async (t) => {
  let enginePath;
  const { directory, service } = await fixture(t, { getEngineStates: () => ({ cloakbrowser: { binaryPath: enginePath, version: '145-fixture' }, camoufox: { binaryPath: '/does/not/exist', error: 'download failed' } }) });
  enginePath = path.join(directory, process.platform === 'win32' ? 'browser.exe' : 'browser');
  await writeFile(enginePath, 'fixture executable', { mode: 0o700 });
  const engines = (await service.snapshot()).engines;
  assert.equal(engines.find((engine) => engine.id === 'cloakbrowser').installed, true);
  assert.equal(engines.find((engine) => engine.id === 'cloakbrowser').version, '145-fixture');
  assert.equal(engines.find((engine) => engine.id === 'camoufox').installed, false);
  assert.equal(engines.find((engine) => engine.id === 'camoufox').error, 'download failed');
});

test('create translates native profile fields and metadata without passing dangerous upstream fields', async (t) => {
  const { service, client } = await fixture(t);
  const profile = await create(service, { notes: '本地备注', startUrl: 'https://example.com' });
  const body = client.requests.find((request) => request.method === 'POST' && request.route === '/api/profiles').body;
  assert.equal(body.engine, undefined);
  assert.equal(body.runtime_id, 'cloakbrowser');
  assert.equal(body.fingerprint_seed, 1234);
  assert.equal(body.fingerprint.timezone, 'Asia/Shanghai');
  assert.deepEqual(body.launch_overrides, { target_os: 'macos', locale: 'zh-CN', timezone: 'Asia/Shanghai' });
  assert.equal(profile.notes, '本地备注');
  assert.equal(profile.startUrl, 'https://example.com');
  assert.equal(profile.cpuPercent, null);
  await assert.rejects(create(service, { profile_dir: '/outside' }), { code: 'VALIDATION_ERROR' });
  await assert.rejects(create(service, { engine: 'camoufox' }), { code: 'UNSUPPORTED_CAPABILITY' });
  const firefox = await create(service, { engine: 'camoufox', seed: null });
  assert.equal(firefox.seed, null);
});

test('live observed fingerprint is separate from desired fields and closed stale sessions are stopped', async (t) => {
  const { service, client } = await fixture(t);
  const profile = await create(service);
  let snapshot = await service.call('startProfile', { id: profile.id });
  assert.equal(snapshot.profiles[0].status, 'running');
  assert.equal(snapshot.profiles[0].timezone, 'Asia/Shanghai');
  assert.equal(snapshot.profiles[0].observed.timezone, 'America/Los_Angeles');
  assert.match(snapshot.profiles[0].screenshot, /^data:image\/png;base64,/);
  await assert.rejects(service.call('clearProfile', { id: profile.id }), { code: 'PROFILE_RUNNING' });
  client.closedSessions.add(client.sessions[0].session_id);
  snapshot = await service.snapshot();
  assert.equal(client.sessions.length, 1, 'fixture mimics upstream stale session map');
  assert.equal(snapshot.profiles[0].status, 'stopped');
  client.healthFailure = 'HTTP timed out';
  snapshot = await service.snapshot();
  assert.equal(snapshot.profiles[0].status, 'error');
  assert.match(snapshot.profiles[0].lastError, /timed out/);
});

test('supported missing providers allow drafts while start requires a real installed binary', async (t) => {
  const { service, client } = await fixture(t, { mockInstalled: false });
  client.descriptors.find((engine) => engine.id === 'cloakbrowser').enabled = false;
  const profile = await create(service);
  assert.equal(profile.status, 'stopped');
  await service.call('updateProfile', { id: profile.id, profile: { name: '未安装内核的草稿' } });
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'ENGINE_NOT_INSTALLED' });
  assert.equal(client.sessions.length, 0);
});

test('switching fixed locale and timezone to auto clears overrides and old fingerprint defaults', async (t) => {
  const { service, client } = await fixture(t);
  const profile = (await service.call('createProfile', { profile: { name: '自动网络匹配', engine: 'cloakbrowser', seed: 12345, locale: 'zh-CN', timezone: 'Asia/Shanghai' } })).profiles[0];
  assert.equal(profile.localeMode, 'fixed');
  assert.equal(profile.timezoneMode, 'fixed');
  const auto = await service.call('updateProfile', { id: profile.id, profile: { locale: '', timezone: '' } });
  assert.deepEqual(client.profiles[0].launch_overrides, { locale: '', timezone: '' });
  assert.deepEqual(client.profiles[0].fingerprint, {});
  assert.equal(auto.profiles[0].locale, '');
  assert.equal(auto.profiles[0].timezone, '');
  assert.equal(auto.profiles[0].localeMode, 'auto');
  assert.equal(auto.profiles[0].timezoneMode, 'auto');
  const exported = await service.call('exportProfiles');
  assert.equal(exported.profiles[0].locale, '');
  assert.equal(exported.profiles[0].timezone, '');
  const returned = await service.call('updateProfile', { id: profile.id, profile: { locale: 'en-US', timezone: 'America/New_York' } });
  assert.equal(returned.profiles[0].localeMode, 'fixed');
  assert.equal(returned.profiles[0].timezone, 'America/New_York');
  assert.equal(client.profiles[0].fingerprint['navigator.language'], 'en-US');
});

test('OS metrics hook gets actual backend profiles and only valid live measurements are displayed', async (t) => {
  let received, values = {};
  const { service, client } = await fixture(t, { getMetrics: (profiles) => { received = profiles; return values; } });
  const profile = await create(service);
  values = { [profile.id]: { cpuPercent: 7.2, memoryBytes: 102400 } };
  assert.equal((await service.snapshot()).profiles[0].cpuPercent, null, 'stopped profiles cannot display a stale process sample');
  const started = await service.call('startProfile', { id: profile.id });
  assert.deepEqual(received, client.profiles);
  assert.equal(started.profiles[0].cpuPercent, 7.2);
  assert.equal(started.profiles[0].memoryBytes, 102400);
  values = { [profile.id]: { cpuPercent: NaN, memoryBytes: -10 } };
  const invalid = await service.snapshot();
  assert.equal(invalid.profiles[0].cpuPercent, null);
  assert.equal(invalid.profiles[0].memoryBytes, null);
  service.options.getMetrics = () => { throw new Error('ps unavailable'); };
  assert.equal((await service.snapshot()).profiles[0].memoryBytes, null);
});

test('live previews refresh every ten seconds, share in-flight captures, and preserve original timestamps on failure', async (t) => {
  let clock = 1000;
  const { service, client } = await fixture(t, { nowMs: () => clock });
  const profile = await create(service);
  const started = await service.call('startProfile', { id: profile.id });
  const first = started.profiles[0];
  const captures = () => client.requests.filter((request) => request.route.endsWith('/screenshot')).length;
  assert.equal(captures(), 1);
  assert.equal(first.screenshotCapturedAt, new Date(clock).toISOString());
  clock = 10999;
  assert.equal((await service.snapshot()).profiles[0].screenshot, first.screenshot);
  assert.equal(captures(), 1);
  clock = 11000;
  const refreshed = (await service.snapshot()).profiles[0];
  assert.notEqual(refreshed.screenshot, first.screenshot);
  assert.equal(captures(), 2);
  let release;
  client.screenshotGate = new Promise((resolve) => { release = resolve; });
  clock = 21000;
  const polls = Promise.all([service.snapshot(), service.snapshot()]);
  while (captures() < 3) await new Promise((resolve) => setImmediate(resolve));
  release();
  const snapshots = await polls;
  client.screenshotGate = null;
  assert.equal(captures(), 3);
  assert.equal(snapshots[0].profiles[0].screenshot, snapshots[1].profiles[0].screenshot);
  assert.equal(snapshots[0].profiles[0].screenshotCapturedAt, new Date(clock).toISOString());
  clock = 31000;
  client.screenshotFailure = true;
  const failed = (await service.snapshot()).profiles[0];
  assert.equal(failed.screenshot, snapshots[0].profiles[0].screenshot);
  assert.equal(failed.screenshotCapturedAt, snapshots[0].profiles[0].screenshotCapturedAt);
  clock = 31001;
  await service.snapshot();
  assert.equal(captures(), 4, 'failed capture attempts are throttled too');
  const stopped = await service.call('stopProfile', { id: profile.id });
  assert.equal(stopped.profiles[0].screenshot, undefined);
  assert.equal(service.previews.size, 0);
  assert.equal(service.previewCapturedAt.size, 0);
});

test('an in-flight screenshot cannot resurrect a preview after its session stops', async (t) => {
  let clock = 1000;
  const { service, client } = await fixture(t, { nowMs: () => clock });
  const profile = await create(service);
  await service.call('startProfile', { id: profile.id });
  let release;
  client.screenshotGate = new Promise((resolve) => { release = resolve; });
  clock = 11000;
  const poll = service.snapshot();
  while (client.requests.filter((request) => request.route.endsWith('/screenshot')).length < 2) await new Promise((resolve) => setImmediate(resolve));
  await service.call('stopProfile', { id: profile.id });
  release();
  await poll;
  assert.equal(service.previews.size, 0);
  assert.equal(service.previewInFlight.size, 0);
  assert.equal((await service.snapshot()).profiles[0].screenshot, undefined);
});

test('long launch only locks its own profile; other stop and metadata actions continue, installation waits', async (t) => {
  const { service, client } = await fixture(t, { installEngine: async () => {} });
  const first = await create(service, { name: '启动慢的环境' });
  const second = await create(service, { name: '已运行环境' });
  await service.call('startProfile', { id: second.id });
  let release;
  client.startGates.set(first.id, new Promise((resolve) => { release = resolve; }));
  const start = service.call('startProfile', { id: first.id });
  try {
    while (!client.requests.some((request) => request.route === '/api/sessions' && request.method === 'POST' && request.body.profile_id === first.id)) await new Promise((resolve) => setImmediate(resolve));
    const stop = service.call('stopProfile', { id: second.id });
    await Promise.race([stop, new Promise((_, reject) => setTimeout(() => reject(new Error('other-profile Stop was blocked behind Start')), 500))]);
    assert.equal(client.sessions.length, 0);
    await create(service, { name: '启动期间创建' });
    await assert.rejects(service.call('deleteProfile', { id: first.id }), { code: 'PROFILE_RUNNING' });
    await assert.rejects(service.call('installEngine', { runtimeId: 'camoufox' }), { code: 'ENGINE_INSTALL_BUSY' });
  } finally { release(); await start; }
  assert.equal(client.sessions[0].profile_id, first.id);
});

test('clone bypasses upstream duplicate to regenerate seed without copying structured fingerprint or data', async (t) => {
  const { service, client } = await fixture(t);
  const original = await create(service);
  const snapshot = await service.call('cloneProfile', { id: original.id });
  const clone = snapshot.profiles.at(-1);
  const body = client.requests.filter((request) => request.method === 'POST' && request.route === '/api/profiles').at(-1).body;
  assert.notEqual(clone.id, original.id);
  assert.notEqual(body.fingerprint_seed, original.seed);
  assert.equal(body.fingerprint, undefined);
  assert.equal(clone.dataBytes, 0);
  assert.equal(client.requests.some((request) => request.route.endsWith('/duplicate')), false);
});

test('proxy and group bindings are preserved and missing region or proxy reference fails explicitly', async (t) => {
  const { service } = await fixture(t);
  const proxy = (await service.call('saveProxy', { proxy: { name: '纽约代理', protocol: 'socks5', host: 'proxy.example', port: 1080, username: 'alice', password: 'secret', region: 'us-ny' } })).proxies[0];
  const profile = await create(service, { engine: 'browseforge-chromium', proxyId: proxy.id });
  assert.equal(profile.proxyId, proxy.id);
  await service.call('saveGroup', { name: '工作', proxyId: proxy.id, proxyMode: 'enforced' });
  const snapshot = await service.call('updateProfile', { id: profile.id, profile: { group: '工作', proxyId: null } });
  assert.equal(snapshot.profiles[0].proxySource, 'group');
  assert.equal(snapshot.profiles[0].proxyId, proxy.id);
  await assert.rejects(service.call('deleteProxy', { id: proxy.id }), { code: 'PROXY_IN_USE' });
  await assert.rejects(create(service, { proxyId: 'missing' }), { code: 'PROXY_NOT_FOUND' });
  const noRegion = (await service.call('saveProxy', { proxy: { name: '无地域', protocol: 'http', host: 'localhost', port: 8080 } })).proxies.find((item) => item.name === '无地域');
  await assert.rejects(create(service, { engine: 'browseforge-chromium', proxyId: noRegion.id }), { code: 'INVALID_PROXY_REGION' });
});

test('redacted export retains required proxy mapping and import never silently switches to direct', async (t) => {
  const { service, client } = await fixture(t);
  const proxy = (await service.call('saveProxy', { proxy: { name: '认证代理', protocol: 'http', host: 'proxy.example', port: 8080, username: 'alice', password: 'secret' } })).proxies[0];
  await create(service, { proxyId: proxy.id });
  const document = await service.call('exportProfiles');
  assert.equal(document.version, 2);
  assert.equal(document.profiles[0].proxyId, proxy.id);
  assert.equal(document.proxies[0].requiresCredentials, true);
  assert.equal(document.profiles[0].fingerprint.timezone, 'Asia/Shanghai');
  assert.equal(JSON.stringify(document).includes('secret'), false);
  assert.equal(JSON.stringify(document).includes('alice'), false);
  await assert.rejects(service.call('importProfiles', { document }), { code: 'PROXY_MAPPING_REQUIRED' });
  assert.equal(client.profiles.length, 1);
  const imported = await service.call('importProfiles', { document, proxyMap: { [proxy.id]: proxy.id } });
  assert.equal(imported.profiles.length, 2);
  assert.ok(imported.profiles.every((profile) => profile.proxyId === proxy.id));
  assert.equal(client.profiles.at(-1).proxy.password, 'secret');
});

test('import validates the whole batch first and rolls back only newly created records on remote failure', async (t) => {
  const { service, client } = await fixture(t);
  const original = await create(service);
  const rows = [{ name: '导入一', engine: 'cloakbrowser', seed: 12345, proxyId: null }, { name: '导入二', engine: 'cloakbrowser', seed: 12346, proxyId: null }];
  await assert.rejects(service.call('importProfiles', { profiles: [rows[0], { ...rows[1], seed: 0 }] }), { code: 'VALIDATION_ERROR' });
  assert.equal(client.createCount, 1);
  client.failCreateAt = 3;
  await assert.rejects(service.call('importProfiles', { profiles: rows }), /fixture create failed/);
  assert.deepEqual(client.profiles.map((profile) => profile.id), [original.id]);
  assert.deepEqual((await service.snapshot()).profiles.map((profile) => profile.id), [original.id]);
});

test('clear preserves downloads and configuration while rejecting backend paths outside the managed root', async (t) => {
  const { service, client } = await fixture(t);
  const profile = await create(service);
  const directory = client.profiles[0].profile_dir;
  await writeFile(path.join(directory, 'browser-data', 'cookies'), 'cookie');
  await mkdir(path.join(directory, 'downloads'));
  await writeFile(path.join(directory, 'downloads', 'report'), 'download');
  const cleared = await service.call('clearProfile', { id: profile.id });
  assert.equal(cleared.profiles[0].dataBytes, 0);
  assert.equal(await readFile(path.join(directory, 'downloads', 'report'), 'utf8'), 'download');
  client.profiles[0].profile_dir = path.dirname(directory);
  await assert.rejects(service.call('deleteProfile', { id: profile.id }), { code: 'UNSAFE_PROFILE_PATH' });
  assert.equal(client.profiles.length, 1);
});

test('a new profile symlink cannot clear or delete an original legacy directory', async (t) => {
  const { directory, service, client } = await fixture(t);
  const profile = await create(service);
  const legacyDirectory = path.join(directory, 'profiles', 'existing-legacy');
  await mkdir(path.join(legacyDirectory, 'browser-data'), { recursive: true });
  await writeFile(path.join(legacyDirectory, 'browser-data', 'Cookies'), 'protected-original');
  await rm(client.profiles[0].profile_dir, { recursive: true });
  await symlink(legacyDirectory, client.profiles[0].profile_dir, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(service.call('clearProfile', { id: profile.id }), { code: 'UNSAFE_PROFILE_PATH' });
  await assert.rejects(service.call('deleteProfile', { id: profile.id }), { code: 'UNSAFE_PROFILE_PATH' });
  assert.equal(await readFile(path.join(legacyDirectory, 'browser-data', 'Cookies'), 'utf8'), 'protected-original');
  assert.equal(client.profiles.length, 1);
});

async function seedLegacy(directory) {
  const profileId = '11111111-1111-4111-8111-111111111111';
  const proxyId = '22222222-2222-4222-8222-222222222222';
  const workspace = { schema: 'envara.workspace', version: 1, profiles: [{ id: profileId, name: '旧环境', engine: 'cloakbrowser', group: '旧分组', notes: '旧备注', platform: 'macos', seed: 12345, locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, startUrl: 'about:blank', proxyId, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', lastLaunchedAt: null }], proxies: [{ id: proxyId, name: '旧代理', protocol: 'socks5', host: '127.0.0.1', port: 1080, username: 'legacy-user', password: 'legacy-password' }], settings: { closeBrowsersOnExit: true }, events: [] };
  const bytes = JSON.stringify(workspace, null, 2);
  await writeFile(path.join(directory, 'workspace.json'), bytes);
  await mkdir(path.join(directory, 'profiles', profileId, 'Default'), { recursive: true });
  await writeFile(path.join(directory, 'profiles', profileId, 'Default', 'Cookies'), 'original-cookie-bytes');
  await writeFile(path.join(directory, 'profiles', profileId, 'SingletonLock'), 'stale-lock');
  return { profileId, bytes };
}

test('explicit legacy migration creates complete backup copies and preserves original configuration and browser files', async (t) => {
  const { directory, service, client } = await fixture(t, { assertLegacyStopped: () => true });
  const original = await seedLegacy(directory);
  const preview = await service.call('previewLegacyMigration');
  assert.equal(preview.profiles.length, 1);
  assert.equal(preview.profiles[0].migrated, false);
  const migrated = await service.call('migrateLegacy', { copyBrowserData: true });
  assert.equal(migrated.actionResult.migratedCount, 1);
  assert.equal(await readFile(path.join(directory, 'workspace.json'), 'utf8'), original.bytes);
  assert.equal(await readFile(path.join(directory, 'profiles', original.profileId, 'Default', 'Cookies'), 'utf8'), 'original-cookie-bytes');
  assert.equal(await readFile(path.join(migrated.actionResult.backupDir, 'profiles', original.profileId, 'SingletonLock'), 'utf8'), 'stale-lock');
  assert.equal(await readFile(path.join(client.profiles[0].profile_dir, 'browser-data', 'Default', 'Cookies'), 'utf8'), 'original-cookie-bytes');
  assert.equal((await readdir(path.join(client.profiles[0].profile_dir, 'browser-data'))).includes('SingletonLock'), false);
  assert.equal(client.profiles[0].fingerprint_seed, 12345);
  assert.equal(client.profiles[0].proxy.password, 'legacy-password');
  assert.equal(migrated.profiles[0].createdAt, '2026-01-01T00:00:00.000Z');
  assert.equal((await service.call('previewLegacyMigration')).profiles[0].migrated, true);
  await assert.rejects(service.call('migrateLegacy'), /没有需要迁移/);
});

test('migration requires stopped-session confirmation and a failed migration leaves every legacy byte untouched', async (t) => {
  const { directory, service, client } = await fixture(t);
  const original = await seedLegacy(directory);
  await assert.rejects(service.call('migrateLegacy'), { code: 'LEGACY_SESSIONS_NOT_CONFIRMED_STOPPED' });
  assert.equal(client.createCount, 0);
  service.options.assertLegacyStopped = () => true;
  client.failCreateAt = 1;
  await assert.rejects(service.call('migrateLegacy'), /原资料未修改/);
  assert.equal(await readFile(path.join(directory, 'workspace.json'), 'utf8'), original.bytes);
  assert.equal(await readFile(path.join(directory, 'profiles', original.profileId, 'Default', 'Cookies'), 'utf8'), 'original-cookie-bytes');
  assert.equal(client.profiles.length, 0);
  assert.equal((await service.store.read()).proxies.length, 0);
  assert.equal((await readdir(path.join(directory, 'migration-backups'))).length, 1);
});
