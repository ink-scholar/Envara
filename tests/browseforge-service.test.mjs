import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { ProxyNetworkProbe } from '../electron/proxy-network.mjs';
import { languages } from '../shared/interface-languages.mjs';
import { networkApplicationChoices, chooseApplicationProfile, createdProfileFromSnapshot } from '../src/network-flow-state.mjs';
import { linkBrowsersFor } from '../src/link-browser.mjs';

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
    const duplicate = route.match(/^\/api\/profiles\/([A-Za-z0-9_-]+)\/duplicate$/);
    if (duplicate && method === 'POST') {
      const source = structuredClone(this.profiles.find(item => item.id === duplicate[1]));
      assert.ok(source);
      const id = `prof_${String(++this.createCount).padStart(12, '0')}`;
      const copy = { ...source, id, name: body.name, fingerprint_seed: (source.fingerprint_seed || 1) + 1, profile_dir: path.join(this.profilesDir, id) };
      this.profiles.push(copy);
      await mkdir(path.join(copy.profile_dir, 'browser-data'), { recursive: true });
      return { data: structuredClone(copy) };
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
    if (group) { const name = decodeURIComponent(group[1]); if (method === 'PUT') { this.groups = this.groups.filter((item) => item.name !== name); this.groups.push({ name, ...body }); return { data: { name, ...body, restart_required: this.sessions.length > 0 } }; } if (group[2]) { const existing = this.groups.find((item) => item.name === name); if (existing) existing.proxy = null; } else { this.groups = this.groups.filter((item) => item.name !== name); for (const profile of this.profiles) if (profile.group === name) profile.group = ''; } return { data: 'deleted' }; }
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
  const offlineProbe = new ProxyNetworkProbe({ transport: async () => { throw new Error('fixture offline; no external network requests'); } });
  const service = new BrowseForgeService(directory, client, { platform: 'darwin' }, () => {}, { profilesDir, proxyCore: managedProxyFixture().proxyCore, networkProbe: offlineProbe, addressGeocoder: { reverse: async () => null, close() {} }, ...serviceOptions });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { directory, profilesDir, client, service };
}
const create = async (service, patch = {}) => (await service.call('createProfile', { profile: { name: '测试环境', engine: 'cloakbrowser', platform: 'macos', seed: 1234, locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900, proxyId: null, ...patch } })).profiles.at(-1);

test('BrowseForge interface-language settings keep browser locale and fingerprint data unchanged', async (t) => {
  const { service, client, directory } = await fixture(t);
  assert.equal((await service.snapshot()).settings.language, undefined);
  await create(service, { locale: 'ja-JP', timezone: 'Asia/Tokyo' });
  const before = structuredClone(client.profiles);
  for (const language of languages) {
    await service.saveSettings({ settings: { closeBrowsersOnExit: true, language } });
    assert.equal((await service.snapshot()).settings.language, language);
    assert.deepEqual(client.profiles, before);
  }
  const persisted = JSON.parse(await readFile(path.join(directory, 'browseforge-manager', 'workspace.json'), 'utf8'));
  assert.equal(persisted.settings.language, languages.at(-1));
  for (const language of ['en-US', 'ar', '__proto__', '', {}, ['en']]) {
    await assert.rejects(service.saveSettings({ settings: { closeBrowsersOnExit: true, language } }), { code: 'VALIDATION_ERROR' });
  }
  assert.equal((await service.snapshot()).settings.language, languages.at(-1));
});

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
  const profile = (await service.call('createProfile', { profile: { name: '自动网络匹配', engine: 'cloakbrowser', deviceProfileId: 'provider-default', seed: 12345, locale: 'zh-CN', timezone: 'Asia/Shanghai' } })).profiles[0];
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

test('fingerprint-only legacy timezone and locale stay fixed when egress detection fails, without storage changes', async (t) => {
  let networkRequests = 0;
  const networkProbe = new ProxyNetworkProbe({ endpoints: [{ url: 'https://ipwho.is/', source: 'ipwho.is', format: 'ipwho' }], transport: async () => { networkRequests++; throw new Error('fixture egress unavailable'); } });
  const { service, client } = await fixture(t, { networkProbe });
  const profile = await create(service, { timezone: 'Asia/Tokyo', locale: 'ja-JP' });
  delete client.profiles[0].launch_overrides;
  const before = structuredClone(client.profiles[0]);
  const snapshot = (await service.snapshot()).profiles[0];
  assert.equal(snapshot.timezone, 'Asia/Tokyo'); assert.equal(snapshot.timezoneMode, 'fixed'); assert.equal(snapshot.timezoneSource, 'manual');
  assert.equal(snapshot.resolvedTimezone, 'Asia/Tokyo'); assert.equal(snapshot.locale, 'ja-JP'); assert.equal(snapshot.localeMode, 'fixed');
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.timezone, 'Asia/Tokyo'); assert.equal(context.timezoneSource, 'manual'); assert.equal(context.network.ok, false);
  assert.equal(context.geolocation, null); assert.equal(context.locale, 'ja-JP'); assert.ok(context.networkLastError);
  const started = await service.call('startProfile', { id: profile.id });
  assert.equal(started.profiles[0].resolvedTimezone, 'Asia/Tokyo');
  assert.deepEqual(client.requests.find((request) => request.route === '/api/sessions' && request.method === 'POST').body.launch_overrides, { timezone: 'Asia/Tokyo', locale: 'ja-JP', privacy: { mode: 'standard' }, geolocation: null });
  assert.equal(networkRequests, 2, 'context and forced launch each detect the actual egress without replacing fixed policy');
  assert.deepEqual(client.profiles[0], before, 'legacy fingerprint and stored overrides must remain untouched');
});

test('explicit launch overrides take precedence over conflicting legacy fingerprint fields', async (t) => {
  let networkRequests = 0;
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { networkRequests++; return networkGeo; } });
  const { service, client } = await fixture(t, { networkProbe });
  const profile = await create(service, { timezone: 'Asia/Tokyo', locale: 'ja-JP' });
  client.profiles[0].launch_overrides = { timezone: 'Europe/Berlin', locale: 'de-DE' };
  const snapshot = (await service.snapshot()).profiles[0];
  assert.equal(snapshot.timezone, 'Europe/Berlin'); assert.equal(snapshot.locale, 'de-DE');
  assert.equal(snapshot.timezoneMode, 'fixed'); assert.equal(snapshot.localeMode, 'fixed');
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.timezone, 'Europe/Berlin'); assert.equal(context.timezoneSource, 'manual'); assert.equal(networkRequests, 1);
  assert.equal(context.locale, 'de-DE'); assert.equal(context.network.ip, networkGeo.ip);
  assert.equal(client.profiles[0].fingerprint.timezone, 'Asia/Tokyo');
});

test('changing a legacy fingerprint timezone invalidates its previously resolved workspace context', async (t) => {
  const { service, client } = await fixture(t);
  const profile = await create(service, { timezone: 'Asia/Tokyo' });
  delete client.profiles[0].launch_overrides;
  await service.resolveWorkspaceContext(profile.id);
  const previousSignature = service.workspaceContexts.get(profile.id).signature;
  client.profiles[0].fingerprint.timezone = 'America/New_York';
  const snapshot = (await service.snapshot()).profiles[0];
  assert.equal(snapshot.resolvedTimezone, 'America/New_York', 'old context must not keep displaying the previous timezone');
  assert.equal(snapshot.timezoneSource, 'manual');
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.timezone, 'America/New_York'); assert.notEqual(service.workspaceContexts.get(profile.id).signature, previousSignature);
});

test('legacy fixed to explicit automatic mode clears fingerprint defaults even when Go omits empty override fields', async (t) => {
  let networkRequests = 0;
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { networkRequests++; return networkGeo; } });
  const { service, client } = await fixture(t, { networkProbe });
  const profile = await create(service, { timezone: 'Asia/Tokyo', locale: 'ja-JP' });
  delete client.profiles[0].launch_overrides;
  await service.resolveWorkspaceContext(profile.id);
  await service.call('updateProfile', { id: profile.id, profile: { timezone: '', locale: '' } });
  assert.equal(client.profiles[0].fingerprint.timezone, undefined); assert.equal(client.profiles[0].fingerprint['navigator.language'], undefined);
  for (const key of ['timezone', 'locale']) delete client.profiles[0].launch_overrides[key]; // Real Go omitempty representation.
  const snapshot = (await service.snapshot()).profiles[0];
  assert.equal(snapshot.timezone, null); assert.equal(snapshot.locale, null); assert.equal(snapshot.timezoneMode, 'auto'); assert.equal(snapshot.localeMode, 'auto');
  assert.equal(snapshot.resolvedTimezone, null); assert.equal(snapshot.timezoneSource, null);
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.timezone, 'America/New_York'); assert.equal(context.timezoneSource, 'direct'); assert.equal(networkRequests, 1);
  assert.equal(client.profiles[0].launch_overrides.timezone, undefined, 'resolution never writes a fixed timezone into automatic storage');
});

test('invalid legacy manual timezone reports validation failure and cannot silently become automatic', async (t) => {
  let networkRequests = 0;
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { networkRequests++; return networkGeo; } });
  const { service, client } = await fixture(t, { networkProbe });
  const profile = await create(service);
  delete client.profiles[0].launch_overrides;
  client.profiles[0].fingerprint.timezone = 'Mars/Olympus';
  const snapshot = (await service.snapshot()).profiles[0];
  assert.equal(snapshot.timezoneMode, 'fixed'); assert.equal(snapshot.resolvedTimezone, null);
  await assert.rejects(service.resolveWorkspaceContext(profile.id), { code: 'INVALID_MANUAL_TIMEZONE' });
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'INVALID_MANUAL_TIMEZONE' });
  assert.match((await service.snapshot()).profiles[0].lastError, /手动时区无效/);
  assert.equal(networkRequests, 0); assert.equal(client.requests.some((request) => request.route === '/api/sessions' && request.method === 'POST'), false);
  client.profiles[0].fingerprint.timezone = 0;
  await assert.rejects(service.resolveWorkspaceContext(profile.id), { code: 'INVALID_MANUAL_TIMEZONE' });
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

test('clone uses the canonical native duplicate and retains custom settings without copying browser data', async (t) => {
  const { service, client } = await fixture(t);
  const original = await create(service, { deviceProfileId: 'provider-default', fingerprint: { 'custom.fixture': true } });
  const snapshot = await service.call('cloneProfile', { id: original.id });
  const clone = snapshot.profiles.at(-1);
  const request = client.requests.find(request => request.route.endsWith('/duplicate'));
  assert.equal(request.route, `/api/profiles/${original.id}/duplicate`);
  assert.deepEqual(request.body, { name: `${original.name} 副本` });
  assert.notEqual(clone.id, original.id);
  assert.notEqual(clone.seed, original.seed);
  assert.deepEqual(clone.fingerprint, original.fingerprint);
  assert.equal(clone.dataBytes, 0);
  assert.equal(client.requests.filter(request => request.method === 'POST' && request.route === '/api/profiles').length, 1);
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

const networkGeo = { success: true, ip: '8.8.8.8', country: 'United States', country_code: 'US', region: 'New York', city: 'New York', timezone: { id: 'America/New_York' } };
const savedProxy = async (service, patch = {}) => (await service.call('saveProxy', { proxy: { name: '认证出口', protocol: 'http', host: 'proxy.example', port: 8080, username: 'dummy-user', password: 'dummy-password', ...patch } })).proxies.find((proxy) => proxy.name === (patch.name ?? '认证出口'));

test('global confirmed regions flow into BrowseForge profiles and groups without rewriting saved identity', async (t) => {
  let measured = { ...networkGeo, country: 'Japan', country_code: 'JP', region: 'Tokyo', city: 'Tokyo', timezone: { id: 'Asia/Tokyo' } };
  const { service, client } = await fixture(t, { networkProbe: new ProxyNetworkProbe({ transport: async () => measured }) });
  const draft = { name: '全球出口', protocol: 'http', host: 'proxy.example', port: 8080 };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const saved = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  assert.equal(saved.region, '', 'automatic region selection does not become an explicit saved override');
  const profile = await create(service, { engine: 'browseforge-chromium', proxyId: saved.id, group: '全球地区' });
  assert.equal(client.profiles[0].proxy.region, 'jp-tokyo');
  assert.deepEqual((await service.snapshot()).proxies.map(proxy => proxy.id), [saved.id], 'the native profile projection is not another saved network');
  const identity = structuredClone({ seed: client.profiles[0].fingerprint_seed, fingerprint: client.profiles[0].fingerprint });
  await service.call('saveGroup', { name: '全球地区', proxyId: saved.id });
  assert.equal(client.groups[0].proxy.region, 'jp-tokyo');
  assert.deepEqual((await service.snapshot()).proxies.map(proxy => proxy.id), [saved.id], 'the native group projection reuses its saved network');

  measured = { ...networkGeo, country: 'Malaysia', country_code: 'MY', region: 'Selangor', city: 'Petaling', timezone: { id: 'Asia/Kuala_Lumpur' } };
  const moved = { ...draft, id: saved.id, port: 8081 };
  const nextPreview = await service.call('previewProxyNetwork', { proxy: moved });
  await service.call('saveProxy', { proxy: { ...moved, location: { mode: 'ip', confirmed: true } }, locationPreviewToken: nextPreview.locationPreviewToken });
  assert.equal(client.profiles[0].proxy.region, 'my', 'an unsupported city uses its supported country');
  assert.equal(client.groups[0].proxy.region, 'my');
  await service.call('updateProfile', { id: profile.id, profile: { name: '改名后环境' } });
  assert.deepEqual({ seed: client.profiles[0].fingerprint_seed, fingerprint: client.profiles[0].fingerprint }, identity);
  const stored = (await service.store.read()).proxies.find(item => item.id === saved.id);
  assert.equal(stored.region, '');
  assert.equal(stored.location.countryCode, 'MY');
  assert.match(stored.location.label, /Petaling/);
  assert.deepEqual((await service.snapshot()).proxies.map(proxy => proxy.id), [saved.id]);
});

test('network lists keep saved identities and only collapse native projections of their own bindings', () => {
  const saved = { id: 'saved_a', name: 'Saved A', protocol: 'http', host: 'proxy.example', port: 8080, username: 'fixture-user', password: 'fixture-password', region: '', location: { confirmed: true, countryCode: 'JP', region: 'Tokyo' } };
  const projected = { type: 'http', host: saved.host, port: saved.port, username: saved.username, password: saved.password, region: 'jp-tokyo' };
  const service = { networkProbe: { peek: () => null }, proxyWires: new Map() };
  const list = (proxies, profiles, groups, remoteProfiles, remoteGroups) => BrowseForgeService.prototype.proxies.call(service, { proxies, profiles, groups }, { profiles: remoteProfiles, groups: remoteGroups });
  const remoteProfile = { id: 'profile_a', name: 'Profile A', proxy: projected };
  const remoteGroup = { name: 'Group A', proxy: projected };
  const profileBinding = { id: remoteProfile.id, proxyId: saved.id };
  const groupBinding = { name: remoteGroup.name, proxyId: saved.id };
  const second = { ...saved, id: 'saved_b', name: 'Saved B' };
  const before = structuredClone({ saved, second, remoteProfile, remoteGroup });

  assert.deepEqual(list([saved, second], [profileBinding], [], [remoteProfile], []).map(proxy => proxy.id), [saved.id, second.id]);
  assert.deepEqual(list([saved, second], [], [groupBinding], [], [remoteGroup]).map(proxy => proxy.id), [saved.id, second.id]);
  for (const proxyId of [undefined, 'missing', second.id]) {
    const others = proxyId === second.id ? [{ ...second, host: 'other.example' }] : [];
    assert.equal(list([saved, ...others], [{ ...profileBinding, proxyId }], [], [remoteProfile], []).at(-1).source, 'profile', `profile binding ${proxyId} cannot borrow another saved projection`);
    assert.equal(list([saved, ...others], [], [{ ...groupBinding, proxyId }], [], [remoteGroup]).at(-1).source, 'group', `group binding ${proxyId} cannot borrow another saved projection`);
  }
  for (const patch of [{ host: 'other.example' }, { port: 8081 }, { type: 'socks5' }, { username: 'other-user' }, { password: 'other-password' }, { region: 'us-ny' }]) {
    assert.equal(list([saved], [profileBinding], [], [{ ...remoteProfile, proxy: { ...projected, ...patch } }], []).length, 2, `changed profile ${Object.keys(patch)[0]} stays visible`);
    assert.equal(list([saved], [], [groupBinding], [], [{ ...remoteGroup, proxy: { ...projected, ...patch } }]).length, 2, `changed group ${Object.keys(patch)[0]} stays visible`);
  }
  const exact = { ...saved, region: 'jp-tokyo' };
  assert.equal(list([exact], [], [], [remoteProfile], [remoteGroup]).length, 1, 'existing exact configuration matching remains compatible');
  assert.equal(list([{ ...saved, region: 'JP-TOKYO' }], [profileBinding], [groupBinding], [remoteProfile], [remoteGroup]).length, 1, 'native region normalization does not create a second network');
  assert.deepEqual({ saved, second, remoteProfile, remoteGroup }, before, 'list synthesis does not rewrite saved or native configuration');
});

test('bound native projections can reuse the measured region of an unconfirmed saved node', () => {
  const saved = { id: 'measured', name: 'Measured', protocol: 'http', host: 'proxy.example', port: 8080, username: '', password: '', region: '' };
  const native = { type: 'http', host: saved.host, port: saved.port, region: 'jp-tokyo' };
  const network = { ok: true, scope: 'egress', ip: '203.0.113.10', countryCode: 'JP', region: 'Tokyo', timezone: 'Asia/Tokyo' };
  const service = { networkProbe: { peek: () => network }, proxyWires: new Map([[saved.id, { protocol: 'http', host: '127.0.0.1', port: 20000, username: 'fixture-wire-user', password: 'fixture-wire-password' }]]) };
  const workspace = { proxies: [saved], profiles: [{ id: 'profile', proxyId: saved.id }], groups: [{ name: 'Group', proxyId: saved.id }] };
  const remote = { profiles: [{ id: 'profile', name: 'Profile', proxy: native }], groups: [{ name: 'Group', proxy: native }] };
  assert.deepEqual(BrowseForgeService.prototype.proxies.call(service, workspace, remote).map(proxy => proxy.id), [saved.id]);
  assert.equal(saved.region, '');
  assert.equal(saved.location, undefined);
  service.networkProbe.peek = () => null;
  assert.equal(BrowseForgeService.prototype.proxies.call(service, workspace, remote).length, 2, 'unavailable measurements cannot invent a matching region');
  service.networkProbe.peek = () => network;
  service.proxyWires.clear();
  const withoutWire = BrowseForgeService.prototype.proxies.call(service, workspace, remote);
  assert.equal(withoutWire.length, 2); assert.equal(withoutWire[0].network, null, 'managed nodes never fall back to an old raw cache after losing their wire');
});

test('network projection matching preserves readable legacy credentials and AnyTLS native differences', () => {
  const service = { networkProbe: { peek: () => null }, proxyWires: new Map() };
  const saved = { id: 'saved', name: 'Legacy', protocol: 'http', host: 'proxy.example', port: 8080, username: 'legacy:user', password: 'fixture-password', region: '', location: { confirmed: true, countryCode: 'JP', region: 'Tokyo' } };
  const native = { type: 'http', host: saved.host, port: saved.port, username: saved.username, password: saved.password, region: 'jp-tokyo' };
  const list = (proxy, inline, group = false) => BrowseForgeService.prototype.proxies.call(service, {
    proxies: [proxy], profiles: [{ id: 'legacy', proxyId: proxy.id }], groups: [{ name: 'Legacy', proxyId: proxy.id }],
  }, { profiles: group ? [] : [{ id: 'legacy', name: 'Legacy', proxy: inline }], groups: group ? [{ name: 'Legacy', proxy: inline }] : [] });
  for (const group of [false, true]) {
    assert.equal(list(saved, native, group).length, 2, 'invalid legacy usernames remain readable for repair');
    const anytls = { ...saved, protocol: 'anytls', username: '', serverName: 'tls.example', alpn: ['h2'], udp: false };
    const nativeAnyTLS = { ...native, type: 'anytls', username: '' };
    assert.equal(list(anytls, nativeAnyTLS, group).length, 2, 'the ordinary projection cannot discard AnyTLS options');
    assert.equal(list(anytls, { ...native, type: 'socks5', host: '127.0.0.1', port: 50000, username: 'runtime-user' }, group).length, 2, 'a managed listener is not the saved upstream node');
  }
});

test('invalid explicit BrowseForge region is refused across profile, proxy and group writes', async (t) => {
  const { service, client } = await fixture(t);
  const supported = await savedProxy(service, { name: '合法地区', region: 'jp-tokyo' });
  const invalid = await savedProxy(service, { name: '不支持地区', region: 'jp-osaka', host: 'other.example' });
  const profile = await create(service, { engine: 'browseforge-chromium', proxyId: supported.id, group: '地区校验' });
  await assert.rejects(create(service, { engine: 'browseforge-chromium', proxyId: invalid.id }), { code: 'INVALID_PROXY_REGION' });
  await assert.rejects(service.call('saveProxy', { proxy: { ...supported, region: 'jp-osaka' } }), { code: 'INVALID_PROXY_REGION' });
  await assert.rejects(service.call('saveGroup', { name: '地区校验', proxyId: invalid.id }), { code: 'INVALID_PROXY_REGION' });
  assert.equal(client.profiles.length, 1);
  assert.equal(client.profiles[0].id, profile.id);
  assert.equal(client.profiles[0].proxy.region, 'jp-tokyo');
  assert.deepEqual(client.groups, []);
});

test('network creation previews actual egress then stores only a matching confirmed location', async (t) => {
  const { service } = await fixture(t, { networkProbe: new ProxyNetworkProbe({ transport: async () => networkGeo }) });
  const draft = { name: '推荐位置', protocol: 'http', host: 'proxy.example', port: 8080, username: 'dummy-user', password: 'dummy-password' };
  const before = JSON.stringify(await service.store.read());
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  assert.equal(preview.network.scope, 'egress'); assert.equal(preview.network.ip, '8.8.8.8');
  assert.equal(preview.locationRecommendation.confirmed, false); assert.ok(preview.locationPreviewToken);
  assert.equal(JSON.stringify(await service.store.read()), before);
  assert.equal(JSON.stringify(preview).includes(draft.password), false);
  await assert.rejects(service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true } } }), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
  await assert.rejects(service.call('saveProxy', { proxy: { ...draft, password: 'changed-password', location: { mode: 'ip', confirmed: true } }, locationPreviewToken: preview.locationPreviewToken }), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
  const snapshot = await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true, latitude: 0, longitude: 0, label: 'forged house' } }, locationPreviewToken: preview.locationPreviewToken });
  const saved = snapshot.proxies[0];
  assert.equal(saved.location.confirmed, true); assert.equal(saved.location.latitude, preview.network.geolocation?.latitude ?? null);
  assert.equal(saved.location.egressIP, preview.network.ip); assert.equal(saved.location.egressTimezone, preview.network.timezone);
  assert.notEqual(saved.location.label, 'forged house'); assert.equal(saved.location.addressResolved, false);
  const renamed = await service.call('saveProxy', { proxy: { ...draft, id: saved.id, name: '重命名' } });
  assert.deepEqual(renamed.proxies[0].location, saved.location);
  const replaced = await service.call('saveProxy', { proxy: { ...draft, id: saved.id, password: 'changed-password' } });
  assert.equal(replaced.proxies[0].location, undefined, 'old selection cannot move silently to another node');
});

test('failed or expired egress preview cannot confirm a location', async (t) => {
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { throw new Error('offline fixture'); } });
  const { service } = await fixture(t, { networkProbe });
  const draft = { name: '离线', protocol: 'socks5', host: 'proxy.example', port: 1080 };
  const offline = await service.call('previewProxyNetwork', { proxy: draft });
  assert.equal(offline.network.ok, false); assert.equal(offline.locationRecommendation, null); assert.equal(offline.locationPreviewToken, null);
  networkProbe.transport = async () => networkGeo;
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  service.locationPreviews.get(preview.locationPreviewToken).expiresAt = 0;
  await assert.rejects(service.call('saveProxy', { proxy: { ...draft, location: { mode: 'manual', confirmed: true, label: 'Chosen address' } }, locationPreviewToken: preview.locationPreviewToken }), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
  assert.equal((await service.store.read()).proxies.length, 0);
});

test('confirmed manual coordinate propagates through scoped context and browser without altering detected egress', async (t) => {
  const networkProbe = new ProxyNetworkProbe({ transport: async () => networkGeo });
  const { service, client } = await fixture(t, { networkProbe });
  const draft = { name: '用户位置', protocol: 'socks5', host: 'proxy.example', port: 1080 };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const saved = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'manual', confirmed: true, label: 'Selected map pin', mapsUrl: 'https://www.google.com/maps/search/?api=1&query=40.7,-74.1' } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  const profile = await create(service, { proxyId: saved.id, timezone: 'Asia/Tokyo', locale: '' });
  const original = JSON.stringify(client.profiles);
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.locationSource, 'manual'); assert.equal(context.selectedLocation.label, 'Selected map pin');
  assert.deepEqual(context.geolocation, { latitude: 40.7, longitude: -74.1, accuracy: 1000 });
  assert.deepEqual(context.network.geolocation, preview.network.geolocation);
  assert.equal(context.timezone, preview.network.timezone);
  assert.equal(context.timezoneSource, 'proxy-egress', 'source stays compatible with platform adapters');
  assert.equal(context.timezoneOrigin, 'network-environment', 'confirmed network timezone takes precedence over per-profile legacy settings');
  assert.equal(JSON.stringify(client.profiles), original, 'selection is a child launch override, not a persistent fingerprint rewrite');
  const snapshot = await service.call('startProfile', { id: profile.id });
  assert.equal(snapshot.profiles[0].selectedLocation.label, 'Selected map pin');
  const launched = client.requests.find(row => row.route === '/api/sessions' && row.method === 'POST');
  assert.deepEqual(launched.body.launch_overrides.geolocation, context.geolocation);
  assert.equal(launched.body.launch_overrides.timezone, preview.network.timezone);
});

test('confirmed text-only address stays unresolved instead of silently using the IP centre', async (t) => {
  const { service } = await fixture(t, { networkProbe: new ProxyNetworkProbe({ transport: async () => networkGeo }) });
  const draft = { name: '手填地址', protocol: 'http', host: 'proxy.example', port: 8080 };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const saved = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'manual', confirmed: true, label: 'User selected address' } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  const profile = await create(service, { proxyId: saved.id, timezone: '' });
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.geolocation, null); assert.equal(context.selectedLocation.addressResolved, false);
  assert.equal(context.network.ip, preview.network.ip);
});

test('confirmed group context is shared across consumers while unrelated profiles retain their own configuration', async (t) => {
  const { service, client } = await fixture(t, { networkProbe: new ProxyNetworkProbe({ transport: async () => networkGeo }) });
  const draft = { name: '网络分组', protocol: 'socks5', host: 'group.proxy.example', port: 1080 };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const selected = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'manual', confirmed: true, latitude: 40.7, longitude: -74.1 } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  await service.call('saveGroup', { name: '共同网络', proxyId: selected.id, proxyMode: 'enforced' });
  const first = await create(service, { group: '共同网络', timezone: 'Asia/Tokyo' });
  const second = await create(service, { group: '共同网络', timezone: 'Europe/Paris' });
  const unrelated = await create(service, { name: '独立环境', timezone: 'Asia/Tokyo' });
  const before = JSON.stringify(client.profiles);
  const one = await service.resolveWorkspaceContext(first.id), two = await service.resolveWorkspaceContext(second.id), other = await service.resolveWorkspaceContext(unrelated.id);
  assert.deepEqual(one.selectedLocation, two.selectedLocation); assert.deepEqual(one.geolocation, two.geolocation);
  assert.equal(one.timezone, preview.network.timezone); assert.equal(two.timezone, one.timezone);
  assert.equal(one.proxySource, 'group'); assert.equal(other.timezone, 'Asia/Tokyo'); assert.equal(other.selectedLocation, null);
  assert.equal(JSON.stringify(client.profiles), before);
  const savedSnapshot = await service.snapshot();
  assert.equal(savedSnapshot.profiles.find(row => row.id === first.id).timezoneOrigin, 'network-environment');
});

test('confirmed node launch refuses a failed fresh egress even when the legacy profile timezone is fixed', async (t) => {
  const networkProbe = new ProxyNetworkProbe({ transport: async () => networkGeo });
  const { service, client } = await fixture(t, { networkProbe });
  const draft = { name: '断线环境', protocol: 'http', host: 'proxy.example', port: 8080 };
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const selected = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  const profile = await create(service, { proxyId: selected.id, timezone: 'Asia/Tokyo' });
  await service.resolveWorkspaceContext(profile.id);
  networkProbe.transport = async () => { throw new Error('offline fixture'); };
  await assert.rejects(service.resolveWorkspaceContext(profile.id, { force: true }), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
  assert.equal(client.sessions.length, 0); assert.equal((await service.snapshot()).profiles[0].network.ok, false);
  assert.equal(service.workspaceContexts.get(profile.id).geolocation, null);
  const failed = (await service.snapshot()).profiles[0];
  assert.equal(failed.resolvedTimezone, null); assert.equal(failed.timezoneSource, null);
  assert.equal(failed.selectedLocation.timezone, preview.network.timezone, 'saved selection remains available for editing without becoming a verified runtime result');
});

test('same node moving to another region blocks resolve and browser launch while same-region IP rotation preserves confirmation', async (t) => {
  for (const mode of ['ip', 'manual']) {
    let actual = { ...networkGeo, latitude: 40.7, longitude: -74.1 };
    const networkProbe = new ProxyNetworkProbe({ transport: async () => structuredClone(actual) });
    const { service, client } = await fixture(t, { networkProbe });
    const draft = { name: `确认-${mode}`, protocol: 'socks5', host: 'proxy.example', port: 1080 };
    const preview = await service.call('previewProxyNetwork', { proxy: draft });
    const selected = (await service.call('saveProxy', { proxy: { ...draft, location: { mode, confirmed: true, ...(mode === 'manual' ? { label: 'Chosen pin', latitude: 40.8, longitude: -74.2 } : {}) } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
    const profile = await create(service, { proxyId: selected.id, timezone: 'Asia/Tokyo' });
    const original = structuredClone((await service.store.read()).proxies[0]);
    const first = await service.resolveWorkspaceContext(profile.id);
    actual = { ...actual, ip: '1.1.1.1', city: 'Different city', latitude: 41, longitude: -75 };
    const rotated = await service.resolveWorkspaceContext(profile.id);
    assert.equal(rotated.network.ip, '1.1.1.1', 'confirmed contexts force a fresh probe rather than reusing a cached IP');
    assert.deepEqual(rotated.selectedLocation, first.selectedLocation); assert.deepEqual(rotated.geolocation, first.geolocation); assert.equal(rotated.timezone, first.timezone);
    for (const moved of [{ ...actual, timezone: { id: 'America/Los_Angeles' } }, { ...actual, country_code: 'CA' }]) {
      actual = moved;
      await assert.rejects(service.resolveWorkspaceContext(profile.id), { code: 'NETWORK_LOCATION_RECONFIRM_REQUIRED' });
      await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'NETWORK_LOCATION_RECONFIRM_REQUIRED' });
      assert.equal(client.sessions.length, 0);
      assert.equal(service.workspaceContexts.get(profile.id).geolocation, null);
      assert.match(service.workspaceContexts.get(profile.id).networkLastError, /重新检测并确认/);
      assert.deepEqual((await service.store.read()).proxies[0], original);
    }
    const reconfirm = await service.call('previewProxyNetwork', { proxy: original });
    const updated = (await service.call('saveProxy', { proxy: original, locationPreviewToken: reconfirm.locationPreviewToken })).proxies[0];
    assert.equal(updated.location.timezone, actual.timezone.id); assert.equal(updated.location.countryCode, actual.country_code);
    const ready = await service.resolveWorkspaceContext(profile.id);
    assert.equal(ready.timezone, actual.timezone.id);
    if (mode === 'manual') assert.deepEqual(ready.geolocation, first.geolocation, 'explicit reconfirmation updates region proof while retaining the user selected pin');
  }
});

test('legacy unconfirmed node metadata keeps the original profile timezone behavior', async (t) => {
  const { service } = await fixture(t, { networkProbe: new ProxyNetworkProbe({ transport: async () => networkGeo }) });
  const proxy = await savedProxy(service);
  await service.store.transaction(workspace => { workspace.proxies[0].location = { mode: 'ip', confirmed: false, timezone: 'Asia/Manila' }; });
  const profile = await create(service, { proxyId: proxy.id, timezone: 'Asia/Tokyo' });
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.timezone, 'Asia/Tokyo'); assert.equal(context.timezoneSource, 'manual'); assert.equal(context.selectedLocation, null);
});

test('egress checks cache saved configuration, exclude network cache from export, and do not save drafts', async (t) => {
  let requests = 0;
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { requests++; return networkGeo; } });
  const { service } = await fixture(t, { networkProbe });
  const proxy = await savedProxy(service);
  const result = await service.call('checkProxy', { id: proxy.id });
  assert.equal(result.scope, 'egress'); assert.equal(result.ip, '8.8.8.8'); assert.equal(result.ok, true);
  assert.equal((await service.snapshot()).proxies[0].network.timezone, 'America/New_York');
  const before = JSON.stringify(await service.store.read());
  const draft = await service.call('checkProxy', { proxy: { protocol: 'socks5', host: 'draft.example', port: 1080, username: 'draft-user', password: 'draft-password', endpoint: 'https://evil.invalid/' } });
  assert.equal(draft.ok, true); assert.equal(JSON.stringify(await service.store.read()), before);
  await create(service, { proxyId: proxy.id });
  const exported = await service.call('exportProfiles');
  assert.equal(JSON.stringify(exported).includes('network'), false); assert.equal(JSON.stringify(result).includes('dummy-password'), false);
  const updated = await savedProxy(service, { id: proxy.id, password: 'new-password' });
  assert.equal(updated.network, null, 'credential edits invalidate cached egress');
  assert.equal(requests, 2);
});

test('automatic timezone resolves an enforced group proxy and sends a transient launch override', async (t) => {
  const inputs = [];
  const managed = managedProxyFixture();
  const networkProbe = new ProxyNetworkProbe({ transport: async () => networkGeo });
  const probe = networkProbe.probe.bind(networkProbe);
  networkProbe.probe = (proxy, options) => { inputs.push({ proxy: structuredClone(proxy), options }); return probe(proxy, options); };
  const { service, client } = await fixture(t, { ...managed, networkProbe });
  const ownProxy = await savedProxy(service, { name: '个人出口', host: 'own.example' });
  const groupProxy = await savedProxy(service, { name: '分组出口', host: 'group.example', password: 'group-password' });
  await service.call('saveGroup', { name: '强制分组', proxyId: groupProxy.id, proxyMode: 'enforced' });
  const profile = await create(service, { group: '强制分组', proxyId: ownProxy.id, timezone: '' });
  const started = await service.call('startProfile', { id: profile.id });
  assert.equal(managed.calls[0].host, 'group.example'); assert.equal(managed.calls[0].password, 'group-password');
  assert.equal(inputs[0].proxy.host, '127.0.0.1'); assert.equal(inputs[0].options.force, true);
  const { proxy: launchProxy, ...overrides } = client.requests.find((request) => request.route === '/api/sessions' && request.method === 'POST').body.launch_overrides;
  assert.deepEqual(overrides, { timezone: 'America/New_York', locale: 'zh-CN', country_code: 'US', privacy: { mode: 'standard' }, geolocation: null });
  assert.deepEqual(launchProxy, { type: 'http', host: inputs[0].proxy.host, port: inputs[0].proxy.port, username: inputs[0].proxy.username, password: inputs[0].proxy.password });
  assert.equal(client.profiles[0].launch_overrides.timezone, '', 'stored profile remains automatic');
  assert.equal(started.profiles[0].resolvedTimezone, 'America/New_York'); assert.equal(started.profiles[0].timezoneSource, 'proxy');
  assert.equal(started.profiles[0].network.ip, '8.8.8.8');
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.proxy.password, inputs[0].proxy.password); assert.equal(context.proxySource, 'group'); assert.equal(context.timezone, 'America/New_York');
  await assert.rejects(service.call('resolveWorkspaceContext', { id: profile.id }), { code: 'UNKNOWN_METHOD' });
  await assert.rejects(service.call('getWorkspaceContext', { id: profile.id }), { code: 'UNKNOWN_METHOD' });
  assert.equal(JSON.stringify(started.profiles[0].network).includes('group-password'), false);
});

test('automatic locale and regional location use the detected egress and remain transient launch values', async (t) => {
  const networkProbe = new ProxyNetworkProbe({ transport: async () => ({ ...networkGeo, country: 'Philippines', country_code: 'PH', timezone: { id: 'Asia/Manila' }, latitude: 14.6, longitude: 121 }) });
  const { service, client } = await fixture(t, { networkProbe });
  const proxy = await savedProxy(service);
  const profile = await create(service, { proxyId: proxy.id, timezone: '', locale: '' });
  const before = structuredClone(client.profiles[0]);
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.timezone, 'Asia/Manila'); assert.equal(context.timezoneSource, 'proxy'); assert.equal(context.locale, 'en-PH');
  assert.deepEqual(context.geolocation, { latitude: 14.6, longitude: 121, accuracy: 50000 });
  await service.call('startProfile', { id: profile.id });
  const launch = client.requests.find(request => request.route === '/api/sessions' && request.method === 'POST').body.launch_overrides;
  assert.deepEqual(launch, { timezone: 'Asia/Manila', locale: 'en-PH', country_code: 'PH', privacy: { mode: 'standard' }, geolocation: context.geolocation, proxy: { type: 'http', host: context.proxy.host, port: context.proxy.port, username: context.proxy.username, password: context.proxy.password } });
  assert.deepEqual(client.profiles[0], before, 'resolved egress values must not change the stored automatic configuration');
  const exported = await service.call('exportProfiles');
  assert.equal(JSON.stringify(exported).includes('latitude'), false);
});

test('fixed timezone and locale remain independent from a successful egress location', async (t) => {
  const networkProbe = new ProxyNetworkProbe({ transport: async () => ({ ...networkGeo, latitude: 40.7, longitude: -74 }) });
  const { service, client } = await fixture(t, { networkProbe });
  const proxy = await savedProxy(service);
  const profile = await create(service, { proxyId: proxy.id, timezone: 'Europe/Berlin', locale: 'de-DE' });
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.network.timezone, 'America/New_York'); assert.equal(context.timezone, 'Europe/Berlin'); assert.equal(context.timezoneSource, 'manual'); assert.equal(context.locale, 'de-DE');
  assert.deepEqual(context.geolocation, { latitude: 40.7, longitude: -74, accuracy: 50000 });
  await service.call('startProfile', { id: profile.id });
  const launch = client.requests.find(request => request.route === '/api/sessions' && request.method === 'POST').body.launch_overrides;
  assert.equal(launch.timezone, 'Europe/Berlin'); assert.equal(launch.locale, 'de-DE'); assert.deepEqual(launch.geolocation, context.geolocation);
  assert.equal(client.profiles[0].launch_overrides.timezone, 'Europe/Berlin'); assert.equal(client.profiles[0].launch_overrides.locale, 'de-DE');
});

test('failed proxy geolocation blocks automatic launch without direct fallback and manual timezone remains usable', async (t) => {
  const inputs = [];
  const networkProbe = new ProxyNetworkProbe({ endpoints: [{ url: 'https://ipwho.is/', source: 'ipwho.is', format: 'ipwho' }], transport: async () => { throw new Error('credentials dummy-user:dummy-password must not appear'); } });
  const probe = networkProbe.probe.bind(networkProbe);
  networkProbe.probe = (proxy, options) => { inputs.push(proxy); return probe(proxy, options); };
  const { service, client } = await fixture(t, { networkProbe });
  const proxy = await savedProxy(service);
  const profile = await create(service, { proxyId: proxy.id, timezone: '' });
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'AUTO_TIMEZONE_FAILED' });
  assert.equal(client.requests.some((request) => request.route === '/api/sessions' && request.method === 'POST'), false);
  assert.ok(inputs.every((input) => input?.host === '127.0.0.1' && input.username && input.password && input.password !== 'dummy-password'));
  const failed = (await service.snapshot()).profiles[0];
  assert.equal(failed.status, 'error'); assert.equal(failed.network.ok, false); assert.match(failed.networkLastError, /HTTPS/);
  assert.equal(JSON.stringify(failed).includes('dummy-password'), false);
  await service.call('updateProfile', { id: profile.id, profile: { timezone: 'Asia/Shanghai' } });
  const started = await service.call('startProfile', { id: profile.id });
  assert.equal(inputs.length, 2, 'fixed timezone still checks the selected egress for location while preserving manual timezone');
  assert.equal(started.profiles[0].resolvedTimezone, 'Asia/Shanghai'); assert.equal(started.profiles[0].timezoneSource, 'manual');
  assert.equal(client.profiles[0].launch_overrides.timezone, 'Asia/Shanghai');
  assert.equal(client.requests.find((request) => request.route === '/api/sessions' && request.method === 'POST').body.launch_overrides.geolocation, null);
  assert.equal(started.profiles[0].network.ok, false);
});

test('direct automatic lookup uses explicit direct routing and failure is labeled local without changing process timezone', async (t) => {
  const inputs = [], originalTZ = process.env.TZ;
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { throw new Error('offline'); } });
  const probe = networkProbe.probe.bind(networkProbe);
  networkProbe.probe = (proxy, options) => { inputs.push(proxy); return probe(proxy, options); };
  const { service, client } = await fixture(t, { networkProbe });
  const profile = await create(service, { timezone: '' });
  const started = await service.call('startProfile', { id: profile.id });
  assert.deepEqual(inputs, [null]); assert.equal(started.profiles[0].timezoneSource, 'local');
  assert.equal(started.profiles[0].network.ok, false); assert.ok(started.profiles[0].networkLastError);
  assert.equal(started.profiles[0].resolvedTimezone, Intl.DateTimeFormat().resolvedOptions().timeZone);
  assert.equal(process.env.TZ, originalTZ); assert.equal(client.profiles[0].launch_overrides.timezone, '');
});

test('direct successful geolocation is labeled direct and automatic starts refresh previous checks', async (t) => {
  let hits = 0;
  const networkProbe = new ProxyNetworkProbe({ transport: async ({ agent }) => { assert.equal(agent, false); hits++; return { ...networkGeo, timezone: { id: hits === 1 ? 'America/New_York' : 'America/Los_Angeles' } }; } });
  const { service, client } = await fixture(t, { networkProbe });
  const profile = await create(service, { timezone: '' });
  const initial = await service.resolveWorkspaceContext(profile.id);
  assert.equal(initial.timezoneSource, 'direct'); assert.equal(initial.timezone, 'America/New_York');
  const started = await service.call('startProfile', { id: profile.id });
  assert.equal(hits, 2, 'browser launch must verify current egress instead of trusting an earlier check');
  assert.equal(started.profiles[0].resolvedTimezone, 'America/Los_Angeles'); assert.equal(started.profiles[0].timezoneSource, 'direct');
  assert.equal(client.profiles[0].launch_overrides.timezone, '');
});

test('a stale in-flight check cannot attach old egress information to an edited proxy', async (t) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const networkProbe = new ProxyNetworkProbe({ transport: async () => { await gate; return networkGeo; } });
  const { service } = await fixture(t, { networkProbe });
  const proxy = await savedProxy(service);
  const pending = service.call('checkProxy', { id: proxy.id });
  while (!networkProbe.inflight.size) await new Promise((resolve) => setImmediate(resolve));
  await savedProxy(service, { id: proxy.id, password: 'new-password' });
  release(); await pending;
  assert.equal((await service.snapshot()).proxies[0].network, null);
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

const anytlsConfig = (patch = {}) => ({ name: '内置 AnyTLS', protocol: 'anytls', host: 'node.example.test', port: 443, password: 'fixture-raw-password', region: 'jp-tokyo', serverName: 'tls.example.test', skipCertVerify: false, clientFingerprint: 'chrome', ...patch });
function managedProxyFixture() {
  const calls = [], releases = [], wires = new Map(), probes = [];
  let count = 0;
  const proxyCore = {
    async ensure(proxy) { calls.push(structuredClone(proxy)); if (this.failure) throw Object.assign(new Error(`fixture failure ${proxy.password}`), { code: 'PROXY_CORE_FAILED' }); if (!wires.has(proxy.id)) wires.set(proxy.id, { protocol: 'http', host: '127.0.0.1', port: 20000 + ++count, username: `wire-user-${count}`, password: `wire-secret-${count}`, region: proxy.region }); return structuredClone(wires.get(proxy.id)); },
    async release(id) { releases.push(id); wires.delete(id); },
    async close() { this.closed = true; wires.clear(); },
  };
  const networkProbe = {
    peek() { return null; }, invalidate() {}, close() {},
    async probe(proxy, options) { probes.push({ proxy: structuredClone(proxy), options }); return this.failure ? { ok: false, message: 'fixture egress unavailable', timezone: null } : { ok: true, timezone: 'Asia/Tokyo', ip: '203.0.113.8', city: 'fixture', checkedAt: new Date().toISOString() }; },
  };
  return { proxyCore, networkProbe, calls, releases, wires, probes };
}

test('AnyTLS location preview uses an owned authenticated route and releases only its draft core', async (t) => {
  const managed = managedProxyFixture();
  const originalProbe = managed.networkProbe.probe.bind(managed.networkProbe);
  managed.networkProbe.probe = async (...args) => ({ ...(await originalProbe(...args)), scope: 'egress', countryCode: 'JP', country: 'Japan', geolocation: { latitude: 35.6, longitude: 139.7, accuracy: 50000 } });
  const referenceLocation = { kind: 'nearby-reference', label: 'Example Street', latitude: 35.61, longitude: 139.71, source: 'Photon', attribution: '© OpenStreetMap contributors' };
  const { service } = await fixture(t, { ...managed, addressGeocoder: { close() {}, async reverse({ proxy: wire }) {
    assert.deepEqual(wire, managed.probes.at(-1).proxy, 'reverse reuses the exact wire that verified egress');
    assert.equal(managed.wires.has(managed.calls.at(-1).id), true, 'the owned draft remains active until reverse completes');
    return referenceLocation;
  } } });
  const saved = (await service.call('saveProxy', { proxy: anytlsConfig({ name: '已保存' }) })).proxies[0];
  const profile = await create(service, { proxyId: saved.id, timezone: '' });
  await service.resolveWorkspaceContext(profile.id);
  assert.equal(managed.wires.has(saved.id), true);
  const before = JSON.stringify(await service.store.read());
  const draft = anytlsConfig({ name: '新位置', host: 'draft.example.test', alpn: ['h2', 'http/1.1'], udp: false });
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  assert.ok(preview.locationPreviewToken); assert.equal(preview.locationRecommendation.timezone, 'Asia/Tokyo');
  assert.deepEqual(preview.referenceLocation, referenceLocation);
  assert.equal(managed.wires.size, 1); assert.equal(managed.wires.has(saved.id), true);
  const created = managed.calls.at(-1);
  assert.match(created.id, /^draft_/); assert.deepEqual(created.alpn, draft.alpn); assert.equal(created.udp, false); assert.equal(created.serverName, draft.serverName);
  assert.deepEqual(managed.releases, [created.id]);
  const wire = managed.probes.at(-1).proxy;
  assert.equal(wire.host, '127.0.0.1'); assert.notEqual(wire.password, draft.password);
  assert.equal(JSON.stringify(preview).includes(draft.password), false); assert.equal(JSON.stringify(preview).includes(wire.password), false);
  assert.equal(JSON.stringify(await service.store.read()), before);
  service.addressGeocoder.reverse = async () => { throw new Error('fixture reverse unavailable'); };
  const fallback = await service.call('previewProxyNetwork', { proxy: draft });
  assert.ok(fallback.locationPreviewToken); assert.equal(fallback.referenceLocation, null);
  assert.equal(managed.releases.length, 2); assert.equal(managed.wires.size, 1); assert.equal(managed.wires.has(saved.id), true);
});

test('managed core death cannot refill a resolved timezone from the saved network selection', async (t) => {
  const managed = managedProxyFixture();
  const originalProbe = managed.networkProbe.probe.bind(managed.networkProbe);
  managed.networkProbe.probe = async (...args) => ({ ...(await originalProbe(...args)), scope: 'egress', countryCode: 'JP', country: 'Japan', geolocation: { latitude: 35.6, longitude: 139.7, accuracy: 50000 } });
  const { service } = await fixture(t, managed);
  const draft = anytlsConfig();
  const preview = await service.call('previewProxyNetwork', { proxy: draft });
  const selected = (await service.call('saveProxy', { proxy: { ...draft, location: { mode: 'ip', confirmed: true } }, locationPreviewToken: preview.locationPreviewToken })).proxies[0];
  const profile = await create(service, { proxyId: selected.id, timezone: 'America/New_York' });
  await service.resolveWorkspaceContext(profile.id);
  assert.equal((await service.snapshot()).profiles[0].resolvedTimezone, 'Asia/Tokyo');
  service.invalidateManagedProxy(selected.id);
  const failed = (await service.snapshot()).profiles[0];
  assert.equal(failed.resolvedTimezone, null); assert.equal(failed.timezoneSource, null); assert.equal(failed.geolocation, null);
  assert.equal(failed.selectedLocation.timezone, 'Asia/Tokyo'); assert.equal(failed.network.ok, false);
});

test('AnyTLS raw configuration and stable profile bindings survive reopen without native wire credentials', async (t) => {
  const managed = managedProxyFixture();
  const { service, client, directory, profilesDir } = await fixture(t, managed);
  const proxy = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: proxy.id, timezone: '' });
  assert.equal(profile.proxyId, proxy.id); assert.equal(profile.profileProxyId, proxy.id);
  assert.equal(client.profiles[0].proxy, null); assert.equal(managed.calls.length, 0);
  const persisted = await service.store.read();
  assert.equal(persisted.proxies[0].password, 'fixture-raw-password');
  assert.equal(persisted.profiles[0].proxyId, proxy.id);
  await service.shutdown();
  const reopened = new BrowseForgeService(directory, client, {}, () => {}, { profilesDir, ...managed });
  assert.equal((await reopened.snapshot()).profiles[0].proxyId, proxy.id);
  await reopened.shutdown();
  assert.equal(JSON.stringify(client.profiles).includes('wire-secret'), false);
});

test('AnyTLS browser and terminal contexts use the same authenticated internal HTTP bridge and transient timezone', async (t) => {
  const managed = managedProxyFixture();
  const { service, client } = await fixture(t, managed);
  const proxy = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: proxy.id, timezone: '' });
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.managedProxy, true); assert.equal(context.timezone, 'Asia/Tokyo');
  assert.equal(context.timezoneSource, 'proxy'); assert.equal(context.proxy.protocol, 'http');
  assert.equal(context.proxy.host, '127.0.0.1'); assert.notEqual(context.proxy.password, proxy.password);
  await service.call('startProfile', { id: profile.id });
  const request = client.requests.find((row) => row.route === '/api/sessions' && row.method === 'POST');
  assert.deepEqual(request.body.launch_overrides, { timezone: context.timezone, locale: 'zh-CN', privacy: { mode: 'standard' }, geolocation: null, proxy: { type: 'http', host: context.proxy.host, port: context.proxy.port, username: context.proxy.username, password: context.proxy.password, region: 'jp-tokyo' } });
  assert.ok(managed.probes.every((row) => row.proxy.protocol === 'http' && row.proxy.port === context.proxy.port && row.proxy.password === context.proxy.password));
  assert.equal(client.profiles[0].proxy, null);
  const persisted = JSON.stringify(await service.store.read());
  assert.equal(persisted.includes(context.proxy.password), false); assert.equal(persisted.includes(context.proxy.username), false);
  const snapshot = JSON.stringify(await service.snapshot());
  assert.equal(snapshot.includes(context.proxy.password), false); assert.equal(snapshot.includes(context.proxy.username), false);
  assert.ok(managed.calls.every((row) => row.id === proxy.id && row.protocol === 'anytls'));
});

test('HTTP browser, terminal and application routes share one owned core while saved bindings keep their upstream', async t => {
  for (const protocol of ['http', 'https', 'socks5']) {
    const managed = managedProxyFixture();
    managed.proxyCore.routingIdentity = id => managed.wires.has(id) ? { proxyId: id, nodeType: protocol, routeIdentity: 'owned-route', corePid: 12345, coreGeneration: 'owned-generation', coreVersion: 'v1.19.32' } : null;
    const { service, client } = await fixture(t, managed);
    const proxy = await savedProxy(service, { protocol });
    const profile = await create(service, { proxyId: proxy.id });
    const before = structuredClone(client.profiles[0]), saved = JSON.stringify(await service.store.read());
    const ordinary = await service.resolveWorkspaceContext(profile.id);
    assert.equal(ordinary.managedProxy, protocol !== 'socks5');
    assert.equal(ordinary.proxy.host, protocol === 'socks5' ? proxy.host : '127.0.0.1');
    assert.equal(managed.calls.length, protocol === 'socks5' ? 0 : 1);
    const application = await service.resolveWorkspaceContext(profile.id, { force: true, requireManagedRoute: true });
    assert.equal(application.managedProxy, true); assert.equal(application.proxy.host, '127.0.0.1');
    assert.equal(application.applicationRoute.protocol, 'socks5'); assert.equal(application.applicationRoute.udp, protocol === 'socks5');
    assert.equal(application.applicationRoute.udpPolicy, protocol === 'socks5' ? 'proxy' : 'block');
    assert.equal(application.managedRoute.nodeType, protocol); assert.equal(application.managedRoute.profileId, profile.id);
    if (protocol !== 'socks5') assert.deepEqual(ordinary.proxy, application.proxy);
    assert.equal(managed.probes.at(-1).proxy.password, application.applicationRoute.password);
    assert.deepEqual(client.profiles[0], before); assert.equal(JSON.stringify(await service.store.read()), saved);
    assert.equal(JSON.stringify(await service.snapshot()).includes(application.proxy.password), false);
    service.invalidateManagedProxy(proxy.id);
    assert.equal((await service.snapshot()).profiles[0].network.ok, false);
    await service.releaseProxy(proxy); assert.equal(managed.wires.has(proxy.id), false);
  }
});

test('HTTP and HTTPS require the owned core even with a fixed manual timezone', async t => {
  for (const protocol of ['http', 'https']) {
    const managed = managedProxyFixture();
    const { service, client } = await fixture(t, { ...managed, proxyCore: null });
    const proxy = await savedProxy(service, { protocol });
    const profile = await create(service, { proxyId: proxy.id });
    await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'PROXY_CORE_UNAVAILABLE' });
    await assert.rejects(service.call('checkProxy', { id: proxy.id }), { code: 'PROXY_CORE_UNAVAILABLE' });
    assert.equal(client.sessions.length, 0); assert.equal(managed.probes.length, 0);
  }
});

test('HTTP compatibility diagnostics are public snapshot data and never saved or exported', async t => {
  const managed = managedProxyFixture();
  const diagnostics = { enabled: true, recoveredConnections: 3, failedConnections: 1, lastErrorCode: 'UPSTREAM_CONNECT_FAILED', lastUpstreamStatus: 502 };
  managed.proxyCore.compatibilitySnapshot = id => managed.wires.has(id) ? structuredClone(diagnostics) : null;
  const { service } = await fixture(t, managed);
  const proxy = await savedProxy(service), profile = await create(service, { proxyId: proxy.id });
  assert.equal((await service.snapshot()).proxies[0].compatibility, null);
  await service.resolveWorkspaceContext(profile.id);
  const publicProxy = (await service.snapshot()).proxies[0];
  assert.deepEqual(publicProxy.compatibility, diagnostics);
  await service.call('saveProxy', { proxy: { ...publicProxy, name: 'Edited name' } });
  assert.equal(JSON.stringify(await service.store.read()).includes('compatibility'), false);
  assert.equal(JSON.stringify(await service.call('exportProfiles')).includes('recoveredConnections'), false);
});

test('HTTP and HTTPS draft checks, previews and address searches release only their owned temporary cores', async t => {
  for (const protocol of ['http', 'https']) {
    const managed = managedProxyFixture(), lookups = [];
    const probe = managed.networkProbe.probe.bind(managed.networkProbe);
    managed.networkProbe.probe = async (...args) => ({ ...await probe(...args), scope: 'egress', countryCode: 'JP', country: 'Japan', geolocation: { latitude: 35.6, longitude: 139.7, accuracy: 50000 } });
    const addressGeocoder = { close() {}, async reverse(input) { lookups.push(input); this.onReverse?.(); return null; }, async search(input) { lookups.push(input); this.onSearch?.(); if (this.failure) throw new Error('fixture address lookup failed'); return [{ label: 'Tokyo', latitude: 35.6, longitude: 139.7 }]; } };
    const { service } = await fixture(t, { ...managed, addressGeocoder });
    const saved = await savedProxy(service, { protocol }), profile = await create(service, { proxyId: saved.id });
    const context = await service.resolveWorkspaceContext(profile.id), before = JSON.stringify(await service.store.read());
    const draft = { protocol, host: 'draft.example', port: 8443, username: 'draft-user', password: 'draft-password' };
    const preview = await service.call('previewProxyNetwork', { proxy: draft });
    assert.ok(preview.locationPreviewToken); assert.equal(managed.releases.length, 1);
    await service.call('checkProxy', { proxy: draft });
    assert.equal(managed.releases.length, 2);
    await service.call('checkProxy', { id: saved.id });
    assert.equal(managed.releases.length, 2, 'saved checks retain the shared route');
    await service.call('searchNetworkAddress', { proxy: draft, locationPreviewToken: preview.locationPreviewToken, query: 'Tokyo' });
    assert.equal(managed.releases.length, 3);
    addressGeocoder.onSearch = () => service.invalidateManagedProxy(managed.calls.at(-1).id);
    await assert.rejects(service.call('searchNetworkAddress', { proxy: draft, locationPreviewToken: preview.locationPreviewToken, query: 'Tokyo' }), { code: 'PROXY_CORE_STOPPED' });
    delete addressGeocoder.onSearch;
    addressGeocoder.onReverse = () => service.invalidateManagedProxy(managed.calls.at(-1).id);
    await assert.rejects(service.call('previewProxyNetwork', { proxy: draft }), { code: 'PROXY_CORE_STOPPED' });
    delete addressGeocoder.onReverse;
    assert.equal(managed.releases.length, 5, 'invalidation during either map callback cannot retain a draft or accept stale results');
    addressGeocoder.failure = true;
    await assert.rejects(service.call('searchNetworkAddress', { proxy: draft, locationPreviewToken: preview.locationPreviewToken, query: 'Tokyo' }), /fixture address lookup failed/);
    assert.equal(managed.releases.length, 6);
    managed.proxyCore.failure = true;
    await assert.rejects(service.call('checkProxy', { proxy: draft }), value => value.code === 'PROXY_CORE_FAILED' && !value.message.includes(draft.password));
    assert.equal(managed.releases.length, 7);
    assert.ok(managed.releases.every(id => id.startsWith('draft_')));
    assert.ok(lookups.every(input => input.proxy.host === '127.0.0.1' && input.proxy.username && input.proxy.password !== draft.password));
    assert.deepEqual([...managed.wires.keys()], [saved.id]); assert.deepEqual(managed.wires.get(saved.id), context.proxy);
    assert.equal(JSON.stringify(await service.store.read()), before);
  }
});

test('managed HTTP launch receipts retain the stored marker and never persist runtime credentials', async t => {
  for (const [protocol, marker] of [['http', false], ['https', false], ['http', undefined], ['anytls', false]]) {
    const managed = managedProxyFixture();
    const { service, client } = await fixture(t, managed);
    const proxy = protocol === 'anytls' ? (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0] : await savedProxy(service, { protocol });
    const profile = await create(service, { proxyId: proxy.id });
    if (marker === undefined) delete client.profiles[0].managed_proxy_required; else client.profiles[0].managed_proxy_required = marker;
    const before = structuredClone(client.profiles[0]), request = client.request.bind(client);
    let launchedProxy;
    client.request = async (method, route, body, options) => {
      if (route.endsWith('/identity')) {
        const digest = createHash('sha256').update('envara-browser-route-v1\0');
        for (const field of [launchedProxy.type, launchedProxy.host, String(launchedProxy.port), launchedProxy.username, launchedProxy.password]) digest.update(`${Buffer.byteLength(field)}:`).update(field);
        return { data: { instance_id: client.sessions[0].instance_id, route_digest: digest.digest('hex') } };
      }
      if (route === '/api/playwright/endpoint') return { data: client.sessions.map(session => ({ ...session, endpoint: 'ws://127.0.0.1:28000/fixture' })) };
      const response = await request(method, route, body, options);
      if (route === '/api/sessions' && method === 'POST') { launchedProxy = body.launch_overrides.proxy; response.data.instance_id = '1'.repeat(32); client.sessions[0].instance_id = response.data.instance_id; }
      return response;
    };
    const context = await service.resolveWorkspaceContext(profile.id);
    await service.call('startProfile', { id: profile.id });
    assert.ok(service.browserLaunchReceipts.has(profile.id));
    assert.equal((await service.ensureBoundBrowser({ profileId: profile.id, expectedContext: context })).profile_id, profile.id);
    assert.deepEqual(client.profiles[0], protocol === 'anytls' ? { ...before, managed_proxy_required: true } : before);
    assert.equal(launchedProxy.host, '127.0.0.1'); assert.equal(launchedProxy.password, context.proxy.password);
    for (const value of [await service.store.read(), await service.snapshot(), await service.call('exportProfiles'), client.profiles]) {
      assert.equal(JSON.stringify(value).includes(context.proxy.password), false);
      assert.equal(JSON.stringify(value).includes(context.proxy.username), false);
    }
  }
});

test('legacy inline HTTP routes acquire their existing synthetic identity without rewriting native configuration', async t => {
  for (const protocol of ['http', 'https']) for (const source of ['profile', 'group', 'bound-inline']) {
    const managed = managedProxyFixture();
    const { service, client } = await fixture(t, managed);
    const profile = await create(service, { group: source === 'group' ? 'Legacy' : '', proxyId: null });
    const native = { type: protocol, host: 'legacy.example', port: 8443, username: 'legacy-user', password: 'legacy-password', region: 'jp-tokyo' };
    if (source === 'group') client.groups.push({ name: 'Legacy', proxy_mode: 'enforced', proxy: native });
    else client.profiles[0].proxy = native;
    await service.store.transaction(workspace => { workspace.profiles = source === 'bound-inline' ? [{ id: profile.id, proxyId: `inline_${profile.id}` }] : []; });
    const before = structuredClone({ profiles: client.profiles, groups: client.groups }), stored = JSON.stringify(await service.store.read());
    const expectedId = (await service.snapshot()).proxies[0].id;
    const context = await service.resolveWorkspaceContext(profile.id);
    assert.equal(context.proxyId, expectedId); assert.equal(context.managedProxy, true); assert.equal(context.proxy.host, '127.0.0.1');
    assert.equal(managed.calls[0].id, expectedId); assert.equal(managed.calls[0].protocol, protocol);
    assert.deepEqual({ profiles: client.profiles, groups: client.groups }, before); assert.equal(JSON.stringify(await service.store.read()), stored);
    service.invalidateManagedProxy(expectedId);
    assert.equal((await service.snapshot()).profiles[0].network.ok, false);
  }
});

test('legacy native routes borrow an existing node ID without inheriting its confirmed location', async t => {
  const managed = managedProxyFixture();
  const { service, client } = await fixture(t, managed);
  const saved = await savedProxy(service, { region: 'jp-tokyo' });
  const profile = await create(service, { proxyId: null, timezone: 'Europe/Berlin', locale: 'de-DE' });
  client.profiles[0].proxy = { type: saved.protocol, host: saved.host, port: saved.port, username: saved.username, password: saved.password, region: saved.region };
  await service.store.transaction(workspace => { workspace.proxies[0].location = { mode: 'manual', confirmed: true, countryCode: 'JP', timezone: 'Asia/Tokyo', label: 'Saved-only map pin', latitude: 35.6, longitude: 139.7 }; });
  const native = structuredClone(client.profiles[0]);
  const context = await service.resolveWorkspaceContext(profile.id);
  assert.equal(context.proxyId, saved.id); assert.equal(context.timezone, 'Europe/Berlin');
  assert.equal(context.selectedLocation, null); assert.equal(context.geolocation, null);
  assert.equal((await service.snapshot()).profiles[0].network.ok, true, 'the runtime context keeps the native configuration signature');
  service.invalidateManagedProxy(saved.id);
  assert.equal((await service.snapshot()).profiles[0].network.ok, false);
  assert.deepEqual(client.profiles[0], native);
});

test('HTTP and HTTPS core invalidation blocks stale results and focus restores only the existing session', async t => {
  for (const protocol of ['http', 'https']) {
    const managed = managedProxyFixture();
    const { service, client } = await fixture(t, managed);
    const proxy = await savedProxy(service, { protocol }), profile = await create(service, { proxyId: proxy.id });
    await service.call('startProfile', { id: profile.id });
    const originalProbe = managed.networkProbe.probe.bind(managed.networkProbe);
    for (const operation of [() => service.call('checkProxy', { id: proxy.id }), () => service.resolveWorkspaceContext(profile.id, { force: true })]) {
      let entered, finish;
      const started = new Promise(resolve => { entered = resolve; });
      managed.networkProbe.probe = async () => { entered(); return new Promise(resolve => { finish = () => resolve({ ok: true, timezone: 'Asia/Tokyo', ip: '203.0.113.8' }); }); };
      const pending = operation();
      await started; service.invalidateManagedProxy(proxy.id); finish();
      await assert.rejects(pending, { code: 'PROXY_CORE_STOPPED' });
      assert.equal((await service.snapshot()).profiles[0].network.ok, false);
    }
    managed.networkProbe.probe = originalProbe;
    const previousCalls = managed.calls.length;
    await service.call('focusProfile', { id: profile.id });
    assert.equal(managed.calls.length, previousCalls + 1); assert.equal((await service.snapshot()).profiles[0].network.ok, true);
    assert.equal(client.requests.filter(row => row.method === 'POST' && row.route === '/api/sessions').length, 1);
  }
});

test('application route creation fails closed on absent bindings, core failure and missing ownership', async t => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const unbound = await create(service, { proxyId: null });
  await assert.rejects(service.resolveWorkspaceContext(unbound.id, { requireManagedRoute: true }), { code: 'MANAGED_PROXY_BINDING_MISSING' });
  assert.equal(managed.probes.length, 0);
  const proxy = await savedProxy(service), profile = await create(service, { proxyId: proxy.id });
  managed.proxyCore.failure = true;
  await assert.rejects(service.resolveWorkspaceContext(profile.id, { requireManagedRoute: true }), value => value.code === 'PROXY_CORE_FAILED' && !value.message.includes(proxy.password));
  assert.equal(managed.probes.length, 0);
  managed.proxyCore.failure = false;
  await assert.rejects(service.resolveWorkspaceContext(profile.id, { requireManagedRoute: true }), { code: 'INVALID_PROXY_CORE' });
  managed.proxyCore.routingIdentity = () => ({ proxyId: proxy.id, nodeType: proxy.protocol });
  const probe = managed.networkProbe.probe.bind(managed.networkProbe);
  managed.networkProbe.probe = async (...args) => { const result = await probe(...args); service.invalidateManagedProxy(proxy.id); return result; };
  await assert.rejects(service.resolveWorkspaceContext(profile.id, { requireManagedRoute: true }), { code: 'PROXY_CORE_STOPPED' });
});

test('HTTPS attachment selection creates an ungrouped owner and links its browser without a group-policy write', async t => {
  const managed = managedProxyFixture();
  managed.proxyCore.routingIdentity = id => ({ proxyId: id, nodeType: 'https' });
  const { service, client } = await fixture(t, managed);
  const proxy = await savedProxy(service, { protocol: 'https' });
  const initial = await service.snapshot();
  const choice = networkApplicationChoices(initial.proxies, initial.groups, initial.profiles).find(item => item.proxyId === proxy.id);
  assert.equal(choice.id, `node:${proxy.id}`); assert.equal(choice.group, '');
  assert.equal(chooseApplicationProfile(choice, initial.profiles, null), null);
  await create(service, { proxyId: choice.proxyId, group: choice.group });
  const created = await service.snapshot();
  const owner = createdProfileFromSnapshot(new Set(initial.profiles.map(item => item.id)), created, choice);
  assert.ok(owner); assert.equal(linkBrowsersFor(created.profiles, owner)[0].id, owner.id);
  const context = await service.resolveWorkspaceContext(owner.id, { requireManagedRoute: true });
  assert.equal(context.managedRoute.nodeType, 'https'); assert.equal(context.proxyId, proxy.id);
  assert.equal(client.requests.some(row => row.route.startsWith('/api/groups') && row.method !== 'GET'), false);
});

test('releasing AnyTLS invalidates only its supported wire while ordinary raw and managed measurements stay distinct', async t => {
  const managed = managedProxyFixture();
  const networkProbe = new ProxyNetworkProbe({ transport: async () => networkGeo });
  const { service } = await fixture(t, { ...managed, networkProbe });
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  await service.call('checkProxy', { proxy: anytlsConfig() });
  await service.resolveWorkspaceContext((await create(service, { proxyId: raw.id })).id);
  await service.releaseProxy(raw); assert.equal(managed.wires.has(raw.id), false);
  const ordinary = await savedProxy(service);
  managed.proxyCore.routingIdentity = id => ({ proxyId: id, nodeType: 'http' });
  await service.resolveWorkspaceContext((await create(service, { proxyId: ordinary.id })).id, { requireManagedRoute: true });
  networkProbe.transport = async () => { throw new Error('fixture offline'); };
  const result = await service.call('checkProxy', { id: ordinary.id });
  assert.equal(result.ok, false); assert.equal((await service.snapshot()).proxies.find(item => item.id === ordinary.id).network.ok, false);
});

test('AnyTLS group policy keeps enforced/default semantics across ordinary policy replacement and reopen', async (t) => {
  const managed = managedProxyFixture();
  const { service, client, directory, profilesDir } = await fixture(t, managed);
  const ordinary = await savedProxy(service);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies.find((row) => row.protocol === 'anytls');
  const own = await create(service, { group: '团队', proxyId: ordinary.id, timezone: '' });
  const inherits = await create(service, { name: '继承', group: '团队', timezone: '', proxyId: null });
  await service.call('saveGroup', { name: '团队', proxyId: ordinary.id, proxyMode: 'enforced' });
  assert.equal(client.groups[0].proxy.type, 'http');
  const enforced = await service.call('saveGroup', { name: '团队', proxyId: raw.id, proxyMode: 'enforced' });
  assert.ok(client.groups.every((row) => !row.proxy), 'old native policy must be cleared rather than storing a local wire');
  assert.ok(enforced.profiles.every((row) => row.proxyId === raw.id && row.proxySource === 'group' && row.proxyMode === 'enforced'));
  assert.equal(enforced.profiles.find((row) => row.id === own.id).profileProxyId, ordinary.id);
  await service.call('saveGroup', { name: '团队', proxyId: raw.id, proxyMode: 'default' });
  const defaultRows = (await service.snapshot()).profiles;
  assert.equal(defaultRows.find((row) => row.id === own.id).proxyId, ordinary.id);
  assert.equal(defaultRows.find((row) => row.id === inherits.id).proxyId, raw.id);
  await service.shutdown();
  const reopened = new BrowseForgeService(directory, client, {}, () => {}, { profilesDir, ...managed });
  assert.equal((await reopened.snapshot()).groups.find((row) => row.name === '团队').proxyId, raw.id);
  await reopened.call('clearGroupProxy', { name: '团队' });
  assert.equal((await reopened.snapshot()).profiles.find((row) => row.id === inherits.id).proxyId, null);
  await reopened.shutdown();
});

test('AnyTLS clone and credential-free export/import preserve explicit stable node mappings', async (t) => {
  const managed = managedProxyFixture();
  const { service, client } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id });
  const clone = await service.call('cloneProfile', { id: profile.id });
  assert.equal(clone.profiles.find((row) => row.id === clone.actionResult.createdId).proxyId, raw.id);
  assert.ok(client.profiles.every((row) => row.proxy === null));
  await service.resolveWorkspaceContext(profile.id);
  const document = await service.call('exportProfiles');
  const serialized = JSON.stringify(document);
  assert.equal(serialized.includes('fixture-raw-password'), false); assert.equal(serialized.includes('wire-secret'), false);
  assert.deepEqual(document.proxies[0], { id: raw.id, name: raw.name, protocol: 'anytls', host: raw.host, port: raw.port, region: raw.region, serverName: raw.serverName, skipCertVerify: false, clientFingerprint: 'chrome', alpn: [], udp: true, requiresCredentials: true });
  await assert.rejects(service.call('importProfiles', { document }), { code: 'PROXY_MAPPING_REQUIRED' });
  const imported = await service.call('importProfiles', { document, proxyMap: { [raw.id]: raw.id } });
  assert.ok(imported.actionResult.createdIds.every((id) => imported.profiles.find((row) => row.id === id).proxyId === raw.id));
});

test('AnyTLS draft check releases only its temporary node; saved checks cannot close a live shared core', async (t) => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id });
  const context = await service.resolveWorkspaceContext(profile.id);
  await service.call('checkProxy', { id: raw.id });
  assert.equal(managed.releases.length, 0);
  await service.call('checkProxy', { proxy: anytlsConfig() });
  assert.equal(managed.releases.length, 1); assert.match(managed.releases[0], /^draft_/);
  assert.equal(managed.wires.get(raw.id).password, context.proxy.password);
  managed.proxyCore.failure = true;
  await assert.rejects(service.call('checkProxy', { proxy: anytlsConfig() }), (value) => value.code === 'PROXY_CORE_FAILED' && !value.message.includes('fixture-raw-password'));
  assert.equal(managed.releases.length, 2); assert.ok(managed.releases.every((id) => id !== raw.id));
});

test('AnyTLS proxy edits and deletion respect active browser bindings and release old core only after a successful edit', async (t) => {
  const managed = managedProxyFixture();
  const { service, client } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id });
  await service.call('startProfile', { id: profile.id });
  await assert.rejects(service.call('saveProxy', { proxy: { ...raw, password: 'new-fixture-password' } }), { code: 'PROFILE_RUNNING' });
  await assert.rejects(service.call('deleteProxy', { id: raw.id }), { code: 'PROXY_IN_USE' });
  assert.equal(managed.releases.length, 0);
  await service.call('stopProfile', { id: profile.id });
  const edited = await service.call('saveProxy', { proxy: { ...raw, protocol: 'http' } });
  assert.equal(edited.profiles[0].proxyId, raw.id); assert.equal(client.profiles[0].proxy.type, 'http');
  assert.deepEqual(managed.releases, [raw.id]);
  await service.call('saveProxy', { proxy: { ...raw, password: 'new-fixture-password' } });
  assert.equal(client.profiles[0].proxy, null);
  await service.call('updateProfile', { id: profile.id, profile: { proxyId: null } });
  await service.call('deleteProxy', { id: raw.id });
  assert.equal((await service.snapshot()).proxies.length, 0);
});

test('AnyTLS core and actual egress failures block automatic browser launch without any direct fallback', async (t) => {
  const managed = managedProxyFixture();
  const { service, client } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id, timezone: '' });
  managed.proxyCore.failure = true;
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'PROXY_CORE_FAILED' });
  assert.equal(managed.probes.length, 0); assert.equal(client.sessions.length, 0);
  assert.equal(JSON.stringify(await service.snapshot()).includes('fixture failure fixture-raw-password'), false);
  managed.proxyCore.failure = false; managed.networkProbe.failure = true;
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'AUTO_TIMEZONE_FAILED' });
  assert.equal(client.sessions.length, 0); assert.ok(managed.probes.every((row) => row.proxy && row.proxy.host === '127.0.0.1'));
  await service.call('updateProfile', { id: profile.id, profile: { timezone: 'Asia/Tokyo' } });
  await service.call('startProfile', { id: profile.id });
  assert.equal(client.sessions.length, 1); assert.equal(client.requests.filter((row) => row.route === '/api/sessions' && row.method === 'POST').length, 1);
});

test('AnyTLS configuration validation rejects credentials, TLS options and host control injection before saving', async (t) => {
  const { service } = await fixture(t, managedProxyFixture());
  for (const patch of [{ password: '' }, { username: 'unsupported-user' }, { password: 'p\r\nq' }, { serverName: 'https://wrong.example' }, { serverName: 'tls.example\n.test' }, { skipCertVerify: 'true' }, { clientFingerprint: 'unknown' }, { host: 'node.example\r\n.test' }, { port: 65536 }, { region: 'jp/tokyo' }, { alpn: ['h2', 'http/1.1', 'bad\nprotocol'] }, { alpn: ['h2', 'h2'] }, { udp: 'true' }]) {
    await assert.rejects(service.call('saveProxy', { proxy: anytlsConfig(patch) }), { code: 'VALIDATION_ERROR' });
  }
  assert.equal((await service.snapshot()).proxies.length, 0);
});

test('AnyTLS stable IDs stay distinct even when two nodes have identical endpoint settings', async (t) => {
  const { service } = await fixture(t, managedProxyFixture());
  await service.call('saveProxy', { proxy: anytlsConfig({ name: '节点 A' }) });
  const saved = await service.call('saveProxy', { proxy: anytlsConfig({ name: '节点 B' }) });
  const selected = saved.proxies.find((row) => row.name === '节点 B');
  const profile = await create(service, { proxyId: selected.id });
  assert.equal(profile.proxyId, selected.id); assert.equal(profile.profileProxyId, selected.id);
  await service.call('saveGroup', { name: '分组 B', proxyId: selected.id, proxyMode: 'enforced' });
  assert.equal((await service.snapshot()).groups.find((row) => row.name === '分组 B').proxyId, selected.id);
});

test('AnyTLS group edits protect every running member and preserve local bindings on rejected changes', async (t) => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig({ alpn: ['h2', 'http/1.1'], udp: false }) })).proxies[0];
  const profile = await create(service, { group: '托管组', proxyId: null });
  await service.call('saveGroup', { name: '托管组', proxyId: raw.id, proxyMode: 'enforced' });
  await service.call('startProfile', { id: profile.id });
  await assert.rejects(service.call('saveGroup', { name: '托管组', proxyId: raw.id, proxyMode: 'default' }), { code: 'PROFILE_RUNNING' });
  await assert.rejects(service.call('clearGroupProxy', { name: '托管组' }), { code: 'PROFILE_RUNNING' });
  await assert.rejects(service.call('deleteGroup', { name: '托管组' }), { code: 'PROFILE_RUNNING' });
  await assert.rejects(service.call('saveProxy', { proxy: { ...raw, alpn: ['http/1.1'] } }), { code: 'PROFILE_RUNNING' });
  assert.deepEqual((await service.store.read()).groups, [{ name: '托管组', proxyId: raw.id, proxyMode: 'enforced' }]);
  assert.deepEqual((await service.store.read()).proxies[0].alpn, ['h2', 'http/1.1']);
  assert.equal((await service.store.read()).proxies[0].udp, false);
});

test('AnyTLS stale or unavailable managed bindings fail closed even with a fixed manual timezone', async (t) => {
  const { service, client } = await fixture(t, { proxyCore: null });
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id, timezone: 'Asia/Tokyo' });
  await assert.rejects(service.call('startProfile', { id: profile.id }), { code: 'PROXY_CORE_UNAVAILABLE' });
  assert.equal(client.sessions.length, 0);
  await service.store.transaction((workspace) => { workspace.proxies = []; });
  await assert.rejects(service.resolveWorkspaceContext(profile.id), { code: 'PROXY_NOT_FOUND' });
  assert.equal(client.requests.filter((row) => row.route === '/api/sessions' && row.method === 'POST').length, 0);
});

test('AnyTLS TLS settings participate in context invalidation without replacing other identical node IDs', async (t) => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const first = (await service.call('saveProxy', { proxy: anytlsConfig({ name: '节点 A' }) })).proxies[0];
  const second = (await service.call('saveProxy', { proxy: anytlsConfig({ name: '节点 B' }) })).proxies.find((row) => row.name === '节点 B');
  const profile = await create(service, { proxyId: second.id, timezone: '' });
  await service.call('saveGroup', { name: 'A', proxyId: first.id, proxyMode: 'enforced' });
  await service.call('saveGroup', { name: 'B', proxyId: second.id, proxyMode: 'enforced' });
  await service.resolveWorkspaceContext(profile.id);
  const previous = service.workspaceContexts.get(profile.id).signature;
  await service.call('saveProxy', { proxy: { ...second, serverName: 'other.example.test', alpn: ['h2'], udp: false } });
  const snapshot = await service.snapshot();
  assert.equal(snapshot.profiles[0].resolvedTimezone, null);
  assert.equal(snapshot.groups.find((row) => row.name === 'A').proxyId, first.id);
  assert.equal((await service.store.read()).proxies.find((row) => row.id === first.id).serverName, first.serverName);
  await service.resolveWorkspaceContext(profile.id);
  assert.notEqual(service.workspaceContexts.get(profile.id).signature, previous);
  assert.deepEqual(managed.releases, [second.id]);
});

test('AnyTLS managed launch marker follows create, clone, import, explicit proxy clearing and group moves', async (t) => {
  const { service, client } = await fixture(t, managedProxyFixture());
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const own = await create(service, { proxyId: raw.id });
  assert.equal(client.profiles.find((row) => row.id === own.id).managed_proxy_required, true);
  const cloned = await service.call('cloneProfile', { id: own.id });
  assert.equal(client.profiles.find((row) => row.id === cloned.actionResult.createdId).managed_proxy_required, true);
  const document = await service.call('exportProfiles', { id: own.id });
  const imported = await service.call('importProfiles', { document, proxyMap: { [raw.id]: raw.id } });
  assert.equal(client.profiles.find((row) => row.id === imported.actionResult.createdIds[0]).managed_proxy_required, true);
  await service.call('updateProfile', { id: own.id, profile: { proxyId: null } });
  assert.equal(client.profiles.find((row) => row.id === own.id).managed_proxy_required, false);
  await service.call('saveGroup', { name: '托管移动组', proxyId: raw.id, proxyMode: 'enforced' });
  await service.call('bulkProfiles', { action: 'move', ids: [own.id], group: '托管移动组' });
  assert.equal(client.profiles.find((row) => row.id === own.id).managed_proxy_required, true);
  await service.call('bulkProfiles', { action: 'move', ids: [own.id], group: '' });
  assert.equal(client.profiles.find((row) => row.id === own.id).managed_proxy_required, false);
});

test('AnyTLS group managed markers track effective precedence and are installed before native policy clearing', async (t) => {
  const { service, client } = await fixture(t, managedProxyFixture());
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const ordinary = await savedProxy(service);
  const ownRaw = await create(service, { name: '专属 AnyTLS', group: '策略组', proxyId: raw.id });
  const ownNormal = await create(service, { name: '专属普通', group: '策略组', proxyId: ordinary.id });
  const inherits = await create(service, { name: '直接组成员', group: '策略组', proxyId: null });
  const flags = () => [ownRaw, ownNormal, inherits].map(({ id }) => client.profiles.find((row) => row.id === id).managed_proxy_required);
  assert.deepEqual(flags(), [true, false, false]);
  await service.call('saveGroup', { name: '策略组', proxyId: raw.id, proxyMode: 'default' });
  assert.deepEqual(flags(), [true, false, true]);
  await service.call('saveGroup', { name: '策略组', proxyId: raw.id, proxyMode: 'enforced' });
  assert.deepEqual(flags(), [true, true, true]);
  await service.call('saveGroup', { name: '策略组', proxyId: ordinary.id, proxyMode: 'enforced' });
  assert.deepEqual(flags(), [false, false, false]);
  const cursor = client.requests.length;
  await service.call('clearGroupProxy', { name: '策略组' });
  assert.deepEqual(flags(), [true, false, false]);
  const changes = client.requests.slice(cursor).filter((row) => row.method !== 'GET');
  assert.ok(changes.findIndex((row) => row.method === 'PUT' && row.body.managed_proxy_required === true) < changes.findIndex((row) => row.method === 'DELETE' && row.route.endsWith('/proxy')));
  await service.call('saveGroup', { name: '策略组', proxyId: raw.id, proxyMode: 'enforced' });
  await service.call('deleteGroup', { name: '策略组' });
  assert.deepEqual(flags(), [true, false, false]);
  assert.ok(client.profiles.every((row) => row.group === ''));
});

test('AnyTLS proxy protocol conversion updates inherited group member managed markers', async (t) => {
  const { service, client } = await fixture(t, managedProxyFixture());
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { group: '转换组', proxyId: null });
  await service.call('saveGroup', { name: '转换组', proxyId: raw.id, proxyMode: 'enforced' });
  assert.equal(client.profiles[0].managed_proxy_required, true);
  await service.call('saveProxy', { proxy: { ...raw, protocol: 'http' } });
  assert.equal(client.profiles[0].managed_proxy_required, false); assert.equal(client.groups[0].proxy.type, 'http');
  await service.call('saveProxy', { proxy: raw });
  assert.equal(client.profiles[0].managed_proxy_required, true); assert.ok(client.groups.every((row) => !row.proxy));
  assert.equal((await service.snapshot()).profiles.find((row) => row.id === profile.id).proxyId, raw.id);
});

test('AnyTLS missing local metadata cannot turn a previously marked profile into a direct terminal context', async (t) => {
  const managed = managedProxyFixture();
  const { service, client } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id });
  assert.equal(client.profiles[0].managed_proxy_required, true);
  await service.store.transaction((workspace) => { workspace.profiles = []; workspace.groups = []; });
  await assert.rejects(service.resolveWorkspaceContext(profile.id), { code: 'MANAGED_PROXY_BINDING_MISSING' });
  assert.equal(managed.calls.length, 0); assert.equal(managed.probes.length, 0);
  assert.equal(client.profiles[0].managed_proxy_required, true);
});

test('AnyTLS group metadata storage failure restores old native policy and managed markers', async (t) => {
  const { service, client } = await fixture(t, managedProxyFixture());
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const ordinary = await savedProxy(service);
  await create(service, { group: '回滚组', proxyId: null });
  await service.call('saveGroup', { name: '回滚组', proxyId: ordinary.id, proxyMode: 'enforced' });
  const previous = await service.store.read();
  const transaction = service.store.transaction;
  service.store.transaction = async () => { throw new Error('fixture disk failure'); };
  await assert.rejects(service.call('saveGroup', { name: '回滚组', proxyId: raw.id, proxyMode: 'enforced' }), /fixture disk failure/);
  service.store.transaction = transaction;
  assert.equal(client.profiles[0].managed_proxy_required, false);
  assert.equal(client.groups[0].proxy.type, 'http'); assert.equal(client.groups[0].proxy.host, ordinary.host);
  assert.deepEqual((await service.store.read()).groups, previous.groups);
});

test('AnyTLS runtime failure invalidates only affected wire/geolocation contexts and focus restores the same client route', async (t) => {
  const managed = managedProxyFixture();
  const originalProbe = managed.networkProbe.probe.bind(managed.networkProbe);
  managed.networkProbe.probe = async (...args) => ({ ...(await originalProbe(...args)), countryCode: 'JP', geolocation: { latitude: 35.6, longitude: 139.7, accuracy: 50000 } });
  const invalidated = [];
  managed.networkProbe.invalidate = (proxy) => invalidated.push(structuredClone(proxy));
  const { service, client } = await fixture(t, managed);
  const first = (await service.call('saveProxy', { proxy: anytlsConfig({ name: '节点 A' }) })).proxies[0];
  const second = (await service.call('saveProxy', { proxy: anytlsConfig({ name: '节点 B', host: 'other.example.test' }) })).proxies.find((row) => row.name === '节点 B');
  const affected = await create(service, { proxyId: first.id, timezone: '' });
  const unrelated = await create(service, { name: '不受影响', proxyId: second.id, timezone: '' });
  await service.call('startProfile', { id: affected.id });
  await service.resolveWorkspaceContext(unrelated.id);
  assert.equal((await service.snapshot()).profiles.find((row) => row.id === affected.id).geolocation.latitude, 35.6);
  const original = structuredClone(managed.wires.get(first.id));
  service.invalidateManagedProxy(first.id);
  const failed = await service.snapshot();
  assert.equal(failed.profiles.find((row) => row.id === affected.id).network.ok, false);
  assert.equal(failed.profiles.find((row) => row.id === affected.id).network.ip, null);
  assert.equal(failed.profiles.find((row) => row.id === affected.id).resolvedTimezone, null);
  assert.equal(failed.profiles.find((row) => row.id === affected.id).geolocation, null);
  assert.equal(failed.profiles.find((row) => row.id === affected.id).resolvedLocale, null);
  assert.match(failed.profiles.find((row) => row.id === affected.id).networkLastError, /代理网络内核已停止/);
  assert.equal(failed.profiles.find((row) => row.id === unrelated.id).network.ok, true);
  assert.equal(failed.profiles.find((row) => row.id === unrelated.id).geolocation.latitude, 35.6);
  assert.deepEqual(invalidated, [original]);
  const before = managed.calls.length;
  await service.call('focusProfile', { id: affected.id });
  assert.equal(managed.calls.length, before + 1);
  assert.deepEqual(service.proxyWires.get(first.id), original);
  assert.equal((await service.snapshot()).profiles.find((row) => row.id === affected.id).network.ok, true);
  assert.equal(client.requests.filter((row) => row.route === '/api/sessions' && row.method === 'POST').length, 1, 'recovery must retain the running browser rather than creating another session');
});

test('AnyTLS runtime failure during an in-flight lookup cannot resurrect a successful workspace context', async (t) => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id, timezone: '' });
  await service.resolveWorkspaceContext(profile.id);
  let release, entered;
  const started = new Promise((resolve) => { entered = resolve; });
  managed.networkProbe.probe = async () => { entered(); return new Promise((resolve) => { release = () => resolve({ ok: true, timezone: 'Asia/Tokyo', ip: '203.0.113.8' }); }); };
  const pending = service.resolveWorkspaceContext(profile.id, { force: true });
  await started;
  service.invalidateManagedProxy(raw.id);
  release();
  await assert.rejects(pending, { code: 'PROXY_CORE_STOPPED' });
  const snapshot = await service.snapshot();
  assert.equal(snapshot.profiles[0].network.ok, false); assert.equal(snapshot.profiles[0].network.ip, null);
  assert.equal(snapshot.profiles[0].resolvedTimezone, null);
});

test('AnyTLS saved proxy check cannot report an old successful egress after a runtime failure', async (t) => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  let release, entered;
  const started = new Promise((resolve) => { entered = resolve; });
  managed.networkProbe.probe = async () => { entered(); return new Promise((resolve) => { release = () => resolve({ ok: true, timezone: 'Asia/Tokyo', ip: '203.0.113.8' }); }); };
  const pending = service.call('checkProxy', { id: raw.id });
  await started; service.invalidateManagedProxy(raw.id); release();
  await assert.rejects(pending, { code: 'PROXY_CORE_STOPPED' });
  assert.equal(service.proxyWires.has(raw.id), false); assert.equal(managed.releases.length, 0);
});

test('AnyTLS old failed lookup cannot overwrite a recovered successful context after runtime invalidation', async (t) => {
  const managed = managedProxyFixture();
  const { service } = await fixture(t, managed);
  const raw = (await service.call('saveProxy', { proxy: anytlsConfig() })).proxies[0];
  const profile = await create(service, { proxyId: raw.id, timezone: '' });
  await service.resolveWorkspaceContext(profile.id);
  let release, entered, requests = 0;
  const started = new Promise((resolve) => { entered = resolve; });
  managed.networkProbe.probe = async () => {
    requests++;
    if (requests === 1) { entered(); return new Promise((resolve) => { release = () => resolve({ ok: false, timezone: null, message: 'obsolete failed lookup' }); }); }
    return { ok: true, timezone: 'Asia/Tokyo', ip: '203.0.113.9' };
  };
  const obsolete = service.resolveWorkspaceContext(profile.id, { force: true });
  await started;
  service.invalidateManagedProxy(raw.id);
  const recovered = await service.resolveWorkspaceContext(profile.id, { force: true });
  assert.equal(recovered.network.ok, true); assert.equal(recovered.network.ip, '203.0.113.9');
  release();
  await assert.rejects(obsolete, { code: 'PROXY_CORE_STOPPED' });
  const current = (await service.snapshot()).profiles[0];
  assert.equal(current.network.ok, true); assert.equal(current.network.ip, '203.0.113.9');
  assert.equal(current.resolvedTimezone, 'Asia/Tokyo'); assert.equal(current.networkLastError, null);
});
