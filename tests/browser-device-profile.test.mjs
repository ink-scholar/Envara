import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { BROWSER_DEVICE_PROFILES, PROVIDER_DEFAULT_DEVICE_PROFILE_ID, applyBrowserDeviceProfile, defaultBrowserDeviceProfileId, deviceProfileFingerprint, getBrowserDeviceProfile, supportsBrowserDeviceProfiles, validateBrowserDeviceProfileInput } from '../shared/browser-device-profile.mjs';

async function fixture(t, platform = 'darwin') {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-device-profile-'));
  const profilesDir = path.join(root, 'browseforge/profiles');
  const binary = path.join(root, 'fixture-browser'); await writeFile(binary, '', { mode: 0o700 });
  const profiles = [], sessions = [], requests = [];
  const descriptors = ['cloakbrowser', 'camoufox', 'browseforge-chromium'].map(id => ({ id, family: id === 'camoufox' ? 'firefox' : 'chromium', enabled: true, platform_supported: true, binary_path: binary,
    capabilities: { supports_seed_fingerprint: id !== 'camoufox' } }));
  let next = 0;
  const client = { request: async (method, route, body) => {
    requests.push({ method, route, body: structuredClone(body) });
    if (method === 'GET') {
      const lists = { '/api/profiles': profiles, '/api/sessions': sessions, '/api/groups': [], '/api/runtimes': descriptors };
      if (Object.hasOwn(lists, route)) return { data: structuredClone(lists[route]), default_runtime_id: 'cloakbrowser' };
    }
    if (method === 'POST' && route === '/api/profiles') {
      const id = `profile_${++next}`, profile_dir = path.join(profilesDir, id);
      await mkdir(path.join(profile_dir, 'browser-data'), { recursive: true });
      const profile = { ...structuredClone(body), id, profile_dir, created_at: new Date().toISOString() };
      await writeFile(path.join(profile_dir, 'profile.json'), JSON.stringify(profile));
      profiles.push(profile); return { data: structuredClone(profile) };
    }
    const duplicateMatch = route.match(/^\/api\/profiles\/([A-Za-z0-9_-]+)\/duplicate$/);
    if (method === 'POST' && duplicateMatch) {
      const source = structuredClone(profiles.find(p => p.id === duplicateMatch[1]));
      const id = `profile_${++next}`, profile_dir = path.join(profilesDir, id);
      const profile = { ...source, id, name: body.name, profile_dir, fingerprint_seed: (source.fingerprint_seed || 1) + 1 };
      for (const key of ['canvas:seed', 'audio:seed']) delete profile.fingerprint?.[key];
      await mkdir(path.join(profile_dir, 'browser-data'), { recursive: true });
      await writeFile(path.join(profile_dir, 'profile.json'), JSON.stringify(profile));
      profiles.push(profile); return { data: structuredClone(profile) };
    }
    const profileMatch = route.match(/^\/api\/profiles\/([A-Za-z0-9_-]+)$/);
    if (method === 'PUT' && profileMatch) {
      const profile = profiles.find(p => p.id === profileMatch[1]); Object.assign(profile, structuredClone(body));
      await writeFile(path.join(profile.profile_dir, 'profile.json'), JSON.stringify(profile));
      return { data: structuredClone(profile) };
    }
    if (method === 'POST' && route === '/api/sessions') {
      const session = { session_id: `sess_${body.profile_id}`, profile_id: body.profile_id }; sessions.push(session); return { data: session };
    }
    if (/\/eval$/.test(route)) return { data: { language: 'en-US', timezone: 'America/New_York', platform: 'MacIntel' } };
    if (/\/screenshot$/.test(route)) return Buffer.from('fixture');
    if (route === '/api/shutdown') return { data: 'closed' };
    throw new Error('Unsupported fixture request');
  } };
  const coreRoutes = new Map(), coreCalls = [], probes = [];
  let wireSequence = 0;
  const proxyCore = {
    async ensure(proxy) {
      coreCalls.push(structuredClone(proxy));
      if (!coreRoutes.has(proxy.id)) {
        const serial = ++wireSequence;
        coreRoutes.set(proxy.id, { upstream: structuredClone(proxy), wire: { protocol: 'http', host: '127.0.0.1', port: 24000 + serial, username: `fixture-wire-user-${serial}`, password: `fixture-wire-password-${serial}` } });
      }
      return structuredClone(coreRoutes.get(proxy.id).wire);
    },
    async release(id) { coreRoutes.delete(id); },
    async close() { coreRoutes.clear(); },
  };
  const networkProbe = { peek: () => null, invalidate() {}, close() {}, probe: async proxy => {
    const route = proxy && [...coreRoutes.values()].find(({ wire }) => ['protocol', 'host', 'port', 'username', 'password'].every(key => wire[key] === proxy[key]));
    if (proxy) assert.ok(route, 'network measurements must use an authenticated owned wire');
    probes.push({ wire: structuredClone(proxy), upstream: structuredClone(route?.upstream ?? null) });
    const malaysia = route?.upstream.host === 'my.example';
    return { ok: true, ip: malaysia ? '203.0.113.2' : '203.0.113.1', countryCode: malaysia ? 'MY' : 'US', timezone: malaysia ? 'Asia/Kuala_Lumpur' : 'America/New_York', geolocation: null };
  } };
  let service = new BrowseForgeService(root, client, { platform }, () => {}, { profilesDir, networkProbe, proxyCore });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(root, { recursive: true, force: true }); });
  const create = async patch => {
    const result = await service.call('createProfile', { profile: { name: 'Device fixture', engine: 'cloakbrowser', ...patch } });
    return result.profiles.find(p => p.id === result.actionResult.createdId);
  };
  const reopen = async () => {
    await service.shutdown();
    const stored = await Promise.all((await readdir(profilesDir)).map(async id => JSON.parse(await readFile(path.join(profilesDir, id, 'profile.json'), 'utf8'))));
    profiles.splice(0, profiles.length, ...stored);
    service = new BrowseForgeService(root, client, { platform }, () => {}, { profilesDir, networkProbe, proxyCore });
    await service.ready;
    return service;
  };
  return { root, get service() { return service; }, client, profiles, sessions, requests, coreCalls, probes, create, reopen };
}

test('device catalog is versioned, country-independent and limited to tested provider mappings', () => {
  assert.equal(defaultBrowserDeviceProfileId('darwin'), 'mac-standard-v1');
  assert.equal(defaultBrowserDeviceProfileId('win32'), 'windows-standard-v1');
  assert.equal(defaultBrowserDeviceProfileId('linux'), 'linux-standard-v1');
  assert.equal(defaultBrowserDeviceProfileId('US'), PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.equal(getBrowserDeviceProfile(PROVIDER_DEFAULT_DEVICE_PROFILE_ID), null);
  assert.throws(() => getBrowserDeviceProfile('us-mac'), { code: 'DEVICE_PROFILE_INVALID' });
  for (const engine of ['cloakbrowser', 'camoufox', 'browseforge-chromium']) assert(supportsBrowserDeviceProfiles(engine));
  assert(!supportsBrowserDeviceProfiles('unmapped-provider'));
  assert(BROWSER_DEVICE_PROFILES.every(profile => Object.isFrozen(profile) && !Object.hasOwn(profile, 'country')));
  const fingerprint = deviceProfileFingerprint('mac-standard-v1');
  assert.deepEqual(fingerprint, { 'screen.width': 1440, 'screen.height': 900, 'screen.devicePixelRatio': 2, 'navigator.hardwareConcurrency': 8, 'navigator.deviceMemory': 8 });
  assert(!Object.keys(fingerprint).some(key => /webgl|font|useragent|timezone|language/i.test(key)));
  fingerprint['screen.width'] = 100;
  assert.equal(deviceProfileFingerprint('mac-standard-v1')['screen.width'], 1440);
  assert.throws(() => validateBrowserDeviceProfileInput({ deviceProfileId: 'mac-standard-v1' }, 'unmapped-provider', 'darwin'), { code: 'DEVICE_PROFILE_UNSUPPORTED' });
  assert.throws(() => validateBrowserDeviceProfileInput({ deviceProfileId: 'windows-standard-v1' }, 'cloakbrowser', 'darwin'), { code: 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED' });
});

test('minimal new environments delegate all device defaults to their selected provider on every host', async t => {
  for (const host of ['darwin', 'win32', 'linux']) for (const engine of ['cloakbrowser', 'camoufox', 'browseforge-chromium']) await t.test(`${host}/${engine}`, async t => {
    const f = await fixture(t, host), profile = await f.create({ engine });
    assert.equal(profile.deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
    assert.equal(profile.platform, null);
    assert.equal(profile.width, null); assert.equal(profile.height, null);
    assert.deepEqual(profile.fingerprint, {});
    const created = f.requests.find(request => request.method === 'POST' && request.route === '/api/profiles').body;
    assert.equal(created.identity, undefined, 'provider uses its native platform without a fabricated override');
    assert.equal(created.fingerprint, undefined, 'no shared CPU, RAM, geometry or other device tuple is injected');
    assert.equal(created.deviceProfileId, undefined, 'desktop metadata is not a native field');
    assert.equal((await f.service.store.read()).profiles[0].deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
    const saved = JSON.parse(await readFile(path.join(f.root, 'browseforge-manager/workspace.json'), 'utf8'));
    assert.equal(saved.profiles[0].deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
    if (engine === 'camoufox') assert.equal(created.fingerprint_seed, undefined, 'structured provider retains its own generation contract');
    else assert.ok(Number.isSafeInteger(created.fingerprint_seed) && created.fingerprint_seed > 0 && created.fingerprint_seed <= 4294967295);
  });
});

test('an explicit fixed preset persists its native settings for every provider and host', async t => {
  for (const engine of ['cloakbrowser', 'camoufox', 'browseforge-chromium']) for (const [host, id, platform] of [['darwin', 'mac-standard-v1', 'macos'], ['win32', 'windows-standard-v1', 'windows'], ['linux', 'linux-standard-v1', 'linux']]) await t.test(`${engine}/${host}`, async t => {
    const f = await fixture(t, host), profile = await f.create({ engine, deviceProfileId: id });
    assert.equal(profile.deviceProfileId, id); assert.equal(profile.platform, platform);
    assert.deepEqual(f.profiles[0].fingerprint, deviceProfileFingerprint(id, engine));
    assert.equal((await f.service.store.read()).profiles[0].deviceProfileId, id);
  });
});

test('provider defaults get independent saved seeds that survive service restart and unrelated edits without touching browser data', async t => {
  const f = await fixture(t), first = await f.create(), second = await f.create();
  assert.ok(Number.isSafeInteger(first.seed) && first.seed > 0);
  assert.ok(Number.isSafeInteger(second.seed) && second.seed > 0);
  assert.notEqual(first.seed, second.seed, 'fresh environments receive separate randomly generated seeds');
  const source = f.profiles.find(profile => profile.id === first.id), marker = path.join(source.profile_dir, 'browser-data', 'Cookies');
  await writeFile(marker, 'fixture-login-data');
  const persisted = JSON.parse(await readFile(path.join(source.profile_dir, 'profile.json'), 'utf8'));
  assert.equal(persisted.fingerprint_seed, first.seed);
  const writesBefore = f.requests.filter(request => ['POST', 'PUT'].includes(request.method) && /^\/api\/profiles(?:\/[^/]+)?$/.test(request.route)).length;
  await f.reopen();
  const restarted = (await f.service.snapshot()).profiles.find(profile => profile.id === first.id);
  assert.equal(restarted.seed, first.seed); assert.equal(restarted.deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.deepEqual(restarted.fingerprint, {});
  assert.equal(f.requests.filter(request => ['POST', 'PUT'].includes(request.method) && /^\/api\/profiles(?:\/[^/]+)?$/.test(request.route)).length, writesBefore, 'restart does not recreate or reseed a profile');
  await f.service.call('updateProfile', { id: first.id, profile: { notes: 'An unrelated edit' } });
  const updated = (await f.service.snapshot()).profiles.find(profile => profile.id === first.id);
  assert.equal(updated.seed, first.seed); assert.deepEqual(updated.fingerprint, {});
  assert.equal(await readFile(marker, 'utf8'), 'fixture-login-data');
});

test('old custom creation calls preserve their explicit configuration', async t => {
  const f = await fixture(t);
  for (const patch of [
    { platform: 'windows', width: 1920, height: 1080 },
    { platform: 'macos', width: 1280, height: 800 },
    { fingerprint: { 'navigator.hardwareConcurrency': 4, 'navigator.deviceMemory': 4 } },
    { platform: 'macos', width: 1440, height: 900 },
    { engine: 'camoufox' },
  ]) {
    const result = await f.create(patch);
    assert.equal(result.deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
    if (patch.width) assert.equal(result.width, patch.width);
    if (patch.platform) assert.equal(result.platform, patch.platform);
    if (patch.fingerprint) assert.deepEqual(result.fingerprint, patch.fingerprint);
  }
  await assert.rejects(f.create({ deviceProfileId: 'windows-standard-v1' }), { code: 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED' });
});

test('unlabelled existing environments stay untouched until a device profile is explicitly selected', async t => {
  const f = await fixture(t);
  const profile = await f.create({ deviceProfileId: 'provider-default', platform: 'macos', width: 1280, height: 800, fingerprint: { 'navigator.hardwareConcurrency': 4, 'navigator.deviceMemory': 4, 'custom.fixture': true } });
  await f.service.store.transaction(next => { delete next.profiles[0].deviceProfileId; });
  const original = structuredClone(f.profiles[0].fingerprint);
  assert.equal((await f.service.snapshot()).profiles[0].deviceProfileId, 'provider-default');
  await f.service.call('updateProfile', { id: profile.id, profile: { notes: 'Unrelated edit' } });
  assert.deepEqual(f.profiles[0].fingerprint, original);
  await f.service.call('updateProfile', { id: profile.id, profile: { deviceProfileId: 'mac-standard-v1' } });
  assert.deepEqual(f.profiles[0].fingerprint, { ...original, ...deviceProfileFingerprint('mac-standard-v1') });
  await f.service.call('updateProfile', { id: profile.id, profile: { deviceProfileId: 'provider-default', width: 1280 } });
  assert.equal(f.profiles[0].fingerprint['navigator.hardwareConcurrency'], 8, 'custom mode never clears existing hardware settings');
  assert.equal(f.profiles[0].fingerprint['screen.width'], 1280);
});

test('network changes alter regional context without changing the device or seed', async t => {
  const f = await fixture(t);
  const saved = [];
  for (const [name, host] of [['US', 'us.example'], ['MY', 'my.example']]) {
    const result = await f.service.call('saveProxy', { proxy: { name, protocol: 'http', host, port: 8080 } });
    saved.push(result.proxies.find(p => p.name === name));
  }
  const profile = await f.create({ proxyId: saved[0].id });
  const fingerprint = structuredClone(f.profiles[0].fingerprint), seed = f.profiles[0].fingerprint_seed;
  assert.equal((await f.service.resolveWorkspaceContext(profile.id)).locale, 'en-US');
  await f.service.call('updateProfile', { id: profile.id, profile: { proxyId: saved[1].id } });
  const context = await f.service.resolveWorkspaceContext(profile.id);
  assert.equal(context.locale, 'ms-MY'); assert.equal(context.timezone, 'Asia/Kuala_Lumpur');
  assert.deepEqual(f.coreCalls.map(proxy => proxy.host), ['us.example', 'my.example']);
  assert.deepEqual(f.probes.map(probe => probe.upstream.id), saved.map(proxy => proxy.id));
  assert.ok(f.probes.every(probe => probe.wire.host === '127.0.0.1' && probe.wire.username && probe.wire.password));
  assert.notEqual(f.probes[0].wire.port, f.probes[1].wire.port);
  assert.deepEqual(f.profiles[0].fingerprint, fingerprint); assert.equal(f.profiles[0].fingerprint_seed, seed);
  assert.equal((await f.service.snapshot()).profiles[0].deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.deepEqual(fingerprint ?? {}, {}, 'changing egress never injects a fixed device specification');
});

test('explicit null geometry restores provider defaults without clearing hardware, seed, other configuration or browser data', async t => {
  const f = await fixture(t);
  const fingerprint = { 'screen.width': 2560, 'screen.height': 1440, 'screen.availWidth': 2560, 'screen.availHeight': 1400,
    'screen.devicePixelRatio': 1.5, 'navigator.hardwareConcurrency': 4, 'navigator.deviceMemory': 16, 'canvas:seed': 918, 'custom.fixture': true };
  const profile = await f.create({ seed: 12345, fingerprint });
  const marker = path.join(f.profiles[0].profile_dir, 'browser-data', 'Cookies');
  await writeFile(marker, 'existing-login-data');
  await f.service.call('updateProfile', { id: profile.id, profile: { notes: 'omitted geometry stays unchanged' } });
  assert.deepEqual(f.profiles[0].fingerprint, fingerprint);
  await f.service.call('updateProfile', { id: profile.id, profile: { width: null } });
  const withoutWidth = { ...fingerprint }; delete withoutWidth['screen.width']; delete withoutWidth['screen.availWidth'];
  assert.deepEqual(f.profiles[0].fingerprint, withoutWidth, 'height and its available area survive when omitted');
  await f.service.call('updateProfile', { id: profile.id, profile: { width: null, height: null } });
  const automatic = { ...withoutWidth }; delete automatic['screen.height']; delete automatic['screen.availHeight'];
  assert.deepEqual(f.profiles[0].fingerprint, automatic);
  assert.equal(f.profiles[0].fingerprint_seed, 12345);
  const result = (await f.service.snapshot()).profiles[0];
  assert.equal(result.width, null); assert.equal(result.height, null);
  assert.equal(result.deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.equal(await readFile(marker, 'utf8'), 'existing-login-data');
});

test('null dimensions on new drafts add no geometry while an explicitly fixed preset still owns its dimensions', async t => {
  const f = await fixture(t), automatic = await f.create({ width: null, height: null });
  assert.deepEqual(automatic.fingerprint, {});
  const fixed = await f.create({ deviceProfileId: 'mac-standard-v1', width: null, height: null });
  assert.deepEqual(fixed.fingerprint, deviceProfileFingerprint('mac-standard-v1'));
  await f.service.call('updateProfile', { id: fixed.id, profile: { width: null, height: null } });
  const updated = (await f.service.snapshot()).profiles.find(profile => profile.id === fixed.id);
  assert.equal(updated.deviceProfileId, 'mac-standard-v1');
  assert.deepEqual(updated.fingerprint, fixed.fingerprint);
  assert.equal(updated.seed, fixed.seed);
});

test('existing fixed environments keep their label, custom fields, seed and data through unrelated updates', async t => {
  const f = await fixture(t), fixed = await f.create({ deviceProfileId: 'mac-standard-v1', seed: 45678, fingerprint: { 'custom.fixture': true, 'canvas:seed': 567 } });
  const fingerprint = structuredClone(f.profiles[0].fingerprint), marker = path.join(f.profiles[0].profile_dir, 'browser-data', 'Cookies');
  await writeFile(marker, 'fixed-login-data');
  await f.service.call('updateProfile', { id: fixed.id, profile: { notes: 'Keep an existing user selection' } });
  const result = (await f.service.snapshot()).profiles[0];
  assert.equal(result.deviceProfileId, 'mac-standard-v1');
  assert.equal(result.seed, 45678); assert.deepEqual(result.fingerprint, fingerprint);
  assert.equal(await readFile(marker, 'utf8'), 'fixed-login-data');
});

test('default-device export/import preserves the seed and explicitly mapped network without adding hardware settings', async t => {
  const f = await fixture(t);
  const proxies = await f.service.call('saveProxy', { proxy: { name: 'US', protocol: 'http', host: 'us.example', port: 8080 } });
  const proxy = proxies.proxies.find(item => item.name === 'US');
  const source = await f.create({ proxyId: proxy.id });
  const exported = await f.service.exportProfiles({ id: source.id });
  assert.equal(exported.profiles[0].deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.deepEqual(exported.profiles[0].fingerprint, {});
  const importedResult = await f.service.call('importProfiles', { document: exported, proxyMap: { [proxy.id]: proxy.id } });
  const imported = importedResult.profiles.find(profile => profile.id === importedResult.actionResult.createdIds[0]);
  assert.equal(imported.seed, source.seed);
  assert.equal(imported.deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.equal(imported.proxyId, proxy.id);
  assert.equal(imported.platform, null); assert.equal(imported.width, null); assert.equal(imported.height, null);
  assert.deepEqual(imported.fingerprint, {});
  const payload = f.requests.filter(request => request.method === 'POST' && request.route === '/api/profiles').at(-1).body;
  assert.equal(payload.fingerprint_seed, source.seed);
  assert.deepEqual(payload.proxy, f.profiles[0].proxy);
  assert.deepEqual(payload.fingerprint, {});
});

test('selecting a fixed device clears stale available geometry while custom mode preserves it', async t => {
  const f = await fixture(t);
  const geometry = { 'screen.availWidth': 2560, 'screen.availHeight': 1400 };
  const original = await f.create({ deviceProfileId: 'provider-default', fingerprint: geometry });
  await f.service.call('updateProfile', { id: original.id, profile: { notes: 'Custom values remain owned by the user' } });
  assert.deepEqual(f.profiles[0].fingerprint, geometry);
  await f.service.call('updateProfile', { id: original.id, profile: { deviceProfileId: 'mac-standard-v1', fingerprint: geometry } });
  assert.deepEqual(f.profiles[0].fingerprint, deviceProfileFingerprint('mac-standard-v1'));
  const fixedImport = { ...(await f.service.exportProfiles({ id: original.id })).profiles[0], fingerprint: { ...deviceProfileFingerprint('mac-standard-v1'), ...geometry } };
  const result = await f.service.call('importProfiles', { profiles: [fixedImport] });
  assert.deepEqual(result.profiles.find(p => p.id === result.actionResult.createdIds[0]).fingerprint, fixedImport.fingerprint, 'import restores the exact saved identity instead of reapplying the template');
});

test('clones retain immutable device specs with a fresh seed and no generated noise or browser data', async t => {
  const f = await fixture(t), original = await f.create({ deviceProfileId: 'mac-standard-v1' });
  f.profiles[0].fingerprint['canvas:seed'] = 123;
  f.profiles[0].fingerprint['audio:seed'] = 456;
  await writeFile(path.join(f.profiles[0].profile_dir, 'browser-data', 'owned-fixture'), 'source data');
  const result = await f.service.call('cloneProfile', { id: original.id });
  const clone = result.profiles.find(p => p.id === result.actionResult.createdId);
  assert.equal(clone.deviceProfileId, original.deviceProfileId); assert.notEqual(clone.seed, original.seed);
  assert.deepEqual(clone.fingerprint, deviceProfileFingerprint(original.deviceProfileId));
  assert.equal(clone.dataBytes, 0);
});

test('export/import retains fixed profiles, while legacy imports preserve custom values', async t => {
  const f = await fixture(t), original = await f.create({ deviceProfileId: 'mac-standard-v1' });
  const document = await f.service.exportProfiles({ id: original.id });
  assert.equal(document.profiles[0].deviceProfileId, 'mac-standard-v1');
  const result = await f.service.call('importProfiles', { document });
  const imported = result.profiles.find(p => p.id === result.actionResult.createdIds[0]);
  assert.equal(imported.deviceProfileId, original.deviceProfileId); assert.equal(imported.seed, original.seed);
  assert.deepEqual(imported.fingerprint, original.fingerprint);
  const legacy = { ...document.profiles[0], name: 'Legacy import', width: 1280, height: 800,
    fingerprint: { 'screen.width': 1280, 'screen.height': 800, 'navigator.hardwareConcurrency': 4 } };
  delete legacy.deviceProfileId;
  const oldResult = await f.service.call('importProfiles', { profiles: [legacy] });
  const old = oldResult.profiles.find(p => p.id === oldResult.actionResult.createdIds[0]);
  assert.equal(old.deviceProfileId, 'provider-default'); assert.equal(old.width, 1280);
  assert.equal(old.fingerprint['navigator.hardwareConcurrency'], 4);
});

test('invalid or conflicting device selections fail before native writes and a running browser cannot change', async t => {
  const f = await fixture(t), profile = await f.create({ deviceProfileId: 'mac-standard-v1' });
  const before = structuredClone(f.profiles), metadata = await f.service.store.read();
  for (const patch of [{ deviceProfileId: 'missing' }, { deviceProfileId: null }, { width: 1200 }, { platform: 'windows' }, { fingerprint: { 'navigator.hardwareConcurrency': 4 } }]) {
    await assert.rejects(f.service.call('updateProfile', { id: profile.id, profile: patch }), { code: patch.deviceProfileId === null || patch.deviceProfileId === 'missing' ? 'DEVICE_PROFILE_INVALID' : 'DEVICE_PROFILE_CONFLICT' });
  }
  assert.deepEqual(f.profiles, before); assert.deepEqual(await f.service.store.read(), metadata);
  const invalid = { ...(await f.service.exportProfiles()).profiles[0], fingerprint: { ...profile.fingerprint, 'navigator.deviceMemory': 4 } };
  await assert.rejects(f.service.call('importProfiles', { profiles: [invalid] }), { code: 'DEVICE_PROFILE_CONFLICT' });
  assert.equal(f.profiles.length, 1);
  f.sessions.push({ profile_id: profile.id, session_id: `sess_${profile.id}` });
  await assert.rejects(f.service.call('updateProfile', { id: profile.id, profile: { deviceProfileId: 'provider-default' } }), { code: 'PROFILE_RUNNING' });
  f.sessions.length = 0; f.service.starting.add(profile.id);
  await assert.rejects(f.service.call('updateProfile', { id: profile.id, profile: { deviceProfileId: 'provider-default' } }), { code: 'PROFILE_RUNNING' });
  f.service.starting.delete(profile.id);
});

test('externally changed native settings cannot launch under a stale fixed device label', async t => {
  const f = await fixture(t), profile = await f.create({ deviceProfileId: 'mac-standard-v1' });
  f.profiles[0].fingerprint['navigator.hardwareConcurrency'] = 4;
  await assert.rejects(f.service.call('startProfile', { id: profile.id }), { code: 'DEVICE_PROFILE_CONFLICT' });
  assert.equal(f.requests.filter(r => r.route === '/api/sessions' && r.method === 'POST').length, 0);
  delete f.profiles[0].fingerprint['navigator.hardwareConcurrency'];
  await assert.rejects(f.service.call('startProfile', { id: profile.id }), { code: 'DEVICE_PROFILE_CONFLICT' });
});


test('generated identity metadata survives desktop snapshots, export, import and unrelated edits', async t => {
  const f = await fixture(t), source = await f.create({ seed: 9801 });
  const generation = { provider: 'cloakbrowser', version: 1, tuple_id: 'mac-retina-v1', generated_fields: { 'screen.width': 1440, 'screen.height': 900 } };
  Object.assign(f.profiles[0], { fingerprint_generation: generation, fingerprint: { ...generation.generated_fields } });
  const snapshot = (await f.service.snapshot()).profiles[0];
  assert.deepEqual(snapshot.fingerprintGeneration, generation);
  const document = await f.service.exportProfiles({ id: source.id });
  assert.deepEqual(document.profiles[0].fingerprintGeneration, generation);
  const result = await f.service.call('importProfiles', { document });
  const imported = result.profiles.find(p => p.id === result.actionResult.createdIds[0]);
  assert.deepEqual(imported.fingerprintGeneration, generation);
  assert.deepEqual(imported.fingerprint, snapshot.fingerprint);
  assert.equal(imported.seed, snapshot.seed);
  const request = f.requests.filter(r => r.method === 'POST' && r.route === '/api/profiles').at(-1);
  assert.equal(request.body.identity_mode, 'preserve');
  await f.service.call('updateProfile', { id: source.id, profile: { notes: 'Keep identity' } });
  assert.deepEqual(f.profiles[0].fingerprint_generation, generation);
  const invalid = { ...document.profiles[0], fingerprintGeneration: { ...generation, provider: 'camoufox' } };
  await assert.rejects(f.service.call('importProfiles', { profiles: [invalid] }), { code: 'VALIDATION_ERROR' });
});

test('legacy imports explicitly preserve an absent seed and never request new identity generation', async t => {
  const f = await fixture(t);
  const result = await f.service.call('importProfiles', { profiles: [{ name: 'Legacy', engine: 'cloakbrowser', fingerprint: {} }] });
  const request = f.requests.find(r => r.method === 'POST' && r.route === '/api/profiles');
  assert.equal(request.body.identity_mode, 'preserve');
  assert.equal(request.body.fingerprint_seed, 0);
  assert.equal(request.body.fingerprint_generation, undefined);
  assert.equal(result.profiles[0].seed, null);
});


test('choosing a fixed or custom value revokes generated ownership even when the value is unchanged', async t => {
  const f = await fixture(t), source = await f.create({ seed: 9802 });
  const fields = deviceProfileFingerprint('mac-standard-v1');
  f.profiles[0].fingerprint = { ...fields };
  f.profiles[0].fingerprint_generation = { provider: 'cloakbrowser', version: 1, tuple_id: 'mac-retina-v1', generated_fields: { ...fields } };
  await f.service.call('updateProfile', { id: source.id, profile: { notes: 'Only a note', width: fields['screen.width'], height: fields['screen.height'] } });
  assert.deepEqual(f.profiles[0].fingerprint_generation.generated_fields, fields);
  await f.service.call('updateProfile', { id: source.id, profile: { fingerprint: { 'navigator.hardwareConcurrency': 8 } } });
  assert.equal(Object.hasOwn(f.profiles[0].fingerprint_generation.generated_fields, 'navigator.hardwareConcurrency'), false);
  assert.equal(f.profiles[0].fingerprint_generation.generated_fields['screen.width'], 1440);
  await f.service.call('updateProfile', { id: source.id, profile: { deviceProfileId: 'mac-standard-v1' } });
  assert.deepEqual(f.profiles[0].fingerprint_generation.generated_fields, {});
  assert.equal(f.profiles[0].fingerprint_generation.version, 1, 'manual hardware keeps the native noise generation version');
  assert.deepEqual(f.profiles[0].fingerprint, fields);
  const result = await f.service.call('cloneProfile', { id: source.id });
  assert.deepEqual(result.profiles.find(p => p.id === result.actionResult.createdId).fingerprint, fields);
});


test('editing a legacy environment without a seed never creates a new identity', async t => {
  const f = await fixture(t);
  const result = await f.service.call('importProfiles', { profiles: [{ name: 'Legacy zero seed', engine: 'cloakbrowser', fingerprint: { 'screen.width': 1280 } }] });
  const id = result.actionResult.createdIds[0], before = structuredClone(f.profiles[0].fingerprint);
  await f.service.call('updateProfile', { id, profile: { notes: 'A note', seed: null } });
  assert.equal(f.profiles[0].fingerprint_seed, 0);
  assert.deepEqual(f.profiles[0].fingerprint, before);
});

test('Camoufox templates use only pinned native properties and leave RAM and the inner viewport native', async () => {
  const schema = JSON.parse(await readFile(new URL('../third_party/browseforge/internal/profile/camoufox-data/native-properties.json', import.meta.url), 'utf8'));
  const properties = new Set(schema.map(item => item.property));
  for (const device of BROWSER_DEVICE_PROFILES) {
    const fields = deviceProfileFingerprint(device.id, 'camoufox');
    for (const key of Object.keys(fields)) assert(properties.has(key), `native Camoufox property: ${key}`);
    assert.equal(fields['window.devicePixelRatio'], device.deviceScaleFactor);
    assert.equal(fields['navigator.hardwareConcurrency'], device.hardwareConcurrency);
    assert.equal(fields['screen.availWidth'], fields['screen.width']);
    assert.equal(fields['screen.availHeight'], fields['screen.height']);
    assert.equal(fields['window.outerWidth'], fields['screen.width']);
    assert.equal(fields['window.outerHeight'], fields['screen.height']);
    for (const key of ['navigator.deviceMemory', 'screen.devicePixelRatio', 'window.innerWidth', 'window.innerHeight']) assert.equal(Object.hasOwn(fields, key), false, key);
  }
});

test('applying a native template replaces dependent geometry without replacing the provider identity', () => {
  const old = { 'screen.width': 2560, 'screen.availWidth': 2500, 'window.outerWidth': 2400, 'window.innerWidth': 2300,
    'screen.height': 1440, 'screen.availHeight': 1400, 'window.outerHeight': 1350, 'window.innerHeight': 1280,
    'navigator.deviceMemory': 4, 'screen.devicePixelRatio': 1, 'webGl:vendor': 'provider sample', fonts: ['Sample Font'], 'canvas:aaOffset': 17 };
  const before = structuredClone(old);
  for (const engine of ['camoufox', 'browseforge-chromium']) {
    const changed = applyBrowserDeviceProfile(old, 'mac-standard-v1', engine);
    for (const [key, value] of Object.entries(deviceProfileFingerprint('mac-standard-v1', engine))) assert.deepEqual(changed[key], value);
    assert.equal(Object.hasOwn(changed, 'window.innerWidth'), false);
    assert.equal(Object.hasOwn(changed, 'window.innerHeight'), false);
    assert.deepEqual(changed.fonts, old.fonts); assert.equal(changed['webGl:vendor'], old['webGl:vendor']);
    assert.equal(changed['canvas:aaOffset'], old['canvas:aaOffset']);
    if (engine === 'camoufox') {
      assert.equal(Object.hasOwn(changed, 'navigator.deviceMemory'), false);
      assert.equal(Object.hasOwn(changed, 'screen.devicePixelRatio'), false);
    } else {
      assert.equal(Object.hasOwn(changed, 'window.outerWidth'), false);
      assert.equal(Object.hasOwn(changed, 'screen.availWidth'), false);
    }
  }
  assert.deepEqual(old, before);
});

test('new providers apply templates only on selection and preserve the saved identity through unrelated edits and import', async t => {
  for (const engine of ['camoufox', 'browseforge-chromium']) await t.test(engine, async t => {
    const f = await fixture(t), source = await f.create({ engine });
    const fields = { 'screen.width': 2560, 'screen.height': 1440, 'screen.availWidth': 2560, 'screen.availHeight': 1400,
      'window.outerWidth': 2400, 'window.outerHeight': 1300, 'window.innerWidth': 2300, 'window.innerHeight': 1200,
      'navigator.hardwareConcurrency': 12, 'webGl:vendor': 'sample vendor', fonts: ['Sample Font'], 'custom.fixture': true };
    Object.assign(f.profiles[0], { identity: { target_os: 'macos' }, fingerprint: structuredClone(fields), fingerprint_generation: { provider: engine, version: 1, tuple_id: 'synthetic-source', generated_fields: structuredClone(fields) } });
    const seed = f.profiles[0].fingerprint_seed;
    await f.service.call('updateProfile', { id: source.id, profile: { notes: 'No identity change' } });
    assert.deepEqual(f.profiles[0].fingerprint, fields);
    assert.deepEqual(f.profiles[0].fingerprint_generation.generated_fields, fields);
    await f.service.call('updateProfile', { id: source.id, profile: { deviceProfileId: 'mac-standard-v1' } });
    const selected = applyBrowserDeviceProfile(fields, 'mac-standard-v1', engine);
    assert.deepEqual(f.profiles[0].fingerprint, selected);
    assert.equal(f.profiles[0].fingerprint_seed, seed);
    for (const key of Object.keys(selected).filter(key => /^(screen\.|window\.|navigator\.hardwareConcurrency)/.test(key))) assert.equal(Object.hasOwn(f.profiles[0].fingerprint_generation.generated_fields, key), false, key);
    assert.equal(f.profiles[0].fingerprint_generation.generated_fields['webGl:vendor'], fields['webGl:vendor']);
    const generation = structuredClone(f.profiles[0].fingerprint_generation);
    await f.service.call('updateProfile', { id: source.id, profile: { deviceProfileId: 'mac-standard-v1', width: 1440, height: 900, notes: 'Form resubmits the saved choice' } });
    assert.deepEqual(f.profiles[0].fingerprint, selected);
    assert.deepEqual(f.profiles[0].fingerprint_generation, generation);
    const exported = await f.service.exportProfiles({ id: source.id });
    // Independent custom viewport settings are not part of a later import edit.
    exported.profiles[0].fingerprint['window.innerWidth'] = 1280;
    exported.profiles[0].fingerprint['window.innerHeight'] = 720;
    const importedResult = await f.service.call('importProfiles', { document: exported });
    const importedId = importedResult.actionResult.createdIds[0];
    const imported = f.profiles.find(profile => profile.id === importedId);
    assert.deepEqual(imported.fingerprint, exported.profiles[0].fingerprint);
    assert.deepEqual(imported.fingerprint_generation, generation);
    await f.service.call('updateProfile', { id: importedId, profile: { deviceProfileId: 'mac-standard-v1', notes: 'Retain the imported identity' } });
    assert.deepEqual(imported.fingerprint, exported.profiles[0].fingerprint);
    assert.deepEqual(imported.fingerprint_generation, generation);
  });
});

test('new provider fixed labels reject mismatched native device settings before launch', async t => {
  for (const engine of ['camoufox', 'browseforge-chromium']) await t.test(engine, async t => {
    const f = await fixture(t), profile = await f.create({ engine, deviceProfileId: 'mac-standard-v1' });
    const dprKey = engine === 'camoufox' ? 'window.devicePixelRatio' : 'screen.devicePixelRatio';
    f.profiles[0].fingerprint[dprKey] = 1;
    await assert.rejects(f.service.call('startProfile', { id: profile.id }), { code: 'DEVICE_PROFILE_CONFLICT' });
    assert.equal(f.requests.filter(r => r.route === '/api/sessions' && r.method === 'POST').length, 0);
  });
});

test('an incomplete fixed import is rejected rather than synthesizing missing identity fields', async t => {
  for (const engine of ['cloakbrowser', 'camoufox', 'browseforge-chromium']) await t.test(engine, async t => {
    const f = await fixture(t);
    const fingerprint = deviceProfileFingerprint('mac-standard-v1', engine);
    delete fingerprint['navigator.hardwareConcurrency'];
    await assert.rejects(f.service.call('importProfiles', { profiles: [{ name: 'Incomplete template', engine, deviceProfileId: 'mac-standard-v1', fingerprint }] }), { code: 'DEVICE_PROFILE_CONFLICT' });
    assert.equal(f.profiles.length, 0);
    assert.equal(f.requests.filter(r => r.route === '/api/profiles' && r.method === 'POST').length, 0);
  });
});

test('Camoufox fixed templates reject incompatible or unidentifiable old OS identities without rewriting them', async t => {
  const f = await fixture(t);
  for (const fields of [
    { identity: { target_os: 'windows' }, fingerprint: { fonts: ['Fixture'] } },
    { identity: { target_os: 'macos' }, fingerprint: { 'navigator.platform': 'Win32', fonts: ['Fixture'] } },
    { fingerprint: { 'navigator.platform': 'Win32', 'navigator.oscpu': 'Windows NT 10.0; Win64; x64', fonts: ['Fixture'] } },
    { fingerprint: { 'navigator.userAgent': 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/135.0' } },
    { fingerprint: { 'webGl:vendor': 'Unknown origin fixture', fonts: ['Fixture'] } },
  ]) {
    const created = await f.create({ engine: 'camoufox' });
    const native = f.profiles.find(profile => profile.id === created.id);
    Object.assign(native, fields);
    const before = structuredClone(native);
    await assert.rejects(f.service.call('updateProfile', { id: created.id, profile: { deviceProfileId: 'mac-standard-v1' } }), { code: 'DEVICE_PROFILE_CONFLICT' });
    assert.deepEqual(native, before);
    assert.equal((await f.service.snapshot()).profiles.find(profile => profile.id === created.id).deviceProfileId, 'provider-default');
  }
  const legacy = await f.create({ engine: 'camoufox', fingerprint: { 'navigator.platform': 'MacIntel', 'navigator.oscpu': 'Intel Mac OS X 10.15', fonts: ['Fixture'] } });
  await f.service.call('updateProfile', { id: legacy.id, profile: { deviceProfileId: 'mac-standard-v1' } });
  const native = f.profiles.find(profile => profile.id === legacy.id);
  assert.deepEqual(native.fingerprint.fonts, ['Fixture']);
  assert.equal(native.fingerprint['navigator.platform'], 'MacIntel');
  assert.equal(native.fingerprint['window.devicePixelRatio'], 2);
});

test('Camoufox OS consistency is checked for fixed creation, import and launch', async t => {
  const f = await fixture(t);
  const fingerprint = { ...deviceProfileFingerprint('mac-standard-v1', 'camoufox'), 'navigator.platform': 'Win32' };
  await assert.rejects(f.create({ engine: 'camoufox', deviceProfileId: 'mac-standard-v1', fingerprint }), { code: 'DEVICE_PROFILE_CONFLICT' });
  await assert.rejects(f.service.call('importProfiles', { profiles: [{ name: 'Conflicting OS', engine: 'camoufox', deviceProfileId: 'mac-standard-v1', fingerprint }] }), { code: 'DEVICE_PROFILE_CONFLICT' });
  assert.equal(f.profiles.length, 0);
  const created = await f.create({ engine: 'camoufox', deviceProfileId: 'mac-standard-v1' });
  f.profiles[0].fingerprint['navigator.platform'] = 'Linux x86_64';
  await assert.rejects(f.service.call('startProfile', { id: created.id }), { code: 'DEVICE_PROFILE_CONFLICT' });
  assert.equal(f.requests.filter(r => r.route === '/api/sessions' && r.method === 'POST').length, 0);
});
