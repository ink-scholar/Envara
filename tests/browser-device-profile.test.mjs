import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { BROWSER_DEVICE_PROFILES, PROVIDER_DEFAULT_DEVICE_PROFILE_ID, defaultBrowserDeviceProfileId, deviceProfileFingerprint, getBrowserDeviceProfile, supportsBrowserDeviceProfiles, validateBrowserDeviceProfileInput } from '../shared/browser-device-profile.mjs';

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
      profiles.push(profile); return { data: structuredClone(profile) };
    }
    const profileMatch = route.match(/^\/api\/profiles\/([A-Za-z0-9_-]+)$/);
    if (method === 'PUT' && profileMatch) {
      const profile = profiles.find(p => p.id === profileMatch[1]); Object.assign(profile, structuredClone(body)); return { data: structuredClone(profile) };
    }
    if (method === 'POST' && route === '/api/sessions') {
      const session = { session_id: `sess_${body.profile_id}`, profile_id: body.profile_id }; sessions.push(session); return { data: session };
    }
    if (/\/eval$/.test(route)) return { data: { language: 'en-US', timezone: 'America/New_York', platform: 'MacIntel' } };
    if (/\/screenshot$/.test(route)) return Buffer.from('fixture');
    if (route === '/api/shutdown') return { data: 'closed' };
    throw new Error('Unsupported fixture request');
  } };
  const networkProbe = { peek: () => null, invalidate() {}, close() {}, probe: async proxy => {
    const malaysia = proxy?.host === 'my.example';
    return { ok: true, ip: malaysia ? '203.0.113.2' : '203.0.113.1', countryCode: malaysia ? 'MY' : 'US', timezone: malaysia ? 'Asia/Kuala_Lumpur' : 'America/New_York', geolocation: null };
  } };
  const service = new BrowseForgeService(root, client, { platform }, () => {}, { profilesDir, networkProbe });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(root, { recursive: true, force: true }); });
  const create = async patch => {
    const result = await service.call('createProfile', { profile: { name: 'Device fixture', engine: 'cloakbrowser', ...patch } });
    return result.profiles.find(p => p.id === result.actionResult.createdId);
  };
  return { root, service, client, profiles, sessions, requests, create };
}

test('device catalog is versioned, country-independent and limited to tested provider mappings', () => {
  assert.equal(defaultBrowserDeviceProfileId('darwin'), 'mac-standard-v1');
  assert.equal(defaultBrowserDeviceProfileId('win32'), 'windows-standard-v1');
  assert.equal(defaultBrowserDeviceProfileId('linux'), 'linux-standard-v1');
  assert.equal(defaultBrowserDeviceProfileId('US'), PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.equal(getBrowserDeviceProfile(PROVIDER_DEFAULT_DEVICE_PROFILE_ID), null);
  assert.throws(() => getBrowserDeviceProfile('us-mac'), { code: 'DEVICE_PROFILE_INVALID' });
  assert(supportsBrowserDeviceProfiles('cloakbrowser')); assert(!supportsBrowserDeviceProfiles('camoufox'));
  assert(BROWSER_DEVICE_PROFILES.every(profile => Object.isFrozen(profile) && !Object.hasOwn(profile, 'country')));
  const fingerprint = deviceProfileFingerprint('mac-standard-v1');
  assert.deepEqual(fingerprint, { 'screen.width': 1440, 'screen.height': 900, 'screen.devicePixelRatio': 2, 'navigator.hardwareConcurrency': 8, 'navigator.deviceMemory': 8 });
  assert(!Object.keys(fingerprint).some(key => /webgl|font|useragent|timezone|language/i.test(key)));
  fingerprint['screen.width'] = 100;
  assert.equal(deviceProfileFingerprint('mac-standard-v1')['screen.width'], 1440);
  assert.throws(() => validateBrowserDeviceProfileInput({ deviceProfileId: 'mac-standard-v1' }, 'camoufox', 'darwin'), { code: 'DEVICE_PROFILE_UNSUPPORTED' });
  assert.throws(() => validateBrowserDeviceProfileInput({ deviceProfileId: 'windows-standard-v1' }, 'cloakbrowser', 'darwin'), { code: 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED' });
});

test('new native-platform drafts persist the concrete browser settings and profile id', async t => {
  for (const [host, id, platform] of [['darwin', 'mac-standard-v1', 'macos'], ['win32', 'windows-standard-v1', 'windows'], ['linux', 'linux-standard-v1', 'linux']]) {
    const f = await fixture(t, host), profile = await f.create();
    assert.equal(profile.deviceProfileId, id); assert.equal(profile.platform, platform);
    assert.deepEqual(f.profiles[0].fingerprint, deviceProfileFingerprint(id));
    assert.equal(f.profiles[0].deviceProfileId, undefined, 'desktop metadata does not leak as an unsupported native field');
    assert.equal((await f.service.store.read()).profiles[0].deviceProfileId, id);
    const saved = JSON.parse(await readFile(path.join(f.root, 'browseforge-manager/workspace.json'), 'utf8'));
    assert.equal(saved.profiles[0].deviceProfileId, id);
  }
});

test('old custom creation calls and unsupported providers preserve their explicit configuration', async t => {
  const f = await fixture(t);
  for (const patch of [
    { platform: 'windows', width: 1920, height: 1080 },
    { platform: 'macos', width: 1280, height: 800 },
    { fingerprint: { 'navigator.hardwareConcurrency': 4, 'navigator.deviceMemory': 4 } },
    { engine: 'camoufox' },
  ]) {
    const result = await f.create(patch);
    assert.equal(result.deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
    if (patch.width) assert.equal(result.width, patch.width);
    if (patch.platform) assert.equal(result.platform, patch.platform);
    if (patch.fingerprint) assert.deepEqual(result.fingerprint, patch.fingerprint);
  }
  await assert.rejects(f.create({ deviceProfileId: 'windows-standard-v1' }), { code: 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED' });
  await assert.rejects(f.create({ engine: 'camoufox', deviceProfileId: 'mac-standard-v1' }), { code: 'DEVICE_PROFILE_UNSUPPORTED' });
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
  assert.deepEqual(f.profiles[0].fingerprint, fingerprint); assert.equal(f.profiles[0].fingerprint_seed, seed);
  assert.equal((await f.service.snapshot()).profiles[0].deviceProfileId, 'mac-standard-v1');
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
  assert.deepEqual(result.profiles.find(p => p.id === result.actionResult.createdIds[0]).fingerprint, deviceProfileFingerprint('mac-standard-v1'));
});

test('clones retain immutable device specs with a fresh seed and no generated noise or browser data', async t => {
  const f = await fixture(t), original = await f.create();
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
  const f = await fixture(t), original = await f.create();
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
  const f = await fixture(t), profile = await f.create();
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
  const f = await fixture(t), profile = await f.create();
  f.profiles[0].fingerprint['navigator.hardwareConcurrency'] = 4;
  await assert.rejects(f.service.call('startProfile', { id: profile.id }), { code: 'DEVICE_PROFILE_CONFLICT' });
  assert.equal(f.requests.filter(r => r.route === '/api/sessions' && r.method === 'POST').length, 0);
  delete f.profiles[0].fingerprint['navigator.hardwareConcurrency'];
  await assert.rejects(f.service.call('startProfile', { id: profile.id }), { code: 'DEVICE_PROFILE_CONFLICT' });
});
