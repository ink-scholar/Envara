import test from 'node:test';
import assert from 'node:assert/strict';
import { deviceProfileInput, normalizeBrowseForgeProfile } from '../electron/browseforge-profile-config.mjs';
import { PROVIDER_DEFAULT_DEVICE_PROFILE_ID } from '../shared/browser-device-profile.mjs';

const descriptor = { id: 'cloakbrowser', platform_supported: true, capabilities: { supports_seed_fingerprint: true } };
const base = { name: 'Fixture', deviceProfileId: PROVIDER_DEFAULT_DEVICE_PROFILE_ID };
const options = extra => ({ hostPlatform: 'darwin', profiles: [], ...extra });

test('profile normalization requests entropy only after the original configuration validation stage', () => {
  const calls = [];
  const generateSeed = (...args) => { calls.push(args); return 123456; };
  for (const patch of [{ name: '' }, { unsupported: true }, { tags: 'invalid' }, { locale: 'invalid locale' },
    { timezone: 'Invalid/Timezone' }, { width: 1 }, { seed: 0 }, { fingerprint: { secretToken: 'private' } }]) {
    assert.throws(() => normalizeBrowseForgeProfile({ ...base, ...patch }, descriptor, options({ generateSeed })));
    assert.deepEqual(calls, [], 'rejected configuration must not consume a seed');
  }
  const result = normalizeBrowseForgeProfile(base, descriptor, options({ generateSeed }));
  assert.equal(result.fingerprint_seed, 123456); assert.deepEqual(calls, [[1, 4294967295]]);
});

test('existing, explicit and preserved identities never request replacement entropy', () => {
  const generateSeed = () => assert.fail('An existing or imported identity must not be reseeded');
  const existing = { id: 'profile_a', name: 'Existing', fingerprint_seed: 98765, fingerprint: { 'navigator.hardwareConcurrency': 8 } };
  const kept = normalizeBrowseForgeProfile(base, descriptor, options({ existing, generateSeed }));
  assert.equal(kept.fingerprint_seed, 98765);
  assert.equal(normalizeBrowseForgeProfile({ ...base, seed: 1234 }, descriptor, options({ generateSeed })).fingerprint_seed, 1234);
  assert.equal(normalizeBrowseForgeProfile(base, descriptor, options({ preserveIdentity: true, generateSeed })).fingerprint_seed, 0);
  assert.throws(() => normalizeBrowseForgeProfile({ ...base, seed: 1234 }, descriptor, options({ existing, generateSeed })), /现有环境种子不可修改/);
  const structured = { ...descriptor, id: 'camoufox', capabilities: { supports_seed_fingerprint: false } };
  assert.equal(normalizeBrowseForgeProfile(base, structured, options({ generateSeed })).fingerprint_seed, undefined);
  assert.throws(() => normalizeBrowseForgeProfile({ ...base, seed: 3 }, structured, options({ generateSeed })), { code: 'UNSUPPORTED_CAPABILITY' });
});

test('automatic locale and geometry edits retain unrelated identity and leave saved input untouched', () => {
  const existing = { id: 'profile_a', name: 'Existing', fingerprint_seed: 42,
    launch_overrides: { locale: 'ja-JP', timezone: 'Asia/Tokyo' },
    fingerprint: { 'navigator.language': 'ja-JP', 'navigator.languages': ['ja-JP'], timezone: 'Asia/Tokyo',
      'screen.width': 1440, 'screen.availWidth': 1440, 'screen.height': 900, 'navigator.hardwareConcurrency': 8 },
    fingerprint_generation: { provider: 'cloakbrowser', version: 1, tuple_id: 'fixture_identity', generated_fields: { 'screen.width': 1440, 'navigator.hardwareConcurrency': 8 } } };
  const before = structuredClone(existing);
  const input = { ...base, locale: '', timezone: '', width: null, fingerprint: { 'navigator.hardwareConcurrency': 8 } };
  const result = normalizeBrowseForgeProfile(input, descriptor, options({ existing }));
  assert.deepEqual(result.launch_overrides, { locale: '', timezone: '' });
  assert.equal(result.fingerprint['screen.width'], undefined); assert.equal(result.fingerprint['screen.availWidth'], undefined);
  assert.equal(result.fingerprint['screen.height'], 900); assert.equal(result.fingerprint['navigator.hardwareConcurrency'], 8);
  assert.deepEqual(result.fingerprint_generation.generated_fields, {});
  assert.deepEqual(existing, before);
  assert.equal(input.fingerprint['navigator.hardwareConcurrency'], 8);
});

test('device selection labels remain explicit and do not normalize away existing choices', () => {
  assert.equal(deviceProfileInput({ name: 'new' }, descriptor).deviceProfileId, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  assert.equal(deviceProfileInput({ name: 'edit' }, descriptor, { existing: { deviceProfileId: 'kept-legacy-label' } }).deviceProfileId, 'kept-legacy-label');
  assert.throws(() => deviceProfileInput({ ...base, deviceProfileId: 'not-a-real-profile' }, descriptor));
});
