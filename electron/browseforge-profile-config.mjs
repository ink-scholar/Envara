import { randomInt } from 'node:crypto';
import { normalizePrivacy } from './privacy-policy.mjs';
import { PROVIDER_DEFAULT_DEVICE_PROFILE_ID, applyBrowserDeviceProfile, deviceProfileFingerprint, deviceProfileReplacedFields, getBrowserDeviceProfile, validateBrowserDeviceProfileIdentity, validateBrowserDeviceProfileInput } from '../shared/browser-device-profile.mjs';

const PROFILE_KEYS = new Set(['name', 'group', 'notes', 'engine', 'platform', 'seed', 'locale', 'timezone', 'width', 'height', 'startUrl', 'proxyId', 'tags', 'fingerprint', 'fingerprintGeneration', 'privacy', 'deviceProfileId']);

function error(message, code = 'VALIDATION_ERROR') { return Object.assign(new Error(message), { code }); }
function object(value, label) { if (!value || typeof value !== 'object' || Array.isArray(value)) throw error(`${label}必须是对象。`); return value; }
function fingerprintConfig(value) {
  object(value, '指纹');
  const validate = (entry) => {
    if (entry && typeof entry === 'object') for (const [key, child] of Object.entries(entry)) {
      if (['__proto__', 'constructor', 'prototype'].includes(key) || /password|username|credential|token|secret/i.test(key)) throw error('指纹配置不能包含凭据或保留字段。');
      validate(child);
    }
    else if (entry != null && !['string', 'number', 'boolean'].includes(typeof entry)) throw error('指纹配置必须是 JSON 数据。');
  };
  if (JSON.stringify(value).length > 200000) throw error('指纹配置过大。');
  validate(value);
  return structuredClone(value);
}
function fingerprintGenerationConfig(value, provider) {
  if (value == null) return null;
  object(value, '指纹生成记录');
  if (Object.keys(value).some(key => !['provider', 'version', 'tuple_id', 'generated_fields'].includes(key)) || value.provider !== provider || value.version !== 1 || typeof value.tuple_id !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(value.tuple_id)) throw error('指纹生成记录无效。');
  return { provider, version: 1, tuple_id: value.tuple_id, generated_fields: fingerprintConfig(value.generated_fields) };
}
function text(value, label, maximum = 100, optional = false) {
  if (optional && value == null) return '';
  if (typeof value !== 'string' || value.includes('\0') || value.length > maximum || (!optional && !value.trim())) throw error(`${label}格式无效。`);
  return value.trim();
}
function number(value, label, minimum, maximum) { if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw error(`${label}必须为 ${minimum} 至 ${maximum} 的整数。`); return value; }

export function deviceProfileInput(input, descriptor, { existing } = {}) {
  object(input, '环境配置');
  if (Object.hasOwn(input, 'deviceProfileId')) {
    getBrowserDeviceProfile(input.deviceProfileId);
    return { ...input };
  }
  // A new environment delegates its device defaults to its selected provider.
  // Existing labels and custom/imported fields stay unchanged; only an explicit
  // selection applies one of Envara's fixed device specifications.
  return { ...input, deviceProfileId: existing?.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID };
}

/** Translate persisted profile identity and explicit edits into native fields.
 * No stores, routes, sessions or queues are accessed. Entropy is requested only
 * at the original new-profile seed step, after all preceding validation. */
export function normalizeBrowseForgeProfile(input, descriptor, { hostPlatform, profiles, existing = null,
  preserveIdentity = false, generateSeed = randomInt }) {
  object(input, '环境配置');
  if (Object.hasOwn(input, 'privacy')) normalizePrivacy(input.privacy);
  for (const key of Object.keys(input)) if (!PROFILE_KEYS.has(key)) throw error(`不支持的环境字段：${key}`);
  const name = text(input.name ?? existing?.name, '环境名称');
  const group = text(input.group ?? existing?.group ?? '', '分组', 100, true);
  if (!descriptor || !descriptor.platform_supported) throw error('当前平台不支持所选浏览器内核。', 'UNSUPPORTED_ENGINE');
  const deviceProfile = validateBrowserDeviceProfileInput(input, descriptor, hostPlatform, { requireComplete: preserveIdentity });
  const previousDeviceProfileId = profiles.find(item => item.id === existing?.id)?.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
  const applyDeviceProfile = deviceProfile && !preserveIdentity && (!existing || input.deviceProfileId !== previousDeviceProfileId);
  if (applyDeviceProfile && existing) validateBrowserDeviceProfileIdentity(deviceProfile.id, descriptor, existing, { requireKnownOrigin: true });
  const payload = { name, group, runtime_id: descriptor.id };
  let generation = Object.hasOwn(input, 'fingerprintGeneration')
    ? fingerprintGenerationConfig(input.fingerprintGeneration, descriptor.id)
    : structuredClone(existing?.fingerprint_generation ?? null);
  const launchOverrides = { ...(existing?.launch_overrides ?? {}) };
  if (input.tags != null) { if (!Array.isArray(input.tags) || input.tags.length > 30) throw error('标签格式无效。'); payload.tags = input.tags.map((tag) => text(tag, '标签', 60)); }
  const platform = deviceProfile?.platform ?? input.platform ?? existing?.identity?.target_os;
  if (platform != null) { if (!['macos', 'windows', 'linux'].includes(platform)) throw error('指纹平台无效。'); payload.identity = { ...(existing?.identity ?? {}), target_os: platform }; launchOverrides.target_os = platform; }
  let fingerprint = { ...(existing?.fingerprint ?? {}) };
  if (input.fingerprint != null) Object.assign(fingerprint, fingerprintConfig(input.fingerprint));
  // Imports and ordinary edits retain their complete saved identity. Only a
  // newly selected fixed specification replaces provider-specific geometry.
  if (applyDeviceProfile) fingerprint = applyBrowserDeviceProfile(fingerprint, deviceProfile.id, descriptor);
  // Null explicitly restores provider-managed geometry; an omitted field is
  // an unrelated edit and must retain the user's existing configuration.
  // A fixed specification continues to own its dimensions even for null.
  if (!deviceProfile) {
    if (Object.hasOwn(input, 'width') && input.width === null) {
      delete fingerprint['screen.width']; delete fingerprint['screen.availWidth'];
    }
    if (Object.hasOwn(input, 'height') && input.height === null) {
      delete fingerprint['screen.height']; delete fingerprint['screen.availHeight'];
    }
  }
  if (input.locale === '') {
    launchOverrides.locale = '';
    for (const key of ['navigator.language', 'navigator.languages', 'locale:language', 'locale:region']) delete fingerprint[key];
  } else if (input.locale != null) { let locale; try { locale = Intl.getCanonicalLocales(input.locale)[0]; } catch { throw error('语言代码无效。'); } if (!locale) throw error('语言代码无效。'); fingerprint['navigator.language'] = locale; fingerprint['navigator.languages'] = [...new Set([locale, locale.split('-')[0]])]; const parts = locale.split('-'); fingerprint['locale:language'] = parts[0]; if (parts[1]) fingerprint['locale:region'] = parts[1]; launchOverrides.locale = locale; }
  if (input.timezone === '') { launchOverrides.timezone = ''; delete fingerprint.timezone; }
  else if (input.timezone != null) { try { new Intl.DateTimeFormat('en', { timeZone: input.timezone }); } catch { throw error('时区无效。'); } fingerprint.timezone = input.timezone; launchOverrides.timezone = input.timezone; }
  if (Object.keys(launchOverrides).length) payload.launch_overrides = launchOverrides;
  if (input.width != null) fingerprint['screen.width'] = number(input.width, '屏幕宽度', 800, 7680);
  if (input.height != null) fingerprint['screen.height'] = number(input.height, '屏幕高度', 600, 4320);
  if (Object.keys(fingerprint).length || existing?.fingerprint != null || input.fingerprint != null) payload.fingerprint = fingerprint;
  if (generation && existing && !preserveIdentity) {
    // An explicit selection owns even a value equal to the generated value.
    // Cloning must keep that choice instead of mistaking it for an automatic one.
    const owned = new Set(Object.keys(input.fingerprint ?? {}));
    if (applyDeviceProfile) for (const key of [...Object.keys(deviceProfileFingerprint(deviceProfile.id, descriptor)), ...deviceProfileReplacedFields(descriptor)]) owned.add(key);
    if (Object.hasOwn(input, 'width') && input.width !== (existing.fingerprint?.['screen.width'] ?? null)) { owned.add('screen.width'); owned.add('screen.availWidth'); }
    if (Object.hasOwn(input, 'height') && input.height !== (existing.fingerprint?.['screen.height'] ?? null)) { owned.add('screen.height'); owned.add('screen.availHeight'); }
    for (const key of owned) delete generation.generated_fields[key];
  }
  if (existing || Object.hasOwn(input, 'fingerprintGeneration')) payload.fingerprint_generation = generation;
  if (descriptor.capabilities?.supports_seed_fingerprint) payload.fingerprint_seed = input.seed != null ? number(input.seed, '指纹种子', 1, 4294967295) : existing ? existing.fingerprint_seed ?? 0 : preserveIdentity ? 0 : generateSeed(1, 4294967295);
  else if (input.seed != null) throw error('所选内核使用结构化指纹，不支持种子参数。', 'UNSUPPORTED_CAPABILITY');
  if (existing && input.seed != null && payload.fingerprint_seed !== existing.fingerprint_seed) throw error('现有环境种子不可修改，请克隆新环境。');
  return payload;
}

export { PROFILE_KEYS, error, object, text, number, fingerprintConfig };
