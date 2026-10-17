/** Versioned browser-visible device settings. A country never selects hardware.
 * Provider-managed fields (GPU, fonts and native OS identity) are not fabricated
 * here; these records describe browser settings, not physical machine specs. */
export const PROVIDER_DEFAULT_DEVICE_PROFILE_ID = 'provider-default';

export const BROWSER_DEVICE_PROFILES = Object.freeze([
  { id: 'mac-standard-v1', label: 'macOS 标准设备', platform: 'macos', width: 1440, height: 900, deviceScaleFactor: 2, hardwareConcurrency: 8, deviceMemory: 8 },
  { id: 'windows-standard-v1', label: 'Windows 标准设备', platform: 'windows', width: 1920, height: 1080, deviceScaleFactor: 1, hardwareConcurrency: 8, deviceMemory: 8 },
  { id: 'linux-standard-v1', label: 'Linux 标准设备', platform: 'linux', width: 1920, height: 1080, deviceScaleFactor: 1, hardwareConcurrency: 8, deviceMemory: 8 },
].map(profile => Object.freeze(profile)));

export function getBrowserDeviceProfile(id) {
  if (id === PROVIDER_DEFAULT_DEVICE_PROFILE_ID) return null;
  const profile = BROWSER_DEVICE_PROFILES.find(item => item.id === id);
  if (!profile) throw Object.assign(new Error('浏览器设备档案无效。'), { code: 'DEVICE_PROFILE_INVALID' });
  return profile;
}

export function defaultBrowserDeviceProfileId(platform) {
  const normalized = { darwin: 'macos', win32: 'windows' }[platform] ?? platform;
  return BROWSER_DEVICE_PROFILES.find(item => item.platform === normalized)?.id ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
}

const deviceProfileEngine = engine => typeof engine === 'string' ? engine : engine?.id;

/** Each supported provider has a native field mapping; Firefox has no RAM API. */
export function supportsBrowserDeviceProfiles(engine) {
  return ['cloakbrowser', 'camoufox', 'browseforge-chromium'].includes(deviceProfileEngine(engine));
}

export function deviceProfileFingerprint(id, engine = 'cloakbrowser') {
  const profile = getBrowserDeviceProfile(id);
  if (!profile) return {};
  if (deviceProfileEngine(engine) === 'camoufox') return {
    'screen.width': profile.width,
    'screen.height': profile.height,
    'screen.availWidth': profile.width,
    'screen.availHeight': profile.height,
    'screen.availLeft': 0,
    'screen.availTop': 0,
    'window.outerWidth': profile.width,
    'window.outerHeight': profile.height,
    'window.screenX': 0,
    'window.screenY': 0,
    'window.devicePixelRatio': profile.deviceScaleFactor,
    'navigator.hardwareConcurrency': profile.hardwareConcurrency,
  };
  return {
    'screen.width': profile.width,
    'screen.height': profile.height,
    'screen.devicePixelRatio': profile.deviceScaleFactor,
    'navigator.hardwareConcurrency': profile.hardwareConcurrency,
    'navigator.deviceMemory': profile.deviceMemory,
  };
}

// Selecting a preset owns dependent geometry too. Chromium derives its window
// from the new screen; Camoufox accepts an explicit outer window and keeps its
// native inner viewport. These are browser-visible settings, not host work areas.
export function deviceProfileReplacedFields(engine) {
  const geometry = ['screen.availWidth', 'screen.availHeight', 'window.outerWidth', 'window.outerHeight', 'window.innerWidth', 'window.innerHeight'];
  if (deviceProfileEngine(engine) === 'camoufox') return [...geometry, 'screen.devicePixelRatio', 'navigator.deviceMemory'];
  return deviceProfileEngine(engine) === 'browseforge-chromium' ? geometry : geometry.slice(0, 2);
}

export function applyBrowserDeviceProfile(fingerprint, id, engine = 'cloakbrowser') {
  const next = { ...fingerprint };
  if (!getBrowserDeviceProfile(id)) return next;
  for (const key of deviceProfileReplacedFields(engine)) delete next[key];
  return Object.assign(next, deviceProfileFingerprint(id, engine));
}

function deviceProfileConflict() {
  throw Object.assign(new Error('设备档案与平台或硬件参数不一致。请先切换为自定义配置。'), { code: 'DEVICE_PROFILE_CONFLICT' });
}

// Camoufox's saved fonts and complete WebGL families belong to its sampled OS.
// A hardware template must never relabel that identity as a different platform.
export function validateBrowserDeviceProfileIdentity(id, engine, input, { requireKnownOrigin = false } = {}) {
  const profile = getBrowserDeviceProfile(id);
  if (!profile || deviceProfileEngine(engine) !== 'camoufox') return;
  const fingerprint = input?.fingerprint ?? {};
  const platforms = [input?.platform, input?.identity?.target_os, input?.launch_overrides?.target_os].filter(Boolean);
  for (const key of ['navigator.platform', 'navigator.oscpu', 'navigator.userAgent']) {
    const value = fingerprint[key];
    if (typeof value !== 'string') continue;
    if (/\b(?:Win32|Win64|Windows)\b/i.test(value)) platforms.push('windows');
    if (/\b(?:MacIntel|MacPPC|Macintosh|Mac OS X)\b/i.test(value)) platforms.push('macos');
    if (/\bLinux\b/i.test(value)) platforms.push('linux');
  }
  if (platforms.some(platform => platform !== profile.platform) ||
      requireKnownOrigin && !platforms.length && Object.keys(fingerprint).some(key => /^(?:webGl2?:|fonts$|navigator\.(?:platform|oscpu|userAgent)$)/.test(key))) {
    throw Object.assign(new Error('现有 Camoufox 身份与所选模板的平台不一致或无法确认。请保留自定义配置，或新建环境后选择模板。'), { code: 'DEVICE_PROFILE_CONFLICT' });
  }
}

/** Validate explicit edits/imports against an immutable versioned specification. */
export function validateBrowserDeviceProfileInput(input, engine, hostPlatform, { requireComplete = false } = {}) {
  const profile = getBrowserDeviceProfile(input.deviceProfileId);
  if (!profile) return null;
  if (!supportsBrowserDeviceProfiles(engine)) throw Object.assign(new Error('此浏览器内核暂不支持固定设备档案，请保留现有配置。'), { code: 'DEVICE_PROFILE_UNSUPPORTED' });
  if (hostPlatform != null && profile.id !== defaultBrowserDeviceProfileId(hostPlatform)) throw Object.assign(new Error('固定设备档案须与本机平台一致。跨平台配置请使用自定义。'), { code: 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED' });
  validateBrowserDeviceProfileIdentity(profile.id, engine, input);
  for (const key of ['platform', 'width', 'height']) if (input[key] != null && input[key] !== profile[key]) deviceProfileConflict();
  for (const [key, value] of Object.entries(deviceProfileFingerprint(profile.id, engine))) {
    if ((requireComplete || Object.hasOwn(input.fingerprint ?? {}, key)) && input.fingerprint?.[key] !== value) deviceProfileConflict();
  }
  return profile;
}
