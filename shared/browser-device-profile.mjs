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

/** Other providers keep their own configuration until their mappings are tested. */
export function supportsBrowserDeviceProfiles(engine) {
  return (typeof engine === 'string' ? engine : engine?.id) === 'cloakbrowser';
}

export function deviceProfileFingerprint(id) {
  const profile = getBrowserDeviceProfile(id);
  if (!profile) return {};
  return {
    'screen.width': profile.width,
    'screen.height': profile.height,
    'screen.devicePixelRatio': profile.deviceScaleFactor,
    'navigator.hardwareConcurrency': profile.hardwareConcurrency,
    'navigator.deviceMemory': profile.deviceMemory,
  };
}

/** Validate explicit edits/imports against an immutable versioned specification. */
export function validateBrowserDeviceProfileInput(input, engine, hostPlatform) {
  const profile = getBrowserDeviceProfile(input.deviceProfileId);
  if (!profile) return null;
  if (!supportsBrowserDeviceProfiles(engine)) throw Object.assign(new Error('此浏览器内核暂不支持固定设备档案，请保留现有配置。'), { code: 'DEVICE_PROFILE_UNSUPPORTED' });
  if (hostPlatform != null && profile.id !== defaultBrowserDeviceProfileId(hostPlatform)) throw Object.assign(new Error('固定设备档案须与本机平台一致。跨平台配置请使用自定义。'), { code: 'DEVICE_PROFILE_PLATFORM_UNSUPPORTED' });
  const conflict = () => { throw Object.assign(new Error('设备档案与平台或硬件参数不一致。请先切换为自定义配置。'), { code: 'DEVICE_PROFILE_CONFLICT' }); };
  for (const key of ['platform', 'width', 'height']) if (input[key] != null && input[key] !== profile[key]) conflict();
  for (const [key, value] of Object.entries(deviceProfileFingerprint(profile.id))) {
    if (Object.hasOwn(input.fingerprint ?? {}, key) && input.fingerprint[key] !== value) conflict();
  }
  return profile;
}
