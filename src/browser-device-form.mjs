import { PROVIDER_DEFAULT_DEVICE_PROFILE_ID, defaultBrowserDeviceProfileId, getBrowserDeviceProfile, supportsBrowserDeviceProfiles } from '../shared/browser-device-profile.mjs';

// Editing an old environment is not consent to replace its device settings.
export function initialBrowserDeviceFields(profile, hostPlatform, engine) {
  if (profile) return { deviceProfileId: profile.deviceProfileId || PROVIDER_DEFAULT_DEVICE_PROFILE_ID };
  const id = supportsBrowserDeviceProfiles(engine) ? defaultBrowserDeviceProfileId(hostPlatform) : PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
  return selectBrowserDeviceProfile({}, id);
}

export function selectBrowserDeviceProfile(form, deviceProfileId) {
  const device = getBrowserDeviceProfile(deviceProfileId);
  return {
    ...form,
    deviceProfileId,
    ...(device ? { platform: device.platform, width: device.width, height: device.height } : {}),
  };
}

export function changeBrowserDeviceEngine(form, engine) {
  return { ...form, engine, ...(!supportsBrowserDeviceProfiles(engine) ? { deviceProfileId: PROVIDER_DEFAULT_DEVICE_PROFILE_ID } : {}) };
}
