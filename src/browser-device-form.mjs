import { PROVIDER_DEFAULT_DEVICE_PROFILE_ID, getBrowserDeviceProfile, supportsBrowserDeviceProfiles } from '../shared/browser-device-profile.mjs';

// Editing an old environment is not consent to replace its device settings.
export function initialBrowserDeviceFields(profile, hostPlatform, engine) {
  const deviceProfileId = profile?.deviceProfileId || PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
  return profile ? { deviceProfileId } : { deviceProfileId, width: '', height: '' };
}

// Null explicitly clears a previous override; omission would retain it on edit.
export function browserDimensionValue(value) {
  if (value == null || typeof value === 'string' && !value.trim()) return null;
  return ['number', 'string'].includes(typeof value) ? Number(value) : NaN;
}

export function validBrowserDimension(value, minimum, maximum) {
  const dimension = browserDimensionValue(value);
  return dimension === null || Number.isSafeInteger(dimension) && dimension >= minimum && dimension <= maximum;
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
