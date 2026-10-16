import { PROVIDER_DEFAULT_DEVICE_PROFILE_ID, getBrowserDeviceProfile, supportsBrowserDeviceProfiles } from '../shared/browser-device-profile.mjs';

// Form-only provenance survives React state spreads but is never serialized.
const beforeDevicePreset = Symbol('beforeDevicePreset');

// Editing an old environment is not consent to replace its device settings.
export function initialBrowserDeviceFields(profile, hostPlatform, engine) {
  const deviceProfileId = profile?.deviceProfileId || PROVIDER_DEFAULT_DEVICE_PROFILE_ID;
  if (!profile) return { deviceProfileId, width: '', height: '' };
  return {
    deviceProfileId,
    ...(profile.platform == null ? { platform: '' } : {}),
    ...(profile.seed == null ? { seed: '' } : {}),
  };
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
  const previous = getBrowserDeviceProfile(form.deviceProfileId ?? PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  if (!device) {
    const next = { ...form, deviceProfileId };
    const baseline = form[beforeDevicePreset];
    delete next[beforeDevicePreset];
    if (previous) {
      for (const key of ['width', 'height']) {
        if (browserDimensionValue(form[key]) === previous[key]) next[key] = baseline?.[key] ?? '';
      }
      if (baseline && form.platform === previous.platform) next.platform = baseline.platform ?? '';
    }
    return next;
  }
  const baseline = previous ? form[beforeDevicePreset] : { platform: form.platform, width: form.width, height: form.height };
  return {
    ...form,
    deviceProfileId,
    platform: device.platform, width: device.width, height: device.height,
    ...(baseline ? { [beforeDevicePreset]: baseline } : {}),
  };
}

export function changeBrowserDeviceEngine(form, engine) {
  const next = supportsBrowserDeviceProfiles(engine) ? form : selectBrowserDeviceProfile(form, PROVIDER_DEFAULT_DEVICE_PROFILE_ID);
  return { ...next, engine };
}
