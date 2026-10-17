// Google Maps URLs need no API key. Links are parsed locally; this module never
// fetches a URL or claims to have geocoded a street address.
// https://developers.google.com/maps/documentation/urls/get-started
const fail = (message, code = 'INVALID_NETWORK_LOCATION') => Object.assign(new Error(message), { code });
const allowed = new Set(['mode', 'confirmed', 'label', 'mapsUrl', 'latitude', 'longitude', 'accuracy', 'accuracyKind', 'source', 'coordinateSource', 'addressResolved', 'referenceLocation', 'confirmedAt', 'detectedAt', 'egressIP', 'egressTimezone', 'timezone', 'countryCode']);
const has = (value) => value !== undefined && value !== null && value !== '';
function text(value, max = 500) {
  if (value == null) return '';
  if (typeof value !== 'string' || value.length > max || /[\x00-\x1f\x7f]/.test(value)) throw fail('位置文本格式无效。');
  return value.trim();
}
function coordinate(value, min, max) {
  const number = typeof value === 'string' && /^[-+]?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value.trim()) ? Number(value) : value;
  if (typeof number !== 'number' || !Number.isFinite(number) || number < min || number > max) throw fail('位置坐标超出有效范围。');
  return Object.is(number, -0) ? 0 : number;
}
function coordinates(latitude, longitude) {
  if (!has(latitude) && !has(longitude)) return null;
  if (!has(latitude) || !has(longitude)) throw fail('请同时填写纬度和经度。');
  return { latitude: coordinate(latitude, -90, 90), longitude: coordinate(longitude, -180, 180) };
}
// Optional map context is kept separate from the IP estimate and never becomes
// browser/native geolocation. Imports may preserve it as a nearby reference.
function nearbyReference(value) {
  if (value == null) return null;
  const keys = new Set(['kind', 'label', 'latitude', 'longitude', 'source', 'attribution']);
  if (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.has(key)) ||
      value.kind !== 'nearby-reference' || value.source !== 'Photon' || value.attribution !== '© OpenStreetMap contributors') throw fail('位置文本格式无效。');
  const point = coordinates(value.latitude, value.longitude), label = text(value.label);
  if (!point || !label) throw fail('位置文本格式无效。');
  return { kind: 'nearby-reference', label, ...point, source: 'Photon', attribution: '© OpenStreetMap contributors' };
}
function pair(value) {
  if (typeof value !== 'string') return null;
  const match = /^\s*([-+]?(?:\d+(?:\.\d*)?|\.\d+))\s*,\s*([-+]?(?:\d+(?:\.\d*)?|\.\d+))\s*$/.exec(value);
  return match ? coordinates(match[1], match[2]) : null;
}
function timezone(value) {
  const input = text(value, 128);
  try { return new Intl.DateTimeFormat('en', { timeZone: input }).resolvedOptions().timeZone; }
  catch { throw fail('网络环境时区无效。'); }
}
function countryCode(value) {
  const input = text(value, 2).toUpperCase();
  if (!/^[A-Z]{2}$/.test(input)) throw fail('网络环境国家代码无效。');
  return input;
}

/** Accept explicit search pins or place data, never the @ map camera centre. */
export function parseGoogleMapsLocation(value) {
  const input = text(value, 2048);
  if (!input) return null;
  let url;
  try { url = new URL(input); } catch { throw fail('请填写有效的 Google Maps 链接。'); }
  const short = url.hostname === 'maps.app.goo.gl';
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      (!short && !['google.com', 'www.google.com', 'maps.google.com'].includes(url.hostname)) ||
      (!short && url.hostname !== 'maps.google.com' && !/^\/maps(?:\/|$)/.test(url.pathname))) throw fail('位置链接仅支持 HTTPS Google Maps。');
  const query = url.searchParams.get('query') ?? url.searchParams.get('q') ?? '';
  let selected = pair(query);
  // Place links contain selected latitude/longitude in !3d…!4d…; @… is a
  // viewport and may be kilometres away from the chosen place.
  const point = /!3d([-+]?[\d.]+)!4d([-+]?[\d.]+)/.exec(url.pathname);
  if (!selected && point) selected = coordinates(point[1], point[2]);
  return { mapsUrl: url.href, label: query && !pair(query) ? text(query) : '', ...(selected ?? {}), coordinateSource: selected ? 'google-maps-link' : null, addressResolved: false };
}

export function googleMapsLocationURL({ latitude, longitude, label = '' } = {}) {
  const point = coordinates(latitude, longitude);
  const query = point ? `${point.latitude},${point.longitude}` : text(label);
  if (!query) return null;
  const url = new URL('https://www.google.com/maps/search/');
  url.searchParams.set('api', '1');
  url.searchParams.set('query', query);
  return url.href;
}

/** A city-scale recommendation comes only from the authenticated egress. */
export function recommendNetworkLocation(network) {
  if (!network?.ok || network.scope !== 'egress' || !network.ip || !network.timezone) return null;
  const point = network.geolocation ? coordinates(network.geolocation.latitude, network.geolocation.longitude) : null;
  const label = [network.city, network.region, network.country ?? network.countryCode].filter(Boolean).map(value => text(value, 100)).filter((value, index, all) => all.indexOf(value) === index).join(', ');
  const accuracy = point ? Math.max(1000, Math.min(1000000, Number(network.geolocation.accuracy) || 50000)) : null;
  return { mode: 'ip', confirmed: false, label, mapsUrl: googleMapsLocationURL({ ...point, label }), latitude: point?.latitude ?? null, longitude: point?.longitude ?? null,
    accuracy, accuracyKind: 'ip-estimate', source: 'ip-estimate', coordinateSource: point ? 'ip-estimate' : null, addressResolved: false,
    detectedAt: network.checkedAt ?? null, egressIP: network.ip, egressTimezone: timezone(network.timezone), timezone: timezone(network.timezone), countryCode: network.countryCode ?? null };
}

/** Validate stored/input data without upgrading a label to resolved coordinates. */
export function normalizeNetworkLocation(value) {
  if (value == null) return null;
  if (typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Object.keys(value).some(key => !allowed.has(key)) ||
      !['ip', 'manual'].includes(value.mode) || value.confirmed !== true) throw fail('请确认网络环境的位置。');
  const explicit = coordinates(value.latitude, value.longitude);
  const parsed = has(value.mapsUrl) ? parseGoogleMapsLocation(value.mapsUrl) : null;
  if (explicit && parsed?.latitude != null && (explicit.latitude !== parsed.latitude || explicit.longitude !== parsed.longitude)) throw fail('Google Maps 链接与填写的坐标不一致。');
  const point = explicit ?? (parsed?.latitude != null ? coordinates(parsed.latitude, parsed.longitude) : null);
  const label = text(value.label) || parsed?.label || '';
  if (!point && !label && !parsed && value.mode !== 'ip') throw fail('请填写地址、Google Maps 链接或坐标。');
  const isIP = value.mode === 'ip';
  const accuracy = isIP && point ? coordinate(value.accuracy ?? 50000, 1000, 1000000) : point ? 1000 : null;
  const referenceLocation = isIP ? nearbyReference(value.referenceLocation) : null;
  return { mode: value.mode, confirmed: true, label, mapsUrl: parsed?.mapsUrl ?? googleMapsLocationURL({ ...point, label }), latitude: point?.latitude ?? null, longitude: point?.longitude ?? null,
    accuracy, accuracyKind: isIP ? 'ip-estimate' : 'simulation-radius', source: isIP ? 'ip-estimate' : 'manual',
    coordinateSource: point ? isIP ? 'ip-estimate' : parsed?.latitude != null && value.coordinateSource !== 'user-coordinate' ? 'google-maps-link' : 'user-coordinate' : null, addressResolved: false,
    ...(referenceLocation ? { referenceLocation } : {}),
    ...(has(value.confirmedAt) ? { confirmedAt: text(value.confirmedAt, 64) } : {}),
    ...(has(value.detectedAt) ? { detectedAt: text(value.detectedAt, 64) } : {}),
    ...(has(value.egressIP) ? { egressIP: text(value.egressIP, 64) } : {}),
    ...(has(value.egressTimezone) ? { egressTimezone: timezone(value.egressTimezone) } : {}),
    ...(has(value.timezone) ? { timezone: timezone(value.timezone) } : {}),
    ...(has(value.countryCode) ? { countryCode: countryCode(value.countryCode) } : {}) };
}

/** Private matching probe supplies all IP provenance; renderer fields cannot. */
export function confirmNetworkLocation(input, network, confirmedAt = new Date().toISOString(), referenceLocation = null) {
  const recommendation = recommendNetworkLocation(network);
  if (!recommendation) throw fail('请先通过代理验证实际网络出口，再确认位置。', 'NETWORK_LOCATION_NOT_VERIFIED');
  if (input?.confirmed !== true || !['ip', 'manual'].includes(input?.mode)) throw fail('请确认网络环境的位置。');
  if (input.mode === 'ip') return normalizeNetworkLocation({ ...recommendation, confirmed: true, confirmedAt, referenceLocation });
  const manual = normalizeNetworkLocation(input);
  return { ...manual, confirmedAt, detectedAt: recommendation.detectedAt, egressIP: recommendation.egressIP, egressTimezone: recommendation.egressTimezone, timezone: recommendation.timezone, countryCode: recommendation.countryCode };
}

export function networkLocationGeolocation(location) {
  const value = normalizeNetworkLocation(location);
  return value?.latitude != null ? { latitude: value.latitude, longitude: value.longitude, accuracy: value.accuracy } : null;
}

/** IP rotation is allowed; moving the same node to a new region needs consent. */
export function assertNetworkLocationMatchesEgress(location, network) {
  if (location?.confirmed !== true) return;
  const selected = normalizeNetworkLocation(location);
  if (!network?.ok || network.scope !== 'egress' || !network.ip || !network.timezone) throw fail('指定网络出口验证失败，请检查代理后再启动。', 'NETWORK_LOCATION_NOT_VERIFIED');
  let actualTimezone, actualCountry;
  try {
    actualTimezone = timezone(network.timezone);
    actualCountry = has(network.countryCode) ? countryCode(network.countryCode) : null;
  } catch { throw fail('指定网络出口未返回有效的时区和国家信息。', 'NETWORK_LOCATION_NOT_VERIFIED'); }
  if (selected.countryCode && !actualCountry) throw fail('无法核验已确认网络环境的国家，请重新检测代理。', 'NETWORK_LOCATION_NOT_VERIFIED');
  if ([selected.timezone, selected.egressTimezone].filter(Boolean).some(value => value !== actualTimezone) ||
      (selected.countryCode && selected.countryCode !== actualCountry)) {
    throw fail('网络出口的国家或时区已改变，请在网络环境中重新检测并确认位置与时区后再启动。', 'NETWORK_LOCATION_RECONFIRM_REQUIRED');
  }
}
