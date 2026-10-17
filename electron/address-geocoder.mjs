import { createHash } from 'node:crypto';
import { createProxyAgent, proxyFingerprint, requestGeoJSON } from './proxy-network.mjs';

// Photon permits moderate, user-triggered use: one nearby reference after a
// requested egress check, or an explicit address search. No autocomplete or
// periodic queries. A trusted host can supply its own HTTPS Photon instance.
// https://github.com/komoot/photon#demo-server
export const ADDRESS_SEARCH_ENDPOINT = 'https://photon.komoot.io/api/';
const failure = (message, code) => Object.assign(new Error(message), { code });
function addressPoint(value) {
  return value && Number.isFinite(value.latitude) && value.latitude >= -90 && value.latitude <= 90 &&
    Number.isFinite(value.longitude) && value.longitude >= -180 && value.longitude <= 180
    ? { latitude: value.latitude, longitude: value.longitude } : null;
}
export function addressQuery(value) {
  if (typeof value !== 'string' || value.trim().length < 2 || value.length > 500 || /[\x00-\x1f\x7f]/.test(value)) {
    throw failure('请填写 2 至 500 个字符的地址或地点。', 'ADDRESS_QUERY_INVALID');
  }
  return value.trim();
}
export function parseAddressResults(data) {
  if (data?.type !== 'FeatureCollection' || !Array.isArray(data.features) || data.features.length > 50) throw failure('地址查询返回了无效结果。', 'ADDRESS_RESPONSE_INVALID');
  const seen = new Set();
  return data.features.flatMap(feature => {
    if (!Array.isArray(feature?.geometry?.coordinates)) return [];
    const [longitude, latitude] = feature.geometry.coordinates;
    if (feature?.geometry?.type !== 'Point' || !Number.isFinite(latitude) || latitude < -90 || latitude > 90 || !Number.isFinite(longitude) || longitude < -180 || longitude > 180) return [];
    const properties = feature.properties ?? {};
    const clean = value => typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, 160) : '';
    const street = [clean(properties.housenumber), clean(properties.street)].filter(Boolean).join(' ');
    const label = [...new Set([clean(properties.name), street, clean(properties.district), clean(properties.city), clean(properties.state), clean(properties.country)].filter(Boolean))].join(', ').slice(0, 500);
    const id = createHash('sha256').update(`${latitude},${longitude}:${label}`).digest('hex').slice(0, 20);
    if (!label || seen.has(id)) return [];
    seen.add(id);
    return [{ id, label, latitude, longitude }];
  }).slice(0, 5);
}

/** Main-only transport. Callers must provide the selected, verified proxy wire. */
export class AddressGeocoder {
  constructor({ endpoint = ADDRESS_SEARCH_ENDPOINT, transport = requestGeoJSON, timeoutMs = 12000, reverseTimeoutMs = 5000, now = Date.now, minIntervalMs = 1100, cacheTtlMs = 30 * 60 * 1000, tlsOptions = {} } = {}) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) throw new Error('Invalid address search endpoint');
    this.endpoint = url.href; this.reverseEndpoint = new URL('../reverse', url).href;
    this.transport = transport; this.timeoutMs = timeoutMs; this.reverseTimeoutMs = Math.min(timeoutMs, reverseTimeoutMs); this.now = now;
    this.minIntervalMs = minIntervalMs; this.cacheTtlMs = cacheTtlMs; this.tlsOptions = tlsOptions;
    this.cache = new Map(); this.controllers = new Set(); this.inflight = new Map(); this.nextAllowedAt = 0; this.closed = false;
  }
  close() { this.closed = true; for (const controller of this.controllers) controller.abort(); this.cache.clear(); }
  async search({ query, proxy, language = 'en', routeKey, bias }) {
    return this.request({ query: addressQuery(query), proxy, language, routeKey, point: addressPoint(bias) });
  }
  async reverse({ coordinates, proxy, language = 'en', routeKey }) {
    const point = addressPoint(coordinates);
    if (!point) throw failure('位置坐标超出有效范围。', 'ADDRESS_COORDINATES_INVALID');
    const result = await this.request({ proxy, language, routeKey, point, reverse: true });
    const candidate = result.candidates[0];
    return candidate ? { kind: 'nearby-reference', label: candidate.label, latitude: candidate.latitude, longitude: candidate.longitude,
      source: result.source, attribution: result.attribution } : null;
  }
  async request({ query, proxy, language, routeKey, point, reverse = false }) {
    if (this.closed) throw failure('应用正在退出。', 'APP_CLOSING');
    if (!proxy) throw failure('地址查询需要已验证的代理线路。', 'ADDRESS_PROXY_REQUIRED');
    const wireKey = proxyFingerprint(proxy);
    // The public instance indexes these translations. Other UI languages use
    // local place names; this never changes the environment's browser locale.
    const lang = ['en', 'de', 'fr', 'it'].includes(language) ? language : '';
    // A service can key ephemeral AnyTLS listeners by the verified saved route.
    const key = createHash('sha256').update(JSON.stringify([routeKey ?? wireKey, lang, reverse ? 'reverse' : 'search', query ?? null, point])).digest('hex');
    const cached = this.cache.get(key);
    if (cached && this.now() - cached.time < this.cacheTtlMs) return structuredClone(cached.result);
    if (this.inflight.has(key)) return structuredClone(await this.inflight.get(key));
    if (this.now() < this.nextAllowedAt) throw failure('查询过于频繁，请稍后再试。', 'ADDRESS_RATE_LIMITED');
    this.nextAllowedAt = this.now() + this.minIntervalMs;
    const operation = this.lookup({ query, proxy, lang, point, reverse });
    this.inflight.set(key, operation);
    try {
      const result = await operation;
      if (!this.closed) {
        if (this.cache.size >= 64) this.cache.delete(this.cache.keys().next().value);
        this.cache.set(key, { time: this.now(), result });
      }
      return structuredClone(result);
    } finally { this.inflight.delete(key); }
  }
  async lookup({ query, proxy, lang, point, reverse }) {
    const controller = new AbortController(); this.controllers.add(controller);
    let agent;
    try {
      const timeoutMs = reverse ? this.reverseTimeoutMs : this.timeoutMs;
      agent = createProxyAgent(proxy, timeoutMs, this.tlsOptions, controller.signal);
      const url = new URL(reverse ? this.reverseEndpoint : this.endpoint);
      if (!reverse) url.searchParams.set('q', query);
      url.searchParams.set('limit', reverse ? '1' : '5');
      if (point) { url.searchParams.set('lat', String(point.latitude)); url.searchParams.set('lon', String(point.longitude)); }
      // A nearby mapped object supplies context, never a more accurate IP fix.
      if (reverse) url.searchParams.set('radius', '5');
      if (lang) url.searchParams.set('lang', lang);
      const data = await this.transport({ url: url.href, agent, timeoutMs, maxBodyBytes: 65536, tlsOptions: this.tlsOptions, controller,
        headers: { 'User-Agent': 'Envara (address lookup; https://github.com/ink-scholar/Envara)' } });
      return { candidates: parseAddressResults(data), source: 'Photon', attribution: '© OpenStreetMap contributors' };
    } catch (value) {
      if (value.code === 'ADDRESS_RESPONSE_INVALID') throw value;
      throw failure('无法通过所选代理查询地址，请重试或手动填写坐标。', 'ADDRESS_LOOKUP_FAILED');
    } finally { this.controllers.delete(controller); agent?.destroy?.(); }
  }
}
