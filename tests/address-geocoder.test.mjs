import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AddressGeocoder, addressQuery, parseAddressResults } from '../electron/address-geocoder.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { EnvaraService } from '../electron/service.mjs';
import { ProxyNetworkProbe } from '../electron/proxy-network.mjs';
import { networkLocationGeolocation } from '../shared/network-location.mjs';

const proxy = { name: 'Fixture route', protocol: 'http', host: 'proxy.example', port: 8080, username: 'fixture-user', password: 'fixture-password' };
const feature = (name = 'Fixture place', longitude = 139.7, latitude = 35.6) => ({ type: 'Feature', geometry: { type: 'Point', coordinates: [longitude, latitude] }, properties: { name, city: 'Tokyo', country: 'Japan' } });
const collection = (...features) => ({ type: 'FeatureCollection', features });
const geo = { success: true, ip: '8.8.8.8', country: 'Japan', country_code: 'JP', region: 'Tokyo', city: 'Tokyo', timezone: { id: 'Asia/Tokyo' } };

test('address input and returned map candidates are bounded and do not infer extra location evidence', () => {
  assert.equal(addressQuery('  東京駅  '), '東京駅');
  for (const query of ['', 'x', ' '.repeat(5), 'ab\ncd', 'x'.repeat(501), null, {}]) assert.throws(() => addressQuery(query), { code: 'ADDRESS_QUERY_INVALID' });
  for (const data of [null, {}, { type: 'FeatureCollection', features: {} }, collection(...Array(51).fill(feature()))]) assert.throws(() => parseAddressResults(data), { code: 'ADDRESS_RESPONSE_INVALID' });
  const withAddress = feature('  Example\u0000\n Building ');
  withAddress.properties = { ...withAddress.properties, housenumber: '10', street: 'Example Road', district: 'Central', state: 'Tokyo' };
  const results = parseAddressResults(collection(withAddress, withAddress, feature('Invalid latitude', 0, 91), feature('Invalid longitude', 181, 0), { geometry: { type: 'LineString', coordinates: [1, 2] } }, feature('', 0, 0)));
  assert.equal(results.length, 2);
  assert.deepEqual(Object.keys(results[0]).sort(), ['id', 'label', 'latitude', 'longitude']);
  assert.equal(results[0].label, 'Example Building, 10 Example Road, Central, Tokyo, Japan');
  assert.equal(results[0].latitude, 35.6); assert.equal(results[0].longitude, 139.7);
  assert.match(results[0].id, /^[a-f0-9]{20}$/);
  assert.equal(parseAddressResults(collection(...Array.from({ length: 10 }, (_, index) => feature(`Place ${index}`)))).length, 5);
});

test('address lookup uses the selected authenticated proxy and a bounded HTTPS request', async (t) => {
  for (const protocol of ['http', 'https', 'socks5']) {
    const calls = [];
    const geocoder = new AddressGeocoder({ transport: async args => { calls.push(args); return collection(feature()); } });
    t.after(() => geocoder.close());
    const result = await geocoder.search({ query: 'Tokyo Station', proxy: { ...proxy, protocol }, language: 'zh-CN' });
    assert.equal(calls.length, 1);
    const { url, agent, timeoutMs, maxBodyBytes, headers } = calls[0];
    assert.ok(agent && typeof agent.connect === 'function', 'transport must receive a proxy agent, never direct mode');
    assert.equal(protocol === 'socks5' ? agent.proxy.host : agent.proxy.hostname, 'proxy.example');
    const parsed = new URL(url);
    assert.equal(parsed.protocol, 'https:'); assert.equal(parsed.hostname, 'photon.komoot.io');
    assert.equal(parsed.searchParams.get('q'), 'Tokyo Station');
    assert.equal(parsed.searchParams.get('limit'), '5'); assert.equal(parsed.searchParams.has('lang'), false);
    assert.equal(timeoutMs, 12000); assert.equal(maxBodyBytes, 65536);
    assert.match(headers['User-Agent'], /^Envara /);
    assert.equal(result.source, 'Photon'); assert.equal(result.attribution, '© OpenStreetMap contributors');
    for (const secret of [proxy.username, proxy.password, proxy.host]) assert.equal(JSON.stringify(result).includes(secret), false);
  }
  for (const endpoint of ['http://example.invalid/api/', 'https://user:password@example.invalid/api/', 'https://example.invalid/api/?q=x', 'https://example.invalid/api/#fragment']) assert.throws(() => new AddressGeocoder({ endpoint }));
});

test('address lookup fails closed before transport without a valid proxy and redacts transport errors', async (t) => {
  let calls = 0;
  const geocoder = new AddressGeocoder({ minIntervalMs: 0, transport: async () => { calls++; throw new Error(`${proxy.host} ${proxy.username} ${proxy.password}`); } });
  t.after(() => geocoder.close());
  await assert.rejects(geocoder.search({ query: 'Tokyo', proxy: null }), { code: 'ADDRESS_PROXY_REQUIRED' });
  for (const invalid of [{}, { ...proxy, protocol: 'ftp' }, { ...proxy, host: 'bad host' }, { ...proxy, port: 0 }]) await assert.rejects(geocoder.search({ query: 'Tokyo', proxy: invalid }));
  assert.equal(calls, 0);
  await assert.rejects(geocoder.search({ query: 'Tokyo', proxy }), value => value.code === 'ADDRESS_LOOKUP_FAILED' && ![proxy.host, proxy.username, proxy.password].some(secret => value.message.includes(secret)));
  assert.equal(calls, 1);
});

test('identical in-flight queries share one operation and cached results cannot be mutated by callers', async (t) => {
  let complete, calls = 0, time = 100;
  const geocoder = new AddressGeocoder({ now: () => time, cacheTtlMs: 5000, transport: () => { calls++; return new Promise(resolve => { complete = resolve; }); } });
  t.after(() => geocoder.close());
  const first = geocoder.search({ query: 'Tokyo', proxy, language: 'fr' });
  const second = geocoder.search({ query: 'Tokyo', proxy, language: 'fr' });
  assert.equal(calls, 1);
  await assert.rejects(geocoder.search({ query: 'Osaka', proxy }), { code: 'ADDRESS_RATE_LIMITED' });
  complete(collection(feature()));
  const [a, b] = await Promise.all([first, second]);
  a.candidates[0].label = 'Changed by caller';
  assert.notEqual(b.candidates[0].label, a.candidates[0].label);
  assert.notEqual((await geocoder.search({ query: 'Tokyo', proxy, language: 'fr' })).candidates[0].label, a.candidates[0].label);
  assert.equal(calls, 1);
  time += 6000;
  const expired = geocoder.search({ query: 'Tokyo', proxy, language: 'fr' });
  assert.equal(calls, 2); complete(collection(feature('Fresh place')));
  assert.equal((await expired).candidates[0].label.startsWith('Fresh place'), true);
  time += 1100;
  const changedRoute = geocoder.search({ query: 'Tokyo', proxy: { ...proxy, password: 'replacement-secret' }, language: 'fr' });
  assert.equal(calls, 3); complete(collection(feature())); await changedRoute;
});

test('a verified route key reuses results across temporary listeners but keeps different routes isolated', async (t) => {
  const calls = [];
  const geocoder = new AddressGeocoder({ minIntervalMs: 0, transport: async args => { calls.push(args); return collection(feature(`Lookup ${calls.length}`)); } });
  t.after(() => geocoder.close());
  const wire = { protocol: 'http', host: '127.0.0.1', port: 43123, username: 'first-wire-user', password: 'first-wire-password' };
  const first = await geocoder.search({ query: 'Tokyo', proxy: wire, routeKey: 'verified-route-a' });
  const nextWire = { ...wire, port: 43124, username: 'next-wire-user', password: 'next-wire-password' };
  assert.deepEqual(await geocoder.search({ query: 'Tokyo', proxy: nextWire, routeKey: 'verified-route-a' }), first);
  assert.equal(calls.length, 1, 'a new temporary listener for the same verified route should use the cached result');
  const different = await geocoder.search({ query: 'Tokyo', proxy: nextWire, routeKey: 'verified-route-b' });
  assert.equal(calls.length, 2); assert.notDeepEqual(different, first);
  assert.equal(Number(calls[1].agent.proxy.port), nextWire.port, 'an uncached route uses its current listener');
  for (const missing of [null, undefined]) await assert.rejects(geocoder.search({ query: 'Tokyo', proxy: missing, routeKey: 'verified-route-a' }), { code: 'ADDRESS_PROXY_REQUIRED' });
  assert.equal(calls.length, 2);
});

test('nearby lookup uses a bounded proxy request and keeps map context separate from forward search and IP coordinates', async (t) => {
  const calls = [];
  const geocoder = new AddressGeocoder({ minIntervalMs: 0, transport: async args => { calls.push(args); return collection(feature('Nearby street', 139.71, 35.61)); } });
  t.after(() => geocoder.close());
  const coordinates = { latitude: 35.6, longitude: 139.7, accuracy: 50000 };
  const reference = await geocoder.reverse({ coordinates, proxy, language: 'fr' });
  const url = new URL(calls[0].url);
  assert.equal(url.origin, 'https://photon.komoot.io'); assert.equal(url.pathname, '/reverse');
  assert.equal(url.searchParams.get('lat'), '35.6'); assert.equal(url.searchParams.get('lon'), '139.7');
  assert.equal(url.searchParams.get('radius'), '5'); assert.equal(url.searchParams.get('limit'), '1'); assert.equal(url.searchParams.get('lang'), 'fr');
  assert.equal(url.searchParams.has('q'), false); assert.equal(calls[0].timeoutMs, 5000);
  assert.equal(calls[0].agent.proxy.hostname, proxy.host);
  assert.deepEqual(reference, { kind: 'nearby-reference', label: 'Nearby street, Tokyo, Japan', latitude: 35.61, longitude: 139.71, source: 'Photon', attribution: '© OpenStreetMap contributors' });
  assert.deepEqual(coordinates, { latitude: 35.6, longitude: 139.7, accuracy: 50000 });
  reference.label = 'Caller mutation';
  assert.notEqual((await geocoder.reverse({ coordinates, proxy, language: 'fr' })).label, reference.label);
  assert.equal(calls.length, 1, 'the same route/point/language uses the reverse cache');
  await geocoder.search({ query: 'Station Road', proxy, language: 'fr', bias: coordinates });
  assert.equal(calls.length, 2, 'forward queries never reuse reverse results');
  const forward = new URL(calls[1].url);
  assert.equal(forward.pathname, '/api/'); assert.equal(forward.searchParams.get('lat'), '35.6'); assert.equal(forward.searchParams.get('lon'), '139.7');
  assert.equal(forward.searchParams.has('radius'), false, 'a focus ranks search results without imposing a hard region filter');
  await geocoder.search({ query: 'Station Road', proxy, language: 'fr', bias: { latitude: 0, longitude: 0 } });
  assert.equal(calls.length, 3, 'a different verified point cannot reuse old regional results');
  assert.equal(new URL(calls[2].url).searchParams.get('lat'), '0');
  await geocoder.search({ query: 'Station Road', proxy, language: 'fr', bias: { latitude: 91, longitude: 0 } });
  assert.equal(calls.length, 4); assert.equal(new URL(calls[3].url).searchParams.has('lat'), false);
  for (const point of [null, {}, { latitude: 0 }, { latitude: '35', longitude: 139 }, { latitude: NaN, longitude: 0 }, { latitude: 0, longitude: 181 }]) {
    await assert.rejects(geocoder.reverse({ coordinates: point, proxy }), { code: 'ADDRESS_COORDINATES_INVALID' });
  }
  await assert.rejects(geocoder.reverse({ coordinates, proxy: null }), { code: 'ADDRESS_PROXY_REQUIRED' });
  assert.equal(calls.length, 4, 'invalid reverse inputs cannot reach the network');
});

test('closing aborts an active address request and disallows further queries', async () => {
  let signal;
  const geocoder = new AddressGeocoder({ transport: ({ controller }) => { signal = controller.signal; return new Promise((_resolve, reject) => signal.addEventListener('abort', () => reject(new Error('fixture abort')), { once: true })); } });
  const pending = geocoder.search({ query: 'Tokyo', proxy });
  geocoder.close();
  assert.equal(signal.aborted, true);
  await assert.rejects(pending, { code: 'ADDRESS_LOOKUP_FAILED' });
  assert.equal(geocoder.controllers.size, 0); assert.equal(geocoder.inflight.size, 0); assert.equal(geocoder.cache.size, 0);
  await assert.rejects(geocoder.search({ query: 'Tokyo', proxy }), { code: 'APP_CLOSING' });
});

async function serviceFixture(t, kind, options = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'envara-address-test-'));
  const networkProbe = new ProxyNetworkProbe({ transport: async () => geo });
  const calls = [];
  const addressGeocoder = new AddressGeocoder({ minIntervalMs: 0, transport: async args => { calls.push(args); return collection(feature()); } });
  const client = { request: async (method, route) => { assert.equal(method, 'POST'); assert.equal(route, '/api/shutdown'); return { data: 'closed' }; } };
  const service = kind === 'browseforge' ? new BrowseForgeService(directory, client, {}, () => {}, { networkProbe, addressGeocoder, ...options }) : new EnvaraService(directory, { closeAll: async () => {} }, {}, () => {}, { networkProbe, addressGeocoder, ...options });
  await service.ready;
  t.after(async () => { await service.shutdown(); await rm(directory, { recursive: true, force: true }); });
  return { service, calls };
}

for (const kind of ['browseforge', 'legacy']) test(`${kind} address search requires a matching live private preview and never writes configuration`, async (t) => {
  const { service, calls } = await serviceFixture(t, kind);
  const before = await service.store.read();
  await assert.rejects(service.call('searchNetworkAddress', { proxy, query: 'Tokyo', locationPreviewToken: 'renderer-invented' }), { code: 'ADDRESS_NETWORK_NOT_VERIFIED' });
  const preview = await service.call('previewProxyNetwork', { proxy });
  assert.ok(preview.locationPreviewToken);
  await assert.rejects(service.call('searchNetworkAddress', { proxy: { ...proxy, password: 'changed' }, query: 'Tokyo', locationPreviewToken: preview.locationPreviewToken }), { code: 'ADDRESS_NETWORK_NOT_VERIFIED' });
  assert.equal(calls.length, 0);
  const result = await service.call('searchNetworkAddress', { proxy, query: 'Tokyo', locationPreviewToken: preview.locationPreviewToken });
  assert.equal(result.candidates.length, 1); assert.equal(calls.length, 1);
  assert.deepEqual(await service.store.read(), before);
  service.locationPreviews.get(preview.locationPreviewToken).expiresAt = 0;
  await assert.rejects(service.call('searchNetworkAddress', { proxy, query: 'Tokyo', locationPreviewToken: preview.locationPreviewToken }), { code: 'ADDRESS_NETWORK_NOT_VERIFIED' });
  assert.equal(calls.length, 1);
});

for (const kind of ['browseforge', 'legacy']) test(`${kind} automatically saves a private nearby reference without changing measured geolocation or trusting renderer fields`, async (t) => {
  const measured = { ...geo, latitude: 35.65, longitude: 139.75 };
  const { service, calls } = await serviceFixture(t, kind, { networkProbe: new ProxyNetworkProbe({ transport: async () => measured }) });
  service.remote = async () => ({ profiles: [], groups: [] });
  const preview = await service.call('previewProxyNetwork', { proxy, language: 'de', coordinates: { latitude: 0, longitude: 0 } });
  assert.equal(calls.length, 1);
  const reverse = new URL(calls[0].url);
  assert.equal(reverse.pathname, '/reverse'); assert.equal(reverse.searchParams.get('lat'), '35.65'); assert.equal(reverse.searchParams.get('lang'), 'de');
  const originalNetwork = structuredClone(preview.network), originalReference = structuredClone(preview.referenceLocation);
  assert.equal(preview.locationRecommendation.latitude, 35.65); assert.equal(preview.locationRecommendation.accuracy, 50000);
  assert.equal(preview.referenceLocation.latitude, 35.6); assert.equal(preview.referenceLocation.kind, 'nearby-reference');
  assert.equal((await service.store.read()).proxies.length, 0, 'preview does not persist configuration');
  preview.network.geolocation.latitude = 0; preview.referenceLocation.label = 'Forged renderer street';
  await service.call('searchNetworkAddress', { proxy, query: 'Station Road', language: 'de', locationPreviewToken: preview.locationPreviewToken, bias: { latitude: 0, longitude: 0 } });
  assert.equal(new URL(calls[1].url).searchParams.get('lat'), '35.65', 'forward bias comes from the private verified preview');
  await service.saveProxy({ proxy: { ...proxy, location: { mode: 'ip', confirmed: true, referenceLocation: preview.referenceLocation } }, locationPreviewToken: preview.locationPreviewToken });
  const saved = (await service.store.read()).proxies[0];
  assert.deepEqual(saved.location.referenceLocation, originalReference);
  assert.equal(saved.location.label, 'Tokyo, Japan'); assert.equal(saved.location.source, 'ip-estimate'); assert.equal(saved.location.addressResolved, false);
  assert.deepEqual(networkLocationGeolocation(saved.location), originalNetwork.geolocation, 'only the original IP coordinates are used by consumers');
  assert.equal(calls.length, 2, 'saving does not perform another reverse lookup');
});

for (const kind of ['browseforge', 'legacy']) test(`${kind} optional reverse failures preserve verified IP confirmation and manual choices`, async (t) => {
  const addressGeocoder = new AddressGeocoder({ minIntervalMs: 0, transport: async () => { throw new Error('fixture reverse unavailable'); } });
  const { service } = await serviceFixture(t, kind, { addressGeocoder, networkProbe: new ProxyNetworkProbe({ transport: async () => ({ ...geo, latitude: 35.65, longitude: 139.75 }) }) });
  service.remote = async () => ({ profiles: [], groups: [] });
  const preview = await service.call('previewProxyNetwork', { proxy });
  assert.equal(preview.network.ok, true); assert.ok(preview.locationPreviewToken); assert.equal(preview.referenceLocation, null);
  const manual = { mode: 'manual', confirmed: true, label: 'Saved chosen street', latitude: 1.23, longitude: 4.56 };
  await service.saveProxy({ proxy: { ...proxy, location: manual }, locationPreviewToken: preview.locationPreviewToken });
  const saved = (await service.store.read()).proxies[0].location;
  assert.equal(saved.label, manual.label); assert.equal(saved.latitude, manual.latitude); assert.equal(saved.longitude, manual.longitude);
  assert.equal(Object.hasOwn(saved, 'referenceLocation'), false);
});

test('AnyTLS address search creates and releases only its temporary owned route on success and failure', async (t) => {
  const active = new Set(['saved-route']), ensured = [], released = [];
  const proxyCore = {
    async ensure(config) { ensured.push(config); active.add(config.id); return { protocol: 'http', host: '127.0.0.1', port: 43123 + ensured.length, username: `wire-user-${ensured.length}`, password: `wire-password-${ensured.length}` }; },
    async release(id) { released.push(id); active.delete(id); },
    async close() {},
  };
  const { service, calls } = await serviceFixture(t, 'browseforge', { proxyCore });
  const anytls = { name: 'AnyTLS fixture', protocol: 'anytls', host: 'node.example', port: 443, password: 'anytls-fixture-secret', serverName: 'tls.example', region: 'jp-tokyo' };
  const preview = await service.call('previewProxyNetwork', { proxy: anytls });
  assert.equal(ensured.length, 1); assert.equal(released.length, 1);
  const args = { proxy: anytls, query: 'Tokyo', locationPreviewToken: preview.locationPreviewToken };
  await assert.rejects(service.call('searchNetworkAddress', { ...args, query: 'x' }), { code: 'ADDRESS_QUERY_INVALID' });
  assert.equal(ensured.length, 1, 'invalid input must not start a core');
  await service.call('searchNetworkAddress', args);
  assert.equal(calls[0].agent.proxy.hostname, '127.0.0.1');
  assert.equal(ensured.length, 2); assert.equal(released.length, 2);
  assert.notEqual(ensured[0].id, ensured[1].id);
  assert.deepEqual([...active], ['saved-route']);
  await service.call('searchNetworkAddress', args);
  assert.equal(ensured.length, 3); assert.equal(released.length, 3);
  assert.equal(calls.length, 1, 'the service uses the verified original route key despite changing listener credentials');
  assert.deepEqual([...active], ['saved-route']);
  service.addressGeocoder.transport = async () => { throw new Error('fixture unavailable'); };
  await assert.rejects(service.call('searchNetworkAddress', { ...args, query: 'Osaka' }), { code: 'ADDRESS_LOOKUP_FAILED' });
  assert.equal(ensured.length, 4); assert.equal(released.length, 4);
  assert.deepEqual([...active], ['saved-route']);
  assert.equal(service.proxyWires.size, 0);
});

test('service shutdown aborts an in-flight address request and releases its temporary AnyTLS route', async (t) => {
  const active = new Set(), released = [];
  const proxyCore = {
    async ensure(config) { active.add(config.id); return { protocol: 'http', host: '127.0.0.1', port: 43123, username: 'wire-user', password: 'wire-password' }; },
    async release(id) { released.push(id); active.delete(id); },
    async close() {},
  };
  let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const addressGeocoder = new AddressGeocoder({ transport: ({ controller }) => new Promise((_resolve, reject) => {
    controller.signal.addEventListener('abort', () => reject(new Error('fixture request aborted')), { once: true });
    entered();
  }) });
  const { service } = await serviceFixture(t, 'browseforge', { proxyCore, addressGeocoder });
  const anytls = { name: 'AnyTLS fixture', protocol: 'anytls', host: 'node.example', port: 443, password: 'fixture-password' };
  const preview = await service.call('previewProxyNetwork', { proxy: anytls });
  const pending = service.call('searchNetworkAddress', { proxy: anytls, query: 'Tokyo', locationPreviewToken: preview.locationPreviewToken });
  const rejected = assert.rejects(pending, { code: 'ADDRESS_LOOKUP_FAILED' });
  await started;
  assert.equal(active.size, 1);
  await service.shutdown();
  await rejected;
  assert.equal(active.size, 0); assert.equal(released.length, 2);
  assert.equal(addressGeocoder.controllers.size, 0); assert.equal(service.proxyWires.size, 0);
});
