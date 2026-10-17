import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { browseForgeRegionFor, preferredEngine } from '../shared/engine-choice.mjs';
import { BROWSEFORGE_CHROMIUM_REGION_PRESETS } from '../shared/browseforge-regions.mjs';
import { confirmNetworkLocation, normalizeNetworkLocation } from '../shared/network-location.mjs';

const networkAt = (countryCode, patch = {}) => ({ ok: true, scope: 'egress', ip: '8.8.8.8', timezone: 'UTC', countryCode, ...patch });
const at = (countryCode, label) => ({ location: normalizeNetworkLocation({ mode: 'manual', confirmed: true, countryCode, label }) });

const engines = [
  { id: 'browseforge-chromium', supported: true, installed: true },
  { id: 'camoufox', supported: true, installed: false, experimental: true },
  { id: 'cloakbrowser', supported: true, installed: true },
];

test('a new environment uses CloakBrowser unless another engine was chosen and is usable', () => {
  assert.equal(preferredEngine(engines, null), 'cloakbrowser', 'after a reset there is no saved choice');
  assert.equal(preferredEngine(engines, 'browseforge-chromium'), 'browseforge-chromium');
  assert.equal(preferredEngine(engines, 'camoufox'), 'cloakbrowser', 'a saved engine that is not installed is not used');
  assert.equal(preferredEngine([{ id: 'browseforge-chromium', supported: true, installed: true }], null), 'browseforge-chromium');
  assert.equal(preferredEngine([], null), 'cloakbrowser');
});

test('the shared BrowseForge catalog exactly matches the engine source and accepts every supported preset', async () => {
  const source = await readFile(new URL('../third_party/browseforge/internal/browser/launch_chromium.go', import.meta.url), 'utf8');
  const body = /var browseForgeProxyRegionPresets = \[\]BrowseForgeProxyRegionPreset\{\n([\s\S]*?)\n\}/.exec(source)?.[1];
  assert.ok(body, 'engine preset declaration must remain inspectable');
  const native = [...body.matchAll(/\{Value: "([^"]+)", Label: "((?:\\.|[^"\\])*)"\}/g)].map(([, value, label]) => ({ value, label: JSON.parse(`"${label}"`) }));
  assert.equal(native.length, body.split('\n').filter(line => line.trim()).length, 'every native entry must be parsed');
  assert.deepEqual(BROWSEFORGE_CHROMIUM_REGION_PRESETS, native);
  assert.equal(new Set(native.map(({ value }) => value)).size, native.length);
  assert.equal(native.filter(({ value }) => !value.includes('-')).length, 249);
  assert.equal(native.filter(({ value }) => value.includes('-')).length, 27);
  for (const { value, label } of native) {
    assert.equal(browseForgeRegionFor({ region: value }), value);
    assert.equal(browseForgeRegionFor({ region: ` ${value.toUpperCase()} ` }), value);
    const country = value.slice(0, 2).toUpperCase();
    assert.equal(browseForgeRegionFor(at(country, label)), value, label);
  }
});

test('BrowseForge Chromium matches exact confirmed places and otherwise uses a supported country preset', () => {
  assert.equal(browseForgeRegionFor(at('US', 'Brooklyn, New York, United States')), 'us-ny');
  assert.equal(browseForgeRegionFor(at('US', 'Los Angeles, California, United States')), 'us-ca');
  assert.equal(browseForgeRegionFor(at('CA', 'Vancouver, British Columbia, Canada')), 'ca-bc');
  assert.equal(browseForgeRegionFor(at('MY', 'Petaling, Selangor, Malaysia')), 'my');
  assert.equal(browseForgeRegionFor(at('MY', 'Kuala Lumpur, Malaysia')), 'my-kuala-lumpur');
  assert.equal(browseForgeRegionFor(at('US', 'Seattle, Washington, United States')), 'us');
  assert.equal(browseForgeRegionFor(at('JP', 'Tokyo, Japan')), 'jp-tokyo');
  assert.equal(browseForgeRegionFor(at('JP', 'Osaka, Japan')), 'jp');
  assert.equal(browseForgeRegionFor(at('BR', 'São Paulo, Brazil')), 'br-sao-paulo');
  assert.equal(browseForgeRegionFor(at('CH', 'Zurich, Switzerland')), 'ch-zurich');
  assert.equal(browseForgeRegionFor(at('ZA', 'Johannesburg, Gauteng, South Africa')), 'za');
  assert.equal(browseForgeRegionFor(at('SG', 'Singapore')), 'sg');
  assert.equal(browseForgeRegionFor(at('HK', 'Hong Kong')), 'hk');
});

test('confirmed location has priority over a different measured city or country without changing stored data', () => {
  for (const [country, label, measured, expected] of [
    ['US', 'Austin, Texas, United States', networkAt('US', { city: 'New York', region: 'New York' }), 'us-tx'],
    ['MY', 'Penang, Malaysia', networkAt('MY', { city: 'Kuala Lumpur' }), 'my'],
    ['US', 'Seattle, Washington, United States', networkAt('CA', { region: 'New York' }), 'us'],
    ['JP', 'Osaka, Japan', networkAt('JP', { city: 'Tokyo' }), 'jp'],
    ['XX', 'Unknown location', networkAt('JP', { city: 'Tokyo' }), null],
  ]) {
    const proxy = { ...at(country, label), network: measured };
    const before = structuredClone(proxy);
    assert.equal(browseForgeRegionFor(proxy), expected);
    assert.deepEqual(proxy, before);
  }
  const countryMissing = { location: { confirmed: true, label: 'Tokyo, Japan' }, network: networkAt('JP') };
  assert.equal(browseForgeRegionFor(countryMissing), 'jp-tokyo');
});

test('only verified egress observations can supply an automatic region before location confirmation', () => {
  assert.equal(browseForgeRegionFor({ network: networkAt('US', { region: 'Texas', city: 'New York' }) }), 'us-tx');
  assert.equal(browseForgeRegionFor({ network: networkAt('JP', { region: 'Kanto', city: 'Tokyo' }) }), 'jp-tokyo');
  assert.equal(browseForgeRegionFor({ network: networkAt('DE', { city: 'Berlin' }) }), 'de-berlin');
  assert.equal(browseForgeRegionFor({ network: networkAt('AU', { city: 'Melbourne' }) }), 'au');
  for (const patch of [{ ok: false }, { ok: 'true' }, { scope: 'tcp' }, { scope: undefined }, { ip: null }, { timezone: null }, { countryCode: null }, { countryCode: 'XX' }]) {
    assert.equal(browseForgeRegionFor({ network: networkAt('JP', { city: 'Tokyo', ...patch }) }), null);
  }
  assert.equal(browseForgeRegionFor({ location: { confirmed: false, countryCode: 'US', label: 'New York' } }), null);
  assert.equal(browseForgeRegionFor({ location: { confirmed: false, countryCode: 'US', label: 'New York' }, network: networkAt('JP', { city: 'Tokyo' }) }), 'jp-tokyo');
});

test('a confirmed and normalized probe recommendation retains its exact supported place', () => {
  for (const [countryCode, region, city, expected] of [
    ['US', 'Texas', 'Austin', 'us-tx'], ['JP', 'Tokyo', 'Tokyo', 'jp-tokyo'],
    ['MY', 'Kuala Lumpur', 'Kuala Lumpur', 'my-kuala-lumpur'], ['MY', 'Selangor', 'Petaling', 'my'],
  ]) {
    const location = confirmNetworkLocation({ mode: 'ip', confirmed: true }, networkAt(countryCode, { region, city }));
    assert.equal(browseForgeRegionFor({ location: normalizeNetworkLocation(location) }), expected);
  }
});

test('freeform addresses, substrings and ambiguous names never guess a specific region', () => {
  for (const label of ['New York Avenue', 'New Yorkshire', 'West New York', 'New York, Texas, United States']) assert.equal(browseForgeRegionFor(at('US', label)), 'us');
  for (const label of ['Kuala Lumpur Road', 'Not Kuala Lumpur']) assert.equal(browseForgeRegionFor(at('MY', label)), 'my');
  assert.equal(browseForgeRegionFor(at('JP', '東京、日本')), 'jp', 'unmapped local spelling stays country-level');
  assert.equal(browseForgeRegionFor(at('US', 'California，United States')), 'us-ca');
  assert.equal(browseForgeRegionFor({ network: networkAt('JP', { region: 'Tokyo Avenue', city: 'Tokyo Bay' }) }), 'jp');
  assert.equal(browseForgeRegionFor({ network: networkAt('US', { region: 'CA' }) }), 'us-ca');
});

test('a saved region wins and an invalid explicit choice never falls through to automatic location', () => {
  const location = at('MY', 'Kuala Lumpur, Malaysia').location;
  assert.equal(browseForgeRegionFor({ region: 'us-ny', location }), 'us-ny');
  for (const region of ['za-gauteng', 'jp-osaka', '192.0.2.1', 'us-ny\ninvalid', 'constructor', {}, 42]) {
    assert.equal(browseForgeRegionFor({ region, location, network: networkAt('JP', { city: 'Tokyo' }) }), null);
  }
  assert.equal(browseForgeRegionFor({ region: '', location }), 'my-kuala-lumpur');
  assert.equal(browseForgeRegionFor({ region: '  ', location }), 'my-kuala-lumpur');
  assert.equal(browseForgeRegionFor(null), null);
});
