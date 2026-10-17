import assert from 'node:assert/strict';
import test from 'node:test';
import { assertNetworkLocationMatchesEgress, confirmNetworkLocation, googleMapsLocationURL, networkLocationGeolocation, normalizeNetworkLocation, parseGoogleMapsLocation, recommendNetworkLocation } from '../shared/network-location.mjs';

const network = { ok: true, scope: 'egress', ip: '8.8.8.8', countryCode: 'PH', country: 'Philippines', region: 'Metro Manila', city: 'Manila', timezone: 'Asia/Manila', geolocation: { latitude: 14.6, longitude: 121, accuracy: 50000 }, checkedAt: '2026-10-09T00:00:00.000Z' };

test('recommendation is actual authenticated egress and preserves city-scale accuracy', () => {
  for (const invalid of [null, { ...network, ok: false }, { ...network, scope: 'tcp' }, { ...network, ip: null }, { ...network, timezone: null }]) assert.equal(recommendNetworkLocation(invalid), null);
  const location = recommendNetworkLocation(network);
  assert.equal(location.confirmed, false);
  assert.equal(location.label, 'Manila, Metro Manila, Philippines');
  assert.equal(location.accuracy, 50000);
  assert.equal(location.source, 'ip-estimate');
  assert.equal(location.addressResolved, false);
  assert.equal(new URL(location.mapsUrl).searchParams.get('query'), '14.6,121');
});

test('IP confirmation ignores forged IP, timezone, street label and precise coordinates', () => {
  const location = confirmNetworkLocation({ mode: 'ip', confirmed: true, label: 'Pretend home', latitude: 0, longitude: 0, accuracy: 1, egressIP: '1.1.1.1', egressTimezone: 'Europe/London' }, network, '2026-10-09T00:01:00.000Z');
  assert.equal(location.latitude, 14.6); assert.equal(location.longitude, 121);
  assert.equal(location.egressIP, '8.8.8.8'); assert.equal(location.egressTimezone, 'Asia/Manila');
  assert.equal(location.accuracy, 50000); assert.equal(location.label, 'Manila, Metro Manila, Philippines');
  assert.equal(location.confirmedAt, '2026-10-09T00:01:00.000Z');
  assert.equal(location.timezone, 'Asia/Manila');
  assert.deepEqual(normalizeNetworkLocation(location), location);
  assert.throws(() => confirmNetworkLocation({ mode: 'ip', confirmed: true }, { ...network, ok: false }), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
});

test('nearby map references persist independently and only private confirmation can supply them', () => {
  const reference = { kind: 'nearby-reference', label: 'Example Street, Manila', latitude: 14.601, longitude: 121.001, source: 'Photon', attribution: '© OpenStreetMap contributors' };
  const input = { mode: 'ip', confirmed: true, referenceLocation: { ...reference, label: 'Forged street' } };
  assert.equal(confirmNetworkLocation(input, network).referenceLocation, undefined);
  const location = confirmNetworkLocation(input, network, '2026-10-09T00:01:00.000Z', reference);
  assert.deepEqual(location.referenceLocation, reference);
  assert.deepEqual(normalizeNetworkLocation(JSON.parse(JSON.stringify(location))), location, 'exports/imports preserve the reference as map context');
  assert.deepEqual(networkLocationGeolocation(location), network.geolocation, 'reference coordinates never become browser/native location');
  assert.equal(location.label, 'Manila, Metro Manila, Philippines'); assert.equal(location.accuracy, 50000); assert.equal(location.addressResolved, false);
  for (const invalid of [{ ...reference, kind: 'verified-street' }, { ...reference, source: 'forged' }, { ...reference, latitude: 91 }, { ...reference, longitude: null }, { ...reference, accuracy: 1 }, { ...reference, label: '' }]) {
    assert.throws(() => normalizeNetworkLocation({ ...location, referenceLocation: invalid }), { code: 'INVALID_NETWORK_LOCATION' });
  }
  const manual = confirmNetworkLocation({ mode: 'manual', confirmed: true, label: 'Chosen address', latitude: 0, longitude: 0, referenceLocation: reference }, network, undefined, reference);
  assert.equal(manual.referenceLocation, undefined); assert.equal(manual.label, 'Chosen address'); assert.equal(manual.latitude, 0);
});

test('Google Maps explicit pin differs from its camera centre and does not geocode a text query', () => {
  const pin = parseGoogleMapsLocation('https://www.google.com/maps/place/Example/@14,120,15z/data=!4m2!3d14.6!4d121');
  assert.equal(pin.latitude, 14.6); assert.equal(pin.longitude, 121);
  assert.equal(parseGoogleMapsLocation('https://www.google.com/maps/@14,120,15z').latitude, undefined);
  assert.equal(parseGoogleMapsLocation('https://www.google.com/maps/search/?api=1&query=Manila').latitude, undefined);
  assert.equal(parseGoogleMapsLocation('https://maps.app.goo.gl/example').coordinateSource, null);
  const search = parseGoogleMapsLocation(googleMapsLocationURL({ latitude: 0, longitude: 0 }));
  assert.equal(search.latitude, 0); assert.equal(search.longitude, 0);
});

test('manual address remains an unverified label while explicit coordinates are scoped simulation', () => {
  const label = confirmNetworkLocation({ mode: 'manual', confirmed: true, label: 'My selected address' }, network);
  assert.equal(label.source, 'manual'); assert.equal(label.addressResolved, false);
  assert.equal(networkLocationGeolocation(label), null);
  const point = confirmNetworkLocation({ mode: 'manual', confirmed: true, latitude: 14.55, longitude: 121.04 }, network);
  assert.equal(point.accuracyKind, 'simulation-radius'); assert.equal(point.coordinateSource, 'user-coordinate');
  assert.deepEqual(normalizeNetworkLocation(point), point);
  assert.deepEqual(networkLocationGeolocation(point), { latitude: 14.55, longitude: 121.04, accuracy: 1000 });
  assert.equal(point.egressTimezone, network.timezone);
  assert.equal(point.timezone, network.timezone);
});

test('arbitrary URLs, credentials, mismatched pins and invalid coordinates are rejected locally', () => {
  for (const url of ['http://www.google.com/maps', 'https://google.com.attacker.example/maps', 'https://user:pass@www.google.com/maps', 'file:///etc/passwd', 'https://www.google.com/search?q=address', 'https://www.google.com:8443/maps', 'https://maps.google.com/?q=91,0']) assert.throws(() => parseGoogleMapsLocation(url), { code: 'INVALID_NETWORK_LOCATION' });
  for (const value of [{ mode: 'manual', confirmed: true, latitude: 1 }, { mode: 'manual', confirmed: true, latitude: 91, longitude: 0 }, { mode: 'manual', confirmed: true, latitude: 0, longitude: NaN }, { mode: 'manual', confirmed: true, label: 'x\nunsafe' }, { mode: 'manual', confirmed: true, label: 'x', token: 'credential' }, { mode: 'manual', confirmed: true, latitude: 1, longitude: 2, mapsUrl: googleMapsLocationURL({ latitude: 3, longitude: 4 }) }]) assert.throws(() => normalizeNetworkLocation(value), { code: 'INVALID_NETWORK_LOCATION' });
});

test('confirmed region refuses changed country or timezone without silently moving the selected pin', () => {
  for (const mode of ['ip', 'manual']) {
    const selected = confirmNetworkLocation({ mode, confirmed: true, ...(mode === 'manual' ? { latitude: 14.55, longitude: 121.04, label: 'My chosen pin' } : {}) }, network);
    const original = structuredClone(selected);
    for (const moved of [{ ...network, timezone: 'Asia/Tokyo' }, { ...network, countryCode: 'US' }, { ...network, timezone: 'Asia/Tokyo', countryCode: 'JP' }]) assert.throws(() => assertNetworkLocationMatchesEgress(selected, moved), { code: 'NETWORK_LOCATION_RECONFIRM_REQUIRED' });
    assert.doesNotThrow(() => assertNetworkLocationMatchesEgress(selected, { ...network, ip: '1.1.1.1', city: 'Another city', geolocation: { latitude: 15, longitude: 120, accuracy: 50000 } }));
    assert.deepEqual(selected, original);
  }
});

test('region comparison normalizes timezone aliases and compares country only when saved', () => {
  const selected = confirmNetworkLocation({ mode: 'ip', confirmed: true }, { ...network, countryCode: 'US', timezone: 'US/Eastern' });
  assert.doesNotThrow(() => assertNetworkLocationMatchesEgress(selected, { ...network, countryCode: 'us', timezone: 'America/New_York' }));
  assert.throws(() => assertNetworkLocationMatchesEgress({ ...selected, egressTimezone: 'America/Los_Angeles' }, { ...network, countryCode: 'US', timezone: 'America/New_York' }), { code: 'NETWORK_LOCATION_RECONFIRM_REQUIRED' });
  const withoutCountry = { ...selected }; delete withoutCountry.countryCode;
  assert.doesNotThrow(() => assertNetworkLocationMatchesEgress(withoutCountry, { ...network, countryCode: 'CA', timezone: 'America/New_York' }));
  assert.throws(() => assertNetworkLocationMatchesEgress(withoutCountry, { ...network, timezone: 'America/Los_Angeles' }), { code: 'NETWORK_LOCATION_RECONFIRM_REQUIRED' });
  assert.doesNotThrow(() => assertNetworkLocationMatchesEgress(null, { ok: false }));
  assert.doesNotThrow(() => assertNetworkLocationMatchesEgress({ confirmed: false, timezone: 'Asia/Manila' }, { ok: false }));
});

test('confirmed region requires a successful actual egress and its known country', () => {
  const selected = confirmNetworkLocation({ mode: 'ip', confirmed: true }, network);
  for (const unavailable of [{ ...network, ok: false }, { ...network, scope: 'tcp' }, { ...network, ip: null }, { ...network, timezone: null }, { ...network, timezone: 'invalid/timezone' }, { ...network, countryCode: null }]) assert.throws(() => assertNetworkLocationMatchesEgress(selected, unavailable), { code: 'NETWORK_LOCATION_NOT_VERIFIED' });
});
