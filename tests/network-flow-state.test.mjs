import test from 'node:test';
import assert from 'node:assert/strict';
import { locationFormState, verifiedLocationPreview, locationConfirmation, proxyRouteFields, networkApplicationChoices, chooseApplicationProfile, isApplicationAlreadyAttached, createdProfileFromSnapshot, savedNetworkPresentation, terminalTimezonePresentation } from '../src/network-flow-state.mjs';

const preview = { network: { ok: true, scope: 'egress', ip: '192.0.2.10', timezone: 'Asia/Manila' }, locationRecommendation: { source: 'ip-estimate' }, locationPreviewToken: 'private-form-token' };

test('a location cannot be confirmed from a direct lookup, missing timezone or failed route', () => {
  for (const value of [null, { ...preview, locationPreviewToken: null }, { ...preview, network: { ...preview.network, scope: 'direct' } },
    { ...preview, network: { ...preview.network, ok: false } }, { ...preview, network: { ...preview.network, timezone: null } },
    { ...preview, locationRecommendation: { source: 'manual' } }]) {
    assert.equal(verifiedLocationPreview(value), false);
    assert.throws(() => locationConfirmation({ mode: 'ip', confirmed: true }, value), /先检测/);
  }
  assert.throws(() => locationConfirmation({ mode: 'ip', confirmed: false }, preview), /请确认/);
  assert.deepEqual(locationConfirmation({ mode: 'ip', confirmed: true, latitude: 0, timezone: 'wrong' }, preview), { mode: 'ip', confirmed: true });
});

test('failed or absent current route displays saved timezone as configuration without filling resolved state', () => {
  const proxy = { location: { confirmed: true, timezone: 'Asia/Manila', label: 'Saved place' }, network: { ok: true, scope: 'egress', timezone: 'Asia/Manila' } };
  for (const failure of [{ network: { ok: false } }, { networkLastError: 'core stopped' }, { networkContextUnavailable: true }]) {
    const profile = { resolvedTimezone: null, timezoneSource: null, ...failure };
    const display = savedNetworkPresentation(profile, proxy);
    assert.equal(display.timezone, 'Asia/Manila');
    assert.equal(display.savedOnly, true);
    assert.equal(display.failed, true);
    assert.equal(profile.resolvedTimezone, null);
    assert.equal(profile.timezoneSource, null);
  }
  assert.equal(savedNetworkPresentation({ resolvedTimezone: null }, proxy).savedOnly, true);
  assert.equal(savedNetworkPresentation({ network: { ok: true, scope: 'egress' }, resolvedTimezone: 'Asia/Manila' }, proxy).savedOnly, false);
  assert.equal(savedNetworkPresentation({ network: { ok: false }, timezone: 'Europe/London' }, null).savedOnly, true);
});

test('terminal failed context and detached-window flag outrank stale successful metadata', () => {
  const metadata = { timezone: 'Asia/Manila', timezoneSource: 'proxy-egress', network: { egress: { ok: true, scope: 'egress' } } };
  const profile = { savedNetworkTimezone: 'Asia/Manila', resolvedTimezone: null, timezoneSource: null };
  assert.equal(terminalTimezonePresentation({ profile, metadata, hasLiveSession: false }).source, 'saved-configuration');
  assert.equal(terminalTimezonePresentation({ profile, metadata, hasLiveSession: true }).source, 'proxy-egress');
  for (const failure of [{ network: { ok: false } }, { networkLastError: 'failed probe' }, { networkContextUnavailable: true }]) {
    const display = terminalTimezonePresentation({ profile: { ...profile, ...failure }, metadata, hasLiveSession: true });
    assert.equal(display.timezone, 'Asia/Manila');
    assert.equal(display.source, 'saved-configuration');
    assert.equal(display.failed, true);
  }
});

test('manual address selection does not fabricate coordinates or trust a map camera centre', () => {
  const state = { ...locationFormState(), mode: 'manual', label: 'Makati, Philippines', confirmed: true };
  const confirmed = locationConfirmation(state, preview);
  assert.equal(confirmed.latitude, '');
  assert.equal(confirmed.longitude, '');
  assert.equal(confirmed.label, 'Makati, Philippines');
  assert.throws(() => locationConfirmation({ ...state, label: '', mapsUrl: 'https://example.test/maps' }, preview), /Google Maps/);
  assert.throws(() => locationConfirmation({ ...state, latitude: '91', longitude: '0' }, preview), /范围/);
  assert.throws(() => locationConfirmation({ ...state, latitude: '14', longitude: '' }, preview), /同时/);
  assert.equal(locationFormState({ mode: 'manual', label: 'Saved', confirmed: true }).confirmed, false);
  for (const field of ['password', 'username', 'serverName', 'alpn', 'skipCertVerify', 'udp', 'host', 'port']) assert.ok(proxyRouteFields.has(field));
  assert.equal(proxyRouteFields.has('name'), false);
});

test('network selection uses only saved nodes and preserves the exact group binding', () => {
  const profiles = [{ id: 'a', group: 'Work', proxyId: 'node-a' }, { id: 'b', group: 'Work', proxyId: 'node-b' }, { id: 'c', group: '', proxyId: 'node-a' }];
  const choices = networkApplicationChoices([{ id: 'node-a', name: 'PH' }, { id: 'node-b', name: 'JP' }], [{ name: 'Work', proxyId: 'node-a' }, { name: 'Missing', proxyId: 'removed' }], profiles);
  assert.deepEqual(choices.map(item => item.id), ['group:Work', 'node:node-b']);
  assert.deepEqual(choices[0].profileIds, ['a']);
  assert.equal(chooseApplicationProfile(choices[0], profiles, 'b').id, 'a');
  assert.equal(chooseApplicationProfile(choices[0], [{ ...profiles[0], proxyId: 'node-b' }], 'a'), null);
  const ungrouped = networkApplicationChoices([{ id: 'node-a', name: 'PH' }], [], profiles)[0];
  assert.equal(chooseApplicationProfile(ungrouped, profiles, 'c').id, 'c');
  assert.equal(chooseApplicationProfile(ungrouped, profiles, 'other', profile => profile.id === 'a').id, 'c');
});

test('snapshot ownership refuses ambiguous new environments and one identity cannot be attached twice', () => {
  const before = new Set(['old']);
  const expected = { proxyId: 'chosen', group: 'Work' };
  const created = { id: 'new', proxyId: 'chosen', group: 'Work' };
  assert.equal(createdProfileFromSnapshot(before, { profiles: [{ id: 'old' }, created] }, expected), created);
  for (const profiles of [[{ id: 'old' }], [created, { id: 'concurrent', proxyId: 'chosen', group: 'Work' }], [{ ...created, proxyId: 'other' }], [{ ...created, group: 'Other' }]]) {
    assert.equal(createdProfileFromSnapshot(before, { profiles }, expected), null);
  }
  const app = { identity: 'bundle:notion', path: '/Applications/Notion.app' };
  assert.equal(isApplicationAlreadyAttached(app, [{ ...app, profileId: 'other' }]), true);
  assert.equal(isApplicationAlreadyAttached(app, [{ identity: 'bundle:notion', path: '/another/copy.app' }]), true);
  assert.equal(isApplicationAlreadyAttached(app, [{ identity: 'bundle:other', path: app.path }]), true);
  assert.equal(isApplicationAlreadyAttached(app, [{ identity: 'bundle:other', path: '/Applications/Other.app' }]), false);
});
