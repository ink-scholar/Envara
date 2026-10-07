import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizePrivacy, normalizeGeolocation, privacyLaunchArgs, shouldBlockTracker, snapshotPrivacy, applyBrowserPrivacy } from '../electron/privacy-policy.mjs';

test('privacy has a useful default and rejects unknown configuration instead of silently disabling protection', () => {
  assert.deepEqual(normalizePrivacy(null), { mode: 'standard' });
  for (const mode of ['off', 'standard', 'strict']) assert.equal(normalizePrivacy({ mode }).mode, mode);
  for (const value of [true, [], {}, { mode: 'other' }, { mode: 'off', bypass: true }]) assert.throws(() => normalizePrivacy(value), { code: 'INVALID_PRIVACY_POLICY' });
  assert.equal(privacyLaunchArgs('off').includes('--disable-domain-reliability'), false);
  assert.equal(privacyLaunchArgs('off').includes('--deny-permission-prompts'), true);
});

test('tracker matching uses parsed host boundaries, permits first party and preserves authentication and normal API requests', () => {
  const firstPartyUrl = 'https://claude.ai/';
  for (const url of ['https://www.google-analytics.com/g/collect', 'https://region1.google-analytics.com/g/collect', 'https://stats.g.doubleclick.net/collect', 'https://api.segment.io/v1/track']) assert.equal(shouldBlockTracker(url, { firstPartyUrl }), true);
  for (const url of ['https://accounts.google.com/signin', 'https://claude.ai/api/organizations', 'https://api.anthropic.com/v1/messages', 'https://www.google-analytics.com.evil.example/collect', 'https://example.com/google-analytics.com', 'file:///google-analytics.com', 'https://example.com/?redirect=https://api.segment.io']) assert.equal(shouldBlockTracker(url, { mode: 'strict', firstPartyUrl }), false);
  assert.equal(shouldBlockTracker('https://api.mixpanel.com/track', { firstPartyUrl }), false);
  assert.equal(shouldBlockTracker('https://api.mixpanel.com/track', { mode: 'strict', firstPartyUrl }), true);
  assert.equal(shouldBlockTracker('https://api.segment.io/v1', { firstPartyUrl: 'https://api.segment.io/settings' }), false);
  assert.equal(shouldBlockTracker('https://api.segment.io/v1', { mode: 'off', firstPartyUrl }), false);
});

test('only finite regional coordinates are accepted and privacy snapshots are detached safe metadata', () => {
  const geo = { latitude: 14.6, longitude: 121, accuracy: 50000 };
  assert.deepEqual(normalizeGeolocation(geo), geo); assert.equal(normalizeGeolocation(null), null);
  for (const value of [{ ...geo, latitude: 91 }, { ...geo, longitude: NaN }, { ...geo, accuracy: 999 }, { ...geo, address: 'street address' }]) assert.throws(() => normalizeGeolocation(value), { code: 'INVALID_PRIVACY_POLICY' });
  const state = { mode: 'strict', blockedRequests: 2, geolocation: geo, private: 'not-exported' }, snapshot = snapshotPrivacy(state);
  assert.equal(snapshot.blockedRequests, 2); assert.equal(snapshot.private, undefined); snapshot.geolocation.latitude = 0; assert.equal(state.geolocation.latitude, 14.6);
});

test('explicit service roots permit sibling APIs while outside sites and hostname lookalikes remain blocked', () => {
  const permitted = [
    ['https://api.segment.com/v1/sources', 'https://app.segment.com/', 'standard'],
    ['https://api.segment.io/v1/track', 'https://app.segment.com/', 'standard'],
    ['https://cdn.segment.com/script.js', 'https://app.segment.io/', 'standard'],
    ['https://api.mixpanel.com/query/events', 'https://app.mixpanel.com/', 'strict'],
    ['https://api.amplitude.com/api', 'https://analytics.amplitude.com/', 'strict'],
    ['https://sessions.bugsnag.com/', 'https://app.bugsnag.com/', 'strict'],
    ['https://browser-intake-datadoghq.eu/api', 'https://app.datadoghq.eu/', 'strict'],
    ['https://ingest.us.sentry.io/api', 'https://project.sentry.io/', 'strict'],
    ['https://static.hotjar.io/script.js', 'https://insights.hotjar.com/', 'strict'],
    ['https://stats.google-analytics.com/api', 'https://www.google-analytics.com/', 'standard'],
  ];
  for (const [url, firstPartyUrl, mode] of permitted) {
    assert.equal(shouldBlockTracker(url, { firstPartyUrl, mode }), false, `${firstPartyUrl} → ${url}`);
    assert.equal(shouldBlockTracker(url, { firstPartyUrl: 'https://example.com/', mode }), true, `outside site → ${url}`);
  }
  for (const firstPartyUrl of ['https://app.segment.com.evil.example/', 'https://notsegment.com/', 'https://app-segment.com/', 'https://app.segment.io.evil.example/', 'https://segment.com@evil.example/', 'https://example.com/?site=segment.com']) {
    assert.equal(shouldBlockTracker('https://api.segment.com/v1/sources', { firstPartyUrl }), true, firstPartyUrl);
  }
  assert.equal(shouldBlockTracker('https://api.mixpanel.com/query/events', { mode: 'strict', firstPartyUrl: 'https://app.segment.com/' }), true);
  assert.equal(shouldBlockTracker('https://api.segment.com.evil.example/v1', { firstPartyUrl: 'https://app.segment.com/' }), false);
});

test('top-level navigation uses its destination while fetches and child navigation retain the actual top party', async () => {
  let handler;
  const context = { clearPermissions: async () => {}, setGeolocation: async () => {}, grantPermissions: async () => {}, route: async (_pattern, callback) => { handler = callback; } };
  const state = await applyBrowserPrivacy(context, { privacy: { mode: 'standard' }, geolocation: { latitude: 0, longitude: 0, accuracy: 50000 } });
  const top = { url: () => 'https://example.com/old-page', parentFrame: () => null };
  const child = { url: () => 'https://child.example.net/', parentFrame: () => top };
  const nestedChild = { url: () => 'https://nested.example.net/', parentFrame: () => child };
  for (const [frame, navigation, expected] of [[top, true, 'continue'], [top, false, 'abort'], [child, true, 'abort'], [nestedChild, true, 'abort'], [null, true, 'abort']]) {
    let action;
    await handler({ request: () => ({ frame: () => frame, isNavigationRequest: () => navigation, url: () => 'https://api.segment.io/settings' }),
      abort: async () => { action = 'abort'; }, continue: async () => { action = 'continue'; } });
    assert.equal(action, expected);
  }
  assert.equal(snapshotPrivacy(state).blockedRequests, 4);
});
