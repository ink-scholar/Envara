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
  const context = { pages: () => [], on: () => {}, routeWebSocket: async () => {}, clearPermissions: async () => {}, setGeolocation: async () => {}, grantPermissions: async () => {}, route: async (_pattern, callback) => { handler = callback; } };
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

test('standard blocks pure collection hosts; ad networks and Facebook Login hosts wait for strict; sign-in stays reachable', () => {
  const outside = { firstPartyUrl: 'https://example.com/' };
  for (const url of ['https://www.clarity.ms/tag/abc', 'https://bat.bing.com/bat.js', 'https://analytics.tiktok.com/i18n/pixel/events.js', 'https://px.ads.linkedin.com/collect',
    'https://mc.yandex.ru/watch/1', 'https://hm.baidu.com/hm.js', 'https://s4.cnzz.com/z_stat.php', 'https://sb.scorecardresearch.com/b', 'https://pixel.quantserve.com/pixel',
    'https://site.sc.omtrdc.net/b/ss', 'https://dpm.demdex.net/id']) {
    assert.equal(shouldBlockTracker(url, outside), true, url);
  }
  for (const url of ['https://connect.facebook.net/en_US/sdk.js', 'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js', 'https://www.googleadservices.com/pagead/conversion.js',
    'https://static.criteo.net/js/ld/publishertag.js', 'https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js', 'https://bam.nr-data.net/1/x', 'https://c.amazon-adsystem.com/aax2/apstag.js']) {
    assert.equal(shouldBlockTracker(url, outside), false, `standard keeps ${url}`);
    assert.equal(shouldBlockTracker(url, { ...outside, mode: 'strict' }), true, `strict blocks ${url}`);
  }
  for (const url of ['https://accounts.google.com/o/oauth2/v2/auth', 'https://appleid.apple.com/auth/authorize', 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    'https://www.facebook.com/login.php', 'https://www.bing.com/search?q=envara', 'https://www.baidu.com/s?wd=envara', 'https://www.linkedin.com/feed/']) {
    assert.equal(shouldBlockTracker(url, { ...outside, mode: 'strict' }), false, url);
  }
  // A service's own site keeps its own analytics: first party, not cross-site tracking.
  assert.equal(shouldBlockTracker('https://bat.bing.com/bat.js', { firstPartyUrl: 'https://www.bing.com/' }), false);
  assert.equal(shouldBlockTracker('https://connect.facebook.net/en_US/sdk.js', { firstPartyUrl: 'https://www.facebook.com/', mode: 'strict' }), false);
  assert.equal(shouldBlockTracker('https://bat.bing.com.evil.example/bat.js', outside), false);
});

test('the BrowseForge kernel enforces exactly the same tracker hosts and service roots as the desktop policy', async () => {
  const { readFile } = await import('node:fs/promises');
  const { STANDARD_TRACKER_DOMAINS, STRICT_TRACKER_DOMAINS } = await import('../electron/privacy-policy.mjs');
  const go = await readFile(new URL('../third_party/browseforge/internal/browser/privacy.go', import.meta.url), 'utf8');
  const js = await readFile(new URL('../electron/privacy-policy.mjs', import.meta.url), 'utf8');
  const strings = text => [...text.matchAll(/"([^"]+)"/g)].map(([, value]) => value);
  const goStandard = strings(/var standardTrackerDomains = \[\]string\{([^}]*)\}/.exec(go)[1]);
  const goStrict = strings(/var strictTrackerDomains = \[\]string\{([^}]*)\}/.exec(go)[1]);
  assert.deepEqual(goStandard, [...STANDARD_TRACKER_DOMAINS]);
  assert.deepEqual([...goStandard, ...goStrict], [...STRICT_TRACKER_DOMAINS]);
  const rootBlock = /var trackerServiceRoots = map\[string\]\[\]string\{\n([\s\S]*?)\n\}/.exec(go)[1];
  const goRoots = Object.fromEntries([...rootBlock.matchAll(/^\s*"([^"]+)":\s*\{([^}]*)\},$/gm)].map(([, key, values]) => [key, strings(values)]));
  const jsRoots = Function(`return ${/const TRACKER_SERVICE_ROOTS = Object\.freeze\((\{[\s\S]*?\})\);/.exec(js)[1]}`)();
  assert.deepEqual(goRoots, jsRoots);
  for (const domain of STRICT_TRACKER_DOMAINS) assert.ok(jsRoots[domain], `${domain} has an explicit service root`);
});

test('WS and WSS keep tier, first-party and service-root exceptions', () => {
  for (const scheme of ['ws', 'wss']) {
    const target = `${scheme}://api.segment.io/live`;
    assert.equal(shouldBlockTracker(target, { firstPartyUrl: 'https://example.test' }), true);
    assert.equal(shouldBlockTracker(target, { firstPartyUrl: 'https://app.segment.com' }), false);
    assert.equal(shouldBlockTracker(target, { firstPartyUrl: 'https://app.segment.com.evil.test' }), true);
    assert.equal(shouldBlockTracker(target, { mode: 'off' }), false);
    assert.equal(shouldBlockTracker(`${scheme}://api.mixpanel.com/live`, { mode: 'standard' }), false);
    assert.equal(shouldBlockTracker(`${scheme}://api.mixpanel.com/live`, { mode: 'strict' }), true);
    assert.equal(shouldBlockTracker(`${scheme}://chat.example.test/live`, { mode: 'strict' }), false);
  }
});

test('WebSocket routes cover existing and new pages, preserve page ownership and close blocked sockets without connecting', async () => {
  const page = { url: () => 'https://app.segment.com/', routeWebSocket: async (_pattern, callback) => { page.handler = callback; } };
  let newPage, fallback;
  const context = { pages: () => [page], on: (event, callback) => { if (event === 'page') newPage = callback; },
    clearPermissions: async () => {}, setGeolocation: async () => {}, grantPermissions: async () => {}, route: async () => {},
    routeWebSocket: async (_pattern, callback) => { fallback = callback; } };
  const state = await applyBrowserPrivacy(context, { geolocation: { latitude: 0, longitude: 0, accuracy: 50000 } });
  const invoke = async (handler, url, failure = false) => {
    let connected = 0, closed;
    await handler({ url: () => url, close: async options => { closed = options.code; }, connectToServer: () => { connected++; if (failure) throw Error('offline'); } });
    return { connected, closed };
  };
  assert.deepEqual(await invoke(page.handler, 'wss://api.segment.io/live'), { connected: 1, closed: undefined });
  assert.deepEqual(await invoke(fallback, 'wss://api.segment.io/live'), { connected: 0, closed: 1008 });
  const outside = { url: () => 'https://example.test/', routeWebSocket: async (_pattern, callback) => { outside.handler = callback; } };
  newPage(outside);
  assert.deepEqual(await invoke(outside.handler, 'ws://api.segment.io/live'), { connected: 0, closed: 1008 });
  assert.deepEqual(await invoke(outside.handler, 'wss://chat.example.test/live'), { connected: 1, closed: undefined });
  assert.deepEqual(await invoke(outside.handler, 'wss://chat.example.test/live', true), { connected: 1, closed: 1011 });
  assert.equal(snapshotPrivacy(state).blockedWebSockets, 2);
  assert.equal(snapshotPrivacy(state).blockedRequests, 2);
  assert.equal(snapshotPrivacy(state).trackerScope, 'third-party-http-websocket');
});

test('enabled privacy fails when WebSocket routing is unsupported; off does not require it', async () => {
  const context = { clearPermissions: async () => {}, setGeolocation: async () => {}, grantPermissions: async () => {}, route: async () => {} };
  const geolocation = { latitude: 0, longitude: 0, accuracy: 50000 };
  await assert.rejects(applyBrowserPrivacy(context, { geolocation }), { code: 'INVALID_PRIVACY_POLICY' });
  await applyBrowserPrivacy(context, { geolocation, privacy: 'off' });
});

test('Cloak constructor adapter is identical in both launchers and resolves base URLs before native construction', async () => {
  const { readFile } = await import('node:fs/promises');
  const { runInNewContext } = await import('node:vm');
  let install, policy;
  const context = { pages: () => [], on: () => {}, clearPermissions: async () => {}, setGeolocation: async () => {}, grantPermissions: async () => {}, route: async () => {},
    addInitScript: async (fn, args) => { install = fn; policy = args; } };
  const state = await applyBrowserPrivacy(context, { websocketRouting: 'constructor', geolocation: { latitude: 0, longitude: 0, accuracy: 50000 } });
  assert.equal(snapshotPrivacy(state).blockedWebSockets, null);
  const source = await readFile(new URL('../third_party/browseforge/internal/browser/privacy_websocket_constructor.go', import.meta.url), 'utf8');
  assert.equal(/const constructorWebSocketPolicyScript = `([\s\S]*?)`/.exec(source)[1], install.toString());
  const run = ({ target, first = 'https://example.test/', base = first, mode = 'standard', ancestors, blockLoopback = false }) => {
    const native = [];
    function NativeSocket(value) { native.push(value); }
    const sandbox = { WebSocket: NativeSocket, URL, DOMException, document: { baseURI: base }, location: { href: first, ancestorOrigins: ancestors }, policy: { ...policy, mode, blockLoopback }, target };
    sandbox.top = ancestors ? Object.defineProperty({}, 'location', { get() { throw Error('cross origin'); } }) : { location: { href: first } };
    runInNewContext(`(${install.toString()})(policy)`, sandbox);
    let error;
    try { runInNewContext('new WebSocket(target)', sandbox); } catch (caught) { error = caught.name; }
    return { native, error };
  };
  assert.deepEqual(run({ target: '/live', base: 'wss://api.segment.io/' }), { native: [], error: 'SecurityError' });
  assert.deepEqual(run({ target: 'wss://api.segment.io/live', first: 'https://app.segment.com/' }), { native: ['wss://api.segment.io/live'], error: undefined });
  assert.deepEqual(run({ target: 'wss://api.segment.io/live', first: 'https://api.segment.io/', ancestors: ['https://example.test'] }), { native: [], error: 'SecurityError' });
  assert.deepEqual(run({ target: 'wss://api.segment.io/live', mode: 'off' }), { native: ['wss://api.segment.io/live'], error: undefined });
  for (const host of ['127.0.0.1', '127.1', 'localhost', '[::1]', '[::ffff:127.0.0.1]']) {
    assert.deepEqual(run({ target: `ws://${host}/live`, mode: 'off', blockLoopback: true }), { native: [], error: 'SecurityError' }, host);
  }
  for (const host of ['127.example.test', 'localhost.example.test', '[::2]']) {
    assert.deepEqual(run({ target: `ws://${host}/live`, blockLoopback: true }), { native: [`ws://${host}/live`], error: undefined }, host);
  }
  let coerced = 0;
  assert.deepEqual(run({ target: { toString() { coerced++; return 'wss://chat.example.test/'; } } }), { native: ['wss://chat.example.test/'], error: undefined });
  assert.equal(coerced, 1);
});
