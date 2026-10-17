// Conservative host rules, not URL-keyword matching or injected fingerprint scripts.
// Routing and service-worker requirements: https://playwright.dev/docs/api/class-browsercontext#browser-context-route
// Chromium switches: https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md
// Standard: analytics, session-replay and pixel collection hosts only. These
// carry no site function or sign-in, so blocking them breaks nothing visible.
export const STANDARD_TRACKER_DOMAINS = Object.freeze(['google-analytics.com', 'doubleclick.net', 'api.segment.io', 'api.segment.com', 'cdn.segment.com',
  'clarity.ms', 'bat.bing.com', 'analytics.tiktok.com', 'px.ads.linkedin.com', 'mc.yandex.ru', 'mc.yandex.com', 'hm.baidu.com', 'cnzz.com',
  'scorecardresearch.com', 'quantserve.com', 'quantcount.com', 'omtrdc.net', '2o7.net', 'demdex.net']);
// Strict adds tag managers, product analytics, error telemetry and ad networks.
// Some sites need these, and connect.facebook.net also serves Facebook Login.
export const STRICT_TRACKER_DOMAINS = Object.freeze([...STANDARD_TRACKER_DOMAINS, 'googletagmanager.com', 'api.mixpanel.com', 'api-js.mixpanel.com', 'cdn.mxpnl.com', 'api.amplitude.com', 'api2.amplitude.com', 'cdn.amplitude.com', 'hotjar.com', 'hotjar.io', 'sessions.bugsnag.com', 'notify.bugsnag.com', 'browser-intake-datadoghq.com', 'browser-intake-datadoghq.eu', 'ingest.sentry.io', 'ingest.us.sentry.io', 'ingest.de.sentry.io',
  'nr-data.net', 'js-agent.newrelic.com', 'connect.facebook.net', 'ads-twitter.com', 'analytics.twitter.com', 'googleadservices.com', 'googlesyndication.com', 'adservice.google.com',
  'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com', 'adnxs.com', 'amazon-adsystem.com']);
// Only these named services get a sibling-host exception. Do not infer a site
// from the last two hostname labels: shared hosting and public suffixes differ.
const TRACKER_SERVICE_ROOTS = Object.freeze({
  'google-analytics.com': ['google-analytics.com'],
  'doubleclick.net': ['doubleclick.net'],
  'googletagmanager.com': ['googletagmanager.com'],
  'api.segment.io': ['segment.com', 'segment.io'],
  'api.segment.com': ['segment.com', 'segment.io'],
  'cdn.segment.com': ['segment.com', 'segment.io'],
  'api.mixpanel.com': ['mixpanel.com'],
  'api-js.mixpanel.com': ['mixpanel.com'],
  'api.amplitude.com': ['amplitude.com'],
  'api2.amplitude.com': ['amplitude.com'],
  'cdn.amplitude.com': ['amplitude.com'],
  'hotjar.com': ['hotjar.com', 'hotjar.io'],
  'hotjar.io': ['hotjar.com', 'hotjar.io'],
  'sessions.bugsnag.com': ['bugsnag.com'],
  'notify.bugsnag.com': ['bugsnag.com'],
  'browser-intake-datadoghq.com': ['datadoghq.com', 'browser-intake-datadoghq.com'],
  'browser-intake-datadoghq.eu': ['datadoghq.eu', 'browser-intake-datadoghq.eu'],
  'ingest.sentry.io': ['sentry.io'],
  'ingest.us.sentry.io': ['sentry.io'],
  'ingest.de.sentry.io': ['sentry.io'],
  'clarity.ms': ['clarity.ms'],
  'bat.bing.com': ['bing.com'],
  'analytics.tiktok.com': ['tiktok.com'],
  'px.ads.linkedin.com': ['linkedin.com'],
  'mc.yandex.ru': ['yandex.ru'],
  'mc.yandex.com': ['yandex.com'],
  'hm.baidu.com': ['baidu.com'],
  'cnzz.com': ['cnzz.com', 'umeng.com'],
  'scorecardresearch.com': ['scorecardresearch.com'],
  'quantserve.com': ['quantserve.com', 'quantcast.com'],
  'quantcount.com': ['quantcount.com', 'quantcast.com'],
  'omtrdc.net': ['omtrdc.net', 'adobe.com'],
  '2o7.net': ['2o7.net', 'adobe.com'],
  'demdex.net': ['demdex.net', 'adobe.com'],
  'cdn.mxpnl.com': ['mixpanel.com', 'mxpnl.com'],
  'nr-data.net': ['nr-data.net', 'newrelic.com'],
  'js-agent.newrelic.com': ['newrelic.com'],
  'connect.facebook.net': ['facebook.com', 'facebook.net'],
  'ads-twitter.com': ['twitter.com', 'x.com'],
  'analytics.twitter.com': ['twitter.com', 'x.com'],
  'googleadservices.com': ['googleadservices.com'],
  'googlesyndication.com': ['googlesyndication.com'],
  'adservice.google.com': ['google.com'],
  'criteo.com': ['criteo.com'],
  'criteo.net': ['criteo.com', 'criteo.net'],
  'taboola.com': ['taboola.com'],
  'outbrain.com': ['outbrain.com'],
  'adnxs.com': ['adnxs.com', 'xandr.com'],
  'amazon-adsystem.com': ['amazon-adsystem.com'],
});
const fail = message => Object.assign(new Error(message), { code: 'INVALID_PRIVACY_POLICY' });
export function normalizePrivacy(value) {
  if (value == null) return { mode: 'standard' };
  const mode = typeof value === 'string' ? value : value?.mode;
  if (!['off', 'standard', 'strict'].includes(mode) || (typeof value === 'object' && (Array.isArray(value) || Object.keys(value).some(key => key !== 'mode')))) throw fail('隐私模式无效。');
  return { mode };
}
export function normalizeGeolocation(value) {
  if (value == null) return null;
  if (typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['latitude', 'longitude', 'accuracy'].includes(key)) ||
      !Number.isFinite(value.latitude) || value.latitude < -90 || value.latitude > 90 ||
      !Number.isFinite(value.longitude) || value.longitude < -180 || value.longitude > 180 ||
      !Number.isFinite(value.accuracy) || value.accuracy < 1000 || value.accuracy > 1000000) throw fail('出口定位无效，定位精度必须为区域范围。');
  return { latitude: value.latitude, longitude: value.longitude, accuracy: value.accuracy };
}
export function privacyLaunchArgs(value) {
  if (normalizePrivacy(value).mode === 'off') return ['--deny-permission-prompts'];
  return ['--deny-permission-prompts', '--disable-domain-reliability', '--disable-breakpad', '--disable-sync', '--metrics-recording-only', '--no-pings'];
}
const checkedURL = value => {
  try { const parsed = new URL(value); return ['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol) ? parsed : null; } catch { return null; }
};
const matchesDomain = (host, domain) => host === domain || host.endsWith(`.${domain}`);
export function shouldBlockTracker(url, { mode = 'standard', firstPartyUrl } = {}) {
  mode = normalizePrivacy(mode).mode;
  if (mode === 'off') return false;
  const target = checkedURL(url); if (!target) return false;
  const host = target.hostname.toLowerCase().replace(/\.$/, '');
  const trackerDomain = (mode === 'strict' ? STRICT_TRACKER_DOMAINS : STANDARD_TRACKER_DOMAINS).find(domain => matchesDomain(host, domain));
  if (!trackerDomain) return false;
  const first = checkedURL(firstPartyUrl);
  if (first) {
    const firstHost = first.hostname.toLowerCase().replace(/\.$/, '');
    if (matchesDomain(host, firstHost) || matchesDomain(firstHost, host)) return false;
    if (TRACKER_SERVICE_ROOTS[trackerDomain]?.some(root => matchesDomain(firstHost, root))) return false;
  }
  return true;
}
function firstPartyURL(request) {
  try {
    const frame = request.frame(); let top = frame;
    while (top.parentFrame?.()) top = top.parentFrame();
    // A top-level navigation belongs to its destination, not the page being
    // replaced. Subframes and fetches still belong to the actual top page.
    if (request.isNavigationRequest?.() && frame === top) return request.url();
    const current = top.url?.();
    if (checkedURL(current)) return current;
  } catch {}
  return undefined;
}
// Cloak's pinned native build suppresses Playwright's page-to-host binding.
// Keep this provider adapter entirely synchronous: rejected connections never
// call the native constructor; allowed connections retain native routing and
// events. This is page/frame protection, not worker/network-wide filtering.
function installConstructorWebSocketPolicy({ mode, domains, serviceRoots, blockLoopback = false }) {
  const NativeWebSocket = globalThis.WebSocket;
  if (typeof NativeWebSocket !== 'function') return;
  const matches = (host, domain) => host === domain || host.endsWith('.' + domain);
  const hostname = (value, relative = false) => {
    try {
      const parsed = relative ? new URL(value, document.baseURI || location.href) : new URL(value);
      return ['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol) ? parsed.hostname.toLowerCase().replace(/\.$/, '') : '';
    } catch { return ''; }
  };
  const firstParty = () => {
    try { return hostname(top.location.href); }
    catch {
      // Chromium supplies the ordered ancestor origins for cross-origin
      // frames. Do not borrow the embedded frame's own origin as the top site.
      const ancestors = location.ancestorOrigins;
      return ancestors?.length ? hostname(ancestors[ancestors.length - 1]) : '';
    }
  };
  const WrappedWebSocket = new Proxy(NativeWebSocket, {
    construct(target, args, newTarget) {
      if (args.length) {
        // WebIDL string coercion happens once, preserving native validation
        // of protocols and the rest of the constructor arguments.
        const raw = '' + args[0], host = hostname(raw, true), first = firstParty();
        const domain = domains.find(value => matches(host, value));
        const loopback = host => host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127(?:\.[0-9]{1,3}){3}$/.test(host) || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(host);
        if (blockLoopback && loopback(host) && !loopback(first)) throw new DOMException('Blocked by privacy policy', 'SecurityError');
        if (mode !== 'off' && domain && !(first && (matches(host, first) || matches(first, host) || serviceRoots[domain]?.some(value => matches(first, value))))) {
          throw new DOMException('Blocked by privacy policy', 'SecurityError');
        }
        args = [raw, ...args.slice(1)];
      }
      return Reflect.construct(target, args, newTarget);
    },
  });
  Object.defineProperty(NativeWebSocket.prototype, 'constructor', { ...Object.getOwnPropertyDescriptor(NativeWebSocket.prototype, 'constructor'), value: WrappedWebSocket });
  Object.defineProperty(globalThis, 'WebSocket', { ...Object.getOwnPropertyDescriptor(globalThis, 'WebSocket'), value: WrappedWebSocket });
}

export async function applyBrowserPrivacy(context, { privacy, geolocation, websocketRouting = 'playwright' } = {}) {
  const { mode } = normalizePrivacy(privacy), geo = normalizeGeolocation(geolocation);
  if (!['playwright', 'constructor'].includes(websocketRouting)) throw fail('浏览器 WebSocket 隐私接口无效。');
  if (!context || typeof context.clearPermissions !== 'function' || typeof context.grantPermissions !== 'function' || typeof context.setGeolocation !== 'function' || (mode !== 'off' && (typeof context.route !== 'function' || (websocketRouting === 'playwright' ? typeof context.routeWebSocket !== 'function' : typeof context.addInitScript !== 'function') || typeof context.pages !== 'function' || typeof context.on !== 'function'))) throw fail('浏览器内核不支持此隐私配置。');
  const state = { mode, blockedRequests: 0, blockedWebSockets: websocketRouting.startsWith('constructor') && mode !== 'off' ? null : 0, websocketRouting, geolocation: geo, geolocationPolicy: geo ? 'proxy-region' : 'deny', trackerScope: 'third-party-http-websocket', websocketScope: 'page-and-frame', serviceWorkers: mode === 'off' ? 'allow' : 'block', routeInstalled: false };
  await context.clearPermissions();
  await context.setGeolocation(geo);
  await context.grantPermissions(geo ? ['geolocation'] : []);
  if (!geo) {
    if (typeof context.newCDPSession !== 'function' || typeof context.pages !== 'function' || typeof context.on !== 'function') throw fail('此内核尚不支持明确拒绝系统定位。');
    const denyLocation = async page => {
      const cdp = await context.newCDPSession(page);
      try {
        const { targetInfo } = await cdp.send('Target.getTargetInfo');
        const permission = { permission: { name: 'geolocation' }, setting: 'denied' };
        try {
          await cdp.send('Browser.setPermission', { ...permission, ...(targetInfo?.browserContextId ? { browserContextId: targetInfo.browserContextId } : {}) });
        } catch (error) {
          // Cloak's persistent default target has an ID which this browser
          // endpoint cannot address. Retry only that specific compatibility
          // error against the owned browser's default context.
          if (!targetInfo?.browserContextId || !String(error?.message).includes('Failed to find browser context')) throw error;
          await cdp.send('Browser.setPermission', permission);
        }
        await cdp.send('Emulation.setGeolocationOverride', {});
        // Chrome resets these overrides when the CDP session detaches. Keep
        // the owned page session attached until that page actually closes.
        page.on('close', () => { void cdp.detach().catch(() => {}); });
      } catch (error) { await cdp.detach().catch(() => {}); throw error; }
    };
    await Promise.all(context.pages().map(denyLocation));
    context.on('page', page => { void denyLocation(page).catch(() => page.close().catch(() => {})); });
  }
  if (mode !== 'off') {
    // The supported WebSocket routing API has no Request/frame accessor. A
    // page route supplies the top-level party; the context route covers the
    // interval before a new page's route is registered, without guessing it
    // from other open tabs. Neither handler ever connects blocked sockets.
    const websocketHandler = page => async socket => {
      if (shouldBlockTracker(socket.url(), { mode, firstPartyUrl: page?.url() })) {
        state.blockedRequests++; state.blockedWebSockets++;
        await socket.close({ code: 1008, reason: 'Blocked by privacy policy' }).catch(() => {});
      } else {
        try { socket.connectToServer(); }
        catch { await socket.close({ code: 1011, reason: 'Connection unavailable' }).catch(() => {}); }
      }
    };
    if (websocketRouting.startsWith('constructor')) {
      const policy = { mode, domains: mode === 'strict' ? STRICT_TRACKER_DOMAINS : STANDARD_TRACKER_DOMAINS, serviceRoots: TRACKER_SERVICE_ROOTS };
      await context.addInitScript(installConstructorWebSocketPolicy, policy);
      await Promise.all(context.pages().flatMap(page => page.frames().map(frame => frame.evaluate(installConstructorWebSocketPolicy, policy))));
    } else {
      await context.routeWebSocket('**/*', websocketHandler());
      const routePage = page => page.routeWebSocket('**/*', websocketHandler(page));
      context.on('page', page => { void routePage(page).catch(() => page.close().catch(() => {})); });
      await Promise.all(context.pages().map(routePage));
    }
    await context.route('**/*', async route => {
      const request = route.request();
      if (shouldBlockTracker(request.url(), { mode, firstPartyUrl: firstPartyURL(request) })) {
        try { await route.abort('blockedbyclient'); state.blockedRequests++; } catch { /* closed context */ }
      } else await route.continue().catch(() => {});
    });
    state.routeInstalled = true;
  }
  return state;
}
export function snapshotPrivacy(state) {
  return { mode: normalizePrivacy(state?.mode).mode, blockedRequests: Number.isSafeInteger(state?.blockedRequests) && state.blockedRequests >= 0 ? state.blockedRequests : 0,
    websocketRouting: state?.websocketRouting ?? 'playwright',
    blockedWebSockets: state?.blockedWebSockets === null ? null : Number.isSafeInteger(state?.blockedWebSockets) && state.blockedWebSockets >= 0 ? state.blockedWebSockets : 0,
    geolocation: state?.geolocation ? { ...state.geolocation } : null, geolocationPolicy: state?.geolocation ? 'proxy-region' : 'deny',
    trackerScope: 'third-party-http-websocket', websocketScope: 'page-and-frame', serviceWorkers: state?.serviceWorkers ?? 'block', enabled: state?.mode !== 'off' };
}
