// Conservative host rules, not URL-keyword matching or injected fingerprint scripts.
// Routing and service-worker requirements: https://playwright.dev/docs/api/class-browsercontext#browser-context-route
// Chromium switches: https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md
export const STANDARD_TRACKER_DOMAINS = Object.freeze(['google-analytics.com', 'doubleclick.net', 'api.segment.io', 'api.segment.com', 'cdn.segment.com']);
export const STRICT_TRACKER_DOMAINS = Object.freeze([...STANDARD_TRACKER_DOMAINS, 'googletagmanager.com', 'api.mixpanel.com', 'api-js.mixpanel.com', 'api.amplitude.com', 'api2.amplitude.com', 'cdn.amplitude.com', 'hotjar.com', 'hotjar.io', 'sessions.bugsnag.com', 'notify.bugsnag.com', 'browser-intake-datadoghq.com', 'browser-intake-datadoghq.eu', 'ingest.sentry.io', 'ingest.us.sentry.io', 'ingest.de.sentry.io']);
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
  try { const parsed = new URL(value); return ['http:', 'https:'].includes(parsed.protocol) ? parsed : null; } catch { return null; }
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
export async function applyBrowserPrivacy(context, { privacy, geolocation } = {}) {
  const { mode } = normalizePrivacy(privacy), geo = normalizeGeolocation(geolocation);
  if (!context || typeof context.clearPermissions !== 'function' || typeof context.grantPermissions !== 'function' || typeof context.setGeolocation !== 'function' || (mode !== 'off' && typeof context.route !== 'function')) throw fail('浏览器内核不支持此隐私配置。');
  const state = { mode, blockedRequests: 0, geolocation: geo, geolocationPolicy: geo ? 'proxy-region' : 'deny', trackerScope: 'third-party-http', serviceWorkers: mode === 'off' ? 'allow' : 'block', routeInstalled: false };
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
    geolocation: state?.geolocation ? { ...state.geolocation } : null, geolocationPolicy: state?.geolocation ? 'proxy-region' : 'deny',
    trackerScope: 'third-party-http', serviceWorkers: state?.serviceWorkers ?? 'block', enabled: state?.mode !== 'off' };
}
