import { isPublicIP } from './proxy-network.mjs';

const MAX_AGE_MS = 5 * 60_000;
const fail = () => Object.assign(new Error('运行核验参数无效。'), { code: 'RUNTIME_VERIFICATION_INVALID' });
const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
function input(value, optional = false) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => key !== 'id') || !(optional && value.id === undefined || id(value.id))) throw fail();
  return value.id;
}
function locale(value) {
  if (typeof value !== 'string' || value.length > 100) return null;
  try { return Intl.getCanonicalLocales(value)[0] ?? null; } catch { return null; }
}
function timezone(value) {
  if (typeof value !== 'string' || value.length > 100) return null;
  try { return new Intl.DateTimeFormat('en', { timeZone: value }).resolvedOptions().timeZone; } catch { return null; }
}
export function sanitizeRuntimeObservation(value) {
  return { locale: locale(value?.locale), timezone: timezone(value?.timezone), ip: isPublicIP(value?.ip) ? value.ip : null };
}
const comparisons = (expected, observed) => Object.fromEntries(['locale', 'timezone', 'ip'].map(key => [key,
  !expected[key] || !observed[key] ? 'unknown' : expected[key] === observed[key] ? 'match' : 'mismatch']));

/** Explicit checks only; no constructor/snapshot call starts network traffic.
 * Browser results belong to one browser document. Terminal values below are
 * captured launch settings, never a claim about an active shell or its clients. */
export class RuntimeVerificationService {
  constructor({ browserService, terminalService, now = Date.now } = {}) {
    if (typeof browserService?.captureRuntimeVerificationContext !== 'function') throw new TypeError('Runtime verification needs browser authority.');
    this.browser = browserService;
    this.terminal = terminalService;
    this.now = now;
    this.results = new Map();
    this.pending = new Map();
  }
  terminalObservation(profileId, expected) {
    const sessions = [...(this.terminal?.sessions?.values() ?? [])]
      .filter(session => session.profileId === profileId && ['starting', 'running', 'closing'].includes(session.status))
      .map(session => {
        const launchLocale = typeof session.language === 'string' ? locale(session.language.split('.')[0].replaceAll('_', '-')) : null;
        const matches = comparisons(expected, { timezone: timezone(session.timezone), locale: launchLocale, ip: null });
        return { sessionId: id(session.sessionId) ? session.sessionId : null, status: session.status,
        startedAt: Number.isFinite(Date.parse(session.startedAt)) ? new Date(session.startedAt).toISOString() : null,
        timezone: timezone(session.timezone),
        language: typeof session.language === 'string' && /^[A-Za-z0-9_.@-]{1,100}$/.test(session.language) ? session.language : null,
        networkFence: session.networkFence === true,
        configurationMatches: [matches.timezone, matches.locale].includes('mismatch') ? false : matches.timezone === 'match' && matches.locale === 'match' ? true : null,
      }; });
    return { scope: 'terminal-launch-context', status: 'unknown', sessions, observed: { locale: null, timezone: null, ip: null } };
  }
  async present(record) {
    let staleReason = null;
    let currentExpected = sanitizeRuntimeObservation(null);
    try {
      const current = await this.browser.captureRuntimeVerificationContext(record.profileId);
      currentExpected = sanitizeRuntimeObservation(current.expected);
      if (current.revision !== record.revision || !current.available) staleReason = 'configuration';
    } catch { staleReason = 'unavailable'; }
    if (!staleReason && this.now() - record.checkedAt > MAX_AGE_MS) staleReason = 'age';
    return { profileId: record.profileId, checkedAt: new Date(record.checkedAt).toISOString(),
      stale: !!staleReason, staleReason, expected: { ...record.expected },
      browser: structuredClone(record.browser), terminal: this.terminalObservation(record.profileId, currentExpected) };
  }
  async runtimeVerificationSnapshot(args = {}) {
    const profileId = input(args, true);
    const records = profileId ? [this.results.get(profileId)].filter(Boolean) : [...this.results.values()];
    return { results: await Promise.all(records.map(record => this.present(record))), pending: [...this.pending.keys()].filter(key => !profileId || key === profileId) };
  }
  checkRuntimeVerification(args) {
    const profileId = input(args);
    if (this.pending.has(profileId)) return this.pending.get(profileId);
    const task = this.check(profileId).finally(() => { if (this.pending.get(profileId) === task) this.pending.delete(profileId); });
    this.pending.set(profileId, task);
    return task;
  }
  async check(profileId) {
    let state;
    try { state = await this.browser.captureRuntimeVerificationContext(profileId, { verifyReceipt: true }); }
    catch { state = await this.browser.captureRuntimeVerificationContext(profileId).catch(() => null); }
    if (!state) throw Object.assign(new Error('无法读取当前环境，请刷新后重试。'), { code: 'RUNTIME_VERIFICATION_UNAVAILABLE' });
    const expected = sanitizeRuntimeObservation(state.expected);
    let observed = sanitizeRuntimeObservation(null);
    let reason = 'route-unverified';
    // snapshot-only candidates have no pinned authority and cannot issue HTTP.
    if (state.available && state.sessionId && /^[a-f0-9]{32}$/.test(state.instanceId ?? '') && /^[a-f0-9]{64}$/.test(state.routeDigest ?? '')) {
      try {
        const response = await this.browser.request('POST', `/api/sessions/${encodeURIComponent(state.sessionId)}/runtime-verification`,
          { instance_id: state.instanceId, route_digest: state.routeDigest }, { timeoutMs: 15000 });
        observed = sanitizeRuntimeObservation(response?.data);
        reason = observed.ip ? null : 'egress-unobserved';
      } catch (error) { reason = error?.code === 'RUNTIME_VERIFICATION_UNSUPPORTED' ? 'unsupported-runtime' : 'observation-unavailable'; }
    }
    const observedCount = Object.values(observed).filter(Boolean).length;
    const record = { profileId, revision: state.revision, expected, checkedAt: this.now(), browser: {
      scope: 'browser-owned-page', status: observedCount === 3 ? 'observed' : observedCount ? 'partial' : 'unknown',
      source: observed.ip ? 'ipwho.is' : null, observed, checks: comparisons(expected, observed), reason,
    } };
    this.results.set(profileId, record);
    return this.present(record);
  }
}
