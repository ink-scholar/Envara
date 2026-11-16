import { networkInterfaces } from 'node:os';
import { createHash } from 'node:crypto';

// Addresses only inform a private change detector. They are never published,
// persisted, sent to a renderer, or used as evidence of Internet reachability.
function signature(interfaces) {
  return createHash('sha256').update(JSON.stringify(Object.entries(interfaces).flatMap(([name, addresses]) =>
    (addresses ?? []).filter(item => !item.internal).map(item => [name, item.family, item.address, item.scopeid ?? null])
  ).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))))).digest('hex');
}

export function initialNetworkRecoveryState() {
  return { revision: 0, phase: 'idle', reason: null, attempt: 0, retryAt: null, checkedAt: null };
}

/** Main-process observer; online hints schedule routed HTTPS checks only.
 * Published state describes attempts on previously used routes, never network
 * addresses, credentials, or a claim about every consumer's connectivity.
 */
export function createNetworkRecoveryMonitor({ recover, isOnline = () => true, powerMonitor,
  interfaces = networkInterfaces, pollIntervalMs = 5000, retryDelaysMs = [1000, 3000, 10000, 30000],
  timers = globalThis, nowMs = Date.now, onChange = () => {} } = {}) {
  if (typeof recover !== 'function' || typeof isOnline !== 'function' || typeof interfaces !== 'function' ||
      typeof nowMs !== 'function' || typeof onChange !== 'function' ||
      !Number.isFinite(pollIntervalMs) || pollIntervalMs < 1 || !Array.isArray(retryDelaysMs) ||
      retryDelaysMs.some(value => !Number.isFinite(value) || value < 1)) throw new TypeError('Invalid network recovery monitor');
  let closed = false, running = false, retry = null, attempts = 0, revision = 0;
  let state = initialNetworkRecoveryState();
  const snapshot = () => ({ ...state });
  const publish = next => {
    state = { ...state, ...next, revision: state.revision + 1 };
    try { Promise.resolve(onChange(snapshot())).catch(() => {}); } catch { /* Observation never controls recovery. */ }
  };
  const timestamp = () => new Date(nowMs()).toISOString();
  const read = () => { try { return `${isOnline() === true}:${signature(interfaces())}`; } catch { return null; } };
  let previous = read();
  const controllers = new Set();
  const cancelRetry = () => { if (retry != null) timers.clearTimeout(retry); retry = null; };
  const run = async (retrying, reason) => {
    if (closed) return;
    if (running && retrying) return;
    const current = ++revision;
    for (const controller of controllers) controller.abort();
    const controller = new AbortController(); controllers.add(controller);
    running = true; cancelRetry();
    const attempt = ++attempts;
    publish({ phase: 'checking', reason, attempt, retryAt: null, checkedAt: retrying ? state.checkedAt : null });
    let result;
    try {
      if (!closed && current === revision) result = await recover({ retry: retrying, signal: controller.signal });
    } catch { /* Retry transient route and DHCP failures without exposing details. */ }
    finally {
      controllers.delete(controller);
      if (closed || current !== revision) return;
      running = false;
      if (result?.ok === true) {
        if (result.checkedRouteCount === 0) publish({ phase: 'idle', reason: null, attempt: 0, retryAt: null, checkedAt: null });
        else publish({ phase: 'recovered', retryAt: null, checkedAt: timestamp() });
      } else {
        const delay = retryDelaysMs.length ? retryDelaysMs[Math.min(attempt - 1, retryDelaysMs.length - 1)] : null;
        publish({ phase: 'waiting', retryAt: delay == null ? null : new Date(nowMs() + delay).toISOString(), checkedAt: timestamp() });
        if (delay != null && !closed && current === revision) {
          retry = timers.setTimeout(() => {
            if (closed || current !== revision) return;
            retry = null; void run(true, 'retry');
          }, delay);
          retry?.unref?.();
        }
      }
    }
  };
  const check = () => {
    if (closed) return;
    const current = read();
    if (current !== previous) { previous = current; attempts = 0; cancelRetry(); void run(false, 'network-change'); }
  };
  const resume = () => { if (!closed) { previous = read(); attempts = 0; cancelRetry(); void run(false, 'resume'); } };
  const interval = timers.setInterval(check, pollIntervalMs); interval?.unref?.();
  powerMonitor?.on?.('resume', resume);
  return Object.freeze({
    check, snapshot,
    retryNow(args = {}) {
      // Renderer requests choose no route, target, retry policy or credentials.
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.getPrototypeOf(args) !== Object.prototype || Reflect.ownKeys(args).length)
        throw Object.assign(new Error('网络重试参数无效。'), { code: 'INVALID_NETWORK_RECOVERY_REQUEST' });
      if (closed) throw Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' });
      if (running) return snapshot();
      const current = read();
      // A manual retry can arrive before the next interface poll. That change
      // still requires fresh route/cache invalidation, not failed-node retries.
      const retrying = state.phase === 'waiting' && current === previous;
      if (!retrying) attempts = 0;
      previous = current; cancelRetry(); void run(retrying, 'manual');
      return snapshot();
    },
    close() {
      if (closed) return;
      closed = true; revision++; running = false;
      for (const controller of controllers) controller.abort();
      cancelRetry(); timers.clearInterval(interval); powerMonitor?.removeListener?.('resume', resume);
      publish({ phase: 'idle', reason: null, attempt: 0, retryAt: null, checkedAt: null });
    },
  });
}
