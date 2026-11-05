import { networkInterfaces } from 'node:os';
import { createHash } from 'node:crypto';

// Addresses only inform a private change detector. They are never published,
// persisted, sent to a renderer, or used as evidence of Internet reachability.
function signature(interfaces) {
  return createHash('sha256').update(JSON.stringify(Object.entries(interfaces).flatMap(([name, addresses]) =>
    (addresses ?? []).filter(item => !item.internal).map(item => [name, item.family, item.address, item.scopeid ?? null])
  ).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))))).digest('hex');
}

/** Main-process observer; online hints schedule routed HTTPS checks only. */
export function createNetworkRecoveryMonitor({ recover, isOnline = () => true, powerMonitor,
  interfaces = networkInterfaces, pollIntervalMs = 5000, retryDelaysMs = [1000, 3000, 10000, 30000],
  timers = globalThis } = {}) {
  if (typeof recover !== 'function' || typeof isOnline !== 'function' || typeof interfaces !== 'function' ||
      !Number.isFinite(pollIntervalMs) || pollIntervalMs < 1 || !Array.isArray(retryDelaysMs) ||
      retryDelaysMs.some(value => !Number.isFinite(value) || value < 1)) throw new TypeError('Invalid network recovery monitor');
  let closed = false, running = false, retry = null, attempts = 0, revision = 0;
  const read = () => { try { return `${isOnline() === true}:${signature(interfaces())}`; } catch { return null; } };
  let previous = read();
  const controllers = new Set();
  const cancelRetry = () => { if (retry != null) timers.clearTimeout(retry); retry = null; };
  const run = async (retrying = false) => {
    if (closed) return;
    if (running && retrying) return;
    const current = ++revision;
    for (const controller of controllers) controller.abort();
    const controller = new AbortController(); controllers.add(controller);
    running = true; cancelRetry();
    let success = false;
    try { success = (await recover({ retry: retrying, signal: controller.signal }))?.ok === true; } catch { /* Retry transient route and DHCP failures without exposing details. */ }
    finally {
      controllers.delete(controller);
      if (closed || current !== revision) return;
      running = false;
      if (!success && retryDelaysMs.length) {
        const delay = retryDelaysMs[Math.min(attempts++, retryDelaysMs.length - 1)];
        retry = timers.setTimeout(() => { retry = null; void run(true); }, delay); retry?.unref?.();
      } else attempts = 0;
    }
  };
  const check = () => {
    if (closed) return;
    const current = read();
    if (current !== previous) { previous = current; attempts = 0; cancelRetry(); void run(); }
  };
  const resume = () => { if (!closed) { previous = read(); attempts = 0; cancelRetry(); void run(); } };
  const interval = timers.setInterval(check, pollIntervalMs); interval?.unref?.();
  powerMonitor?.on?.('resume', resume);
  return Object.freeze({
    check,
    close() { if (closed) return; closed = true; for (const controller of controllers) controller.abort(); cancelRetry(); timers.clearInterval(interval); powerMonitor?.removeListener?.('resume', resume); },
  });
}
