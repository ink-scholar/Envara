import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { chmod, lstat, mkdir, open, rename, rm } from 'node:fs/promises';

const MAX_STAGES = 32;
const FLUSH_WAIT_MS = 250;
const stageName = value => typeof value === 'string' && /^[a-z][a-z0-9.-]{0,63}$/.test(value);
const errorCode = value => typeof value === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/.test(value) ? value : null;
const finiteClock = (read, fallback) => {
  try { const value = read(); return Number.isFinite(value) ? value : fallback; } catch { return fallback; }
};
const milliseconds = value => Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, Math.round(value)));
const ownFile = info => info.isFile() && !info.isSymbolicLink() && info.nlink === 1 &&
  (typeof process.getuid !== 'function' || info.uid === process.getuid());

/** Private, bounded startup timing only. `directory` is the app's userData root.
 * Automatic writes are queued before awaiting work, never awaited by that work.
 * A stalled filesystem can delay a receipt but cannot stall the startup stages.
 */
export function createStartupDiagnostics({ directory, version, clock = () => performance.now(), wallClock = Date.now,
  entryUptimeMs = Math.round(process.uptime() * 1000) } = {}) {
  const root = typeof directory === 'string' && path.isAbsolute(directory) && !/[\0\r\n]/.test(directory)
    ? path.join(directory, 'startup-diagnostics') : null;
  const appVersion = typeof version === 'string' && version.length <= 80 && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)
    ? version : 'unknown';
  const origin = finiteClock(clock, 0);
  const startedAtMs = milliseconds(finiteClock(wallClock, Date.now()));
  const uptime = Number.isFinite(entryUptimeMs) ? milliseconds(entryUptimeMs) : 0;
  const stages = [];
  let elapsed = 0, failureCode = null, rotated = false;
  let writes = Promise.resolve(false);
  const now = () => (elapsed = Math.max(elapsed, milliseconds(finiteClock(clock, origin) - origin)));

  function snapshot() {
    const totalMs = now();
    return { version: appVersion, startedAtMs, entryUptimeMs: uptime, totalMs,
      stages: stages.map(stage => ({ name: stage.name, status: stage.status, startedMs: stage.startedMs,
        durationMs: stage.durationMs ?? Math.max(0, totalMs - stage.startedMs), ...(stage.code ? { code: stage.code } : {}) })),
      ...(failureCode ? { code: failureCode } : {}) };
  }

  async function regularFile(filename) {
    try { const info = await lstat(filename); if (!ownFile(info)) throw new Error('unsafe diagnostic file'); return true; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }
  async function persist(document) {
    if (!root) return false;
    let temporary, handle;
    try {
      await mkdir(root, { recursive: true, mode: 0o700 });
      const info = await lstat(root);
      if (!info.isDirectory() || info.isSymbolicLink() || typeof process.getuid === 'function' && info.uid !== process.getuid()) return false;
      await chmod(root, 0o700);
      const last = path.join(root, 'last-startup.json'), previous = path.join(root, 'previous-startup.json');
      if (!rotated) {
        const exists = await regularFile(last);
        if (exists) { await regularFile(previous); await rename(last, previous); await chmod(previous, 0o600); }
        rotated = true;
      }
      // A random exclusive sibling is atomically published; no partial JSON is
      // visible, and a linked/replaced old log is never opened for writing.
      temporary = path.join(root, `.last-startup-${randomUUID()}.tmp`);
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(JSON.stringify(document, null, 2) + '\n');
      await handle.chmod(0o600);
      await handle.close(); handle = null;
      await rename(temporary, last); temporary = null;
      return true;
    } catch { return false; }
    finally {
      try { await handle?.close(); } catch {}
      if (temporary) try { await rm(temporary, { force: true }); } catch {}
    }
  }

  function flush() {
    const document = snapshot();
    // The actual writer remains serialized even if a caller's bounded wait
    // expires. A timed-out write cannot race the next snapshot onto disk.
    const pending = writes.then(() => persist(document)).catch(() => false);
    writes = pending;
    let timer;
    const timeout = new Promise(resolve => { timer = setTimeout(() => resolve(false), FLUSH_WAIT_MS); });
    return Promise.race([pending, timeout]).finally(() => clearTimeout(timer));
  }
  function start(name, status = 'started') {
    if (!stageName(name) || stages.length >= MAX_STAGES) return null;
    const stage = { name, status, startedMs: now(), ...(status === 'completed' ? { durationMs: 0 } : {}) };
    stages.push(stage);
    void flush();
    return stage;
  }
  function mark(name) {
    return start(name, 'completed') !== null;
  }
  function fail(code) {
    const stable = errorCode(code);
    if (!stable) return false;
    failureCode ??= stable;
    void flush();
    return true;
  }
  async function step(name, operation) {
    const stage = start(name);
    try {
      const result = await operation();
      if (stage) { stage.status = 'completed'; stage.durationMs = Math.max(0, now() - stage.startedMs); void flush(); }
      return result;
    } catch (error) {
      if (stage) {
        stage.status = 'failed'; stage.durationMs = Math.max(0, now() - stage.startedMs);
        try { stage.code = errorCode(error?.code); } catch {}
        void flush();
      }
      throw error;
    }
  }
  return { step, mark, fail, flush, snapshot };
}
