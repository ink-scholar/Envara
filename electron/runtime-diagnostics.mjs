import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';

export const RUNTIME_DIAGNOSTIC_STAGES = Object.freeze([
  'ipc.snapshot', 'ipc.terminalSnapshot', 'ipc.writeTerminal', 'ipc.resizeTerminal', 'ipc.openTerminalWindow', 'ipc.other',
  'ipc.scope', 'ipc.transfer', 'ipc.dispatch', 'ipc.enrich',
  'snapshot.ready', 'snapshot.store', 'snapshot.remote', 'snapshot.engines', 'snapshot.metrics', 'snapshot.profiles',
  'snapshot.health', 'snapshot.capture', 'snapshot.directory', 'snapshot.data-size', 'snapshot.migration',
  'snapshot.applications', 'snapshot.availability', 'snapshot.compatibility', 'snapshot.history',
  'snapshot.appearance', 'snapshot.connection', 'snapshot.publish',
  'terminal.write', 'terminal.resize', 'terminal.snapshot', 'terminal.window',
  'terminal.pty-close', 'terminal.pty-exit', 'terminal.output',
  'shutdown.startup', 'shutdown.applications', 'shutdown.diagnostics', 'shutdown.terminal', 'shutdown.broker',
  'shutdown.links', 'shutdown.router', 'shutdown.backend', 'shutdown.sidecar', 'shutdown.proxy', 'shutdown.complete',
]);

const STAGES = new Set(RUNTIME_DIAGNOSTIC_STAGES);
const MAX_PENDING = 128;
const MAX_RECENT = 256;
const MAX_FLUSH_WAITERS = 64;
const OBSERVE_INTERVAL_MS = 500;
const SLOW_STAGE_MS = 2000;
const PENDING_REFRESH_MS = 5000;
const FLUSH_WAIT_MS = 250;
const SCHEMA = 'envara.runtime-diagnostics/v1';
const own = info => typeof process.getuid !== 'function' || info.uid === process.getuid();
const privateFile = info => info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && own(info) && !(info.mode & 0o077);
const integer = value => Number.isSafeInteger(value) && value >= 0;

/** Timing evidence only, never execution or cleanup authority. Callers pass a
 * fixed stage and optional byte count, never request arguments or error objects.
 * Business operations never await persistence. Slow disks retain one active
 * write and one replaceable latest snapshot, rather than an unbounded queue.
 */
export function createRuntimeDiagnostics({ directory, clock = () => performance.now(), flushWaitMs = FLUSH_WAIT_MS } = {}) {
  const directoryPath = typeof directory === 'string' && path.isAbsolute(directory) && !/[\0\r\n]/.test(directory)
    ? path.resolve(directory) : null;
  const root = directoryPath ? path.join(directoryPath, 'runtime-diagnostics') : null;
  const waitMs = integer(flushWaitMs) && flushWaitMs > 0 && flushWaitMs <= 1000 ? flushWaitMs : FLUSH_WAIT_MS;
  const context = new AsyncLocalStorage();
  const pending = new Map(), recent = [], waiters = new Set(), reportedSlow = new Set(), unsavedImportant = new Set();
  let lastClock = 0;
  const readClock = () => {
    try { const value = clock(); if (Number.isFinite(value)) lastClock = Math.max(lastClock, value); } catch {}
    return lastClock;
  };
  const origin = readClock();
  const now = () => Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, Math.round(readClock() - origin)));
  let ordinal = 0, dropped = 0, closed = false, dirty = false, timer = null;
  let writing = false, queued = null, generation = 0, rotated = false;
  let lastPersistRequestMs = -Infinity;

  function snapshot() {
    const elapsedMs = now();
    return { schema: SCHEMA, elapsedMs, dropped,
      pending: [...pending.values()].map(item => ({ ...item, elapsedMs: Math.max(0, elapsedMs - item.startedMs) })),
      recent: recent.map(item => ({ ...item })) };
  }

  async function checkedFile(filename) {
    try { if (!privateFile(await lstat(filename))) throw new Error('unsafe diagnostic file'); return true; }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
  }
  async function persist(document) {
    if (!root) return false;
    let temporary, handle;
    try {
      // Reject linked parents before creating anything below them.
      const parent = await lstat(directoryPath);
      if (!parent.isDirectory() || parent.isSymbolicLink() || !own(parent) || await realpath(directoryPath) !== directoryPath) return false;
      await mkdir(root, { mode: 0o700 });
    } catch (error) { if (error.code !== 'EEXIST') return false; }
    try {
      const info = await lstat(root);
      if (!info.isDirectory() || info.isSymbolicLink() || !own(info) || await realpath(root) !== root) return false;
      await chmod(root, 0o700);
      const last = path.join(root, 'last-runtime.json'), previous = path.join(root, 'previous-runtime.json');
      if (!rotated) {
        if (await checkedFile(last)) { await checkedFile(previous); await rename(last, previous); }
        rotated = true;
      }
      await checkedFile(last);
      temporary = path.join(root, `.runtime-${randomUUID()}.tmp`);
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      await handle.writeFile(JSON.stringify(document, null, 2) + '\n');
      await handle.close(); handle = null;
      await rename(temporary, last); temporary = null;
      return true;
    } catch { return false; }
    finally {
      try { await handle?.close(); } catch {}
      if (temporary) try { await unlink(temporary); } catch {}
    }
  }

  function completeWaiters(through, result) {
    for (const waiter of waiters) if (waiter.generation <= through) {
      waiters.delete(waiter); clearTimeout(waiter.timer); waiter.resolve(result);
    }
  }
  function drain() {
    if (writing || !queued) return;
    writing = true;
    void Promise.resolve().then(async () => {
      while (queued) {
        const next = queued; queued = null;
        let result = false;
        try { result = await persist(next.document); } catch {}
        if (result) for (const item of next.document.recent) unsavedImportant.delete(item.ordinal);
        completeWaiters(next.generation, result);
      }
    }).finally(() => { writing = false; if (queued) drain(); }).catch(() => {});
  }
  function enqueue() {
    const value = ++generation;
    queued = { generation: value, document: snapshot() };
    lastPersistRequestMs = now();
    for (const item of pending.values()) if (lastPersistRequestMs - item.startedMs >= SLOW_STAGE_MS) reportedSlow.add(item.ordinal);
    dirty = false;
    drain();
    return value;
  }
  function schedule() {
    if (closed || timer || !pending.size && !dirty) return;
    timer = setTimeout(() => {
      timer = null;
      const elapsedMs = now();
      const slow = [...pending.values()].filter(item => elapsedMs - item.startedMs >= SLOW_STAGE_MS);
      if (dirty || slow.some(item => !reportedSlow.has(item.ordinal)) || slow.length && elapsedMs - lastPersistRequestMs >= PENDING_REFRESH_MS) enqueue();
      if ((pending.size || dirty) && !closed) schedule();
    }, OBSERVE_INTERVAL_MS);
    timer.unref?.();
  }

  function begin(stage, details) {
    if (closed || !STAGES.has(stage)) return null;
    if (pending.size >= MAX_PENDING || ordinal >= Number.MAX_SAFE_INTEGER) { dropped = Math.min(Number.MAX_SAFE_INTEGER, dropped + 1); schedule(); return null; }
    const item = { ordinal: ++ordinal, stage, startedMs: now() };
    const parentOrdinal = context.getStore();
    if (Number.isSafeInteger(parentOrdinal) && parentOrdinal > 0) item.parentOrdinal = parentOrdinal;
    // Never retain arbitrary keys, values, object references or accessors.
    try { const bytes = Object.getOwnPropertyDescriptor(details ?? {}, 'bytes')?.value; if (integer(bytes)) item.bytes = bytes; } catch {}
    pending.set(item.ordinal, item); schedule();
    return item.ordinal;
  }
  function end(id, details) {
    const item = pending.get(id);
    if (!item) return false;
    pending.delete(id);
    reportedSlow.delete(id);
    let failed = false;
    try { failed = Object.getOwnPropertyDescriptor(details ?? {}, 'failed')?.value === true; } catch {}
    const elapsedMs = Math.max(0, now() - item.startedMs);
    recent.push({ ...item, elapsedMs, status: failed ? 'failed' : 'completed' });
    if (failed || elapsedMs >= SLOW_STAGE_MS) { dirty = true; unsavedImportant.add(item.ordinal); }
    if (recent.length > MAX_RECENT) {
      // Rapid successful writes must not evict the failure that caused a
      // debounced save. Protection ends only after that evidence reaches disk.
      const normal = recent.findIndex(row => !unsavedImportant.has(row.ordinal));
      const [removed] = recent.splice(normal < 0 ? 0 : normal, 1);
      if (unsavedImportant.delete(removed.ordinal)) dropped = Math.min(Number.MAX_SAFE_INTEGER, dropped + 1);
    }
    if (!pending.size && !dirty) { clearTimeout(timer); timer = null; }
    schedule();
    return true;
  }
  async function step(stage, operation, details) {
    const id = begin(stage, details);
    try {
      const value = await (id === null ? operation() : context.run(id, operation));
      end(id);
      return value;
    } catch (error) { end(id, { failed: true }); throw error; }
  }
  function mark(stage, details) {
    const id = begin(stage, details);
    if (id !== null) end(id);
    return id;
  }
  function flush() {
    if (waiters.size >= MAX_FLUSH_WAITERS) return Promise.resolve(false);
    const requested = enqueue();
    return new Promise(resolve => {
      const waiter = { generation: requested, resolve, timer: null };
      waiter.timer = setTimeout(() => { waiters.delete(waiter); resolve(false); }, waitMs);
      waiters.add(waiter);
    });
  }
  function close() { closed = true; clearTimeout(timer); timer = null; }
  return { begin, end, step, mark, snapshot, flush, close };
}
