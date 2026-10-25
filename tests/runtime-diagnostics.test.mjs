import test from 'node:test';
import assert from 'node:assert/strict';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRuntimeDiagnostics, RUNTIME_DIAGNOSTIC_STAGES } from '../electron/runtime-diagnostics.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
async function fixture(t, options = {}) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-runtime-diagnostics-')));
  const diagnostics = createRuntimeDiagnostics({ directory, ...options });
  t.after(async () => { diagnostics.close(); await rm(directory, { recursive: true, force: true }); });
  return { directory, diagnostics, root: path.join(directory, 'runtime-diagnostics'),
    last: path.join(directory, 'runtime-diagnostics/last-runtime.json'), previous: path.join(directory, 'runtime-diagnostics/previous-runtime.json') };
}

test('nested and concurrent stages retain only local ordinal ancestry and preserve operation results', async t => {
  let tick = 100;
  const f = await fixture(t, { clock: () => tick });
  const gate = deferred(), entered = deferred();
  const value = { synthetic: true };
  const operation = f.diagnostics.step('ipc.snapshot', async () => {
    tick = 110;
    return f.diagnostics.step('ipc.dispatch', async () => {
      await Promise.resolve();
      return Promise.all([
        f.diagnostics.step('snapshot.store', async () => value),
        f.diagnostics.step('snapshot.remote', async () => { entered.resolve(); await gate.promise; return 42; }),
      ]);
    });
  });
  await entered.promise;
  tick = 135;
  const pending = f.diagnostics.snapshot();
  assert.deepEqual(pending.pending.map(row => [row.ordinal, row.parentOrdinal, row.stage]), [
    [1, undefined, 'ipc.snapshot'], [2, 1, 'ipc.dispatch'], [4, 2, 'snapshot.remote'],
  ]);
  assert.equal(pending.pending[0].elapsedMs, 35);
  assert.deepEqual(pending.recent.map(row => [row.ordinal, row.parentOrdinal, row.stage]), [[3, 2, 'snapshot.store']]);
  pending.pending[0].stage = 'private-mutation';
  assert.equal(await f.diagnostics.flush(), true);
  assert.equal(JSON.parse(await readFile(f.last, 'utf8')).pending[0].stage, 'ipc.snapshot');
  gate.resolve();
  const result = await operation;
  assert.equal(result[0], value);
  assert.equal(result[1], 42);
  assert.deepEqual(f.diagnostics.snapshot().pending, []);
  assert.equal(f.diagnostics.snapshot().recent.at(-1).elapsedMs, 35);
  const outside = f.diagnostics.mark('terminal.write', { bytes: 7 });
  assert.equal(outside, 5);
  assert.equal(f.diagnostics.snapshot().recent.at(-1).parentOrdinal, undefined);
});

test('fixed stage allowlists and numeric metadata exclude contents, paths, identifiers, credentials and errors', async t => {
  const f = await fixture(t);
  let accessorReads = 0;
  const secret = 'PRIVATE_FIXTURE_SECRET';
  const details = { bytes: 12, input: secret, output: secret, args: { password: secret }, id: secret,
    sessionId: secret, token: secret, path: '/private/fixture-only' };
  const id = f.diagnostics.begin('terminal.write', details);
  details.bytes = 99;
  f.diagnostics.end(id, { failed: true, message: secret, code: secret });
  const accessor = { get bytes() { accessorReads++; throw new Error(secret); } };
  f.diagnostics.mark('terminal.output', accessor);
  f.diagnostics.mark('terminal.output', { bytes: -1 });
  f.diagnostics.mark('terminal.output', { bytes: Infinity });
  f.diagnostics.mark('terminal.output', { bytes: '12' });
  f.diagnostics.mark('terminal.output', { bytes: 0 });
  for (const stage of [secret, 'snapshot.' + secret, '/private/fixture-only', null, {}, 'constructor'])
    assert.equal(f.diagnostics.begin(stage, details), null);
  const failure = Object.assign(new Error(secret), { code: secret, path: '/private/fixture-only' });
  await assert.rejects(f.diagnostics.step('ipc.writeTerminal', async () => { throw failure; }), error => error === failure);
  assert.equal(await f.diagnostics.step(secret, async () => 42), 42, 'An invalid diagnostic stage cannot block business work');
  assert.equal(accessorReads, 0);
  assert.equal(await f.diagnostics.flush(), true);
  const text = await readFile(f.last, 'utf8');
  assert.doesNotMatch(text, /PRIVATE_FIXTURE_SECRET|fixture-only|"(?:sessionId|password|token|input|output|args|path|message|stack)"\s*:/);
  const rows = JSON.parse(text).recent;
  assert.equal(rows[0].bytes, 12);
  assert.equal(rows[0].status, 'failed');
  assert.equal(rows[1].bytes, undefined);
  assert.equal(rows[5].bytes, 0);
  assert.ok(rows.every(row => Object.keys(row).every(key => ['ordinal', 'parentOrdinal', 'stage', 'startedMs', 'elapsedMs', 'status', 'bytes'].includes(key))));
  assert.equal(new Set(RUNTIME_DIAGNOSTIC_STAGES).size, RUNTIME_DIAGNOSTIC_STAGES.length);
  assert.equal(Object.isFrozen(RUNTIME_DIAGNOSTIC_STAGES), true);
});

test('pending operations and completed history remain bounded while unrecorded work still executes', async t => {
  const f = await fixture(t);
  const ids = Array.from({ length: 128 }, () => f.diagnostics.begin('ipc.snapshot'));
  assert.equal(ids.at(-1), 128);
  assert.equal(f.diagnostics.begin('ipc.snapshot'), null);
  assert.equal(await f.diagnostics.step('terminal.write', async () => 'accepted'), 'accepted');
  assert.equal(f.diagnostics.snapshot().pending.length, 128);
  assert.equal(f.diagnostics.snapshot().dropped, 2);
  for (const id of ids) assert.equal(f.diagnostics.end(id), true);
  assert.equal(f.diagnostics.end(ids[0]), false);
  for (let index = 0; index < 300; index++) f.diagnostics.mark('terminal.write', { bytes: 1 });
  const state = f.diagnostics.snapshot();
  assert.equal(state.pending.length, 0);
  assert.equal(state.recent.length, 256);
  assert.equal(state.recent[0].ordinal, 173);
  assert.equal(state.recent.at(-1).ordinal, 428);
  state.recent[0].bytes = 999;
  assert.equal(f.diagnostics.snapshot().recent[0].bytes, 1);
});

test('slow persistence coalesces snapshots and cannot hold business work or explicit flushes indefinitely', async t => {
  const f = await fixture(t, { flushWaitMs: 50 }), gate = deferred(), entered = deferred();
  const originalOpen = fsPromises.open;
  let opens = 0, active = 0, maximum = 0;
  t.mock.method(fsPromises, 'open', async (filename, ...args) => {
    if (typeof filename !== 'string' || !filename.startsWith(f.root + path.sep)) return originalOpen(filename, ...args);
    opens++; active++; maximum = Math.max(maximum, active);
    if (opens === 1) { entered.resolve(); await gate.promise; }
    try { return await originalOpen(filename, ...args); } finally { active--; }
  });
  syncBuiltinESMExports();
  try {
    f.diagnostics.mark('snapshot.remote');
    const first = f.diagnostics.flush();
    await entered.promise;
    const queued = [];
    for (let index = 0; index < 16; index++) {
      f.diagnostics.mark('snapshot.metrics');
      queued.push(f.diagnostics.flush());
    }
    assert.equal(await f.diagnostics.step('terminal.write', async () => 'accepted'), 'accepted');
    assert.deepEqual(await Promise.all([first, ...queued]), Array(17).fill(false));
    assert.equal(opens, 1, 'Only one persistence operation reaches the stalled filesystem');
    const latest = f.diagnostics.mark('shutdown.complete');
    const finalFlush = f.diagnostics.flush();
    f.diagnostics.close();
    gate.resolve();
    assert.equal(await finalFlush, true);
    assert.equal(opens, 2, 'All pending persistence snapshots coalesce into one latest snapshot');
    assert.equal(maximum, 1);
    assert.equal(JSON.parse(await readFile(f.last, 'utf8')).recent.at(-1).ordinal, latest);
  } finally { gate.resolve(); t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('fast terminal writes and workspace snapshots stay in memory without automatic disk writes', async t => {
  const f = await fixture(t);
  for (let index = 0; index < 100; index++) {
    await f.diagnostics.step('terminal.write', async () => true, { bytes: 1 });
    await f.diagnostics.step('ipc.snapshot', async () => true);
  }
  await new Promise(resolve => setTimeout(resolve, 650));
  assert.deepEqual(await readdir(f.directory), []);
  assert.equal(f.diagnostics.snapshot().recent.length, 200);
});

test('an unresolved slow stage and its completion are saved without cancelling its operation', async t => {
  const f = await fixture(t), gate = deferred();
  const operation = f.diagnostics.step('ipc.openTerminalWindow', async () => { await gate.promise; return 'window'; });
  try {
    await new Promise(resolve => setTimeout(resolve, 2250));
    const state = JSON.parse(await readFile(f.last, 'utf8'));
    assert.equal(state.pending.length, 1);
    assert.equal(state.pending[0].stage, 'ipc.openTerminalWindow');
    assert.ok(state.pending[0].elapsedMs >= 2000);
    assert.equal(state.recent.length, 0);
    await new Promise(resolve => setTimeout(resolve, 650));
    assert.equal(await readFile(f.last, 'utf8'), JSON.stringify(state, null, 2) + '\n', 'An unchanged pending stage is not written every observation tick');
    gate.resolve();
    assert.equal(await operation, 'window');
    await new Promise(resolve => setTimeout(resolve, 650));
    const completed = JSON.parse(await readFile(f.last, 'utf8'));
    assert.equal(completed.pending.length, 0);
    assert.equal(completed.recent[0].status, 'completed');
  } finally { gate.resolve(); await operation; }
});

test('a fast failure saves only the fixed stage and failure state automatically', async t => {
  const f = await fixture(t), error = new Error('private fixture error');
  await assert.rejects(f.diagnostics.step('terminal.write', async () => { throw error; }), actual => actual === error);
  await new Promise(resolve => setTimeout(resolve, 650));
  const text = await readFile(f.last, 'utf8');
  assert.doesNotMatch(text, /private fixture error/);
  assert.equal(JSON.parse(text).recent[0].status, 'failed');
});

test('fast event bursts cannot evict unsaved failures or slow completions before their coalesced save', async t => {
  let tick = 0;
  const f = await fixture(t, { clock: () => tick });
  const slow = f.diagnostics.begin('snapshot.remote');
  tick = 2100; f.diagnostics.end(slow);
  const failed = f.diagnostics.begin('terminal.write'); f.diagnostics.end(failed, { failed: true });
  for (let index = 0; index < 300; index++) f.diagnostics.mark('snapshot.store');
  assert.equal(f.diagnostics.snapshot().recent.length, 256);
  await new Promise(resolve => setTimeout(resolve, 650));
  const saved = JSON.parse(await readFile(f.last, 'utf8'));
  assert.ok(saved.recent.some(row => row.ordinal === slow && row.elapsedMs === 2100));
  assert.ok(saved.recent.some(row => row.ordinal === failed && row.status === 'failed'));
  for (let index = 0; index < 300; index++) f.diagnostics.mark('snapshot.store');
  assert.ok(!f.diagnostics.snapshot().recent.some(row => row.ordinal === failed || row.ordinal === slow), 'Successfully saved evidence can age out normally');
});

test('even an error storm has bounded retained evidence and reports dropped evidence numerically', async t => {
  const f = await fixture(t);
  for (let index = 0; index < 300; index++) {
    const id = f.diagnostics.begin('terminal.write'); f.diagnostics.end(id, { failed: true });
  }
  const state = f.diagnostics.snapshot();
  assert.equal(state.recent.length, 256);
  assert.equal(state.dropped, 44);
  assert.ok(state.recent.every(row => row.status === 'failed'));
});

test('private receipts rotate once per instance and preserve only the current and previous run', async t => {
  const f = await fixture(t);
  assert.deepEqual(await readdir(f.directory), [], 'Construction alone does not write');
  f.diagnostics.mark('terminal.write');
  assert.equal(await f.diagnostics.flush(), true);
  f.diagnostics.close();
  for (const stage of ['snapshot.store', 'shutdown.complete']) {
    const diagnostics = createRuntimeDiagnostics({ directory: f.directory });
    diagnostics.mark(stage); assert.equal(await diagnostics.flush(), true);
    diagnostics.mark(stage); assert.equal(await diagnostics.flush(), true);
    diagnostics.close();
  }
  assert.deepEqual((await readdir(f.root)).sort(), ['last-runtime.json', 'previous-runtime.json']);
  assert.deepEqual(JSON.parse(await readFile(f.last, 'utf8')).recent.map(row => row.stage), ['shutdown.complete', 'shutdown.complete']);
  assert.deepEqual(JSON.parse(await readFile(f.previous, 'utf8')).recent.map(row => row.stage), ['snapshot.store', 'snapshot.store']);
  if (process.platform !== 'win32') {
    assert.equal((await stat(f.root)).mode & 0o777, 0o700);
    assert.equal((await stat(f.last)).mode & 0o777, 0o600);
    assert.equal((await stat(f.previous)).mode & 0o777, 0o600);
  }
});

test('linked diagnostic roots and receipt files fail soft without touching unrelated targets', async t => {
  const f = await fixture(t), target = path.join(f.directory, 'unrelated');
  await mkdir(target);
  const keep = path.join(target, 'keep'); await writeFile(keep, 'untouched');
  await symlink(target, f.root, process.platform === 'win32' ? 'junction' : 'dir');
  assert.equal(await f.diagnostics.step('terminal.write', async () => 42), 42);
  assert.equal(await f.diagnostics.flush(), false);
  assert.deepEqual(await readdir(target), ['keep']);
  assert.equal(await readFile(keep, 'utf8'), 'untouched');
  await rm(f.root); await mkdir(f.root);
  await symlink(keep, f.last, process.platform === 'win32' ? 'file' : undefined);
  assert.equal(await f.diagnostics.flush(), false);
  assert.equal(await readFile(keep, 'utf8'), 'untouched');
  const disabled = createRuntimeDiagnostics({ directory: 'relative', clock: () => { throw new Error('private clock error'); } });
  try {
    assert.equal(await disabled.step('terminal.write', async () => 7), 7);
    assert.equal(await disabled.flush(), false);
    assert.equal(disabled.snapshot().elapsedMs, 0);
  } finally { disabled.close(); }
});
