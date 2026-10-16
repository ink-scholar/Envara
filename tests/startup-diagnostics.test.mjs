import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { chmod, mkdtemp, mkdir, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { createStartupDiagnostics } from '../electron/startup-diagnostics.mjs';

async function fixture(t) {
  const directory = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-startup-diagnostics-')));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, root: path.join(directory, 'startup-diagnostics'), last: path.join(directory, 'startup-diagnostics/last-startup.json'),
    previous: path.join(directory, 'startup-diagnostics/previous-startup.json') };
}
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('an awaited stage is persisted as started before completion and preserves the operation result', async t => {
  const f = await fixture(t), gate = deferred();
  let tick = 100;
  const diagnostics = createStartupDiagnostics({ directory: f.directory, version: '0.5.18', clock: () => tick, wallClock: () => 1700000000000, entryUptimeMs: 1200 });
  tick = 110;
  const operation = diagnostics.step('sidecar.initialize', () => gate.promise);
  assert.equal(await diagnostics.flush(), true);
  const pending = JSON.parse(await readFile(f.last, 'utf8'));
  assert.deepEqual(pending, { version: '0.5.18', startedAtMs: 1700000000000, entryUptimeMs: 1200, totalMs: 10,
    stages: [{ name: 'sidecar.initialize', status: 'started', startedMs: 10, durationMs: 0 }] });
  tick = 135; gate.resolve('ready');
  assert.equal(await operation, 'ready');
  assert.equal(await diagnostics.flush(), true);
  const completed = JSON.parse(await readFile(f.last, 'utf8'));
  assert.deepEqual(completed.stages, [{ name: 'sidecar.initialize', status: 'completed', startedMs: 10, durationMs: 25 }]);
  assert.equal(completed.entryUptimeMs, 1200);
  if (process.platform !== 'win32') {
    assert.equal((await stat(f.root)).mode & 0o777, 0o700);
    assert.equal((await stat(f.last)).mode & 0o777, 0o600);
  }
});

test('stable error codes and marks never retain errors, paths or mutable caller data', async t => {
  const f = await fixture(t);
  const diagnostics = createStartupDiagnostics({ directory: f.directory, version: '0.5.18' });
  const failure = Object.assign(new Error('private password and /Users/private/profile'), { code: 'SIDECAR_UNAVAILABLE', path: '/private/user-data' });
  await assert.rejects(diagnostics.step('sidecar.initialize', async () => { throw failure; }), value => value === failure);
  const raw = Object.assign(new Error('private raw failure'), { code: 'https://private-token.example' });
  await assert.rejects(diagnostics.step('window.load', async () => { throw raw; }), value => value === raw);
  const accessor = new Error('private getter'); Object.defineProperty(accessor, 'code', { get() { throw new Error('private code getter'); } });
  await assert.rejects(diagnostics.step('window.ready', async () => { throw accessor; }), value => value === accessor);
  assert.equal(diagnostics.mark('ipc.ready'), true);
  assert.equal(diagnostics.fail('STARTUP_FAILED'), true);
  assert.equal(diagnostics.fail('private code/path'), false);
  const copy = diagnostics.snapshot(); copy.stages[0].name = 'private-mutation';
  assert.equal(await diagnostics.flush(), true);
  const text = await readFile(f.last, 'utf8');
  assert.doesNotMatch(text, /password|Users|private|profile|raw failure|getter|https:|path|message|stack/);
  const result = JSON.parse(text);
  assert.equal(result.code, 'STARTUP_FAILED');
  assert.equal(result.stages[0].code, 'SIDECAR_UNAVAILABLE');
  assert.equal(result.stages[1].code, undefined);
  assert.equal(result.stages[3].status, 'completed');
});

test('stage names, stage count and version are bounded without stopping unrecorded business operations', async t => {
  const f = await fixture(t);
  const diagnostics = createStartupDiagnostics({ directory: f.directory, version: 'https://private-version.example' });
  for (const name of ['UpperCase', 'raw/path', 'secret value', 'a'.repeat(65), null]) assert.equal(diagnostics.mark(name), false);
  for (let index = 0; index < 34; index++) diagnostics.mark(`stage-${index}`);
  assert.equal(await diagnostics.step('another.stage', async () => 42), 42);
  assert.equal(diagnostics.snapshot().stages.length, 32);
  assert.equal(diagnostics.snapshot().version, 'unknown');
  assert.equal(await diagnostics.flush(), true);
  assert.doesNotMatch(await readFile(f.last, 'utf8'), /private-version|another\.stage/);
});

test('each instance rotates the previous startup once and retains exactly two completed receipts', async t => {
  const f = await fixture(t);
  const first = createStartupDiagnostics({ directory: f.directory, version: '0.5.18' });
  first.mark('first.ready'); await first.flush();
  if (process.platform !== 'win32') await chmod(f.last, 0o644);
  const second = createStartupDiagnostics({ directory: f.directory, version: '0.5.19' });
  assert.equal(JSON.parse(await readFile(f.last, 'utf8')).version, '0.5.18', 'construction alone performs no filesystem mutation');
  second.mark('second.ready'); await second.flush();
  second.mark('second.window'); await second.flush();
  assert.equal(JSON.parse(await readFile(f.previous, 'utf8')).version, '0.5.18');
  if (process.platform !== 'win32') assert.equal((await stat(f.previous)).mode & 0o777, 0o600);
  const third = createStartupDiagnostics({ directory: f.directory, version: '0.5.20' });
  third.mark('third.ready'); await third.flush();
  assert.equal(JSON.parse(await readFile(f.last, 'utf8')).version, '0.5.20');
  assert.equal(JSON.parse(await readFile(f.previous, 'utf8')).version, '0.5.19');
  assert.deepEqual((await readdir(f.root)).sort(), ['last-startup.json', 'previous-startup.json']);
});

test('concurrent flushes remain serialized while stalled disk I/O cannot delay a stage or an explicit flush indefinitely', async t => {
  const f = await fixture(t), gate = deferred(), entered = deferred();
  const originalOpen = fsPromises.open;
  let active = 0, maximum = 0, first = true;
  t.mock.method(fsPromises, 'open', async (filename, ...args) => {
    if (typeof filename !== 'string' || !filename.startsWith(f.root + path.sep)) return originalOpen(filename, ...args);
    active++; maximum = Math.max(maximum, active);
    if (first) { first = false; entered.resolve(); await gate.promise; }
    try { return await originalOpen(filename, ...args); } finally { active--; }
  });
  syncBuiltinESMExports();
  const diagnostics = createStartupDiagnostics({ directory: f.directory, version: '0.5.18' });
  try {
    assert.equal(await diagnostics.step('app.ready', async () => 'business-ready'), 'business-ready');
    await entered.promise;
    const queued = [diagnostics.flush(), diagnostics.flush()];
    const at = performance.now();
    assert.deepEqual(await Promise.all(queued), [false, false]);
    assert.ok(performance.now() - at < 1000);
    assert.equal(maximum, 1);
    gate.resolve();
    assert.equal(await diagnostics.flush(), true);
    assert.equal(JSON.parse(await readFile(f.last, 'utf8')).stages[0].status, 'completed');
  } finally { gate.resolve(); t.mock.restoreAll(); syncBuiltinESMExports(); }
});

test('storage failures and linked diagnostic directories fail soft without touching their targets', async t => {
  const f = await fixture(t);
  const target = path.join(f.directory, 'other'); await mkdir(target);
  await writeFile(path.join(target, 'keep'), 'untouched');
  await symlink(target, f.root, process.platform === 'win32' ? 'junction' : 'dir');
  const diagnostics = createStartupDiagnostics({ directory: f.directory, version: '0.5.18' });
  assert.equal(await diagnostics.step('app.ready', async () => 42), 42);
  assert.equal(await diagnostics.flush(), false);
  assert.deepEqual(await readdir(target), ['keep']);
  assert.equal(await readFile(path.join(target, 'keep'), 'utf8'), 'untouched');
  const invalid = createStartupDiagnostics({ directory: 'not-an-absolute-path', version: '0.5.18' });
  assert.equal(await invalid.step('app.ready', async () => 7), 7);
  assert.equal(await invalid.flush(), false);
});
