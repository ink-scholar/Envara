import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, stat, writeFile, readFile, realpath, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { waitForApplicationUpdateStartup } from '../electron/application-update-startup.mjs';
import { createDesktopStartup } from '../electron/desktop-startup.mjs';
const macOSFeature = process.platform !== 'darwin' && 'macOS-only feature';

const status = active => ({ active });
const pending = () => ({ stageRoot: '/synthetic/application-updates/update-abcdef', version: '1.2.4', originatingPid: 12345, outcome: 'pending', error: null, receipt: null });
const installed = () => ({ ...pending(), receipt: { type: 'installed', version: '1.2.4', relaunch: 'requested' } });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('a normal startup with no installation marker initializes without a process scan', async () => {
  assert.deepEqual(await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', readInstallation: async () => null,
    inspectInstaller: () => assert.fail('no marker should require no native scan') }), { status: 'ready', result: 'none' });
});

test('an old loaded entry yields immediately to a live installer or originating parent without creating owned services', async () => {
  const calls = [];
  const startup = createDesktopStartup({ initialize: async ({ checkOpen }) => {
    const decision = await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', checkOpen,
      readInstallation: async () => pending(), inspectInstaller: async input => { calls.push(input); return status(true); },
      wait: () => assert.fail('an old entry must exit instead of holding the single-instance lock') });
    if (decision.status !== 'ready') return decision;
    calls.push('allocate-services');
  } });
  assert.deepEqual(await startup.start(), { status: 'defer-to-installer', version: '1.2.4' });
  assert.deepEqual(calls, [{ stageRoot: pending().stageRoot, originatingPid: 12345 }]);
});

test('the newly loaded version waits for the atomic final receipt before initializing owned services', async () => {
  let record = pending(), elapsed = 0, scans = 0; const calls = [];
  const startup = createDesktopStartup({ initialize: async ({ checkOpen }) => {
    const result = await waitForApplicationUpdateStartup({ currentVersion: '1.2.4', checkOpen, now: () => elapsed,
      readInstallation: async () => record, inspectInstaller: async () => { scans++; return status(true); },
      wait: async ms => { calls.push('wait'); elapsed += ms; record = installed(); } });
    assert.equal(result.status, 'ready'); calls.push('allocate-services'); return result;
  } });
  assert.deepEqual(await startup.start(), { status: 'ready', result: 'installed', version: '1.2.4' });
  assert.equal(scans, 1); assert.deepEqual(calls, ['wait', 'allocate-services']);
});

test('a final installed receipt cannot let an already-loaded old version initialize', async () => {
  const result = await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', readInstallation: async () => installed(),
    inspectInstaller: () => assert.fail('atomic completion does not need a live process scan') });
  assert.deepEqual(result, { status: 'restart-required', version: '1.2.4' });
});

test('retained receipts allow equal and newer manual installs without a relaunch loop, comparing version segments numerically', async t => {
  for (const [currentVersion, installedVersion, expected] of [
    ['1.2.4', '1.2.4', 'ready'], ['1.2.5', '1.2.4', 'ready'],
    ['1.10.0', '1.9.9', 'ready'], ['2.0.0', '1.99.99', 'ready'],
    ['1.2.10', '1.2.9', 'ready'], ['1.9.9', '1.10.0', 'restart-required'],
    ['1.2.9', '1.2.10', 'restart-required'], ['1.99.99', '2.0.0', 'restart-required'],
  ]) await t.test(`${currentVersion} after ${installedVersion}`, async () => {
    let allocated = false;
    const record = { ...installed(), version: installedVersion,
      receipt: { ...installed().receipt, version: installedVersion } };
    const startup = createDesktopStartup({ initialize: async ({ checkOpen }) => {
      const decision = await waitForApplicationUpdateStartup({ currentVersion, checkOpen, readInstallation: async () => record,
        inspectInstaller: () => assert.fail('a final installed receipt needs no process scan') });
      if (decision.status === 'ready') allocated = true;
      return decision;
    } });
    assert.equal((await startup.start()).status, expected);
    assert.equal(allocated, expected === 'ready');
  });
});

test('a helper that exits while publishing its receipt is re-read before an old entry is admitted', async () => {
  let reads = 0;
  const result = await waitForApplicationUpdateStartup({ currentVersion: '1.2.3',
    readInstallation: async () => ++reads === 1 ? pending() : installed(), inspectInstaller: async () => status(false) });
  assert.equal(reads, 2); assert.deepEqual(result, { status: 'restart-required', version: '1.2.4' });
});

test('a confirmed absent helper and originating parent permit an abandoned preparation without deleting its history', async () => {
  const record = pending();
  const result = await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', readInstallation: async () => record,
    inspectInstaller: async () => status(false) });
  assert.deepEqual(result, { status: 'ready', result: 'abandoned', version: '1.2.4' });
  assert.deepEqual(record, pending());
});

test('a failed pointer alone does not prove a still-running helper has completed', async () => {
  const result = await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', readInstallation: async () => ({ ...pending(), outcome: 'failed', error: 'APP_UPDATE_HELPER' }),
    inspectInstaller: async () => status(true) });
  assert.equal(result.status, 'defer-to-installer');
});

test('validated terminal failure receipts and removed failed preparation permit normal startup', async t => {
  for (const record of [{ ...pending(), receipt: { type: 'failed', code: 'APP_UPDATE_PACKAGE', committed: true, replaced: false } },
    { ...pending(), receipt: { type: 'failed', code: 'APP_UPDATE_ROLLED_BACK', committed: true, replaced: false } },
    { ...pending(), stageRoot: null, outcome: 'failed', error: 'APP_UPDATE_PREPARE_FAILED' }]) await t.test(JSON.stringify(record.receipt?.type ?? 'removed'), async () => {
    assert.deepEqual(await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', readInstallation: async () => record,
      inspectInstaller: () => assert.fail('final receipt cannot perform another replacement') }), { status: 'ready', result: 'failed', version: '1.2.4' });
  });
});

test('failed receipts with unconfirmed restoration or cleanup never initialize owned services', async t => {
  for (const [fields, code] of [
    [{ code: 'APP_UPDATE_PACKAGE', replaced: true }, 'APP_UPDATE_ROLLBACK_FAILED'],
    [{ code: 'APP_UPDATE_ROLLBACK_UNCERTAIN' }, 'APP_UPDATE_ROLLBACK_FAILED'],
    [{ code: 'APP_UPDATE_ROLLBACK_FAILED' }, 'APP_UPDATE_ROLLBACK_FAILED'],
    [{ code: 'APP_UPDATE_CLEANUP_UNCERTAIN' }, 'APP_UPDATE_CLEANUP'],
    [{ code: 'APP_UPDATE_CLEANUP' }, 'APP_UPDATE_CLEANUP'],
    [{ cleanupCode: 'APP_UPDATE_CLEANUP_UNCERTAIN' }, 'APP_UPDATE_CLEANUP'],
    [{ replaced: undefined }, 'APP_UPDATE_PROTOCOL'],
    [{ committed: undefined }, 'APP_UPDATE_PROTOCOL'],
  ]) await t.test(JSON.stringify(fields), async () => {
    let allocated = false;
    const startup = createDesktopStartup({ initialize: async ({ checkOpen }) => {
      await waitForApplicationUpdateStartup({ currentVersion: '1.2.3', checkOpen,
        readInstallation: async () => ({ ...pending(), receipt: { type: 'failed', code: 'APP_UPDATE_PACKAGE', committed: true, replaced: false, ...fields } }),
        inspectInstaller: () => assert.fail('a receipt cannot erase uncertain replacement evidence') });
      allocated = true;
    } });
    await assert.rejects(startup.start(), { code });
    assert.equal(allocated, false);
  });
});

test('unknown process state, malformed evidence and an expired wait never initialize owned services', async t => {
  const cases = {
    unknown: { inspectInstaller: async () => { throw new Error('/private/path and secret'); }, code: 'APP_UPDATE_PARENT' },
    malformed: { inspectInstaller: async () => ({ active: 'false' }), code: 'APP_UPDATE_PROTOCOL' },
    extraField: { inspectInstaller: async () => ({ ...status(false), path: 'private' }), code: 'APP_UPDATE_PROTOCOL' },
    markerRead: { readInstallation: async () => { throw new Error('private metadata'); }, code: 'APP_UPDATE_PROTOCOL' },
    missingOrigin: { readInstallation: async () => ({ ...pending(), originatingPid: undefined }), code: 'APP_UPDATE_PROTOCOL' },
    missingPendingStage: { readInstallation: async () => ({ ...pending(), stageRoot: null }), code: 'APP_UPDATE_PROTOCOL' },
    timeout: { code: 'APP_UPDATE_TIMEOUT' },
  };
  for (const [name, overrides] of Object.entries(cases)) await t.test(name, async () => {
    let elapsed = 0, allocated = false;
    const startup = createDesktopStartup({ initialize: async () => {
      await waitForApplicationUpdateStartup({ currentVersion: '1.2.4', readInstallation: async () => pending(), inspectInstaller: async () => status(true),
        timeoutMs: 3, intervalMs: 1, now: () => elapsed, wait: async ms => { elapsed += ms; }, ...overrides });
      allocated = true;
    } });
    await assert.rejects(startup.start(), error => { assert.equal(error.code, overrides.code); assert.doesNotMatch(error.message, /private|secret/); return true; });
    assert.equal(allocated, false);
  });
});

test('shutdown during a native scan aborts startup even when that scan later reports no installer', async () => {
  const hold = deferred(); let scanned = false, allocated = false;
  const startup = createDesktopStartup({ initialize: async ({ checkOpen }) => {
    await waitForApplicationUpdateStartup({ currentVersion: '1.2.4', checkOpen, readInstallation: async () => pending(),
      inspectInstaller: () => { scanned = true; return hold.promise; } });
    allocated = true;
  } });
  const result = startup.start();
  while (!scanned) await new Promise(resolve => setImmediate(resolve));
  const closing = startup.close(); hold.resolve(status(false));
  await assert.rejects(result, { code: 'APP_CLOSING' }); await closing; assert.equal(allocated, false);
});

test('a replaced or disappearing marker during the wait does not open startup admission', async t => {
  for (const replacement of [null, { ...pending(), stageRoot: '/different-stage' }, { ...pending(), originatingPid: 999 }]) await t.test(String(replacement?.stageRoot), async () => {
    let record = pending(), elapsed = 0;
    await assert.rejects(waitForApplicationUpdateStartup({ currentVersion: '1.2.4', readInstallation: async () => record,
      inspectInstaller: async () => status(true), now: () => elapsed,
      wait: async ms => { elapsed += ms; record = replacement; } }), { code: 'APP_UPDATE_PROTOCOL' });
  });
});

test('production private-marker reading and abandoned inspection leave synthetic configuration and staging byte-for-byte intact', { skip: macOSFeature }, async t => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-update-startup-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stageRoot = path.join(root, 'update-abcdef'); await mkdir(stageRoot, { mode: 0o700 });
  const identity = await stat(stageRoot), filename = path.join(root, 'last-installation.json');
  const pointer = JSON.stringify({ schema: 'envara.app-update/v1', stageName: 'update-abcdef', version: '1.2.4',
    stageDev: String(identity.dev), stageIno: String(identity.ino), originatingPid: 12345, outcome: 'pending' });
  await writeFile(filename, pointer, { mode: 0o600 });
  const config = path.join(root, 'synthetic-account'); await writeFile(config, 'retained synthetic account', { mode: 0o600 });
  const result = await waitForApplicationUpdateStartup({ cacheDir: root, currentVersion: '1.2.3', inspectInstaller: async args => {
    assert.deepEqual(args, { stageRoot, originatingPid: 12345 }); return status(false);
  } });
  assert.equal(result.result, 'abandoned');
  assert.equal(await readFile(filename, 'utf8'), pointer); assert.equal(await readFile(config, 'utf8'), 'retained synthetic account');
  assert.equal((await stat(stageRoot)).ino, identity.ino);
});
