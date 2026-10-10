import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, stat, symlink, rm, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { NotionDiagnosticsStore } from '../electron/notion-diagnostics-store.mjs';
const runId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const environmentId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const record = { applicationId: 'app_fixture', runId, environmentId, phase: 'cleanup-required', active: false,
  initialFailure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native: { stage: 'guardian', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } },
  cleanupFailure: { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' },
  events: [{ sequence: 1, stage: 'failed', code: 'APPLICATION_APP_NATIVE_REFUSED', nativeStage: 'guardian', nativeReason: 'NATIVE_OPERATION_REFUSED', errno: 13 }],
  message: 'private-token-fixture', route: { password: 'private-token-fixture' }, path: '/private/fixture' };

test('persisted diagnostic survives restart without private input or routing authority', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-diagnostics-')));
  try {
    const directory = path.join(root, 'history');
    const first = new NotionDiagnosticsStore(directory);
    await first.save(record);
    const file = path.join(directory, 'app_fixture.json');
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    assert.equal((await readFile(file, 'utf8')).includes('private-token-fixture'), false);
    const restarted = new NotionDiagnosticsStore(directory);
    const history = await restarted.read('app_fixture');
    assert.deepEqual(history.initialFailure, record.initialFailure);
    assert.deepEqual(history.cleanupFailure, record.cleanupFailure);
    assert.equal(history.diagnosticOnly, true);
    assert.equal(history.ready, false);
    assert.equal(history.protected, false);
    assert.equal(await restarted.read('../fixture'), null);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('serialized updates remain readable and symlink history is rejected', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-diagnostics-')));
  try {
    const store = new NotionDiagnosticsStore(path.join(root, 'history'));
    await Promise.all([store.save(record), store.save({ ...record, phase: 'cleaned', cleanupComplete: true, cleanupUncertain: false })]);
    assert.equal((await store.read('app_fixture')).phase, 'cleaned');
    await symlink(path.join(root, 'history'), path.join(root, 'link'));
    await assert.rejects(new NotionDiagnosticsStore(path.join(root, 'link')).save(record));
    await assert.rejects(store.save({ ...record, runId: 'invalid' }));
  } finally { await rm(root, { recursive: true, force: true }); }
});
