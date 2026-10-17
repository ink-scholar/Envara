import test from 'node:test';
import assert from 'node:assert/strict';
import { completeWorkspaceOperation } from '../src/workspace-operation.mjs';

test('a completed export is still successful if only the following snapshot refresh fails', async () => {
  let executions = 0, refreshes = 0;
  const saved = { canceled: false, count: 1 };
  const outcome = await completeWorkspaceOperation({
    execute: async () => { executions++; return saved; }, acceptSnapshot: () => false,
    refresh: async () => { refreshes++; throw new Error('snapshot unavailable'); },
  });
  assert.deepEqual(outcome, { result: saved, refreshFailed: true });
  assert.equal(executions, 1); assert.equal(refreshes, 1, 'no action replay or automatic retry');
});

test('primary action failures still reject without refreshing or replaying the action', async () => {
  let executions = 0, refreshes = 0;
  const failure = new Error('operation refused');
  await assert.rejects(completeWorkspaceOperation({
    execute: async () => { executions++; throw failure; }, acceptSnapshot: () => false,
    refresh: async () => { refreshes++; },
  }), error => error === failure);
  assert.equal(executions, 1); assert.equal(refreshes, 0);
});

test('cancellation and pending import password/mapping stages do not need an unrelated refresh', async () => {
  for (const result of [{ canceled: true }, { needsPassword: true, importId: 'import_a' }, { needsProxyMapping: true, importId: 'import_a' }]) {
    let refreshes = 0;
    assert.deepEqual(await completeWorkspaceOperation({ execute: async () => result, acceptSnapshot: () => false,
      refresh: async () => { refreshes++; throw new Error('unrelated failure'); } }), { result, refreshFailed: false });
    assert.equal(refreshes, 0);
  }
});

test('a returned complete snapshot is applied without requesting a second snapshot', async () => {
  const result = { profiles: [], proxies: [], settings: {}, system: { platform: 'darwin' } };
  let applied = null, refreshes = 0;
  const outcome = await completeWorkspaceOperation({ execute: async () => result,
    acceptSnapshot: value => { applied = value; return true; }, refresh: async () => { refreshes++; } });
  assert.equal(applied, result); assert.equal(refreshes, 0);
  assert.deepEqual(outcome, { result, refreshFailed: false });
});

test('ordinary metadata responses still trigger one best-effort state update', async () => {
  let refreshes = 0;
  const result = { ok: true };
  const outcome = await completeWorkspaceOperation({ execute: async () => result, acceptSnapshot: () => false,
    refresh: async () => { refreshes++; return { profiles: [] }; } });
  assert.equal(refreshes, 1); assert.deepEqual(outcome, { result, refreshFailed: false });
});

test('a completed attached run is applied without a second full refresh that can leave it starting forever', async () => {
  const { applyNotionTrialOperationResult, notionTrialControls, attachedApplicationStatus } = await import('../src/notion-trial-state.mjs');
  const result = { applicationId: 'attached-code', runId: 'bb756095-daf2-4137-b7e6-f8714b0c9ad0', environmentId: '76e164dd-3827-4746-9e5d-43ae1f4219de',
    phase: 'cleaned', active: false, cleanupComplete: true, cleanupUncertain: false, errorCode: 'APPLICATION_APP_NATIVE_REFUSED',
    initialFailure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED' } };
  for (const refresh of [() => new Promise(() => {}), async () => { throw new Error('unrelated workspace read failed'); }]) {
    let snapshot = { profiles: [], proxies: [], system: {}, applications: [{ id: 'attached-code', identity: 'fixture-code', notionTrial: { ...result, active: true, phase: 'preparing' } }] };
    let pending = true, refreshes = 0;
    const operation = completeWorkspaceOperation({ execute: async () => result,
      acceptSnapshot: value => {
        const next = applyNotionTrialOperationResult(snapshot, value, { method: 'runNotionTrial', applicationId: result.applicationId });
        if (!next) return false; snapshot = next; return true;
      }, refresh: () => { refreshes++; return refresh(); } }).finally(() => { pending = false; });
    let timer;
    const outcome = await Promise.race([operation, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('completed trial waited for an unrelated refresh')), 100); })]).finally(() => clearTimeout(timer));
    assert.equal(outcome.result, result); assert.equal(refreshes, 0); assert.equal(pending, false);
    assert.equal(attachedApplicationStatus(notionTrialControls(snapshot.applications[0], { controlledNotionTrialAvailable: true }, true,
      pending ? { 'runNotionTrial:attached-code': true } : {})), 'stopped');
    assert.deepEqual(snapshot.applications[0].notionTrial.initialFailure, result.initialFailure);
  }
});
