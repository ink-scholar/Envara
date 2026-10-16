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
