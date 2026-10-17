import test from 'node:test';
import assert from 'node:assert/strict';
import { finishEnvironmentDeletion } from '../electron/environment-deletion-cleanup.mjs';
import { completeWorkspaceOperation, workspaceOperationWarning } from '../src/workspace-operation.mjs';

test('data cleanup failure keeps the completed deletion snapshot and pending import custody', async () => {
  const snapshot = { profiles: [], proxies: [], system: {} }, released = [];
  const result = await finishEnvironmentDeletion({ method: 'deleteProfile', args: { id: 'deleted' }, result: snapshot,
    eraseData: async () => { throw Object.assign(new Error('private filesystem detail'), { code: 'EACCES' }); },
    releaseImport: id => released.push(id) });
  assert.equal(result.profiles, snapshot.profiles);
  assert.deepEqual(result.warnings, [{ code: 'ENVIRONMENT_APPLICATION_CLEANUP_INCOMPLETE', profileId: 'deleted' }]);
  assert.deepEqual(released, []);
  assert.doesNotMatch(JSON.stringify(result), /private filesystem detail|EACCES/);
  let actions = 0, accepted = 0;
  const outcome = await completeWorkspaceOperation({ execute: async () => { actions++; return result; },
    acceptSnapshot: value => { assert.equal(value, result); accepted++; return true; },
    refresh: () => { throw new Error('already received the committed snapshot'); } });
  assert.equal(actions, 1); assert.equal(accepted, 1); assert.equal(outcome.refreshFailed, false);
  assert.match(workspaceOperationWarning(outcome.result), /环境已删除.*未清理完成/);
});

test('bulk finalization handles only successful deletions and continues past cleanup failures', async () => {
  const removed = [], erased = [], released = [];
  const snapshot = { profiles: [{ id: 'kept' }], actionResult: { results: [
    { id: 'a', ok: true }, { id: 'kept', ok: false }, { id: 'b', ok: true }, { id: 'c', ok: true },
  ] } };
  const result = await finishEnvironmentDeletion({ method: 'bulkProfiles', args: { action: 'delete' }, result: snapshot,
    applications: { snapshot: async () => ({ applications: ['a', 'b', 'kept'].map(profileId => ({ id: `app_${profileId}`, profileId })) }),
      deleteApplication: async ({ id }) => { removed.push(id); if (id === 'app_a') throw new Error('still owned'); } },
    eraseData: async id => { erased.push(id); if (id === 'b') throw new Error('cleanup incomplete'); },
    releaseImport: id => released.push(id) });
  assert.deepEqual(removed, ['app_a', 'app_b']);
  assert.deepEqual(erased, ['b', 'c']);
  assert.deepEqual(released, ['c']);
  assert.deepEqual(result.warnings.map(item => item.profileId), ['a', 'b']);
  assert.equal(result.actionResult, snapshot.actionResult);
});

test('failed binding inventory reports all deleted profiles and preserves data', async () => {
  const result = await finishEnvironmentDeletion({ method: 'deleteProfile', args: { id: 'a' }, result: { profiles: [] },
    applications: { snapshot: async () => { throw new Error('inventory unavailable'); } },
    eraseData: () => assert.fail('cannot establish whether app still owns data'), releaseImport: () => assert.fail('retain custody') });
  assert.equal(result.warnings[0].profileId, 'a');
});

test('successful cleanup releases import custody and unrelated methods remain unchanged', async () => {
  const result = { profiles: [] }, calls = [];
  const options = { args: { id: 'a' }, result, eraseData: async id => calls.push(`erase:${id}`), releaseImport: id => calls.push(`release:${id}`) };
  assert.equal(await finishEnvironmentDeletion({ ...options, method: 'updateProfile' }), result);
  assert.deepEqual(calls, []);
  assert.equal(await finishEnvironmentDeletion({ ...options, method: 'deleteProfile' }), result);
  assert.deepEqual(calls, ['erase:a', 'release:a']);
  assert.equal(workspaceOperationWarning(result), null);
});
