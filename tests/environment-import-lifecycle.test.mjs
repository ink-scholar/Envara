import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { DesktopEnvironmentTransferLock, environmentMutationProfile, discardPendingEnvironmentImport, expirePendingEnvironmentImports, finishPendingEnvironmentImport, releaseDeletedEnvironmentImportProfile,
  isEnvironmentDataMutation, makePendingImportRoom, registerPendingEnvironmentImport, withPendingEnvironmentImport } from '../electron/environment-import-lifecycle.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('an idle environment can export while another environment runs, but its own starts and global changes stay excluded', async () => {
  const lock = new DesktopEnvironmentTransferLock(), running = deferred(), copying = deferred();
  const other = lock.mutate('startApplication', {}, () => running.promise, 'prof_other');
  const transfer = lock.transfer(() => copying.promise, 'prof_export');
  await assert.rejects(lock.mutate('openTerminal', {}, async () => {}, 'prof_export'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  await assert.rejects(lock.mutate('saveProxy', {}, async () => {}), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.equal(await lock.mutate('writeTerminal', {}, async () => 'other remains usable', 'prof_other'), 'other remains usable');
  copying.resolve(); await transfer;
  await assert.rejects(lock.transfer(async () => {}, 'prof_other'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  await assert.rejects(lock.transfer(async () => {}), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  running.resolve(); await other;
  assert.equal(await lock.transfer(async () => 'done'), 'done');
});

test('IPC mutation scopes for applications and terminals come from main-owned bindings', () => {
  const owned = { applications: { applications: new Map([['app_1', { profileId: 'prof_app' }]]) },
    terminal: { sessions: new Map([['session_1', { profileId: 'prof_terminal' }]]) } };
  assert.equal(environmentMutationProfile('startApplication', { id: 'app_1', profileId: 'forged' }, owned), 'prof_app');
  assert.equal(environmentMutationProfile('runNotionTrial', { applicationId: 'app_1', id: 'forged' }, owned), 'prof_app');
  assert.equal(environmentMutationProfile('writeTerminal', { sessionId: 'session_1', id: 'forged' }, owned), 'prof_terminal');
  assert.equal(environmentMutationProfile('openTerminal', { id: 'prof_selected' }, owned), 'prof_selected');
  assert.equal(environmentMutationProfile('deleteClaudeAccount', { id: 'prof_selected', profileId: 'forged' }, owned), 'prof_selected');
  assert.equal(environmentMutationProfile('saveProxy', { id: 'prof_selected' }, owned), null);
  assert.equal(environmentMutationProfile('startApplication', { id: 'unknown', profileId: 'forged' }, owned), null);
});

test('account deletion excludes a same-environment export or import while other environments remain available', async () => {
  const lock = new DesktopEnvironmentTransferLock(), gate = deferred();
  assert.equal(isEnvironmentDataMutation('deleteClaudeAccount'), true);
  const transfer = lock.transfer(() => gate.promise, 'env_one');
  await assert.rejects(lock.mutate('deleteClaudeAccount', {}, async () => assert.fail('must not delete during transfer'), 'env_one'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.equal(await lock.mutate('deleteClaudeAccount', {}, async () => 'other allowed', 'env_two'), 'other allowed');
  gate.resolve(); await transfer;
  const deletionGate = deferred();
  const deletion = lock.mutate('deleteClaudeAccount', {}, () => deletionGate.promise, 'env_one');
  await assert.rejects(lock.transfer(async () => assert.fail('must not copy during deletion'), 'env_one'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  deletionGate.resolve(); await deletion;
  assert.equal(await lock.transfer(async () => 'ready', 'env_one'), 'ready');
});

test('SSH configuration changes respect environment transfer locks while read-only selection remains available', async () => {
  const lock = new DesktopEnvironmentTransferLock(), gate = deferred();
  const transfer = lock.transfer(() => gate.promise, 'env_one');
  for (const method of ['saveTerminalSshConnection', 'removeTerminalSshConnection']) {
    assert.equal(isEnvironmentDataMutation(method), true);
    assert.equal(environmentMutationProfile(method, { id: 'env_one' }), 'env_one');
    await assert.rejects(lock.mutate(method, {}, async () => assert.fail('configuration must not change during transfer'), 'env_one'), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
    assert.equal(await lock.mutate(method, {}, async () => 'other allowed', 'env_two'), 'other allowed');
  }
  for (const method of ['listTerminalSshConnections', 'prepareTerminalSshIdentity']) {
    assert.equal(isEnvironmentDataMutation(method), false);
    assert.equal(await lock.mutate(method, {}, async () => 'metadata only', 'env_one'), 'metadata only');
  }
  gate.resolve(); await transfer;
});
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-import-lifecycle-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const staging = path.join(root, 'staging'); await mkdir(staging);
  await writeFile(path.join(staging, 'login'), 'exported sign-in data');
  const pending = { createdAt: 1, document: { profiles: [{ name: 'Imported' }] }, bundle: { staging, manifest: {} } };
  const imports = new Map([['import-1', pending]]), calls = [], profiles = new Map();
  let sequence = 0;
  const service = { async call(method, args) {
    calls.push({ method, args });
    if (method === 'importProfiles') {
      const id = `prof_${++sequence}`; profiles.set(id, { id });
      return { profiles: [...profiles.values()], actionResult: { createdIds: [id] } };
    }
    if (method === 'deleteProfile') { profiles.delete(args.id); return { profiles: [...profiles.values()] }; }
    throw new Error('Unexpected method');
  } };
  const discard = (importId = 'import-1', options = {}) => discardPendingEnvironmentImport({ imports, importId,
    removeStaging: target => rm(target, { recursive: true, force: true }), ...options });
  const finish = (restore, extra = {}) => withPendingEnvironmentImport(pending, () => finishPendingEnvironmentImport({ pending,
    service, restore, discard: () => discard('import-1', { completed: true }), ...extra }));
  return { root, staging, pending, imports, calls, profiles, service, discard, finish };
}

test('successful import restores the backend-created environment and then removes staging', async t => {
  const f = await fixture(t);
  const result = await f.finish(async id => {
    assert.equal(id, 'prof_1'); assert.equal(await readFile(path.join(f.staging, 'login'), 'utf8'), 'exported sign-in data');
    assert.equal(f.imports.has('import-1'), true);
    return { browser: true, terminal: true, applications: [] };
  });
  assert.equal(result.restored.terminal, true);
  assert.deepEqual([...f.profiles.keys()], ['prof_1']);
  assert.equal(f.pending.busy, false); assert.equal(f.imports.size, 0);
  await assert.rejects(access(f.staging), { code: 'ENOENT' });
});

test('failed restoration rolls back only the newly created environment and preserves retry data', async t => {
  const f = await fixture(t); f.profiles.set('existing', { id: 'existing' });
  await assert.rejects(f.finish(async () => { throw Object.assign(new Error('private token and local path'), { code: 'EIO' }); }), error => {
    assert.equal(error.code, 'IMPORT_RESTORE_FAILED'); assert.equal(error.message.includes('private'), false); return true;
  });
  assert.deepEqual([...f.profiles.keys()], ['existing']);
  assert.deepEqual(f.calls.map(item => [item.method, item.args.id]), [['importProfiles', undefined], ['deleteProfile', 'prof_1']]);
  assert.equal(f.imports.get('import-1'), f.pending); assert.equal(f.pending.createdResult, undefined);
  assert.equal(await readFile(path.join(f.staging, 'login'), 'utf8'), 'exported sign-in data');
  const result = await f.finish(async id => ({ importedProfile: id }));
  assert.equal(result.restored.importedProfile, 'prof_2');
  assert.deepEqual([...f.profiles.keys()], ['existing', 'prof_2']);
});

test('failed rollback keeps the exact created profile for retry instead of creating another', async t => {
  const f = await fixture(t), call = f.service.call;
  f.service.call = async (method, args) => { if (method === 'deleteProfile') throw new Error('private backend detail'); return call(method, args); };
  await assert.rejects(f.finish(async () => { throw new Error('restore failed'); }), { code: 'IMPORT_ROLLBACK_INCOMPLETE' });
  assert.deepEqual(f.pending.createdResult.actionResult.createdIds, ['prof_1']);
  await assert.rejects(f.discard(), { code: 'IMPORT_ROLLBACK_INCOMPLETE' });
  assert.equal(f.imports.size, 1); await access(f.staging);
  const result = await f.finish(async id => ({ importedProfile: id }));
  assert.equal(result.restored.importedProfile, 'prof_1');
  assert.equal(f.calls.filter(item => item.method === 'importProfiles').length, 1);
});

test('a later failed retry never deletes a retained environment with newly added user data', async t => {
  const f = await fixture(t), call = f.service.call;
  let firstRollback = true;
  f.service.call = async (method, args) => {
    if (method === 'deleteProfile' && firstRollback) { firstRollback = false; throw new Error('temporary rollback failure'); }
    return call(method, args);
  };
  await assert.rejects(f.finish(async () => { throw new Error('first restore failed'); }), { code: 'IMPORT_ROLLBACK_INCOMPLETE' });
  const retained = f.profiles.get('prof_1');
  retained.userData = 'newly created after the earlier attempt';
  await assert.rejects(f.finish(async () => { throw Object.assign(new Error('new data conflicts with staged data'), { code: 'IMPORT_TARGET_NOT_EMPTY' }); }), { code: 'IMPORT_ROLLBACK_INCOMPLETE' });
  assert.equal(f.profiles.get('prof_1'), retained);
  assert.equal(retained.userData, 'newly created after the earlier attempt');
  assert.deepEqual(f.pending.createdResult.actionResult.createdIds, ['prof_1']);
  assert.equal(f.calls.filter(item => item.method === 'importProfiles').length, 1);
  assert.equal(f.calls.filter(item => item.method === 'deleteProfile').length, 0, 'retry must not call delete again');
  assert.equal(await readFile(path.join(f.staging, 'login'), 'utf8'), 'exported sign-in data');
});

test('a fresh import also preserves nonempty or unsafe targets instead of deleting a competing writer', async t => {
  for (const code of ['IMPORT_TARGET_NOT_EMPTY', 'IMPORT_TARGET_UNSAFE']) await t.test(code, async t => {
    const f = await fixture(t);
    await assert.rejects(f.finish(async id => {
      f.profiles.get(id).userData = 'created by another consumer during import';
      throw Object.assign(new Error('private changed directory'), { code });
    }), error => error.code === 'IMPORT_ROLLBACK_INCOMPLETE' && !error.message.includes('private'));
    assert.equal(f.profiles.get('prof_1').userData, 'created by another consumer during import');
    assert.equal(f.calls.filter(item => item.method === 'deleteProfile').length, 0);
    assert.deepEqual(f.pending.createdResult.actionResult.createdIds, ['prof_1']);
    assert.equal(await readFile(path.join(f.staging, 'login'), 'utf8'), 'exported sign-in data');
  });
});

test('explicit deletion releases only its retained destination and preserves staging for a newly created retry', async t => {
  const f = await fixture(t);
  f.pending.createdResult = await f.service.call('importProfiles', { document: f.pending.document });
  const unrelated = { createdResult: { actionResult: { createdIds: ['prof_other'] } } };
  f.imports.set('other-import', unrelated);
  f.profiles.delete('prof_1'); // Main has completed the user's explicit deletion.
  assert.deepEqual(releaseDeletedEnvironmentImportProfile({ imports: f.imports, profileId: 'prof_1' }), { released: 1 });
  assert.equal(f.pending.createdResult, undefined);
  assert.deepEqual(unrelated.createdResult.actionResult.createdIds, ['prof_other']);
  assert.equal(await readFile(path.join(f.staging, 'login'), 'utf8'), 'exported sign-in data');
  const result = await f.finish(async id => ({ importedProfile: id }));
  assert.equal(result.restored.importedProfile, 'prof_2');
  assert.deepEqual([...f.imports.keys()], ['other-import']);
});

test('release of an explicitly deleted destination refuses active or multi-id imports atomically', () => {
  const retained = () => ({ createdResult: { actionResult: { createdIds: ['prof_1'] } }, bundle: { staging: '/retained/retry-source' } });
  for (const state of [{ busy: true }, { disposing: true }, { createdResult: { actionResult: { createdIds: ['prof_1', 'prof_other'] } } }]) {
    const valid = retained(), blocked = { ...retained(), ...state }, imports = new Map([['valid', valid], ['blocked', blocked]]);
    assert.throws(() => releaseDeletedEnvironmentImportProfile({ imports, profileId: 'prof_1' }), { code: state.createdResult ? 'IMPORT_RESULT_INVALID' : 'IMPORT_BUSY' });
    assert.deepEqual(valid.createdResult.actionResult.createdIds, ['prof_1']);
    assert.equal(valid.bundle.staging, '/retained/retry-source');
    assert.equal(imports.size, 2);
  }
  assert.deepEqual(releaseDeletedEnvironmentImportProfile({ imports: new Map([['unrelated', retained()]]), profileId: 'prof_none' }), { released: 0 });
});

test('a concurrent request, cancellation, expiry and capacity eviction cannot remove an active import', async t => {
  const f = await fixture(t), started = deferred(), release = deferred();
  const first = f.finish(async () => { started.resolve(); await release.promise; return { browser: true }; });
  await started.promise;
  await assert.rejects(f.finish(async () => { throw new Error('must not run'); }), { code: 'IMPORT_BUSY' });
  await assert.rejects(f.discard(), { code: 'IMPORT_BUSY' });
  await expirePendingEnvironmentImports({ imports: f.imports, discard: f.discard, now: 9999999 });
  await assert.rejects(makePendingImportRoom({ imports: f.imports, discard: f.discard, limit: 1 }), { code: 'IMPORT_BUSY' });
  assert.equal(f.imports.size, 1); await access(f.staging);
  release.resolve(); await first;
  assert.equal(f.calls.filter(item => item.method === 'importProfiles').length, 1);
});

test('cancel and expiry remove idle plaintext staging but preserve incomplete rollback records', async t => {
  const f = await fixture(t);
  await f.discard(); assert.equal(f.imports.size, 0); await assert.rejects(access(f.staging), { code: 'ENOENT' });
  const old = path.join(f.root, 'old'), retained = path.join(f.root, 'retained'); await mkdir(old); await mkdir(retained);
  f.imports.set('old', { createdAt: 1, bundle: { staging: old } });
  f.imports.set('retained', { createdAt: 1, bundle: { staging: retained }, createdResult: {} });
  await expirePendingEnvironmentImports({ imports: f.imports, discard: f.discard, now: 9999999 });
  assert.deepEqual([...f.imports.keys()], ['retained']);
  await assert.rejects(access(old), { code: 'ENOENT' }); await access(retained);
});

test('capacity evicts an idle import and keeps its cleanup tied to the same record', async t => {
  const f = await fixture(t);
  f.imports.set('busy', { busy: true, createdAt: 1 });
  await makePendingImportRoom({ imports: f.imports, discard: f.discard, limit: 2 });
  assert.deepEqual([...f.imports.keys()], ['busy']);
  await assert.rejects(access(f.staging), { code: 'ENOENT' });
});

test('simultaneous registrations enforce capacity atomically without holding human mapping open', async () => {
  const imports = new Map([['busy-a', { busy: true }], ['busy-b', { busy: true }]]), discarded = [];
  const discard = async id => { discarded.push(id); imports.delete(id); };
  const result = await Promise.allSettled(['third', 'fourth'].map(importId => registerPendingEnvironmentImport({ imports, importId,
    pending: { needsProxyMapping: true }, discard, limit: 3 })));
  assert(result.every(item => item.status === 'fulfilled'));
  assert.equal(imports.size, 3);
  assert.deepEqual([...imports.keys()], ['busy-a', 'busy-b', 'fourth']);
  assert.deepEqual(discarded, ['third']);
});

test('failed registration cleans only its new staging and never evicts a busy or retained import', async t => {
  const f = await fixture(t), incoming = path.join(f.root, 'incoming'); await mkdir(incoming);
  await writeFile(path.join(incoming, 'login'), 'incoming private fixture');
  f.pending.busy = true;
  let removed = 0;
  await assert.rejects(registerPendingEnvironmentImport({ imports: f.imports, importId: 'second', pending: { bundle: { staging: incoming } },
    discard: async () => { throw new Error('busy record must not be discarded'); },
    removeStaging: async target => { assert.equal(target, incoming); removed++; await rm(target, { recursive: true }); }, limit: 1 }), { code: 'IMPORT_BUSY' });
  assert.equal(removed, 1); await assert.rejects(access(incoming), { code: 'ENOENT' });
  assert.equal(await readFile(path.join(f.staging, 'login'), 'utf8'), 'exported sign-in data');
  assert.deepEqual([...f.imports.keys()], ['import-1']);
  await assert.rejects(registerPendingEnvironmentImport({ imports: f.imports, importId: 'import-1', pending: f.pending,
    discard: f.discard, removeStaging: async () => { throw new Error('existing staging must never be removed'); }, limit: 1 }), { code: 'IMPORT_BUSY' });
  await access(f.staging);
});

test('registration failures release their queue so a subsequent import can be registered', async t => {
  const f = await fixture(t), incoming = path.join(f.root, 'incoming-cleanup-fails'); await mkdir(incoming);
  f.pending.createdResult = { actionResult: { createdIds: ['prof_retained'] } };
  await assert.rejects(registerPendingEnvironmentImport({ imports: f.imports, importId: 'second', pending: { bundle: { staging: incoming } },
    discard: f.discard, removeStaging: async () => { throw new Error('synthetic cleanup failure'); }, limit: 1 }), { code: 'IMPORT_STAGING_CLEANUP_FAILED' });
  await access(incoming); await access(f.staging);
  f.imports.delete('import-1');
  await registerPendingEnvironmentImport({ imports: f.imports, importId: 'next', pending: { file: '/owned/encrypted-fixture' }, discard: f.discard, limit: 1 });
  assert.deepEqual([...f.imports.keys()], ['next']);
});

test('a failed backend import releases the lock and keeps original staging for retry', async t => {
  const f = await fixture(t);
  f.service.call = async () => { throw Object.assign(new Error('proxy mapping required'), { code: 'PROXY_MAPPING_REQUIRED' }); };
  await assert.rejects(f.finish(async () => { throw new Error('must not restore'); }), { code: 'PROXY_MAPPING_REQUIRED' });
  assert.equal(f.pending.busy, false); assert.equal(f.imports.size, 1); await access(f.staging);
});

test('failure deleting completed staging retries disposal without restoring or creating a second profile', async t => {
  const f = await fixture(t); let restores = 0, disposals = 0;
  const discard = async () => { if (++disposals === 1) throw new Error('temporary removal failed'); await f.discard('import-1', { completed: true }); };
  const restore = async () => { restores++; return { browser: true }; };
  await assert.rejects(f.finish(restore, { discard }), /temporary removal failed/);
  assert.equal(f.pending.busy, false); assert.equal(f.imports.size, 1);
  assert.equal((await f.finish(restore, { discard })).restored.browser, true);
  assert.equal(restores, 1); assert.equal(f.calls.filter(item => item.method === 'importProfiles').length, 1);
});

test('plain configuration imports also dispose their pending record on success', async t => {
  const f = await fixture(t); delete f.pending.bundle;
  const result = await f.finish(async () => { throw new Error('must not restore a JSON-only import'); });
  assert.deepEqual(result.actionResult.createdIds, ['prof_1']); assert.equal(f.imports.size, 0);
});

test('asynchronous staging disposal blocks import, a second cancel, expiry and eviction until it finishes', async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  const disposal = discardPendingEnvironmentImport({ imports: f.imports, importId: 'import-1',
    removeStaging: async target => { entered.resolve(); await release.promise; await rm(target, { recursive: true, force: true }); } });
  await entered.promise;
  await assert.rejects(f.finish(async () => { throw new Error('must not restore during disposal'); }), { code: 'IMPORT_BUSY' });
  await assert.rejects(f.discard(), { code: 'IMPORT_BUSY' });
  await expirePendingEnvironmentImports({ imports: f.imports, discard: f.discard, now: 9999999 });
  await assert.rejects(makePendingImportRoom({ imports: f.imports, discard: f.discard, limit: 1 }), { code: 'IMPORT_BUSY' });
  assert.equal(f.imports.size, 1); assert.equal(f.calls.length, 0); await access(f.staging);
  release.resolve(); await disposal;
  assert.equal(f.imports.size, 0); assert.equal(f.pending.disposing, false);
});

test('an active desktop transfer refuses every data mutation while snapshot and stop/close stay callable', async () => {
  const lock = new DesktopEnvironmentTransferLock(), entered = deferred(), release = deferred();
  const transfer = lock.transfer(async () => { entered.resolve(); await release.promise; return 'export complete'; });
  await entered.promise;
  const refused = ['startProfile', 'clearProfile', 'deleteProfile', 'updateProfile', 'createProfile', 'cloneProfile',
    'openTerminal', 'duplicateTerminal', 'writeTerminal', 'chooseWorkspaceDirectory', 'setTerminalLinkBrowser',
    'createClaudeAccount', 'renameClaudeAccount', 'startApplication', 'runNotionTrial', 'saveApplication',
    'deleteApplication', 'clearApplicationData', 'deleteSignInData', 'setApplicationLinkBrowser',
    'saveProxy', 'deleteProxy', 'saveGroup', 'clearGroupProxy', 'installEngine', 'reclaimApplicationStorage'];
  for (const method of refused) {
    assert.equal(isEnvironmentDataMutation(method), true, method);
    await assert.rejects(lock.mutate(method, {}, async () => { throw new Error(`${method} must not execute`); }), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  }
  await assert.rejects(lock.mutate('bulkProfiles', { action: 'start' }, async () => {}), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  for (const method of ['snapshot', 'terminalSnapshot', 'notionTrialSnapshot', 'stopProfile', 'closeTerminal', 'stopApplication', 'stopNotionTrial'])
    assert.equal(await lock.mutate(method, {}, async () => method), method);
  assert.equal(await lock.mutate('bulkProfiles', { action: 'stop' }, async () => 'stopped'), 'stopped');
  await assert.rejects(lock.transfer(async () => { throw new Error('second transfer must not execute'); }), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  release.resolve(); assert.equal(await transfer, 'export complete');
  assert.equal(await lock.mutate('startProfile', {}, async () => 'started'), 'started');
});

test('an already-in-flight desktop mutation prevents transfer from racing it without blocking stop', async () => {
  const lock = new DesktopEnvironmentTransferLock(), entered = deferred(), release = deferred();
  const launch = lock.mutate('runNotionTrial', {}, async () => { entered.resolve(); await release.promise; });
  await entered.promise;
  await assert.rejects(lock.transfer(async () => { throw new Error('transfer must not race active launch'); }), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  assert.equal(await lock.mutate('stopNotionTrial', {}, async () => { release.resolve(); return 'stop accepted'; }), 'stop accepted');
  await launch; assert.equal(lock.mutations, 0);
  assert.equal(await lock.transfer(async () => 'safe to restore'), 'safe to restore');
});

test('desktop mutation and transfer failures release all reservations for subsequent operations', async () => {
  const lock = new DesktopEnvironmentTransferLock();
  await assert.rejects(lock.mutate('writeTerminal', {}, async () => { throw new Error('write failed'); }), /write failed/);
  assert.equal(lock.mutations, 0);
  await assert.rejects(lock.transfer(async () => { throw new Error('restore failed'); }), /restore failed/);
  assert.equal(lock.transferring, false);
  assert.equal(await lock.transfer(async () => 'retry succeeds'), 'retry succeeds');
  assert.equal(await lock.mutate('renameClaudeAccount', {}, async () => 'renamed'), 'renamed');
});

test('two in-flight desktop mutations both finish before a transfer can acquire its reservation', async () => {
  const lock = new DesktopEnvironmentTransferLock(), first = deferred(), second = deferred();
  const a = lock.mutate('saveApplication', {}, () => first.promise);
  const b = lock.mutate('renameClaudeAccount', {}, () => second.promise);
  assert.equal(lock.mutations, 2);
  first.resolve(); await a;
  await assert.rejects(lock.transfer(async () => {}), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  second.resolve(); await b;
  assert.equal(await lock.transfer(async () => 'done'), 'done'); assert.equal(lock.mutations, 0);
});
