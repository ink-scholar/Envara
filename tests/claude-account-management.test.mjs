import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { TerminalService } from '../electron/terminal-service.mjs';
import { TerminalController } from '../electron/terminal-controller.mjs';

const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const absent = target => assert.rejects(fs.lstat(target), { code: 'ENOENT' });
async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'envara-account-management-')));
  const options = { dataDir: path.join(root, 'data'), availableLocales: ['C'], resolveContext: async () => { throw new Error('No real launch is expected'); } };
  const service = new TerminalService(options); await service.ready;
  t.after(async () => { service.sessions.clear(); await service.shutdown().catch(() => {}); await fs.rm(root, { recursive: true, force: true }); });
  const { account } = await service.createClaudeAccount({ id: 'env_one', name: 'Selected' });
  const directories = await service.directories('env_one', account.id);
  const marker = path.join(directories.claude, 'synthetic-login'); await fs.writeFile(marker, 'selected fixture', { mode: 0o600 });
  const detached = path.join(service.root, 'claude-account-deletions', 'env_one', account.id);
  const detach = async () => { await fs.mkdir(path.dirname(detached), { recursive: true, mode: 0o700 }); await fs.rename(directories.claude, detached); };
  const remove = () => service.deleteClaudeAccount({ id: 'env_one', accountId: account.id, confirmed: true });
  return { root, service, options, account, directories, marker, detached, detach, remove };
}

test('confirmed deletion removes only the selected account, preserving shared, default, other-environment and host fixtures', async t => {
  const f = await fixture(t), { service } = f;
  const { account: other } = await service.createClaudeAccount({ id: 'env_one', name: 'Other' });
  const otherDirs = await service.directories('env_one', other.id);
  const defaultDirs = await service.directories('env_one');
  const otherEnv = await service.directories('env_two');
  const kept = [path.join(otherDirs.claude, 'keep'), path.join(defaultDirs.claude, 'keep'), path.join(otherEnv.claude, 'keep'), path.join(defaultDirs.home, 'shell-history'), path.join(f.root, 'host-fixture')];
  for (const filename of kept) await fs.writeFile(filename, 'preserved fixture', { mode: 0o600 });
  assert.throws(() => service.deleteClaudeAccount({ id: 'env_one', accountId: f.account.id }), { code: 'CLAUDE_ACCOUNT_DELETE_CONFIRMATION_REQUIRED' });
  assert.throws(() => service.deleteClaudeAccount({ id: 'env_one', accountId: 'default', confirmed: true }), { code: 'CLAUDE_ACCOUNT_DEFAULT' });
  assert.equal(await fs.readFile(f.marker, 'utf8'), 'selected fixture');
  assert.deepEqual(await f.remove(), { accountId: f.account.id, deleted: true, cleanupPending: false });
  await absent(f.directories.claude); await absent(f.detached);
  assert.deepEqual((await service.listClaudeAccounts({ id: 'env_one' })).accounts.map(value => value.id), ['default', other.id]);
  for (const filename of kept) assert.equal(await fs.readFile(filename, 'utf8'), 'preserved fixture');
});

test('active and queued Claude launches block deletion, including controller queue and picker cancellation', async t => {
  const f = await fixture(t), { service } = f;
  for (const status of ['starting', 'running', 'closing']) {
    service.sessions.set('synthetic', { profileId: 'env_one', kind: 'claude-code', claudeAccountId: f.account.id, status });
    assert.throws(f.remove, { code: 'CLAUDE_ACCOUNT_IN_USE' });
  }
  service.sessions.clear();
  const gate = deferred(), entered = deferred();
  const controller = new TerminalController({ terminal: service, service: { snapshot: async () => ({ profiles: [{ id: 'env_one' }] }) }, pickDirectory: async () => { entered.resolve(); await gate.promise; return { canceled: true }; } });
  const launch = controller.dispatch('openTerminal', { id: 'env_one', kind: 'claude-code', browserProfileId: 'env_one', claudeAccountId: f.account.id });
  assert.equal(service.accountInUse('env_one', f.account.id), true, 'reserved before any queued work');
  await entered.promise;
  await assert.rejects(controller.dispatch('deleteClaudeAccount', { id: 'env_one', accountId: f.account.id, confirmed: true }), { code: 'CLAUDE_ACCOUNT_IN_USE' });
  gate.resolve(); assert.deepEqual(await launch, { canceled: true });
  assert.equal(service.accountInUse('env_one', f.account.id), false);
  await f.remove();
});

test('service queued starts and duplicate reservations refuse deletion until their work settles', async t => {
  const f = await fixture(t), { service } = f, gate = deferred();
  service.settings.set('env_one', { cwd: f.root });
  service.profileQueues.set('env_one', gate.promise);
  service.startSession = async () => ({ synthetic: true });
  const launch = service.create({ id: 'env_one', kind: 'claude-code', browserProfileId: 'env_one', claudeAccountId: f.account.id });
  assert.throws(f.remove, { code: 'CLAUDE_ACCOUNT_IN_USE' });
  gate.resolve(); await launch;
  assert.equal(service.accountInUse('env_one', f.account.id), false);
  const sourceId = `term_${'a'.repeat(32)}`;
  service.sessions.set(sourceId, { sessionId: sourceId, profileId: 'env_one', kind: 'claude-code', claudeAccountId: f.account.id, status: 'running', cwd: f.root, browserProfileId: 'env_one', launchContext: {} });
  const release = service.reserveClaudeAccountDuplicateStart(sourceId);
  service.sessions.get(sourceId).status = 'closed';
  assert.throws(f.remove, { code: 'CLAUDE_ACCOUNT_IN_USE' });
  release(); release();
  assert.equal(service.accountInUse('env_one', f.account.id), false);
  service.sessions.clear(); await f.remove();
});

test('metadata failure restores the exact account directory and keeps the deletion retryable', async t => {
  const f = await fixture(t), before = await fs.lstat(f.directories.claude), save = f.service.claudeAccounts.save;
  f.service.claudeAccounts.save = async () => { throw new Error('Synthetic metadata failure'); };
  await assert.rejects(f.remove(), { code: 'CLAUDE_ACCOUNT_DELETE_FAILED' });
  f.service.claudeAccounts.save = save;
  assert.equal((await fs.lstat(f.directories.claude)).ino, before.ino);
  assert.equal(await fs.readFile(f.marker, 'utf8'), 'selected fixture');
  assert.equal((await f.service.claudeAccounts.get('env_one', f.account.id)).name, 'Selected');
  await absent(f.detached); await f.remove();
});

test('a failed rollback keeps its detached copy and refuses recovery over a competing directory', async t => {
  const f = await fixture(t), save = f.service.claudeAccounts.save;
  f.service.claudeAccounts.save = async () => {
    await fs.mkdir(f.directories.claude, { mode: 0o700 });
    await fs.writeFile(path.join(f.directories.claude, 'new-writer'), 'preserve competing writer');
    throw new Error('Synthetic metadata failure');
  };
  await assert.rejects(f.remove(), { code: 'CLAUDE_ACCOUNT_DELETE_RECOVERY_REQUIRED' });
  f.service.claudeAccounts.save = save;
  assert.equal(await fs.readFile(path.join(f.detached, 'synthetic-login'), 'utf8'), 'selected fixture');
  assert.equal(await fs.readFile(path.join(f.directories.claude, 'new-writer'), 'utf8'), 'preserve competing writer');
  const restarted = new TerminalService(f.options);
  await assert.rejects(restarted.ready, { code: 'CLAUDE_ACCOUNT_DELETE_RECOVERY_REQUIRED' });
  assert.equal(await fs.readFile(path.join(f.detached, 'synthetic-login'), 'utf8'), 'selected fixture');
  // Only the synthetic competing writer is removed to model explicit resolution.
  await fs.rm(f.directories.claude, { recursive: true });
  await f.service.recoverClaudeAccountDeletion('env_one', f.account.id);
  assert.equal(await fs.readFile(f.marker, 'utf8'), 'selected fixture');
});

test('committed cleanup failure retains only detached data, rejects new starts, and retries cleanup', async t => {
  const f = await fixture(t), remove = fs.rm;
  fs.rm = async (target, options) => { if (target === f.detached) throw new Error('Synthetic cleanup failure'); return remove(target, options); };
  syncBuiltinESMExports();
  try {
    assert.deepEqual(await f.remove(), { accountId: f.account.id, deleted: true, cleanupPending: true });
    await absent(f.directories.claude);
    assert.equal(await fs.readFile(path.join(f.detached, 'synthetic-login'), 'utf8'), 'selected fixture');
    assert.deepEqual(await f.remove(), { accountId: f.account.id, deleted: true, cleanupPending: true }, 'a repeated cleanup failure remains retryable without exposing filesystem details');
    await assert.rejects(f.service.create({ id: 'env_one', kind: 'claude-code', browserProfileId: 'env_one', claudeAccountId: f.account.id }), { code: 'CLAUDE_ACCOUNT_NOT_FOUND' });
  } finally { fs.rm = remove; syncBuiltinESMExports(); }
  assert.deepEqual(await f.remove(), { accountId: f.account.id, deleted: true, cleanupPending: false });
  await absent(f.detached);
});

test('restart restores precommit data and finishes postcommit cleanup without reading authentication contents', async t => {
  for (const committed of [false, true]) await t.test(String(committed), async t => {
    const f = await fixture(t); await f.detach();
    if (committed) await f.service.claudeAccounts.remove('env_one', f.account.id);
    const restarted = new TerminalService(f.options); await restarted.ready;
    t.after(() => restarted.shutdown());
    await absent(f.detached);
    if (committed) { await absent(f.directories.claude); await assert.rejects(restarted.claudeAccounts.get('env_one', f.account.id), { code: 'CLAUDE_ACCOUNT_NOT_FOUND' }); }
    else assert.equal(await fs.readFile(f.marker, 'utf8'), 'selected fixture');
  });
});

test('linked account or quarantine paths are refused without modifying their target', async t => {
  for (const unsafe of ['account', 'parent', 'quarantine']) await t.test(unsafe, async t => {
    const f = await fixture(t);
    const target = unsafe === 'account' ? f.directories.claude : unsafe === 'parent' ? path.dirname(f.directories.claude) : path.join(f.service.root, 'claude-account-deletions');
    const outside = path.join(f.root, 'outside');
    if (unsafe === 'quarantine') { await fs.mkdir(outside, { mode: 0o700 }); await fs.writeFile(path.join(outside, 'keep'), 'preserved'); }
    else await fs.rename(target, outside);
    await fs.symlink(outside, target);
    await assert.rejects(f.remove(), { code: 'CLAUDE_ACCOUNT_UNSAFE_PATH' });
    assert.equal((await fs.lstat(target)).isSymbolicLink(), true);
    assert.equal((await f.service.claudeAccounts.get('env_one', f.account.id)).name, 'Selected');
    const marker = unsafe === 'quarantine' ? path.join(outside, 'keep') : unsafe === 'parent' ? path.join(outside, f.account.id, 'synthetic-login') : path.join(outside, 'synthetic-login');
    assert.equal(await fs.readFile(marker, 'utf8'), unsafe === 'quarantine' ? 'preserved' : 'selected fixture');
  });
});

test('a deletion holds a synchronous reservation against a later launch', async t => {
  const f = await fixture(t), gate = deferred();
  f.service.profileQueues.set('env_one', gate.promise);
  const deletion = f.remove();
  await assert.rejects(f.service.create({ id: 'env_one', kind: 'claude-code', browserProfileId: 'env_one', claudeAccountId: f.account.id }), { code: 'CLAUDE_ACCOUNT_DELETE_BUSY' });
  gate.resolve(); await deletion;
});
