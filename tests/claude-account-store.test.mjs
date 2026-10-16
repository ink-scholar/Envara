import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, unlink, utimes, writeFile } from 'node:fs/promises';
import { ClaudeAccountStore } from '../electron/claude-account-store.mjs';

const DEFAULT = { id: 'default', name: '默认', default: true };
const SYNTHETIC_AUTH = 'SYNTHETIC_AUTH_MARKER_DO_NOT_INCLUDE_IN_ERRORS';

async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-claude-accounts-')));
  await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, filename: path.join(root, 'claude-accounts.json') };
}

async function openStore(root) {
  const store = new ClaudeAccountStore({ root });
  await store.ready;
  return store;
}

function hasCode(code) {
  return error => {
    assert.equal(error.code, code);
    assert.equal(error.message.includes(SYNTHETIC_AUTH), false, 'errors must not disclose stored text');
    return true;
  };
}

test('account labels persist while the default remains implicit and compatible', async t => {
  const f = await fixture(t);
  const store = await openStore(f.root);
  assert.deepEqual(await store.list('env_one'), [DEFAULT]);
  assert.deepEqual(await store.get('env_one'), DEFAULT);
  const account = await store.create('env_one', '工作账号');
  assert.match(account.id, /^account_[0-9a-f]{32}$/);
  assert.equal(account.name, '工作账号');
  const renamed = await store.rename('env_one', account.id, '团队账号');
  assert.equal(renamed.id, account.id);
  assert.equal(renamed.name, '团队账号');
  assert.deepEqual(await store.get('env_one', account.id), renamed);

  const restarted = await openStore(f.root);
  assert.deepEqual(await restarted.list('env_one'), [DEFAULT, renamed]);
  assert.deepEqual(await restarted.get('env_one', account.id), renamed);
  assert.deepEqual(await restarted.get('env_two'), DEFAULT);
  assert.equal((await lstat(f.filename)).mode & 0o777, 0o600);

  const serialized = await readFile(f.filename, 'utf8');
  const accountRecords = [];
  const collect = value => {
    if (Array.isArray(value)) for (const child of value) collect(child);
    else if (value && typeof value === 'object') {
      if (value.id === account.id) accountRecords.push(value);
      for (const child of Object.values(value)) collect(child);
    }
  };
  collect(JSON.parse(serialized));
  assert.ok(accountRecords.length > 0, 'the renamed account must be persisted');
  for (const record of accountRecords) assert.deepEqual(Object.keys(record).sort(), ['id', 'name']);
});

test('accounts belong to their environment and removing a profile only removes its metadata', async t => {
  const f = await fixture(t);
  const markerDirectory = path.join(f.root, 'profiles', 'env_one', 'claude');
  await mkdir(markerDirectory, { recursive: true, mode: 0o700 });
  const marker = path.join(markerDirectory, '.credentials.json');
  await writeFile(marker, SYNTHETIC_AUTH, { mode: 0o600 });
  const store = await openStore(f.root);
  const one = await store.create('env_one', '工作');
  const two = await store.create('env_two', '工作');
  assert.notEqual(one.id, two.id);
  await assert.rejects(store.get('env_two', one.id), hasCode('CLAUDE_ACCOUNT_NOT_FOUND'));
  await store.removeProfile('env_one');
  assert.deepEqual(await store.list('env_one'), [DEFAULT]);
  assert.deepEqual(await store.list('env_two'), [DEFAULT, two]);
  assert.equal(await readFile(marker, 'utf8'), SYNTHETIC_AUTH);
  const restarted = await openStore(f.root);
  assert.deepEqual(await restarted.list('env_one'), [DEFAULT]);
  assert.deepEqual(await restarted.get('env_two', two.id), two);
});

test('duplicate labels are rejected within an environment without losing existing accounts', async t => {
  const f = await fixture(t);
  const store = await openStore(f.root);
  const first = await store.create('env_one', '个人');
  const second = await store.create('env_one', '工作');
  await assert.rejects(store.create('env_one', first.name), hasCode('CLAUDE_ACCOUNT_NAME_EXISTS'));
  await assert.rejects(store.rename('env_one', second.id, first.name), hasCode('CLAUDE_ACCOUNT_NAME_EXISTS'));
  assert.deepEqual(await store.list('env_one'), [DEFAULT, first, second]);
  assert.equal((await store.create('env_two', first.name)).name, first.name);
});

test('empty names, malformed identifiers and missing accounts fail before changing metadata', async t => {
  const f = await fixture(t);
  const store = await openStore(f.root);
  const account = await store.create('env_one', '有效账号');
  for (const name of ['', '   ', '\t\n', null, 42]) {
    await assert.rejects(async () => store.create('env_one', name), hasCode('CLAUDE_ACCOUNT_INVALID'));
    await assert.rejects(async () => store.rename('env_one', account.id, name), hasCode('CLAUDE_ACCOUNT_INVALID'));
  }
  for (const profileId of ['', '../outside', 'env/child', 'env\nother', null]) {
    await assert.rejects(store.list(profileId), hasCode('CLAUDE_ACCOUNT_INVALID'));
    await assert.rejects(async () => store.create(profileId, '有效账号'), hasCode('CLAUDE_ACCOUNT_INVALID'));
    await assert.rejects(store.get(profileId), hasCode('CLAUDE_ACCOUNT_INVALID'));
    await assert.rejects(async () => store.rename(profileId, account.id, '新名称'), hasCode('CLAUDE_ACCOUNT_INVALID'));
    await assert.rejects(async () => store.removeProfile(profileId), hasCode('CLAUDE_ACCOUNT_INVALID'));
  }
  for (const accountId of ['', '../outside', 'account_invalid', 'default/child', null]) {
    await assert.rejects(store.get('env_one', accountId), hasCode('CLAUDE_ACCOUNT_INVALID'));
    await assert.rejects(async () => store.rename('env_one', accountId, '新名称'), hasCode('CLAUDE_ACCOUNT_INVALID'));
  }
  const missing = `account_${'f'.repeat(32)}`;
  await assert.rejects(store.get('env_one', missing), hasCode('CLAUDE_ACCOUNT_NOT_FOUND'));
  await assert.rejects(store.rename('env_one', missing, '新名称'), hasCode('CLAUDE_ACCOUNT_NOT_FOUND'));
  assert.deepEqual(await store.list('env_one'), [DEFAULT, account]);
});

test('concurrent account creation persists every record with a distinct identity', async t => {
  const f = await fixture(t);
  const store = await openStore(f.root);
  const created = await Promise.all(Array.from({ length: 12 }, (_, index) => store.create('env_one', `账号 ${index}`)));
  assert.equal(new Set(created.map(account => account.id)).size, created.length);
  const expected = new Map(created.map(account => [account.id, account.name]));
  const restarted = await openStore(f.root);
  const listed = await restarted.list('env_one');
  assert.equal(listed.length, created.length + 1);
  assert.deepEqual(listed[0], DEFAULT);
  assert.deepEqual(new Map(listed.slice(1).map(account => [account.id, account.name])), expected);
});

test('the account limit includes the existing default account', async t => {
  const f = await fixture(t);
  const store = await openStore(f.root);
  for (let index = 0; index < 19; index += 1) await store.create('env_one', `账号 ${index}`);
  await assert.rejects(store.create('env_one', '第二十一个账号'), hasCode('CLAUDE_ACCOUNT_LIMIT'));
  assert.equal((await store.list('env_one')).length, 20);
  assert.equal((await store.create('env_two', '不共享上限')).name, '不共享上限');
});

test('metadata operations never access or relocate existing authentication files', async t => {
  const f = await fixture(t);
  const legacyDirectory = path.join(f.root, 'profiles', 'env_one', 'claude');
  await mkdir(legacyDirectory, { recursive: true, mode: 0o700 });
  const marker = path.join(legacyDirectory, '.credentials.json');
  // Synthetic malformed auth text and unreadable permissions make accidental
  // auth parsing unnecessary and observable without using a real credential.
  await writeFile(marker, SYNTHETIC_AUTH, { mode: 0o600 });
  const oldTime = new Date('2001-01-01T00:00:00Z');
  await utimes(marker, oldTime, oldTime);
  await chmod(marker, 0o000);
  const before = await lstat(marker);
  const store = await openStore(f.root);
  assert.deepEqual(await store.list('env_one'), [DEFAULT]);
  const account = await store.create('env_one', '另一个账号');
  await store.rename('env_one', account.id, '已重命名');
  await store.get('env_one', account.id);
  await store.removeProfile('env_one');
  await openStore(f.root);
  const after = await lstat(marker);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mode, before.mode);
  assert.equal(after.size, before.size);
  assert.equal(after.mtimeMs, before.mtimeMs);
  assert.equal(after.atimeMs, before.atimeMs);
  assert.equal((await readFile(f.filename, 'utf8')).includes(SYNTHETIC_AUTH), false);
  await chmod(marker, 0o600);
  assert.equal(await readFile(marker, 'utf8'), SYNTHETIC_AUTH);
});

test('linked metadata is refused without following or disclosing the target', async t => {
  const f = await fixture(t);
  const target = path.join(f.root, 'synthetic-auth.json');
  await writeFile(target, SYNTHETIC_AUTH, { mode: 0o600 });
  await symlink(target, f.filename);
  const store = new ClaudeAccountStore({ root: f.root });
  await assert.rejects(store.ready, hasCode('CLAUDE_ACCOUNT_STORAGE_INVALID'));
  assert.equal((await lstat(f.filename)).isSymbolicLink(), true);
  assert.equal(await readFile(target, 'utf8'), SYNTHETIC_AUTH);
});

test('a metadata file replaced by a link is refused on the next write', async t => {
  const f = await fixture(t);
  const store = await openStore(f.root);
  await store.create('env_one', '已有账号');
  const target = path.join(f.root, 'synthetic-auth.json');
  await writeFile(target, SYNTHETIC_AUTH, { mode: 0o600 });
  await unlink(f.filename);
  await symlink(target, f.filename);
  await assert.rejects(store.create('env_one', '新增账号'), hasCode('CLAUDE_ACCOUNT_UNSAFE_PATH'));
  assert.equal((await lstat(f.filename)).isSymbolicLink(), true);
  assert.equal(await readFile(target, 'utf8'), SYNTHETIC_AUTH);
});

test('malformed metadata is rejected without reflecting private file contents', async t => {
  const f = await fixture(t);
  await writeFile(f.filename, `invalid-json ${SYNTHETIC_AUTH}`, { mode: 0o600 });
  const store = new ClaudeAccountStore({ root: f.root });
  await assert.rejects(store.ready, hasCode('CLAUDE_ACCOUNT_STORAGE_INVALID'));
  assert.equal(await readFile(f.filename, 'utf8'), `invalid-json ${SYNTHETIC_AUTH}`);
});

test('an oversized UTF-8 update preserves readable account metadata and its in-memory state', async t => {
  const f = await fixture(t);
  const limit = 1024 * 1024;
  const document = { schema: 'envara.claude-accounts', version: 1, profiles: [] };
  const account = index => ({ id: `account_${index.toString(16).padStart(32, '0')}`, name: '界'.repeat(76) + String(index).padStart(4, '0') });
  const full = [{ id: 'default', name: '默认' }, ...Array.from({ length: 19 }, (_, index) => account(index))];
  while (true) {
    document.profiles.push({ id: `synthetic_${document.profiles.length}`, accounts: full });
    if (Buffer.byteLength(JSON.stringify(document)) > limit) { document.profiles.pop(); break; }
  }
  const growing = { id: 'growing', accounts: [{ id: 'default', name: '默认' }] };
  document.profiles.push(growing);
  for (let index = 0; index < 19; index++) {
    growing.accounts.push(account(index));
    if (Buffer.byteLength(JSON.stringify(document)) > limit) { growing.accounts.pop(); break; }
  }
  const before = JSON.stringify(document);
  assert(Buffer.byteLength(before) <= limit);
  assert(growing.accounts.length < 20);
  await writeFile(f.filename, before, { mode: 0o600 });
  const store = await openStore(f.root);
  const accounts = await store.list(growing.id);
  await assert.rejects(store.create(growing.id, account(9999).name), hasCode('CLAUDE_ACCOUNT_STORAGE_INVALID'));
  assert.equal(await readFile(f.filename, 'utf8'), before);
  assert.deepEqual(await store.list(growing.id), accounts);
  assert.deepEqual(await (await openStore(f.root)).list(growing.id), accounts);
});
