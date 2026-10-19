import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { TerminalEntryStore, TERMINAL_ENTRY_LIMIT } from '../electron/terminal-entry-store.mjs';

const secret = 'SYNTHETIC_SECRET_NEVER_INCLUDE_IN_FAILURES';
async function fixture(t) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'envara-terminal-entries-')));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  return { root, filename: path.join(root, 'saved-terminals.json') };
}
async function openStore(root) { const store = new TerminalEntryStore({ root }); await store.ready; return store; }
const config = (root, patch = {}) => ({ profileId: 'profile_one', name: '项目终端', kind: 'shell', cwd: path.join(root, 'selected-project'),
  browserProfileId: null, claudeAccountId: null, networkRef: { kind: 'direct', proxyId: null }, ...patch });
const hasCode = code => error => { assert.equal(error.code, code); assert.equal(error.message.includes(secret), false); return true; };

test('terminal entries persist names and native timestamps without requiring the selected folder to exist', async t => {
  const f = await fixture(t), store = await openStore(f.root);
  assert.deepEqual(await store.list(), []);
  const entry = await store.upsert(config(f.root, { name: '  工作台  ' }));
  assert.match(entry.id, /^savedterm_[a-f0-9]{32}$/); assert.equal(entry.name, '工作台');
  for (const key of ['createdAt', 'updatedAt', 'lastOpenedAt']) assert.equal(new Date(entry[key]).toISOString(), entry[key]);
  const restarted = await openStore(f.root);
  assert.deepEqual(await restarted.get('profile_one', entry.id), entry);
  assert.deepEqual(await restarted.list('profile_two'), []);
  assert.equal((await lstat(f.filename)).mode & 0o777, 0o600);
  assert.deepEqual(Object.keys(JSON.parse(await readFile(f.filename, 'utf8'))).sort(), ['entries', 'schema', 'version']);
  entry.networkRef.kind = 'managed'; entry.name = 'client mutation';
  assert.equal((await store.get('profile_one', entry.id)).name, '工作台');
  assert.deepEqual((await store.get('profile_one', entry.id)).networkRef, { kind: 'direct', proxyId: null });
});

test('matching configurations deduplicate, retain renamed names and update only their durable network reference', async t => {
  const f = await fixture(t), store = await openStore(f.root);
  const one = await store.upsert(config(f.root));
  const renamed = await store.rename('profile_one', one.id, '保留这个名称');
  const reopened = await store.upsert(config(f.root, { name: 'fallback name', networkRef: { kind: 'managed', proxyId: 'proxy_new' } }));
  assert.equal(reopened.id, one.id); assert.equal(reopened.name, renamed.name); assert.equal(reopened.createdAt, one.createdAt);
  assert.deepEqual(reopened.networkRef, { kind: 'managed', proxyId: 'proxy_new' });
  assert.equal((await store.list()).length, 1);
  const others = await Promise.all([
    store.upsert(config(f.root, { profileId: 'profile_two' })),
    store.upsert(config(f.root, { browserProfileId: 'system' })),
    store.upsert(config(f.root, { cwd: path.join(f.root, 'other-project') })),
    store.upsert(config(f.root, { kind: 'claude-code', browserProfileId: 'profile_one', claudeAccountId: 'default' })),
    store.upsert(config(f.root, { kind: 'claude-code', browserProfileId: 'profile_one', claudeAccountId: `account_${'a'.repeat(32)}` })),
  ]);
  assert.equal(new Set([one.id, ...others.map(entry => entry.id)]).size, 6);
  assert.equal((await (await openStore(f.root)).list()).length, 6, 'serialized writes cannot lose concurrent additions');
});

test('entry removal is profile-scoped and never removes login, command-history or project files', async t => {
  const f = await fixture(t), store = await openStore(f.root);
  const project = path.join(f.root, 'selected-project'); await mkdir(project);
  const marker = path.join(project, 'synthetic-sign-in-and-history.txt'); await writeFile(marker, secret, { mode: 0o600 });
  const one = await store.upsert(config(f.root)), two = await store.upsert(config(f.root, { browserProfileId: 'system' }));
  const foreign = await store.upsert(config(f.root, { profileId: 'profile_two' }));
  for (const operation of [() => store.get('profile_two', one.id), () => store.rename('profile_two', one.id, 'foreign'), () => store.remove('profile_two', one.id)])
    await assert.rejects(operation(), hasCode('TERMINAL_ENTRY_NOT_FOUND'));
  assert.deepEqual(await store.remove('profile_one', one.id), one);
  assert.deepEqual((await store.removeProfile('profile_one')).map(entry => entry.id), [two.id]);
  assert.deepEqual(await store.list(), [foreign]); assert.equal(await readFile(marker, 'utf8'), secret);
  assert.deepEqual(await (await openStore(f.root)).list(), [foreign]);
});

test('invalid or runtime-bearing configuration is rejected without exposing or persisting its payload', async t => {
  const f = await fixture(t), store = await openStore(f.root), existing = await store.upsert(config(f.root));
  const before = await readFile(f.filename, 'utf8');
  const invalid = [
    { name: '' }, { name: `${secret}\n` }, { name: 'x'.repeat(81) }, { profileId: '../outside' },
    { cwd: '/not/canonical/../path' }, { cwd: 'relative' }, { cwd: `/${secret}\0` }, { cwd: `/${'x'.repeat(8192)}` },
    { kind: 'ssh' }, { browserProfileId: '../outside' }, { claudeAccountId: 'default' },
    { kind: 'claude-code', browserProfileId: 'profile_other', claudeAccountId: 'default' },
    { kind: 'claude-code', browserProfileId: 'profile_one', claudeAccountId: '../outside' },
    { networkRef: { kind: 'managed', proxyId: null } }, { networkRef: { kind: 'direct', proxyId: 'proxy_one' } },
    { networkRef: { kind: 'proxy', proxyId: '../outside' } }, { networkRef: { kind: 'proxy', proxyId: null, password: secret } },
    ...['password', 'username', 'endpoint', 'port', 'pid', 'sessionId', 'command', 'replay', 'output', 'id', 'createdAt'].map(key => ({ [key]: secret })),
  ];
  for (const patch of invalid) {
    await assert.rejects(async () => store.upsert(config(f.root, patch)), hasCode('TERMINAL_ENTRY_INVALID'));
    assert.deepEqual(await store.list(), [existing]); assert.equal(await readFile(f.filename, 'utf8'), before);
  }
});

test('failed saves retain committed entries and the queue recovers on the next safe mutation', async t => {
  const f = await fixture(t), store = await openStore(f.root), entry = await store.upsert(config(f.root));
  const before = await readFile(f.filename, 'utf8'), save = store.save;
  store.save = async () => { throw Object.assign(new Error('Synthetic storage failure'), { code: 'EIO' }); };
  for (const operation of [() => store.rename('profile_one', entry.id, 'not committed'), () => store.remove('profile_one', entry.id),
    () => store.removeProfile('profile_one'), () => store.upsert(config(f.root, { browserProfileId: 'system' }))]) {
    await assert.rejects(operation(), { code: 'EIO' }); assert.deepEqual(await store.list(), [entry]);
    assert.equal(await readFile(f.filename, 'utf8'), before);
  }
  store.save = save;
  assert.equal((await store.rename('profile_one', entry.id, 'saved')).name, 'saved');
  assert.equal((await (await openStore(f.root)).get('profile_one', entry.id)).name, 'saved');
  assert.deepEqual((await readdir(f.root)).sort(), ['saved-terminals.json']);
});

test('symbolic or hard-linked files and a changed storage root are rejected without touching their targets', async t => {
  const f = await fixture(t), store = await openStore(f.root), entry = await store.upsert(config(f.root));
  const before = await readFile(f.filename, 'utf8'), target = path.join(f.root, 'foreign.txt');
  await writeFile(target, secret, { mode: 0o600 }); await unlink(f.filename); await symlink(target, f.filename);
  await assert.rejects(openStore(f.root), hasCode('TERMINAL_ENTRY_UNSAFE_PATH'));
  await assert.rejects(store.rename('profile_one', entry.id, 'unsafe'), hasCode('TERMINAL_ENTRY_UNSAFE_PATH'));
  assert.equal(await readFile(target, 'utf8'), secret); assert.equal((await store.get('profile_one', entry.id)).name, entry.name);
  await unlink(f.filename); await link(target, f.filename);
  await assert.rejects(openStore(f.root), hasCode('TERMINAL_ENTRY_UNSAFE_PATH'));
  await assert.rejects(store.remove('profile_one', entry.id), hasCode('TERMINAL_ENTRY_UNSAFE_PATH'));
  assert.equal(await readFile(target, 'utf8'), secret); await unlink(f.filename); await writeFile(f.filename, before, { mode: 0o600 });
  const alias = path.join(f.root, 'root-alias'); await symlink(f.root, alias);
  await assert.rejects(openStore(alias), hasCode('TERMINAL_ENTRY_UNSAFE_PATH'));
  await chmod(f.root, 0o777);
  await assert.rejects(store.rename('profile_one', entry.id, 'unsafe'), hasCode('TERMINAL_ENTRY_UNSAFE_PATH'));
  await chmod(f.root, 0o700); assert.equal(await readFile(f.filename, 'utf8'), before);
});

test('malformed, excessive, duplicated and runtime-bearing stored records fail with bounded sanitized errors', async t => {
  const f = await fixture(t), store = await openStore(f.root), entry = await store.upsert(config(f.root));
  const document = entries => ({ schema: 'envara.terminal-entries', version: 1, entries });
  const cases = [
    secret, '{', JSON.stringify({ schema: secret, version: 1, entries: [] }),
    JSON.stringify(document([entry, entry])), JSON.stringify(document([{ ...entry, password: secret }])),
    JSON.stringify(document([{ ...entry, id: '../outside' }])), JSON.stringify(document([{ ...entry, createdAt: secret }])),
    JSON.stringify(document([{ ...entry, updatedAt: '2000-01-01T00:00:00.000Z' }])),
    JSON.stringify(document([{ ...entry, lastOpenedAt: '2099-01-01T00:00:00.000Z' }])),
    JSON.stringify(document(Array.from({ length: TERMINAL_ENTRY_LIMIT + 1 }, () => entry))),
    'x'.repeat(1024 * 1024 + 1),
  ];
  for (const serialized of cases) {
    await writeFile(f.filename, serialized, { mode: 0o600 });
    const invalid = new TerminalEntryStore({ root: f.root });
    await assert.rejects(invalid.ready, error => {
      assert.ok(['TERMINAL_ENTRY_STORAGE_INVALID', 'TERMINAL_ENTRY_UNSAFE_PATH'].includes(error.code));
      assert.equal(error.message.includes(secret), false); return true;
    });
    assert.equal(invalid.entries.size, 0); assert.equal(await readFile(f.filename, 'utf8'), serialized, 'loading never rewrites a malformed file');
  }
});

test('the bounded entry limit still permits reopening and renaming existing records', async t => {
  const f = await fixture(t), store = await openStore(f.root), entry = await store.upsert(config(f.root));
  const entries = Array.from({ length: TERMINAL_ENTRY_LIMIT }, (_, index) => ({ ...entry,
    id: `savedterm_${index.toString(16).padStart(32, '0')}`, cwd: path.join(f.root, `project-${index}`) }));
  await writeFile(f.filename, JSON.stringify({ schema: 'envara.terminal-entries', version: 1, entries }), { mode: 0o600 });
  const full = await openStore(f.root), before = await readFile(f.filename, 'utf8');
  await assert.rejects(full.upsert(config(f.root)), hasCode('TERMINAL_ENTRY_LIMIT'));
  assert.equal(await readFile(f.filename, 'utf8'), before); assert.equal((await full.list()).length, TERMINAL_ENTRY_LIMIT);
  assert.equal((await full.upsert(config(f.root, { cwd: entries[0].cwd }))).id, entries[0].id);
  assert.equal((await full.rename('profile_one', entries[0].id, 'Still usable')).name, 'Still usable');
  assert.equal((await (await openStore(f.root)).list()).length, TERMINAL_ENTRY_LIMIT);
});
