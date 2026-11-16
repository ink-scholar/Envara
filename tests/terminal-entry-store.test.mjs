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
  const document = entries => ({ schema: 'envara.terminal-entries', version: 2, entries });
  const cases = [
    secret, '{', JSON.stringify({ schema: secret, version: 1, entries: [] }),
    JSON.stringify(document([entry, entry])), JSON.stringify(document([{ ...entry, password: secret }])),
    JSON.stringify(document([entry, { ...entry, id: `savedterm_${'f'.repeat(32)}`, pinned: true }])),
    ...[undefined, null, 1, 'true', {}].map(pinned => JSON.stringify(document([{ ...entry, pinned }]))),
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
  await writeFile(f.filename, JSON.stringify({ schema: 'envara.terminal-entries', version: 2, entries }), { mode: 0o600 });
  const full = await openStore(f.root), before = await readFile(f.filename, 'utf8');
  await assert.rejects(full.upsert(config(f.root)), hasCode('TERMINAL_ENTRY_LIMIT'));
  assert.equal(await readFile(f.filename, 'utf8'), before); assert.equal((await full.list()).length, TERMINAL_ENTRY_LIMIT);
  assert.equal((await full.upsert(config(f.root, { cwd: entries[0].cwd }))).id, entries[0].id);
  assert.equal((await full.rename('profile_one', entries[0].id, 'Still usable')).name, 'Still usable');
  assert.equal((await (await openStore(f.root)).list()).length, TERMINAL_ENTRY_LIMIT);
});

test('legacy entries retain their stored order and upgrade only after an explicit mutation', async t => {
  const f = await fixture(t), initial = await openStore(f.root);
  const first = await initial.upsert(config(f.root));
  const second = await initial.upsert(config(f.root, { cwd: path.join(f.root, 'second') }));
  const entries = [second, first].map(({ pinned, ...entry }) => entry);
  const legacy = JSON.stringify({ schema: 'envara.terminal-entries', version: 1, entries });
  await writeFile(f.filename, legacy, { mode: 0o600 });
  const store = await openStore(f.root);
  assert.deepEqual(await store.list('profile_one'), entries.map(entry => ({ ...entry, pinned: false })));
  assert.equal(await readFile(f.filename, 'utf8'), legacy, 'reading a legacy file does not rewrite it');
  await store.setPinned('profile_one', first.id, true);
  const persisted = JSON.parse(await readFile(f.filename, 'utf8'));
  assert.equal(persisted.version, 2);
  assert.deepEqual(persisted.entries.map(entry => entry.id), [second.id, first.id], 'pinning retains the durable underlying order');
  assert.deepEqual((await (await openStore(f.root)).list('profile_one')).map(entry => [entry.id, entry.pinned]), [[first.id, true], [second.id, false]]);
});

test('pin groups and movement persist independently per environment without changing unrelated entries', async t => {
  const f = await fixture(t), store = await openStore(f.root);
  const add = (name, profileId = 'profile_one') => store.upsert(config(f.root, { profileId, name, cwd: path.join(f.root, name) }));
  const a = await add('a'), foreignA = await add('foreign-a', 'profile_two'), b = await add('b'), c = await add('c');
  const foreignB = await add('foreign-b', 'profile_two'), d = await add('d');
  await Promise.all([store.setPinned('profile_one', b.id, true), store.setPinned('profile_one', d.id, true)]);
  const ids = async () => (await store.list('profile_one')).map(entry => entry.id);
  assert.deepEqual(await ids(), [b.id, d.id, a.id, c.id]);
  await store.move('profile_one', d.id, 'up');
  await store.move('profile_one', c.id, 'up');
  assert.deepEqual(await ids(), [d.id, b.id, c.id, a.id]);
  assert.deepEqual(await store.list('profile_two'), [foreignA, foreignB]);
  const beforeBoundaries = await store.list();
  for (const [id, direction] of [[d.id, 'up'], [b.id, 'down'], [c.id, 'up'], [a.id, 'down']])
    await store.move('profile_one', id, direction);
  assert.deepEqual(await store.list(), beforeBoundaries, 'movement stops at each pin-group boundary');
  const returned = await store.setPinned('profile_one', b.id, false);
  returned.pinned = true; returned.networkRef.kind = 'managed';
  assert.deepEqual(await ids(), [d.id, c.id, a.id, b.id]);
  const reopened = await store.upsert(config(f.root, { name: 'ignored', cwd: path.join(f.root, 'd') }));
  assert.equal(reopened.pinned, true);
  await store.rename('profile_one', c.id, 'renamed without reordering');
  assert.deepEqual(await ids(), [d.id, c.id, a.id, b.id]);
  assert.deepEqual(await (await openStore(f.root)).list(), await store.list());
  const persisted = JSON.parse(await readFile(f.filename, 'utf8')).entries;
  assert.equal(persisted[1].id, foreignA.id); assert.equal(persisted[4].id, foreignB.id);
});

test('pin and move reject malformed, unknown and cross-environment requests without any writes', async t => {
  const f = await fixture(t), store = await openStore(f.root), entry = await store.upsert(config(f.root));
  const before = await readFile(f.filename, 'utf8');
  for (const pinned of [undefined, null, 0, 1, 'true', [], {}])
    await assert.rejects(async () => store.setPinned('profile_one', entry.id, pinned), hasCode('TERMINAL_ENTRY_INVALID'));
  for (const direction of [undefined, null, 0, 'UP', 'down ', [], {}])
    await assert.rejects(async () => store.move('profile_one', entry.id, direction), hasCode('TERMINAL_ENTRY_INVALID'));
  for (const method of ['setPinned', 'move']) {
    const value = method === 'setPinned' ? true : 'down';
    await assert.rejects(async () => store[method]('../outside', entry.id, value), hasCode('TERMINAL_ENTRY_INVALID'));
    await assert.rejects(async () => store[method]('profile_one', [entry.id, entry.id], value), hasCode('TERMINAL_ENTRY_INVALID'));
    await assert.rejects(store[method]('profile_two', entry.id, value), hasCode('TERMINAL_ENTRY_NOT_FOUND'));
    await assert.rejects(store[method]('profile_one', `savedterm_${'f'.repeat(32)}`, value), hasCode('TERMINAL_ENTRY_NOT_FOUND'));
  }
  assert.deepEqual(await store.list(), [entry]);
  assert.equal(await readFile(f.filename, 'utf8'), before);
});

test('failed pin and reorder saves retain both committed metadata and order and allow a later retry', async t => {
  const f = await fixture(t), store = await openStore(f.root);
  const first = await store.upsert(config(f.root)), second = await store.upsert(config(f.root, { cwd: path.join(f.root, 'second') }));
  const before = await readFile(f.filename, 'utf8'), save = store.save;
  store.save = async () => { throw Object.assign(new Error('Synthetic storage failure'), { code: 'EIO' }); };
  for (const operation of [() => store.setPinned('profile_one', second.id, true), () => store.move('profile_one', second.id, 'up')]) {
    await assert.rejects(operation(), { code: 'EIO' });
    assert.deepEqual(await store.list(), [first, second]);
    assert.equal(await readFile(f.filename, 'utf8'), before);
  }
  store.save = save;
  await store.move('profile_one', second.id, 'up');
  await store.setPinned('profile_one', second.id, true);
  assert.deepEqual((await (await openStore(f.root)).list()).map(entry => [entry.id, entry.pinned]), [[second.id, true], [first.id, false]]);
  assert.deepEqual((await readdir(f.root)).sort(), ['saved-terminals.json']);
});
