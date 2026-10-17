import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import * as filesystem from 'node:fs/promises';
import { LinkPreferences } from '../electron/link-preferences.mjs';

const defaults = { openInEnvironment: true, declinedAt: null };
const timestamp = '2026-10-17T00:00:00.000Z';
async function fixture(t, io = filesystem) {
  const root = await filesystem.mkdtemp(path.join(os.tmpdir(), 'envara-link-preferences-'));
  t.after(() => filesystem.rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'link-preferences.json');
  return { root, file, store: new LinkPreferences({ file, filesystem: io }) };
}
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('legacy preferences and defaults load without rewriting the source', async t => {
  for (const [name, saved, expected] of [
    ['missing', null, defaults],
    ['malformed', '{', defaults],
    ['existing', JSON.stringify({ openInEnvironment: false, declinedAt: 'legacy-value', ignored: 'not retained' }), { openInEnvironment: false, declinedAt: 'legacy-value' }],
    ['partial', JSON.stringify({ openInEnvironment: 0, declinedAt: false }), defaults],
    ['null', 'null', defaults],
  ]) await t.test(name, async subtest => {
    const f = await fixture(subtest);
    if (saved !== null) await filesystem.writeFile(f.file, saved);
    assert.deepEqual(await f.store.load(), expected);
    assert.deepEqual(f.store.snapshot(), expected);
    if (saved === null) await assert.rejects(filesystem.access(f.file), { code: 'ENOENT' });
    else assert.equal(await filesystem.readFile(f.file, 'utf8'), saved);
  });
});

test('a patch loads existing fields, commits a private file and returns a detached snapshot', async t => {
  const f = await fixture(t);
  await filesystem.writeFile(f.file, JSON.stringify({ ...defaults, declinedAt: timestamp }));
  const value = await f.store.patch({ openInEnvironment: false });
  assert.deepEqual(value, { openInEnvironment: false, declinedAt: timestamp });
  value.declinedAt = null;
  const snapshot = f.store.snapshot(); snapshot.openInEnvironment = true;
  assert.deepEqual(f.store.snapshot(), { openInEnvironment: false, declinedAt: timestamp });
  assert.deepEqual(JSON.parse(await filesystem.readFile(f.file, 'utf8')), f.store.snapshot());
  if (process.platform !== 'win32') assert.equal((await filesystem.stat(f.file)).mode & 0o777, 0o600);
  assert.deepEqual(await filesystem.readdir(f.root), ['link-preferences.json']);
});

for (const operation of ['writeFile', 'rename']) test(`${operation} failure preserves disk and memory, removes staging and permits retry`, async t => {
  let reject = true;
  const io = { ...filesystem, [operation]: async (...args) => {
    if (reject) {
      if (operation === 'writeFile') await filesystem.writeFile(...args);
      throw Object.assign(new Error('private-endpoint-or-token-must-not-escape'), { code: 'EIO' });
    }
    return filesystem[operation](...args);
  } };
  const f = await fixture(t, io), original = JSON.stringify(defaults) + '\n';
  await filesystem.writeFile(f.file, original);
  await f.store.load();
  await assert.rejects(f.store.patch({ openInEnvironment: false }), error => error.code === 'LINK_PREFERENCES_SAVE_FAILED'
    && !error.message.includes('private-endpoint-or-token'));
  assert.deepEqual(f.store.snapshot(), defaults);
  assert.equal(await filesystem.readFile(f.file, 'utf8'), original);
  assert.deepEqual(await filesystem.readdir(f.root), ['link-preferences.json']);
  reject = false;
  assert.deepEqual(await f.store.patch({ declinedAt: timestamp }), { ...defaults, declinedAt: timestamp });
  assert.deepEqual(JSON.parse(await filesystem.readFile(f.file, 'utf8')), { ...defaults, declinedAt: timestamp });
});

test('concurrent patches merge after the prior atomic commit and never expose pending state', async t => {
  const entered = deferred(), proceed = deferred(); let calls = 0;
  const f = await fixture(t, { ...filesystem, rename: async (...args) => {
    if (++calls === 1) { entered.resolve(); await proceed.promise; }
    return filesystem.rename(...args);
  } });
  const first = f.store.patch({ openInEnvironment: false });
  await entered.promise;
  const second = f.store.patch({ declinedAt: timestamp });
  assert.deepEqual(f.store.snapshot(), defaults);
  await assert.rejects(filesystem.access(f.file), { code: 'ENOENT' });
  proceed.resolve();
  assert.deepEqual(await first, { openInEnvironment: false, declinedAt: null });
  assert.deepEqual(await second, { openInEnvironment: false, declinedAt: timestamp });
  assert.deepEqual(JSON.parse(await filesystem.readFile(f.file, 'utf8')), f.store.snapshot());
});

test('a queued patch ignores a failed update and late load cannot overwrite committed state', async t => {
  let first = true;
  const f = await fixture(t, { ...filesystem, rename: async (...args) => {
    if (first) { first = false; throw Object.assign(new Error('fixture'), { code: 'EIO' }); }
    return filesystem.rename(...args);
  } });
  const failed = assert.rejects(f.store.patch({ openInEnvironment: false }), { code: 'LINK_PREFERENCES_SAVE_FAILED' });
  const success = f.store.patch({ declinedAt: timestamp });
  await failed;
  assert.deepEqual(await success, { ...defaults, declinedAt: timestamp });
  assert.deepEqual(await f.store.load(), { ...defaults, declinedAt: timestamp });
});

test('only preference fields and timestamps can be persisted', async t => {
  const f = await fixture(t);
  for (const patch of [null, [], { openInEnvironment: 0 }, { declinedAt: 'https://private.invalid/token' },
    { declinedAt: '2026-02-30T00:00:00.000Z' }, { url: 'https://private.invalid/' }, { token: 'fixture' }]) {
    await assert.rejects(f.store.patch(patch), { code: 'LINK_PREFERENCES_INVALID' });
  }
  assert.deepEqual(f.store.snapshot(), defaults);
  assert.deepEqual(await filesystem.readdir(f.root), []);
});

test('cleanup failure cannot misreport a successful rename or hide the persistence error', async t => {
  let renameFails = true;
  const f = await fixture(t, { ...filesystem,
    rename: async (...args) => { if (renameFails) throw Object.assign(new Error('primary'), { code: 'EIO' }); return filesystem.rename(...args); },
    rm: async (...args) => { await filesystem.rm(...args); throw Object.assign(new Error('cleanup'), { code: 'EIO' }); },
  });
  await assert.rejects(f.store.patch({ openInEnvironment: false }), { code: 'LINK_PREFERENCES_SAVE_FAILED' });
  assert.deepEqual(f.store.snapshot(), defaults);
  renameFails = false;
  assert.deepEqual(await f.store.patch({ declinedAt: timestamp }), { ...defaults, declinedAt: timestamp });
  assert.deepEqual(JSON.parse(await filesystem.readFile(f.file, 'utf8')), f.store.snapshot());
});
