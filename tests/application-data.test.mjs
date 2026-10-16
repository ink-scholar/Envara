import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, symlink, rm, rename } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { APPLICATION_DATA_DIRECTORIES, pruneAttachedApplicationCache, attachedApplicationDataInventory, eraseEnvironmentData } from '../electron/application-data.mjs';

const environmentId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', registrationId = 'ffffffff-1111-4222-8333-444444444444';
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-app-cache-')); t.after(() => rm(root, { recursive: true, force: true }));
  const data = path.join(root, environmentId, registrationId, 'UserData'), partition = path.join(data, 'Partitions', 'notion');
  for (const dir of [path.join(data, 'Cache'), path.join(data, 'Local Storage'), path.join(partition, 'Service Worker', 'CacheStorage'),
    path.join(partition, 'Cache'), path.join(partition, 'IndexedDB'), path.join(partition, 'Local Storage')]) await mkdir(dir, { recursive: true });
  await writeFile(path.join(data, 'Cookies'), 'session');
  await writeFile(path.join(data, 'Cache', 'data_0'), Buffer.alloc(64 * 1024));
  await writeFile(path.join(partition, 'Service Worker', 'CacheStorage', 'bundle.js'), Buffer.alloc(256 * 1024));
  await writeFile(path.join(partition, 'Cookies'), 'session');
  await writeFile(path.join(partition, 'IndexedDB', 'db'), 'pages');
  return { root, data, partition, uid: process.getuid() };
}

test('stopping keeps sign-in and offline documents, removing only known caches at the root and in every partition', async t => {
  const { root, data, partition, uid } = await fixture(t);
  await mkdir(path.join(partition, 'blob_storage'));
  await writeFile(path.join(partition, 'blob_storage', 'draft'), 'offline draft');
  const freed = await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid, platform: 'darwin' });
  assert.ok(freed >= 64 * 1024 && freed < 256 * 1024, 'only the regenerable cache is reported as freed');
  assert.deepEqual((await readdir(data)).sort(), ['Cookies', 'Local Storage', 'Partitions']);
  assert.deepEqual((await readdir(partition)).sort(), ['Cookies', 'IndexedDB', 'Local Storage', 'Service Worker', 'blob_storage']);
  assert.equal(await readFile(path.join(partition, 'blob_storage', 'draft'), 'utf8'), 'offline draft');
  assert.equal((await readFile(path.join(partition, 'Service Worker', 'CacheStorage', 'bundle.js'))).length, 256 * 1024);
  assert.equal(await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid, platform: 'darwin' }), 0, 'nothing left to free');
});

test('pruning never follows a link, touches another user\'s data, or accepts a malformed id', async t => {
  const { root, data, uid } = await fixture(t);
  const outside = await mkdtemp(path.join(os.tmpdir(), 'envara-outside-')); t.after(() => rm(outside, { recursive: true, force: true }));
  await writeFile(path.join(outside, 'keep'), 'outside');
  await rm(path.join(data, 'Cache'), { recursive: true }); await symlink(outside, path.join(data, 'Cache'));
  await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid, platform: 'darwin' });
  assert.deepEqual(await readdir(outside), ['keep'], 'a linked cache is left alone');
  assert.equal(await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid: uid + 1, platform: 'darwin' }), 0);
  assert.equal(await pruneAttachedApplicationCache({ environmentId: '../x', registrationId, root, uid, platform: 'darwin' }), 0);
  assert.equal(await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid, platform: 'linux' }), 0);
});

test('the inventory lists each environment and application with its size, and one can be cleared alone', async t => {
  const { root, uid } = await fixture(t);
  const other = '11111111-2222-4333-8444-555555555555';
  await mkdir(path.join(root, environmentId, other, 'UserData'), { recursive: true });
  await writeFile(path.join(root, environmentId, other, 'UserData', 'Cookies'), 'other');
  await mkdir(path.join(root, 'not-an-environment', registrationId, 'UserData'), { recursive: true });
  const items = await attachedApplicationDataInventory({ root, uid, platform: 'darwin' });
  assert.deepEqual(items.map(item => item.registrationId).sort(), [other, registrationId].sort());
  assert.ok(items.every(item => item.environmentId === environmentId && item.bytes > 0 && typeof item.modifiedAt === 'string'));
  assert.deepEqual(await eraseEnvironmentData(environmentId, { registrationId: other, root, uid, platform: 'darwin' }), [other]);
  assert.deepEqual(await readdir(path.join(root, environmentId, other, 'UserData')), []);
  assert.ok((await readdir(path.join(root, environmentId, registrationId, 'UserData'))).includes('Cookies'), 'the other application keeps its sign-in data');
});

test('an empty owned application folder measures zero but still has a real environment data scope', async t => {
  const { mkdtemp, mkdir, writeFile, rm } = await import('node:fs/promises');
  const os = await import('node:os'); const path = await import('node:path');
  const { attachedApplicationDataInventory } = await import('../electron/application-data.mjs');
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-signin-size-')); t.after(() => rm(root, { recursive: true, force: true }));
  const environment = '11111111-2222-4333-8444-555555555555', registration = '66666666-7777-4888-9999-000000000000';
  const leaf = path.join(root, environment, registration, 'UserData');
  await mkdir(path.join(leaf, 'Default'), { recursive: true });
  const measure = async () => (await attachedApplicationDataInventory({ root, uid: process.getuid(), platform: 'darwin' }))[0]?.bytes;
  // Folders alone are the layout, not data: after the data is erased nothing is left to list.
  assert.equal(await measure(), 0);
  const [empty] = await attachedApplicationDataInventory({ root, uid: process.getuid(), platform: 'darwin' });
  assert.equal(empty.dataScope, 'environment');
  assert.equal(empty.hasDataDirectory, true);
  await writeFile(path.join(leaf, 'Default', 'Cookies'), 'x'.repeat(5000));
  assert.ok(await measure() >= 5000);
});

test('inventory aggregates all five owned leaves and explicit erasure empties each while keeping layout and unknown siblings', async t => {
  const { root, uid } = await fixture(t);
  const registration = path.join(root, environmentId, registrationId);
  for (const name of APPLICATION_DATA_DIRECTORIES) {
    await mkdir(path.join(registration, name), { recursive: true });
    await writeFile(path.join(registration, name, 'owned-content'), Buffer.alloc(8192, name[0]));
  }
  await mkdir(path.join(registration, 'NotManaged'));
  await writeFile(path.join(registration, 'NotManaged', 'keep'), 'unknown sibling');
  const [item] = await attachedApplicationDataInventory({ root, uid, platform: 'darwin' });
  assert.ok(item.bytes >= 320 * 1024 + 5 * 8192);
  assert.equal(item.hasDataDirectory, true);
  assert.deepEqual(await eraseEnvironmentData(environmentId, { registrationId, root, uid, platform: 'darwin' }), [registrationId]);
  for (const name of APPLICATION_DATA_DIRECTORIES) assert.deepEqual(await readdir(path.join(registration, name)), []);
  assert.equal(await readFile(path.join(registration, 'NotManaged', 'keep'), 'utf8'), 'unknown sibling');
  const [cleared] = await attachedApplicationDataInventory({ root, uid, platform: 'darwin' });
  assert.equal(cleared.bytes, 0);
  assert.equal(cleared.dataScope, 'environment');
});

test('pruning does not touch isolated home, extensions, temp, or unknown cache content', async t => {
  const { root, uid } = await fixture(t);
  const registration = path.join(root, environmentId, registrationId);
  for (const name of ['Home', 'Extensions', 'Temp', 'Cache']) {
    await mkdir(path.join(registration, name, 'Cache'), { recursive: true });
    await writeFile(path.join(registration, name, 'keep'), 'application content');
    await writeFile(path.join(registration, name, 'Cache', 'payload'), 'cache-shaped content');
  }
  await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid, platform: 'darwin' });
  for (const name of ['Home', 'Extensions', 'Temp', 'Cache'])
    assert.equal(await readFile(path.join(registration, name, 'keep'), 'utf8'), 'application content');
  for (const name of ['Home', 'Extensions', 'Temp'])
    assert.equal(await readFile(path.join(registration, name, 'Cache', 'payload'), 'utf8'), 'cache-shaped content');
  assert.deepEqual(await readdir(path.join(registration, 'Cache')), ['keep']);
});

test('missing owned leaves produce no inventory or successful erasure', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-app-empty-')); t.after(() => rm(root, { recursive: true, force: true }));
  const options = { root, uid: process.getuid(), platform: 'darwin' };
  await mkdir(path.join(root, environmentId, registrationId, 'Unknown'), { recursive: true });
  assert.deepEqual(await attachedApplicationDataInventory(options), []);
  assert.deepEqual(await eraseEnvironmentData(environmentId, { ...options, registrationId }), []);
});

test('root, environment, registration and data leaf symlinks are never traversed', async t => {
  for (const level of ['root', 'environment', 'registration', 'leaf']) await t.test(level, async t => {
    const { root, data, uid } = await fixture(t);
    const target = level === 'root' ? root : level === 'environment' ? path.join(root, environmentId)
      : level === 'registration' ? path.join(root, environmentId, registrationId) : data;
    const outside = `${target}-outside`;
    await rename(target, outside);
    t.after(() => rm(outside, { recursive: true, force: true }));
    await symlink(outside, target);
    const options = { root, uid, platform: 'darwin' };
    assert.deepEqual(await attachedApplicationDataInventory(options), []);
    assert.equal(await pruneAttachedApplicationCache({ ...options, environmentId, registrationId }), 0);
    if (['registration', 'leaf'].includes(level))
      await assert.rejects(eraseEnvironmentData(environmentId, { ...options, registrationId }), { code: 'APPLICATION_DATA_NOT_CLEARED' });
    else assert.deepEqual(await eraseEnvironmentData(environmentId, { ...options, registrationId }), []);
    assert.equal(await readFile(path.join(data, 'Cookies'), 'utf8'), 'session', 'the external target has not been erased');
  });
});

test('explicit erase unlinks data symlinks without following them and refuses mixed unsafe owned leaves before deletion', async t => {
  const { root, data, uid } = await fixture(t);
  const outside = path.join(root, 'outside');
  await mkdir(outside); await writeFile(path.join(outside, 'keep'), 'external');
  await symlink(outside, path.join(data, 'external'));
  const options = { root, uid, platform: 'darwin', registrationId };
  await eraseEnvironmentData(environmentId, options);
  assert.equal(await readFile(path.join(outside, 'keep'), 'utf8'), 'external');
  await writeFile(path.join(data, 'Cookies'), 'new session');
  await symlink(outside, path.join(path.dirname(data), 'Home'));
  await assert.rejects(eraseEnvironmentData(environmentId, options), error =>
    error.code === 'APPLICATION_DATA_NOT_CLEARED' && error.incomplete.includes(registrationId));
  assert.equal(await readFile(path.join(data, 'Cookies'), 'utf8'), 'new session', 'safe leaves survive a refused registration');
});

test('foreign-owned leaves are excluded from inventory and cannot be reported erased', async t => {
  const { root, data, uid } = await fixture(t);
  const fs = { readdir, rm, lstat: async target => {
    const info = await lstat(target);
    return target === data ? Object.assign(info, { uid: uid + 1 }) : info;
  } };
  const options = { root, uid, platform: 'darwin', fs };
  assert.deepEqual(await attachedApplicationDataInventory(options), []);
  assert.equal(await pruneAttachedApplicationCache({ ...options, environmentId, registrationId }), 0);
  await assert.rejects(eraseEnvironmentData(environmentId, { ...options, registrationId }), { code: 'APPLICATION_DATA_NOT_CLEARED' });
  assert.equal(await readFile(path.join(data, 'Cookies'), 'utf8'), 'session');
});

test('a failed leaf removal reports incomplete cleanup and never claims the registration was erased', async t => {
  const { root, data, uid } = await fixture(t);
  const fs = { readdir, lstat, rm: async (target, options) => {
    if (target === path.join(data, 'Cookies')) throw Object.assign(new Error('denied'), { code: 'EACCES' });
    return rm(target, options);
  } };
  await assert.rejects(eraseEnvironmentData(environmentId, { registrationId, root, uid, platform: 'darwin', fs }), error => {
    assert.equal(error.code, 'APPLICATION_DATA_NOT_CLEARED');
    assert.deepEqual(error.erased, []);
    assert.deepEqual(error.incomplete, [registrationId]);
    return true;
  });
});
