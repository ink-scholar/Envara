import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readdir, symlink, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pruneAttachedApplicationCache, attachedApplicationDataInventory, eraseEnvironmentData } from '../electron/application-data.mjs';

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

test('stopping keeps sign-in state and removes only regenerable caches, at the root and in every partition', async t => {
  const { root, data, partition, uid } = await fixture(t);
  const freed = await pruneAttachedApplicationCache({ environmentId, registrationId, root, uid, platform: 'darwin' });
  assert.ok(freed >= 320 * 1024, 'the removed caches are reported as freed');
  assert.deepEqual((await readdir(data)).sort(), ['Cookies', 'Local Storage', 'Partitions']);
  assert.deepEqual((await readdir(partition)).sort(), ['Cookies', 'IndexedDB', 'Local Storage']);
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

test('an emptied sign-in folder measures zero, so it is not listed as sign-in data', async t => {
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
  await writeFile(path.join(leaf, 'Default', 'Cookies'), 'x'.repeat(5000));
  assert.ok(await measure() >= 5000);
});
