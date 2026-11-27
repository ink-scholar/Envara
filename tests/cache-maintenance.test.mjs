import nodeTest from 'node:test';
import { platformTest } from './support/platform-test.mjs';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, symlink, link, rm, chmod } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createCacheMaintenance } from '../electron/cache-maintenance.mjs';

// Moving and deleting cache files is verified by POSIX ownership. Windows has no
// user ID, so the service stays read-only there until an NTFS ACL check exists;
// these tests exercise the enabled service and run where it can be enabled.
const test = platformTest(['darwin', 'linux'], 'cache maintenance stays read-only on Windows until an NTFS ACL check exists');

async function fixture(t, options = {}) {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'envara-cache-maintenance-'));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const profile = path.join(dataDir, 'browseforge', 'profiles', 'fixture', 'browser-data');
  const cache = path.join(profile, 'Default', 'Cache');
  await mkdir(cache, { recursive: true, mode: 0o700 });
  await writeFile(path.join(cache, 'data_0'), 'regenerable fixture cache');
  const protectedNames = ['Default/Cookies', 'Default/History', 'Default/Login Data', 'Default/IndexedDB/pages',
    'Default/Local Storage/state', 'Default/Service Worker/CacheStorage/offline', 'Default/blob_storage/draft', 'bookmarks.json'];
  for (const name of protectedNames) { await mkdir(path.dirname(path.join(profile, name)), { recursive: true }); await writeFile(path.join(profile, name), `preserve ${name}`); }
  let busy = false, locked = false, onIdle = null;
  const lockEvents = [];
  const config = { dataDir, listProfiles: async () => [{ id: 'fixture', name: 'Fixture environment' }],
    assertProfileIdle: async id => { assert.equal(id, 'fixture'); await onIdle?.(); if (busy) throw Object.assign(new Error('busy'), { code: 'PROFILE_RUNNING' }); },
    withMaintenance: async (ids, operation) => { assert.deepEqual(ids, ['fixture']); assert.equal(locked, false); locked = true; lockEvents.push('acquire'); try { return await operation(); } finally { locked = false; lockEvents.push('release'); } }, ...options };
  const service = createCacheMaintenance(config);
  const select = async () => { const inventory = await service.inventory(); return { inventoryId: inventory.inventoryId, entryIds: inventory.entries.filter(item => item.status === 'ready').map(item => item.id) }; };
  const verifyProtected = async () => { for (const name of protectedNames) assert.equal(await readFile(path.join(profile, name), 'utf8'), `preserve ${name}`); };
  return { dataDir, profile, cache, config, service, select, verifyProtected, lockEvents, setBusy: value => { busy = value; }, setIdle: value => { onIdle = value; } };
}
const rejectsCode = (promise, code) => assert.rejects(promise, { code });

test('inventory is read only, has opaque IDs and only enumerates named browser caches', async t => {
  const f = await fixture(t);
  const before = await readdir(f.dataDir);
  const result = await f.service.inventory();
  assert.deepEqual(await readdir(f.dataDir), before);
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0].cacheName, 'Default/Cache');
  assert.equal(result.entries[0].status, 'ready');
  assert.ok(result.entries[0].bytes > 0);
  assert.ok(!JSON.stringify(result).includes(f.dataDir));
  assert.equal(result.batches.length, 0);
  await f.verifyProtected();
});

test('explicit selection moves only chosen cache into private recoverable storage and survives restart', async t => {
  const f = await fixture(t);
  await mkdir(path.join(f.profile, 'Default', 'Code Cache')); await writeFile(path.join(f.profile, 'Default', 'Code Cache', 'code'), 'keep unselected');
  const inventory = await f.service.inventory();
  const chosen = inventory.entries.find(item => item.cacheName === 'Default/Cache');
  const result = await f.service.quarantine({ inventoryId: inventory.inventoryId, entryIds: [chosen.id] });
  assert.equal(result.complete, true); assert.equal(result.moved, 1);
  await assert.rejects(lstat(f.cache), { code: 'ENOENT' });
  assert.equal(await readFile(path.join(f.profile, 'Default', 'Code Cache', 'code'), 'utf8'), 'keep unselected');
  const recovery = path.join(f.dataDir, 'cache-recovery');
  assert.equal((await lstat(recovery)).mode & 0o777, 0o700);
  const restarted = createCacheMaintenance(f.config);
  const next = await restarted.inventory();
  assert.equal(next.batches[0].id, result.batchId); assert.ok(next.batches[0].bytes > 0); assert.equal(next.batches[0].entryCount, 1);
  assert.deepEqual(f.lockEvents, ['acquire', 'release']);
  await f.verifyProtected();
});

test('restore copies exclusively, returns the cache and leaves account and offline files untouched', async t => {
  const f = await fixture(t);
  const { batchId } = await f.service.quarantine(await f.select());
  assert.deepEqual(await f.service.restore({ batchId }), { restored: 1, conflicts: 0, complete: true });
  assert.equal(await readFile(path.join(f.cache, 'data_0'), 'utf8'), 'regenerable fixture cache');
  const inventory = await f.service.inventory(); assert.equal(inventory.batches[0].entryCount, 0);
  await f.verifyProtected();
});

test('restore refuses a newly recreated cache even when it is empty and never overwrites new files', async t => {
  const f = await fixture(t);
  const { batchId } = await f.service.quarantine(await f.select());
  await mkdir(f.cache); await writeFile(path.join(f.cache, 'data_0'), 'new cache');
  assert.deepEqual(await f.service.restore({ batchId }), { restored: 0, conflicts: 1, complete: false });
  assert.equal(await readFile(path.join(f.cache, 'data_0'), 'utf8'), 'new cache');
  assert.equal((await f.service.inventory()).batches[0].entryCount, 1);
  await rm(path.join(f.cache, 'data_0'));
  assert.equal((await f.service.restore({ batchId })).conflicts, 1, 'an empty directory is also preserved');
});

test('purge requires explicit confirmation and removes only the selected recovery batch', async t => {
  const f = await fixture(t);
  const first = await f.service.quarantine(await f.select());
  await mkdir(f.cache); await writeFile(path.join(f.cache, 'second'), 'second fixture');
  const second = await f.service.quarantine(await f.select());
  await rejectsCode(f.service.purge({ batchId: first.batchId }), 'CACHE_DELETE_CONFIRMATION_REQUIRED');
  assert.deepEqual(await f.service.purge({ batchId: first.batchId, confirmed: true }), { deleted: true });
  assert.deepEqual((await f.service.inventory()).batches.map(item => item.id), [second.batchId]);
  await f.verifyProtected();
});

test('maintenance boundary is required; an absent callback allows only read-only inventory', async t => {
  const f = await fixture(t, { withMaintenance: undefined });
  const inventory = await f.service.inventory();
  assert.equal(inventory.maintenanceAvailable, false); assert.equal(inventory.entries[0].status, 'unavailable');
  await rejectsCode(f.service.quarantine({ inventoryId: inventory.inventoryId, entryIds: [inventory.entries[0].id] }), 'CACHE_MAINTENANCE_UNAVAILABLE');
  assert.equal(await readFile(path.join(f.cache, 'data_0'), 'utf8'), 'regenerable fixture cache');
});

test('a browser that becomes busy after inventory is refused under the maintenance reservation', async t => {
  const f = await fixture(t); const selection = await f.select(); f.setBusy(true);
  await rejectsCode(f.service.quarantine(selection), 'PROFILE_RUNNING');
  assert.deepEqual(f.lockEvents, ['acquire', 'release']);
  assert.equal((await f.service.inventory()).entries[0].status, 'busy');
  await assert.rejects(lstat(path.join(f.dataDir, 'cache-recovery')), { code: 'ENOENT' });
});

test('a browser singleton lock is uncertain and is never removed or treated as stopped', async t => {
  const f = await fixture(t); const selection = await f.select();
  await symlink('/nonexistent-fixture-owner', path.join(f.profile, 'SingletonLock'));
  await rejectsCode(f.service.quarantine(selection), 'CACHE_PROFILE_BUSY');
  assert.equal((await lstat(path.join(f.profile, 'SingletonLock'))).isSymbolicLink(), true);
  await f.verifyProtected();
});

test('stale scan, stale ticket, arbitrary paths, duplicate IDs and unselected items cannot authorize cleanup', async t => {
  const f = await fixture(t); const selection = await f.select();
  await writeFile(path.join(f.cache, 'new'), 'created after inventory');
  await rejectsCode(f.service.quarantine(selection), 'CACHE_INVENTORY_STALE');
  await f.service.inventory();
  await rejectsCode(f.service.quarantine(selection), 'CACHE_INVENTORY_STALE');
  const fresh = await f.select();
  await rejectsCode(f.service.quarantine({ ...fresh, entryIds: [...fresh.entryIds, ...fresh.entryIds] }), 'INVALID_CACHE_MAINTENANCE_REQUEST');
  await rejectsCode(f.service.quarantine({ ...fresh, path: f.cache }), 'INVALID_CACHE_MAINTENANCE_REQUEST');
  await rejectsCode(f.service.restore({ batchId: '../outside' }), 'INVALID_CACHE_MAINTENANCE_REQUEST');
  await rejectsCode(f.service.inventory({ root: f.dataDir }), 'INVALID_CACHE_MAINTENANCE_REQUEST');
});

test('linked cache leaves, linked ancestors and linked descendants are all refused without following them', async t => {
  const f = await fixture(t);
  const outside = path.join(f.dataDir, 'outside'); await mkdir(outside); await writeFile(path.join(outside, 'keep'), 'outside');
  const selection = await f.select(); await rm(f.cache, { recursive: true }); await symlink(outside, f.cache);
  await rejectsCode(f.service.quarantine(selection), 'CACHE_PATH_UNSAFE');
  assert.equal((await f.service.inventory()).entries[0].status, 'unsafe');
  await rm(f.cache); await mkdir(f.cache); await symlink(outside, path.join(f.cache, 'linked-child'));
  assert.equal((await f.service.inventory()).entries[0].status, 'unsafe');
  await rm(f.cache, { recursive: true });
  await rm(path.join(f.profile, 'Default'), { recursive: true }); await symlink(outside, path.join(f.profile, 'Default'));
  const inventory = await f.service.inventory();
  assert.ok(inventory.entries.filter(item => item.cacheName.startsWith('Default/')).every(item => item.status === 'unsafe'));
  assert.equal(await readFile(path.join(outside, 'keep'), 'utf8'), 'outside');
});

test('hard-linked data and writable shared paths are refused', async t => {
  const f = await fixture(t); await link(path.join(f.cache, 'data_0'), path.join(f.dataDir, 'hardlink'));
  assert.equal((await f.service.inventory()).entries[0].status, 'unsafe');
  await rm(path.join(f.dataDir, 'hardlink')); await chmod(f.cache, 0o777);
  assert.equal((await f.service.inventory()).entries[0].status, 'unsafe');
});

test('rechecks immediately before moving retain a partial batch after a later candidate changes', async t => {
  const f = await fixture(t);
  await mkdir(path.join(f.profile, 'Default', 'Code Cache')); await writeFile(path.join(f.profile, 'Default', 'Code Cache', 'code'), 'second');
  const selection = await f.select(); let checks = 0;
  f.setIdle(async () => {
    if (++checks === 3) { await rm(path.join(f.profile, 'Default', 'Code Cache'), { recursive: true }); await mkdir(path.join(f.profile, 'Default', 'Code Cache')); await writeFile(path.join(f.profile, 'Default', 'Code Cache', 'code'), 'changed'); }
  });
  const result = await f.service.quarantine(selection);
  assert.equal(result.complete, false); assert.equal(result.moved, 1);
  assert.equal((await f.service.inventory()).batches[0].entryCount, 1);
  assert.equal(await readFile(path.join(f.profile, 'Default', 'Code Cache', 'code'), 'utf8'), 'changed');
});

test('malicious recovery manifest paths and recovery symlinks cannot restore or purge outside data', async t => {
  const f = await fixture(t); const { batchId } = await f.service.quarantine(await f.select());
  const manifestPath = path.join(f.dataDir, 'cache-recovery', batchId, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath)); manifest.entries[0].cacheName = '../Cookies';
  await writeFile(manifestPath, JSON.stringify(manifest));
  await rejectsCode(f.service.restore({ batchId }), 'CACHE_BATCH_INVALID');
  await rejectsCode(f.service.purge({ batchId, confirmed: true }), 'CACHE_BATCH_INVALID');
  manifest.entries[0].cacheName = 'Default/Cache'; await writeFile(manifestPath, JSON.stringify(manifest));
  const payload = path.join(f.dataDir, 'cache-recovery', batchId, manifest.entries[0].id, 'data');
  await rm(payload, { recursive: true }); await symlink(f.profile, payload);
  await rejectsCode(f.service.purge({ batchId, confirmed: true }), 'CACHE_PATH_UNSAFE');
  await f.verifyProtected();
});

test('bounded scans do not authorize partial estimates and refused leases perform no mutation', async t => {
  const f = await fixture(t, { maxEntries: 1 });
  assert.equal((await f.service.inventory()).entries[0].status, 'unsafe');
  const refusing = createCacheMaintenance({ ...f.config, maxEntries: 100, withMaintenance: async () => { throw Object.assign(new Error('live browser'), { code: 'PROFILE_RUNNING' }); } });
  const inventory = await refusing.inventory();
  await rejectsCode(refusing.quarantine({ inventoryId: inventory.inventoryId, entryIds: [inventory.entries[0].id] }), 'PROFILE_RUNNING');
  await assert.rejects(lstat(path.join(f.dataDir, 'cache-recovery')), { code: 'ENOENT' });
});

test('same service serializes concurrent requests; one stale selection cannot move twice', async t => {
  const f = await fixture(t); const selection = await f.select();
  const results = await Promise.allSettled([f.service.quarantine(selection), f.service.quarantine(selection)]);
  assert.equal(results[0].status, 'fulfilled'); assert.equal(results[1].reason.code, 'CACHE_INVENTORY_STALE');
  assert.equal((await f.service.inventory()).batches.length, 1);
});

test('restoration rejects a substituted ancestor and preserves the recovery copy and outside files', async t => {
  const f = await fixture(t); const { batchId } = await f.service.quarantine(await f.select());
  const outside = path.join(f.dataDir, 'outside'); await mkdir(outside); await writeFile(path.join(outside, 'keep'), 'outside');
  await rm(path.join(f.profile, 'Default'), { recursive: true }); await symlink(outside, path.join(f.profile, 'Default'));
  await rejectsCode(f.service.restore({ batchId }), 'CACHE_RESTORE_INCOMPLETE');
  assert.deepEqual(await readdir(outside), ['keep']);
  assert.equal((await f.service.inventory()).batches[0].entryCount, 1);
});

test('a substituted recovery root is never followed for listing, restoration or deletion', async t => {
  const f = await fixture(t); const { batchId } = await f.service.quarantine(await f.select());
  const recovery = path.join(f.dataDir, 'cache-recovery'); await rm(recovery, { recursive: true }); await symlink(f.profile, recovery);
  await rejectsCode(f.service.inventory(), 'CACHE_PATH_UNSAFE');
  await rejectsCode(f.service.restore({ batchId }), 'CACHE_PATH_UNSAFE');
  await rejectsCode(f.service.purge({ batchId, confirmed: true }), 'CACHE_PATH_UNSAFE');
  await f.verifyProtected();
});

test('legacy layout uses only its owned browser cache and cannot restore a different layout batch', async t => {
  const f = await fixture(t);
  const legacyCache = path.join(f.dataDir, 'profiles', 'fixture', 'Default', 'Cache');
  await mkdir(legacyCache, { recursive: true }); await writeFile(path.join(legacyCache, 'legacy'), 'legacy cache');
  const legacy = createCacheMaintenance({ ...f.config, layout: 'legacy' });
  const inventory = await legacy.inventory(); assert.equal(inventory.entries.length, 1);
  const { batchId } = await legacy.quarantine({ inventoryId: inventory.inventoryId, entryIds: [inventory.entries[0].id] });
  assert.equal(await readFile(path.join(f.cache, 'data_0'), 'utf8'), 'regenerable fixture cache');
  await rejectsCode(f.service.restore({ batchId }), 'CACHE_BATCH_INVALID');
  assert.equal((await legacy.restore({ batchId })).restored, 1);
  assert.equal(await readFile(path.join(legacyCache, 'legacy'), 'utf8'), 'legacy cache');
});

test('requests reject non-plain objects, getters and unknown confirmation fields without invoking accessors', async t => {
  const f = await fixture(t); let read = false;
  for (const args of [null, [], new Date(), 'path', 1, { get batchId() { read = true; return 'x'; } }, { batchId: 'x', path: '/outside' }])
    await rejectsCode(f.service.restore(args), 'INVALID_CACHE_MAINTENANCE_REQUEST');
  assert.equal(read, false);
});

test('unverified filesystem ownership keeps inventory read-only, including permanent deletion', async t => {
  const f = await fixture(t); const { batchId } = await f.service.quarantine(await f.select());
  const readonly = createCacheMaintenance({ ...f.config, uid: null });
  assert.equal((await readonly.inventory()).maintenanceAvailable, false);
  await rejectsCode(readonly.restore({ batchId }), 'CACHE_MAINTENANCE_UNAVAILABLE');
  await rejectsCode(readonly.purge({ batchId, confirmed: true }), 'CACHE_MAINTENANCE_UNAVAILABLE');
  assert.equal((await f.service.inventory()).batches[0].entryCount, 1);
});

nodeTest('on Windows the service lists caches but never moves, restores or deletes them', { skip: process.platform !== 'win32' && 'Windows behavior' }, async t => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'envara-cache-maintenance-'));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  const cache = path.join(dataDir, 'browseforge', 'profiles', 'fixture', 'browser-data', 'Default', 'Cache');
  await mkdir(cache, { recursive: true }); await writeFile(path.join(cache, 'data_0'), 'regenerable fixture cache');
  const service = createCacheMaintenance({ dataDir, listProfiles: async () => [{ id: 'fixture', name: 'Fixture environment' }],
    assertProfileIdle: async () => {}, withMaintenance: async (_ids, operation) => operation() });
  const inventory = await service.inventory();
  assert.equal(inventory.maintenanceAvailable, false); assert.equal(inventory.purgeAvailable, false);
  assert.deepEqual(inventory.entries.map(item => [item.cacheName, item.status]), [['Default/Cache', 'unavailable']]);
  await rejectsCode(service.quarantine({ inventoryId: inventory.inventoryId, entryIds: inventory.entries.map(item => item.id) }), 'CACHE_MAINTENANCE_UNAVAILABLE');
  assert.equal(await readFile(path.join(cache, 'data_0'), 'utf8'), 'regenerable fixture cache');
});
