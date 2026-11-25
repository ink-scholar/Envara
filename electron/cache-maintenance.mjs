import path from 'node:path';
import { constants } from 'node:fs';
import { lstat, readdir, realpath, mkdir, open, rename, rm } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import { accessibleByOthers } from './file-trust.mjs';

// Deliberately narrower than complete profile exports or application-data cleanup.
// No Cookies, History, Local Storage, IndexedDB, Service Worker or blob_storage.
export const BROWSER_REGENERABLE_CACHES = Object.freeze([
  'Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache',
  'GraphiteDawnCache', 'GrShaderCache', 'ShaderCache', 'BrowseForgeRuntimeCache',
  'Default/Cache', 'Default/Code Cache', 'Default/GPUCache', 'Default/DawnCache',
  'Default/DawnGraphiteCache', 'Default/DawnWebGPUCache', 'Default/GraphiteDawnCache',
  'Default/GrShaderCache', 'Default/ShaderCache', 'cache2', 'startupCache',
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROFILE = /^[A-Za-z0-9_-]{1,96}$/;
const CACHE_SET = new Set(BROWSER_REGENERABLE_CACHES);
const LIMIT = 50000;
const failure = (code) => Object.assign(new Error(code), { code });
const missing = error => error?.code === 'ENOENT';
const identity = info => `${info.dev}:${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`;
function request(value, keys) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).some(key => typeof key !== 'string' || !keys.includes(key) || !('value' in Object.getOwnPropertyDescriptor(value, key))))
    throw failure('INVALID_CACHE_MAINTENANCE_REQUEST');
}
function identifier(value) { if (typeof value !== 'string' || !UUID.test(value)) throw failure('INVALID_CACHE_MAINTENANCE_REQUEST'); return value; }
function profileId(value) { if (typeof value !== 'string' || !PROFILE.test(value)) throw failure('CACHE_PATH_UNSAFE'); return value; }
function safeStat(info, uid, directory = false) {
  if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile()) || directory && !info.isDirectory() ||
      uid != null && (info.uid !== uid || info.mode & 0o022) || info.isFile() && info.nlink !== 1)
    throw failure('CACHE_PATH_UNSAFE');
}

/** Main-process-only service. listProfiles supplies known IDs, never renderer paths.
 * withMaintenance MUST reserve every profile at the browser manager's launch gate,
 * across REST/MCP/desktop launches, until operation settles. A JS queue alone is
 * insufficient. assertProfileIdle also rejects uncertain/pending cleanup states.
 * No missing boundary silently becomes permission to modify a browser profile.
 */
export function createCacheMaintenance({ dataDir, profilesRoot, layout = 'browseforge', listProfiles,
  assertProfileIdle, withMaintenance, uid = process.getuid?.(), now = () => new Date(), maxEntries = LIMIT } = {}) {
  if (!path.isAbsolute(dataDir ?? '') || !['browseforge', 'legacy'].includes(layout) || typeof listProfiles !== 'function')
    throw failure('INVALID_CACHE_MAINTENANCE_CONFIGURATION');
  const configuredRoot = path.resolve(profilesRoot ?? path.join(dataDir, ...(layout === 'browseforge' ? ['browseforge'] : []), 'profiles'));
  const rootRelative = path.relative(path.resolve(dataDir), configuredRoot);
  if (!rootRelative || rootRelative.startsWith(`..${path.sep}`) || rootRelative === '..' || path.isAbsolute(rootRelative))
    throw failure('INVALID_CACHE_MAINTENANCE_CONFIGURATION');
  const scope = createHash('sha256').update(`${layout}\0${rootRelative}`).digest('hex');
  // POSIX ownership is the current verified permission boundary. Platforms
  // without a user ID stay read-only until an equivalent ACL check is supplied.
  const available = Number.isInteger(uid) && typeof withMaintenance === 'function' && typeof assertProfileIdle === 'function';
  let ticket = null, queue = Promise.resolve();
  const serialized = operation => { const result = queue.then(operation); queue = result.catch(() => {}); return result; };

  async function root() {
    // Canonicalize OS aliases above this trusted application root (e.g. /var).
    safeStat(await lstat(dataDir), uid, true);
    return realpath(dataDir);
  }
  async function checked(base, relative, { optional = false, directory = true } = {}) {
    if (path.isAbsolute(relative) || relative.split(path.sep).some(p => p === '..' || p === '.')) throw failure('CACHE_PATH_UNSAFE');
    let target = base;
    safeStat(await lstat(base), uid, true);
    const parts = relative ? relative.split(path.sep) : [];
    for (let i = 0; i < parts.length; i++) {
      target = path.join(target, parts[i]);
      let info;
      try { info = await lstat(target); } catch (error) { if (optional && missing(error)) return null; throw error; }
      safeStat(info, uid, i < parts.length - 1 || directory);
    }
    if (await realpath(target) !== target) throw failure('CACHE_PATH_UNSAFE');
    return target;
  }
  const sourceRelative = item => path.join(rootRelative, profileId(item.profileId), ...(layout === 'browseforge' ? ['browser-data'] : []), ...item.cacheName.split('/'));
  async function scan(target) {
    const hash = createHash('sha256'); let bytes = 0, count = 0;
    async function walk(current, relative, depth) {
      if (++count > maxEntries || depth > 64) throw failure('CACHE_SCAN_LIMIT');
      const info = await lstat(current); safeStat(info, uid);
      hash.update(`${relative}\0${identity(info)}\0`);
      if (info.isDirectory()) {
        for (const name of (await readdir(current)).sort()) await walk(path.join(current, name), `${relative}/${name}`, depth + 1);
        if (identity(await lstat(current)) !== identity(info)) throw failure('CACHE_INVENTORY_STALE');
      } else bytes += info.blocks == null ? info.size : info.blocks * 512;
    }
    await walk(target, '', 0);
    return { bytes, fingerprint: hash.digest('hex') };
  }
  async function profiles() {
    const rows = await listProfiles();
    if (!Array.isArray(rows) || rows.length > 1000) throw failure('CACHE_STATE_UNCERTAIN');
    const result = new Map();
    for (const row of rows) { profileId(row?.id); result.set(row.id, { id: row.id, name: String(row.name ?? '').slice(0, 160) }); }
    return result;
  }
  async function idle(ids) {
    if (!available) throw failure('CACHE_MAINTENANCE_UNAVAILABLE');
    const known = await profiles();
    for (const id of ids) {
      if (!known.has(id)) throw failure('CACHE_PROFILE_MISSING');
      // Only successful explicit evidence counts; callers should throw on uncertainty.
      if (await assertProfileIdle(id) === false) throw failure('CACHE_PROFILE_BUSY');
      const base = await root();
      const directory = await checked(base, path.join(rootRelative, id, ...(layout === 'browseforge' ? ['browser-data'] : [])), { optional: true });
      if (!directory) continue;
      // Even a stale lock is uncertainty, not authority to remove it.
      for (const name of ['SingletonLock', 'SingletonSocket', 'SingletonCookie', 'parent.lock', '.parentlock', 'lock']) {
        try { await lstat(path.join(directory, name)); throw failure('CACHE_PROFILE_BUSY'); }
        catch (error) { if (!missing(error)) throw error; }
      }
    }
  }
  async function recoveryRoot(base, create = false) {
    if (create) { try { await mkdir(path.join(base, 'cache-recovery'), { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; } }
    const recovery = await checked(base, 'cache-recovery', { optional: !create });
    if (recovery && accessibleByOthers(await lstat(recovery))) throw failure('CACHE_PATH_UNSAFE');
    return recovery;
  }
  async function writeManifest(base, manifest) {
    const batch = await checked(base, path.join('cache-recovery', manifest.id));
    const temporary = path.join(batch, `${randomUUID()}.tmp`);
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try { await handle.writeFile(JSON.stringify(manifest)); await handle.sync(); } finally { await handle.close(); }
    await checked(base, path.join('cache-recovery', manifest.id));
    await rename(temporary, path.join(batch, 'manifest.json'));
  }
  async function readManifest(base, id) {
    identifier(id);
    const batch = await checked(base, path.join('cache-recovery', id));
    if (accessibleByOthers(await lstat(batch))) throw failure('CACHE_PATH_UNSAFE');
    const file = await checked(base, path.join('cache-recovery', id, 'manifest.json'), { directory: false });
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    let manifest;
    try { const info = await handle.stat(); safeStat(info, uid); if (!info.isFile() || info.size > 1024 * 1024) throw failure('CACHE_BATCH_INVALID'); manifest = JSON.parse(await handle.readFile('utf8')); }
    finally { await handle.close(); }
    if (manifest?.version !== 1 || manifest.id !== id || manifest.scope !== scope || !Number.isFinite(Date.parse(manifest.createdAt)) ||
      !Array.isArray(manifest.entries) || !manifest.entries.length || manifest.entries.length > 500 ||
      new Set(manifest.entries.map(item => item?.id)).size !== manifest.entries.length) throw failure('CACHE_BATCH_INVALID');
    for (const item of manifest.entries) {
      if (!UUID.test(item?.id ?? '') || !PROFILE.test(item.profileId ?? '') || !CACHE_SET.has(item.cacheName)) throw failure('CACHE_BATCH_INVALID');
    }
    if (new Set(manifest.entries.map(item => `${item.profileId}/${item.cacheName}`)).size !== manifest.entries.length) throw failure('CACHE_BATCH_INVALID');
    return manifest;
  }
  const payloadRelative = (batchId, itemId) => path.join('cache-recovery', batchId, itemId, 'data');
  async function batchRows(base) {
    const recovery = await recoveryRoot(base);
    if (!recovery) return [];
    const rows = [];
    for (const id of (await readdir(recovery)).filter(name => UUID.test(name)).sort().slice(0, 500)) {
      try {
        const manifest = await readManifest(base, id); let bytes = 0, entryCount = 0;
        for (const item of manifest.entries) {
          const target = await checked(base, payloadRelative(id, item.id), { optional: true });
          if (target) { bytes += (await scan(target)).bytes; entryCount++; }
        }
        rows.push({ id, createdAt: manifest.createdAt, bytes, entryCount, status: 'ready' });
      } catch { rows.push({ id, createdAt: null, bytes: null, entryCount: null, status: 'unsafe' }); }
    }
    return rows;
  }
  async function inventory(args = {}) {
    request(args, []);
    return serialized(async () => {
      const base = await root(), entries = [], records = new Map(), known = await profiles();
      for (const profile of known.values()) {
        let status = available ? 'ready' : 'unavailable';
        if (available) try { await idle([profile.id]); } catch { status = 'busy'; }
        for (const cacheName of BROWSER_REGENERABLE_CACHES) {
          const item = { id: randomUUID(), profileId: profile.id, profileName: profile.name, cacheName, bytes: null, status };
          try {
            const target = await checked(base, sourceRelative(item), { optional: true });
            if (!target) continue;
            const measured = await scan(target); item.bytes = measured.bytes;
            records.set(item.id, { ...item, fingerprint: measured.fingerprint });
          } catch { item.status = 'unsafe'; }
          entries.push(item);
        }
      }
      const inventoryId = randomUUID(); ticket = { id: inventoryId, records };
      return { inventoryId, entries, batches: await batchRows(base), maintenanceAvailable: available, purgeAvailable: Number.isInteger(uid) };
    });
  }
  async function quarantine(args) {
    request(args, ['inventoryId', 'entryIds']); identifier(args.inventoryId);
    if (!Array.isArray(args.entryIds) || !args.entryIds.length || args.entryIds.length > 500 || new Set(args.entryIds).size !== args.entryIds.length) throw failure('INVALID_CACHE_MAINTENANCE_REQUEST');
    args.entryIds.forEach(identifier);
    return serialized(async () => {
      if (!available) throw failure('CACHE_MAINTENANCE_UNAVAILABLE');
      if (!ticket || ticket.id !== args.inventoryId) throw failure('CACHE_INVENTORY_STALE');
      const selected = args.entryIds.map(id => ticket.records.get(id));
      if (selected.some(item => !item || item.status !== 'ready')) throw failure('CACHE_INVENTORY_STALE');
      const ids = [...new Set(selected.map(item => item.profileId))].sort();
      return withMaintenance(ids, async () => {
        await idle(ids); const base = await root();
        for (const item of selected) {
          const target = await checked(base, sourceRelative(item));
          if ((await scan(target)).fingerprint !== item.fingerprint) throw failure('CACHE_INVENTORY_STALE');
        }
        await recoveryRoot(base, true);
        const id = randomUUID(); await mkdir(path.join(base, 'cache-recovery', id), { mode: 0o700 });
        const manifest = { version: 1, id, scope, createdAt: now().toISOString(), entries: selected.map(item => ({ id: randomUUID(), profileId: item.profileId, cacheName: item.cacheName })) };
        await writeManifest(base, manifest); let moved = 0;
        ticket = null;
        for (let i = 0; i < selected.length; i++) {
          try {
            await idle(ids);
            const source = await checked(base, sourceRelative(selected[i]));
            if ((await scan(source)).fingerprint !== selected[i].fingerprint) throw failure('CACHE_INVENTORY_STALE');
            await checked(base, path.join('cache-recovery', id));
            await mkdir(path.join(base, 'cache-recovery', id, manifest.entries[i].id), { mode: 0o700 });
            await checked(base, sourceRelative(selected[i]));
            await rename(source, path.join(base, payloadRelative(id, manifest.entries[i].id)));
            moved++;
          } catch (error) { return { batchId: id, moved, complete: false, code: error.code === 'EXDEV' ? 'CACHE_DIFFERENT_VOLUME' : 'CACHE_MOVE_INCOMPLETE' }; }
        }
        return { batchId: id, moved, complete: true };
      });
    });
  }
  async function copyExclusive(base, source, destination, depth = 0) {
    if (depth > 64) throw failure('CACHE_SCAN_LIMIT');
    await checked(base, path.relative(base, source));
    // mkdir is the exclusive reservation: never merge with a newly created cache.
    await checked(base, path.relative(base, path.dirname(destination)));
    await mkdir(destination, { mode: 0o700 });
    for (const name of await readdir(source)) {
      const from = path.join(source, name), to = path.join(destination, name), info = await lstat(from); safeStat(info, uid);
      if (info.isDirectory()) await copyExclusive(base, from, to, depth + 1);
      else {
        await checked(base, path.relative(base, path.dirname(from)));
        await checked(base, path.relative(base, path.dirname(to)));
        const input = await open(from, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); let output;
        try {
          const current = await input.stat(); safeStat(current, uid); if (!current.isFile() || identity(current) !== identity(info)) throw failure('CACHE_INVENTORY_STALE');
          output = await open(to, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
          const buffer = Buffer.alloc(128 * 1024); let position = 0;
          while (position < current.size) {
            const { bytesRead } = await input.read(buffer, 0, Math.min(buffer.length, current.size - position), position);
            if (!bytesRead) throw failure('CACHE_INVENTORY_STALE');
            let written = 0;
            while (written < bytesRead) {
              const { bytesWritten } = await output.write(buffer, written, bytesRead - written, position + written);
              if (!bytesWritten) throw failure('CACHE_RESTORE_INCOMPLETE');
              written += bytesWritten;
            }
            position += bytesRead;
          }
          if (identity(await input.stat()) !== identity(current)) throw failure('CACHE_INVENTORY_STALE');
          await output.sync();
        } finally { await input.close(); await output?.close(); }
      }
    }
  }
  async function restore(args) {
    request(args, ['batchId']); identifier(args.batchId);
    return serialized(async () => {
      if (!available) throw failure('CACHE_MAINTENANCE_UNAVAILABLE');
      const base = await root(), manifest = await readManifest(base, args.batchId), ids = [...new Set(manifest.entries.map(item => item.profileId))].sort();
      return withMaintenance(ids, async () => {
        await idle(ids); let restored = 0, conflicts = 0;
        for (const item of manifest.entries) {
          const source = await checked(base, payloadRelative(manifest.id, item.id), { optional: true });
          if (!source) continue;
          await idle(ids);
          const destination = path.join(base, sourceRelative(item));
          try { await lstat(destination); conflicts++; continue; } catch (error) { if (!missing(error)) throw error; }
          const before = await scan(source);
          try { await copyExclusive(base, source, destination); }
          catch (error) { if (error.code === 'EEXIST') { conflicts++; continue; } throw failure('CACHE_RESTORE_INCOMPLETE'); }
          if ((await scan(source)).fingerprint !== before.fingerprint) throw failure('CACHE_RESTORE_INCOMPLETE');
          await checked(base, payloadRelative(manifest.id, item.id));
          await rm(source, { recursive: true }); restored++;
        }
        ticket = null;
        return { restored, conflicts, complete: conflicts === 0 };
      });
    });
  }
  async function purge(args) {
    request(args, ['batchId', 'confirmed']); identifier(args.batchId);
    if (args.confirmed !== true) throw failure('CACHE_DELETE_CONFIRMATION_REQUIRED');
    return serialized(async () => {
      if (!Number.isInteger(uid)) throw failure('CACHE_MAINTENANCE_UNAVAILABLE');
      const base = await root(), manifest = await readManifest(base, args.batchId);
      const batch = await checked(base, path.join('cache-recovery', manifest.id));
      // Preflight the complete private batch. Unknown additions and links refuse
      // deletion, including a tampered manifest that points elsewhere.
      const expected = new Set(['manifest.json', ...manifest.entries.map(item => item.id)]);
      if ((await readdir(batch)).some(name => !expected.has(name))) throw failure('CACHE_BATCH_INVALID');
      await scan(batch);
      await checked(base, path.join('cache-recovery', manifest.id));
      await rm(batch, { recursive: true });
      return { deleted: true };
    });
  }
  return { inventory, quarantine, restore, purge };
}
