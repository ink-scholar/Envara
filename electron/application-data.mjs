import path from 'node:path';
import { readdir, lstat, rm } from 'node:fs/promises';
import { pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';

export const ATTACHED_APPLICATION_DATA_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-app-data';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const defaultFs = { readdir, lstat, rm };
/* Chromium and Electron rebuild these on demand. Sign-in state lives elsewhere
 * (Cookies, Local Storage, IndexedDB, the application's own databases), so
 * removing them keeps the user signed in and only costs a slower first load. */
export const REGENERABLE_CACHE_ENTRIES = Object.freeze(['Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache',
  'GraphiteDawnCache', 'GrShaderCache', 'ShaderCache', 'Service Worker', 'blob_storage', 'Crashpad', 'component_crx_cache',
  'extensions_crx_cache', 'Shared Dictionary']);

const owned = (info, uid) => info.isDirectory() && !info.isSymbolicLink() && info.uid === uid;
async function userDataLeaf(environmentId, registrationId, { root, uid, fs }) {
  if (!UUID.test(environmentId ?? '') || !UUID.test(registrationId ?? '')) return null;
  const leaf = path.join(root, environmentId, registrationId, 'UserData');
  try { return owned(await fs.lstat(leaf), uid) ? leaf : null; } catch { return null; }
}
/* Allocated size of a tree, never following a link; bounded so a huge or
 * hostile tree cannot stall the caller. */
async function treeBytes(target, fs, budget = { entries: 200000 }) {
  let info; try { info = await fs.lstat(target); } catch { return 0; }
  if (--budget.entries < 0) return 0;
  // A folder's own entry is not data: an emptied sign-in folder measures zero.
  let total = info.isDirectory() && !info.isSymbolicLink() ? 0 : (info.blocks ?? 0) * 512 || info.size || 0;
  if (info.isDirectory() && !info.isSymbolicLink())
    for (const name of await fs.readdir(target).catch(() => [])) total += await treeBytes(path.join(target, name), fs, budget);
  return total;
}

/** Empties the sign-in data an environment keeps for its attached
 * applications: every application when the environment is deleted, or one
 * registration when the user clears that application's sign-in data. Only the
 * user-owned UserData directories are touched; the root-owned layout above
 * them stays. A folder that is not empty afterwards is reported, not cleared. */
export async function eraseAttachedApplicationData(profileId, { registrationId = null, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin' || typeof profileId !== 'string' || !profileId) return [];
  return eraseEnvironmentData(pfAttachEnvironmentId(profileId), { registrationId, root, uid, platform, fs });
}
export async function eraseEnvironmentData(environmentId, { registrationId = null, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin' || !UUID.test(environmentId ?? '')) return [];
  const environment = path.join(root, environmentId), erased = [], incomplete = [];
  let registrations; try { registrations = await fs.readdir(environment); } catch { return erased; }
  for (const registration of registrations) {
    if (registrationId && registration !== registrationId) continue;
    const leaf = await userDataLeaf(environmentId, registration, { root, uid, fs });
    if (!leaf) continue;
    for (const entry of await fs.readdir(leaf).catch(() => [])) await fs.rm(path.join(leaf, entry), { recursive: true, force: true }).catch(() => {});
    const left = await fs.readdir(leaf).catch(() => null);
    (left?.length === 0 ? erased : incomplete).push(registration);
  }
  if (incomplete.length) throw Object.assign(new Error('登录数据没有全部清除，请退出这个软件后重试。'), { code: 'APPLICATION_DATA_NOT_CLEARED', erased, incomplete });
  return erased;
}

/** Removes the regenerable caches of one stopped application's data in one
 * environment, at the data root, its default profile and every partition.
 * Returns the bytes freed. Never called while that application runs. */
export async function pruneAttachedApplicationCache({ environmentId, registrationId, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin') return 0;
  const leaf = await userDataLeaf(environmentId, registrationId, { root, uid, fs });
  if (!leaf) return 0;
  const containers = [leaf];
  for (const nested of ['Default', 'Partitions']) {
    const target = path.join(leaf, nested);
    let info; try { info = await fs.lstat(target); } catch { continue; }
    if (!owned(info, uid)) continue;
    if (nested === 'Default') { containers.push(target); continue; }
    for (const name of await fs.readdir(target).catch(() => [])) {
      const partition = path.join(target, name);
      try { if (owned(await fs.lstat(partition), uid)) containers.push(partition); } catch {}
    }
  }
  let freed = 0;
  for (const container of containers) for (const name of REGENERABLE_CACHE_ENTRIES) {
    const target = path.join(container, name);
    let info; try { info = await fs.lstat(target); } catch { continue; }
    if (info.isSymbolicLink() || info.uid !== uid) continue;
    const bytes = await treeBytes(target, fs);
    try { await fs.rm(target, { recursive: true, force: true }); freed += bytes; } catch {}
  }
  return freed;
}

/** Every user-owned sign-in data folder, with its allocated size and the last
 * time anything at its top level changed. Read-only. */
export async function attachedApplicationDataInventory({ root = ATTACHED_APPLICATION_DATA_ROOT, uid = process.getuid?.(),
  platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin') return [];
  const items = [];
  for (const environmentId of (await fs.readdir(root).catch(() => [])).filter(name => UUID.test(name)).sort()) {
    for (const registrationId of (await fs.readdir(path.join(root, environmentId)).catch(() => [])).filter(name => UUID.test(name)).sort()) {
      const leaf = await userDataLeaf(environmentId, registrationId, { root, uid, fs });
      if (!leaf) continue;
      let modified = 0;
      for (const name of await fs.readdir(leaf).catch(() => [])) {
        try { modified = Math.max(modified, (await fs.lstat(path.join(leaf, name))).mtimeMs ?? 0); } catch {}
      }
      items.push({ environmentId, registrationId, bytes: await treeBytes(leaf, fs), modifiedAt: modified ? new Date(modified).toISOString() : null });
    }
  }
  return items;
}
