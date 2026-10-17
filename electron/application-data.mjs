import path from 'node:path';
import { readdir, lstat, rm } from 'node:fs/promises';
import { pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';

export const ATTACHED_APPLICATION_DATA_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-app-data';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const defaultFs = { readdir, lstat, rm };
const TREE_ENTRY_BUDGET = 200000;
export const APPLICATION_DATA_DIRECTORIES = Object.freeze(['UserData', 'Home', 'Cache', 'Temp', 'Extensions']);
/* These named Chromium caches are regenerable. Service Worker and blob_storage
 * may hold offline documents, so they are deliberately not in this list. */
export const REGENERABLE_CACHE_ENTRIES = Object.freeze(['Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache',
  'GraphiteDawnCache', 'GrShaderCache', 'ShaderCache', 'Crashpad', 'component_crx_cache',
  'extensions_crx_cache', 'Shared Dictionary']);

const owned = (info, uid) => info.isDirectory() && !info.isSymbolicLink() && info.uid === uid;
const notCleared = (erased = [], incomplete = []) => Object.assign(new Error('应用数据没有全部清除，请退出这个软件后重试。'),
  { code: 'APPLICATION_DATA_NOT_CLEARED', erased, incomplete });
// The production layout is root-owned; fixture layouts belong to the user.
// Check every layout component before reading descendants, not just the leaf.
async function safeLayout(root, components, { uid, fs, strict = false }) {
  let target = root;
  for (const component of ['', ...components]) {
    if (component) target = path.join(target, component);
    try {
      const info = await fs.lstat(target);
      if (!info.isDirectory() || info.isSymbolicLink() || (info.uid !== 0 && info.uid !== uid)) {
        if (strict) throw notCleared();
        return null;
      }
    } catch (error) {
      if (strict && error.code !== 'ENOENT') throw notCleared();
      return null;
    }
  }
  return target;
}
async function applicationDataLeaves(environmentId, registrationId, options) {
  if (!UUID.test(environmentId ?? '') || !UUID.test(registrationId ?? '')) return { leaves: [], unsafe: false };
  const registration = await safeLayout(options.root, [environmentId, registrationId], options);
  if (!registration) return { leaves: [], unsafe: true };
  const leaves = [];
  let unsafe = false;
  for (const name of APPLICATION_DATA_DIRECTORIES) {
    const leaf = path.join(registration, name);
    try {
      if (owned(await options.fs.lstat(leaf), options.uid)) leaves.push({ name, path: leaf });
      else unsafe = true;
    } catch (error) { if (error.code !== 'ENOENT') unsafe = true; }
  }
  return { leaves, unsafe };
}
/* Allocated size of a tree, never following a link; bounded so a huge or
 * hostile tree cannot stall the caller. */
async function treeBytes(target, fs, budget = { entries: TREE_ENTRY_BUDGET }, visit, depth = 0) {
  if (budget.entries <= 0) return 0;
  budget.entries -= 1;
  let info; try { info = await fs.lstat(target); } catch { return 0; }
  visit?.(info, depth);
  // A folder's own entry is not data: an emptied sign-in folder measures zero.
  let total = info.isDirectory() && !info.isSymbolicLink() ? 0 : (info.blocks ?? 0) * 512 || info.size || 0;
  if (info.isDirectory() && !info.isSymbolicLink() && budget.entries > 0)
    for (const name of await fs.readdir(target).catch(() => [])) {
      if (budget.entries <= 0) break;
      total += await treeBytes(path.join(target, name), fs, budget, visit, depth + 1);
    }
  return total;
}

/** Empties the application data an environment keeps for its attached
 * applications: every application when the environment is deleted, or one
 * registration when the user explicitly clears that application's data. Only
 * the five fixed user-owned directories are touched; the root-owned layout above
 * them stays. A folder that is not empty afterwards is reported, not cleared. */
export async function eraseAttachedApplicationData(profileId, { registrationId = null, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin' || typeof profileId !== 'string' || !profileId) return [];
  return eraseEnvironmentData(pfAttachEnvironmentId(profileId), { registrationId, root, uid, platform, fs });
}
export async function eraseEnvironmentData(environmentId, { registrationId = null, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin' || !UUID.test(environmentId ?? '')) return [];
  const options = { root, uid, fs }, erased = [], incomplete = [];
  const environment = await safeLayout(root, [environmentId], { ...options, strict: true });
  if (!environment) return erased;
  let registrations;
  try { registrations = await fs.readdir(environment); }
  catch (error) { if (error.code === 'ENOENT') return erased; throw notCleared(); }
  for (const registration of registrations) {
    if (registrationId && registration !== registrationId) continue;
    if (!UUID.test(registration)) continue;
    const { leaves, unsafe } = await applicationDataLeaves(environmentId, registration, options);
    // A known but inaccessible directory is not an empty application. Refuse
    // the whole registration before mutating any of its other directories.
    if (unsafe) { incomplete.push(registration); continue; }
    if (!leaves.length) continue;
    let complete = true;
    for (const { path: leaf } of leaves) {
      const entries = await fs.readdir(leaf).catch(() => null);
      if (!entries) { complete = false; continue; }
      for (const entry of entries) await fs.rm(path.join(leaf, entry), { recursive: true, force: true }).catch(() => { complete = false; });
      const left = await fs.readdir(leaf).catch(() => null);
      if (!left || left.length) complete = false;
    }
    (complete ? erased : incomplete).push(registration);
  }
  if (incomplete.length) throw notCleared(erased, incomplete);
  return erased;
}

/** Removes the regenerable caches of one stopped application's data in one
 * environment, at the data root, its default profile and every partition.
 * Returns the bytes freed. Never called while that application runs. */
export async function pruneAttachedApplicationCache({ environmentId, registrationId, root = ATTACHED_APPLICATION_DATA_ROOT,
  uid = process.getuid?.(), platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin') return 0;
  const { leaves, unsafe } = await applicationDataLeaves(environmentId, registrationId, { root, uid, fs });
  if (unsafe) return 0;
  const leaf = leaves.find(item => item.name === 'UserData')?.path;
  // Never prune Home, Temp or Extensions, nor unknown entries in Cache.
  const containers = leaves.filter(item => ['UserData', 'Cache'].includes(item.name)).map(item => item.path);
  for (const nested of ['Default', 'Partitions']) {
    if (!leaf) break;
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

/** Every application's existing user-owned data directories, with their total
 * allocated size and the last
 * time anything at its top level changed. Read-only. */
export async function attachedApplicationDataInventory({ root = ATTACHED_APPLICATION_DATA_ROOT, uid = process.getuid?.(),
  platform = process.platform, fs = defaultFs } = {}) {
  if (platform !== 'darwin') return [];
  const items = [];
  const options = { root, uid, fs };
  if (!await safeLayout(root, [], options)) return items;
  for (const environmentId of (await fs.readdir(root).catch(() => [])).filter(name => UUID.test(name)).sort()) {
    const environment = await safeLayout(root, [environmentId], options);
    if (!environment) continue;
    for (const registrationId of (await fs.readdir(environment).catch(() => [])).filter(name => UUID.test(name)).sort()) {
      const { leaves } = await applicationDataLeaves(environmentId, registrationId, options);
      if (!leaves.length) continue;
      let modified = 0, bytes = 0;
      // At the limit, size and time describe only the visited entries.
      const budget = { entries: TREE_ENTRY_BUDGET };
      const visit = (info, depth) => { if (depth === 1) modified = Math.max(modified, info.mtimeMs ?? 0); };
      for (const { path: leaf } of leaves) {
        if (budget.entries <= 0) break;
        bytes += await treeBytes(leaf, fs, budget, visit);
      }
      items.push({ environmentId, registrationId, dataScope: 'environment', hasDataDirectory: true, bytes,
        modifiedAt: modified ? new Date(modified).toISOString() : null });
    }
  }
  return items;
}
