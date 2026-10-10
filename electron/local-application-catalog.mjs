import path from 'node:path';
import os from 'node:os';
import { lstat, opendir, realpath } from 'node:fs/promises';
import { inspectLocalApplication } from './application-service.mjs';

const supported = platform => ['darwin', 'win32'].includes(platform);
const invalid = () => Object.assign(new Error('本地软件列表的查询参数无效。'), { code: 'APPLICATION_CATALOG_INVALID_QUERY' });
const contained = (root, filename) => {
  const relative = path.relative(root, filename);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};
const validPath = value => typeof value === 'string' && path.isAbsolute(value) && value.length <= 8192 && !/[\0\r\n]/.test(value);

/** Fixed installation roots only; renderer requests cannot select a scan directory. */
export function localApplicationRoots({ platform = process.platform, home = os.homedir(), environment = process.env } = {}) {
  if (platform === 'darwin') return ['/Applications', path.join(home, 'Applications')].filter(validPath);
  if (platform === 'win32') return [...new Set([
    environment.ProgramFiles,
    environment['ProgramFiles(x86)'],
    environment.LOCALAPPDATA && path.join(environment.LOCALAPPDATA, 'Programs'),
  ].filter(validPath))];
  return [];
}

function queryOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['query', 'limit'].includes(key))) throw invalid();
  const query = value.query ?? '', limit = value.limit ?? 200;
  if (typeof query !== 'string' || query.length > 256 || /[\0\r\n]/.test(query) || !Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw invalid();
  return { query: query.trim().normalize('NFKC').toLowerCase(), limit };
}

async function bundleIsBounded(bundle) {
  for (const suffix of ['Contents', 'Contents/MacOS']) {
    const directory = path.join(bundle, suffix), info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || !contained(bundle, await realpath(directory))) return false;
  }
  const metadata = path.join(bundle, 'Contents/Info.plist'), info = await lstat(metadata);
  return info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= 1024 * 1024 && contained(bundle, await realpath(metadata));
}

/** Read-only, bounded discovery. Selection is re-inspected by ApplicationService before binding/launch. */
export class LocalApplicationCatalog {
  constructor({ platform = process.platform, roots = localApplicationRoots({ platform }), inspectApplication = inspectLocalApplication,
    cacheMs = 15000, timeoutMs = 4000, maxEntries = 4096, maxDirectories = 256, maxCandidates = 750, now = Date.now } = {}) {
    if (!Array.isArray(roots) || roots.length > 8 || roots.some(root => !validPath(root)) || typeof inspectApplication !== 'function' || typeof now !== 'function' ||
        ![cacheMs, timeoutMs, maxEntries, maxDirectories, maxCandidates].every(value => Number.isSafeInteger(value) && value > 0) ||
        cacheMs > 60000 || timeoutMs > 10000 || maxEntries > 8192 || maxDirectories > 512 || maxCandidates > 1000) throw invalid();
    this.platform = platform; this.roots = [...new Set(roots)]; this.inspectApplication = inspectApplication;
    this.cacheMs = cacheMs; this.timeoutMs = timeoutMs; this.maxEntries = maxEntries; this.maxDirectories = maxDirectories;
    this.maxCandidates = maxCandidates; this.now = now; this.cached = null; this.pending = null;
  }

  async list(input = {}) {
    const { query, limit } = queryOptions(input);
    if (!supported(this.platform)) return { applications: [], platform: this.platform, available: false, scanComplete: true, truncated: false };
    if (!this.cached || this.now() - this.cached.at >= this.cacheMs) {
      this.pending ??= this.scan().then(value => { this.cached = { ...value, at: this.now() }; return this.cached; }).finally(() => { this.pending = null; });
      await this.pending;
    }
    const matches = this.cached.applications.filter(item => !query || `${item.name}\n${path.basename(item.path)}`.normalize('NFKC').toLowerCase().includes(query));
    return { applications: matches.slice(0, limit).map(item => ({ ...item })), platform: this.platform, available: true,
      scanComplete: this.cached.scanComplete, truncated: !this.cached.scanComplete || matches.length > limit };
  }

  async scan() {
    const applications = [], identities = new Set(), paths = new Set(), queue = [];
    const deadline = this.now() + this.timeoutMs, maxDepth = this.platform === 'darwin' ? 2 : 3;
    let entries = 0, directories = 0, candidates = 0, scanComplete = true;
    const expired = () => this.now() >= deadline || entries >= this.maxEntries || candidates >= this.maxCandidates;
    for (const root of this.roots) {
      try {
        const info = await lstat(root);
        if (!info.isDirectory() || info.isSymbolicLink()) { scanComplete = false; continue; }
        queue.push({ root: await realpath(root), directory: await realpath(root), depth: 0 });
      } catch (error) { if (error.code !== 'ENOENT') scanComplete = false; }
    }
    while (queue.length) {
      if (expired() || directories >= this.maxDirectories) { scanComplete = false; break; }
      const { root, directory, depth } = queue.shift();
      let handle;
      try {
        const info = await lstat(directory), canonical = await realpath(directory);
        if (!info.isDirectory() || info.isSymbolicLink() || canonical !== directory || !contained(root, canonical)) { scanComplete = false; continue; }
        handle = await opendir(directory); directories++;
        const names = [];
        while (!expired()) {
          const entry = await handle.read(); if (!entry) break;
          entries++; if (!entry.name.startsWith('.')) names.push(entry.name);
        }
        if (expired()) scanComplete = false;
        names.sort((left, right) => left.localeCompare(right, 'en'));
        for (const name of names) {
          if (this.now() >= deadline || candidates >= this.maxCandidates) { scanComplete = false; break; }
          const filename = path.join(directory, name);
          try {
            const item = await lstat(filename);
            if (item.isSymbolicLink()) continue;
            const isApplication = this.platform === 'darwin' ? item.isDirectory() && /\.app$/i.test(name) : item.isFile() && /\.exe$/i.test(name);
            if (isApplication) {
              candidates++;
              const canonical = await realpath(filename);
              if (!contained(root, canonical) || this.platform === 'darwin' && !await bundleIsBounded(canonical)) continue;
              const inspected = await this.inspectApplication(canonical, { platform: this.platform });
              if (!validPath(inspected.path) || !validPath(inspected.executablePath) || !contained(root, inspected.path) ||
                  this.platform === 'darwin' && !contained(inspected.path, inspected.executablePath) ||
                  typeof inspected.name !== 'string' || !inspected.name.trim() || inspected.name.length > 128 || /[\0\r\n]/.test(inspected.name) ||
                  typeof inspected.identity !== 'string' || inspected.identity.length > 300 || !/^(bundle:[A-Za-z0-9._-]+|path:[a-f0-9]{64})$/.test(inspected.identity)) continue;
              if (identities.has(inspected.identity) || paths.has(inspected.path)) continue;
              identities.add(inspected.identity); paths.add(inspected.path);
              applications.push({ path: inspected.path, executablePath: inspected.executablePath, name: inspected.name, identity: inspected.identity });
            } else if (item.isDirectory() && depth < maxDepth) queue.push({ root, directory: filename, depth: depth + 1 });
          } catch { /* Broken or changing bundles are omitted; no file contents or paths are logged. */ }
        }
      } catch { scanComplete = false; }
      finally { await handle?.close().catch(() => {}); }
    }
    applications.sort((left, right) => left.name.localeCompare(right.name, 'en') || left.path.localeCompare(right.path, 'en'));
    return { applications, scanComplete };
  }
}
