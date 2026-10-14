import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';

const fail = () => Object.assign(new Error('附加软件配置目录或文件无效。'), { code: 'APPLICATION_STORAGE_UNAVAILABLE' });
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
export function storedApplication(value) {
  if (!value || !validId(value.id) || !validId(value.profileId) || typeof value.name !== 'string' || !value.name.trim() || value.name.length > 128 ||
      ![value.path, value.executablePath].every(item => typeof item === 'string' && path.isAbsolute(item) && item.length <= 8192 && !/[\0\r\n]/.test(item)) ||
      typeof value.identity !== 'string' || !/^[A-Za-z0-9:._-]{1,512}$/.test(value.identity) ||
      !Array.isArray(value.args) || value.args.length > 128 || value.args.some(arg => typeof arg !== 'string' || arg.length > 8192 || /[\0\r\n]/.test(arg)) ||
      value.browserProfileId != null && !validId(value.browserProfileId)) throw fail();
  // Explicit allowlist: routing credentials and runtime sessions are never persisted.
  return { id: value.id, profileId: value.profileId, name: value.name.trim(), path: value.path, executablePath: value.executablePath,
    identity: value.identity, args: [...value.args], ...(value.browserProfileId ? { browserProfileId: value.browserProfileId } : {}) };
}
export class ApplicationStore {
  constructor(dataDir) {
    if (!path.isAbsolute(dataDir ?? '')) throw fail();
    this.dataDir = path.resolve(dataDir); this.ready = this.initialize();
  }
  async initialize() {
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    const canonical = await realpath(this.dataDir);
    this.root = path.join(canonical, 'applications');
    await mkdir(this.root, { mode: 0o700 }).catch(error => { if (error.code !== 'EEXIST') throw error; });
    const info = await lstat(this.root);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(this.root) !== this.root) throw fail();
    await chmod(this.root, 0o700); this.filename = path.join(this.root, 'applications.json');
  }
  async read() {
    await this.ready;
    try {
      const info = await lstat(this.filename);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 4 * 1024 * 1024) throw fail();
      const document = JSON.parse(await readFile(this.filename, 'utf8'));
      if (document.schema !== 'envara.applications' || document.version !== 1 || !Array.isArray(document.applications) || document.applications.length > 1000) throw fail();
      const values = document.applications.map(storedApplication), ids = new Set(), identities = new Set();
      for (const item of values) { if (ids.has(item.id) || identities.has(item.identity)) throw fail(); ids.add(item.id); identities.add(item.identity); }
      await chmod(this.filename, 0o600); return values;
    } catch (error) { if (error.code === 'ENOENT') return []; throw fail(); }
  }
  async write(values) {
    await this.ready;
    const applications = values.map(storedApplication);
    const ids = new Set(), identities = new Set();
    for (const item of applications) { if (ids.has(item.id) || identities.has(item.identity)) throw fail(); ids.add(item.id); identities.add(item.identity); }
    if (applications.length > 1000) throw fail();
    try { const info = await lstat(this.filename); if (!info.isFile() || info.isSymbolicLink()) throw fail(); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    const temporary = `${this.filename}.${randomUUID()}.tmp`;
    try { await writeFile(temporary, JSON.stringify({ schema: 'envara.applications', version: 1, applications }, null, 2), { flag: 'wx', mode: 0o600 }); await rename(temporary, this.filename); }
    finally { await rm(temporary, { force: true }); }
  }
}
