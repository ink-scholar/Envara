import path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as filesystem from 'node:fs/promises';

const defaults = () => ({ openInEnvironment: true, declinedAt: null });
const normalize = saved => ({ openInEnvironment: saved?.openInEnvironment !== false,
  declinedAt: typeof saved?.declinedAt === 'string' ? saved.declinedAt : null });
const failure = code => Object.assign(new Error(code === 'LINK_PREFERENCES_INVALID'
  ? '链接偏好无效。' : '链接偏好保存失败，请重试。'), { code });

function checkedPatch(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(key => !['openInEnvironment', 'declinedAt'].includes(key))) throw failure('LINK_PREFERENCES_INVALID');
  const patch = {};
  if (Object.hasOwn(value, 'openInEnvironment')) {
    if (typeof value.openInEnvironment !== 'boolean') throw failure('LINK_PREFERENCES_INVALID');
    patch.openInEnvironment = value.openInEnvironment;
  }
  if (Object.hasOwn(value, 'declinedAt')) {
    const timestamp = value.declinedAt;
    if (timestamp !== null && (typeof timestamp !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(timestamp)
      || !Number.isFinite(Date.parse(timestamp)) || new Date(timestamp).toISOString() !== timestamp)) throw failure('LINK_PREFERENCES_INVALID');
    patch.declinedAt = timestamp;
  }
  return patch;
}

/** One main-process instance owns the committed preferences and write queue. */
export class LinkPreferences {
  #state = defaults();
  #queue = Promise.resolve();
  #loaded = false;
  #file;
  #filesystem;
  constructor({ file, filesystem: io = filesystem } = {}) {
    if (typeof file !== 'string' && typeof file !== 'function') throw failure('LINK_PREFERENCES_INVALID');
    this.#file = file;
    this.#filesystem = io;
  }
  snapshot() { return { ...this.#state }; }
  #filename() {
    const filename = typeof this.#file === 'function' ? this.#file() : this.#file;
    if (typeof filename !== 'string' || !path.isAbsolute(filename) || /[\0\r\n]/.test(filename)) throw failure('LINK_PREFERENCES_INVALID');
    return filename;
  }
  #serialize(operation) {
    const pending = this.#queue.then(operation);
    this.#queue = pending.catch(() => {});
    return pending;
  }
  async #load() {
    if (this.#loaded) return;
    const filename = this.#filename();
    try { this.#state = normalize(JSON.parse(await this.#filesystem.readFile(filename, 'utf8'))); }
    catch { this.#state = defaults(); }
    this.#loaded = true;
  }
  load() { return this.#serialize(async () => { await this.#load(); return this.snapshot(); }); }
  async patch(value) {
    // Capture only the supplied fields before waiting; merge after prior commits.
    const patch = checkedPatch(value);
    return this.#serialize(async () => {
      await this.#load();
      const next = { ...this.#state, ...patch };
      const filename = this.#filename(), temporary = `${filename}.tmp-${randomUUID()}`;
      try {
        await this.#filesystem.writeFile(temporary, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
        await this.#filesystem.rename(temporary, filename);
        this.#state = next;
        return this.snapshot();
      } catch { throw failure('LINK_PREFERENCES_SAVE_FAILED'); }
      finally {
        // Rename is the commit point. Cleanup cannot turn a committed write into
        // a rejected operation or hide the original persistence failure.
        await this.#filesystem.rm(temporary, { force: true }).catch(() => {});
      }
    });
  }
}
