import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';

const copy = (value) => structuredClone(value);

/** A single-user, serialized JSON store. A failed transaction never replaces the file. */
export class EnvaraStore {
  constructor(dataDir) {
    if (typeof dataDir !== 'string' || !path.isAbsolute(dataDir)) {
      throw new Error('数据目录必须是绝对路径。');
    }
    this.dataDir = path.resolve(dataDir);
    this.file = path.join(this.dataDir, 'workspace.json');
    this.queue = Promise.resolve();
    this.ready = this.load();
  }

  async load() {
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    try {
      const value = JSON.parse(await readFile(this.file, 'utf8'));
      if (value?.schema !== 'envara.workspace' || value.version !== 1 ||
          !Array.isArray(value.profiles) || !Array.isArray(value.proxies) ||
          !Array.isArray(value.events) || !value.settings || typeof value.settings !== 'object') {
        throw new Error('数据文件格式不受支持。');
      }
      this.value = value;
    } catch (error) {
      if (error.code !== 'ENOENT') {
        // JSON parser snippets can contain proxy credentials or account data.
        // Keep the original file, but never carry its raw error into startup
        // logs, IPC errors or their cause chain.
        throw Object.assign(new Error('无法读取工作区，原文件已保留，请检查文件权限或从备份恢复。'), { code: 'WORKSPACE_STORAGE_UNAVAILABLE' });
      }
      this.value = {
        schema: 'envara.workspace', version: 1,
        profiles: [], proxies: [], settings: { closeBrowsersOnExit: true }, events: [],
      };
      await this.write(this.value);
    }
  }

  async write(value) {
    const temporary = path.join(this.dataDir, `.workspace-${randomUUID()}.tmp`);
    let handle;
    try {
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, this.file);
    } catch (error) {
      await handle?.close().catch(() => {});
      await rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  }

  async read() {
    await this.ready;
    await this.queue;
    return copy(this.value);
  }

  async transaction(update) {
    const transaction = this.queue.then(async () => {
      await this.ready;
      const next = copy(this.value);
      const result = await update(next);
      await this.write(next);
      this.value = next;
      return copy(result);
    });
    this.queue = transaction.catch(() => {});
    return transaction;
  }

  /** Serialize a read/reservation with writes, without touching the file. */
  async inspect(read) {
    const operation = this.queue.then(async () => {
      await this.ready;
      return copy(await read(copy(this.value)));
    });
    this.queue = operation.catch(() => {});
    return operation;
  }
}

export default EnvaraStore;
