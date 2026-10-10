import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, lstat, realpath, open, rename, unlink } from 'node:fs/promises';
import { exportPFNotionTrialDiagnostics } from './macos-pf-notion-trial.mjs';

const applicationId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const refused = () => Object.assign(new Error('试运行诊断无法保存或读取。'), { code: 'PF_NOTION_DIAGNOSTICS_UNAVAILABLE' });

// User-owned history is explanatory only. It lives outside the privileged run
// directory and is never consumed as cleanup or launch authority.
export class NotionDiagnosticsStore {
  constructor(directory) {
    if (!path.isAbsolute(directory)) throw refused();
    this.directory = directory;
    this.pending = Promise.resolve();
  }
  async prepare() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const info = await lstat(this.directory);
    if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o077 ||
        typeof process.getuid === 'function' && info.uid !== process.getuid() ||
        await realpath(this.directory) !== this.directory) throw refused();
  }
  save(value) {
    const report = exportPFNotionTrialDiagnostics(value);
    if (!report) return Promise.reject(refused());
    const task = this.pending.catch(() => {}).then(async () => {
      await this.prepare();
      const target = path.join(this.directory, `${report.applicationId}.json`);
      const temporary = path.join(this.directory, `.${randomUUID()}.tmp`);
      let handle;
      try {
        handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        await handle.writeFile(`${JSON.stringify(report, null, 2)}\n`);
        await handle.sync(); await handle.close(); handle = null;
        await rename(temporary, target);
      } finally { await handle?.close().catch(() => {}); await unlink(temporary).catch(() => {}); }
      return report;
    });
    this.pending = task;
    return task;
  }
  async read(id) {
    if (!applicationId(id)) return null;
    await this.pending.catch(() => {});
    let handle;
    try {
      await this.prepare();
      handle = await open(path.join(this.directory, `${id}.json`), constants.O_RDONLY | constants.O_NOFOLLOW);
      const info = await handle.stat();
      if (!info.isFile() || info.nlink !== 1 || info.mode & 0o077 || info.size > 131072 ||
          typeof process.getuid === 'function' && info.uid !== process.getuid()) throw refused();
      const parsed = JSON.parse(await handle.readFile('utf8'));
      if (parsed.schema !== 'envara.macos-pf-notion-trial-diagnostics/v1' || parsed.applicationId !== id) return null;
      return exportPFNotionTrialDiagnostics(parsed);
    } catch (error) { if (error.code === 'ENOENT') return null; throw refused(); }
    finally { await handle?.close(); }
  }
}
