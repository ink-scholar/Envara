import path from 'node:path';
import { constants } from 'node:fs';
import { lstat, realpath, mkdir, mkdtemp, open, rm } from 'node:fs/promises';
import { TERMINAL_ATTACHMENT_LIMITS as limits, TERMINAL_ATTACHMENT_MESSAGES as messages } from '../shared/terminal-attachments.mjs';

const fail = code => Object.assign(new Error(messages[code] ?? messages.TERMINAL_ATTACHMENT_STORAGE), { code });
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const owned = info => !process.getuid || info.uid === process.getuid();
const validTransfer = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{16,96}$/.test(value);
function filename(value, index) {
  if (typeof value !== 'string' || !value || value.length > 512 || /[\x00-\x1f\x7f]/.test(value) || value !== path.basename(value) || /[\\/]/.test(value)) throw fail('TERMINAL_ATTACHMENT_INVALID');
  return `${index + 1}-${value.replace(/[^\p{L}\p{N} ._()-]/gu, '_').slice(0, 120) || 'attachment'}`;
}
async function directory(target, create = false) {
  if (create) { try { await mkdir(target, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; } }
  const info = await lstat(target);
  if (!info.isDirectory() || info.isSymbolicLink() || !owned(info) || await realpath(target) !== target) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
  return info;
}
export function quoteTerminalAttachmentPath(value, shell = 'posix') {
  if (typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value)) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
  return shell === 'powershell' ? `'${value.replaceAll("'", "''")}'` : `'${value.replaceAll("'", "'\\''")}'`;
}

/** Receives only files selected in the preload File bridge. No caller chooses
 * the destination, environment, shell or final path. Only commit writes input. */
export class TerminalAttachments {
  constructor({ terminal, platform = process.platform }) { this.terminal = terminal; this.platform = platform; this.transfers = new Map(); this.cancelled = new Map(); }
  scope(sessionId) {
    const session = this.terminal.session(sessionId);
    if (session.finished || session.status !== 'running') throw fail('TERMINAL_ATTACHMENT_CANCELLED');
    if (!/^[A-Za-z0-9_-]{1,96}$/.test(session.profileId)) throw fail('TERMINAL_ATTACHMENT_INVALID');
    let foreground = '';
    try { foreground = path.basename(session.pty?.process ?? '').toLowerCase().replace(/\.exe$/, ''); } catch {}
    if (['ssh', 'mosh', 'mosh-client', 'sftp', 'scp'].includes(foreground) || session.kind === 'ssh') throw fail('TERMINAL_ATTACHMENT_REMOTE');
    // Unknown foregrounds may be remote clients or a password prompt. Refuse
    // rather than interpreting a local path as a remote filename or command.
    const nativeClaude = session.kind === 'claude-code' && typeof session.claudeLaunch?.executable === 'string' && foreground === path.basename(session.claudeLaunch.executable).toLowerCase();
    if (!nativeClaude && !['zsh', 'bash', 'sh', 'fish', 'dash', 'ksh', 'claude', 'powershell', 'pwsh'].includes(foreground)) throw fail('TERMINAL_ATTACHMENT_UNSUPPORTED');
    const shell = this.platform === 'win32' ? 'powershell' : 'posix';
    if (this.platform === 'win32' && !['powershell', 'pwsh', 'claude'].includes(foreground)) throw fail('TERMINAL_ATTACHMENT_UNSUPPORTED');
    return { session, shell };
  }
  assertCurrent(record) {
    if (record.cancelled || record.window?.isDestroyed?.() || this.scope(record.sessionId).session !== record.session) throw fail('TERMINAL_ATTACHMENT_CANCELLED');
  }
  async stage({ sessionId, transferId, files }, context = {}) {
    if (!validTransfer(transferId) || !Array.isArray(files) || !files.length || files.length > limits.count) throw fail('TERMINAL_ATTACHMENT_LIMIT');
    const owner = context.window;
    if (!owner || owner.isDestroyed()) throw fail('TERMINAL_ATTACHMENT_CANCELLED');
    await this.terminal.ready;
    if (this.cancelled.has(transferId)) throw fail('TERMINAL_ATTACHMENT_CANCELLED');
    if (this.transfers.has(transferId) || this.transfers.size >= 64 || [...this.transfers.values()].some(item => item.sessionId === sessionId)) throw fail('TERMINAL_ATTACHMENT_BUSY');
    const { session, shell } = this.scope(sessionId);
    const record = { sessionId, session, transferId, window: owner, cancelled: false, directory: null, identity: null };
    this.transfers.set(transferId, record);
    const cancel = () => { record.cancelled = true; if (record.complete) void this.discard(record); };
    owner.once?.('closed', cancel);
    session.abortController?.signal.addEventListener('abort', cancel, { once: true });
    record.detach = () => { owner.removeListener?.('closed', cancel); session.abortController?.signal.removeEventListener('abort', cancel); };
    try {
      const root = this.terminal.profilesDir;
      if (typeof root !== 'string' || !path.isAbsolute(root) || /[\x00-\x1f\x7f]/.test(root)) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
      await directory(root);
      const profile = path.join(root, session.profileId); await directory(profile);
      const attachments = path.join(profile, 'attachments'); await directory(attachments, true);
      this.assertCurrent(record);
      record.directory = await mkdtemp(path.join(attachments, 'batch-')); record.identity = await directory(record.directory);
      let total = 0; const paths = [];
      for (const [index, file] of files.entries()) {
        this.assertCurrent(record);
        if (!file || typeof file !== 'object' || Object.keys(file).some(key => !['name', 'path', 'bytes'].includes(key)) || (file.path == null) === (file.bytes == null)) throw fail('TERMINAL_ATTACHMENT_INVALID');
        const name = filename(file.name, index);
        let bytes;
        if (file.path != null) {
          if (typeof file.path !== 'string' || !path.isAbsolute(file.path) || file.path.length > 4096 || /[\x00-\x1f\x7f]/.test(file.path)) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
          const info = await lstat(file.path);
          if (!info.isFile() || info.isSymbolicLink() || await realpath(file.path) !== file.path) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
          if (info.size > limits.fileBytes || total + info.size > limits.totalBytes) throw fail('TERMINAL_ATTACHMENT_LIMIT');
          const handle = await open(file.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
          try {
            const opened = await handle.stat();
            if (!opened.isFile() || !same(info, opened) || opened.size !== info.size) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
            // A growing source cannot make an unbounded readFile allocation.
            bytes = Buffer.alloc(opened.size + 1);
            let offset = 0;
            while (offset < bytes.length) { this.assertCurrent(record); const read = await handle.read(bytes, offset, bytes.length - offset, offset); if (!read.bytesRead) break; offset += read.bytesRead; }
            const after = await handle.stat();
            if (offset !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
            bytes = bytes.subarray(0, offset);
          } finally { await handle.close(); }
        } else {
          if (!(file.bytes instanceof Uint8Array) && !(file.bytes instanceof ArrayBuffer)) throw fail('TERMINAL_ATTACHMENT_INVALID');
          const length = file.bytes.byteLength;
          if (length > limits.fileBytes || total + length > limits.totalBytes) throw fail('TERMINAL_ATTACHMENT_LIMIT');
          bytes = Buffer.from(file.bytes instanceof ArrayBuffer ? new Uint8Array(file.bytes) : file.bytes);
        }
        total += bytes.length;
        this.assertCurrent(record);
        if (!same(record.identity, await directory(record.directory))) throw fail('TERMINAL_ATTACHMENT_UNSAFE');
        const target = path.join(record.directory, name);
        const output = await open(target, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
        try { await output.writeFile(bytes); } finally { await output.close(); }
        paths.push(target);
      }
      this.assertCurrent(record);
      record.complete = true;
      record.quotedPaths = paths.map(value => quoteTerminalAttachmentPath(value, shell)).join(' ') + ' ';
      return { transferId, count: paths.length, quotedPaths: record.quotedPaths };
    } catch (error) {
      await this.discard(record);
      throw Object.hasOwn(messages, error?.code) ? error : fail('TERMINAL_ATTACHMENT_STORAGE');
    }
  }
  async discard(record) {
    record.cancelled = true;
    if (record.directory && record.identity) {
      try { const info = await lstat(record.directory); if (!info.isSymbolicLink() && same(info, record.identity) && await realpath(record.directory) === record.directory) await rm(record.directory, { recursive: true }); } catch {}
    }
    record.detach?.();
    if (this.transfers.get(record.transferId) === record) this.transfers.delete(record.transferId);
  }
  async finish({ sessionId, transferId, accepted = false, bracketedPaste = false }, context = {}) {
    if (!validTransfer(transferId)) throw fail('TERMINAL_ATTACHMENT_INVALID');
    const record = this.transfers.get(transferId);
    if (!record) {
      if (accepted === true) throw fail('TERMINAL_ATTACHMENT_CANCELLED');
      if (accepted !== true) { if (this.cancelled.size >= 512) this.cancelled.delete(this.cancelled.keys().next().value); this.cancelled.set(transferId, true); }
      return { accepted: false };
    }
    if (record.sessionId !== sessionId || record.window !== context.window) throw fail('TERMINAL_ATTACHMENT_INVALID');
    if (accepted === true) {
      this.assertCurrent(record);
      if (!record.complete) throw fail('TERMINAL_ATTACHMENT_BUSY');
      if (typeof bracketedPaste !== 'boolean') throw fail('TERMINAL_ATTACHMENT_INVALID');
      // Ownership transfers before a PTY write can occur. A delayed write
      // acknowledgement, tab switch or close must not delete referenced files.
      // Foreground and session were rechecked without an await before this call.
      record.detach?.(); this.transfers.delete(transferId);
      const data = bracketedPaste ? `\x1b[200~${record.quotedPaths}\x1b[201~` : record.quotedPaths;
      try { await this.terminal.write({ sessionId, data }); }
      catch { throw fail('TERMINAL_ATTACHMENT_INPUT'); }
      return { accepted: true };
    }
    record.cancelled = true;
    if (record.complete) await this.discard(record);
    return { accepted: false };
  }
}
