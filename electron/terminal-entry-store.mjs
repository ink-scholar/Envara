import path from 'node:path';
import { constants } from 'node:fs';
import { lstat, open, realpath, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const fail = (code, message) => Object.assign(new Error(message), { code });
const invalid = () => fail('TERMINAL_ENTRY_INVALID', '保存的终端配置无效。');
const storageInvalid = () => fail('TERMINAL_ENTRY_STORAGE_INVALID', '保存的终端记录文件无效。');
const unsafePath = () => fail('TERMINAL_ENTRY_UNSAFE_PATH', '保存的终端记录目录或文件不安全。');
const storageFailed = () => fail('TERMINAL_ENTRY_STORAGE_FAILED', '无法保存终端记录，请重试。');
const notFound = () => fail('TERMINAL_ENTRY_NOT_FOUND', '此终端记录已不存在，请重新选择。');
const MAX_BYTES = 1024 * 1024;
export const TERMINAL_ENTRY_LIMIT = 512;
const configKeys = ['profileId', 'name', 'kind', 'cwd', 'browserProfileId', 'claudeAccountId', 'networkRef'];
const entryKeys = ['id', ...configKeys, 'createdAt', 'updatedAt', 'lastOpenedAt'];
const exactKeys = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => allowed.includes(key));
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
const checkedProfileId = value => { if (!validId(value)) throw invalid(); return value; };
export const terminalEntryId = value => {
  if (typeof value !== 'string' || !/^savedterm_[a-f0-9]{32}$/.test(value)) throw invalid();
  return value;
};
const checkedName = value => {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 80 || /[\x00-\x1f\x7f]/.test(value)) throw invalid();
  return value.trim();
};
function configuration(value) {
  if (!exactKeys(value, configKeys) || !['shell', 'claude-code'].includes(value.kind)) throw invalid();
  const profileId = checkedProfileId(value.profileId), name = checkedName(value.name);
  const cwd = value.cwd;
  // Main already authorized the picked directory. Loading a record deliberately
  // does not require it to still exist; reopening must validate it again.
  if (typeof cwd !== 'string' || cwd.length > 8192 || !path.isAbsolute(cwd) || path.resolve(cwd) !== cwd || /[\x00-\x1f\x7f]/.test(cwd)) throw invalid();
  const browserProfileId = value.browserProfileId ?? null, claudeAccountId = value.claudeAccountId ?? null;
  if (browserProfileId !== null && !validId(browserProfileId)) throw invalid();
  if (value.kind === 'claude-code') {
    if (browserProfileId !== profileId || typeof claudeAccountId !== 'string' ||
        claudeAccountId !== 'default' && !/^account_[a-f0-9]{32}$/.test(claudeAccountId)) throw invalid();
  } else if (claudeAccountId !== null) throw invalid();
  const networkRef = value.networkRef;
  if (!exactKeys(networkRef, ['kind', 'proxyId']) || !['direct', 'managed', 'proxy'].includes(networkRef.kind) ||
      !Object.hasOwn(networkRef, 'proxyId') || networkRef.proxyId !== null && !validId(networkRef.proxyId) ||
      networkRef.kind === 'direct' && networkRef.proxyId !== null || networkRef.kind === 'managed' && networkRef.proxyId === null) throw invalid();
  return { profileId, name, kind: value.kind, cwd, browserProfileId, claudeAccountId,
    networkRef: { kind: networkRef.kind, proxyId: networkRef.proxyId } };
}
const validTime = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
function storedEntry(value) {
  if (!exactKeys(value, entryKeys) || !['createdAt', 'updatedAt', 'lastOpenedAt'].every(key => validTime(value[key])) ||
      value.updatedAt < value.createdAt || value.lastOpenedAt < value.createdAt || value.lastOpenedAt > value.updatedAt) throw storageInvalid();
  const fields = Object.fromEntries(configKeys.filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]]));
  return { id: terminalEntryId(value.id), ...configuration(fields),
    createdAt: value.createdAt, updatedAt: value.updatedAt, lastOpenedAt: value.lastOpenedAt };
}
const identity = value => JSON.stringify([value.profileId, value.kind, value.claudeAccountId, value.browserProfileId, value.cwd]);
const copyEntry = value => ({ ...value, networkRef: { ...value.networkRef } });
const changedAt = entry => new Date(Math.max(Date.now(), Date.parse(entry?.updatedAt ?? '') || 0)).toISOString();

/** Main-process launch metadata only; never credentials, commands, output or PIDs. */
export class TerminalEntryStore {
  constructor({ root } = {}) {
    if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root || /[\x00-\x1f\x7f]/.test(root)) throw unsafePath();
    this.root = root; this.filename = path.join(root, 'saved-terminals.json');
    this.entries = new Map(); this.queue = Promise.resolve(); this.ready = this.initialize();
  }
  async checkedRoot() {
    try {
      const info = await lstat(this.root);
      if (!info.isDirectory() || info.isSymbolicLink() || info.mode & 0o022 || await realpath(this.root) !== this.root) throw unsafePath();
      return info;
    } catch { throw unsafePath(); }
  }
  async checkedFile() {
    try {
      const info = await lstat(this.filename);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.mode & 0o022 || info.size > MAX_BYTES) throw unsafePath();
      return info;
    } catch (error) { if (error.code === 'ENOENT') return null; throw unsafePath(); }
  }
  async initialize() {
    await this.checkedRoot();
    const info = await this.checkedFile();
    if (!info) return;
    let handle;
    try {
      handle = await open(this.filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const before = await handle.stat();
      if (!before.isFile() || before.nlink !== 1 || before.dev !== info.dev || before.ino !== info.ino || before.size > MAX_BYTES) throw storageInvalid();
      const bytes = Buffer.alloc(MAX_BYTES + 1); let count = 0;
      while (count < bytes.length) {
        const { bytesRead } = await handle.read(bytes, count, bytes.length - count, null);
        if (!bytesRead) break;
        count += bytesRead;
      }
      const after = await handle.stat();
      if (count > MAX_BYTES || count !== before.size || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw storageInvalid();
      const document = JSON.parse(bytes.toString('utf8', 0, count));
      if (!exactKeys(document, ['schema', 'version', 'entries']) || document.schema !== 'envara.terminal-entries' || document.version !== 1 ||
          !Array.isArray(document.entries) || document.entries.length > TERMINAL_ENTRY_LIMIT) throw storageInvalid();
      const entries = new Map(), identities = new Set();
      for (const item of document.entries) {
        const entry = storedEntry(item), key = identity(entry);
        if (entries.has(entry.id) || identities.has(key)) throw storageInvalid();
        entries.set(entry.id, entry); identities.add(key);
      }
      this.entries = entries;
    } catch { this.entries.clear(); throw storageInvalid(); }
    finally { await handle?.close(); }
  }
  async list(profileId) {
    if (profileId !== undefined) checkedProfileId(profileId);
    await this.ready;
    return [...this.entries.values()].filter(entry => profileId === undefined || entry.profileId === profileId).map(copyEntry);
  }
  async get(profileId, entryId) {
    checkedProfileId(profileId); terminalEntryId(entryId); await this.ready;
    const entry = this.entries.get(entryId);
    if (!entry || entry.profileId !== profileId) throw notFound();
    return copyEntry(entry);
  }
  mutate(operation) {
    const task = this.queue.then(async () => {
      await this.ready;
      const next = new Map([...this.entries].map(([id, entry]) => [id, copyEntry(entry)]));
      const result = operation(next);
      await this.save(next); this.entries = next;
      return result;
    });
    this.queue = task.catch(() => {}); return task;
  }
  async save(entries) {
    const serialized = JSON.stringify({ schema: 'envara.terminal-entries', version: 1, entries: [...entries.values()] });
    if (entries.size > TERMINAL_ENTRY_LIMIT || Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) throw storageInvalid();
    await this.checkedRoot(); await this.checkedFile();
    const temporary = `${this.filename}.${randomUUID()}.tmp`;
    let handle;
    try {
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      await handle.writeFile(serialized, 'utf8'); await handle.sync(); await handle.close(); handle = null;
      await this.checkedRoot(); await this.checkedFile();
      await rename(temporary, this.filename);
    } catch (error) {
      if (['TERMINAL_ENTRY_UNSAFE_PATH', 'TERMINAL_ENTRY_STORAGE_INVALID'].includes(error.code)) throw error;
      throw storageFailed();
    } finally { await handle?.close(); await rm(temporary, { force: true }).catch(() => {}); }
  }
  upsert(config) {
    const fields = configuration(config);
    return this.mutate(entries => {
      const previous = [...entries.values()].find(entry => identity(entry) === identity(fields));
      const now = changedAt(previous);
      if (!previous && entries.size >= TERMINAL_ENTRY_LIMIT) throw fail('TERMINAL_ENTRY_LIMIT', '最多保存 512 个终端入口。');
      const entry = previous ? { ...previous, networkRef: { ...fields.networkRef }, updatedAt: now, lastOpenedAt: now }
        : { id: `savedterm_${randomUUID().replaceAll('-', '')}`, ...fields, createdAt: now, updatedAt: now, lastOpenedAt: now };
      entries.set(entry.id, entry); return copyEntry(entry);
    });
  }
  rename(profileId, entryId, name) {
    checkedProfileId(profileId); terminalEntryId(entryId); name = checkedName(name);
    return this.mutate(entries => {
      const entry = entries.get(entryId);
      if (!entry || entry.profileId !== profileId) throw notFound();
      entry.name = name; entry.updatedAt = changedAt(entry); return copyEntry(entry);
    });
  }
  remove(profileId, entryId) {
    checkedProfileId(profileId); terminalEntryId(entryId);
    return this.mutate(entries => {
      const entry = entries.get(entryId);
      if (!entry || entry.profileId !== profileId) throw notFound();
      entries.delete(entryId); return copyEntry(entry);
    });
  }
  removeProfile(profileId) {
    checkedProfileId(profileId);
    return this.mutate(entries => {
      const removed = [];
      for (const [id, entry] of entries) if (entry.profileId === profileId) { removed.push(copyEntry(entry)); entries.delete(id); }
      return removed;
    });
  }
}
