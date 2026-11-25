import path from 'node:path';
import { constants } from 'node:fs';
import { access, lstat, open, realpath, rename, rm, stat } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { writableByOthers } from './file-trust.mjs';
import { terminalEntryId } from './terminal-entry-store.mjs';

const MAX_BYTES = 256 * 1024;
export const WORK_COMBINATION_LIMIT = 128;
export const WORK_COMBINATION_ENTRY_LIMIT = 8;
const REQUEST_LIMIT = 128;
const messages = {
  WORK_COMBINATION_INVALID: '工作组合参数无效。',
  WORK_COMBINATION_NOT_FOUND: '此工作组合已不存在。',
  WORK_COMBINATION_STORAGE_INVALID: '无法读取工作组合，原有资料已保留。',
  WORK_COMBINATION_STORAGE_FAILED: '无法保存工作组合，请重试。',
  WORK_COMBINATION_UNSAFE_PATH: '工作组合存储路径不安全。',
  WORK_COMBINATION_LIMIT: '工作组合数量或终端数量已达上限。',
  WORK_COMBINATION_CONTEXT_CHANGED: '组合中的终端或浏览器配置已改变，请重新保存组合。',
  WORK_COMBINATION_ENTRY_UNAVAILABLE: '组合中的终端、目录或登录档案已不可用。',
  WORK_COMBINATION_PROFILE_UNAVAILABLE: '此环境已不可用。',
  WORK_COMBINATION_OPEN_FAILED: '工作组合未能全部打开。已打开的会话会保留，请先检查现有会话。',
  WORK_COMBINATION_BUSY: '工作组合正在处理中，请稍后重试。',
};
const failure = code => Object.assign(new Error(messages[code]), { code });
const invalid = () => failure('WORK_COMBINATION_INVALID');
const safeError = error => {
  const code = Object.hasOwn(messages, error?.code) ? error.code : 'WORK_COMBINATION_OPEN_FAILED';
  return { code, message: messages[code] };
};
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
const validId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
const checkedId = value => { if (!validId(value)) throw invalid(); return value; };
const checkedCombinationId = value => { if (typeof value !== 'string' || !/^workcombo_[a-f0-9]{32}$/.test(value)) throw invalid(); return value; };
const checkedName = value => {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 80 || /[\x00-\x1f\x7f]/.test(value)) throw invalid();
  return value.trim();
};
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const validHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const clone = value => structuredClone(value);
const validTime = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

// Only already-authorized main-process metadata enters this digest. Runtime
// credentials, names, pinning, timestamps, output and commands are excluded.
export function workCombinationEntryHash(entry) {
  if (!entry || !validId(entry.profileId) || !['shell', 'claude-code'].includes(entry.kind) || typeof entry.cwd !== 'string' ||
      !path.isAbsolute(entry.cwd) || path.resolve(entry.cwd) !== entry.cwd || !entry.networkRef) throw invalid();
  return digest([entry.profileId, entry.kind, entry.cwd, entry.browserProfileId ?? null, entry.claudeAccountId ?? null,
    entry.networkRef.kind, entry.networkRef.proxyId ?? null]);
}
function browserHash(profile) {
  if (!profile || !validId(profile.id) || typeof profile.engine !== 'string' || !profile.engine ||
      profile.proxyId != null && !validId(profile.proxyId)) throw failure('WORK_COMBINATION_PROFILE_UNAVAILABLE');
  return digest([profile.id, profile.engine, profile.proxyId ?? null]);
}
function storedCombination(value) {
  if (!exact(value, ['id', 'profileId', 'name', 'entries', 'browser', 'createdAt']) || !validTime(value.createdAt) ||
      !Array.isArray(value.entries) || !value.entries.length || value.entries.length > WORK_COMBINATION_ENTRY_LIMIT ||
      new Set(value.entries.map(entry => entry?.entryId)).size !== value.entries.length) throw invalid();
  const entries = value.entries.map(entry => {
    if (!exact(entry, ['entryId', 'contextHash']) || !validHash(entry.contextHash)) throw invalid();
    return { entryId: terminalEntryId(entry.entryId), contextHash: entry.contextHash };
  });
  const profileId = checkedId(value.profileId);
  if (value.browser !== null && (!exact(value.browser, ['profileId', 'contextHash']) || value.browser.profileId !== profileId || !validHash(value.browser.contextHash))) throw invalid();
  return { id: checkedCombinationId(value.id), profileId, name: checkedName(value.name), entries,
    browser: value.browser && { ...value.browser }, createdAt: value.createdAt };
}
const publicCombination = value => ({ id: value.id, profileId: value.profileId, name: value.name,
  entryIds: value.entries.map(entry => entry.entryId), includeBrowser: value.browser !== null, createdAt: value.createdAt });

export class WorkCombinations {
  constructor({ root, terminal, getProfile, ensureBrowser } = {}) {
    if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root || /[\x00-\x1f\x7f]/.test(root)) throw failure('WORK_COMBINATION_UNSAFE_PATH');
    if (!terminal || typeof getProfile !== 'function' || typeof ensureBrowser !== 'function') throw invalid();
    this.root = root; this.filename = path.join(root, 'work-combinations.json');
    this.terminal = terminal; this.getProfile = getProfile; this.ensureBrowser = ensureBrowser;
    this.combinations = new Map(); this.requests = new Map(); this.queue = Promise.resolve();
    this.ready = this.initialize();
  }
  async checkedRoot() {
    try {
      const info = await lstat(this.root);
      if (!info.isDirectory() || info.isSymbolicLink() || writableByOthers(info) || await realpath(this.root) !== this.root) throw new Error();
    } catch { throw failure('WORK_COMBINATION_UNSAFE_PATH'); }
  }
  async checkedFile() {
    try {
      const info = await lstat(this.filename);
      if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || writableByOthers(info) || info.size > MAX_BYTES) throw new Error();
      return info;
    } catch (error) { if (error.code === 'ENOENT') return null; throw failure('WORK_COMBINATION_UNSAFE_PATH'); }
  }
  async initialize() {
    await this.terminal.ready;
    await this.checkedRoot(); const info = await this.checkedFile();
    if (!info) return;
    let handle;
    try {
      handle = await open(this.filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const before = await handle.stat();
      if (!before.isFile() || before.nlink !== 1 || before.dev !== info.dev || before.ino !== info.ino || before.size > MAX_BYTES) throw new Error();
      const buffer = Buffer.alloc(MAX_BYTES + 1); let count = 0;
      while (count < buffer.length) {
        const { bytesRead } = await handle.read(buffer, count, buffer.length - count, null);
        if (!bytesRead) break; count += bytesRead;
      }
      const after = await handle.stat();
      if (count > MAX_BYTES || count !== before.size || ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw new Error();
      const data = JSON.parse(buffer.toString('utf8', 0, count));
      if (!exact(data, ['schema', 'version', 'combinations']) || data.schema !== 'envara.work-combinations' || data.version !== 1 ||
          !Array.isArray(data.combinations) || data.combinations.length > WORK_COMBINATION_LIMIT) throw new Error();
      const next = new Map();
      for (const item of data.combinations) {
        const value = storedCombination(item);
        if (next.has(value.id)) throw new Error(); next.set(value.id, value);
      }
      this.combinations = next;
    } catch { throw failure('WORK_COMBINATION_STORAGE_INVALID'); }
    finally { await handle?.close(); }
  }
  serialize(operation) {
    const task = this.queue.then(async () => { await this.ready; return operation(); });
    this.queue = task.catch(() => {}); return task;
  }
  async persist(next) {
    const bytes = JSON.stringify({ schema: 'envara.work-combinations', version: 1, combinations: [...next.values()] });
    if (next.size > WORK_COMBINATION_LIMIT || Buffer.byteLength(bytes) > MAX_BYTES) throw failure('WORK_COMBINATION_LIMIT');
    await this.checkedRoot(); await this.checkedFile();
    const temporary = `${this.filename}.${randomUUID()}.tmp`; let handle;
    try {
      handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = null;
      await this.checkedRoot(); await this.checkedFile(); await rename(temporary, this.filename);
    } catch (error) {
      if (error.code === 'WORK_COMBINATION_UNSAFE_PATH') throw error;
      throw failure('WORK_COMBINATION_STORAGE_FAILED');
    } finally { await handle?.close(); await rm(temporary, { force: true }).catch(() => {}); }
  }
  async profile(id) {
    let profile;
    try { profile = await this.getProfile(id); } catch { throw failure('WORK_COMBINATION_PROFILE_UNAVAILABLE'); }
    if (!profile || profile.id !== id) throw failure('WORK_COMBINATION_PROFILE_UNAVAILABLE');
    return profile;
  }
  async list(args) {
    if (!exact(args, ['id'])) throw invalid(); const id = checkedId(args.id);
    await this.ready;
    return { combinations: [...this.combinations.values()].filter(value => value.profileId === id).map(publicCombination) };
  }
  save(args) {
    if (!exact(args, ['id', 'name', 'entryIds', 'includeBrowser']) || typeof args.includeBrowser !== 'boolean' ||
        !Array.isArray(args.entryIds) || !args.entryIds.length || args.entryIds.length > WORK_COMBINATION_ENTRY_LIMIT ||
        new Set(args.entryIds).size !== args.entryIds.length) throw invalid();
    const id = checkedId(args.id), name = checkedName(args.name);
    const entryIds = args.entryIds.map(terminalEntryId), includeBrowser = args.includeBrowser;
    return this.serialize(async () => {
      const profile = await this.profile(id), entries = [];
      for (const entryId of entryIds) {
        let entry; try { entry = await this.terminal.savedTerminal(id, entryId); }
        catch { throw failure('WORK_COMBINATION_ENTRY_UNAVAILABLE'); }
        if (entry.profileId !== id) throw failure('WORK_COMBINATION_ENTRY_UNAVAILABLE');
        entries.push({ entryId, contextHash: workCombinationEntryHash(entry) });
      }
      const value = { id: `workcombo_${randomUUID().replaceAll('-', '')}`, profileId: id, name, entries,
        browser: includeBrowser ? { profileId: id, contextHash: browserHash(profile) } : null, createdAt: new Date().toISOString() };
      const next = new Map(this.combinations); next.set(value.id, value);
      await this.persist(next); this.combinations = next;
      return { combination: publicCombination(value) };
    });
  }
  remove(args) {
    if (!exact(args, ['id', 'combinationId'])) throw invalid();
    const id = checkedId(args.id), combinationId = checkedCombinationId(args.combinationId);
    return this.serialize(async () => {
      if (this.combinations.get(combinationId)?.profileId !== id) throw failure('WORK_COMBINATION_NOT_FOUND');
      const next = new Map(this.combinations); next.delete(combinationId);
      await this.persist(next); this.combinations = next; return { removed: true };
    });
  }
  // Called after an explicitly successful environment deletion. The profile
  // need not exist anymore; only this store's matching metadata is removed.
  removeProfile(profileId) {
    const id = checkedId(profileId);
    return this.serialize(async () => {
      const next = new Map([...this.combinations].filter(([, value]) => value.profileId !== id));
      const removed = this.combinations.size - next.size;
      if (!removed) return { removed: 0 };
      await this.persist(next); this.combinations = next;
      return { removed };
    });
  }
  async preflight(value) {
    const profile = await this.profile(value.profileId);
    if (value.browser && browserHash(profile) !== value.browser.contextHash) throw failure('WORK_COMBINATION_CONTEXT_CHANGED');
    const entries = [];
    for (const item of value.entries) {
      let entry;
      try { entry = await this.terminal.savedTerminal(value.profileId, item.entryId); }
      catch { throw failure('WORK_COMBINATION_ENTRY_UNAVAILABLE'); }
      if (entry.profileId !== value.profileId || workCombinationEntryHash(entry) !== item.contextHash) throw failure('WORK_COMBINATION_CONTEXT_CHANGED');
      try {
        if (await realpath(entry.cwd) !== entry.cwd || !(await stat(entry.cwd)).isDirectory()) throw new Error();
        await access(entry.cwd, constants.R_OK | constants.X_OK);
        if (entry.kind === 'claude-code') await this.terminal.claudeAccounts.get(value.profileId, entry.claudeAccountId);
      } catch { throw failure('WORK_COMBINATION_ENTRY_UNAVAILABLE'); }
      entries.push(entry);
    }
    const context = await this.terminal.resolveContext(value.profileId);
    if (context?.id !== value.profileId) throw failure('WORK_COMBINATION_PROFILE_UNAVAILABLE');
    for (const entry of entries) {
      try { await this.terminal.validateSavedTerminalContext(entry, context); }
      catch { throw failure('WORK_COMBINATION_CONTEXT_CHANGED'); }
    }
    return entries;
  }
  open(args) {
    if (!exact(args, ['id', 'combinationId', 'requestId'])) throw invalid();
    const id = checkedId(args.id), combinationId = checkedCombinationId(args.combinationId), requestId = checkedId(args.requestId);
    const key = `${id}:${combinationId}`, previous = this.requests.get(requestId);
    if (previous) { if (previous.key !== key) throw invalid(); return previous.promise.then(clone); }
    if (this.requests.size >= REQUEST_LIMIT) {
      const completed = [...this.requests].find(([, value]) => value.completed);
      if (!completed) throw failure('WORK_COMBINATION_BUSY'); this.requests.delete(completed[0]);
    }
    const request = { key, completed: false, promise: null };
    request.promise = this.serialize(async () => {
      const result = { status: 'failed', profileId: id, combinationId, requestId, sessions: [], browserOpened: false, error: null };
      const releases = [];
      try {
        const value = this.combinations.get(combinationId);
        if (value?.profileId !== id) throw failure('WORK_COMBINATION_NOT_FOUND');
        const entries = await this.preflight(value);
        for (const entry of entries) releases.push(await this.terminal.reserveSavedTerminalStart({ id, entryId: entry.id }));
        if (value.browser) {
          if (browserHash(await this.profile(id)) !== value.browser.contextHash) throw failure('WORK_COMBINATION_CONTEXT_CHANGED');
          await this.ensureBrowser(id); result.browserOpened = true;
        }
        for (const entry of entries) {
          const current = await this.terminal.savedTerminal(id, entry.id);
          if (workCombinationEntryHash(current) !== workCombinationEntryHash(entry)) throw failure('WORK_COMBINATION_CONTEXT_CHANGED');
          // Fresh checks the authorized directory, account and route again at
          // launch. No command, old process state or renderer path is accepted.
          const opened = await this.terminal.openSavedTerminalFresh({ id, entryId: entry.id, requestId: `combo_${randomUUID().replaceAll('-', '')}` });
          if (!opened || opened.canceled || opened.profileId !== id || !validId(opened.sessionId)) throw failure('WORK_COMBINATION_OPEN_FAILED');
          result.sessions.push({ profileId: id, sessionId: opened.sessionId, savedTerminalId: entry.id });
        }
        result.status = 'opened';
      } catch (error) {
        result.status = result.sessions.length || result.browserOpened ? 'partial' : 'failed'; result.error = safeError(error);
      } finally { for (const release of releases.reverse()) release?.(); }
      return result;
    }).finally(() => { request.completed = true; });
    this.requests.set(requestId, request);
    return request.promise.then(clone);
  }
}
