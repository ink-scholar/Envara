import path from 'node:path';
import { constants } from 'node:fs';
import { lstat, open, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const fail = (message, code = 'CLAUDE_ACCOUNT_INVALID') => Object.assign(new Error(message), { code });
const storageInvalid = () => fail('Claude 登录档案元数据无效。', 'CLAUDE_ACCOUNT_STORAGE_INVALID');
export const DEFAULT_CLAUDE_ACCOUNT = 'default';
const MAX_ACCOUNTS = 20;
const MAX_BYTES = 1024 * 1024;
const profileId = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw fail('Claude 登录档案的境舱标识无效。');
  return value;
};
export const claudeAccountId = value => {
  if (typeof value !== 'string' || (value !== DEFAULT_CLAUDE_ACCOUNT && !/^account_[a-f0-9]{32}$/.test(value))) throw fail('Claude 登录档案标识无效。');
  return value;
};
const accountName = value => {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 80 || /[\x00-\x1f\x7f]/.test(value)) throw fail('请填写不超过 80 个字符的 Claude 登录档案名称。');
  return value.trim();
};
const nameKey = value => value.normalize('NFKC').toLocaleLowerCase('en-US');
const publicAccount = account => ({ id: account.id, name: account.name, default: account.id === DEFAULT_CLAUDE_ACCOUNT });
const defaultAccount = () => ({ id: DEFAULT_CLAUDE_ACCOUNT, name: '默认' });

/** Names and stable ids only. Authentication files and Keychain are never read. */
export class ClaudeAccountStore {
  constructor({ root } = {}) {
    if (typeof root !== 'string' || !path.isAbsolute(root) || path.resolve(root) !== root || /[\0\r\n]/.test(root)) throw fail('Claude 登录档案存储目录无效。', 'CLAUDE_ACCOUNT_UNSAFE_PATH');
    this.root = root;
    this.filename = path.join(root, 'claude-accounts.json');
    this.profiles = new Map();
    this.queue = Promise.resolve();
    this.ready = this.initialize();
  }
  async checkedRoot() {
    const info = await lstat(this.root);
    if (!info.isDirectory() || info.isSymbolicLink() || await realpath(this.root) !== this.root) throw fail('Claude 登录档案存储目录包含不安全的链接。', 'CLAUDE_ACCOUNT_UNSAFE_PATH');
  }
  async initialize() {
    await this.checkedRoot();
    let info;
    try { info = await lstat(this.filename); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_BYTES) throw storageInvalid();
    const handle = await open(this.filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino || opened.size > MAX_BYTES) throw storageInvalid();
      const bytes = Buffer.alloc(MAX_BYTES + 1);
      let count = 0;
      while (count < bytes.length) {
        const { bytesRead } = await handle.read(bytes, count, bytes.length - count, null);
        if (!bytesRead) break;
        count += bytesRead;
      }
      const after = await handle.stat();
      if (count > MAX_BYTES || count !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) throw storageInvalid();
      const document = JSON.parse(bytes.toString('utf8', 0, count));
      if (document?.schema !== 'envara.claude-accounts' || document.version !== 1 || !Array.isArray(document.profiles)) throw storageInvalid();
      for (const item of document.profiles) {
        const id = profileId(item?.id);
        if (this.profiles.has(id) || !Array.isArray(item.accounts) || !item.accounts.length || item.accounts.length > MAX_ACCOUNTS) throw storageInvalid();
        const ids = new Set(), names = new Set();
        const accounts = item.accounts.map(value => {
          const account = { id: claudeAccountId(value?.id), name: accountName(value?.name) };
          if (ids.has(account.id) || names.has(nameKey(account.name))) throw storageInvalid();
          ids.add(account.id); names.add(nameKey(account.name));
          return account;
        });
        if (!ids.has(DEFAULT_CLAUDE_ACCOUNT)) throw storageInvalid();
        this.profiles.set(id, accounts);
      }
    } catch (error) {
      this.profiles.clear();
      if (error.code === 'CLAUDE_ACCOUNT_STORAGE_INVALID') throw error;
      throw storageInvalid();
    } finally { await handle.close(); }
  }
  async list(id) {
    profileId(id); await this.ready;
    return (this.profiles.get(id) ?? [defaultAccount()]).map(publicAccount);
  }
  async get(id, accountId = DEFAULT_CLAUDE_ACCOUNT) {
    claudeAccountId(accountId);
    const account = (await this.list(id)).find(item => item.id === accountId);
    if (!account) throw fail('此 Claude 登录档案已不存在，请重新选择。', 'CLAUDE_ACCOUNT_NOT_FOUND');
    return account;
  }
  mutate(operation) {
    const task = this.queue.then(async () => {
      await this.ready;
      const next = new Map([...this.profiles].map(([id, accounts]) => [id, accounts.map(account => ({ ...account }))]));
      const result = operation(next);
      await this.save(next);
      this.profiles = next;
      return result;
    });
    this.queue = task.catch(() => {});
    return task;
  }
  async save(profiles) {
    const serialized = JSON.stringify({ schema: 'envara.claude-accounts', version: 1, profiles: [...profiles].map(([id, accounts]) => ({ id, accounts })) });
    if (Buffer.byteLength(serialized, 'utf8') > MAX_BYTES) throw storageInvalid();
    await this.checkedRoot();
    try {
      const info = await lstat(this.filename);
      if (!info.isFile() || info.isSymbolicLink()) throw fail('Claude 登录档案元数据包含不安全的链接。', 'CLAUDE_ACCOUNT_UNSAFE_PATH');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const temporary = `${this.filename}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, serialized, { mode: 0o600, flag: 'wx' });
      await rename(temporary, this.filename);
    } finally { await rm(temporary, { force: true }); }
  }
  create(id, name) {
    profileId(id); name = accountName(name);
    return this.mutate(profiles => {
      const accounts = profiles.get(id) ?? [defaultAccount()];
      if (accounts.length >= MAX_ACCOUNTS) throw fail('一个境舱最多保存 20 个 Claude 登录档案。', 'CLAUDE_ACCOUNT_LIMIT');
      if (accounts.some(account => nameKey(account.name) === nameKey(name))) throw fail('此 Claude 登录档案名称已存在。', 'CLAUDE_ACCOUNT_NAME_EXISTS');
      const account = { id: `account_${randomUUID().replaceAll('-', '')}`, name };
      profiles.set(id, [...accounts, account]);
      return publicAccount(account);
    });
  }
  /* An imported environment keeps its login profile ids and names; their
   * directories arrived with the export. Only a new environment adopts them. */
  adopt(id, accounts) {
    profileId(id);
    const adopted = (Array.isArray(accounts) ? accounts : []).filter(account => account?.id !== DEFAULT_CLAUDE_ACCOUNT)
      .slice(0, MAX_ACCOUNTS - 1).map(account => ({ id: claudeAccountId(account?.id), name: accountName(account?.name) }));
    if (new Set(adopted.map(account => nameKey(account.name))).size !== adopted.length) throw fail('此 Claude 登录档案名称已存在。', 'CLAUDE_ACCOUNT_NAME_EXISTS');
    return this.mutate(profiles => {
      if (profiles.has(id)) throw fail('此境舱已有 Claude 登录档案。', 'CLAUDE_ACCOUNT_NAME_EXISTS');
      if (adopted.length) profiles.set(id, [defaultAccount(), ...adopted]);
      return adopted.map(publicAccount);
    });
  }
  rename(id, accountId, name) {
    profileId(id); claudeAccountId(accountId); name = accountName(name);
    return this.mutate(profiles => {
      const accounts = profiles.get(id) ?? [defaultAccount()];
      const account = accounts.find(item => item.id === accountId);
      if (!account) throw fail('此 Claude 登录档案已不存在，请重新选择。', 'CLAUDE_ACCOUNT_NOT_FOUND');
      if (accounts.some(item => item.id !== accountId && nameKey(item.name) === nameKey(name))) throw fail('此 Claude 登录档案名称已存在。', 'CLAUDE_ACCOUNT_NAME_EXISTS');
      account.name = name; profiles.set(id, accounts);
      return publicAccount(account);
    });
  }
  removeProfile(id) {
    profileId(id);
    return this.mutate(profiles => { profiles.delete(id); });
  }
}
