import { randomUUID } from 'node:crypto';
const fail = (message, code = 'TERMINAL_ACTION_FAILED') => Object.assign(new Error(message), { code });
const identifier = (value) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw fail('无效的环境标识。', 'VALIDATION_ERROR');
  return value;
};

export const TERMINAL_METHODS = new Set(['terminalSnapshot', 'chooseWorkspaceDirectory', 'pickTerminalDirectory', 'openTerminal', 'duplicateTerminal', 'writeTerminal', 'resizeTerminal', 'closeTerminal', 'setTerminalLinkBrowser', 'listClaudeAccounts', 'createClaudeAccount', 'renameClaudeAccount', 'deleteClaudeAccount', 'claudeInstallationStatus']);
const PROFILE_CONFIGURATION = new Set(['updateProfile', 'deleteProfile']);
const PROXY_CONFIGURATION = new Set(['saveProxy', 'deleteProxy']);
const GROUP_CONFIGURATION = new Set(['saveGroup', 'deleteGroup', 'clearGroupProxy']);

/** Serializes directory selection / launch against edits affecting a live PTY. */
export class TerminalController {
  constructor({ terminal, service, pickDirectory }) {
    this.terminal = terminal;
    this.service = service;
    this.pickDirectory = pickDirectory;
    /* Folders picked in the native dialog for one new terminal. The renderer
     * holds only a token, so a directory always comes from the user's pick. */
    this.pickedDirectories = new Map();
    this.queue = Promise.resolve();
  }

  serialize(operation) {
    const pending = this.queue.then(operation);
    this.queue = pending.catch(() => {});
    return pending;
  }

  async profile(id) {
    identifier(id);
    const snapshot = await this.service.snapshot();
    const profile = snapshot.profiles.find((row) => row.id === id);
    if (!profile) throw fail('环境不存在。', 'PROFILE_NOT_FOUND');
    return profile;
  }

  async selectDirectory(id, context = {}) {
    await this.profile(id);
    const state = await this.terminal.snapshot({ id });
    const current = state.profiles?.find((row) => row.profileId === id);
    if (current?.sessions?.some((row) => ['running', 'starting', 'closing'].includes(row.status))) {
      throw fail('请先关闭此环境的终端，再更换工作目录。', 'TERMINAL_BUSY');
    }
    const choice = await this.pickDirectory({ id, currentPath: current?.cwd ?? undefined }, context);
    if (choice.canceled || !choice.path) return { canceled: true };
    await this.profile(id); // Native picker can remain open while external automation edits profiles.
    await this.terminal.setDirectory({ id, path: choice.path });
    return { canceled: false, ...(await this.terminal.snapshot({ id })) };
  }

  /* A folder for the next new terminal only: picked, not yet applied. Unlike
   * changing the environment's directory, this is allowed while terminals run,
   * because they keep their own. */
  async pickNewDirectory(id, context = {}) {
    await this.profile(id);
    const state = await this.terminal.snapshot({ id });
    const current = state.profiles?.find((row) => row.profileId === id);
    const choice = await this.pickDirectory({ id, currentPath: current?.cwd ?? undefined }, context);
    if (choice.canceled || !choice.path) return { canceled: true };
    await this.profile(id);
    const now = Date.now();
    for (const [token, item] of this.pickedDirectories) if (item.expiresAt <= now) this.pickedDirectories.delete(token);
    const token = randomUUID();
    this.pickedDirectories.set(token, { id, path: choice.path, expiresAt: now + 30 * 60 * 1000 });
    return { canceled: false, path: choice.path, token };
  }
  takeDirectory(token) {
    if (token == null) return null;
    const item = typeof token === 'string' ? this.pickedDirectories.get(token) : null;
    this.pickedDirectories.delete(token);
    // The user picked this folder for a new terminal; which environment the
    // terminal then runs in may still change before it opens.
    if (!item || item.expiresAt <= Date.now()) throw fail('所选文件夹已失效，请重新选择。', 'TERMINAL_DIRECTORY_EXPIRED');
    return item.path;
  }

  async dispatch(method, args = {}, context = {}) {
    if (!TERMINAL_METHODS.has(method)) throw fail('不支持的终端操作。');
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw fail('终端参数格式无效。', 'VALIDATION_ERROR');
    if (method === 'terminalSnapshot') {
      if (args.id != null) await this.profile(args.id);
      return this.terminal.snapshot(args);
    }
    if (method === 'writeTerminal') return this.terminal.write(args);
    if (method === 'resizeTerminal') return this.terminal.resize(args);
    // Installation can await network I/O inside serialize(). Close must reach
    // its AbortController immediately instead of waiting behind that launch.
    if (method === 'closeTerminal') return this.terminal.close({ sessionId: args.sessionId });
    if (method === 'listClaudeAccounts' || method === 'claudeInstallationStatus') {
      await this.profile(args.id);
      return this.terminal[method]({ id: args.id });
    }
    // Refuse immediately when an account has a queued/installing session, even
    // when that launch is holding the controller's global queue.
    if (method === 'deleteClaudeAccount') {
      await this.profile(args.id);
      return this.terminal.deleteClaudeAccount({ id: args.id, accountId: args.accountId, confirmed: args.confirmed === true });
    }
    const releaseAccount = method === 'openTerminal' && args.kind === 'claude-code'
      ? this.terminal.reserveClaudeAccountStart(args.id, args.claudeAccountId ?? undefined)
      : method === 'duplicateTerminal' ? this.terminal.reserveClaudeAccountDuplicateStart(args.sessionId) : null;
    return this.serialize(async () => {
      if (method === 'duplicateTerminal') {
        const state = await this.terminal.snapshot();
        const profile = state.profiles?.find(row => row.sessions?.some(session => session.sessionId === args.sessionId));
        if (!profile) throw fail('终端会话不存在。', 'TERMINAL_SESSION_NOT_FOUND');
        await this.profile(profile.profileId);
        return this.terminal.duplicate(args);
      }
      identifier(args.id);
      if (method === 'chooseWorkspaceDirectory') return this.selectDirectory(args.id, context);
      if (method === 'pickTerminalDirectory') return this.pickNewDirectory(args.id, context);
      /* Which browser this environment's links open in. Allowed while it runs:
       * a link resolves the setting when it is opened. */
      if (method === 'setTerminalLinkBrowser') return this.setLinkBrowser(args);
      await this.profile(args.id);
      if (method === 'createClaudeAccount') return this.terminal.createClaudeAccount({ id: args.id, name: args.name });
      if (method === 'renameClaudeAccount') return this.terminal.renameClaudeAccount({ id: args.id, accountId: args.accountId, name: args.name });
      // Only the fields a caller may set; a directory comes from a picked token.
      const directory = this.takeDirectory(args.directoryToken ?? null);
      const request = { id: args.id, columns: args.columns, rows: args.rows, fresh: args.fresh === true, directory,
        ...(args.kind !== undefined ? { kind: args.kind } : {}), ...(args.browserProfileId !== undefined ? { browserProfileId: args.browserProfileId } : {}),
        ...(args.claudeAccountId !== undefined ? { claudeAccountId: args.claudeAccountId } : {}), ...(args.requestId !== undefined ? { requestId: args.requestId } : {}),
        ...(args.claudeInstallSource !== undefined ? { claudeInstallSource: args.claudeInstallSource } : {}) };
      if (!directory) {
        const state = await this.terminal.snapshot({ id: args.id });
        const current = state.profiles?.find((row) => row.profileId === args.id);
        if (!current?.cwd) {
          const choice = await this.selectDirectory(args.id, context);
          if (choice.canceled) return choice;
        }
      }
      return this.terminal.create(request);
    }).finally(() => releaseAccount?.());
  }

  async setLinkBrowser(args) {
    identifier(args.id);
    await this.profile(args.id);
    return this.terminal.setLinkBrowser({ id: args.id, browserProfileId: args.browserProfileId ?? null });
  }
  async protectMutation(method, args, operation) {
    const changesProfiles = method === 'bulkProfiles' && ['move', 'delete'].includes(args.action);
    if (!PROFILE_CONFIGURATION.has(method) && !PROXY_CONFIGURATION.has(method) && !GROUP_CONFIGURATION.has(method) && !changesProfiles) return operation();
    return this.serialize(async () => {
      const terminalState = await this.terminal.snapshot();
      const activeIds = new Set((terminalState.profiles ?? []).filter((row) => row.sessions?.some((session) => ['running', 'starting', 'closing'].includes(session.status))).map((row) => row.profileId));
      if (activeIds.size) {
        const snapshot = await this.service.snapshot();
        const affected = snapshot.profiles.filter((profile) => {
          if (!activeIds.has(profile.id)) return false;
          if (PROFILE_CONFIGURATION.has(method)) return profile.id === args.id;
          if (changesProfiles) return Array.isArray(args.ids) && args.ids.includes(profile.id);
          if (PROXY_CONFIGURATION.has(method)) return profile.proxyId === (method === 'saveProxy' ? args.proxy?.id : args.id);
          return profile.group === args.name;
        });
        if (affected.length) throw fail(`请先关闭「${affected[0].name}」的终端，再修改其环境或网络配置。`, 'TERMINAL_BUSY');
      }
      const result = await operation();
      if (method === 'deleteProfile' && typeof this.terminal.removeProfile === 'function') await this.terminal.removeProfile({ id: args.id });
      if (method === 'bulkProfiles' && args.action === 'delete' && typeof this.terminal.removeProfile === 'function') {
        for (const row of result?.actionResult?.results ?? result?.results ?? []) if (row.ok) await this.terminal.removeProfile({ id: row.id });
      }
      return result;
    });
  }
}
