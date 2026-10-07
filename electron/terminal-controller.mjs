const fail = (message, code = 'TERMINAL_ACTION_FAILED') => Object.assign(new Error(message), { code });
const identifier = (value) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw fail('无效的环境标识。', 'VALIDATION_ERROR');
  return value;
};

export const TERMINAL_METHODS = new Set(['terminalSnapshot', 'chooseWorkspaceDirectory', 'openTerminal', 'duplicateTerminal', 'writeTerminal', 'resizeTerminal', 'closeTerminal']);
const PROFILE_CONFIGURATION = new Set(['updateProfile', 'deleteProfile']);
const PROXY_CONFIGURATION = new Set(['saveProxy', 'deleteProxy']);
const GROUP_CONFIGURATION = new Set(['saveGroup', 'deleteGroup', 'clearGroupProxy']);

/** Serializes directory selection / launch against edits affecting a live PTY. */
export class TerminalController {
  constructor({ terminal, service, pickDirectory }) {
    this.terminal = terminal;
    this.service = service;
    this.pickDirectory = pickDirectory;
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

  async dispatch(method, args = {}, context = {}) {
    if (!TERMINAL_METHODS.has(method)) throw fail('不支持的终端操作。');
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw fail('终端参数格式无效。', 'VALIDATION_ERROR');
    if (method === 'terminalSnapshot') {
      if (args.id != null) await this.profile(args.id);
      return this.terminal.snapshot(args);
    }
    if (method === 'writeTerminal') return this.terminal.write(args);
    if (method === 'resizeTerminal') return this.terminal.resize(args);
    return this.serialize(async () => {
      if (method === 'closeTerminal') return this.terminal.close(args);
      if (method === 'duplicateTerminal') {
        const state = await this.terminal.snapshot();
        const profile = state.profiles?.find(row => row.sessions?.some(session => session.sessionId === args.sessionId));
        if (!profile) throw fail('终端会话不存在。', 'TERMINAL_SESSION_NOT_FOUND');
        await this.profile(profile.profileId);
        return this.terminal.duplicate(args);
      }
      identifier(args.id);
      if (method === 'chooseWorkspaceDirectory') return this.selectDirectory(args.id, context);
      await this.profile(args.id);
      const state = await this.terminal.snapshot({ id: args.id });
      const current = state.profiles?.find((row) => row.profileId === args.id);
      if (!current?.cwd) {
        const choice = await this.selectDirectory(args.id, context);
        if (choice.canceled) return choice;
      }
      return this.terminal.create(args);
    });
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
        for (const row of result?.results ?? []) if (row.ok) await this.terminal.removeProfile({ id: row.id });
      }
      return result;
    });
  }
}
