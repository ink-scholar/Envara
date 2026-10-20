import { randomUUID } from 'node:crypto';
import { normalizeSshRoute, sameSshRoute } from './terminal-ssh-route.mjs';
const fail = (message, code = 'TERMINAL_ACTION_FAILED') => Object.assign(new Error(message), { code });
const identifier = (value) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw fail('无效的环境标识。', 'VALIDATION_ERROR');
  return value;
};

export const TERMINAL_METHODS = new Set(['terminalSnapshot', 'renameSavedTerminal', 'removeSavedTerminal', 'reopenSavedTerminal', 'chooseWorkspaceDirectory', 'pickTerminalDirectory', 'openTerminal', 'duplicateTerminal', 'writeTerminal', 'resizeTerminal', 'closeTerminal', 'setTerminalLinkBrowser', 'listClaudeAccounts', 'createClaudeAccount', 'renameClaudeAccount', 'deleteClaudeAccount', 'claudeInstallationStatus', 'listTerminalSshConnections', 'prepareTerminalSshIdentity', 'prepareTerminalSshPassword', 'setTerminalSshPassword', 'saveTerminalSshConnection', 'removeTerminalSshConnection']);
const PROFILE_CONFIGURATION = new Set(['updateProfile', 'deleteProfile']);
const PROXY_CONFIGURATION = new Set(['saveProxy', 'deleteProxy']);
const GROUP_CONFIGURATION = new Set(['saveGroup', 'deleteGroup', 'clearGroupProxy']);
const SSH_SELECTION_LIFETIME = 30 * 60 * 1000;
const sshPublicFields = ['id', 'name', 'alias', 'host', 'port', 'user', 'keyLabel', 'keyFingerprint'];
const sshPublicIdentity = value => ({ ...Object.fromEntries(sshPublicFields.filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]])),
  ...(['password', 'publickey'].includes(value.authType) ? { authType: value.authType } : {}),
  ...(value.authType === 'password' ? { passwordReady: value.passwordReady === true } : {}),
  route: normalizeSshRoute(value.route, { legacy: true }),
  ...(['probe', 'host-known-hosts'].includes(value.trustSource) ? { trustSource: value.trustSource } : {}),
  hostFingerprints: Array.isArray(value.hostFingerprints) ? value.hostFingerprints.filter(item => typeof item === 'string') : [] });
const sshPublicList = value => ({ supported: value?.supported === true,
  connections: Array.isArray(value?.connections) ? value.connections.map(sshPublicIdentity) : [] });
const sshWindow = context => {
  const source = context?.window;
  if (!source || typeof source.isDestroyed !== 'function' || source.isDestroyed()) throw fail('终端窗口已关闭。', 'SSH_WINDOW_CLOSED');
  return source;
};
async function sshPreparation(window, operation) {
  const controller = new AbortController(), cancel = () => controller.abort();
  window.once?.('closed', cancel);
  try {
    if (window.isDestroyed()) throw fail('终端窗口已关闭。', 'SSH_WINDOW_CLOSED');
    return await operation(controller.signal);
  } finally { window.removeListener?.('closed', cancel); }
}
const sshPassword = value => {
  if (typeof value !== 'string' || value.length < 1 || Buffer.byteLength(value) > 1024 || /[\x00\r\n]/.test(value))
    throw fail('请输入有效的 SSH 密码。', 'SSH_PASSWORD_INVALID');
  return value;
};

/** Serializes directory selection / launch against edits affecting a live PTY. */
export class TerminalController {
  constructor({ terminal, service, pickDirectory, pickSSHIdentity }) {
    this.terminal = terminal;
    this.service = service;
    this.pickDirectory = pickDirectory;
    this.pickSSHIdentity = pickSSHIdentity;
    /* Folders picked in the native dialog for one new terminal. The renderer
     * holds only a token, so a directory always comes from the user's pick. */
    this.pickedDirectories = new Map();
    this.pickedSSHIdentities = new Map();
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

  async sshRouteOptions(id) {
    identifier(id);
    const snapshot = await this.service.snapshot();
    if (!snapshot.profiles.some(profile => profile.id === id)) throw fail('环境不存在。', 'PROFILE_NOT_FOUND');
    const routeOptions = [{ route: { kind: 'host' }, label: '本机网络', available: true },
      ...snapshot.profiles.map(profile => {
        identifier(profile.id);
        const available = typeof profile.proxyId === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(profile.proxyId);
        return { route: { kind: 'environment', profileId: profile.id },
          label: typeof profile.name === 'string' && profile.name.trim() && !/[\x00-\x1f\x7f]/.test(profile.name)
            ? profile.name.trim().slice(0, 100) : profile.id,
          available, ...(!available ? { errorCode: 'SSH_ROUTE_UNCONFIGURED' } : {}) };
      })];
    const owner = routeOptions.find(option => option.route.kind === 'environment' && option.route.profileId === id);
    return { routeOptions, defaultRoute: owner?.available ? owner.route : { kind: 'host' } };
  }
  async sshList(id) {
    const options = await this.sshRouteOptions(id);
    return { ...sshPublicList(await this.terminal.listTerminalSshConnections({ id })), ...options };
  }
  async sshRouteSelection(id, input) {
    const { routeOptions, defaultRoute } = await this.sshRouteOptions(id);
    const route = normalizeSshRoute(input === undefined ? defaultRoute : input);
    if (!routeOptions.some(option => option.available && sameSshRoute(option.route, route)))
      throw fail('SSH 所选环境尚未配置可用代理，请选择其他路线。', 'SSH_ROUTE_UNCONFIGURED');
    return route;
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

  async prepareSSHIdentity(args, context) {
    const sourceWindow = sshWindow(context);
    await this.profile(args.id);
    const route = await this.sshRouteSelection(args.id, args.route);
    const host = typeof args.host === 'string' ? args.host.trim() : '';
    const user = typeof args.user === 'string' ? args.user.trim() : '';
    if (!host || host.length > 253 || /[\s/\\\x00-\x1f\x7f]/.test(host) || host.startsWith('-')
      || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(user)
      || !Number.isInteger(args.port) || args.port < 1 || args.port > 65535) throw fail('请填写有效的 SSH 主机、端口和用户名。', 'SSH_INVALID_INPUT');
    if (typeof this.pickSSHIdentity !== 'function') throw fail('SSH 连接目前仅支持 macOS。', 'SSH_UNSUPPORTED');
    sshWindow(context);
    const choice = await this.pickSSHIdentity({ id: args.id, host, port: args.port, user }, context);
    sshWindow(context);
    if (choice?.canceled || !choice?.path) return { canceled: true };
    await this.profile(args.id);
    sshWindow(context);
    // A private key path is obtained only from the native picker. The manager
    // returns public fingerprints and its own one-use selection capability.
    const prepared = await sshPreparation(sourceWindow, signal => this.terminal.prepareTerminalSshIdentity({ id: args.id, host, port: args.port, user, keyPath: choice.path, route, signal }));
    sshWindow(context);
    await this.profile(args.id);
    sshWindow(context);
    if (typeof prepared?.selectionToken !== 'string' || !prepared.selectionToken) throw fail('无法准备 SSH 密钥，请重新选择。', 'SSH_KEY_INVALID');
    return this.retainSSHSelection(args.id, sourceWindow, prepared, route);
  }

  retainSSHSelection(id, sourceWindow, prepared, route) {
    if (prepared.route !== undefined && !sameSshRoute(prepared.route, route)) throw fail('SSH 网络准备结果已改变，请重新核对。', 'SSH_SELECTION_MISMATCH');
    const now = Date.now();
    for (const [token, item] of this.pickedSSHIdentities) if (item.expiresAt <= now || item.window.isDestroyed()) this.pickedSSHIdentities.delete(token);
    // Keep only the latest selection for this environment in this window.
    for (const [token, item] of this.pickedSSHIdentities) if (item.id === id && item.window === sourceWindow) this.pickedSSHIdentities.delete(token);
    const selectionToken = randomUUID();
    this.pickedSSHIdentities.set(selectionToken, { id, window: sourceWindow, selectionToken: prepared.selectionToken,
      authType: prepared.authType === 'password' ? prepared.authType : 'publickey',
      host: prepared.host, port: prepared.port, user: prepared.user, route, expiresAt: now + SSH_SELECTION_LIFETIME });
    return { ...sshPublicIdentity({ ...prepared, route }), selectionToken };
  }

  async prepareSSHPassword(args, context) {
    const sourceWindow = sshWindow(context);
    await this.profile(args.id);
    const route = await this.sshRouteSelection(args.id, args.route);
    sshWindow(context);
    // Preparation reads/probes host keys on the selected route. No password or
    // authentication is supplied until the user confirms the displayed keys.
    const prepared = await sshPreparation(sourceWindow, signal => this.terminal.prepareTerminalSshPassword({ id: args.id,
      host: typeof args.host === 'string' ? args.host.trim() : '', port: args.port,
      user: typeof args.user === 'string' ? args.user.trim() : '', route, signal }));
    sshWindow(context);
    await this.profile(args.id);
    sshWindow(context);
    if (prepared?.authType !== 'password' || typeof prepared.selectionToken !== 'string' || !prepared.selectionToken)
      throw fail('无法准备 SSH 连接，请重新核对。', 'SSH_INVALID_INPUT');
    return this.retainSSHSelection(args.id, sourceWindow, prepared, route);
  }

  async assertSSHIdle(id) {
    const state = await this.terminal.snapshot({ id });
    if (state.profiles?.find(row => row.profileId === id)?.sessions?.some(row => ['starting', 'running', 'closing'].includes(row.status)))
      throw fail('请先关闭此环境的终端会话，再保存或移除 SSH 连接。更改在新会话中生效。', 'SSH_TERMINAL_BUSY');
  }

  async saveSSHConnection(args, context) {
    const sourceWindow = sshWindow(context);
    const item = typeof args.selectionToken === 'string' ? this.pickedSSHIdentities.get(args.selectionToken) : null;
    if (!item || item.expiresAt <= Date.now()) {
      this.pickedSSHIdentities.delete(args.selectionToken);
      throw fail('所选 SSH 密钥已失效，请重新选择。', 'SSH_SELECTION_EXPIRED');
    }
    if (item.id !== args.id || item.window !== sourceWindow) throw fail('所选 SSH 密钥不属于当前窗口或环境，请重新选择。', 'SSH_SELECTION_MISMATCH');
    if (args.hostKeyConfirmed !== true) throw fail('请先核对并确认服务器主机指纹。', 'SSH_HOST_CONFIRMATION_REQUIRED');
    if (args.route !== undefined && !sameSshRoute(args.route, item.route)) throw fail('SSH 网络路线已改变，请重新核对。', 'SSH_SELECTION_MISMATCH');
    const password = item.authType === 'password' ? sshPassword(args.password) : undefined;
    await this.assertSSHIdle(args.id);
    sshWindow(context);
    this.pickedSSHIdentities.delete(args.selectionToken);
    await this.terminal.saveTerminalSshConnection({ id: args.id, name: args.name, selectionToken: item.selectionToken, hostKeyConfirmed: true,
      ...(password !== undefined ? { password } : {}) });
    sshWindow(context);
    return this.sshList(args.id);
  }

  async setSSHPassword(args, context) {
    sshWindow(context);
    const password = sshPassword(args.password);
    await this.assertSSHIdle(args.id);
    sshWindow(context);
    await this.terminal.setTerminalSshPassword({ id: args.id, connectionId: args.connectionId, password });
    sshWindow(context);
    return this.sshList(args.id);
  }

  async dispatch(method, args = {}, context = {}) {
    if (!TERMINAL_METHODS.has(method)) throw fail('不支持的终端操作。');
    if (!args || typeof args !== 'object' || Array.isArray(args)) throw fail('终端参数格式无效。', 'VALIDATION_ERROR');
    if (['renameSavedTerminal', 'removeSavedTerminal', 'reopenSavedTerminal'].includes(method)) {
      const keys = method === 'renameSavedTerminal' ? ['id', 'entryId', 'name'] : method === 'reopenSavedTerminal' ? ['id', 'entryId', 'requestId'] : ['id', 'entryId'];
      if (Object.keys(args).some(key => !keys.includes(key)) || typeof args.entryId !== 'string') throw fail('终端参数格式无效。', 'VALIDATION_ERROR');
      const release = method === 'reopenSavedTerminal' ? await this.terminal.reserveSavedTerminalStart({ id: args.id, entryId: args.entryId }) : null;
      return this.serialize(async () => {
        await this.profile(args.id);
        return this.terminal[method]({ id: args.id, entryId: args.entryId, ...(method === 'renameSavedTerminal' ? { name: args.name } : {}),
          ...(method === 'reopenSavedTerminal' ? { requestId: args.requestId } : {}) });
      }).finally(() => release?.());
    }
    if (method === 'terminalSnapshot') {
      if (args.id != null) await this.profile(args.id);
      return this.terminal.snapshot(args);
    }
    if (method === 'listTerminalSshConnections') {
      await this.profile(args.id);
      return this.sshList(args.id);
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
      if (method === 'prepareTerminalSshIdentity') return this.prepareSSHIdentity(args, context);
      if (method === 'prepareTerminalSshPassword') return this.prepareSSHPassword(args, context);
      /* Which browser this environment's links open in. Allowed while it runs:
       * a link resolves the setting when it is opened. */
      if (method === 'setTerminalLinkBrowser') return this.setLinkBrowser(args);
      await this.profile(args.id);
      if (method === 'saveTerminalSshConnection') return this.saveSSHConnection(args, context);
      if (method === 'setTerminalSshPassword') return this.setSSHPassword(args, context);
      if (method === 'removeTerminalSshConnection') {
        sshWindow(context);
        await this.assertSSHIdle(args.id);
        sshWindow(context);
        await this.terminal.removeTerminalSshConnection({ id: args.id, connectionId: args.connectionId });
        sshWindow(context);
        return this.sshList(args.id);
      }
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
      for (const id of this.terminal.activeSshRouteProfileIds?.() ?? []) activeIds.add(id);
      const snapshot = await this.service.snapshot();
      const affected = snapshot.profiles.filter(profile => {
        if (PROFILE_CONFIGURATION.has(method)) return profile.id === args.id;
        if (changesProfiles) return Array.isArray(args.ids) && args.ids.includes(profile.id);
        if (PROXY_CONFIGURATION.has(method)) return profile.proxyId === (method === 'saveProxy' ? args.proxy?.id : args.id);
        return profile.group === args.name;
      });
      const busy = affected.find(profile => activeIds.has(profile.id));
      if (busy) throw fail(`请先关闭「${busy.name}」的终端，再修改其环境或网络配置。`, 'TERMINAL_BUSY');
      const result = await operation();
      const changed = changesProfiles ? new Set((result?.actionResult?.results ?? result?.results ?? []).filter(row => row.ok).map(row => row.id)) : null;
      await this.terminal.invalidateSshRouteProfiles?.(affected.filter(profile => !changed || changed.has(profile.id)).map(profile => profile.id));
      if (method === 'deleteProfile' && typeof this.terminal.removeProfile === 'function') await this.terminal.removeProfile({ id: args.id });
      if (method === 'bulkProfiles' && args.action === 'delete' && typeof this.terminal.removeProfile === 'function') {
        for (const row of result?.actionResult?.results ?? result?.results ?? []) if (row.ok) await this.terminal.removeProfile({ id: row.id });
      }
      return result;
    });
  }
}
