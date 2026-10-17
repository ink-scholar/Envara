import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { access, chmod, lstat, mkdir, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { captureTerminalProcess, closeTerminalProcess } from './terminal-process.mjs';
import { TerminalNetworkFence } from './terminal-network-fence.mjs';
import { findClaudeExecutable, prepareClaudeSession } from './claude-code-session.mjs';
import { ensureClaudeInstallation, claudeInstallationStatus as inspectClaudeInstallation } from './claude-code-installation.mjs';
import { ClaudeAccountStore, DEFAULT_CLAUDE_ACCOUNT, claudeAccountId as validateClaudeAccountId } from './claude-account-store.mjs';
import { installedProcessLocales, resolveProcessLanguage } from './workspace-context.mjs';

const require = createRequire(import.meta.url);
const MAX_SESSIONS = 8;
const MAX_WRITE_BYTES = 64 * 1024;
const MAX_REPLAY_BYTES = 256 * 1024;
// How long output that could begin a secret is held before it is shown anyway.
const SECRET_TAIL_FLUSH_MS = 40;
const MAX_QUEUE_BYTES = 256 * 1024;
const OUTPUT_CHUNK_BYTES = 32 * 1024;
const FALLBACK_EXIT_TIMEOUT_MS = 1000;
const codeError = (message, code = 'TERMINAL_VALIDATION_ERROR') => Object.assign(new Error(message), { code });
const storageFailure = error => ['EACCES', 'EPERM', 'EROFS', 'ENOSPC'].includes(error?.code)
  ? codeError('无法写入此环境的独立终端配置，请检查应用数据目录的权限与剩余空间。', 'TERMINAL_STORAGE_UNAVAILABLE') : error;
const validId = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw codeError('环境标识无效。');
  return value;
};
const integer = (value, fallback, minimum, maximum) => {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) throw codeError('终端尺寸超出范围。');
  return selected;
};
const tail = (value, bytes) => {
  const buffer = Buffer.from(value);
  if (buffer.length <= bytes) return value;
  let offset = buffer.length - bytes;
  while (offset < buffer.length && (buffer[offset] & 0xc0) === 0x80) offset++;
  return buffer.subarray(offset).toString('utf8');
};
const publicNetwork = proxy => {
  if (!proxy) return { mode: 'direct', scope: 'proxy-aware-cli', description: '直连；终端不是系统网络沙箱。' };
  const mode = proxy.protocol ?? proxy.type;
  return { mode, scope: 'proxy-aware-cli', description: `${mode.toUpperCase()} 代理，仅支持代理配置的命令行工具生效；本机地址直连。` };
};
const unknownNetwork = () => ({ mode: 'unknown', scope: 'proxy-aware-cli', description: '启动时读取环境的时区和网络设置。' });

function checkedProxy(value) {
  if (!value) return null;
  const protocol = value.protocol ?? value.type;
  if (!['http', 'https', 'socks5'].includes(protocol)) throw codeError('终端暂不支持此代理协议。', 'TERMINAL_UNSUPPORTED_PROXY');
  let host = value.host;
  if (typeof host !== 'string' || !host || host.length > 253 || /[\s/@?#\0]/.test(host)) throw codeError('终端代理主机无效。');
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (host.includes(':') && net.isIP(host) !== 6) throw codeError('终端代理地址无效。');
  if (!Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535) throw codeError('终端代理端口无效。');
  for (const key of ['username', 'password']) if (value[key] != null && (typeof value[key] !== 'string' || value[key].length > 2048 || /[\0\r\n]/.test(value[key]))) throw codeError('终端代理凭据格式无效。');
  return { protocol, host, port: value.port, username: value.username ?? '', password: value.password ?? '' };
}
function proxyURL(proxy) {
  const host = proxy.host.includes(':') ? `[${proxy.host}]` : proxy.host;
  const value = new URL(`${proxy.protocol}://${host}:${proxy.port}`);
  if (proxy.username || proxy.password) { value.username = proxy.username; value.password = proxy.password; }
  return value.href.replace(/\/$/, '');
}
function safeTimezone(value) {
  if (typeof value !== 'string' || !value || value.length > 128 || value === 'Local') throw codeError('环境时区尚未确认，请先检测出口或设置固定时区。', 'TERMINAL_TIMEZONE_UNAVAILABLE');
  try { new Intl.DateTimeFormat('en', { timeZone: value }); } catch { throw codeError('环境时区无效。', 'TERMINAL_TIMEZONE_UNAVAILABLE'); }
  return value;
}
function defaultPtyFactory(shell, args, options) {
  // Windows workers need a physical package; Unix node-pty maps its helper to
  // app.asar.unpacked itself, so its require must retain the virtual ASAR path.
  const module = process.platform === 'win32' && process.versions.electron && import.meta.url.includes('/app.asar/')
    ? require(path.join(process.resourcesPath, 'app.asar.unpacked/node_modules/node-pty')) : require('node-pty');
  return module.spawn(shell, args, options);
}
async function privateDirectory(parent, name, { owned = false } = {}) {
  const parentInfo = await lstat(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() || owned && process.getuid && parentInfo.uid !== process.getuid()
    || await realpath(parent) !== parent) throw codeError('终端配置目录包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
  const target = path.join(parent, name);
  try { await mkdir(target, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const info = await lstat(target);
  if (!info.isDirectory() || info.isSymbolicLink() || owned && process.getuid && info.uid !== process.getuid()
    || await realpath(target) !== target) throw codeError('终端配置目录包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
  await chmod(target, 0o700);
  return target;
}
async function ownedFile(filename, source, overwrite = false) {
  try {
    const info = await lstat(filename);
    if (info.isSymbolicLink() || !info.isFile()) throw codeError('终端配置文件包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
    if (!overwrite) { await chmod(filename, 0o600); return; }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const temporary = `${filename}.${randomUUID()}.tmp`;
  try { await writeFile(temporary, source, { mode: 0o600, flag: 'wx' }); await rename(temporary, filename); }
  finally { await rm(temporary, { force: true }); }
}

/** Real per-profile PTYs with private tool configuration; this is not an OS sandbox. */
// Seatbelt admits only loopback peers, so a remote HTTP(S) upstream stays unfenced.
function loopbackRoutePort(bridge, endpoint) {
  if (bridge) return bridge.port;
  if (!endpoint) return null;
  try {
    const url = new URL(endpoint);
    return ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) ? Number(url.port || (url.protocol === 'https:' ? 443 : 80)) : null;
  } catch { return null; }
}

export class TerminalService {
  constructor({ dataDir, onEvent = () => {}, resolveContext, ptyFactory = defaultPtyFactory, processControl = { capture: captureTerminalProcess, close: closeTerminalProcess }, additionalExecutablePaths = [],
    networkFence = process.platform === 'darwin' ? new TerminalNetworkFence() : null,
    /* Links a fenced terminal asks to open come back through this channel and
     * are opened by the app, never by the host's default browser. */
    linkChannel = null, browserBroker = null, claudeExecutableResolver = findClaudeExecutable, claudeInstaller = ensureClaudeInstallation, availableLocales = null }) {
    if (!path.isAbsolute(dataDir ?? '') || typeof resolveContext !== 'function') throw codeError('终端数据目录或环境解析器无效。');
    this.dataDir = path.resolve(dataDir);
    this.onEvent = onEvent;
    this.resolveContext = resolveContext;
    this.ptyFactory = ptyFactory;
    this.processControl = processControl;
    if (networkFence != null && typeof networkFence.wrap !== 'function') throw codeError('终端网络围栏无效。');
    this.networkFence = networkFence;
    if (!Array.isArray(additionalExecutablePaths) || additionalExecutablePaths.some(value => typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value))) throw codeError('可信程序搜索目录无效。');
    this.additionalExecutablePaths = [...additionalExecutablePaths];
    if (linkChannel != null && (typeof linkChannel.environment !== 'function' || typeof linkChannel.executableDirectory !== 'function')) throw codeError('终端链接通道无效。');
    this.linkChannel = linkChannel;
    this.browserBroker = browserBroker;
    this.claudeExecutableResolver = claudeExecutableResolver;
    this.claudeInstaller = claudeInstaller;
    if (availableLocales !== null && (!Array.isArray(availableLocales) || availableLocales.some(value => typeof value !== 'string'))) throw codeError('终端语言区域列表无效。');
    this.availableLocales = availableLocales && [...availableLocales];
    this.hostHome = os.homedir();
    this.settings = new Map();
    this.contexts = new Map();
    this.sessions = new Map();
    this.profileQueues = new Map();
    this.settingsQueue = Promise.resolve();
    // Failure generations catch a core exit while resolveContext is awaiting
    // its probe, before the starting session knows its managed proxy id.
    this.managedProxyFailures = new Map();
    this.closed = false;
    this.ready = this.initialize().catch(error => { throw storageFailure(error); });
  }
  async initialize() {
    this.availableLocales ??= await installedProcessLocales();
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    const canonical = await realpath(this.dataDir);
    this.root = await privateDirectory(canonical, 'terminal');
    this.profilesDir = await privateDirectory(this.root, 'profiles');
    this.settingsFile = path.join(this.root, 'workspace.json');
    this.claudeAccounts = new ClaudeAccountStore({ root: this.root });
    await this.claudeAccounts.ready;
    try {
      const info = await lstat(this.settingsFile);
      if (info.isSymbolicLink() || !info.isFile() || info.size > 1024 * 1024) throw codeError('终端元数据文件无效。', 'TERMINAL_UNSAFE_PATH');
      const document = JSON.parse(await readFile(this.settingsFile, 'utf8'));
      if (document.schema !== 'envara.terminal' || document.version !== 1 || !Array.isArray(document.profiles)) throw codeError('终端元数据版本无效。');
      for (const item of document.profiles) {
        validId(item.id);
        // Link preferences can be saved before the first directory is picked.
        // A missing directory is still refused by create(), not by all startup.
        if (item.cwd != null && (typeof item.cwd !== 'string' || !path.isAbsolute(item.cwd) || item.cwd.includes('\0'))) throw codeError('终端工作目录无效。');
        this.settings.set(item.id, { ...(item.cwd != null ? { cwd: item.cwd } : {}), ...(typeof item.browserProfileId === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(item.browserProfileId) ? { browserProfileId: item.browserProfileId } : {}) });
      }
      await chmod(this.settingsFile, 0o600);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  async saveSettings() {
    await ownedFile(this.settingsFile, JSON.stringify({ schema: 'envara.terminal', version: 1,
      profiles: [...this.settings].map(([id, item]) => ({ id, cwd: item.cwd, ...(item.browserProfileId ? { browserProfileId: item.browserProfileId } : {}) })) }, null, 2), true);
  }
  updateSettings(id, update) {
    const task = this.settingsQueue.then(async () => {
      const previous = this.settings.get(id);
      const next = update(previous);
      if (next === undefined) this.settings.delete(id);
      else this.settings.set(id, next);
      try { await this.saveSettings(); }
      catch (error) {
        if (previous === undefined) this.settings.delete(id);
        else this.settings.set(id, previous);
        throw error;
      }
    });
    this.settingsQueue = task.catch(() => {});
    return task;
  }
  serialized(id, operation) {
    validId(id);
    const task = (this.profileQueues.get(id) ?? Promise.resolve()).then(async () => { await this.ready; return operation(); });
    const settled = task.catch(() => {});
    this.profileQueues.set(id, settled);
    settled.then(() => { if (this.profileQueues.get(id) === settled) this.profileQueues.delete(id); });
    return task;
  }
  active(id, kind = null, accountId = null) { return [...this.sessions.values()].find(session => session.profileId === id && (!kind || session.kind === kind) && (!accountId || session.claudeAccountId === accountId) && ['starting', 'running', 'closing'].includes(session.status)); }
  metadata(session) {
    return { sessionId: session.sessionId, profileId: session.profileId, kind: session.kind ?? 'shell', ...(session.browserProfileId ? { browserProfileId: session.browserProfileId, browserName: session.browserName ?? null } : {}), status: session.status, cwd: session.cwd, timezone: session.timezone ?? null, language: session.language ?? null, networkFence: session.networkFence === true, privacy: session.launchContext?.privacy ?? { mode: 'standard' }, geolocation: session.launchContext?.geolocation ?? null, network: session.network ?? unknownNetwork(), columns: session.columns, rows: session.rows, startedAt: session.startedAt, sequence: session.sequence, replay: session.replay,
      ...(session.requestId ? { requestId: session.requestId } : {}),
      ...(session.kind === 'claude-code' ? { claudeAccountId: session.claudeAccountId, claudeAccountName: session.claudeAccountName ?? null, claudeInstallSource: session.claudeInstallSource,
        deviceIdentifierRestrictions: session.deviceIdentifierRestrictions === true } : {}),
      ...(session.claudeInstall ? { claudeInstall: { ...session.claudeInstall } } : {}),
      ...(session.exitCode != null ? { exitCode: session.exitCode } : {}), ...(session.error ? { error: session.error } : {}),
      ...(session.errorCode ? { errorCode: session.errorCode } : {}), ...(session.cleanupError ? { cleanupError: session.cleanupError } : {}) };
  }
  async snapshot({ id } = {}) {
    await this.ready;
    if (id != null) validId(id);
    const ids = id ? [id] : [...new Set([...this.settings.keys(), ...this.contexts.keys(), ...this.sessions.values()].map(value => typeof value === 'string' ? value : value.profileId))];
    return { profiles: ids.map(profileId => {
      const context = this.contexts.get(profileId);
      return { profileId, name: context?.name ?? null, cwd: this.settings.get(profileId)?.cwd ?? null, browserProfileId: this.settings.get(profileId)?.browserProfileId ?? null, timezone: context?.timezone ?? null, timezoneSource: context?.timezoneSource ?? 'unknown', language: context?.language ?? null, network: context?.network ?? unknownNetwork(),
        configDir: context?.configDir ?? null, claudeConfigDir: context?.claudeConfigDir ?? null,
        sessions: [...this.sessions.values()].filter(session => session.profileId === profileId).map(session => this.metadata(session)) };
    }) };
  }
  /* The browser this environment's links use. It is read when a link arrives,
   * so changing it applies to the next link without a restart. */
  linkBrowser(id) { validId(id); return this.settings.get(id)?.browserProfileId ?? null; }
  accountInUse(id, accountId) {
    return [...this.sessions.values()].some(session => session.profileId === id && session.kind === 'claude-code'
      && session.claudeAccountId === accountId && ['starting', 'running', 'closing'].includes(session.status));
  }
  async listClaudeAccounts({ id }) {
    validId(id); await this.ready;
    return { accounts: (await this.claudeAccounts.list(id)).map(account => ({ ...account, inUse: this.accountInUse(id, account.id) })) };
  }
  async claudeInstallationStatus({ id }) {
    validId(id); await this.ready;
    return inspectClaudeInstallation({ home: path.join(this.profilesDir, id, 'home') });
  }
  createClaudeAccount({ id, name }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      return { account: { ...await this.claudeAccounts.create(id, name), inUse: false } };
    });
  }
  renameClaudeAccount({ id, accountId, name }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      validateClaudeAccountId(accountId);
      if (this.accountInUse(id, accountId)) throw codeError('请先关闭使用此登录档案的 Claude 终端，再重命名。', 'CLAUDE_ACCOUNT_IN_USE');
      return { account: { ...await this.claudeAccounts.rename(id, accountId, name), inUse: false } };
    });
  }
  async setLinkBrowser({ id, browserProfileId }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      validId(id);
      if (browserProfileId != null && browserProfileId !== '' && (typeof browserProfileId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(browserProfileId))) throw codeError('浏览器标识无效。', 'VALIDATION_ERROR');
      await this.updateSettings(id, previous => {
        const next = { ...(previous ?? {}), ...(browserProfileId ? { browserProfileId } : {}) };
        if (!browserProfileId) delete next.browserProfileId;
        return next;
      });
      return this.snapshot({ id });
    });
  }
  /* Which environment a live process belongs to, from its process ancestry. */
  sessionForProcess(chain = []) {
    const pids = new Set(chain.map(Number).filter(Number.isSafeInteger));
    for (const session of this.sessions.values())
      if (['running', 'starting'].includes(session.status) && pids.has(Number(session.identity?.pid ?? session.pty?.pid))) return { profileId: session.profileId, sessionId: session.sessionId };
    return null;
  }
  // A dedicated session keeps its browser choice even if the ordinary terminal
  // preference changes. A refusal never delegates to the host browser.
  boundBrowserLink(sessionId, url) {
    const session = this.session(sessionId);
    if (session.kind !== 'claude-code') return null;
    if (session.status !== 'running' || !session.browserBinding) throw codeError('Claude 浏览器会话已结束。', 'TERMINAL_NOT_RUNNING');
    return session.browserBinding.openLink(url);
  }
  managedProxyId(session) {
    const context = session.launchContext;
    return context?.managedProxy === true || context?.managedRoute ? context.proxyId ?? context.managedRoute?.proxyId ?? null : null;
  }
  markManagedProxyFailure(session) {
    const failure = { code: 'CLAUDE_NETWORK_ROUTE_LOST', message: '所选网络的代理内核已停止，Claude Code 会话已中止。请检查网络后新建会话。' };
    session.networkFailure ??= failure;
    session.error ??= failure.message;
    session.errorCode ??= failure.code;
    session.startCancelled = true;
    session.abortController?.abort();
    session.status = 'closing';
    session.network = { ...(session.network ?? unknownNetwork()), available: false, errorCode: failure.code };
    this.emit(session, 'status', { status: 'closing', error: session.error, errorCode: session.errorCode });
    // Revoke synchronously before waiting for process cleanup. The broker's
    // dispose() removes authority before its first filesystem await.
    if (session.browserBinding && !session.browserRevocation) {
      try { session.browserRevocation = Promise.resolve(session.browserBinding.dispose()); }
      catch (error) { session.browserRevocation = Promise.reject(error); }
      session.browserRevocation.catch(() => {});
    }
  }
  /** Called by the owned proxy core's failed event; never repairs/restarts it.
   * Ordinary terminals and sessions using other nodes keep their lifecycle. */
  invalidateManagedProxy(proxyId) {
    if (typeof proxyId !== 'string' || !proxyId) return Promise.resolve([]);
    this.managedProxyFailures.set(proxyId, (this.managedProxyFailures.get(proxyId) ?? 0) + 1);
    const affected = [...this.sessions.values()].filter(session => session.kind === 'claude-code' && !session.finished
      && ['starting', 'running'].includes(session.status) && this.managedProxyId(session) === proxyId);
    for (const session of affected) this.markManagedProxyFailure(session);
    return Promise.allSettled(affected.map(session => this.close({ sessionId: session.sessionId })));
  }
  async setDirectory({ id, path: selectedPath }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      if (this.active(id)) throw codeError('请先关闭此环境的终端，再切换工作目录。', 'TERMINAL_RUNNING');
      await this.rememberDirectory(id, selectedPath);
      return this.snapshot({ id });
    });
  }
  /* The directory new terminals of this environment start in. Sessions that
   * already run keep their own; only the next new one uses this. */
  async rememberDirectory(id, selectedPath) {
    if (typeof selectedPath !== 'string' || !path.isAbsolute(selectedPath) || selectedPath.includes('\0') || selectedPath.length > 8192) throw codeError('请选择有效的绝对工作目录。');
    const cwd = await realpath(selectedPath);
    if (!(await stat(cwd)).isDirectory()) throw codeError('终端工作目录必须是文件夹。');
    await access(cwd, constants.R_OK | constants.X_OK);
    await this.updateSettings(id, previous => ({ ...(previous ?? {}), cwd }));
    return cwd;
  }
  async directories(id, accountId = DEFAULT_CLAUDE_ACCOUNT) {
    const root = await privateDirectory(this.profilesDir, validId(id));
    const home = await privateDirectory(root, 'home');
    const config = await privateDirectory(home, '.config');
    const cache = await privateDirectory(home, '.cache');
    const local = await privateDirectory(home, '.local');
    const data = await privateDirectory(local, 'share');
    const state = await privateDirectory(local, 'state');
    // The default is the original directory. Named accounts never copy or
    // inspect its authentication state; the official CLI owns those files.
    const legacyClaude = await privateDirectory(root, 'claude');
    let claude = legacyClaude;
    if (accountId !== DEFAULT_CLAUDE_ACCOUNT) {
      validateClaudeAccountId(accountId);
      await this.claudeAccounts.get(id, accountId);
      claude = await privateDirectory(await privateDirectory(root, 'claude-accounts'), accountId);
    }
    // Anthropic profiles use a separate directory contract from CLAUDE_CONFIG_DIR.
    // Keep both within the selected account; never adopt the old shared HOME data.
    const anthropic = await privateDirectory(claude, 'anthropic', { owned: true });
    const temp = await privateDirectory(root, 'tmp');
    const history = path.join(home, '.envara_history');
    const zshEnv = '# Envara: environment-local initialization; do not load host shell files.\nunsetopt GLOBAL_RCS\n';
    const zshRC = '# Envara: private interactive shell defaults.\nunsetopt GLOBAL_RCS\nHISTFILE="$HOME/.envara_history"\nHISTSIZE=1000\nSAVEHIST=1000\nsetopt APPEND_HISTORY INC_APPEND_HISTORY HIST_IGNORE_SPACE\nPROMPT=\'envara %~ %# \'\n';
    const bashRC = '# Envara: private interactive shell defaults.\nHISTFILE="$HOME/.envara_history"\nHISTSIZE=1000\nHISTFILESIZE=1000\nshopt -s histappend\nPROMPT_COMMAND=\'history -a\'\nPS1=\'envara \\w \\$ \'\n';
    for (const [file, source] of [[history, ''], [path.join(home, '.gitconfig'), '# Envara environment-local Git configuration\n'], [path.join(home, '.npmrc'), ''], [path.join(home, '.zshenv'), zshEnv], [path.join(home, '.zshrc'), zshRC], [path.join(home, '.bashrc'), bashRC]]) await ownedFile(file, source);
    return { root, home, config, cache, data, state, claude, anthropic, temp, history };
  }
  languageFor(locale) { return resolveProcessLanguage(locale, this.availableLocales ?? ['C']); }
  childEnvironment(directories, timezone, proxyEndpoint, privacy = { mode: 'standard' }, linkShim = null, locale = null) {
    // Build from scratch: host API keys, SSH agent and author variables are
    // deliberately absent. HOME/TZ here belong only to the new child process.
    const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
    const language = this.languageFor(locale);
    const systemPaths = process.platform === 'win32'
      ? [path.join(systemRoot, 'System32'), systemRoot, path.join(systemRoot, 'System32/WindowsPowerShell/v1.0'), path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'nodejs'), path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git/cmd'), path.join(this.hostHome, 'AppData/Roaming/npm'), path.join(this.hostHome, 'AppData/Local/Microsoft/WindowsApps')]
      : ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin', path.join(this.hostHome, '.local/bin')];
    const environment = {
      PATH: [...new Set([...(linkShim ? [linkShim.directory] : []), ...this.additionalExecutablePaths, ...systemPaths])].join(path.delimiter),
      HOME: directories.home, USERPROFILE: directories.home,
      XDG_CONFIG_HOME: directories.config, XDG_CACHE_HOME: directories.cache, XDG_DATA_HOME: directories.data, XDG_STATE_HOME: directories.state,
      CLAUDE_CONFIG_DIR: directories.claude, ANTHROPIC_CONFIG_DIR: directories.anthropic,
      HISTFILE: directories.history, HISTSIZE: '1000', SAVEHIST: '1000',
      ZDOTDIR: directories.home, NPM_CONFIG_USERCONFIG: path.join(directories.home, '.npmrc'),
      GIT_CONFIG_GLOBAL: path.join(directories.home, '.gitconfig'), GIT_CONFIG_NOSYSTEM: '1',
      TMPDIR: directories.temp, TMP: directories.temp, TEMP: directories.temp,
      TZ: timezone, TERM: 'xterm-256color', COLORTERM: 'truecolor', TERM_PROGRAM: 'Envara',
      LANG: language.posix, LC_ALL: language.posix,
      NO_PROXY: 'localhost,127.0.0.1,::1', no_proxy: 'localhost,127.0.0.1,::1',
    };
    if (process.platform === 'win32') {
      for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']) if (process.env[key]) environment[key] = process.env[key];
      const drive = path.parse(directories.home).root;
      environment.HOMEDRIVE = drive.slice(0, 2); environment.HOMEPATH = directories.home.slice(2);
    }
    if (proxyEndpoint) for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) environment[key] = proxyEndpoint;
    // Node's built-in fetch/http ignore proxy variables unless this is set.
    if (proxyEndpoint) environment.NODE_USE_ENV_PROXY = '1';
    // Supported tool opt-outs apply only to this owned shell and its children.
    if (linkShim) {
      environment.BROWSER = path.join(linkShim.directory, 'browser');
      // The open shim reports links over this channel; without these it can only refuse.
      for (const key of ['ENVARA_LINK_SOCKET', 'ENVARA_LINK_TOKEN']) if (typeof linkShim[key] === 'string' && linkShim[key] && !/[\0\r\n]/.test(linkShim[key])) environment[key] = linkShim[key];
    }
    if (privacy?.mode !== 'off') Object.assign(environment, { DO_NOT_TRACK: '1', DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1' });
    if (privacy?.mode === 'strict') environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
    return environment;
  }
  shell(environment) {
    if (process.platform === 'win32') return { executable: process.env.ComSpec ?? path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/cmd.exe'), args: ['/D', '/Q'], environment: { ...environment, PROMPT: 'envara $P$G' } };
    if (process.platform === 'darwin') return { executable: '/bin/zsh', args: ['-d', '-i'], environment: { ...environment, SHELL: '/bin/zsh', PS1: 'envara %~ %# ' } };
    return { executable: '/bin/bash', args: ['--noprofile', '--rcfile', path.join(environment.HOME, '.bashrc'), '-i'], environment: { ...environment, SHELL: '/bin/bash', PS1: 'envara \\w \\$ ' } };
  }
  async create({ id, columns, rows, fresh = false, directory = null, kind = 'shell', browserProfileId = null, claudeAccountId: accountId = null, claudeInstallSource, requestId = null }) {
    if (!['shell', 'claude-code'].includes(kind)) throw codeError('终端会话类型无效。');
    if (kind === 'claude-code' && (browserProfileId !== id || browserProfileId === 'system')) throw codeError('Claude Code 必须使用创建终端时选定的境舱浏览器。', 'CLAUDE_BROWSER_REQUIRED');
    if (requestId != null) validId(requestId);
    if (kind !== 'claude-code' && accountId != null) throw codeError('普通终端不能选择 Claude 登录档案。', 'CLAUDE_ACCOUNT_INVALID');
    if (kind !== 'claude-code' && claudeInstallSource !== undefined) throw codeError('普通终端不能选择 Claude 安装来源。', 'CLAUDE_CODE_INSTALL_SOURCE_INVALID');
    const installSource = kind === 'claude-code' ? claudeInstallSource === undefined ? 'download' : claudeInstallSource : null;
    if (kind === 'claude-code' && !['download', 'local'].includes(installSource)) throw codeError('Claude 安装来源无效，请重新选择。', 'CLAUDE_CODE_INSTALL_SOURCE_INVALID');
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      const account = kind === 'claude-code' ? await this.claudeAccounts.get(id, accountId ?? DEFAULT_CLAUDE_ACCOUNT) : null;
      if (!fresh) {
        const existing = this.active(id, kind, account?.id);
        if (existing) return this.metadata(existing);
      }
      const cwd = directory != null ? await this.rememberDirectory(id, directory) : this.settings.get(id)?.cwd;
      if (!cwd) throw codeError('请先选择终端工作目录。', 'TERMINAL_DIRECTORY_REQUIRED');
      return this.startSession({ id, cwd, columns, rows, kind, browserProfileId, account, requestId, claudeInstallSource: installSource });
    });
  }
  async duplicate({ sessionId, columns, rows }) {
    const source = this.session(sessionId);
    return this.serialized(source.profileId, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      this.requireDuplicable(source);
      // Credentials stay in native memory. A duplicate uses the source launch
      // context, never a fresh resolver or any interactive command/output state.
      const context = { ...source.launchContext, proxy: source.launchContext.proxy && { ...source.launchContext.proxy } };
      const account = source.kind === 'claude-code' ? await this.claudeAccounts.get(source.profileId, source.claudeAccountId) : null;
      return this.startSession({ id: source.profileId, cwd: source.cwd, columns: columns ?? source.columns, rows: rows ?? source.rows, context, source, kind: source.kind, browserProfileId: source.browserProfileId, account, claudeInstallSource: source.claudeInstallSource });
    });
  }
  requireDuplicable(session) {
    if (session.status !== 'running' || session.finished || session.finishing || !session.launchContext) throw codeError('只能复制仍在运行的终端。', 'TERMINAL_NOT_RUNNING');
  }
  assertStarting(session) {
    if (session.networkFailure) throw codeError(session.networkFailure.message, session.networkFailure.code);
    if (this.closed || session.startCancelled || session.status !== 'starting' || session.finished) throw codeError('终端启动已取消。', 'TERMINAL_START_CANCELLED');
  }
  async retainLaunchCleanup(session, field, resource) {
    // An async resource can arrive after Close finished an empty cleanup. Wait
    // for that cleanup before retaining the new authority for the normal retry
    // path; a failed disposal must never disappear in a local catch handler.
    await session.finishing?.catch(() => {});
    await session.cleanupPromise?.catch(() => {});
    session[field] = resource;
    session.cleanupPromise = null; session.finishing = null; session.finished = false; session.status = 'closing';
  }
  installProgress(session, progress) {
    if (session.status !== 'starting' || session.startCancelled || session.finished || this.closed
      || !['metadata', 'downloading', 'verifying', 'installing'].includes(progress?.phase)) return;
    const safe = { phase: progress.phase };
    for (const key of ['receivedBytes', 'totalBytes']) if (Number.isSafeInteger(progress[key]) && progress[key] >= 0) safe[key] = progress[key];
    if (typeof progress.version === 'string' && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(progress.version) && progress.version.length <= 80) safe.version = progress.version;
    session.claudeInstall = safe;
    this.emit(session, 'status', { status: 'starting', claudeInstall: safe });
  }
  async startSession({ id, cwd, columns, rows, context: copiedContext, source, kind = 'shell', browserProfileId = null, account = null, requestId = null, claudeInstallSource = 'download' }) {
    if ([...this.sessions.values()].filter(session => ['starting', 'running', 'closing'].includes(session.status)).length >= MAX_SESSIONS) throw codeError('最多同时打开 8 个终端会话。', 'TERMINAL_LIMIT');
    const session = { sessionId: `term_${randomUUID().replaceAll('-', '')}`, profileId: id, kind, requestId, claudeAccountId: account?.id ?? null, claudeAccountName: account?.name ?? null, claudeInstallSource: kind === 'claude-code' ? claudeInstallSource : null, abortController: new AbortController(), browserProfileId: kind === 'claude-code' ? browserProfileId : null, status: 'starting', cwd, columns: integer(columns, 100, 20, 400), rows: integer(rows, 30, 5, 150), startedAt: new Date().toISOString(), sequence: 0, replay: '', events: [], queuedBytes: 0, secretTail: '', secrets: [], disposables: [], finished: false, pumping: false };
    const proxyFailuresAtStart = new Map(this.managedProxyFailures);
    // Reserve before the first asynchronous check so parallel profiles and
    // duplicates cannot race past the global session limit.
    this.sessions.set(session.sessionId, session);
    this.emit(session, 'status', { status: 'starting' });
    try {
      const canonical = await realpath(cwd);
      this.assertStarting(session);
      const directory = await stat(cwd);
      this.assertStarting(session);
      if (canonical !== cwd || !directory.isDirectory()) throw codeError('工作目录已改变，请重新选择。', 'TERMINAL_UNSAFE_PATH');
      const context = copiedContext ?? await this.resolveContext(id);
      this.assertStarting(session);
      if (!context || context.id !== id) throw codeError('未找到此环境的终端配置。', 'TERMINAL_PROFILE_NOT_FOUND');
      const timezone = safeTimezone(context.timezone);
      session.language = this.languageFor(context.locale);
      const proxy = checkedProxy(context.proxy);
      session.launchContext = { ...structuredClone(context), id, name: typeof context.name === 'string' ? context.name.slice(0, 100) : null, timezone, timezoneSource: typeof context.timezoneSource === 'string' ? context.timezoneSource.slice(0, 64) : 'unknown', proxy, privacy: context.privacy ?? { mode: 'standard' }, geolocation: context.geolocation ?? null, networkEgress: context.network ?? context.networkEgress ?? null };
      const managedProxyId = this.managedProxyId(session);
      if (kind === 'claude-code' && managedProxyId && (this.managedProxyFailures.get(managedProxyId) ?? 0) !== (proxyFailuresAtStart.get(managedProxyId) ?? 0)) {
        this.markManagedProxyFailure(session); this.assertStarting(session);
      }
      const directories = await this.directories(id, account?.id ?? DEFAULT_CLAUDE_ACCOUNT);
      this.assertStarting(session);
      let endpoint;
      if (proxy?.protocol === 'socks5') {
        const { createTerminalProxyBridge } = await import('./terminal-proxy-bridge.mjs');
        this.assertStarting(session);
        const bridge = await createTerminalProxyBridge(proxy);
        try { this.assertStarting(session); }
        catch (error) { await bridge.close(); throw error; }
        session.bridge = bridge;
        endpoint = session.bridge.url;
      } else if (proxy) endpoint = proxyURL(proxy);
      if (endpoint) {
        const parsed = new URL(endpoint);
        session.secrets = [...new Set([endpoint, proxy && proxyURL(proxy), proxy?.password, proxy?.password && encodeURIComponent(proxy.password), parsed.password && decodeURIComponent(parsed.password), parsed.username && Buffer.from(`${decodeURIComponent(parsed.username)}:${decodeURIComponent(parsed.password)}`).toString('base64')].filter(value => typeof value === 'string' && value.length >= 4))].sort((a, b) => b.length - a.length);
      }
      session.timezone = timezone; session.network = { ...publicNetwork(proxy), ...(typeof context.proxyName === 'string' && context.proxyName ? { routeName: context.proxyName.slice(0, 100) } : {}), ...(session.launchContext.networkEgress?.ok ? { egress: session.launchContext.networkEgress } : {}) };
      this.contexts.set(id, { name: session.launchContext.name, timezone, timezoneSource: session.launchContext.timezoneSource, language: session.language, network: session.network, configDir: directories.config, claudeConfigDir: directories.claude });
      if (source) this.requireDuplicable(source);
      /* The environment's links leave through its own designated browser; the
       * shim reports them over the app's channel instead of the host opener. */
      let linkShim = null;
      if (this.linkChannel) {
        try { linkShim = { directory: await this.linkChannel.executableDirectory(id), ...this.linkChannel.environment(id) }; }
        catch (error) { this.assertStarting(session); throw codeError(`终端链接通道不可用，未启动终端：${error.message}`, 'TERMINAL_LINK_CHANNEL_UNAVAILABLE'); }
      }
      let claudeLaunch = null;
      if (kind === 'claude-code') {
        if (!proxy || !loopbackRoutePort(session.bridge, endpoint) || !this.networkFence) throw codeError('Claude Code 专用会话需要支持网络围栏的代理线路。', 'CLAUDE_NETWORK_FENCE_REQUIRED');
        if (!this.browserBroker || !linkShim) throw codeError('Claude 浏览器通道不可用，未启动会话。', 'CLAUDE_BROWSER_UNAVAILABLE');
        const installation = await this.claudeInstaller({ home: directories.home, source: session.claudeInstallSource,
          findHostExecutable: () => this.claudeExecutableResolver({ hostHome: this.hostHome, platform: process.platform, additionalExecutablePaths: this.additionalExecutablePaths }),
          downloadContext: { proxyUrl: endpoint, signal: session.abortController.signal },
          onProgress: progress => this.installProgress(session, progress) });
        this.assertStarting(session);
        const binding = await this.browserBroker.createSession({ sessionId: session.sessionId, profileId: id, browserProfileId, context: session.launchContext });
        try { this.assertStarting(session); }
        catch (error) { await this.retainLaunchCleanup(session, 'browserBinding', binding); throw error; }
        session.browserBinding = binding;
        session.browserName = binding.browser.name;
        linkShim = { directory: linkShim.directory, ...binding.environment };
        for (const [key, value] of Object.entries(binding.environment)) if (/TOKEN|SECRET/.test(key) && typeof value === 'string') session.secrets.push(value);
        const environment = { ...this.childEnvironment(directories, timezone, endpoint, session.launchContext.privacy, linkShim, session.launchContext.locale), ...binding.environment };
        const prepared = await prepareClaudeSession({ sessionId: session.sessionId, directories, installation, mcpServer: binding.mcpServer, environment, privacy: session.launchContext.privacy });
        try { this.assertStarting(session); }
        catch (error) { await this.retainLaunchCleanup(session, 'claudeLaunch', prepared); throw error; }
        session.claudeLaunch = prepared;
        claudeLaunch = prepared;
      }
      if (linkShim?.ENVARA_LINK_TOKEN) session.secrets = [...new Set([...session.secrets, linkShim.ENVARA_LINK_TOKEN])];
      this.assertStarting(session);
      // Dedicated Claude terminals start at a normal prompt. Their private
      // PATH wrapper supplies the binding only when the user runs `claude`.
      let shell = this.shell(claudeLaunch?.environment ?? this.childEnvironment(directories, timezone, endpoint, session.launchContext.privacy, linkShim, session.launchContext.locale));
      // A loopback route (this session's bridge or the managed core listener)
      // is the environment's only network path for this whole process tree.
      // Fence it or refuse to start; never run it unfenced.
      session.networkFence = false;
      const routePort = loopbackRoutePort(session.bridge, endpoint);
      if (routePort && this.networkFence) {
        shell = await this.networkFence.wrap(shell, { routePort, ...(kind === 'claude-code' ? { restrictDeviceIdentifiers: true } : {}) });
        if (kind === 'claude-code' && shell.deviceIdentifierRestrictions !== true)
          throw codeError('设备标识读取限制未确认，未启动 Claude 终端。', 'TERMINAL_DEVICE_IDENTIFIERS_UNAVAILABLE');
        session.deviceIdentifierRestrictions = kind === 'claude-code' && shell.deviceIdentifierRestrictions === true;
        session.networkFence = true;
        session.network = { ...session.network, fenced: true, description: '围栏阻止直接公网连接。本地开发服务仍可访问，其联网不受此围栏控制。' };
        const known = this.contexts.get(id);
        if (known) this.contexts.set(id, { ...known, network: session.network });
      }
      this.assertStarting(session);
      const spawned = this.ptyFactory(shell.executable, shell.args, { name: 'xterm-256color', cols: session.columns, rows: session.rows, cwd, env: shell.environment, encoding: 'utf8', handleFlowControl: false });
      const pty = typeof spawned?.then === 'function' ? await spawned : spawned;
      // The native factory is synchronous. An injected asynchronous factory can
      // still return a resource after close; reclaim it instead of reusing the
      // earlier empty cleanup result or leaving an untracked process.
      const cancelled = this.closed || session.startCancelled || session.finished || session.status !== 'starting';
      if (cancelled) {
        await session.finishing?.catch(() => {});
        session.finished = false; session.status = 'closing';
        session.cleanupPromise = null; session.finishing = null;
      }
      session.pty = pty;
      if (!session.pty || typeof session.pty.onData !== 'function' || typeof session.pty.onExit !== 'function') throw codeError('原生终端接口无效。', 'TERMINAL_PTY_UNAVAILABLE');
      session.capturePromise = Promise.resolve().then(() => this.processControl.capture(session.pty.pid)).then(identity => { session.identity = identity; return identity; });
      if (!cancelled) session.disposables.push(session.pty.onData(data => this.receive(session, data)));
      session.disposables.push(session.pty.onExit(event => { session.nativeExited = true; void this.finish(session, event).catch(() => {}); }));
      if (cancelled) this.assertStarting(session);
      await session.capturePromise;
      if (session.networkFailure) this.assertStarting(session);
      if (session.status === 'starting' && !session.finished && !session.finishing) { session.status = 'running'; this.emit(session, 'status', { status: 'running' }); }
      this.pruneSessions();
      return this.metadata(session);
    } catch (error) {
      if (typeof error?.claudeCleanup === 'function') {
        // Failed preparation returns the same private retry authority.
        await this.retainLaunchCleanup(session, 'claudeLaunch', { cleanup: error.claudeCleanup });
      }
      const reported = session.networkFailure ? codeError(session.networkFailure.message, session.networkFailure.code)
        : session.startCancelled || this.closed ? codeError('终端启动已取消。', 'TERMINAL_START_CANCELLED') : storageFailure(error);
      session.error ??= this.redact(session, reported.message ?? '终端无法启动。', true);
      session.errorCode ??= reported.code ?? 'TERMINAL_START_FAILED';
      session.status = 'closing';
      try { await this.cleanup(session); session.finished = true; session.status = reported.code === 'TERMINAL_START_CANCELLED' ? 'closed' : 'error'; this.releaseLaunchContext(session); }
      catch { session.cleanupError = '终端进程清理未完成，请重试关闭会话。'; }
      this.emit(session, 'status', { status: session.status, error: session.error, errorCode: session.errorCode, ...(session.cleanupError ? { cleanupError: session.cleanupError } : {}) });
      this.pruneSessions();
      throw codeError(session.error, session.errorCode);
    }
  }
  releaseLaunchContext(session) {
    session.launchContext = null;
    session.secrets = [];
    session.secretTail = '';
    session.bridge = null;
    session.pty = null;
    session.identity = null;
    session.capturePromise = null;
    session.browserBinding = null;
    session.browserRevocation = null;
    session.claudeLaunch = null;
    for (const disposable of session.disposables) disposable?.dispose?.();
    session.disposables = [];
  }
  redact(session, data, final = false) {
    let value = session.secretTail + String(data);
    session.secretTail = '';
    for (const secret of session.secrets) value = value.replaceAll(secret, '[redacted]');
    if (!final) {
      let length = 0;
      for (const secret of session.secrets) for (let count = Math.min(secret.length - 1, value.length); count > length; count--) if (value.endsWith(secret.slice(0, count))) { length = count; break; }
      if (length) { session.secretTail = value.slice(-length); value = value.slice(0, -length); }
    } else if (value && session.secrets.some(secret => secret.startsWith(value))) value = '[redacted]';
    return value;
  }
  receive(session, data) {
    if (session.finished || typeof data !== 'string') return;
    clearTimeout(session.secretTimer); session.secretTimer = null;
    this.deliver(session, this.redact(session, data));
    /* Output that splits a secret arrives in one burst, so a tail that could
     * start a secret waits only briefly. Without this, the echo of a typed
     * character that happens to begin a secret stays hidden until the next key. */
    if (session.secretTail) session.secretTimer = setTimeout(() => {
      session.secretTimer = null;
      if (session.finished || !session.secretTail) return;
      const held = session.secretTail; session.secretTail = '';
      this.deliver(session, held);
    }, SECRET_TAIL_FLUSH_MS);
  }
  deliver(session, value) {
    if (!value) return;
    session.replay = tail(session.replay + value, MAX_REPLAY_BYTES);
    const buffer = Buffer.from(tail(value, MAX_QUEUE_BYTES));
    for (let start = 0; start < buffer.length;) {
      let end = Math.min(buffer.length, start + OUTPUT_CHUNK_BYTES);
      while (end < buffer.length && (buffer[end] & 0xc0) === 0x80) end--;
      this.emit(session, 'data', { data: buffer.subarray(start, end).toString('utf8') });
      start = end;
    }
  }
  pump(session) {
    if (session.pumping) return;
    session.pumping = true;
    queueMicrotask(() => { void (async () => {
      try {
        while (session.events.length) {
          const item = session.events.shift();
          session.queuedBytes -= item.bytes;
          try { await this.onEvent(item.event); } catch {}
          item.resolve();
          if (session.paused && session.queuedBytes < MAX_QUEUE_BYTES / 4 && !session.finished) { try { session.pty?.resume?.(); session.paused = false; } catch {} }
        }
      } finally { session.pumping = false; }
    })().catch(() => { session.pumping = false; }); });
  }
  emit(session, type, value = {}) {
    const event = { type, sessionId: session.sessionId, profileId: session.profileId, ...(session.requestId ? { requestId: session.requestId } : {}), sequence: ++session.sequence, ...value };
    const bytes = type === 'data' ? Buffer.byteLength(value.data) : 0;
    const delivery = new Promise(resolve => session.events.push({ event, bytes, resolve }));
    session.queuedBytes += bytes;
    while (session.queuedBytes > MAX_QUEUE_BYTES) {
      const index = session.events.findIndex(item => item.event.type === 'data');
      if (index < 0) break;
      const [removed] = session.events.splice(index, 1);
      session.queuedBytes -= removed.bytes; removed.resolve();
      if (!session.outputLimited) { session.outputLimited = true; this.emit(session, 'status', { status: session.status, message: '输出过快，已保留最近的终端输出。' }); }
    }
    if (session.queuedBytes > MAX_QUEUE_BYTES / 2 && !session.finished) { try { session.pty?.pause?.(); session.paused = true; } catch {} }
    this.pump(session);
    return delivery;
  }
  session(sessionId) {
    if (typeof sessionId !== 'string' || !/^term_[a-f0-9]{32}$/.test(sessionId)) throw codeError('终端会话标识无效。');
    const session = this.sessions.get(sessionId);
    if (!session) throw codeError('终端会话不存在。', 'TERMINAL_SESSION_NOT_FOUND');
    return session;
  }
  async write({ sessionId, data }) {
    const session = this.session(sessionId);
    if (session.status !== 'running' || session.finished) throw codeError('终端已停止。', 'TERMINAL_NOT_RUNNING');
    if (typeof data !== 'string' || Buffer.byteLength(data) > MAX_WRITE_BYTES) throw codeError('终端输入过大，请分段发送。', 'TERMINAL_INPUT_LIMIT');
    session.pty.write(data);
    return { accepted: true };
  }
  async resize({ sessionId, columns, rows }) {
    const session = this.session(sessionId);
    if (session.status !== 'running' || session.finished) throw codeError('终端已停止。', 'TERMINAL_NOT_RUNNING');
    const cols = integer(columns, session.columns, 20, 400); const height = integer(rows, session.rows, 5, 150);
    session.pty.resize(cols, height); session.columns = cols; session.rows = height;
    return this.metadata(session);
  }
  async stopUnidentifiedPty(session) {
    let listener, timer;
    try {
      const exited = new Promise(resolve => {
        // Listen before signaling: native node-pty can report exit immediately.
        listener = session.pty.onExit(() => { session.nativeExited = true; resolve(true); });
        timer = setTimeout(() => resolve(false), FALLBACK_EXIT_TIMEOUT_MS);
      });
      session.pty.kill();
      if (!session.nativeExited && !await exited) throw new Error('exit not confirmed');
    } catch { throw codeError('终端仍有未退出的子进程。', 'TERMINAL_CLEANUP_FAILED'); }
    finally { clearTimeout(timer); try { listener?.dispose?.(); } catch {} }
  }
  async cleanup(session) {
    if (session.cleanupPromise) return session.cleanupPromise;
    session.cleanupPromise = Promise.resolve().then(async () => {
      let failure;
      const attempt = async operation => { try { await operation(); } catch (error) { failure ??= error; } };
      // Revoke first. A private-directory removal failure must never skip the
      // process family, proxy bridge, or other independently owned resources.
      await attempt(async () => {
        if (session.browserRevocation) {
          try { await session.browserRevocation; } catch (error) { session.browserRevocation = null; throw error; }
        } else await session.browserBinding?.dispose();
      });
      await attempt(async () => {
        if (session.capturePromise && !session.identity) await session.capturePromise.catch(() => {});
        if (session.pty && session.identity) {
          const result = await this.processControl.close({ pty: session.pty, identity: session.identity });
          if (result?.ok === false) throw codeError('终端仍有未退出的子进程。', 'TERMINAL_CLEANUP_FAILED');
        } else if (session.pty && !session.finished && !session.nativeExited) {
          // Without a captured identity this is the only remaining cleanup
          // handle. A refused kill must keep it available for explicit retry.
          await this.stopUnidentifiedPty(session);
        }
      });
      await attempt(() => session.bridge?.close());
      await attempt(() => session.claudeLaunch?.cleanup());
      if (failure) {
        if (session.networkFailure) {
          session.cleanupError = '终端进程清理未完成，请重试关闭会话。';
          this.emit(session, 'status', { status: 'closing', error: session.error, errorCode: session.errorCode, cleanupError: session.cleanupError });
        }
        throw failure;
      }
      session.cleanupError = null;
    });
    // A later explicit Close can retry a failed filesystem cleanup.
    void session.cleanupPromise.catch(() => { session.cleanupPromise = null; });
    return session.cleanupPromise;
  }
  async finish(session, event = {}) {
    if (session.finished) return;
    if (session.finishing) return session.finishing;
    const closing = session.status === 'closing';
    session.status = 'closing';
    session.finishing = Promise.resolve().then(async () => {
      if (session.finished) return;
      clearTimeout(session.secretTimer); session.secretTimer = null;
      const pending = this.redact(session, '', true);
      if (pending) { session.replay = tail(session.replay + pending, MAX_REPLAY_BYTES); this.emit(session, 'data', { data: pending }); }
      if (Number.isInteger(event.exitCode)) session.exitCode = event.exitCode;
      try { await this.cleanup(session); }
      catch (error) { session.cleanupError = '终端进程清理未完成，请查看应用状态。'; session.error ??= session.cleanupError; this.emit(session, 'status', { status: 'closing', error: session.error, ...(session.errorCode ? { errorCode: session.errorCode } : {}), cleanupError: session.cleanupError }); throw error; }
      session.finished = true; session.status = session.networkFailure ? 'error' : closing ? 'closed' : 'exited';
      this.releaseLaunchContext(session);
      this.emit(session, 'exit', { exitCode: session.exitCode ?? null, status: session.status, ...(session.error ? { error: session.error } : {}), ...(session.errorCode ? { errorCode: session.errorCode } : {}), ...(Number.isInteger(event.signal) ? { signal: event.signal } : {}) });
      this.pruneSessions();
    });
    void session.finishing.catch(() => { session.finishing = null; });
    return session.finishing;
  }
  async close({ sessionId }) {
    const session = this.session(sessionId);
    session.abortController?.abort();
    if (session.finished) { await this.cleanup(session); return this.metadata(session); }
    if (session.status === 'starting') session.startCancelled = true;
    session.status = 'closing'; this.emit(session, 'status', { status: 'closing', ...(session.error ? { error: session.error } : {}), ...(session.errorCode ? { errorCode: session.errorCode } : {}), ...(session.cleanupError ? { cleanupError: session.cleanupError } : {}) });
    await this.cleanup(session);
    if (!session.finished) await this.finish(session);
    return this.metadata(session);
  }
  pruneSessions() {
    const finished = [...this.sessions.values()].filter(session => session.finished);
    while (finished.length > 32) this.sessions.delete(finished.shift().sessionId);
  }
  async removeProfile({ id }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      if (this.active(id)) throw codeError('请先关闭此环境的终端。', 'TERMINAL_RUNNING');
      const namespace = path.join(this.profilesDir, id);
      const parentInfo = await lstat(this.profilesDir);
      if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() || await realpath(this.profilesDir) !== this.profilesDir) throw codeError('终端配置目录包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
      let exists = false;
      try {
        const info = await lstat(namespace); exists = true;
        if (!info.isDirectory() || info.isSymbolicLink() || await realpath(namespace) !== namespace) throw codeError('终端配置目录包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
      const selected = this.settings.get(id)?.cwd;
      const preserve = selected && (selected === namespace || selected.startsWith(`${namespace}${path.sep}`));
      await this.updateSettings(id, () => undefined);
      if (exists && !preserve) await rm(namespace, { recursive: true, force: true });
      await this.claudeAccounts.removeProfile(id);
      this.contexts.delete(id);
      for (const session of this.sessions.values()) if (session.profileId === id) this.sessions.delete(session.sessionId);
      return { profileId: id, removed: true, configRemoved: !preserve, ...(preserve ? { reason: 'SELECTED_DIRECTORY_PRESERVED' } : {}) };
    });
  }
  async shutdown() {
    this.closed = true;
    // A download may be awaiting inside the profile queue. Cancel it before
    // waiting for that queue, otherwise shutdown cannot reach session cleanup.
    for (const session of this.sessions.values()) session.abortController?.abort();
    await this.ready;
    await Promise.allSettled([...this.profileQueues.values()]);
    await this.settingsQueue;
    const results = await Promise.allSettled([...this.sessions.values()].filter(session => !session.finished).map(session => this.close({ sessionId: session.sessionId })));
    const rejected = results.find(result => result.status === 'rejected');
    if (rejected) throw rejected.reason;
  }
}
