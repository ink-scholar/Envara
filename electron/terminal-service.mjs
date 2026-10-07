import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { access, chmod, lstat, mkdir, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { captureTerminalProcess, closeTerminalProcess } from './terminal-process.mjs';

const require = createRequire(import.meta.url);
const MAX_SESSIONS = 8;
const MAX_WRITE_BYTES = 64 * 1024;
const MAX_REPLAY_BYTES = 256 * 1024;
const MAX_QUEUE_BYTES = 256 * 1024;
const OUTPUT_CHUNK_BYTES = 32 * 1024;
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
async function privateDirectory(parent, name) {
  const parentInfo = await lstat(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() || await realpath(parent) !== parent) throw codeError('终端配置目录包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
  const target = path.join(parent, name);
  try { await mkdir(target, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const info = await lstat(target);
  if (!info.isDirectory() || info.isSymbolicLink() || await realpath(target) !== target) throw codeError('终端配置目录包含不安全的链接。', 'TERMINAL_UNSAFE_PATH');
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
export class TerminalService {
  constructor({ dataDir, onEvent = () => {}, resolveContext, ptyFactory = defaultPtyFactory, processControl = { capture: captureTerminalProcess, close: closeTerminalProcess }, additionalExecutablePaths = [] }) {
    if (!path.isAbsolute(dataDir ?? '') || typeof resolveContext !== 'function') throw codeError('终端数据目录或环境解析器无效。');
    this.dataDir = path.resolve(dataDir);
    this.onEvent = onEvent;
    this.resolveContext = resolveContext;
    this.ptyFactory = ptyFactory;
    this.processControl = processControl;
    if (!Array.isArray(additionalExecutablePaths) || additionalExecutablePaths.some(value => typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value))) throw codeError('可信程序搜索目录无效。');
    this.additionalExecutablePaths = [...additionalExecutablePaths];
    this.hostHome = os.homedir();
    this.settings = new Map();
    this.contexts = new Map();
    this.sessions = new Map();
    this.profileQueues = new Map();
    this.settingsQueue = Promise.resolve();
    this.closed = false;
    this.ready = this.initialize().catch(error => { throw storageFailure(error); });
  }
  async initialize() {
    await mkdir(this.dataDir, { recursive: true, mode: 0o700 });
    const canonical = await realpath(this.dataDir);
    this.root = await privateDirectory(canonical, 'terminal');
    this.profilesDir = await privateDirectory(this.root, 'profiles');
    this.settingsFile = path.join(this.root, 'workspace.json');
    try {
      const info = await lstat(this.settingsFile);
      if (info.isSymbolicLink() || !info.isFile() || info.size > 1024 * 1024) throw codeError('终端元数据文件无效。', 'TERMINAL_UNSAFE_PATH');
      const document = JSON.parse(await readFile(this.settingsFile, 'utf8'));
      if (document.schema !== 'envara.terminal' || document.version !== 1 || !Array.isArray(document.profiles)) throw codeError('终端元数据版本无效。');
      for (const item of document.profiles) {
        validId(item.id);
        if (typeof item.cwd !== 'string' || !path.isAbsolute(item.cwd) || item.cwd.includes('\0')) throw codeError('终端工作目录无效。');
        this.settings.set(item.id, { cwd: item.cwd });
      }
      await chmod(this.settingsFile, 0o600);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  async saveSettings() {
    await ownedFile(this.settingsFile, JSON.stringify({ schema: 'envara.terminal', version: 1, profiles: [...this.settings].map(([id, item]) => ({ id, cwd: item.cwd })) }, null, 2), true);
  }
  mutateSettings(operation) {
    const task = this.settingsQueue.then(operation);
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
  active(id) { return [...this.sessions.values()].find(session => session.profileId === id && ['starting', 'running', 'closing'].includes(session.status)); }
  metadata(session) {
    return { sessionId: session.sessionId, profileId: session.profileId, status: session.status, cwd: session.cwd, timezone: session.timezone ?? null, privacy: session.launchContext?.privacy ?? { mode: 'standard' }, geolocation: session.launchContext?.geolocation ?? null, network: session.network ?? unknownNetwork(), columns: session.columns, rows: session.rows, startedAt: session.startedAt, sequence: session.sequence, replay: session.replay,
      ...(session.exitCode != null ? { exitCode: session.exitCode } : {}), ...(session.error ? { error: session.error } : {}) };
  }
  async snapshot({ id } = {}) {
    await this.ready;
    if (id != null) validId(id);
    const ids = id ? [id] : [...new Set([...this.settings.keys(), ...this.contexts.keys(), ...this.sessions.values()].map(value => typeof value === 'string' ? value : value.profileId))];
    return { profiles: ids.map(profileId => {
      const context = this.contexts.get(profileId);
      return { profileId, name: context?.name ?? null, cwd: this.settings.get(profileId)?.cwd ?? null, timezone: context?.timezone ?? null, timezoneSource: context?.timezoneSource ?? 'unknown', network: context?.network ?? unknownNetwork(),
        configDir: context?.configDir ?? null, claudeConfigDir: context?.claudeConfigDir ?? null,
        sessions: [...this.sessions.values()].filter(session => session.profileId === profileId).map(session => this.metadata(session)) };
    }) };
  }
  async setDirectory({ id, path: selectedPath }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      if (this.active(id)) throw codeError('请先关闭此环境的终端，再切换工作目录。', 'TERMINAL_RUNNING');
      if (typeof selectedPath !== 'string' || !path.isAbsolute(selectedPath) || selectedPath.includes('\0') || selectedPath.length > 8192) throw codeError('请选择有效的绝对工作目录。');
      const cwd = await realpath(selectedPath);
      if (!(await stat(cwd)).isDirectory()) throw codeError('终端工作目录必须是文件夹。');
      await access(cwd, constants.R_OK | constants.X_OK);
      await this.mutateSettings(async () => {
        const previous = this.settings.get(id);
        this.settings.set(id, { cwd });
        try { await this.saveSettings(); } catch (error) { if (previous) this.settings.set(id, previous); else this.settings.delete(id); throw error; }
      });
      return this.snapshot({ id });
    });
  }
  async directories(id) {
    const root = await privateDirectory(this.profilesDir, validId(id));
    const home = await privateDirectory(root, 'home');
    const config = await privateDirectory(home, '.config');
    const cache = await privateDirectory(home, '.cache');
    const local = await privateDirectory(home, '.local');
    const data = await privateDirectory(local, 'share');
    const state = await privateDirectory(local, 'state');
    const claude = await privateDirectory(root, 'claude');
    const temp = await privateDirectory(root, 'tmp');
    const history = path.join(home, '.envara_history');
    const zshEnv = '# Envara: environment-local initialization; do not load host shell files.\nunsetopt GLOBAL_RCS\n';
    const zshRC = '# Envara: private interactive shell defaults.\nunsetopt GLOBAL_RCS\nHISTFILE="$HOME/.envara_history"\nHISTSIZE=1000\nSAVEHIST=1000\nsetopt APPEND_HISTORY INC_APPEND_HISTORY HIST_IGNORE_SPACE\nPROMPT=\'envara %~ %# \'\n';
    const bashRC = '# Envara: private interactive shell defaults.\nHISTFILE="$HOME/.envara_history"\nHISTSIZE=1000\nHISTFILESIZE=1000\nshopt -s histappend\nPROMPT_COMMAND=\'history -a\'\nPS1=\'envara \\w \\$ \'\n';
    for (const [file, source] of [[history, ''], [path.join(home, '.gitconfig'), '# Envara environment-local Git configuration\n'], [path.join(home, '.npmrc'), ''], [path.join(home, '.zshenv'), zshEnv], [path.join(home, '.zshrc'), zshRC], [path.join(home, '.bashrc'), bashRC]]) await ownedFile(file, source);
    return { root, home, config, cache, data, state, claude, temp, history };
  }
  childEnvironment(directories, timezone, proxyEndpoint, privacy = { mode: 'standard' }) {
    // Build from scratch: host API keys, SSH agent and author variables are
    // deliberately absent. HOME/TZ here belong only to the new child process.
    const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
    const systemPaths = process.platform === 'win32'
      ? [path.join(systemRoot, 'System32'), systemRoot, path.join(systemRoot, 'System32/WindowsPowerShell/v1.0'), path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'nodejs'), path.join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git/cmd'), path.join(this.hostHome, 'AppData/Roaming/npm'), path.join(this.hostHome, 'AppData/Local/Microsoft/WindowsApps')]
      : ['/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin', path.join(this.hostHome, '.local/bin')];
    const environment = {
      PATH: [...new Set([...this.additionalExecutablePaths, ...systemPaths])].join(path.delimiter),
      HOME: directories.home, USERPROFILE: directories.home,
      XDG_CONFIG_HOME: directories.config, XDG_CACHE_HOME: directories.cache, XDG_DATA_HOME: directories.data, XDG_STATE_HOME: directories.state,
      CLAUDE_CONFIG_DIR: directories.claude, HISTFILE: directories.history, HISTSIZE: '1000', SAVEHIST: '1000',
      ZDOTDIR: directories.home, NPM_CONFIG_USERCONFIG: path.join(directories.home, '.npmrc'),
      GIT_CONFIG_GLOBAL: path.join(directories.home, '.gitconfig'), GIT_CONFIG_NOSYSTEM: '1',
      TMPDIR: directories.temp, TMP: directories.temp, TEMP: directories.temp,
      TZ: timezone, TERM: 'xterm-256color', COLORTERM: 'truecolor', TERM_PROGRAM: 'Envara',
      LANG: /^[A-Za-z0-9_.@-]{1,64}$/.test(process.env.LANG ?? '') ? process.env.LANG : 'en_US.UTF-8',
      NO_PROXY: 'localhost,127.0.0.1,::1', no_proxy: 'localhost,127.0.0.1,::1',
    };
    if (process.platform === 'win32') {
      for (const key of ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']) if (process.env[key]) environment[key] = process.env[key];
      const drive = path.parse(directories.home).root;
      environment.HOMEDRIVE = drive.slice(0, 2); environment.HOMEPATH = directories.home.slice(2);
    }
    if (proxyEndpoint) for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) environment[key] = proxyEndpoint;
    // Supported tool opt-outs apply only to this owned shell and its children.
    if (privacy?.mode !== 'off') Object.assign(environment, { DO_NOT_TRACK: '1', DISABLE_TELEMETRY: '1', DISABLE_ERROR_REPORTING: '1' });
    if (privacy?.mode === 'strict') environment.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
    return environment;
  }
  shell(environment) {
    if (process.platform === 'win32') return { executable: process.env.ComSpec ?? path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32/cmd.exe'), args: ['/D', '/Q'], environment: { ...environment, PROMPT: 'envara $P$G' } };
    if (process.platform === 'darwin') return { executable: '/bin/zsh', args: ['-d', '-i'], environment: { ...environment, SHELL: '/bin/zsh', PS1: 'envara %~ %# ' } };
    return { executable: '/bin/bash', args: ['--noprofile', '--rcfile', path.join(environment.HOME, '.bashrc'), '-i'], environment: { ...environment, SHELL: '/bin/bash', PS1: 'envara \\w \\$ ' } };
  }
  async create({ id, columns, rows }) {
    return this.serialized(id, async () => {
      if (this.closed) throw codeError('应用正在退出。', 'APP_CLOSING');
      const existing = this.active(id);
      if (existing) return this.metadata(existing);
      const cwd = this.settings.get(id)?.cwd;
      if (!cwd) throw codeError('请先选择终端工作目录。', 'TERMINAL_DIRECTORY_REQUIRED');
      return this.startSession({ id, cwd, columns, rows });
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
      return this.startSession({ id: source.profileId, cwd: source.cwd, columns: columns ?? source.columns, rows: rows ?? source.rows, context, source });
    });
  }
  requireDuplicable(session) {
    if (session.status !== 'running' || session.finished || session.finishing || !session.launchContext) throw codeError('只能复制仍在运行的终端。', 'TERMINAL_NOT_RUNNING');
  }
  assertStarting(session) {
    if (this.closed || session.startCancelled || session.status !== 'starting' || session.finished) throw codeError('终端启动已取消。', 'TERMINAL_START_CANCELLED');
  }
  async startSession({ id, cwd, columns, rows, context: copiedContext, source }) {
    if ([...this.sessions.values()].filter(session => ['starting', 'running', 'closing'].includes(session.status)).length >= MAX_SESSIONS) throw codeError('最多同时打开 8 个终端会话。', 'TERMINAL_LIMIT');
    const session = { sessionId: `term_${randomUUID().replaceAll('-', '')}`, profileId: id, status: 'starting', cwd, columns: integer(columns, 100, 20, 400), rows: integer(rows, 30, 5, 150), startedAt: new Date().toISOString(), sequence: 0, replay: '', events: [], queuedBytes: 0, secretTail: '', secrets: [], disposables: [], finished: false, pumping: false };
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
      const proxy = checkedProxy(context.proxy);
      session.launchContext = { id, name: typeof context.name === 'string' ? context.name.slice(0, 100) : null, timezone, timezoneSource: typeof context.timezoneSource === 'string' ? context.timezoneSource.slice(0, 64) : 'unknown', proxy, privacy: context.privacy ?? { mode: 'standard' }, geolocation: context.geolocation ?? null, networkEgress: context.network ?? context.networkEgress ?? null };
      const directories = await this.directories(id);
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
      session.timezone = timezone; session.network = { ...publicNetwork(proxy), ...(session.launchContext.networkEgress?.ok ? { egress: session.launchContext.networkEgress } : {}) };
      this.contexts.set(id, { name: session.launchContext.name, timezone, timezoneSource: session.launchContext.timezoneSource, network: session.network, configDir: directories.config, claudeConfigDir: directories.claude });
      if (source) this.requireDuplicable(source);
      const shell = this.shell(this.childEnvironment(directories, timezone, endpoint, session.launchContext.privacy));
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
      if (cancelled) throw codeError('终端启动已取消。', 'TERMINAL_START_CANCELLED');
      await session.capturePromise;
      if (session.status === 'starting' && !session.finished && !session.finishing) { session.status = 'running'; this.emit(session, 'status', { status: 'running' }); }
      this.pruneSessions();
      return this.metadata(session);
    } catch (error) {
      const reported = storageFailure(error);
      session.error = this.redact(session, reported.message ?? '终端无法启动。', true);
      session.status = 'closing';
      try { await this.cleanup(session); session.finished = true; session.status = reported.code === 'TERMINAL_START_CANCELLED' ? 'closed' : 'error'; this.releaseLaunchContext(session); }
      catch { session.error += '；终端进程清理未完成。'; }
      this.emit(session, 'status', { status: session.status, error: session.error });
      throw codeError(session.error, reported.code ?? 'TERMINAL_START_FAILED');
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
    const value = this.redact(session, data);
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
    const event = { type, sessionId: session.sessionId, profileId: session.profileId, sequence: ++session.sequence, ...value };
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
  async cleanup(session) {
    if (session.cleanupPromise) return session.cleanupPromise;
    session.cleanupPromise = Promise.resolve().then(async () => {
      try {
        if (session.capturePromise && !session.identity) await session.capturePromise.catch(() => {});
        if (session.pty && session.identity) {
          const result = await this.processControl.close({ pty: session.pty, identity: session.identity });
          if (result?.ok === false) throw codeError('终端仍有未退出的子进程。', 'TERMINAL_CLEANUP_FAILED');
        } else if (session.pty && !session.finished && !session.nativeExited) { try { session.pty.kill(); } catch {} }
      } finally { await session.bridge?.close(); }
    });
    return session.cleanupPromise;
  }
  async finish(session, event = {}) {
    if (session.finished) return;
    if (session.finishing) return session.finishing;
    const closing = session.status === 'closing';
    session.status = 'closing';
    session.finishing = Promise.resolve().then(async () => {
      if (session.finished) return;
      const pending = this.redact(session, '', true);
      if (pending) { session.replay = tail(session.replay + pending, MAX_REPLAY_BYTES); this.emit(session, 'data', { data: pending }); }
      if (Number.isInteger(event.exitCode)) session.exitCode = event.exitCode;
      try { await this.cleanup(session); }
      catch (error) { session.error = '终端进程清理未完成，请查看应用状态。'; this.emit(session, 'status', { status: 'closing', error: session.error }); throw error; }
      session.finished = true; session.status = closing ? 'closed' : 'exited';
      this.releaseLaunchContext(session);
      this.emit(session, 'exit', { exitCode: session.exitCode ?? null, status: session.status, ...(Number.isInteger(event.signal) ? { signal: event.signal } : {}) });
      this.pruneSessions();
    });
    return session.finishing;
  }
  async close({ sessionId }) {
    const session = this.session(sessionId);
    if (session.finished) { await this.cleanup(session); return this.metadata(session); }
    if (session.status === 'starting') session.startCancelled = true;
    session.status = 'closing'; this.emit(session, 'status', { status: 'closing' });
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
      await this.mutateSettings(async () => {
        const previous = this.settings.get(id);
        this.settings.delete(id);
        try { await this.saveSettings(); } catch (error) { if (previous) this.settings.set(id, previous); throw error; }
      });
      if (exists && !preserve) await rm(namespace, { recursive: true, force: true });
      this.contexts.delete(id);
      for (const session of this.sessions.values()) if (session.profileId === id) this.sessions.delete(session.sessionId);
      return { profileId: id, removed: true, configRemoved: !preserve, ...(preserve ? { reason: 'SELECTED_DIRECTORY_PRESERVED' } : {}) };
    });
  }
  async shutdown() {
    this.closed = true;
    await this.ready;
    await Promise.allSettled([...this.profileQueues.values()]);
    await this.settingsQueue;
    const results = await Promise.allSettled([...this.sessions.values()].filter(session => !session.finished).map(session => this.close({ sessionId: session.sessionId })));
    const rejected = results.find(result => result.status === 'rejected');
    if (rejected) throw rejected.reason;
  }
}
