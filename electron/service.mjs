import { randomInt, randomUUID } from 'node:crypto';
import { mkdir, readdir, rm, stat } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import EnvaraStore from './store.mjs';
import { normalizePrivacy } from './privacy-policy.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROFILE_FIELDS = new Set(['name', 'group', 'notes', 'engine', 'platform', 'seed', 'locale', 'timezone', 'width', 'height', 'startUrl', 'proxyId', 'privacy']);
const IMPORT_FIELDS = new Set([...PROFILE_FIELDS, 'id', 'createdAt', 'updatedAt', 'lastLaunchedAt']);
const PROXY_FIELDS = new Set(['id', 'name', 'protocol', 'host', 'port', 'username', 'password']);
const MAX_PROFILES = 500;
const now = () => new Date().toISOString();
const seed = () => randomInt(1, 2147483647);

function failure(message, code = 'VALIDATION_ERROR') {
  const error = new Error(message);
  error.code = code;
  return error;
}

function record(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw failure(`${label}必须是对象。`);
  }
  return value;
}

function allowed(value, fields, label) {
  record(value, label);
  for (const key of Object.keys(value)) {
    if (!fields.has(key)) throw failure(`${label}包含不支持的字段：${key}`);
  }
}

function string(value, label, maximum, { optional = false, trim = true } = {}) {
  if (value == null && optional) return '';
  if (typeof value !== 'string') throw failure(`${label}必须是文本。`);
  const result = trim ? value.trim() : value;
  if ((!optional && !result) || result.length > maximum || result.includes('\0')) {
    throw failure(`${label}${optional ? '' : '不能为空，且'}长度不能超过 ${maximum} 个字符。`);
  }
  return result;
}

function integer(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw failure(`${label}必须是 ${minimum} 到 ${maximum} 之间的整数。`);
  }
  return value;
}

function id(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('无效的环境或代理标识。');
  return value;
}

function profileConfig(input, defaults, proxyIds) {
  allowed(input, PROFILE_FIELDS, '环境配置');
  const result = { ...defaults, ...input };
  result.privacy = normalizePrivacy(result.privacy);
  result.name = string(result.name, '环境名称', 100);
  result.group = string(result.group, '分组', 100, { optional: true });
  result.notes = string(result.notes, '备注', 4000, { optional: true });
  if (result.engine !== 'cloakbrowser') throw failure('当前仅支持 CloakBrowser 内核。');
  if (!['macos', 'windows', 'linux'].includes(result.platform)) throw failure('请选择有效的指纹平台。');
  result.seed = integer(result.seed, '指纹种子', 1, 2147483647);
  result.width = integer(result.width, '窗口宽度', 800, 7680);
  result.height = integer(result.height, '窗口高度', 600, 4320);
  result.locale = string(result.locale, '语言', 64);
  try {
    const locales = Intl.getCanonicalLocales(result.locale);
    if (locales.length !== 1) throw new Error();
    result.locale = locales[0];
  } catch { throw failure('语言必须是有效的语言代码，例如 zh-CN。'); }
  result.timezone = string(result.timezone, '时区', 100);
  try { new Intl.DateTimeFormat('en', { timeZone: result.timezone }); }
  catch { throw failure('时区无效，例如 Asia/Shanghai。'); }
  result.startUrl = string(result.startUrl, '启动页面', 2048);
  if (result.startUrl !== 'about:blank') {
    let url;
    try { url = new URL(result.startUrl); } catch { throw failure('启动页面必须是有效的网址。'); }
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) {
      throw failure('启动页面仅支持 HTTP、HTTPS 或 about:blank，且不能包含登录凭据。');
    }
    result.startUrl = url.href;
  }
  if (result.proxyId !== null) {
    id(result.proxyId);
    if (!proxyIds.has(result.proxyId)) throw failure('指定的网络出口不存在。');
  }
  return Object.fromEntries([...PROFILE_FIELDS].map((field) => [field, result[field]]));
}

function proxyConfig(input) {
  allowed(input, PROXY_FIELDS, '网络出口');
  const proxy = {
    name: string(input.name, '网络出口名称', 100),
    protocol: input.protocol,
    host: string(input.host, '代理主机', 253),
    port: typeof input.port === 'string' && /^\d+$/.test(input.port) ? Number(input.port) : input.port,
    username: string(input.username, '用户名', 512, { optional: true, trim: false }),
    password: string(input.password, '密码', 2048, { optional: true, trim: false }),
  };
  if (!['http', 'https', 'socks5'].includes(proxy.protocol)) throw failure('代理协议仅支持 HTTP、HTTPS 和 SOCKS5。');
  if (/[/@\s?#]/.test(proxy.host) || proxy.host.includes('://')) {
    throw failure('代理主机仅填写域名或 IP，不包含协议、端口或路径。');
  }
  if (proxy.host.startsWith('[') && proxy.host.endsWith(']')) proxy.host = proxy.host.slice(1, -1);
  if (proxy.host.includes(':') && net.isIP(proxy.host) !== 6) throw failure('代理主机不是有效的 IPv6 地址。');
  integer(proxy.port, '代理端口', 1, 65535);
  return proxy;
}

function event(workspace, type, message) {
  workspace.events.unshift({ id: randomUUID(), time: now(), type, message });
  workspace.events.length = Math.min(workspace.events.length, 100);
}

async function directorySize(directory) {
  let bytes = 0;
  try {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        const childBytes = await directorySize(target);
        if (childBytes === null) return null;
        bytes += childBytes;
      } else if (entry.isFile()) {
        bytes += (await stat(target)).size;
      }
    }
    return bytes;
  } catch (error) { return error.code === 'ENOENT' ? 0 : null; }
}

function metric(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

/** Local application service. Renderer callers only get the whitelisted call API. */
export class EnvaraService {
  constructor(dataDir, runtime, system = {}, onChange = () => {}) {
    this.store = new EnvaraStore(dataDir);
    this.runtime = runtime;
    this.system = { platform: system.platform ?? process.platform, appVersion: system.appVersion ?? '0.1.0', dataDir: this.store.dataDir };
    this.onChange = onChange;
    this.states = new Map();
    this.pendingStarts = new Set();
    this.installPromise = null;
    this.engine = { installed: false, installing: false, version: null, progress: null, error: null };
    this.closed = false;
    this.ready = this.validateWorkspace();
  }

  defaults() {
    return {
      name: '新环境', group: '', notes: '', engine: 'cloakbrowser',
      platform: this.system.platform === 'darwin' || this.system.platform === 'macos' ? 'macos' : this.system.platform === 'win32' || this.system.platform === 'windows' ? 'windows' : 'linux',
      seed: seed(), locale: 'zh-CN', timezone: 'Asia/Shanghai', width: 1440, height: 900,
      startUrl: 'about:blank', proxyId: null, privacy: { mode: 'standard' },
    };
  }

  async validateWorkspace() {
    const workspace = await this.store.read();
    const proxyIds = new Set();
    for (const proxy of workspace.proxies) {
      id(proxy.id);
      if (proxyIds.has(proxy.id)) throw failure('本地数据包含重复的网络出口标识。');
      proxyIds.add(proxy.id);
      proxyConfig(proxy);
    }
    const profileIds = new Set();
    for (const profile of workspace.profiles) {
      id(profile.id);
      if (profileIds.has(profile.id)) throw failure('本地数据包含重复的环境标识。');
      profileIds.add(profile.id);
      allowed(profile, IMPORT_FIELDS, '本地环境');
      profileConfig(Object.fromEntries([...PROFILE_FIELDS].map((field) => [field, profile[field]])), this.defaults(), proxyIds);
    }
    this.settingsConfig(workspace.settings);
  }

  changed() {
    try {
      const result = this.onChange();
      if (result?.catch) result.catch(() => {});
    } catch { /* UI notifications cannot invalidate a saved operation. */ }
  }

  state(profileId) {
    return this.states.get(profileId) ?? { status: 'stopped', lastError: null, generation: 0 };
  }

  assertStopped(profileId) {
    if (['running', 'starting'].includes(this.state(profileId).status)) {
      throw failure('请先停止环境，再编辑、删除或清理数据。', 'PROFILE_RUNNING');
    }
  }

  findProfile(workspace, profileId) {
    id(profileId);
    const profile = workspace.profiles.find((item) => item.id === profileId);
    if (!profile) throw failure('环境不存在。', 'PROFILE_NOT_FOUND');
    return profile;
  }

  profileDir(profileId) { return path.join(this.store.dataDir, 'profiles', id(profileId)); }

  async snapshot() {
    await this.ready;
    const workspace = await this.store.read();
    let measurements = {};
    try { measurements = await this.runtime?.getMetrics?.() ?? {}; } catch { /* Unavailable telemetry is null. */ }
    let runtimeEngine = {};
    try { runtimeEngine = await this.runtime?.snapshot?.() ?? {}; } catch { /* Keep the last known installation error. */ }
    let installed = false;
    try { installed = Boolean(await this.runtime?.isInstalled?.()); } catch { /* Installation is unverified. */ }
    const engine = { ...this.engine, ...runtimeEngine, installed };
    const profiles = await Promise.all(workspace.profiles.map(async (profile) => {
      const state = this.state(profile.id);
      const measurement = measurements[profile.id] ?? {};
      return {
        ...profile, status: state.status, lastError: state.lastError,
        dataBytes: await directorySize(this.profileDir(profile.id)),
        privacyProtection: this.runtime?.privacyForProfile?.(profile.id) ?? null,
        cpuPercent: metric(measurement.cpuPercent), memoryBytes: metric(measurement.memoryBytes),
        ...(state.screenshot ? { screenshot: state.screenshot } : {}),
      };
    }));
    return { profiles, proxies: workspace.proxies, settings: workspace.settings, engine, events: workspace.events, system: this.system };
  }

  async call(method, args = {}) {
    await this.ready;
    if (this.closed) throw failure('应用正在退出。', 'APP_CLOSING');
    record(args, '操作参数');
    const methods = new Set(['createProfile', 'updateProfile', 'cloneProfile', 'deleteProfile', 'clearProfile', 'startProfile', 'stopProfile', 'focusProfile', 'saveProxy', 'deleteProxy', 'checkProxy', 'saveSettings', 'installEngine', 'importProfiles', 'exportProfiles']);
    if (method === 'getSnapshot' || method === 'snapshot') return this.snapshot();
    if (!methods.has(method)) throw failure('不支持的操作。', 'UNKNOWN_METHOD');
    const result = await this[method](args);
    return ['checkProxy', 'exportProfiles'].includes(method) ? result : this.snapshot();
  }

  async createProfile({ profile }) {
    await this.store.transaction((workspace) => {
      if (workspace.profiles.length >= MAX_PROFILES) throw failure(`最多支持 ${MAX_PROFILES} 个环境。`);
      const config = profileConfig(profile, this.defaults(), new Set(workspace.proxies.map((proxy) => proxy.id)));
      const time = now();
      workspace.profiles.push({ ...config, id: randomUUID(), createdAt: time, updatedAt: time, lastLaunchedAt: null });
      event(workspace, 'profile', `创建环境「${config.name}」`);
    });
    this.changed();
  }

  async updateProfile({ id: profileId, profile }) {
    await this.store.transaction((workspace) => {
      const existing = this.findProfile(workspace, profileId);
      this.assertStopped(profileId);
      const config = profileConfig(profile, existing, new Set(workspace.proxies.map((proxy) => proxy.id)));
      if (config.seed !== existing.seed) throw failure('现有环境的指纹种子不可修改；请克隆以生成新指纹。');
      Object.assign(existing, config, { updatedAt: now() });
      event(workspace, 'profile', `更新环境「${existing.name}」`);
    });
    this.changed();
  }

  async cloneProfile({ id: profileId }) {
    await this.store.transaction((workspace) => {
      const existing = this.findProfile(workspace, profileId);
      if (workspace.profiles.length >= MAX_PROFILES) throw failure(`最多支持 ${MAX_PROFILES} 个环境。`);
      const time = now();
      let newSeed = seed();
      while (newSeed === existing.seed) newSeed = seed();
      const clone = { ...existing, id: randomUUID(), name: `${existing.name.slice(0, 95)} 副本`, seed: newSeed, createdAt: time, updatedAt: time, lastLaunchedAt: null };
      workspace.profiles.push(clone);
      event(workspace, 'profile', `克隆环境「${existing.name}」`);
    });
    this.changed();
  }

  async deleteProfile({ id: profileId }) {
    await this.store.transaction(async (workspace) => {
      const profile = this.findProfile(workspace, profileId);
      this.assertStopped(profileId);
      // rm never traverses a symlink supplied as the root path.
      await rm(this.profileDir(profileId), { recursive: true, force: true });
      workspace.profiles = workspace.profiles.filter((item) => item.id !== profileId);
      event(workspace, 'profile', `删除环境「${profile.name}」`);
    });
    this.states.delete(profileId);
    this.changed();
  }

  async clearProfile({ id: profileId }) {
    await this.store.transaction(async (workspace) => {
      const profile = this.findProfile(workspace, profileId);
      this.assertStopped(profileId);
      await rm(this.profileDir(profileId), { recursive: true, force: true });
      profile.updatedAt = now();
      event(workspace, 'profile', `清理环境「${profile.name}」的浏览数据`);
    });
    this.states.delete(profileId);
    this.changed();
  }

  async startProfile({ id: profileId }) {
    const start = this.reserveAndLaunch(profileId);
    this.pendingStarts.add(start);
    try { await start; } finally { this.pendingStarts.delete(start); }
  }

  async reserveAndLaunch(profileId) {
    id(profileId);
    if (!await this.runtime?.isInstalled?.()) throw failure('请先下载浏览器内核。', 'ENGINE_NOT_INSTALLED');
    const reservation = await this.store.inspect((workspace) => {
      if (this.closed) throw failure('应用正在退出。', 'APP_CLOSING');
      const profile = this.findProfile(workspace, profileId);
      const existing = this.state(profileId);
      if (existing.status === 'running') return { focus: true };
      if (existing.status === 'starting') throw failure('环境正在启动。', 'PROFILE_STARTING');
      this.states.set(profileId, { status: 'starting', lastError: null, generation: existing.generation + 1 });
      return { profile, proxy: workspace.proxies.find((proxy) => proxy.id === profile.proxyId) ?? null };
    });
    if (reservation.focus) { await this.focusProfile({ id: profileId }); return; }
    this.changed();
    await this.launch(reservation.profile, reservation.proxy, this.states.get(profileId));
  }

  async launch(profile, proxy, state) {
    try {
      await mkdir(this.profileDir(profile.id), { recursive: true, mode: 0o700 });
      await this.runtime.start(profile, proxy, this.profileDir(profile.id), (error) => {
        if (this.states.get(profile.id) !== state) return;
        state.status = error ? 'error' : 'stopped';
        state.lastError = error ? String(error.message ?? error) : null;
        delete state.screenshot;
        this.store.transaction((workspace) => event(workspace, error ? 'error' : 'browser', error ? `环境「${profile.name}」已关闭：${state.lastError}` : `环境「${profile.name}」已停止`))
          .then(() => this.changed()).catch(() => this.changed());
      });
      if (state.status === 'starting') state.status = 'running';
      await this.store.transaction((workspace) => {
        const current = this.findProfile(workspace, profile.id);
        current.lastLaunchedAt = now();
        event(workspace, 'browser', `启动环境「${profile.name}」`);
      });
      if (state.status === 'running') this.capture(profile.id, state);
      this.changed();
    } catch (error) {
      await Promise.resolve().then(() => this.runtime?.stop?.(profile.id)).catch(() => {});
      state.status = 'error';
      state.lastError = String(error.message ?? error);
      delete state.screenshot;
      await this.store.transaction((workspace) => event(workspace, 'error', `环境「${profile.name}」启动失败：${state.lastError}`));
      this.changed();
      throw failure(state.lastError, 'BROWSER_START_FAILED');
    }
  }

  capture(profileId, state) {
    Promise.resolve().then(() => this.runtime?.screenshot?.(profileId)).then((screenshot) => {
      if (typeof screenshot === 'string' && state.status === 'running' && this.states.get(profileId) === state) {
        state.screenshot = screenshot;
        this.changed();
      }
    }).catch(() => {});
  }

  async stopProfile({ id: profileId }) {
    const workspace = await this.store.read();
    const profile = this.findProfile(workspace, profileId);
    const state = this.state(profileId);
    if (state.status === 'starting') throw failure('环境正在启动，请稍后停止。', 'PROFILE_STARTING');
    if (state.status !== 'running') return;
    await this.runtime.stop(profileId);
    if (state.status === 'running') {
      state.status = 'stopped';
      state.lastError = null;
      delete state.screenshot;
      await this.store.transaction((next) => event(next, 'browser', `环境「${profile.name}」已停止`));
    }
    this.changed();
  }

  async focusProfile({ id: profileId }) {
    this.findProfile(await this.store.read(), profileId);
    const state = this.state(profileId);
    if (state.status !== 'running') throw failure('请先启动环境。', 'PROFILE_NOT_RUNNING');
    await this.runtime.focus(profileId);
    this.capture(profileId, state);
  }

  async saveProxy({ proxy }) {
    const config = proxyConfig(proxy);
    await this.store.transaction((workspace) => {
      if (proxy.id != null) {
        id(proxy.id);
        const existing = workspace.proxies.find((item) => item.id === proxy.id);
        if (!existing) throw failure('网络出口不存在。', 'PROXY_NOT_FOUND');
        for (const profile of workspace.profiles.filter((item) => item.proxyId === proxy.id)) this.assertStopped(profile.id);
        Object.assign(existing, config);
      } else {
        if (workspace.proxies.length >= 500) throw failure('最多支持 500 个网络出口。');
        workspace.proxies.push({ id: randomUUID(), ...config });
      }
      event(workspace, 'proxy', `保存网络出口「${config.name}」`);
    });
    this.changed();
  }

  async deleteProxy({ id: proxyId }) {
    id(proxyId);
    await this.store.transaction((workspace) => {
      const proxy = workspace.proxies.find((item) => item.id === proxyId);
      if (!proxy) throw failure('网络出口不存在。', 'PROXY_NOT_FOUND');
      if (workspace.profiles.some((profile) => profile.proxyId === proxyId)) throw failure('请先取消环境对该网络出口的引用。', 'PROXY_IN_USE');
      workspace.proxies = workspace.proxies.filter((item) => item.id !== proxyId);
      event(workspace, 'proxy', `删除网络出口「${proxy.name}」`);
    });
    this.changed();
  }

  async checkProxy({ id: proxyId }) {
    id(proxyId);
    const proxy = (await this.store.read()).proxies.find((item) => item.id === proxyId);
    if (!proxy) throw failure('网络出口不存在。', 'PROXY_NOT_FOUND');
    return new Promise((resolve) => {
      const started = performance.now();
      const socket = net.createConnection({ host: proxy.host, port: proxy.port });
      let finished = false;
      const finish = (ok, message) => {
        if (finished) return;
        finished = true;
        socket.destroy();
        resolve({ ok, latencyMs: ok ? Math.round(performance.now() - started) : null, scope: 'tcp', message });
      };
      socket.setTimeout(5000);
      socket.once('connect', () => finish(true, '端口连接成功；尚未验证代理认证、出口 IP 或访问能力。'));
      socket.once('timeout', () => finish(false, '端口连接超时。'));
      socket.once('error', (error) => finish(false, `端口连接失败：${error.code ?? 'UNKNOWN'}`));
    });
  }

  settingsConfig(settings) {
    allowed(settings, new Set(['closeBrowsersOnExit', 'language']), '设置');
    if (typeof settings.closeBrowsersOnExit !== 'boolean') throw failure('退出时关闭浏览器必须是布尔值。');
    if (!settings.closeBrowsersOnExit) throw failure('当前版本退出应用时会关闭所有浏览器会话。');
    if (settings.language != null && !['zh-CN', 'en'].includes(settings.language)) throw failure('界面语言无效。');
    return { closeBrowsersOnExit: settings.closeBrowsersOnExit, ...(settings.language != null ? { language: settings.language } : {}) };
  }

  async saveSettings({ settings }) {
    const config = this.settingsConfig(settings);
    await this.store.transaction((workspace) => { workspace.settings = { ...workspace.settings, ...config }; });
    this.changed();
  }

  async installEngine() {
    if (this.installPromise) return this.installPromise;
    if (!this.runtime?.install) throw failure('浏览器内核下载不可用。', 'ENGINE_UNAVAILABLE');
    this.engine.installing = true;
    this.engine.error = null;
    this.changed();
    const interval = setInterval(() => this.changed(), 300);
    interval.unref?.();
    this.installPromise = (async () => {
      try {
        await this.runtime.install();
        await this.store.transaction((workspace) => event(workspace, 'engine', '浏览器内核安装完成'));
      } catch (error) {
        this.engine.error = String(error.message ?? error);
        await this.store.transaction((workspace) => event(workspace, 'error', `浏览器内核安装失败：${this.engine.error}`));
        throw failure(this.engine.error, 'ENGINE_INSTALL_FAILED');
      } finally {
        clearInterval(interval);
        this.engine.installing = false;
        this.installPromise = null;
        this.changed();
      }
    })();
    return this.installPromise;
  }

  async importProfiles({ profiles }) {
    if (!Array.isArray(profiles) || profiles.length === 0 || profiles.length > MAX_PROFILES) throw failure('请选择包含 1 到 500 个环境的配置文件。');
    await this.store.transaction((workspace) => {
      if (workspace.profiles.length + profiles.length > MAX_PROFILES) throw failure(`导入后环境数量不能超过 ${MAX_PROFILES} 个。`);
      const imports = profiles.map((profile) => {
        allowed(profile, IMPORT_FIELDS, '导入环境');
        const editable = Object.fromEntries(Object.entries(profile).filter(([field]) => PROFILE_FIELDS.has(field)));
        // Network credentials and foreign proxy references are deliberately not imported.
        editable.proxyId = null;
        const config = profileConfig(editable, this.defaults(), new Set());
        const time = now();
        return { ...config, id: randomUUID(), createdAt: time, updatedAt: time, lastLaunchedAt: null };
      });
      workspace.profiles.push(...imports);
      event(workspace, 'profile', `导入 ${imports.length} 个环境配置`);
    });
    this.changed();
  }

  async exportProfiles({ id: profileId } = {}) {
    const workspace = await this.store.read();
    const profiles = profileId == null ? workspace.profiles : [this.findProfile(workspace, profileId)];
    return { schema: 'envara.profiles', version: 1, profiles: profiles.map((profile) => ({ ...profile, proxyId: null })) };
  }

  async shutdown() {
    await this.ready;
    this.closed = true;
    await Promise.allSettled([...this.pendingStarts]);
    if (this.runtime?.closeAll) await this.runtime.closeAll();
    else await Promise.allSettled([...this.states].filter(([, state]) => state.status === 'running').map(([profileId]) => this.runtime.stop(profileId)));
    await this.store.read();
  }
}

export default EnvaraService;
