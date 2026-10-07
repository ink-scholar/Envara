import path from 'node:path';
import net from 'node:net';
import { constants } from 'node:fs';
import { access, readFile, realpath, stat } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ApplicationStore } from './application-store.mjs';
import { NativeApplicationRouting, applicationRoutingReady, publicApplicationRoutingStatus, applicationRoutingError, APPLICATION_ROUTING_CHECKS } from './application-routing.mjs';

const execute = promisify(execFile);
const fail = (code, message) => Object.assign(new Error(message), { code });
const validId = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(value)) throw fail('APPLICATION_VALIDATION_ERROR', '软件或境舱标识无效。');
  return value;
};
const checkedArgs = value => {
  const args = value ?? [];
  if (!Array.isArray(args) || args.length > 128 || args.some(item => typeof item !== 'string' || item.length > 8192 || /[\0\r\n]/.test(item))) throw fail('APPLICATION_VALIDATION_ERROR', '软件启动参数无效。');
  return [...args];
};
const safeName = value => {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 128 || /[\0\r\n]/.test(value)) throw fail('APPLICATION_VALIDATION_ERROR', '软件名称无效。');
  return value.trim();
};
function checkedTimezone(value) {
  if (typeof value !== 'string' || !value || value === 'Local' || value.length > 128) throw fail('APPLICATION_TIMEZONE_UNAVAILABLE', '请先检测境舱网络的时区。');
  try { new Intl.DateTimeFormat('en', { timeZone: value }); } catch { throw fail('APPLICATION_TIMEZONE_UNAVAILABLE', '境舱时区无效。'); }
  return value;
}
function publicGeo(value) {
  if (!value || !Number.isFinite(value.latitude) || value.latitude < -90 || value.latitude > 90 ||
      !Number.isFinite(value.longitude) || value.longitude < -180 || value.longitude > 180) return null;
  return { latitude: value.latitude, longitude: value.longitude,
    accuracy: Number.isFinite(value.accuracy) && value.accuracy > 0 ? value.accuracy : 50000 };
}
function checkedRoute(value) {
  if (!value) throw fail('APPLICATION_PROXY_REQUIRED', '请先为此境舱选择网络出口。');
  const protocol = value.protocol ?? value.type;
  if (protocol !== 'socks5') throw fail('APPLICATION_UNSUPPORTED_NODE', '此网络出口尚不支持软件的完整网络接管。');
  const host = value.host;
  if (!['127.0.0.1', '::1'].includes(host) || !Number.isSafeInteger(value.port) || value.port < 1 || value.port > 65535 ||
      ![value.username, value.password].every(item => typeof item === 'string' && item.length > 0 && item.length <= 2048 && !/[\0\r\n]/.test(item))) {
    throw fail('APPLICATION_UNSUPPORTED_NODE', '附加软件需要境舱管理的认证网络入口。');
  }
  if (value.udpPolicy != null && !['proxy', 'block'].includes(value.udpPolicy)) throw fail('APPLICATION_UNSUPPORTED_NODE', '网络出口的数据报策略无效。');
  const udpPolicy = value.udpPolicy ?? (value.udp === true ? 'proxy' : 'block');
  if (udpPolicy === 'proxy' && value.udp !== true) throw fail('APPLICATION_UNSUPPORTED_NODE', '此节点尚未确认数据报支持。');
  return { protocol, host, port: value.port, username: value.username, password: value.password, udp: value.udp === true, udpPolicy };
}
const environmentKeys = new Set(['PATH', 'HOME', 'USERPROFILE', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'CLAUDE_CONFIG_DIR', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'SystemRoot', 'WINDIR', 'HOMEDRIVE', 'HOMEPATH', 'NPM_CONFIG_USERCONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'DO_NOT_TRACK', 'DISABLE_TELEMETRY', 'DISABLE_ERROR_REPORTING', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC']);
function ownedEnvironment(context, application, routeId) {
  const env = {};
  for (const [key, value] of Object.entries(context.environment ?? {})) if (environmentKeys.has(key) && typeof value === 'string' && value.length <= 32768 && !value.includes('\0')) env[key] = value;
  env.TZ = context.timezone; env.ENVARA_PROFILE_ID = application.profileId; env.ENVARA_ROUTE_ID = routeId;
  if (typeof context.locale === 'string' && /^[A-Za-z0-9_.@-]{1,64}$/.test(context.locale)) env.LANG = context.locale.replaceAll('-', '_');
  return env;
}
async function bundleMetadata(filename) {
  const content = await readFile(filename);
  if (content.length > 1024 * 1024) throw new Error();
  if (content.subarray(0, 6).toString() === 'bplist') {
    const result = await execute('/usr/bin/plutil', ['-convert', 'json', '-o', '-', filename], { timeout: 2500, maxBuffer: 1024 * 1024 });
    return JSON.parse(result.stdout);
  }
  const xml = content.toString('utf8');
  const string = key => new RegExp(`<key>\\s*${key}\\s*</key>\\s*<string>([^<]*)</string>`).exec(xml)?.[1];
  return { CFBundleIdentifier: string('CFBundleIdentifier'), CFBundleExecutable: string('CFBundleExecutable'), CFBundleDisplayName: string('CFBundleDisplayName'), CFBundleName: string('CFBundleName') };
}

/** Inspect a local bundle/executable; shell expressions are never interpreted. */
export async function inspectLocalApplication(selectedPath, { platform = process.platform } = {}) {
  if (typeof selectedPath !== 'string' || !path.isAbsolute(selectedPath) || selectedPath.length > 8192 || /[\0\r\n]/.test(selectedPath)) throw fail('APPLICATION_INVALID_PATH', '请选择本地软件的绝对路径。');
  try {
    const canonical = await realpath(selectedPath), info = await stat(canonical);
    let executablePath = canonical, name = path.basename(canonical, path.extname(canonical)), identity;
    if (platform === 'darwin' && info.isDirectory() && canonical.endsWith('.app')) {
      const metadata = await bundleMetadata(path.join(canonical, 'Contents/Info.plist'));
      if (typeof metadata.CFBundleExecutable !== 'string' || !/^[^/\\\0\r\n]{1,255}$/.test(metadata.CFBundleExecutable) || ['.', '..'].includes(metadata.CFBundleExecutable)) throw new Error();
      executablePath = await realpath(path.join(canonical, 'Contents/MacOS', metadata.CFBundleExecutable));
      if (!executablePath.startsWith(`${canonical}${path.sep}`)) throw new Error();
      if (typeof metadata.CFBundleIdentifier === 'string' && /^[A-Za-z0-9._-]{1,255}$/.test(metadata.CFBundleIdentifier)) identity = `bundle:${metadata.CFBundleIdentifier}`;
      name = metadata.CFBundleDisplayName ?? metadata.CFBundleName ?? name;
    } else if (!info.isFile() || (platform === 'win32' && !/\.exe$/i.test(canonical))) throw new Error();
    if (!(await stat(executablePath)).isFile()) throw new Error();
    await access(executablePath, platform === 'win32' ? constants.R_OK : constants.R_OK | constants.X_OK);
    identity ??= `path:${createHash('sha256').update(platform === 'win32' || platform === 'darwin' ? executablePath.toLowerCase() : executablePath).digest('hex')}`;
    return { path: canonical, executablePath, identity, name: safeName(name) };
  } catch { throw fail('APPLICATION_INVALID_PATH', '所选软件不存在、不可执行或应用包不完整。'); }
}

/** Bindings and lifecycle only. Native routing owns every launch and all network interception. */
export class ApplicationService {
  constructor({ dataDir, resolveContext, profileExists, routing, platform = process.platform, onEvent = () => {}, inspectApplication = inspectLocalApplication, pollIntervalMs = 1500 } = {}) {
    if (typeof resolveContext !== 'function') throw fail('APPLICATION_VALIDATION_ERROR', '附加软件环境解析器无效。');
    this.platform = platform; this.resolveContext = resolveContext; this.profileExists = profileExists;
    this.routing = routing ?? new NativeApplicationRouting({ platform }); this.onEvent = onEvent;
    this.inspectApplication = inspectApplication; this.store = new ApplicationStore(dataDir);
    this.applications = new Map(); this.sessions = new Map(); this.queue = Promise.resolve(); this.closed = false;
    this.routingState = publicApplicationRoutingStatus(null, platform);
    this.pollIntervalMs = pollIntervalMs; this.pollTimer = null; this.polling = false;
    this.ready = this.initialize();
  }
  async initialize() { for (const item of await this.store.read()) this.applications.set(item.id, item); }
  serialized(operation) {
    const task = this.queue.then(async () => { await this.ready; return operation(); });
    this.queue = task.catch(() => {}); return task;
  }
  notify(application, type = 'status') {
    try { Promise.resolve(this.onEvent({ type, applicationId: application?.id ?? null, profileId: application?.profileId ?? null })).catch(() => {}); } catch {}
  }
  metadata(application) {
    const session = this.sessions.get(application.id);
    return { ...application, args: [...application.args], status: session?.status ?? 'stopped', sessionId: session?.sessionId ?? null,
      pid: session?.pid ?? null, startedAt: session?.startedAt ?? null, lastError: session?.lastError ?? null,
      timezone: session?.timezone ?? null, timezoneSource: session?.timezoneSource ?? null, geolocation: session?.geolocation ?? null,
      proxyId: session?.proxyId ?? null, network: session?.network ?? null, udpPolicy: session?.udpPolicy ?? null,
      configScope: session?.configScope ?? null, locationScope: 'application-compatible', timezoneScope: 'owned-process',
      ...(session?.exitCode != null ? { exitCode: session.exitCode } : {}) };
  }
  async snapshot() {
    await this.ready;
    return { applications: [...this.applications.values()].map(item => this.metadata(item)), applicationRouting: { ...this.routingState } };
  }
  find(id) {
    validId(id); const item = this.applications.get(id);
    if (!item) throw fail('APPLICATION_NOT_FOUND', '未找到此附加软件。'); return item;
  }
  activeSession(id) { const session = this.sessions.get(id); return session && (['starting', 'running', 'stopping'].includes(session.status) || session.sessionId || session.routeId) ? session : null; }
  hasActiveProfile(profileId) { return [...this.applications.values()].some(item => item.profileId === profileId && !!this.activeSession(item.id)); }
  hasActiveProxy(proxyId) { return !!proxyId && [...this.sessions.values()].some(session => (session.proxyId === proxyId || (session.status === 'starting' && session.proxyId == null)) && (session.routeId || session.sessionId || ['starting', 'running', 'stopping'].includes(session.status))); }
  assertProfileIdle(profileId) { if (this.hasActiveProfile(profileId)) throw fail('APPLICATION_RUNNING', '请先停止此境舱的附加软件。'); }
  assertProxyIdle(proxyId) { if (this.hasActiveProxy(proxyId)) throw fail('APPLICATION_RUNNING', '请先停止使用此网络出口的附加软件。'); }
  async checkProfile(profileId) {
    if (this.profileExists && !(await this.profileExists(profileId))) throw fail('APPLICATION_PROFILE_NOT_FOUND', '此境舱已不存在，请重新选择。');
  }
  async saveApplication({ application } = {}) {
    return this.serialized(async () => {
      if (this.closed) throw fail('APP_CLOSING', '应用正在退出。');
      if (!application || typeof application !== 'object') throw fail('APPLICATION_VALIDATION_ERROR', '附加软件配置无效。');
      const profileId = validId(application.profileId); await this.checkProfile(profileId);
      const id = application.id == null ? `app_${randomUUID().replaceAll('-', '')}` : validId(application.id);
      const previous = this.applications.get(id);
      if (application.id != null && !previous) throw fail('APPLICATION_NOT_FOUND', '未找到此附加软件。');
      if (this.activeSession(id)) throw fail('APPLICATION_RUNNING', '请先停止软件，再修改配置。');
      const local = await this.inspectApplication(application.path, { platform: this.platform });
      const conflict = [...this.applications.values()].find(item => item.id !== id && item.identity === local.identity);
      if (conflict) throw fail('APPLICATION_ALREADY_BOUND', '此软件已经附加到一个境舱，请先移除原绑定。');
      const selected = { id, profileId, ...local, name: safeName(application.name ?? local.name), args: checkedArgs(application.args) };
      const values = [...this.applications.values()].filter(item => item.id !== id); values.push(selected);
      await this.store.write(values); this.applications.set(id, selected); this.sessions.delete(id); this.notify(selected, 'saved');
      return this.snapshot();
    });
  }
  async getApplicationRoutingStatus() {
    await this.ready;
    const state = await this.routing.status(); this.routingState = publicApplicationRoutingStatus(state, this.platform);
    return this.routingState;
  }
  async setupApplicationRouting(params = {}) {
    return this.serialized(async () => {
      if (this.closed) throw fail('APP_CLOSING', '应用正在退出。');
      await this.routing.setup(params); await this.getApplicationRoutingStatus(); this.notify(null, 'routing'); return this.snapshot();
    });
  }
  async startApplication({ id } = {}) {
    return this.serialized(async () => {
      if (this.closed) throw fail('APP_CLOSING', '应用正在退出。');
      const application = this.find(id), active = this.activeSession(id);
      if (active) { if (active.status === 'running') return this.snapshot(); throw fail('APPLICATION_RUNNING', '软件仍在启动、停止或等待清理。'); }
      await this.checkProfile(application.profileId);
      const session = { status: 'starting', sessionId: null, routeId: null, lastError: null, proxyId: null };
      this.sessions.set(id, session); this.notify(application);
      try {
        const state = await this.routing.status(); this.routingState = publicApplicationRoutingStatus(state, this.platform);
        if (!applicationRoutingReady(state)) throw applicationRoutingError({ code: state?.installed !== true ? 'APPLICATION_ROUTING_UNAVAILABLE' : state?.authorized !== true ? 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED' : 'APPLICATION_ROUTING_NOT_READY' });
        const local = await this.inspectApplication(application.path, { platform: this.platform });
        if (local.identity !== application.identity || local.executablePath !== application.executablePath) throw fail('APPLICATION_CHANGED', '软件路径或身份已改变，请重新添加。');
        const context = await this.resolveContext(application.profileId);
        if (!context || (context.profileId ?? context.id) !== application.profileId) throw fail('APPLICATION_PROFILE_NOT_FOUND', '此境舱已不存在，请重新选择。');
        session.proxyId = context.proxyId ?? null;
        const timezone = checkedTimezone(context.timezone);
        if (!context.network || context.network.ok === false || !net.isIP(context.network.ip ?? '')) throw fail('APPLICATION_EGRESS_UNAVAILABLE', '网络出口尚未检测成功，请先检测网络。');
        const route = checkedRoute(context.proxyEndpoint ?? context.applicationRoute ?? context.proxy);
        if (typeof context.cwd !== 'string' || !path.isAbsolute(context.cwd) || context.cwd.includes('\0')) throw fail('APPLICATION_DIRECTORY_REQUIRED', '请先为此境舱选择工作目录。');
        const cwd = await realpath(context.cwd);
        if (cwd !== context.cwd || !(await stat(cwd)).isDirectory()) throw fail('APPLICATION_DIRECTORY_REQUIRED', '境舱工作目录已改变，请重新选择。');
        await access(cwd, constants.R_OK | constants.X_OK);
        const geolocation = publicGeo(context.geolocation);
        const workspace = { cwd, timezone, timezoneSource: context.timezoneSource ?? 'unknown', locale: context.locale ?? null,
          geolocation, privacy: { mode: ['standard', 'strict', 'off'].includes(context.privacy?.mode) ? context.privacy.mode : 'standard' } };
        const prepared = await this.routing.prepareRoute({ application: { ...application }, workspace, route });
        if (typeof prepared?.routeId === 'string' && /^[A-Za-z0-9_-]{1,160}$/.test(prepared.routeId)) session.routeId = prepared.routeId;
        if (!session.routeId || prepared.ready !== true || prepared.failClosed !== true || !APPLICATION_ROUTING_CHECKS.every(key => prepared.capabilities?.[key] === true) ||
            prepared.verification?.passed !== true || !APPLICATION_ROUTING_CHECKS.every(key => prepared.verification.checks?.[key] === true)) throw applicationRoutingError({ code: 'APPLICATION_ROUTING_NOT_READY' });
        if (this.closed) throw fail('APP_CLOSING', '应用正在退出。');
        const launched = await this.routing.launch({ routeId: session.routeId, application: { ...application }, args: [...application.args], cwd,
          env: ownedEnvironment({ ...context, timezone }, application, session.routeId) });
        if (typeof launched?.sessionId === 'string' && /^[A-Za-z0-9_-]{1,160}$/.test(launched.sessionId)) session.sessionId = launched.sessionId;
        if (!session.sessionId || !Number.isSafeInteger(launched.pid) || launched.pid < 1) throw applicationRoutingError({ code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
        Object.assign(session, { status: 'running', pid: launched.pid, startedAt: typeof launched.startedAt === 'string' ? launched.startedAt : new Date().toISOString(),
          timezone, timezoneSource: workspace.timezoneSource, geolocation, udpPolicy: route.udpPolicy,
          configScope: context.environment?.HOME ? 'workspace' : 'application-default',
          network: { ip: context.network.ip, country: typeof context.network.country === 'string' ? context.network.country.slice(0, 128) : null } });
        this.startPolling(); this.notify(application); return this.snapshot();
      } catch (error) {
        const known = error?.code?.startsWith('APPLICATION_') && !error?.code?.startsWith('APPLICATION_ROUTING_') ? error : applicationRoutingError(error);
        session.lastError = { code: known.code ?? 'APPLICATION_START_FAILED', message: known.message ?? '软件无法启动。' };
        try { await this.cleanupSession(session); } catch { session.lastError = { code: 'APPLICATION_CLEANUP_FAILED', message: '软件进程尚未确认停止，网络规则仍保留，请重试停止。' }; }
        session.status = 'error'; this.notify(application); throw fail(session.lastError.code, session.lastError.message);
      }
    });
  }
  async cleanupSession(session) {
    // A timed-out launch may already have spawned; route ownership can reclaim it.
    if (session.routeId || session.sessionId) {
      const stopped = await this.routing.stop(session.sessionId ? { sessionId: session.sessionId } : { routeId: session.routeId });
      if (stopped?.stopped !== true) throw fail('APPLICATION_CLEANUP_FAILED', '软件进程尚未确认停止。');
      session.sessionId = null; session.pid = null;
    }
    if (session.routeId) {
      const revoked = await this.routing.revoke({ routeId: session.routeId });
      if (revoked?.revoked !== true) throw fail('APPLICATION_CLEANUP_FAILED', '软件网络规则尚未确认移除。');
      session.routeId = null;
    }
  }
  async stopApplication({ id } = {}) {
    return this.serialized(async () => {
      const application = this.find(id), session = this.sessions.get(id);
      if (!session || !this.activeSession(id)) return this.snapshot();
      session.status = 'stopping'; this.notify(application);
      try { await this.cleanupSession(session); session.status = 'stopped'; session.lastError = null; this.notify(application); }
      catch { session.status = 'error'; session.lastError = { code: 'APPLICATION_CLEANUP_FAILED', message: '软件进程尚未确认停止，网络规则仍保留，请重试。' }; this.notify(application); throw fail(session.lastError.code, session.lastError.message); }
      this.stopPollingWhenIdle(); return this.snapshot();
    });
  }
  async deleteApplication({ id } = {}) {
    return this.serialized(async () => {
      const application = this.find(id);
      if (this.activeSession(id)) throw fail('APPLICATION_RUNNING', '请先停止软件，再移除绑定。');
      await this.store.write([...this.applications.values()].filter(item => item.id !== id));
      this.applications.delete(id); this.sessions.delete(id); this.notify(application, 'deleted'); return this.snapshot();
    });
  }
  startPolling() {
    if (this.pollTimer || this.pollIntervalMs <= 0) return;
    this.pollTimer = setInterval(() => { void this.poll().catch(() => {}); }, this.pollIntervalMs); this.pollTimer.unref?.();
  }
  stopPollingWhenIdle() { if (![...this.applications.values()].some(item => this.activeSession(item.id)) && this.pollTimer) { clearInterval(this.pollTimer); this.pollTimer = null; } }
  async poll() {
    if (this.polling || this.closed) return; this.polling = true;
    try {
      await this.serialized(async () => {
        const state = await this.routing.status(); this.routingState = publicApplicationRoutingStatus(state, this.platform);
        for (const [id, session] of this.sessions) {
          if (session.status !== 'running') continue;
          const application = this.applications.get(id);
          if (!applicationRoutingReady(state)) {
            try { await this.cleanupSession(session); } catch {}
            session.status = 'error'; session.lastError = { code: 'APPLICATION_ROUTING_NOT_READY', message: '网络接管中断，已请求停止软件。' }; this.notify(application); continue;
          }
          const native = Array.isArray(state.sessions) ? state.sessions.find(item => item.sessionId === session.sessionId) : null;
          if (Array.isArray(state.sessions) && !native) {
            session.status = 'error'; session.lastError = { code: 'APPLICATION_ROUTING_SESSION_MISSING', message: '软件会话的网络保护状态无法确认，正在请求停止软件。' }; this.notify(application);
            try { await this.cleanupSession(session); session.lastError.message = '软件会话的网络保护状态无法确认，已停止软件并清理网络规则。'; }
            catch { session.lastError = { code: 'APPLICATION_CLEANUP_FAILED', message: '软件会话的网络保护状态无法确认，停止或网络规则清理尚未完成，请重试停止。' }; }
            this.notify(application); continue;
          }
          if (native && ['stopped', 'exited', 'error'].includes(native.status)) {
            try { await this.cleanupSession(session); session.status = native.status === 'error' ? 'error' : 'stopped'; session.exitCode = Number.isInteger(native.exitCode) ? native.exitCode : null; }
            catch { session.status = 'error'; session.lastError = { code: 'APPLICATION_CLEANUP_FAILED', message: '软件已退出，网络规则仍等待清理。' }; }
            this.notify(application);
          }
        }
        this.stopPollingWhenIdle();
      });
    } finally { this.polling = false; }
  }
  async shutdown() {
    this.closed = true; if (this.pollTimer) clearInterval(this.pollTimer); this.pollTimer = null;
    await this.serialized(async () => {
      const failures = [];
      for (const [id, session] of this.sessions) {
        if (!this.activeSession(id)) continue;
        try { await this.cleanupSession(session); session.status = 'stopped'; }
        catch (error) { failures.push(error); }
      }
      if (failures.length) throw fail('APPLICATION_CLEANUP_FAILED', '部分附加软件尚未确认停止，网络规则仍保留。');
      await this.routing.shutdown?.();
    });
  }
}
