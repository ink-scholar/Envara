import path from 'node:path';
import { spawn as spawnChild } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { access, lstat, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';

export const APPLICATION_ROUTING_PROTOCOL = 'envara.application-routing';
export const APPLICATION_ROUTING_VERSION = 1;
export const APPLICATION_ROUTING_CHECKS = Object.freeze(['tcp', 'udp', 'dns', 'childProcesses', 'failClosed']);
export const PF_APPLICATION_ROUTING_CHECKS = Object.freeze(['guard', 'unrelatedApps', 'nativeAcceptance']);
const failure = (code, message) => Object.assign(new Error(message), { code });
const errorMessages = {
  APPLICATION_ROUTING_UNAVAILABLE: '应用网络组件尚未安装。',
  APPLICATION_ROUTING_AUTHORIZATION_REQUIRED: '请先在系统中授权应用网络组件。',
  APPLICATION_ROUTING_NOT_READY: '应用网络组件尚未通过完整验证，软件暂不能启动。',
  APPLICATION_ROUTING_PROTOCOL_ERROR: '应用网络组件返回了无效响应。',
  APPLICATION_ROUTING_TIMEOUT: '应用网络组件响应超时。',
  APPLICATION_ROUTING_CLOSED: '应用网络组件正在退出。',
};
export function applicationRoutingError(error, fallback = 'APPLICATION_ROUTING_NOT_READY') {
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{1,95}$/.test(error.code) ? error.code : fallback;
  // Native diagnostics must never echo request bodies, endpoints or credentials.
  return failure(code, errorMessages[code] ?? errorMessages[fallback] ?? '应用网络操作失败。');
}
export function applicationRoutingReady(value) {
  if (value?.backend === 'pf-utun' && (value.processScopeVerified !== true ||
      value.authorization?.kind !== 'privileged-helper' || value.authorization?.verified !== true ||
      value.verification?.backend !== 'pf-utun' || value.verification?.native !== true ||
      !PF_APPLICATION_ROUTING_CHECKS.every(key => value.capabilities?.[key] === true && value.verification?.checks?.[key] === true))) return false;
  return value?.installed === true && value.authorized === true && value.ready === true &&
    value.processScopeVerified !== false &&
    APPLICATION_ROUTING_CHECKS.every(key => value.capabilities?.[key] === true) &&
    value.verification?.passed === true && typeof value.verification.version === 'string' &&
    value.verification.version.length > 0 && value.verification.version.length <= 128 &&
    APPLICATION_ROUTING_CHECKS.every(key => value.verification.checks?.[key] === true);
}
export function publicApplicationRoutingStatus(value, platform = process.platform) {
  const componentNames = { 'mitmproxy-redirector': 'Mitmproxy Redirector', 'envara-windivert': 'Envara · WinDivert', 'envara-app-proxy': 'Envara · App Proxy', 'envara-pf-routing': 'Envara · PF' };
  const publicComponent = component => component && Object.hasOwn(componentNames, component.name) ? {
    name: componentNames[component.name],
    version: typeof component.version === 'string' && /^[A-Za-z0-9._+-]{1,64}$/.test(component.version) ? component.version : null,
    available: component.available === true, verified: component.verified === true, installed: component.installed === true,
  } : null;
  const component = publicComponent(value?.component);
  const diagnosticComponent = publicComponent(value?.diagnosticComponent);
  const capabilities = Object.fromEntries(APPLICATION_ROUTING_CHECKS.map(key => [key, value?.capabilities?.[key] === true]));
  const verification = { passed: value?.verification?.passed === true,
    version: typeof value?.verification?.version === 'string' ? value.verification.version.slice(0, 128) : null,
    checks: Object.fromEntries(APPLICATION_ROUTING_CHECKS.map(key => [key, value?.verification?.checks?.[key] === true])) };
  const ready = applicationRoutingReady(value);
  const status = ready ? 'ready' : value?.installed !== true ? component?.available && component.verified ? 'prepared' : 'unavailable' : value?.authorized !== true ? 'authorization-required' : 'incomplete';
  return { platform, protocolVersion: APPLICATION_ROUTING_VERSION, installed: value?.installed === true,
    authorized: value?.authorized === true, ready, status, capabilities, verification,
    ...(value?.backend === 'pf-utun' ? { backend: 'pf-utun',
      systemChecks: Object.fromEntries(PF_APPLICATION_ROUTING_CHECKS.map(key => [key, value?.verification?.checks?.[key] === true])) } : {}),
    ...(typeof value?.processScopeVerified === 'boolean' ? { processScopeVerified: value.processScopeVerified } : {}),
    ...(component ? { component } : {}),
    ...(diagnosticComponent ? { diagnosticComponent: { ...diagnosticComponent, authorized: value.diagnosticComponent.authorized === true } } : {}),
    message: ready ? '应用网络接管已就绪。' : status === 'prepared' ? '组件已准备，等待安装与系统授权。' : errorMessages[status === 'unavailable' ? 'APPLICATION_ROUTING_UNAVAILABLE' : status === 'authorization-required' ? 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED' : 'APPLICATION_ROUTING_NOT_READY'] };
}

/** One private stdin JSON-RPC request per native helper process. No shell/argv credentials. */
export class NativeApplicationRouting {
  constructor({ helperPath, platform = process.platform, spawn = spawnChild, timeoutMs = 15000, maxBytes = 1024 * 1024 } = {}) {
    if (helperPath != null && (!path.isAbsolute(helperPath) || /[\0\r\n]/.test(helperPath))) throw failure('APPLICATION_ROUTING_UNAVAILABLE', errorMessages.APPLICATION_ROUTING_UNAVAILABLE);
    this.helperPath = helperPath; this.platform = platform; this.spawn = spawn;
    this.timeoutMs = timeoutMs; this.maxBytes = maxBytes; this.closed = false; this.pending = new Set();
  }
  async request(method, params = {}) {
    if (this.closed) throw failure('APPLICATION_ROUTING_CLOSED', errorMessages.APPLICATION_ROUTING_CLOSED);
    if (!['status', 'setup', 'resolveRealm', 'prepareRoute', 'launch', 'stop', 'revoke'].includes(method)) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR', errorMessages.APPLICATION_ROUTING_PROTOCOL_ERROR);
    try {
      if (!this.helperPath) throw new Error();
      const canonical = await realpath(this.helperPath), info = await lstat(canonical);
      if (canonical !== this.helperPath || !info.isFile()) throw new Error();
      await access(canonical, this.platform === 'win32' ? constants.R_OK : constants.X_OK);
    } catch { throw failure('APPLICATION_ROUTING_UNAVAILABLE', errorMessages.APPLICATION_ROUTING_UNAVAILABLE); }
    const id = randomUUID();
    const payload = JSON.stringify({ protocol: APPLICATION_ROUTING_PROTOCOL, version: APPLICATION_ROUTING_VERSION, id, method, params });
    if (Buffer.byteLength(payload) > this.maxBytes) throw failure('APPLICATION_ROUTING_PROTOCOL_ERROR', errorMessages.APPLICATION_ROUTING_PROTOCOL_ERROR);
    return new Promise((resolve, reject) => {
      const env = this.platform === 'win32' ? { SystemRoot: process.env.SystemRoot ?? 'C:\\Windows', WINDIR: process.env.WINDIR ?? 'C:\\Windows' } : { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' };
      let child, output = '', bytes = 0, settled = false;
      const finish = (error, value) => {
        if (settled) return; settled = true; clearTimeout(timer); this.pending.delete(child);
        if (error) { try { child?.kill(); } catch {} reject(applicationRoutingError(error)); } else resolve(value);
      };
      const timer = setTimeout(() => finish(failure('APPLICATION_ROUTING_TIMEOUT', errorMessages.APPLICATION_ROUTING_TIMEOUT)), this.timeoutMs);
      try { child = this.spawn(this.helperPath, ['--rpc'], { env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
      catch (error) { finish(error); return; }
      this.pending.add(child);
      child.stdout?.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > this.maxBytes) finish(failure('APPLICATION_ROUTING_PROTOCOL_ERROR', errorMessages.APPLICATION_ROUTING_PROTOCOL_ERROR));
        else output += chunk.toString('utf8');
      });
      // Drain without logging: a helper error must not expose its private payload.
      child.stderr?.on('data', () => {});
      child.stdin?.on('error', error => finish(error));
      child.once('error', error => finish(error));
      child.once('close', () => {
        if (settled) return;
        try {
          const response = JSON.parse(output);
          if (response.protocol !== APPLICATION_ROUTING_PROTOCOL || response.version !== APPLICATION_ROUTING_VERSION || response.id !== id ||
              (response.error == null && (response.result == null || typeof response.result !== 'object' || Array.isArray(response.result)))) throw new Error();
          if (response.error) finish(applicationRoutingError(response.error)); else finish(null, response.result);
        } catch { finish(failure('APPLICATION_ROUTING_PROTOCOL_ERROR', errorMessages.APPLICATION_ROUTING_PROTOCOL_ERROR)); }
      });
      child.stdin.end(payload);
    });
  }
  async status() {
    try { return await this.request('status'); }
    catch (error) { return { installed: false, authorized: false, ready: false, error: applicationRoutingError(error).code }; }
  }
  setup(params = {}) { return this.request('setup', params); }
  resolveRealm(params) { return this.request('resolveRealm', params); }
  prepareRoute(params) { return this.request('prepareRoute', params); }
  launch(params) { return this.request('launch', params); }
  stop(params) { return this.request('stop', params); }
  revoke(params) { return this.request('revoke', params); }
  async shutdown() { this.closed = true; for (const child of this.pending) { try { child.kill(); } catch {} } this.pending.clear(); }
}
