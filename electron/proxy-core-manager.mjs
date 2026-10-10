import path from 'node:path';
import net from 'node:net';
import { spawn as spawnChild, execFile } from 'node:child_process';
import { networkInterfaces } from 'node:os';
import { promisify } from 'node:util';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createReadStream, constants } from 'node:fs';
import { access, chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { resolveProxyBootstrapHost } from './proxy-bootstrap-dns.mjs';
import { isPublicIP } from './proxy-network.mjs';

export const PROXY_CORE_VERSION = 'v1.19.32';
// IP-addressed DoH bootstraps the node without consulting host VPN fake-IP DNS.
// TLS verification stays enabled. These resolvers never become an OS listener.
export const PROXY_CORE_BOOTSTRAP_DNS = Object.freeze(['https://223.5.5.5/dns-query', 'https://223.6.6.6/dns-query']);
const physicalInterfacePattern = /^(?:en\d+|bridge\d+|bond\d+)$/;
const execute = promisify(execFile);
const fail = (code, message) => Object.assign(new Error(message), { code });
const cancelled = () => fail('PROXY_CORE_CANCELLED', '代理内核启动已取消。');
const safeField = (value, max, optional = false) => typeof value === 'string' && value.length <= max &&
  (optional || value.length > 0) && !/[\x00-\x1f\x7f]/.test(value);

export function physicalInterfaceFromRoute(output, interfaces = networkInterfaces()) {
  const name = /^\s*interface:\s*(\S+)\s*$/m.exec(output ?? '')?.[1];
  if (!physicalInterfacePattern.test(name ?? '') || !interfaces[name]?.some(address => !address.internal &&
      ['IPv4', 'IPv6', 4, 6].includes(address.family))) {
    throw fail('PROXY_CORE_INTERFACE_UNAVAILABLE', '未找到可用的默认物理网络接口，请连接网络后重试。');
  }
  return name;
}
export async function detectMacPhysicalInterface({ command = execute, interfaces = networkInterfaces } = {}) {
  try {
    const result = await command('/sbin/route', ['-n', 'get', 'default'], { timeout: 2500, maxBuffer: 16384,
      env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' } });
    return physicalInterfaceFromRoute(result.stdout, interfaces());
  } catch {
    throw fail('PROXY_CORE_INTERFACE_UNAVAILABLE', '未找到可用的默认物理网络接口，请连接网络后重试。');
  }
}
export function bootstrapLocalAddress(interfaceName, interfaces = networkInterfaces()) {
  const address = interfaces[interfaceName]?.find(item => !item.internal && ['IPv4', 4].includes(item.family) && net.isIP(item.address) === 4)?.address;
  if (!physicalInterfacePattern.test(interfaceName ?? '') || !address) throw fail('PROXY_CORE_INTERFACE_UNAVAILABLE', '节点解析需要默认物理接口的 IPv4 地址。');
  // This binds the owned HTTPS socket's source address; it does not change routes
  // or claim that an arbitrary system VPN cannot capture that socket.
  return address;
}
function isLoopbackHost(host) {
  return host === 'localhost' || host.endsWith('.localhost') || host === '::1' ||
    (net.isIP(host) === 4 && host.startsWith('127.'));
}

/** Only node settings understood by the built-in AnyTLS route reach its config. */
export function anyTlsSettings(input) {
  let host = input?.host;
  if (typeof host === 'string' && host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  const port = Number(input?.port);
  const serverName = input?.serverName || host;
  const clientFingerprint = input?.clientFingerprint ?? 'chrome';
  const alpn = input?.alpn ?? [];
  if (input?.protocol !== 'anytls' || !safeField(host, 253) || /[\s/@?#\\]/.test(host) ||
      (host.includes(':') && net.isIP(host) !== 6) || !Number.isInteger(port) || port < 1 || port > 65535 ||
      !safeField(input?.password, 2048) || !safeField(serverName, 253) || /[\s/@?#\\]/.test(serverName) ||
      !safeField(clientFingerprint, 64) || !/^[a-zA-Z0-9_-]+$/.test(clientFingerprint) ||
      (input.skipCertVerify != null && typeof input.skipCertVerify !== 'boolean') ||
      (input.udp != null && typeof input.udp !== 'boolean') || !Array.isArray(alpn) || alpn.length > 8 ||
      alpn.some(value => typeof value !== 'string' || !/^[\x21-\x7e]{1,64}$/.test(value))) {
    throw fail('INVALID_ANYTLS_PROXY', 'AnyTLS 节点的地址、端口、密码或 TLS 设置无效。');
  }
  if (input.id != null && !safeField(input.id, 160)) throw fail('INVALID_ANYTLS_PROXY', 'AnyTLS 节点标识无效。');
  return { host: host.toLowerCase(), port, password: input.password, serverName,
    skipCertVerify: input.skipCertVerify ?? false, clientFingerprint, alpn: [...alpn], udp: input.udp ?? true };
}

export function anyTlsCoreConfig(settings, local, { interfaceName, resolvedServer } = {}) {
  if (interfaceName != null && !physicalInterfacePattern.test(interfaceName)) throw fail('PROXY_CORE_INTERFACE_UNAVAILABLE', '默认物理网络接口无效。');
  if (resolvedServer != null && (net.isIP(resolvedServer) !== 4 || !isPublicIP(resolvedServer))) throw fail('PROXY_CORE_BOOTSTRAP_UNAVAILABLE', '节点解析未返回有效的公开 IPv4 地址。');
  const resolvers = PROXY_CORE_BOOTSTRAP_DNS.map(url => interfaceName ? `${url}#${interfaceName}` : url);
  return {
    'mixed-port': local.port,
    'bind-address': '127.0.0.1', 'allow-lan': false,
    authentication: [`${local.username}:${local.password}`], 'skip-auth-prefixes': [],
    port: 0, 'socks-port': 0, 'redir-port': 0, 'tproxy-port': 0,
    mode: 'rule', 'log-level': 'silent', ipv6: false, 'find-process-mode': 'off',
    'external-controller': '', 'external-controller-tls': '', 'external-controller-unix': '',
    'external-controller-pipe': '', 'external-ui': '', 'external-ui-url': '',
    'geo-auto-update': false, 'geodata-mode': false,
    'geox-url': { 'geo-ip': '', mmdb: '', asn: '', geosite: '' },
    dns: { enable: true, listen: '', 'enhanced-mode': 'redir-host', 'respect-rules': false,
      'use-hosts': false, 'use-system-hosts': false, ipv6: false,
      'default-nameserver': [...resolvers], nameserver: [...resolvers],
      'proxy-server-nameserver': [...resolvers], fallback: [],
      'nameserver-policy': {}, 'proxy-server-nameserver-policy': {} },
    tun: { enable: false }, sniffer: { enable: false },
    ntp: { enable: false, 'write-to-system': false },
    profile: { 'store-selected': false, 'store-fake-ip': false },
    'proxy-providers': {}, 'rule-providers': {}, 'proxy-groups': [], listeners: [], tunnels: [],
    proxies: [{ name: 'ENVARA_ANYTLS', type: 'anytls', server: resolvedServer ?? settings.host, port: settings.port,
      password: settings.password, sni: settings.serverName,
      ...(interfaceName ? { 'interface-name': interfaceName } : {}),
      'skip-cert-verify': settings.skipCertVerify, 'client-fingerprint': settings.clientFingerprint,
      'client-metadata': '', udp: settings.udp, ...(settings.alpn.length ? { alpn: [...settings.alpn] } : {}), 'min-idle-session': 0 }],
    rules: ['MATCH,ENVARA_ANYTLS'],
  };
}

async function binaryDigest(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}
async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}
async function checkRecoveryPort(port) {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  } catch {
    throw fail('PROXY_CORE_RECOVERY_FAILED', '原代理入口暂时无法恢复，请关闭相关浏览器和终端会话后重试。');
  }
}

/** Authenticate the mixed listener without making an outbound request or DNS lookup. */
export function probeCoreListener(local, { timeoutMs = 400, signal } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: local.port });
    let phase = 0; let buffer = Buffer.alloc(0); let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); socket.destroy();
      error ? reject(error) : resolve();
    };
    const onAbort = () => finish(cancelled());
    const timer = setTimeout(() => finish(fail('PROXY_CORE_NOT_READY', '代理内核尚未就绪。')), timeoutMs);
    socket.once('connect', () => socket.write(Buffer.from([5, 1, 2])));
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 2) return;
      if (phase === 0) {
        if (buffer[0] !== 5 || buffer[1] !== 2) return finish(fail('PROXY_CORE_NOT_READY', '代理监听认证不匹配。'));
        phase = 1; buffer = buffer.subarray(2);
        const user = Buffer.from(local.username); const pass = Buffer.from(local.password);
        socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([pass.length]), pass]));
      }
      if (phase === 1 && buffer.length >= 2) {
        if (buffer[0] !== 1 || buffer[1] !== 0) return finish(fail('PROXY_CORE_NOT_READY', '代理监听认证不匹配。'));
        finish();
      }
    });
    socket.once('error', () => finish(fail('PROXY_CORE_NOT_READY', '代理内核尚未就绪。')));
    socket.once('close', () => finish(fail('PROXY_CORE_NOT_READY', '代理内核尚未就绪。')));
    if (signal?.aborted) onAbort(); else signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Owns only app-created AnyTLS child processes and their private loopback ports. */
export class ProxyCoreManager {
  constructor({ dataDir, resourcesDir, resolveBinary, spawn = spawnChild, choosePort = freePort, verifyRecoveryPort = checkRecoveryPort,
    probeListener = probeCoreListener, onChange = () => {}, startupTimeoutMs = 8000,
    retryDelayMs = 75, portAttempts = 3, stopTimeoutMs = 1500, platform = process.platform,
    detectInterface = detectMacPhysicalInterface, resolveBootstrapHost = resolveProxyBootstrapHost,
    bootstrapAddress = bootstrapLocalAddress } = {}) {
    if (!path.isAbsolute(dataDir ?? '') || !path.isAbsolute(resourcesDir ?? '')) throw fail('INVALID_PROXY_CORE_PATH', '代理内核目录无效。');
    this.baseDir = path.join(dataDir, 'proxy-core'); this.resourcesDir = resourcesDir;
    this.resolveBinary = resolveBinary ?? (() => this._bundledBinary());
    this.spawn = spawn; this.choosePort = choosePort; this.verifyRecoveryPort = verifyRecoveryPort; this.probeListener = probeListener; this.onChange = onChange;
    this.startupTimeoutMs = startupTimeoutMs; this.retryDelayMs = retryDelayMs;
    this.portAttempts = portAttempts; this.stopTimeoutMs = stopTimeoutMs;
    this.platform = platform; this.detectInterface = detectInterface;
    this.resolveBootstrapHost = resolveBootstrapHost; this.bootstrapAddress = bootstrapAddress;
    this.routes = new Map(); this.queues = new Map(); this.generations = new Map(); this.closed = false;
    this.binary = null; this.binaryPromise = null; this.resourceError = null;
  }
  async _bundledBinary() {
    try {
      const provenance = JSON.parse(await readFile(path.join(this.resourcesDir, 'provenance.json'), 'utf8'));
      const name = process.platform === 'win32' ? 'mihomo.exe' : 'mihomo';
      if (provenance.core !== 'mihomo' || provenance.version !== PROXY_CORE_VERSION ||
          provenance.platform !== process.platform || provenance.arch !== process.arch ||
          provenance.binaryName !== name || !/^[a-f0-9]{64}$/.test(provenance.sha256?.binary ?? '')) throw new Error();
      const binary = path.join(this.resourcesDir, name);
      if (!(await lstat(binary)).isFile()) throw new Error();
      await access(binary, process.platform === 'win32' ? constants.F_OK : constants.X_OK);
      if (await binaryDigest(binary) !== provenance.sha256.binary) throw new Error();
      return binary;
    } catch {
      throw fail('PROXY_CORE_UNAVAILABLE', '内置 AnyTLS 内核缺失或校验失败，请使用完整的 Envara 安装包。');
    }
  }
  async initialize() {
    if (this.closed) throw cancelled();
    if (!this.binaryPromise) this.binaryPromise = Promise.resolve().then(this.resolveBinary).then(async result => {
      if (!path.isAbsolute(result ?? '')) throw fail('PROXY_CORE_UNAVAILABLE', '内置 AnyTLS 内核不可用。');
      await access(result, process.platform === 'win32' ? constants.F_OK : constants.X_OK);
      this.binary = result; this.resourceError = null; this._changed(); return result;
    }).catch(() => {
      this.binaryPromise = null; this.resourceError = 'PROXY_CORE_UNAVAILABLE'; this._changed();
      throw fail('PROXY_CORE_UNAVAILABLE', '内置 AnyTLS 内核缺失或校验失败，请使用完整的 Envara 安装包。');
    });
    await this.binaryPromise; return this.snapshot();
  }
  snapshot() {
    return { core: 'mihomo', version: PROXY_CORE_VERSION, protocols: ['anytls'],
      available: !!this.binary && !this.resourceError, activeCount: [...this.routes.values()].filter(route => route.status === 'running').length,
      error: this.resourceError, networkScope: 'app-owned-loopback', systemProxy: false, tun: false };
  }
  _changed(event) { try { Promise.resolve(this.onChange(event)).catch(() => {}); } catch {} }
  _key(proxy, settings) { return proxy.id ?? createHash('sha256').update(JSON.stringify(settings)).digest('hex'); }
  _queue(key, action) {
    const promise = (this.queues.get(key) ?? Promise.resolve()).catch(() => {}).then(action);
    this.queues.set(key, promise);
    promise.finally(() => { if (this.queues.get(key) === promise) this.queues.delete(key); }).catch(() => {});
    return promise;
  }
  async _privateDirectory() {
    await mkdir(this.baseDir, { recursive: true, mode: 0o700 });
    const info = await lstat(this.baseDir);
    if (!info.isDirectory() || info.isSymbolicLink()) throw fail('PROXY_CORE_STORAGE_FAILED', '代理内核工作目录不可用。');
    await chmod(this.baseDir, 0o700);
    const directory = await mkdtemp(path.join(this.baseDir, 'route-'));
    await chmod(directory, 0o700); return directory;
  }
  _environment(directory) {
    const env = { PATH: process.platform === 'win32' ? (process.env.SystemRoot ? path.join(process.env.SystemRoot, 'System32') : '') : '/usr/bin:/bin:/usr/sbin:/sbin',
      HOME: directory, TMPDIR: directory, TEMP: directory, TMP: directory, LANG: 'C', LC_ALL: 'C' };
    if (process.platform === 'win32' && process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    return env;
  }
  _assertLive(route) { if (this.closed || route.controller.signal.aborted) throw cancelled(); }
  async ensure(proxy, { signal } = {}) {
    const settings = anyTlsSettings(proxy); const key = this._key(proxy, settings);
    const digest = createHash('sha256').update(JSON.stringify(settings)).digest('hex');
    const generation = this.generations.get(key) ?? 0;
    if (this.closed || signal?.aborted) throw cancelled();
    return this._queue(key, async () => {
      if (this.closed || signal?.aborted || (this.generations.get(key) ?? 0) !== generation) throw cancelled();
      let interfaceName = null;
      if (this.platform === 'darwin' && !isLoopbackHost(settings.host)) {
        try { interfaceName = await this.detectInterface(); } catch { throw fail('PROXY_CORE_INTERFACE_UNAVAILABLE', '未找到可用的默认物理网络接口，请连接网络后重试。'); }
        if (!physicalInterfacePattern.test(interfaceName ?? '')) throw fail('PROXY_CORE_INTERFACE_UNAVAILABLE', '未找到可用的默认物理网络接口，请连接网络后重试。');
      }
      if (this.closed || signal?.aborted || (this.generations.get(key) ?? 0) !== generation) throw cancelled();
      const existing = this.routes.get(key);
      if (existing?.status === 'running' && existing.digest === digest && existing.interfaceName === interfaceName && !existing.exited) return { ...existing.wire };
      const recoveryWire = existing?.digest === digest ? (existing.recoveryWire ? { ...existing.recoveryWire } :
        existing.status === 'running' && existing.wire ? { ...existing.wire } : null) : null;
      if (existing) await this._stop(existing);
      const route = { key, digest, routeIdentity: randomUUID(), coreGeneration: null, controller: new AbortController(), status: 'starting', child: null, directory: null, exited: false,
        recoveryWire, interfaceName };
      this.routes.set(key, route);
      const onAbort = () => route.controller.abort();
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
      try {
        await this.initialize(); this._assertLive(route);
        let resolvedServer;
        if (this.platform === 'darwin' && !isLoopbackHost(settings.host) && !net.isIP(settings.host)) {
          const localAddress = this.bootstrapAddress(interfaceName);
          try { resolvedServer = await this.resolveBootstrapHost(settings.host, { localAddress, signal: route.controller.signal }); }
          catch { this._assertLive(route); throw fail('PROXY_CORE_BOOTSTRAP_UNAVAILABLE', '无法安全解析节点入口；未切换为系统 DNS 或直接连接。'); }
          if (net.isIP(resolvedServer) !== 4 || !isPublicIP(resolvedServer)) throw fail('PROXY_CORE_BOOTSTRAP_UNAVAILABLE', '节点解析未返回有效的公开 IPv4 地址。');
          this._assertLive(route);
        }
        const deadline = Date.now() + this.startupTimeoutMs;
        const attempts = recoveryWire ? 1 : this.portAttempts;
        for (let attempt = 0; attempt < attempts; attempt++) {
          this._assertLive(route);
          // Silent cores may stay alive after a listener bind collision; reserve
          // time for a fresh port without depending on their diagnostic output.
          const attemptDeadline = Math.min(deadline, Date.now() + Math.max(1, (deadline - Date.now()) / (attempts - attempt)));
          if (recoveryWire) { await this.verifyRecoveryPort(recoveryWire.port); this._assertLive(route); }
          route.directory = await this._privateDirectory(); this._assertLive(route);
          const port = recoveryWire?.port ?? await this.choosePort(); this._assertLive(route);
          route.wire = recoveryWire ? { ...recoveryWire } : { protocol: 'http', host: '127.0.0.1', port,
            username: randomBytes(16).toString('hex'), password: randomBytes(32).toString('hex') };
          const config = path.join(route.directory, 'config.json');
          await writeFile(config, JSON.stringify(anyTlsCoreConfig(settings, route.wire, { interfaceName, resolvedServer })), { mode: 0o600, flag: 'wx' });
          await chmod(config, 0o600); this._assertLive(route);
          route.exited = false; route.bindCollision = false;
          route.coreGeneration = randomUUID();
          route.child = this.spawn(this.binary, ['-d', route.directory, '-f', config], {
            cwd: route.directory, env: this._environment(route.directory), windowsHide: true,
            stdio: ['ignore', 'pipe', 'pipe'], shell: false,
          });
          const child = route.child;
          route.exitPromise = new Promise(resolve => {
            const finish = () => {
              if (route.child !== child) return resolve();
              route.exited = true; resolve();
              if (route.status === 'running') {
                route.recoveryWire = { ...route.wire };
                route.wire = null;
                route.status = 'failed'; this._changed({ id: key, status: 'failed', error: 'PROXY_CORE_EXITED' });
                route.cleanupPromise = this._discard(route);
                route.cleanupPromise.catch(() => {});
              }
            };
            child.once('error', finish); child.once('exit', finish);
          });
          // Never retain or forward core output: it can contain node addresses and credentials.
          const drain = chunk => { if (/address already in use|bind:.*(?:used|in use)/i.test(String(chunk))) route.bindCollision = true; };
          child.stdout?.on('data', drain); child.stderr?.on('data', drain);
          while (Date.now() < attemptDeadline) {
            this._assertLive(route);
            if (route.exited) break;
            try {
              await this.probeListener(route.wire, { timeoutMs: Math.min(400, Math.max(1, attemptDeadline - Date.now())), signal: route.controller.signal });
              this._assertLive(route);
              if (route.exited) break;
              route.status = 'running'; route.recoveryWire = null;
              this._changed({ id: key, status: 'running' }); return { ...route.wire };
            } catch { this._assertLive(route); }
            await delay(this.retryDelayMs, undefined, { signal: route.controller.signal }).catch(() => this._assertLive(route));
          }
          const startupExited = route.exited;
          const retry = !recoveryWire && (route.bindCollision || !startupExited) && attempt + 1 < attempts && Date.now() < deadline;
          await this._stopChild(route); await this._discard(route);
          if (recoveryWire) throw fail('PROXY_CORE_RECOVERY_FAILED', '原代理入口暂时无法恢复，请关闭相关浏览器和终端会话后重试。');
          if (!retry) throw fail(startupExited ? 'PROXY_CORE_START_FAILED' : 'PROXY_CORE_START_TIMEOUT',
            '内置 AnyTLS 内核未能启动，请重试或检查完整安装包。');
        }
        throw fail('PROXY_CORE_START_FAILED', '内置 AnyTLS 内核未能启动。');
      } catch (error) {
        if (recoveryWire && error.code !== 'PROXY_CORE_CANCELLED' && !this.closed && !route.controller.signal.aborted) {
          await this._stopChild(route); await this._discard(route);
          route.recoveryWire = { ...recoveryWire }; route.status = 'failed';
          this._changed({ id: key, status: 'failed', error: 'PROXY_CORE_RECOVERY_FAILED' });
          throw fail('PROXY_CORE_RECOVERY_FAILED', '原代理入口暂时无法恢复，请关闭相关浏览器和终端会话后重试。');
        }
        await this._stop(route);
        if (error.code === 'PROXY_CORE_CANCELLED') throw error;
        if (['PROXY_CORE_UNAVAILABLE', 'PROXY_CORE_START_FAILED', 'PROXY_CORE_START_TIMEOUT', 'PROXY_CORE_STORAGE_FAILED', 'PROXY_CORE_INTERFACE_UNAVAILABLE', 'PROXY_CORE_BOOTSTRAP_UNAVAILABLE'].includes(error.code)) throw error;
        throw fail('PROXY_CORE_START_FAILED', '内置 AnyTLS 内核未能启动，请重试或检查完整安装包。');
      } finally { signal?.removeEventListener('abort', onAbort); }
    });
  }
  async _stopChild(route) {
    const child = route.child;
    if (!child || route.exited) return;
    child.kill('SIGTERM');
    await Promise.race([route.exitPromise, delay(this.stopTimeoutMs)]);
    if (!route.exited) { child.kill('SIGKILL'); await Promise.race([route.exitPromise, delay(this.stopTimeoutMs)]); }
    if (!route.exited) throw fail('PROXY_CORE_STOP_FAILED', '代理内核进程未能退出。');
  }
  async _discard(route) {
    route.wire = null;
    if (route.directory) { const directory = route.directory; route.directory = null; await rm(directory, { recursive: true, force: true }); }
  }
  async _stop(route) {
    route.status = 'stopping'; route.controller.abort();
    await this._stopChild(route); await route.cleanupPromise; await this._discard(route);
    route.recoveryWire = null;
    if (this.routes.get(route.key) === route) this.routes.delete(route.key);
    route.status = 'stopped'; this._changed({ id: route.key, status: 'stopped' });
  }
  /** Private lifecycle evidence, never credentials or a renderer readiness receipt. */
  routingIdentity(proxyOrId) {
    const key = typeof proxyOrId === 'string' ? proxyOrId : this._key(proxyOrId, anyTlsSettings(proxyOrId));
    const route = this.routes.get(key);
    if (this.closed || route?.status !== 'running' || route.exited || route.controller.signal.aborted || !route.wire ||
        !Number.isSafeInteger(route.child?.pid) || route.child.pid < 1 || !route.coreGeneration) return null;
    return { proxyId: key, nodeType: 'anytls', routeIdentity: route.routeIdentity,
      coreGeneration: route.coreGeneration, corePid: route.child.pid, coreVersion: PROXY_CORE_VERSION };
  }
  async release(proxyOrId) {
    const key = typeof proxyOrId === 'string' ? proxyOrId : this._key(proxyOrId, anyTlsSettings(proxyOrId));
    this.generations.set(key, (this.generations.get(key) ?? 0) + 1);
    this.routes.get(key)?.controller.abort();
    return this._queue(key, async () => { const route = this.routes.get(key); if (route) await this._stop(route); });
  }
  async close() {
    this.closed = true;
    for (const route of this.routes.values()) route.controller.abort();
    await Promise.allSettled([...this.queues.values()]);
    const results = await Promise.allSettled([...this.routes.values()].map(route => this._stop(route)));
    const rejected = results.find(result => result.status === 'rejected');
    if (rejected) throw rejected.reason;
  }
}
