import path from 'node:path';
import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { access, mkdir, readFile, writeFile, stat, chmod } from 'node:fs/promises';
import { constants } from 'node:fs';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { BrowseForgeClient } from './browseforge-client.mjs';
import { BrowserRuntime, parseProcessMetrics } from './runtime.mjs';

const execute = promisify(execFile);
const IDS = ['camoufox', 'cloakbrowser', 'browseforge-chromium'];
const fail = (message, code) => Object.assign(new Error(message), { code });
export function macSystemProxyEnvironment(output) {
  const values = Object.fromEntries([...output.matchAll(/^\s*([A-Za-z]+)\s*:\s*([^\r\n]+)\s*$/gm)].map(match => [match[1], match[2].trim()]));
  const endpoint = (kind, protocol) => {
    const host = values[kind + 'Proxy']; const port = Number(values[kind + 'Port']);
    if (values[kind + 'Enable'] !== '1' || !host || /[\s/@?#]/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
    return `${protocol}://${host.includes(':') ? `[${host}]` : host}:${port}`;
  };
  const socks = endpoint('SOCKS', 'socks5');
  const http = socks ?? endpoint('HTTP', 'http');
  const https = socks ?? endpoint('HTTPS', 'http');
  return { ...(http ? { HTTP_PROXY: http } : {}), ...(https ? { HTTPS_PROXY: https } : {}) };
}
export function sidecarConfig(baseDir, port, states, platform = process.platform) {
  const runtimes = Object.fromEntries(IDS.map(id => [id, {
    enabled: !!states[id]?.installed, skip_auto_update: true,
    binary_path: states[id]?.binaryPath ?? '',
    family: id === 'camoufox' ? 'firefox' : 'chromium',
    display_name: { camoufox: 'Camoufox', cloakbrowser: 'CloakBrowser', 'browseforge-chromium': 'BrowseForge Chromium' }[id],
    ...(id !== 'camoufox' ? { settings: { fingerprint_platform: platform === 'darwin' ? 'macos' : platform === 'win32' ? 'windows' : 'linux', target_platform_policy: 'warn', extra_args: [] } } : {}),
  }]));
  return {
    host: '127.0.0.1', port: String(port), allow_empty_runtime: true,
    profiles_dir: path.join(baseDir, 'profiles'), data_dir: path.join(baseDir, 'data'),
    fingerprint_dir: path.join(baseDir, 'data'), log_file: path.join(baseDir, 'logs/server.log'),
    default_runtime_id: IDS.find(id => states[id]?.installed) ?? 'cloakbrowser', runtimes,
  };
}
export function mergeEngineStates(report, existing = {}) {
  return Object.fromEntries(IDS.map(id => {
    const item = report?.browsers?.find(value => value.name === id);
    const old = existing[id] ?? {};
    return [id, { ...old, supported: !!item?.platform_supported, installed: !!item?.ready,
      binaryPath: item?.ready ? item.path : null, version: item?.ready ? item.installed : null,
      error: old.error ?? item?.unsupported_reason ?? null }];
  }));
}
async function availablePort(preferred = 0) {
  const server = net.createServer();
  try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(preferred, '127.0.0.1', resolve); }); }
  catch (error) { if (preferred && error.code === 'EADDRINUSE') return availablePort(); throw error; }
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}
function waitForChildExit(child, timeoutMs) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
  return new Promise(resolve => {
    const finish = exited => { clearTimeout(timer); child.off('exit', onExit); resolve(exited); };
    const onExit = () => finish(true);
    const timer = setTimeout(() => finish(false), timeoutMs);
    timer.unref();
    child.once('exit', onExit);
  });
}

/** Owns only this app's loopback backend and explicitly requested engine downloads. */
export class SidecarManager {
  constructor({ dataDir, resourcesDir, onChange = () => {}, legacyCacheDir, commandGraceMs = 1500, startupStep = async (_name, operation) => await operation() }) {
    if (!Number.isInteger(commandGraceMs) || commandGraceMs < 1 || commandGraceMs > 60000) throw new TypeError('Invalid sidecar command stop deadline.');
    this.dataDir = dataDir;
    this.baseDir = path.join(dataDir, 'browseforge');
    this.resourcesDir = resourcesDir;
    this.binary = path.join(resourcesDir, process.platform === 'win32' ? 'BrowseForge-sidecar.exe' : 'BrowseForge-sidecar');
    this.driver = path.join(resourcesDir, 'playwright-driver');
    this.configFile = path.join(this.baseDir, 'config.json');
    this.states = {};
    this.onChange = onChange;
    this.startupStep = startupStep;
    this.legacy = new BrowserRuntime({ cacheDir: legacyCacheDir ?? path.join(dataDir, 'engines'), collectMetrics: false });
    this.client = new BrowseForgeClient({ baseUrl: () => this.baseUrl, token: () => this.token });
    this.process = null;
    this.installations = new Map();
    this.commands = new Set();
    this.commandStops = new Map();
    this.commandGraceMs = commandGraceMs;
    this.closed = false;
  }
  env() {
    return { ...this.systemProxy, ...process.env, NO_PROXY: [process.env.NO_PROXY, '127.0.0.1', 'localhost', '::1'].filter(Boolean).join(','), BROWSEFORGE_TOKEN: this.token,
      BROWSEFORGE_SKIP_BROWSER_AUTO_UPDATE: 'true', PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1', ENVARA_DESKTOP_BUNDLED_DRIVER: '1',
      PLAYWRIGHT_DRIVER_PATH: this.driver, PLAYWRIGHT_CLI_PATH: path.join(this.driver, 'package/cli.js'), PLAYWRIGHT_NODEJS_PATH: path.join(this.driver, process.platform === 'win32' ? 'node.exe' : 'node'),
      ELECTRON_RUN_AS_NODE: undefined };
  }
  changed() { try { Promise.resolve(this.onChange()).catch(() => {}); } catch {} }
  async command(args, timeout = 15000, progress) {
    return new Promise((resolve, reject) => {
      const child = spawn(this.binary, ['--base-dir', this.baseDir, '--config', this.configFile, ...args], { env: this.env(), cwd: this.baseDir, windowsHide: true });
      this.commands.add(child);
      let output = ''; let diagnostic = '';
      let settled = false, terminationError = null, killTimer, settleTimer;
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer); clearTimeout(killTimer); clearTimeout(settleTimer);
        error ? reject(error) : resolve(result);
      };
      const terminate = error => {
        if (settled || terminationError) return;
        terminationError = error;
        child.kill('SIGTERM');
        if (settled) return;
        killTimer = setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
          // Retain a still-live child in commands rather than claiming cleanup.
          settleTimer = setTimeout(() => finish(terminationError), this.commandGraceMs);
        }, this.commandGraceMs);
      };
      this.commandStops.set(child, terminate);
      child.stdout.on('data', chunk => {
        if (terminationError) return;
        output += chunk;
        if (output.length > 2 * 1024 * 1024) {
          output = '';
          terminate(fail('本地浏览器服务响应超出限制。', 'BACKEND_COMMAND_FAILED'));
        }
      });
      child.stderr.on('data', chunk => {
        diagnostic = (diagnostic + chunk).slice(-6000);
        if (progress) progress(String(chunk).replaceAll(this.token ?? '', '[redacted]').slice(-400));
      });
      const timer = setTimeout(() => terminate(fail('本地浏览器服务操作超时。', 'BACKEND_COMMAND_TIMEOUT')), timeout);
      timer.unref();
      child.once('error', error => finish(error));
      child.once('close', code => {
        this.commands.delete(child);
        this.commandStops.delete(child);
        if (terminationError) { finish(terminationError); return; }
        try {
          const result = JSON.parse(output);
          if (code === 0 || (args.includes('status') && Array.isArray(result.browsers))) finish(null, result);
          else finish(fail(result.error ?? `内核安装失败 (${code})`, 'ENGINE_INSTALL_FAILED'));
        } catch { finish(fail(`本地内核服务失败 (${code})：${diagnostic.replaceAll(this.token ?? '', '[redacted]').slice(-500)}`, 'BACKEND_COMMAND_FAILED')); }
      });
    });
  }
  async probe() {
    const report = await this.command(['browsers', 'status', '--runtimes', IDS.join(','), '--json']);
    this.states = mergeEngineStates(report, this.states);
    // Preserve a previously installed, signature-verified CloakBrowser cache.
    const legacy = this.legacy._usableInfo();
    if (!this.states.cloakbrowser.installed && legacy.installed) {
      this.states.cloakbrowser = { ...this.states.cloakbrowser, installed: true, binaryPath: legacy.binaryPath, version: legacy.version ?? this.legacy.browserVersion };
    }
    for (const state of Object.values(this.states)) if (state.installed) {
      try { await access(state.binaryPath, process.platform === 'win32' ? constants.F_OK : constants.X_OK); if (!(await stat(state.binaryPath)).isFile()) state.installed = false; }
      catch { state.installed = false; state.binaryPath = null; state.version = null; }
    }
    return this.states;
  }
  async initialize() {
    await this.startupStep('sidecar-files', async () => {
      for (const dir of [this.baseDir, 'profiles', 'data', 'logs'].map(dir => path.isAbsolute(dir) ? dir : path.join(this.baseDir, dir))) await mkdir(dir, { recursive: true, mode: 0o700 });
      await access(this.binary, process.platform === 'win32' ? constants.F_OK : constants.X_OK);
      for (const resource of ['package/cli.js', 'package/lib/coreBundle.js', process.platform === 'win32' ? 'node.exe' : 'node']) await access(path.join(this.driver, resource));
      if (process.platform === 'darwin') { try { this.systemProxy = macSystemProxyEnvironment((await execute('/usr/sbin/scutil', ['--proxy'], { timeout: 3000 })).stdout); } catch {} }
      const tokenPath = path.join(this.baseDir, 'data/.envara-token');
      try { this.token = (await readFile(tokenPath, 'utf8')).trim(); if (!/^[a-f0-9]{64}$/.test(this.token)) throw fail('本地服务凭据格式无效。', 'INVALID_LOCAL_TOKEN'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; this.token = randomBytes(32).toString('hex'); await writeFile(tokenPath, this.token, { mode: 0o600, flag: 'wx' }); }
      await chmod(tokenPath, 0o600);
      try { const saved = JSON.parse(await readFile(this.configFile, 'utf8')); const port = Number(saved.port); if (Number.isInteger(port) && port >= 1024 && port <= 65535) this.port = port; } catch {}
    });
    await this.startupStep('sidecar-probe', () => this.probe());
    await this.startupStep('sidecar-start', () => this.start());
    return this;
  }
  async start() {
    if (this.closed) throw fail('应用正在退出。', 'APP_CLOSING');
    this.port = await availablePort(this.port);
    this.baseUrl = `http://127.0.0.1:${this.port}`;
    await writeFile(this.configFile, JSON.stringify(sidecarConfig(this.baseDir, this.port, this.states), null, 2), { mode: 0o600 });
    let diagnostic = '';
    const capture = chunk => { diagnostic = (diagnostic + String(chunk).replaceAll(this.token, '[redacted]').replaceAll(this.token.slice(0, 16), '[redacted]')).slice(-4000); };
    let spawnError;
    const child = await this.startupStep('sidecar-process-spawn', () => {
      const child = spawn(this.binary, ['--base-dir', this.baseDir, '--config', this.configFile, 'serve', '--host', '127.0.0.1', '--port', String(this.port), '--no-open', '--enforce-http-proxy-bridge'], { cwd: this.baseDir, env: this.env(), windowsHide: true });
      this.process = child;
      child.stdout.on('data', capture); child.stderr.on('data', capture);
      child.once('error', error => { spawnError = error; });
      child.once('exit', () => { if (this.process === child) { this.process = null; if (!this.closed) this.changed(); } });
      return child;
    });
    await this.startupStep('sidecar-api-ready', async () => {
      const deadline = Date.now() + 45000;
      while (Date.now() < deadline) {
        if (spawnError || child.exitCode !== null) throw fail(`本地浏览器服务未能启动：${spawnError?.message ?? diagnostic.slice(-800)}`, 'BACKEND_START_FAILED');
        try { await this.client.request('GET', '/api/runtimes', undefined, { timeoutMs: 1000 }); return; } catch {}
        await delay(150);
      }
      await this.stop();
      throw fail('本地浏览器服务启动超时。', 'BACKEND_START_TIMEOUT');
    });
  }
  getEngineStates() { return this.states; }
  async installEngine(id) {
    if (!IDS.includes(id)) throw fail('请选择有效的浏览器内核。', 'INVALID_ENGINE');
    if (this.installations.size) throw fail('请等待当前内核安装完成。', 'ENGINE_INSTALLING');
    const sessions = (await this.client.request('GET', '/api/sessions')).data ?? [];
    if (sessions.length) throw fail('请先停止所有环境，再安装内核。', 'PROFILE_RUNNING');
    if (!this.states[id]?.supported) throw fail('当前平台尚不支持此内核。', 'UNSUPPORTED_ENGINE');
    this.states[id] = { ...this.states[id], installing: true, error: null, progress: '正在下载官方内核…' };
    this.changed();
    const task = this.command(['browsers', 'install', '--runtimes', id, '--json'], 15 * 60 * 1000, message => { this.states[id].progress = message; this.changed(); });
    this.installations.set(id, task);
    try { await task; await this.probe(); await this.stop(); await this.start(); }
    catch (error) { this.states[id].error = error.message; throw error; }
    finally { this.installations.delete(id); this.states[id].installing = false; this.states[id].progress = null; this.changed(); }
    return { installedEngine: id };
  }
  async metrics(profiles) {
    if (process.platform === 'win32') return {};
    try {
      const { stdout } = await execute('/bin/ps', ['-axo', 'pid=,ppid=,%cpu=,rss=,command='], { timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
      return parseProcessMetrics(stdout, new Map(profiles.filter(p => p.runtime_id !== 'camoufox').map(p => [p.id, { profileDir: path.join(this.baseDir, 'profiles', p.id, 'browser-data') }])));
    } catch { return {}; }
  }
  async assertLegacyStopped() {
    if (process.platform === 'win32') return false;
    const { stdout } = await execute('/bin/ps', ['-axo', 'command='], { timeout: 5000, maxBuffer: 8 * 1024 * 1024 });
    return !stdout.split('\n').some(line => line.includes(path.join(this.dataDir, 'profiles') + path.sep) && /(?:--user-data-dir=|--profile|-profile)/.test(line));
  }
  connectionConfig() { return { mcpServers: { envara: { url: `${this.baseUrl}/mcp`, headers: { Authorization: `Bearer ${this.token}` } } } }; }
  cancelInstall() { for (const child of this.commands) this.commandStops.get(child)?.(fail('本地浏览器服务操作已取消。', 'BACKEND_COMMAND_CANCELLED')); }
  async stop() {
    const child = this.process;
    if (!child) return;
    await this.client.request('POST', '/api/shutdown', {}, { timeoutMs: 8000 }).catch(() => {});
    if (!await waitForChildExit(child, 8000)) {
      child.kill('SIGTERM');
      if (!await waitForChildExit(child, 3000)) {
        child.kill('SIGKILL');
        if (!await waitForChildExit(child, this.commandGraceMs)) throw fail('本地浏览器服务进程尚未确认退出。', 'BACKEND_STOP_FAILED');
      }
    }
    if (this.process === child) this.process = null;
  }
  async shutdown() {
    this.closed = true; this.cancelInstall();
    await Promise.allSettled([...this.installations.values()]); await this.stop();
    if (this.commands.size) throw fail('本地浏览器服务进程尚未确认退出。', 'BACKEND_STOP_FAILED');
  }
}
