import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { binaryInfo, ensureBinary, launchPersistentContext } from 'cloakbrowser';
import { applyBrowserPrivacy, normalizePrivacy, privacyLaunchArgs, snapshotPrivacy } from './privacy-policy.mjs';

const execFileAsync = promisify(execFile);
// These are the upstream wrapper's public, freely downloadable baseline builds.
const FREE_VERSIONS = {
  'darwin-arm64': '145.0.7632.109.2',
  'darwin-x64': '145.0.7632.109.2',
  'linux-arm64': '146.0.7680.177.3',
  'linux-x64': '146.0.7680.177.5',
  'win32-x64': '146.0.7680.177.5',
};

// The upstream wrapper reads its cache and executable settings from process.env.
// Serialize those short-lived overrides, including launches, to prevent one
// profile's configuration from being used by another concurrent native call.
let upstreamOperation = Promise.resolve();
function withEnvironment(values, operation) {
  const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = String(value);
  }
  const restore = () => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  };
  try {
    const result = operation();
    if (result && typeof result.then === 'function') return result.finally(restore);
    restore();
    return result;
  } catch (error) {
    restore();
    throw error;
  }
}

export function buildLaunchConfig(profile, proxy, profileDir, browserVersion) {
  if (!Number.isSafeInteger(profile.seed) || profile.seed < 1 || profile.seed > 2147483647) {
    throw new Error('指纹种子必须是 1 至 2147483647 之间的整数。');
  }
  if (!['macos', 'windows', 'linux'].includes(profile.platform)) throw new Error('不支持的指纹平台。');
  const width = Number(profile.width);
  const height = Number(profile.height);
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 800 || height < 600 || width > 7680 || height > 4320) {
    throw new Error('屏幕尺寸超出支持范围。');
  }
  const args = [
    `--fingerprint=${profile.seed}`,
    `--fingerprint-platform=${profile.platform}`,
    `--fingerprint-screen-width=${width}`,
    `--fingerprint-screen-height=${height}`,
    `--window-size=${width},${height}`,
    // The freely downloadable macOS v145 build ignores --lang for
    // navigator.language. Its native --accept-lang path sets the browser's
    // language list; v148+ also fixes --fingerprint-locale itself.
    `--accept-lang=${[profile.locale, profile.locale.split('-')[0]].filter((locale, index, languages) => languages.indexOf(locale) === index).join(',')}`,
    '--no-first-run',
    '--no-default-browser-check',
    ...privacyLaunchArgs(profile.privacy),
  ];
  // Chromium's own policy blocks direct, non-proxied UDP candidates. This is
  // deliberately not described as a guaranteed WebRTC exit-IP spoof.
  if (proxy) args.push('--force-webrtc-ip-handling-policy=disable_non_proxied_udp');
  let proxyOption;
  if (proxy) {
    const protocol = proxy.protocol ?? proxy.type;
    if (!['http', 'https', 'socks5'].includes(protocol)) throw new Error('不支持的代理协议。');
    const host = proxy.host.includes(':') && !proxy.host.startsWith('[') ? `[${proxy.host}]` : proxy.host;
    proxyOption = {
      server: `${protocol}://${host}:${proxy.port}`,
      ...(proxy.username ? { username: proxy.username } : {}),
      ...(proxy.password ? { password: proxy.password } : {}),
    };
  }
  return {
    userDataDir: profileDir,
    headless: false,
    stealthArgs: false,
    args,
    timezone: profile.timezone,
    locale: profile.locale,
    viewport: null,
    browserVersion,
    ...(proxyOption ? { proxy: proxyOption } : {}),
    launchOptions: { timeout: 45000, serviceWorkers: normalizePrivacy(profile.privacy).mode === 'off' ? 'allow' : 'block' },
  };
}

const shellQuote = value => `'${String(value).replaceAll("'", "'\\''")}'`;

export function macLocaleLauncherSource(binaryPath, locale) {
  // Chromium chooses its macOS ICU/application locale from Cocoa. The native
  // NSArgumentDomain syntax requires positional values, which Playwright rejects
  // in launch.args. An exec-only launcher supplies them before forwarding every
  // Playwright argument unchanged. It modifies neither the binary nor OS prefs.
  return `#!/bin/sh\nexec ${shellQuote(binaryPath)} -AppleLanguages ${shellQuote(`(${locale})`)} "$@"\n`;
}

export function isMacLocaleStartupHistory(history, locale) {
  const entry = history.entries?.[0];
  return history.currentIndex === 0 && history.entries?.length === 1 &&
    entry.transitionType === 'auto_toplevel' && !entry.userTypedURL &&
    entry.url?.toLowerCase() === `http://(${locale.toLowerCase()})/`;
}

// Sum real OS samples for a Chromium parent and its descendants. RSS is an
// operating-system resident-memory estimate; shared pages may be counted twice.
export function parseProcessMetrics(output, sessions) {
  const processes = output.split('\n').flatMap(line => {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+([\d.]+)\s+(\d+)\s+(.+)$/);
    return match ? [{ pid: Number(match[1]), ppid: Number(match[2]), cpu: Number(match[3]), rss: Number(match[4]) * 1024, command: match[5] }] : [];
  });
  const metrics = {};
  for (const [id, session] of sessions) {
    const marker = `--user-data-dir=${session.profileDir}`;
    const roots = processes.filter(process => process.command.includes(marker) && [' ', '"', undefined].includes(process.command.split(marker)[1]?.[0]));
    if (!roots.length) { metrics[id] = { cpuPercent: null, memoryBytes: null }; continue; }
    const included = new Set(roots.map(process => process.pid));
    let size;
    do {
      size = included.size;
      for (const process of processes) if (included.has(process.ppid)) included.add(process.pid);
    } while (included.size !== size);
    const owned = processes.filter(process => included.has(process.pid));
    metrics[id] = {
      cpuPercent: Math.round(owned.reduce((total, process) => total + process.cpu, 0) * 10) / 10,
      memoryBytes: owned.reduce((total, process) => total + process.rss, 0),
    };
  }
  return metrics;
}

export class BrowserRuntime {
  constructor(options = {}) {
    this.cacheDir = options.cacheDir ?? path.join(os.homedir(), '.envara', 'browser');
    this.browserVersion = options.browserVersion ?? FREE_VERSIONS[`${process.platform}-${process.arch}`];
    this.onChange = options.onChange ?? (() => {});
    this.launch = options.launchPersistentContext ?? launchPersistentContext;
    this.ensure = options.ensureBinary ?? ensureBinary;
    this.info = options.binaryInfo ?? binaryInfo;
    this.exec = options.execFile ?? execFileAsync;
    this.collectMetrics = options.collectMetrics ?? true;
    this.sessions = new Map();
    this.pending = new Map();
    this.metrics = {};
    this.installing = false;
    this.progress = null;
    this.error = null;
    this.installPromise = null;
    this.timer = null;
    this.closing = false;
  }

  _emit() { this.onChange(this.snapshot()); }

  _info() {
    if (!this.browserVersion) return { installed: false, version: null };
    return withEnvironment({ CLOAKBROWSER_CACHE_DIR: this.cacheDir }, () => this.info(this.browserVersion));
  }

  _usableInfo() {
    const info = this._info();
    if (!info.installed || !info.binaryPath) return { ...info, installed: false };
    try {
      fs.accessSync(info.binaryPath, process.platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK);
      return info;
    } catch { return { ...info, installed: false }; }
  }

  isInstalled() { try { return Boolean(this._usableInfo().installed); } catch { return false; } }

  snapshot() {
    let info;
    try { info = this._usableInfo(); } catch (error) { info = { installed: false, version: this.browserVersion, error: error.message }; }
    return {
      installed: Boolean(info.installed), installing: this.installing,
      version: info.version ?? this.browserVersion ?? null,
      progress: this.progress, error: this.error ?? info.error ?? null,
      engine: 'cloakbrowser', platform: `${process.platform}-${process.arch}`,
      downloadSource: 'https://github.com/CloakHQ/CloakBrowser',
    };
  }

  _native(operation, executablePath) {
    const run = () => withEnvironment({
      CLOAKBROWSER_CACHE_DIR: this.cacheDir,
      CLOAKBROWSER_AUTO_UPDATE: 'false',
      CLOAKBROWSER_BINARY_PATH: executablePath,
    }, operation);
    const result = upstreamOperation.then(run, run);
    upstreamOperation = result.catch(() => {});
    return result;
  }

  async _prepareExecutable(binaryPath, profile) {
    if (process.platform !== 'darwin') return binaryPath;
    const launchersDir = path.join(this.cacheDir, 'launchers');
    await fs.promises.mkdir(launchersDir, { recursive: true });
    const key = createHash('sha256').update(profile.id).digest('hex').slice(0, 24);
    const launcherPath = path.join(launchersDir, `${key}.sh`);
    const temporaryPath = `${launcherPath}.tmp`;
    await fs.promises.writeFile(temporaryPath, macLocaleLauncherSource(binaryPath, profile.locale), { mode: 0o700 });
    await fs.promises.rename(temporaryPath, launcherPath);
    return launcherPath;
  }

  async _cleanMacLocaleStartupPage(context, locale) {
    if (process.platform !== 'darwin' || !context.newCDPSession) return;
    // Chromium also interprets the Cocoa array value as a startup URL. Inspect
    // its original navigation entry, because failed pages expose only
    // chrome-error://chromewebdata/ to Playwright. Close precisely the generated
    // auto_toplevel entry; restored/user pages and their history remain intact.
    const startupPages = context.pages().slice();
    const deadline = Date.now() + 1000;
    do {
      for (const page of startupPages) {
        if (page.isClosed()) continue;
        let cdp;
        try {
          cdp = await context.newCDPSession(page);
          const history = await cdp.send('Page.getNavigationHistory');
          if (isMacLocaleStartupHistory(history, locale)) {
            await page.close();
            return;
          }
        } catch { /* The user may close a startup tab while launch completes. */ }
        finally { if (cdp) await cdp.detach().catch(() => {}); }
      }
      if (Date.now() >= deadline) return;
      await new Promise(resolve => setTimeout(resolve, 50));
    } while (Date.now() < deadline);
  }

  install() {
    if (this.installPromise) return this.installPromise;
    if (this.isInstalled()) return Promise.resolve(this.snapshot());
    if (!this.browserVersion) return Promise.reject(new Error('当前系统没有可下载的 CloakBrowser 内核。'));
    this.installing = true;
    this.error = null;
    // Upstream has no progress callback; an indeterminate indicator is truthful.
    this.progress = null;
    this._emit();
    this.installPromise = (async () => {
      try {
        await fs.promises.mkdir(this.cacheDir, { recursive: true });
        await this._native(() => this.ensure(undefined, this.browserVersion));
        if (!this.isInstalled()) throw new Error('内核下载结束，但未找到可运行的浏览器。');
      } catch (error) {
        this.error = error.message;
        throw error;
      } finally {
        this.installing = false;
        this.installPromise = null;
        this._emit();
      }
      return this.snapshot();
    })();
    return this.installPromise;
  }

  async start(profile, proxy, profileDir, onClose = () => {}) {
    if (this.closing) throw new Error('应用正在退出。');
    if (this.sessions.has(profile.id)) { await this.focus(profile.id); return this.sessions.get(profile.id); }
    if (this.pending.has(profile.id)) return this.pending.get(profile.id);
    const installed = this._usableInfo();
    if (!installed.installed) throw new Error('请先在设置中下载浏览器内核，再启动环境。');
    const config = buildLaunchConfig(profile, proxy, profileDir, installed.version);
    const promise = (async () => {
      await fs.promises.mkdir(profileDir, { recursive: true });
      const executablePath = await this._prepareExecutable(installed.binaryPath, profile);
      const context = await this._native(() => this.launch(config), executablePath);
      const session = { context, profile, profileDir, closed: false, onClose };
      try { session.privacy = await applyBrowserPrivacy(context, { privacy: profile.privacy, geolocation: profile.geolocation }); }
      catch (error) { await context.close().catch(() => {}); throw error; }
      const finish = (error) => {
        if (session.closed) return;
        session.closed = true;
        if (this.sessions.get(profile.id) === session) this.sessions.delete(profile.id);
        delete this.metrics[profile.id];
        if (!this.sessions.size && this.timer) { clearInterval(this.timer); this.timer = null; }
        try { onClose(error); } finally { this._emit(); }
      };
      session.finish = finish;
      this.sessions.set(profile.id, session);
      context.on('close', () => finish());
      if (this.closing) { await context.close(); finish(); return; }
      try {
        await this._cleanMacLocaleStartupPage(context, profile.locale);
        const page = context.pages().find(page => !page.isClosed()) ?? await context.newPage();
        const startUrl = profile.startUrl || 'about:blank';
        if (startUrl !== 'about:blank') await page.goto(startUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        await page.bringToFront();
      } catch (error) {
        // A website/navigation failure should remain visible in the real browser;
        // only a closed context makes the environment stopped.
        if (session.closed) throw error;
      }
      this._emit();
      this._startMetrics();
      return session;
    })();
    this.pending.set(profile.id, promise);
    try { return await promise; } finally { this.pending.delete(profile.id); }
  }

  privacyForProfile(id) {
    const state = this.sessions.get(id)?.privacy;
    return state ? snapshotPrivacy(state) : null;
  }

  async stop(id) {
    if (this.pending.has(id)) await this.pending.get(id).catch(() => {});
    const session = this.sessions.get(id);
    if (!session) return;
    await session.context.close();
    session.finish();
  }

  async focus(id) {
    const session = this.sessions.get(id);
    if (!session) throw new Error('环境尚未运行。');
    const page = session.context.pages().find(page => !page.isClosed()) ?? await session.context.newPage();
    await page.bringToFront();
  }

  async screenshot(id) {
    const page = this.sessions.get(id)?.context.pages().find(page => !page.isClosed());
    if (!page) return null;
    try {
      const buffer = await page.screenshot({ type: 'jpeg', quality: 65, timeout: 8000 });
      return `data:image/jpeg;base64,${buffer.toString('base64')}`;
    } catch { return null; }
  }

  getMetrics() {
    return Object.fromEntries([...this.sessions.keys()].map(id => [id, this.metrics[id] ?? { cpuPercent: null, memoryBytes: null }]));
  }

  getSession(id) { return this.sessions.get(id) ?? null; }

  _startMetrics() {
    if (!this.collectMetrics || process.platform === 'win32' || this.timer) return;
    let sampling = false;
    const sample = async () => {
      if (sampling || !this.sessions.size) return;
      sampling = true;
      try {
        const { stdout } = await this.exec('ps', ['-axo', 'pid=,ppid=,%cpu=,rss=,command='], { maxBuffer: 8 * 1024 * 1024, timeout: 4000 });
        this.metrics = parseProcessMetrics(stdout, this.sessions);
        this._emit();
      } catch { this.metrics = {}; } finally { sampling = false; }
    };
    void sample();
    this.timer = setInterval(sample, 5000);
    this.timer.unref();
  }

  async closeAll() {
    this.closing = true;
    await Promise.allSettled([...this.pending.values()]);
    await Promise.allSettled([...this.sessions.keys()].map(id => this.stop(id)));
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

export default BrowserRuntime;
