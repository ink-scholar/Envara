/** Capture the built React UI using only synthetic data and an isolated Electron instance. */
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';

const execute = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sampleTime = '2026-01-01T00:00:00.000Z';
const network = { ok: true, scope: 'egress', ip: '203.0.113.10', country: '示例地区', city: '演示城市', timezone: 'Asia/Shanghai' };
export const screenshotSnapshot = {
  profiles: [{ id: 'demo_environment', name: '演示环境 · 项目工作区', group: '演示', notes: '合成展示数据，无实际网络连接。',
    engine: 'cloakbrowser', platform: 'macos', deviceProfileId: 'provider-default', seed: null, locale: 'zh-CN', timezone: 'Asia/Shanghai',
    width: null, height: null, startUrl: '', proxyId: 'demo_proxy', status: 'stopped', dataBytes: 0, network,
    createdAt: sampleTime, updatedAt: sampleTime, lastLaunchedAt: null, cpuPercent: null, memoryBytes: null }],
  proxies: [{ id: 'demo_proxy', name: '示例网络 · 无实际连接', protocol: 'anytls', host: 'proxy.example.invalid', port: 443,
    username: '', password: '', network, location: { confirmed: true, mode: 'manual', label: '示例位置（演示数据）', timezone: 'Asia/Shanghai' } }],
  groups: [{ name: '演示', proxyId: 'demo_proxy' }], applications: [], events: [],
  settings: { language: 'zh-CN', closeBrowsersOnExit: true },
  engines: [{ id: 'cloakbrowser', displayName: 'CloakBrowser', family: 'chromium', supported: true, installed: false, installing: false,
    enabled: false, capabilities: { supports_native_proxy: true, supports_seed_fingerprint: true } }],
  applicationRouting: { ready: false, installed: false, authorized: false, status: 'unavailable' },
  system: { platform: 'darwin', appVersion: 'demo', dataDir: '/workspace/envara-demo' },
};
export const screenshotTerminals = { profiles: [{ profileId: 'demo_environment', name: '演示环境 · 项目工作区',
  cwd: '/workspace/demo', browserProfileId: null, timezone: 'Asia/Shanghai', timezoneSource: 'manual', sessions: [] }] };

export async function captureReleaseScreenshot() {
  await fs.access(path.join(root, 'dist/client/index.html'));
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-release-screenshot-'));
  const output = path.join(root, 'docs/media/workspace-zh-CN.png');
  const capture = path.join(temporary, 'workspace.png');
  try {
    for (const name of ['home', 'tmp', 'user-data', 'session-data', 'logs']) await fs.mkdir(path.join(temporary, name), { mode: 0o700 });
    await fs.writeFile(path.join(temporary, 'preload.cjs'), `
const { contextBridge } = require('electron');
const snapshot = ${JSON.stringify(screenshotSnapshot)};
const terminals = ${JSON.stringify(screenshotTerminals)};
const unused = () => () => {};
contextBridge.exposeInMainWorld('envara', Object.freeze({ isDesktop: true,
  call: async method => { if (method === 'snapshot') return snapshot; if (method === 'terminalSnapshot') return terminals; throw new Error('Synthetic screenshot bridge refuses side effects.'); },
  subscribe: unused, onTerminalEvent: unused, onLinkEvent: unused,
}));
`, { mode: 0o600 });
    await fs.writeFile(path.join(temporary, 'main.cjs'), `
const { app, BrowserWindow, session } = require('electron');
const fs = require('node:fs'); const path = require('node:path');
const { fileURLToPath } = require('node:url');
app.setName('Envara Screenshot Fixture');
for (const [key, directory] of [['userData', 'user-data'], ['sessionData', 'session-data'], ['logs', 'logs']]) app.setPath(key, path.join(__dirname, directory));
app.commandLine.appendSwitch('disable-background-networking');
app.whenReady().then(async () => {
  app.dock?.hide();
  const assets = path.join(process.env.ENVARA_SCREENSHOT_ROOT, 'dist/client');
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    let allowed = details.url.startsWith('data:');
    if (details.url.startsWith('file:')) { const relative = path.relative(assets, fileURLToPath(details.url)); allowed = !relative.startsWith('..') && !path.isAbsolute(relative); }
    callback({ cancel: !allowed });
  });
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  const window = new BrowserWindow({ width: 1500, height: 940, show: false, backgroundColor: '#1d1d21',
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, sandbox: true, nodeIntegration: false, spellcheck: false, backgroundThrottling: false } });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', event => event.preventDefault());
  try {
    await window.loadFile(path.join(process.env.ENVARA_SCREENSHOT_ROOT, 'dist/client/index.html'));
    const until = Date.now() + 15000;
    let ready = false;
    while (Date.now() < until) {
      ready = await window.webContents.executeJavaScript("Boolean(document.querySelector('.app-shell')) && document.body.innerText.includes('/workspace/demo') && document.body.innerText.includes('203.0.113.10')");
      if (ready) break;
      await new Promise(resolve => setTimeout(resolve, 80));
    }
    if (!ready) throw new Error('Synthetic renderer did not become ready.');
    const clean = await window.webContents.executeJavaScript("!['/Users/', '/private/var/', '/home/'].some(prefix => document.body.innerText.includes(prefix))");
    if (!clean) throw new Error('Screenshot contains a host-specific path.');
    await new Promise(resolve => setTimeout(resolve, 400));
    const image = await window.webContents.capturePage();
    if (image.isEmpty()) throw new Error('Screenshot is empty.');
    fs.writeFileSync(process.env.ENVARA_SCREENSHOT_OUTPUT, image.toPNG(), { mode: 0o600 });
    app.exit(0);
  } catch { app.exit(1); }
});
`, { mode: 0o600 });
    const electron = (await import('electron')).default;
    const env = { PATH: process.env.PATH || '/usr/bin:/bin', HOME: path.join(temporary, 'home'), TMPDIR: path.join(temporary, 'tmp') + '/',
      LANG: 'en_US.UTF-8', ENVARA_SCREENSHOT_ROOT: root, ENVARA_SCREENSHOT_OUTPUT: capture };
    await execute(electron, [path.join(temporary, 'main.cjs')], { cwd: temporary, env, timeout: 30000, maxBuffer: 256 * 1024 });
    const image = await fs.readFile(capture);
    await fs.mkdir(path.dirname(output), { recursive: true });
    await fs.writeFile(output, image);
    return { file: 'docs/media/workspace-zh-CN.png', sha256: createHash('sha256').update(image).digest('hex'),
      synthetic: true, directory: '/workspace/demo', exampleIP: '203.0.113.10', realServicesUsed: false };
  } finally { await fs.rm(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  captureReleaseScreenshot().then(result => console.log(JSON.stringify(result)), () => { console.error('Synthetic screenshot capture failed.'); process.exitCode = 1; });
}
