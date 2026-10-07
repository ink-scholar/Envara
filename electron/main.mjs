import { app, BrowserWindow, ipcMain, dialog, shell, Menu, nativeImage } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { EnvaraService } from './service.mjs';
import { BrowserRuntime } from './runtime.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isSmoke = process.env.ENVARA_SMOKE === '1' && !app.isPackaged;
if (isSmoke && process.env.ENVARA_SMOKE_DATA) app.setPath('userData', process.env.ENVARA_SMOKE_DATA);
app.setName('Envara');
const ownsLock = app.requestSingleInstanceLock();
if (!ownsLock) app.quit();
let window;
let service;
let quitting = false;
let publishing = false;
let needsPublish = false;

async function publish() {
  if (!service || window?.isDestroyed()) return;
  if (publishing) { needsPublish = true; return; }
  publishing = true;
  try {
    const snapshot = await service.snapshot();
    if (window && !window.isDestroyed()) window.webContents.send('envara:snapshot', snapshot);
  } catch (error) { console.error('Unable to refresh workspace:', error.message); }
  finally { publishing = false; if (needsPublish) { needsPublish = false; void publish(); } }
}
const allowedMethods = new Set(['snapshot','createProfile','updateProfile','cloneProfile','deleteProfile','clearProfile','startProfile','stopProfile','focusProfile','saveProxy','deleteProxy','checkProxy','saveSettings','installEngine','importProfiles','exportProfiles','openDataDirectory','openDocumentation']);

async function handleCall(method, args = {}) {
  if (!allowedMethods.has(method)) throw new Error('不支持的操作');
  if (method === 'openDocumentation') {
    const urls = { project: 'https://github.com/ink-scholar/Envara', 'runtime-license': 'https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md' };
    if (!Object.hasOwn(urls, args.target)) throw new Error('无效文档链接');
    await shell.openExternal(urls[args.target]);
    return { ok: true };
  }
  if (method === 'openDataDirectory') {
    const message = await shell.openPath(app.getPath('userData'));
    if (message) throw new Error(message);
    return { ok: true };
  }
  if (method === 'exportProfiles') {
    const data = await service.call(method, args);
    const choice = await dialog.showSaveDialog(window, { title: '导出环境配置', defaultPath: 'envara-profiles.json', filters: [{ name: 'Envara JSON', extensions: ['json'] }] });
    if (choice.canceled || !choice.filePath) return { canceled: true };
    await writeFile(choice.filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
    return { canceled: false, count: data.profiles.length };
  }
  if (method === 'importProfiles') {
    const choice = await dialog.showOpenDialog(window, { title: '导入环境配置', properties: ['openFile'], filters: [{ name: 'Envara JSON', extensions: ['json'] }] });
    if (choice.canceled || !choice.filePaths[0]) return { canceled: true };
    const text = await readFile(choice.filePaths[0], 'utf8');
    if (Buffer.byteLength(text) > 5 * 1024 * 1024) throw new Error('配置文件不能超过 5 MB');
    let data;
    try { data = JSON.parse(text); } catch { throw new Error('文件不是有效的 JSON 配置'); }
    if (data.schema !== 'envara.profiles' || data.version !== 1 || !Array.isArray(data.profiles)) throw new Error('请选择 Envara 导出的环境配置文件');
    return service.call(method, { profiles: data.profiles });
  }
  return service.call(method, args);
}

async function createWindow() {
  window = new BrowserWindow({ width: 1500, height: 940, minWidth: 1120, minHeight: 720, title: 'Envara · 境舱', backgroundColor: '#1e1e1e', titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 18, y: 17 }, icon: path.join(root, 'build/icon.png'), webPreferences: { preload: path.join(root, 'electron/preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, devTools: !app.isPackaged } });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => {
    const devUrl = process.env.ENVARA_DEV_URL;
    if (!devUrl || !url.startsWith(`${devUrl}/`)) event.preventDefault();
  });
  window.webContents.session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  window.webContents.session.webRequest.onHeadersReceived((details, callback) => {
    const dev = !!process.env.ENVARA_DEV_URL && !app.isPackaged;
    const csp = `default-src 'self'; script-src 'self'${dev ? " 'unsafe-inline'" : ''}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'${dev ? ' ws://127.0.0.1:5173 http://127.0.0.1:5173' : ''}; object-src 'none'; base-uri 'self'`;
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [csp] } });
  });
  if (process.env.ENVARA_DEV_URL && !app.isPackaged) await window.loadURL(process.env.ENVARA_DEV_URL);
  else await window.loadFile(path.join(root, 'dist/client/index.html'));
  if (isSmoke) {
    const { runSmoke } = await import('./smoke.mjs');
    await runSmoke({ app, window, service, runtime: service.runtime });
  }
}

app.on('second-instance', () => { if (window) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); } });
app.on('window-all-closed', () => app.quit());
app.on('activate', () => { if (!quitting && BrowserWindow.getAllWindows().length === 0) void createWindow(); });
app.on('before-quit', event => {
  if (quitting || !service) return;
  event.preventDefault();
  quitting = true;
  void service.shutdown().finally(() => app.quit());
});
// Electron waits for the entry module to settle before emitting ready.
// Waiting for ready with top-level await would deadlock app startup.
if (ownsLock) void app.whenReady().then(async () => {
  const dataDir = app.getPath('userData');
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const runtime = new BrowserRuntime({ cacheDir: isSmoke && process.env.ENVARA_SMOKE_ENGINE_DIR ? process.env.ENVARA_SMOKE_ENGINE_DIR : path.join(dataDir, 'engines'), onChange: publish });
  service = new EnvaraService(dataDir, runtime, { platform: process.platform, appVersion: app.getVersion() }, publish);
  ipcMain.handle('envara:call', async (event, request) => {
    try {
      if (event.sender !== window?.webContents || event.senderFrame !== window.webContents.mainFrame) throw new Error('不允许的请求来源');
      if (!request || typeof request.method !== 'string') throw new Error('无效请求');
      const value = await handleCall(request.method, request.args);
      return { ok: true, value };
    } catch (error) { return { ok: false, error: { message: error.message, code: error.code || 'ACTION_FAILED' } }; }
  });
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'Envara', submenu: [{ label: '关于境舱', role: 'about' }, { type: 'separator' }, { label: '退出境舱', role: 'quit' }] },
    { label: '编辑', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: '窗口', submenu: [{ role: 'minimize' }, { role: 'zoom' }, { role: 'front' }] },
  ]));
  if (process.platform === 'darwin') app.dock?.setIcon(nativeImage.createFromPath(path.join(root, 'build/icon.png')));
  await createWindow();
  const refreshTimer = setInterval(() => { void publish(); }, 4000);
  refreshTimer.unref();
}).catch(error => {
  console.error(error);
  if (isSmoke) process.exitCode = 1;
  dialog.showErrorBox('境舱无法启动', error.message);
  app.quit();
});
