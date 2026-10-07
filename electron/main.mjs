import { app, BrowserWindow, ipcMain, dialog, shell, Menu, nativeImage } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { EnvaraService } from './service.mjs';
import { BrowserRuntime } from './runtime.mjs';
import { SidecarManager } from './sidecar-manager.mjs';
import { BrowseForgeService } from './browseforge-service.mjs';
import { TerminalService } from './terminal-service.mjs';
import { TerminalController, TERMINAL_METHODS } from './terminal-controller.mjs';
import { resolveTerminalView, terminalViewSnapshot } from './terminal-view.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isSmoke = process.env.ENVARA_SMOKE === '1' && !app.isPackaged;
if (isSmoke && process.env.ENVARA_SMOKE_DATA) app.setPath('userData', process.env.ENVARA_SMOKE_DATA);
// Development acceptance runs use an owned directory without touching real workspaces.
if (!isSmoke && !app.isPackaged && process.env.ENVARA_DEV_DATA) {
  if (!path.isAbsolute(process.env.ENVARA_DEV_DATA)) throw new Error('ENVARA_DEV_DATA must be an absolute path');
  app.setPath('userData', path.resolve(process.env.ENVARA_DEV_DATA));
}
app.setName('Envara');
const ownsLock = app.requestSingleInstanceLock();
if (!ownsLock) app.quit();
let window;
let service;
let sidecar;
let terminal;
let terminalController;
const views = new Map();
const terminalWindows = new Map();
let quitting = false;
let publishing = false;
let needsPublish = false;
const pendingImports = new Map();

function workspaceSnapshot(value) {
  if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system) return value;
  return { ...value, system: { ...value.system, terminal: { supported: !!terminal, isolation: 'configuration', networkScope: 'proxy-aware-cli' } } };
}

async function shutdownOwnedServices() {
  await terminal?.shutdown().catch(() => {});
  if (service) await service.shutdown();
  else await sidecar?.shutdown();
}

async function publish() {
  if (!service || !views.size) return;
  if (publishing) { needsPublish = true; return; }
  publishing = true;
  try {
    const snapshot = workspaceSnapshot(await service.snapshot());
    for (const { window: view, kind } of views.values()) if (!view.isDestroyed()) view.webContents.send('envara:snapshot', kind === 'terminal' ? terminalViewSnapshot(snapshot) : snapshot);
  } catch (error) { console.error('Unable to refresh workspace:', error.message); }
  finally { publishing = false; if (needsPublish) { needsPublish = false; void publish(); } }
}
const allowedMethods = new Set(['snapshot','createProfile','updateProfile','cloneProfile','deleteProfile','clearProfile','startProfile','stopProfile','focusProfile','saveProxy','deleteProxy','checkProxy','saveSettings','installEngine','importProfiles','cancelImport','exportProfiles','openDataDirectory','openDocumentation','previewLegacyMigration','migrateLegacy','saveGroup','deleteGroup','clearGroupProxy','bulkProfiles','exportAutomationConfig','openTerminalWindow', ...TERMINAL_METHODS]);

async function handleCall(method, args = {}, caller = window) {
  if (quitting) throw Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' });
  if (!allowedMethods.has(method)) throw new Error('不支持的操作');
  if (TERMINAL_METHODS.has(method)) {
    if (!terminalController) throw new Error('当前运行路径尚未启用终端。');
    return terminalController.dispatch(method, args, { window: caller });
  }
  if (method === 'openTerminalWindow') {
    if (!terminalController) throw new Error('当前运行路径尚未启用终端。');
    return terminalController.serialize(() => openTerminalWindow(args));
  }
  if (method === 'openDocumentation') {
    const urls = { project: 'https://github.com/ink-scholar/Envara', 'runtime-license': 'https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md', automation: 'https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/docs/developer-integration.md', upstream: 'https://github.com/nczz/BrowseForge' };
    if (!Object.hasOwn(urls, args.target)) throw new Error('无效文档链接');
    await shell.openExternal(urls[args.target]);
    return { ok: true };
  }
  if (method === 'openDataDirectory') {
    const message = await shell.openPath(app.getPath('userData'));
    if (message) throw new Error(message);
    return { ok: true };
  }
  if (method === 'exportAutomationConfig') {
    if (!sidecar) throw new Error('多内核后端尚未就绪');
    const choice = await dialog.showSaveDialog(window, { title: '导出本机 MCP 连接配置', defaultPath: 'envara-mcp.json', filters: [{ name: 'MCP JSON', extensions: ['json'] }] });
    if (choice.canceled || !choice.filePath) return { canceled: true };
    await writeFile(choice.filePath, JSON.stringify(sidecar.connectionConfig(), null, 2), { mode: 0o600 });
    return { canceled: false };
  }
  if (method === 'exportProfiles') {
    const data = await service.call(method, args);
    const choice = await dialog.showSaveDialog(window, { title: '导出环境配置', defaultPath: 'envara-profiles.json', filters: [{ name: 'Envara JSON', extensions: ['json'] }] });
    if (choice.canceled || !choice.filePath) return { canceled: true };
    await writeFile(choice.filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
    return { canceled: false, count: data.profiles.length };
  }
  if (method === 'cancelImport') { pendingImports.delete(args.importId); return { canceled: true }; }
  if (method === 'importProfiles') {
    for (const [id, item] of pendingImports) if (Date.now() - item.createdAt > 15 * 60 * 1000) pendingImports.delete(id);
    if (args.importId) {
      const pending = pendingImports.get(args.importId);
      if (!pending) throw new Error('待导入配置已过期，请重新选择文件');
      const result = await service.call(method, { document: pending.document, proxyMap: args.proxyMap ?? {} });
      pendingImports.delete(args.importId);
      return result;
    }
    const choice = await dialog.showOpenDialog(window, { title: '导入环境配置', properties: ['openFile'], filters: [{ name: 'Envara JSON', extensions: ['json'] }] });
    if (choice.canceled || !choice.filePaths[0]) return { canceled: true };
    const text = await readFile(choice.filePaths[0], 'utf8');
    if (Buffer.byteLength(text) > 5 * 1024 * 1024) throw new Error('配置文件不能超过 5 MB');
    let data;
    try { data = JSON.parse(text); } catch { throw new Error('文件不是有效的 JSON 配置'); }
    if (data.schema !== 'envara.profiles' || ![1, 2].includes(data.version) || !Array.isArray(data.profiles)) throw new Error('请选择 Envara 导出的环境配置文件');
    if (data.profiles.some(profile => !profile || typeof profile !== 'object' || Array.isArray(profile) || (profile.proxyId != null && typeof profile.proxyId !== 'string'))) throw new Error('环境配置格式无效');
    if (sidecar) {
      const refs = [...new Set(data.profiles.map(profile => profile?.proxyId).filter(Boolean))];
      if (refs.length) {
        const importId = randomUUID();
        if (pendingImports.size >= 3) pendingImports.delete(pendingImports.keys().next().value);
        pendingImports.set(importId, { document: data, createdAt: Date.now() });
        return { needsProxyMapping: true, importId, profileCount: data.profiles.length, proxyRefs: refs.map(id => {
          const proxy = Array.isArray(data.proxies) ? data.proxies.find(item => item.id === id) : null;
          return { id, name: typeof proxy?.name === 'string' ? proxy.name.slice(0, 100) : '原配置出口', protocol: typeof proxy?.protocol === 'string' ? proxy.protocol.slice(0, 16) : null, host: typeof proxy?.host === 'string' ? proxy.host.slice(0, 253) : null, port: Number.isInteger(proxy?.port) ? proxy.port : null, requiresCredentials: !!proxy?.requiresCredentials };
        }) };
      }
    }
    return service.call(method, sidecar ? { document: data, proxyMap: args.proxyMap ?? {} } : { profiles: data.profiles });
  }
  return terminalController ? terminalController.protectMutation(method, args, () => service.call(method, args)) : service.call(method, args);
}

function registerView(view, kind, profileId = null) {
  const contents = view.webContents;
  views.set(contents, { window: view, kind, profileId });
  view.on('closed', () => {
    views.delete(contents);
    for (const [key, item] of terminalWindows) if (item === view) terminalWindows.delete(key);
    if (window === view) window = null;
  });
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-navigate', (event, url) => {
    const devUrl = process.env.ENVARA_DEV_URL;
    if (!devUrl || !url.startsWith(`${devUrl}/`)) event.preventDefault();
  });
  contents.session.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  contents.session.webRequest.onHeadersReceived((details, callback) => {
    const dev = !!process.env.ENVARA_DEV_URL && !app.isPackaged;
    const csp = `default-src 'self'; script-src 'self'${dev ? " 'unsafe-inline'" : ''}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'${dev ? ' ws://127.0.0.1:5173 http://127.0.0.1:5173' : ''}; object-src 'none'; base-uri 'self'`;
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [csp] } });
  });
}

async function loadView(view, query = {}) {
  if (process.env.ENVARA_DEV_URL && !app.isPackaged) {
    const url = new URL(process.env.ENVARA_DEV_URL);
    for (const [key, value] of Object.entries(query)) if (value != null) url.searchParams.set(key, value);
    await view.loadURL(url.href);
  } else await view.loadFile(path.join(root, 'dist/client/index.html'), { query: Object.fromEntries(Object.entries(query).filter(([, value]) => value != null)) });
}

function viewOptions() {
  return { backgroundColor: '#1e1e1e', titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 18, y: 17 }, icon: path.join(root, 'build/icon.png'), webPreferences: { preload: path.join(root, 'electron/preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, devTools: !app.isPackaged } };
}

async function openTerminalWindow(args) {
  if (!terminal) throw new Error('当前运行路径尚未启用终端。');
  const target = resolveTerminalView(args, await service.snapshot(), await terminal.snapshot());
  const key = JSON.stringify([target.profileId, target.sessionId ?? '']);
  const previous = terminalWindows.get(key);
  if (previous && !previous.isDestroyed()) {
    // The window may have selected another tab since it was first opened.
    // Reload only its view request; the owned terminal process keeps running.
    await loadView(previous, { view: 'terminal', profileId: target.profileId, sessionId: target.sessionId });
    if (previous.isMinimized()) previous.restore();
    previous.show(); previous.focus();
    return { ok: true, windowId: previous.id, profileId: target.profileId, sessionId: target.sessionId, reused: true };
  }
  if (terminalWindows.size >= 8) throw Object.assign(new Error('最多打开 8 个独立终端窗口。'), { code: 'TERMINAL_WINDOW_LIMIT' });
  const view = new BrowserWindow({ ...viewOptions(), width: 1100, height: 760, minWidth: 640, minHeight: 480, title: `${target.name} · 终端 · Envara`, show: false });
  terminalWindows.set(key, view); registerView(view, 'terminal', target.profileId);
  try {
    await loadView(view, { view: 'terminal', profileId: target.profileId, sessionId: target.sessionId });
    if (quitting || view.isDestroyed()) throw new Error('应用正在退出。');
    view.show(); view.focus();
    return { ok: true, windowId: view.id, profileId: target.profileId, sessionId: target.sessionId };
  } catch (failure) { if (!view.isDestroyed()) view.close(); throw failure; }
}

async function createWindow() {
  window = new BrowserWindow({ ...viewOptions(), width: 1500, height: 940, minWidth: 1120, minHeight: 720, title: 'Envara · 境舱' });
  registerView(window, 'workspace');
  await loadView(window);
  if (isSmoke) {
    const { runSmoke } = await import('./smoke.mjs');
    await runSmoke({ app, window, service, runtime: service.runtime });
  }
}

app.on('second-instance', () => {
  if (window && !window.isDestroyed()) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); }
  else if (!quitting) void createWindow();
});
async function quitWhenIdle() {
  if (quitting || views.size) return;
  const snapshot = await terminal?.snapshot();
  if (snapshot?.profiles?.some(profile => profile.sessions?.some(session => ['starting', 'running', 'closing'].includes(session.status)))) return;
  if (!views.size) app.quit();
}
app.on('window-all-closed', () => { void quitWhenIdle().catch(() => app.quit()); });
app.on('activate', () => { if (!quitting && (!window || window.isDestroyed())) void createWindow(); });
app.on('before-quit', event => {
  if (quitting || (!service && !sidecar && !terminal)) return;
  event.preventDefault();
  quitting = true;
  void shutdownOwnedServices().finally(() => app.quit());
});
// Electron waits for the entry module to settle before emitting ready.
// Waiting for ready with top-level await would deadlock app startup.
if (ownsLock) void app.whenReady().then(async () => {
  const dataDir = app.getPath('userData');
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  if (isSmoke || process.env.ENVARA_BACKEND === 'legacy') {
    const runtime = new BrowserRuntime({ cacheDir: isSmoke && process.env.ENVARA_SMOKE_ENGINE_DIR ? process.env.ENVARA_SMOKE_ENGINE_DIR : path.join(dataDir, 'engines'), onChange: publish });
    service = new EnvaraService(dataDir, runtime, { platform: process.platform, appVersion: app.getVersion() }, publish);
  } else {
    sidecar = new SidecarManager({ dataDir, resourcesDir: app.isPackaged ? path.join(process.resourcesPath, 'backend') : path.join(root, 'build/backend'), onChange: publish });
    await sidecar.initialize();
    service = new BrowseForgeService(dataDir, sidecar.client, { platform: process.platform, appVersion: app.getVersion(), backend: 'BrowseForge (Envara desktop)', upstreamVersion: '2.1.15', localApi: sidecar.baseUrl }, publish, {
      profilesDir: path.join(sidecar.baseDir, 'profiles'), getEngineStates: () => sidecar.getEngineStates(),
      installEngine: id => sidecar.installEngine(id), getMetrics: profiles => sidecar.metrics(profiles),
      getConnectionInfo: () => ({ apiUrl: sidecar.baseUrl + '/api', mcpUrl: sidecar.baseUrl + '/mcp', status: sidecar.process ? 'ready' : 'stopped', version: '2.1.15', sourceCommit: 'fa9e0bb670e749706a9c8f2d4095333347d6c521' }),
      cancelInstall: () => sidecar.cancelInstall(),
      assertLegacyStopped: () => sidecar.assertLegacyStopped(), shutdown: () => sidecar.shutdown(),
    });
    terminal = new TerminalService({
      dataDir,
      additionalExecutablePaths: [path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), 'backend', 'playwright-driver')],
      resolveContext: id => service.resolveWorkspaceContext(id),
      onEvent: event => {
        for (const { window: view, kind, profileId } of views.values()) if (!view.isDestroyed() && (kind === 'workspace' || profileId === event.profileId)) view.webContents.send('envara:terminal-event', event);
        if (event.type === 'exit' && !views.size) void quitWhenIdle().catch(() => app.quit());
      },
    });
    terminalController = new TerminalController({ terminal, service, pickDirectory: async ({ currentPath }, context) => {
      const parent = context?.window ?? window;
      if (!parent || parent.isDestroyed()) throw new Error('终端窗口已关闭。');
      parent.show(); parent.focus();
      const choice = await dialog.showOpenDialog(parent, { title: '选择此境舱的工作目录', properties: ['openDirectory'], ...(currentPath ? { defaultPath: currentPath } : {}) });
      return { canceled: choice.canceled, path: choice.filePaths[0] };
    } });
  }
  ipcMain.handle('envara:call', async (event, request) => {
    try {
      const source = views.get(event.sender);
      if (!source || source.window.isDestroyed() || event.senderFrame !== event.sender.mainFrame) throw new Error('不允许的请求来源');
      if (!request || typeof request.method !== 'string') throw new Error('无效请求');
      if (source.kind === 'terminal' && !TERMINAL_METHODS.has(request.method) && !['snapshot', 'openTerminalWindow'].includes(request.method)) throw new Error('此窗口仅支持终端操作。');
      if (source.kind === 'terminal') {
        if (request.method === 'terminalSnapshot') request.args = { ...request.args, id: source.profileId };
        if (['chooseWorkspaceDirectory', 'openTerminal', 'openTerminalWindow'].includes(request.method) && request.args?.id !== source.profileId) throw new Error('此窗口仅操作当前环境。');
        if (['duplicateTerminal', 'writeTerminal', 'resizeTerminal', 'closeTerminal'].includes(request.method)) {
          const current = await terminal.snapshot({ id: source.profileId });
          if (!current.profiles?.some(profile => profile.sessions?.some(session => session.sessionId === request.args?.sessionId))) throw new Error('该会话不属于此终端窗口。');
        }
      }
      const value = workspaceSnapshot(await handleCall(request.method, request.args, source.window));
      return { ok: true, value: source.kind === 'terminal' ? terminalViewSnapshot(value) : value };
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
}).catch(async error => {
  await shutdownOwnedServices().catch(() => {});
  console.error(error);
  if (isSmoke) process.exitCode = 1;
  dialog.showErrorBox('境舱无法启动', error.message);
  app.quit();
});
