import { app, BrowserWindow, ipcMain, dialog, shell, Menu, nativeImage } from 'electron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile, mkdir, readdir, lstat, rm } from 'node:fs/promises';
import { pfAttachEnvironmentId } from '../native/macos-pf-routing/policy.mjs';
import { EnvaraService } from './service.mjs';
import { BrowserRuntime } from './runtime.mjs';
import { SidecarManager } from './sidecar-manager.mjs';
import { BrowseForgeService } from './browseforge-service.mjs';
import { TerminalService } from './terminal-service.mjs';
import { TerminalController, TERMINAL_METHODS } from './terminal-controller.mjs';
import { resolveTerminalView, terminalViewSnapshot } from './terminal-view.mjs';
import { ProxyCoreManager } from './proxy-core-manager.mjs';
import { ApplicationService, inspectLocalApplication } from './application-service.mjs';
import { LocalApplicationCatalog } from './local-application-catalog.mjs';
import { createApplicationIcons, electronApplicationIcon } from './application-icons.mjs';
import { NativeApplicationRouting } from './application-routing.mjs';
import { MacOSApplicationRouting } from './macos-application-routing.mjs';
import { MacOSPFApplicationRouting } from './macos-pf-application-routing.mjs';
import { exportPFNotionTrialDiagnostics, PF_NOTION_TRIAL_CARRIER } from './macos-pf-notion-trial.mjs';
import { NotionDiagnosticsStore } from './notion-diagnostics-store.mjs';
import { verifyPFInstallation } from '../native/macos-pf-routing/controller.mjs';
import { applicationWorkspaceContext } from './workspace-context.mjs';
import { ProxyNetworkProbe } from './proxy-network.mjs';
import { parseGoogleMapsLocation } from '../shared/network-location.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isSmoke = process.env.ENVARA_SMOKE === '1' && !app.isPackaged;
const isWorkspaceSmoke = process.env.ENVARA_WORKSPACE_SMOKE === '1' && !app.isPackaged;
if (isSmoke && process.env.ENVARA_SMOKE_DATA) app.setPath('userData', process.env.ENVARA_SMOKE_DATA);
if (isWorkspaceSmoke && process.env.ENVARA_WORKSPACE_SMOKE_DATA) {
  if (!path.isAbsolute(process.env.ENVARA_WORKSPACE_SMOKE_DATA)) throw new Error('Workspace smoke data must be absolute');
  app.setPath('userData', process.env.ENVARA_WORKSPACE_SMOKE_DATA);
}
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
let proxyCore;
let applications;
let notionTrialAvailability = null;
let notionTrialAvailabilityAt = 0;
let notionTrialAvailabilityPending = null;
let notionTrialReserved = false;
let notionDiagnostics;
const localApplications = new LocalApplicationCatalog();
const pickedApplicationPaths = new Set();
const applicationIcon = createApplicationIcons({ render: electronApplicationIcon({ app, nativeImage }),
  isKnown: async target => localApplications.knows(target) || pickedApplicationPaths.has(target) ||
    !!applications && (await applications.snapshot()).applications.some(item => item.path === target) });
const views = new Map();
const terminalWindows = new Map();
let quitting = false;
let publishing = false;
let needsPublish = false;
const pendingImports = new Map();

function workspaceSnapshot(value) {
  if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system) return value;
  const core = proxyCore?.snapshot();
  return { ...value, system: { ...value.system,
    proxyCore: { supported: core?.available === true, version: core?.version ?? null, protocols: core?.protocols ?? [],
      errorCode: core?.error ?? null, message: core?.available ? '内置 AnyTLS 内核已就绪。' : '内置 AnyTLS 内核不可用，请使用完整安装包。' },
    terminal: { supported: !!terminal, isolation: 'configuration', networkScope: 'proxy-aware-cli' } } };
}

async function fullWorkspaceSnapshot(value) {
  if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system) return value;
  const applicationState = applications ? await applications.snapshot() : { applications: [], applicationRouting: { ready: false, installed: false, authorized: false, status: 'unavailable', message: '应用网络组件尚未安装。' } };
  if (typeof applications?.routing?.controlledNotionTrialAvailability === 'function') {
    const availability = await getNotionTrialAvailability();
    applicationState.applicationRouting = { ...applicationState.applicationRouting,
      controlledNotionTrialAvailable: availability.controlledNotionTrialAvailable === true,
      controlledNotionTrialErrorCode: availability.errorCode ?? null,
      ...(!applicationState.applicationRouting.ready ? {
        message: '应用网络组件尚未通过完整验证，软件暂不能启动。',
        status: 'incomplete',
      } : {}) };
    /* Trials are per saved binding, whichever software was added. The fixed
     * native carrier still decides whether a given bundle may launch. */
    applicationState.applications = await Promise.all(applicationState.applications.map(async item =>
      typeof item?.identity === 'string' && item.identity
        ? { ...item, notionTrial: applications.routing.controlledNotionTrialSnapshot({ applicationId: item.id }),
          notionTrialHistory: await notionDiagnostics?.read(item.id).catch(() => null) ?? null } : item));
  }
  return workspaceSnapshot({ ...value, ...applicationState });
}

async function getNotionTrialAvailability({ force = false } = {}) {
  if (!force && notionTrialAvailability && Date.now() - notionTrialAvailabilityAt < 30000) return notionTrialAvailability;
  if (notionTrialAvailabilityPending) return notionTrialAvailabilityPending;
  notionTrialAvailabilityPending = applications.routing.controlledNotionTrialAvailability().then(value => {
    notionTrialAvailability = value; notionTrialAvailabilityAt = Date.now(); return value;
  }).finally(() => { notionTrialAvailabilityPending = null; });
  return notionTrialAvailabilityPending;
}

/* Any locally added application may be attached. The fixed native carrier and
 * sealed registry decide whether a given bundle can actually launch; this
 * lookup only resolves the saved binding the renderer referenced. */
function findAttachmentApplication(args) {
  if (!args || Object.keys(args).length !== 1 || typeof args.id !== 'string' || !applications ||
      typeof applications.routing?.controlledNotionTrial !== 'function') throw Object.assign(new Error('当前桌面版本不支持软件附加。'), { code: 'PF_NOTION_TRIAL_NOT_ENABLED' });
  const application = applications.find(args.id);
  if (!application || typeof application.path !== 'string' || !application.path.endsWith('.app') ||
      typeof application.identity !== 'string' || !application.identity) throw Object.assign(new Error('请先添加要附加的本地软件。'), { code: 'PF_NOTION_TRIAL_REQUEST_INVALID' });
  return application;
}

function assertNotionTrialContextIdle({ allowReservation = false } = {}) {
  const state = applications?.routing?.controlledNotionTrialSnapshot?.() ?? null;
  if ((!allowReservation && notionTrialReserved) || state?.active === true || state?.cleanupUncertain === true) throw Object.assign(new Error('请先停止附加软件并确认清理，再修改环境。'), { code: 'PF_OWNED_RUNTIME_NOT_EMPTY' });
}

async function shutdownOwnedServices() {
  // Preserve the managed route if native cleanup remains uncertain.
  try { await applications?.shutdown(); }
  finally { await notionDiagnostics?.pending.catch(() => {}); }
  await terminal?.shutdown().catch(() => {});
  try {
    if (service) await service.shutdown();
    else await sidecar?.shutdown();
  } finally { await proxyCore?.close(); }
}

async function publish() {
  if (!service || !views.size) return;
  if (publishing) { needsPublish = true; return; }
  publishing = true;
  try {
    const snapshot = await fullWorkspaceSnapshot(await service.snapshot());
    for (const { window: view, kind } of views.values()) if (!view.isDestroyed()) view.webContents.send('envara:snapshot', kind === 'terminal' ? terminalViewSnapshot(snapshot) : snapshot);
  } catch (error) { console.error('Unable to refresh workspace:', error.message); }
  finally { publishing = false; if (needsPublish) { needsPublish = false; void publish(); } }
}
const allowedMethods = new Set(['snapshot','createProfile','updateProfile','cloneProfile','deleteProfile','clearProfile','startProfile','stopProfile','focusProfile','saveProxy','deleteProxy','checkProxy','saveSettings','installEngine','importProfiles','cancelImport','exportProfiles','openDataDirectory','openDocumentation','previewLegacyMigration','migrateLegacy','saveGroup','deleteGroup','clearGroupProxy','bulkProfiles','exportAutomationConfig','openTerminalWindow', ...TERMINAL_METHODS]);
const applicationMethods = new Set(['saveApplication', 'startApplication', 'stopApplication', 'deleteApplication', 'getApplicationRoutingStatus', 'setupApplicationRouting']);
for (const method of [...applicationMethods, 'pickApplication', 'listLocalApplications', 'applicationIcon', 'previewProxyNetwork', 'checkEnvironmentNetwork', 'openNetworkLocationMap']) allowedMethods.add(method);
for (const method of ['runNotionTrial', 'stopNotionTrial', 'notionTrialSnapshot', 'exportNotionDiagnostics', 'applicationStorage', 'reclaimApplicationStorage']) allowedMethods.add(method);

async function protectApplicationMutation(method, args, operation) {
  if (!applications) return operation();
  const profileMutation = ['updateProfile', 'deleteProfile', 'chooseWorkspaceDirectory'].includes(method);
  const proxyMutation = ['saveProxy', 'deleteProxy'].includes(method);
  const groupMutation = ['saveGroup', 'deleteGroup', 'clearGroupProxy'].includes(method);
  const bulkMutation = method === 'bulkProfiles' && ['move', 'delete'].includes(args.action);
  if (!profileMutation && !proxyMutation && !groupMutation && !bulkMutation) return operation();
  return applications.serialized(async () => {
    assertNotionTrialContextIdle();
    if (profileMutation) applications.assertProfileIdle(args.id);
    if (proxyMutation) applications.assertProxyIdle(method === 'saveProxy' ? args.proxy?.id : args.id);
    if (groupMutation || bulkMutation) {
      const snapshot = await service.snapshot();
      for (const profile of snapshot.profiles) if (groupMutation ? profile.group === args.name : args.ids?.includes(profile.id)) applications.assertProfileIdle(profile.id);
    }
    return operation();
  });
}

/* What attached applications keep on disk. Main alone decides what is still in
 * use: a copy whose original belongs to a currently attached application, and
 * data belonging to an environment that still exists. The renderer can only
 * confirm items from this list for removal, never name any other storage. */
async function applicationStorageCandidates() {
  if (typeof applications?.routing?.applicationStorage !== 'function')
    throw Object.assign(new Error('此平台没有附加软件存储。'), { code: 'APPLICATION_ROUTING_UNAVAILABLE' });
  const [inventory, attached, workspace] = await Promise.all([applications.routing.applicationStorage(), applications.snapshot(), service.snapshot()]);
  const attachedBundles = new Set(attached.applications.map(item => item.path).filter(value => typeof value === 'string'));
  const environments = new Map(workspace.profiles.map(profile => [pfAttachEnvironmentId(profile.id), profile.name]));
  return { attachedApplicationActive: inventory.attachedApplicationActive === true,
    registrations: inventory.registrations.map(item => ({ id: item.registrationId, bundle: item.bundle, versions: item.versions, bytes: item.bytes,
      name: path.basename(item.bundle || '', '.app') || item.identifier || null, inUse: attachedBundles.has(item.bundle) })),
    environments: inventory.environments.map(item => ({ id: item.environmentId, bytes: item.bytes,
      environment: environments.get(item.environmentId) ?? null, inUse: environments.has(item.environmentId) })) };
}
/* A deleted environment's attached-application data is emptied at once: the
 * data directory is owned by the console user and its root-owned ancestors
 * cannot be swapped for a link, so no administrator step is needed. What
 * remains is the empty root-owned skeleton, removed by the storage cleanup.
 * Removal never follows a link. */
async function eraseAttachedApplicationData(profileId) {
  if (process.platform !== 'darwin' || typeof profileId !== 'string' || !profileId) return;
  const root = path.join('/Library/PrivilegedHelperTools/io.envara.pf-app-data', pfAttachEnvironmentId(profileId));
  let registrations; try { registrations = await readdir(root); } catch { return; }
  for (const registration of registrations) {
    const leaf = path.join(root, registration, 'UserData');
    let info; try { info = await lstat(leaf); } catch { continue; }
    if (!info.isDirectory() || info.uid !== process.getuid()) continue;
    for (const entry of await readdir(leaf).catch(() => []))
      await rm(path.join(leaf, entry), { recursive: true, force: true }).catch(() => {});
  }
}

async function handleCall(method, args = {}, caller = window) {
  if (quitting) throw Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' });
  if (!allowedMethods.has(method)) throw new Error('不支持的操作');
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('操作参数无效。');
  if (method === 'applicationStorage') return applicationStorageCandidates();
  if (method === 'reclaimApplicationStorage') {
    const confirmed = new Set(Array.isArray(args.ids) ? args.ids.filter(id => typeof id === 'string') : []);
    const current = await applicationStorageCandidates();
    const registrationIds = current.registrations.filter(item => !item.inUse && confirmed.has(item.id)).map(item => item.id);
    const environmentIds = current.environments.filter(item => !item.inUse && confirmed.has(item.id)).map(item => item.id);
    if (!registrationIds.length && !environmentIds.length) return { registrations: [], environments: [] };
    return applications.routing.reclaimApplicationStorage({ registrationIds, environmentIds });
  }
  if (['runNotionTrial', 'stopNotionTrial', 'notionTrialSnapshot', 'exportNotionDiagnostics'].includes(method)) {
    const application = findAttachmentApplication(args);
    if (method === 'notionTrialSnapshot') return { applicationId: application.id,
      notionTrial: applications.routing.controlledNotionTrialSnapshot({ applicationId: application.id }) };
    if (method === 'exportNotionDiagnostics') {
      const current = applications.routing.controlledNotionTrialSnapshot({ applicationId: application.id });
      const report = exportPFNotionTrialDiagnostics(current) ?? await notionDiagnostics?.read(application.id);
      if (!report) throw Object.assign(new Error('尚无可导出的附加软件诊断。'), { code: 'PF_NOTION_DIAGNOSTICS_UNAVAILABLE' });
      const choice = await dialog.showSaveDialog(caller, { title: '导出附加软件诊断',
        defaultPath: `Envara-Notion-${report.runId}.json`, filters: [{ name: 'JSON', extensions: ['json'] }] });
      if (choice.canceled || !choice.filePath) return { canceled: true };
      await writeFile(choice.filePath, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
      return { exported: true };
    }
    // Stop must not wait behind the long-lived trial reservation.
    if (method === 'stopNotionTrial') return applications.routing.stopControlledNotionTrial({ applicationId: application.id });
    assertNotionTrialContextIdle();
    notionTrialReserved = true;
    return applications.serialized(async () => {
      const application = findAttachmentApplication(args);
      assertNotionTrialContextIdle({ allowReservation: true });
      await applications.checkProfile(application.profileId);
      applications.assertProfileIdle(application.profileId);
      const available = await getNotionTrialAvailability({ force: true });
      if (available.controlledNotionTrialAvailable !== true) throw Object.assign(new Error('附加软件组件尚未就绪。'), { code: available.errorCode ?? 'PF_NOTION_TRIAL_NOT_ENABLED' });
      // A renderer provides only the saved binding id. Network credentials and
      // activation intent are constructed by this main-process action.
      let context;
      try { context = await applicationWorkspaceContext(application.profileId, { service, terminal }); }
      catch (error) {
        if (error.code !== 'APPLICATION_DIRECTORY_REQUIRED') throw error;
        await terminalController.dispatch('chooseWorkspaceDirectory', { id: application.profileId }, { window: caller });
        context = await applicationWorkspaceContext(application.profileId, { service, terminal });
      }
      return applications.routing.controlledNotionTrial({ application: { ...application, args: [...application.args] }, context, activationAuthorized: true });
    }).finally(() => {
      notionTrialReserved = false;
      if (!views.size) void quitWhenIdle().catch(() => {});
    });
  }
  if (method === 'listLocalApplications') return localApplications.list(args);
  if (method === 'applicationIcon') return applicationIcon(args);
  if (method === 'openNetworkLocationMap') {
    const location = parseGoogleMapsLocation(args.url);
    if (!location) throw new Error('请先选择网络位置。');
    await shell.openExternal(location.mapsUrl);
    return { ok: true };
  }
  if (method === 'previewProxyNetwork') {
    if (typeof service?.previewProxyNetwork !== 'function') throw new Error('当前后端不支持网络位置预览。');
    return service.previewProxyNetwork(args);
  }
  if (applicationMethods.has(method)) {
    if (!applications) throw new Error('附加软件需要完整桌面应用。');
    if (['saveApplication', 'deleteApplication', 'setupApplicationRouting'].includes(method)) assertNotionTrialContextIdle();
    if (method !== 'setupApplicationRouting') return applications[method](args);
    /* The upgrade button is driven by the cached trial availability. Without a
     * fresh read after installing, the stale "component outdated" answer kept
     * the button visible for up to 30 seconds and the update looked like it
     * needed a second click. Wait out any read already in flight, then force a
     * new one, whatever the installation's outcome. */
    try { return await applications[method](args); }
    finally {
      await notionTrialAvailabilityPending?.catch(() => {});
      await getNotionTrialAvailability({ force: true }).catch(() => {});
      void publish();
    }
  }
  if (method === 'pickApplication') {
    const choice = await dialog.showOpenDialog(caller, { title: '选择本地软件', properties: ['openFile'], filters: process.platform === 'win32' ? [{ name: 'Application', extensions: ['exe'] }] : process.platform === 'darwin' ? [{ name: 'Application', extensions: ['app'] }] : [{ name: 'Application', extensions: ['*'] }] });
    if (choice.canceled || !choice.filePaths[0]) return null;
    const selected = await inspectLocalApplication(choice.filePaths[0]);
    // A bundle the user chose in the system dialog may show its own icon too.
    if (pickedApplicationPaths.size >= 64) pickedApplicationPaths.delete(pickedApplicationPaths.values().next().value);
    pickedApplicationPaths.add(selected.path);
    return { path: selected.path, name: selected.name };
  }
  if (method === 'checkEnvironmentNetwork') {
    if (!service.resolveWorkspaceContext) throw new Error('当前后端不支持统一网络环境。');
    await service.resolveWorkspaceContext(args.id, { force: true });
    return service.snapshot();
  }
  if (TERMINAL_METHODS.has(method)) {
    if (!terminalController) throw new Error('当前运行路径尚未启用终端。');
    return protectApplicationMutation(method, args, () => terminalController.dispatch(method, args, { window: caller }));
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
  const result = await protectApplicationMutation(method, args, () => terminalController ? terminalController.protectMutation(method, args, () => service.call(method, args)) : service.call(method, args));
  if (applications && method === 'deleteProfile') {
    for (const item of (await applications.snapshot()).applications.filter(item => item.profileId === args.id)) await applications.deleteApplication({ id: item.id });
    await eraseAttachedApplicationData(args.id);
  }
  if (applications && method === 'bulkProfiles' && args.action === 'delete') {
    const deleted = new Set((result?.actionResult?.results ?? result?.results ?? []).filter(item => item.ok).map(item => item.id));
    for (const item of (await applications.snapshot()).applications.filter(item => deleted.has(item.profileId))) await applications.deleteApplication({ id: item.id });
    for (const id of deleted) await eraseAttachedApplicationData(id);
  }
  return result;
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
  if (isWorkspaceSmoke) {
    const { runWorkspaceSmoke } = await import('./workspace-smoke.mjs');
    await runWorkspaceSmoke({ app, window, service, terminal, applications, shutdown: shutdownOwnedServices });
  }
}

app.on('second-instance', () => {
  if (window && !window.isDestroyed()) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); }
  else if (!quitting) void createWindow();
});
async function quitWhenIdle() {
  if (quitting || views.size) return;
  const trial = applications?.routing?.controlledNotionTrialSnapshot?.();
  if (notionTrialReserved || trial?.active === true || trial?.cleanupUncertain === true) return;
  const snapshot = await terminal?.snapshot();
  if (snapshot?.profiles?.some(profile => profile.sessions?.some(session => ['starting', 'running', 'closing'].includes(session.status)))) return;
  if ((await applications?.snapshot())?.applications?.some(item => ['starting', 'running', 'stopping'].includes(item.status))) return;
  if (!views.size) app.quit();
}
app.on('window-all-closed', () => { void quitWhenIdle().catch(() => {}); });
app.on('activate', () => { if (!quitting && (!window || window.isDestroyed())) void createWindow(); });
app.on('before-quit', event => {
  if (quitting || (!service && !sidecar && !terminal && !proxyCore)) return;
  event.preventDefault();
  quitting = true;
  void shutdownOwnedServices().then(() => app.quit()).catch(() => {
    quitting = false;
    if (window && !window.isDestroyed()) { window.show(); window.focus(); }
    else void createWindow();
    dialog.showErrorBox('附加软件清理未确认', '网络会话仍保留。请先停止附加软件并完成清理，再退出境舱。');
  });
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
    proxyCore = new ProxyCoreManager({ dataDir, resourcesDir: app.isPackaged ? path.join(process.resourcesPath, 'proxy-core') : path.join(root, 'build/proxy-core'), onChange: event => {
      if (event?.id && event.status === 'failed') service?.invalidateManagedProxy?.(event.id);
      return publish();
    } });
    await proxyCore.initialize().catch(() => {});
    sidecar = new SidecarManager({ dataDir, resourcesDir: app.isPackaged ? path.join(process.resourcesPath, 'backend') : path.join(root, 'build/backend'), onChange: publish });
    await sidecar.initialize();
    service = new BrowseForgeService(dataDir, sidecar.client, { platform: process.platform, appVersion: app.getVersion(), backend: 'BrowseForge (Envara desktop)', upstreamVersion: '2.1.15', localApi: sidecar.baseUrl }, publish, {
      profilesDir: path.join(sidecar.baseDir, 'profiles'), getEngineStates: () => sidecar.getEngineStates(), proxyCore,
      ...(isWorkspaceSmoke ? { networkProbe: new ProxyNetworkProbe({ transport: async () => ({ success: true, ip: '8.8.8.8', country: 'Philippines', country_code: 'PH', city: 'Manila', latitude: 14.6, longitude: 121, timezone: { id: 'Asia/Manila' } }) }) } : {}),
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
      if (isWorkspaceSmoke) {
        const ownedCwd = process.env.ENVARA_WORKSPACE_SMOKE_CWD;
        if (!ownedCwd || !path.isAbsolute(ownedCwd)) throw new Error('Workspace smoke directory must be absolute');
        return { canceled: false, path: ownedCwd };
      }
      const parent = context?.window ?? window;
      if (!parent || parent.isDestroyed()) throw new Error('终端窗口已关闭。');
      parent.show(); parent.focus();
      const choice = await dialog.showOpenDialog(parent, { title: '选择此境舱的工作目录', properties: ['openDirectory'], ...(currentPath ? { defaultPath: currentPath } : {}) });
      return { canceled: choice.canceled, path: choice.filePaths[0] };
    } });
    const routingRoot = path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), 'app-routing');
    notionDiagnostics = new NotionDiagnosticsStore(path.join(dataDir, 'notion-trial-diagnostics'));
    const helperPath = process.platform === 'darwin'
      ? path.join(routingRoot, 'macos/EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper')
      : process.platform === 'win32' ? path.join(routingRoot, 'win32', process.arch, 'EnvaraAppRouting.exe') : null;
    let pfHelperPath = path.join(routingRoot, 'macos-pf/EnvaraPFHelper');
    if (process.platform === 'darwin') {
      const installedPFHelper = '/Library/PrivilegedHelperTools/io.envara.pf-routing/EnvaraPFHelper';
      const installedPF = await verifyPFInstallation();
      if (installedPF.verified === true && installedPF.manifestVerified === true) pfHelperPath = installedPFHelper;
    }
    const applicationRouting = process.platform === 'darwin'
      ? process.env.ENVARA_MAC_ROUTING_BACKEND === 'app-proxy'
        ? new MacOSApplicationRouting({
        helperPath,
        peerVerifierPath: path.join(routingRoot, 'macos-local/EnvaraPeerVerifier'),
        bundledAppPath: path.join(routingRoot, 'macos-local/Resources/Mitmproxy Redirector.app'),
      }) : new MacOSPFApplicationRouting({ helperPath: pfHelperPath, installerPath: path.join(routingRoot, 'macos-pf/EnvaraPFInstall'),
        notionAuthorizerPath: path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), PF_NOTION_TRIAL_CARRIER),
        onNotionTrialEvent: event => { console.info('Envara Notion trial', JSON.stringify(event)); void publish(); },
        onNotionTrialDiagnostics: report => notionDiagnostics.save(report),
      })
      : new NativeApplicationRouting({ helperPath });
    applications = new ApplicationService({ dataDir, routing: applicationRouting,
      resolveContext: id => applicationWorkspaceContext(id, { service, terminal }),
      profileExists: async id => (await service.snapshot()).profiles.some(profile => profile.id === id), onEvent: publish });
    await applications.ready;
    await applications.getApplicationRoutingStatus();
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
      const value = await fullWorkspaceSnapshot(await handleCall(request.method, request.args, source.window));
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
