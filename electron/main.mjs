import { app, BrowserWindow, ipcMain, dialog, shell, Menu, nativeImage, nativeTheme } from 'electron';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile, mkdir, lstat, rm, cp, rename } from 'node:fs/promises';
import { promisify } from 'node:util';
import { pfAttachEnvironmentId, pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';
import { eraseAttachedApplicationData, eraseEnvironmentData, attachedApplicationDataInventory } from './application-data.mjs';
import { signInDataRows, SignInDataNames, runningSignInDataId, signInDataInUse } from './sign-in-data.mjs';
import { showManagedApplicationWindow } from './application-window.mjs';
import { TerminalLinkChannel, LinkSocketServer } from './terminal-link-channel.mjs';
import { LinkRouter } from './link-router.mjs';
import { LinkPreferences } from './link-preferences.mjs';
import { createLinkRoutingControls } from './link-routing-controls.mjs';
import { EnvaraService } from './service.mjs';
import { BrowserRuntime } from './runtime.mjs';
import { SidecarManager } from './sidecar-manager.mjs';
import { BrowseForgeService } from './browseforge-service.mjs';
import { TerminalService } from './terminal-service.mjs';
import { TerminalSshManager } from './terminal-ssh-manager.mjs';
import { TerminalBrowserBroker } from './terminal-browser-broker.mjs';
import { TerminalController, TERMINAL_METHODS } from './terminal-controller.mjs';
import { resolveTerminalView, terminalViewSnapshot } from './terminal-view.mjs';
import { ProxyCoreManager } from './proxy-core-manager.mjs';
import { ApplicationService, inspectLocalApplication } from './application-service.mjs';
import { LocalApplicationCatalog } from './local-application-catalog.mjs';
import { inspectApplicationCompatibility } from './application-compatibility.mjs';
import { createApplicationIcons, electronApplicationIcon } from './application-icons.mjs';
import { NativeApplicationRouting } from './application-routing.mjs';
import { MacOSApplicationRouting } from './macos-application-routing.mjs';
import { MacOSPFApplicationRouting } from './macos-pf-application-routing.mjs';
import { exportPFNotionTrialDiagnostics } from './macos-pf-notion-trial.mjs';
import { bundledPFRoutingPaths } from './macos-pf-resources.mjs';
import { NotionDiagnosticsStore } from './notion-diagnostics-store.mjs';
import { checkedExportPassword, isEnvironmentExport, readEnvironmentExport } from './environment-export.mjs';
import { applyPendingApplicationData, assertEnvironmentIdle, checkedExportManifest, exportEnvironment, restoreEnvironment } from './environment-transfer.mjs';
import { DesktopEnvironmentTransferLock, discardPendingEnvironmentImport, expirePendingEnvironmentImports, finishPendingEnvironmentImport, registerPendingEnvironmentImport,
  releaseDeletedEnvironmentImportProfile, withPendingEnvironmentImport } from './environment-import-lifecycle.mjs';
import { verifyPFInstallation } from '../native/macos-pf-routing/controller.mjs';
import { applicationWorkspaceContext } from './workspace-context.mjs';
import { ProxyNetworkProbe } from './proxy-network.mjs';
import { parseGoogleMapsLocation } from '../shared/network-location.mjs';
import { createWorkspaceWindowController, createOwnedQuitController } from './desktop-lifecycle.mjs';
import { createStartupDiagnostics } from './startup-diagnostics.mjs';
import { createDesktopStartup } from './desktop-startup.mjs';
import { registerDesktopIPC } from './desktop-ipc.mjs';
import { shutdownDesktopServices } from './desktop-services.mjs';
import { finishEnvironmentDeletion } from './environment-deletion-cleanup.mjs';
import { createAppearanceManager, readInitialAppearance } from './appearance.mjs';
import { appearanceBackground } from '../shared/appearance.mjs';

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
const startupDiagnostics = ownsLock ? createStartupDiagnostics({ directory: app.getPath('userData'), version: app.getVersion() }) : null;
startupDiagnostics?.mark('main-entry');
const startupStep = (name, operation) => startupDiagnostics ? startupDiagnostics.step(name, operation) : operation();
let firstWorkspaceSnapshot = false;
let window;
let service;
let sidecar;
let terminal;
let terminalBrowserBroker;
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
const appearance = createAppearanceManager({ nativeTheme, views, preference: readInitialAppearance(path.join(app.getPath('userData'),
  ...(isSmoke || process.env.ENVARA_BACKEND === 'legacy' ? [] : ['browseforge-manager']), 'workspace.json')) });
const terminalWindows = new Map();
let quitting = false;
let requestEpoch = 0;
let publishing = false;
let needsPublish = false;
const pendingImports = new Map();
const environmentTransferLock = new DesktopEnvironmentTransferLock();
const protectBrowserOperation = (profileId, operation) => environmentTransferLock.mutate('startProfile', { id: profileId }, operation, profileId);
// Decrypted staging belongs to its pending import until completion or disposal.
async function discardImport(importId, { completed = false } = {}) {
  await discardPendingEnvironmentImport({ imports: pendingImports, importId, completed,
    removeStaging: staging => rm(staging, { recursive: true, force: true }) });
}
function proxyMappingRequest(importId, data, scope = 'environment') {
  const refs = [...new Set(data.profiles.map(profile => profile?.proxyId).filter(Boolean))];
  if (!refs.length) return null;
  return { needsProxyMapping: true, importId, scope, profileCount: data.profiles.length, proxyRefs: refs.map(id => {
    const proxy = Array.isArray(data.proxies) ? data.proxies.find(item => item.id === id) : null;
    return { id, name: typeof proxy?.name === 'string' ? proxy.name.slice(0, 100) : '原配置出口', protocol: typeof proxy?.protocol === 'string' ? proxy.protocol.slice(0, 16) : null,
      host: typeof proxy?.host === 'string' ? proxy.host.slice(0, 253) : null };
  }) };
}

function workspaceSnapshot(value) {
  if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system) return value;
  const core = proxyCore?.snapshot();
  return { ...value, settings: { ...value.settings, appearance: appearance.snapshot().preference }, system: { ...value.system,
    accessibilitySupportEnabled: app.isAccessibilitySupportEnabled?.() === true,
    proxyCore: { supported: core?.available === true, version: core?.version ?? null, protocols: core?.protocols ?? [],
      errorCode: core?.error ?? null, message: core?.available ? '内置 AnyTLS 内核已就绪。' : '内置 AnyTLS 内核不可用，请使用完整安装包。' },
    terminal: { supported: !!terminal, isolation: 'configuration', networkScope: 'proxy-aware-cli' } } };
}

async function fullWorkspaceSnapshot(value) {
  if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system) return value;
  // The expensive profile snapshot may predate a settings save. Read only the
  // local store so a delayed network response cannot revert the chosen theme.
  if (service?.store) appearance.setPreference((await service.store.read()).settings.appearance);
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
    applicationState.applications = await Promise.all(applicationState.applications.map(async item =>
      typeof item?.identity === 'string' && item.identity
        ? { ...item, compatibility: await inspectApplicationCompatibility(item, { verifySignature: false }).catch(() => ({
          supported: false, adapter: 'unsupported', reasonCode: 'APPLICATION_INVALID_PATH', dataScope: 'unavailable', verification: 'pending',
        })),
          notionTrial: applications.routing.controlledNotionTrialSnapshot({ applicationId: item.id }),
          notionTrialHistory: await notionDiagnostics?.read(item.id).catch(() => null) ?? null } : item));
  }
  const snapshot = workspaceSnapshot({ ...value, ...applicationState });
  if (!firstWorkspaceSnapshot) { firstWorkspaceSnapshot = true; startupDiagnostics?.mark('workspace-snapshot'); }
  return snapshot;
}

async function getNotionTrialAvailability({ force = false } = {}) {
  if (!force && notionTrialAvailability && Date.now() - notionTrialAvailabilityAt < 30000) return notionTrialAvailability;
  if (notionTrialAvailabilityPending) return notionTrialAvailabilityPending;
  notionTrialAvailabilityPending = applications.routing.controlledNotionTrialAvailability().then(value => {
    notionTrialAvailability = value; notionTrialAvailabilityAt = Date.now(); return value;
  }).finally(() => { notionTrialAvailabilityPending = null; });
  return notionTrialAvailabilityPending;
}

// Resolve only a saved binding; the native carrier separately authorizes launch.
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

// Explicit fallback to the host browser, outside the environment.
async function shellOpen(url, bundleId = null) {
  if (process.platform !== 'darwin') return;
  const args = bundleId && /^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$/.test(bundleId) ? ['-b', bundleId, url] : [url];
  await new Promise((resolve, reject) => execFile('/usr/bin/open', args, { timeout: 15000 }, error => error ? reject(error) : resolve()));
}
// Bypass our default-handler registration to avoid sending the link back here.
async function openOutsideEnvironment(url) {
  const status = process.platform === 'darwin' ? await linkRouterStatus().catch(() => null) : null;
  if (status?.enabled) return shellOpen(url, status.previous && status.previous !== LINK_ROUTER_BUNDLE_ID ? status.previous : 'com.apple.Safari');
  return shellOpen(url);
}
const shutdownOwnedServices = () => shutdownDesktopServices({ applications, diagnostics: notionDiagnostics,
  terminal, terminalBrowserBroker, linkChannel, routerChannel, service, sidecar, proxyCore });

async function publish() {
  if (desktopStartup.phase !== 'ready' || quitting || !service || !views.size) return;
  if (publishing) { needsPublish = true; return; }
  publishing = true;
  const publishEpoch = requestEpoch;
  try {
    const snapshot = await fullWorkspaceSnapshot(await service.snapshot());
    if (quitting || publishEpoch !== requestEpoch) return;
    for (const { window: view, kind } of views.values()) if (!view.isDestroyed()) view.webContents.send('envara:snapshot', kind === 'terminal' ? terminalViewSnapshot(snapshot) : snapshot);
  } catch (error) { console.error('Unable to refresh workspace:', error.message); }
  finally { publishing = false; if (needsPublish) { needsPublish = false; void publish(); } }
}
const execFileAsync = promisify(execFile);
const allowedMethods = new Set([
  'snapshot', 'createProfile', 'updateProfile', 'cloneProfile', 'deleteProfile', 'clearProfile',
  'startProfile', 'stopProfile', 'focusProfile', 'bulkProfiles',
  'saveProxy', 'deleteProxy', 'checkProxy', 'saveGroup', 'deleteGroup', 'clearGroupProxy',
  'saveSettings', 'installEngine', 'importProfiles', 'cancelImport', 'exportProfiles',
  'openDataDirectory', 'openDocumentation', 'previewLegacyMigration', 'migrateLegacy',
  'exportAutomationConfig', 'openTerminalWindow', ...TERMINAL_METHODS,
]);
const applicationMethods = new Set(['saveApplication', 'startApplication', 'stopApplication', 'deleteApplication',
  'getApplicationRoutingStatus', 'setupApplicationRouting', 'setApplicationLinkBrowser']);
for (const method of [...applicationMethods, 'pickApplication', 'listLocalApplications', 'applicationIcon',
  'showApplicationWindow', 'clearApplicationData', 'signInData', 'deleteSignInData', 'linkRouterStatus', 'setLinkRouter',
  'requestSystemLinkRouting', 'disableSystemLinkRouting',
  'previewProxyNetwork', 'searchNetworkAddress', 'checkEnvironmentNetwork', 'openNetworkLocationMap']) allowedMethods.add(method);
for (const method of ['runNotionTrial', 'stopNotionTrial', 'notionTrialSnapshot', 'exportNotionDiagnostics', 'applicationStorage', 'reclaimApplicationStorage']) allowedMethods.add(method);
allowedMethods.add('exportEnvironment');

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

// The renderer may select these owned storage rows, never arbitrary paths.
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
// macOS alone confirms changes to this system-wide default browser handler.
const LINK_ROUTER_BUNDLE_ID = 'io.envara.link-router';
// Keep the per-user Unix socket path within macOS's 104-byte limit.
const LINK_ROUTER_SOCKET_PATH = `/private/tmp/io.envara.link-router.${process.getuid?.() ?? 0}.sock`;
function linkRouterResources() {
  const base = app.isPackaged ? process.resourcesPath : path.join(root, 'build');
  return path.join(base, 'app-routing', 'macos-link-router');
}
function linkRouterInstalled() {
  return path.join(app.getPath('userData'), 'link-router', 'EnvaraLinkRouter.app');
}
async function linkRouterRun(arguments_, bundle = linkRouterInstalled()) {
  const { stdout } = await execFileAsync(path.join(bundle, 'Contents/MacOS/EnvaraLinkRouter'), arguments_, { timeout: 120000, maxBuffer: 1024 * 1024 });
  return stdout.trim();
}
// Keep the router outside versioned app bundles so removing an old build is safe.
async function ensureLinkRouterInstalled() {
  if (process.platform !== 'darwin') throw Object.assign(new Error('链接路由需要 macOS。'), { code: 'LINK_ROUTER_UNAVAILABLE' });
  const source = linkRouterResources(), target = linkRouterInstalled();
  const info = await lstat(source).catch(() => null);
  if (!info?.isDirectory()) throw Object.assign(new Error('此版本没有内置链接路由。'), { code: 'LINK_ROUTER_UNAVAILABLE' });
  const marker = path.join(app.getPath('userData'), 'link-router', 'installed.json');
  let installed = null;
  try { installed = JSON.parse(await readFile(marker, 'utf8')); } catch {}
  const [sourceBinary, targetBinary] = await Promise.all([lstat(path.join(source, 'Contents', 'MacOS', 'EnvaraLinkRouter')),
    lstat(path.join(target, 'Contents', 'MacOS', 'EnvaraLinkRouter')).catch(() => null)]);
  const fresh = targetBinary && installed?.bundleIdentifier === LINK_ROUTER_BUNDLE_ID && installed?.size === sourceBinary.size && installed?.mtimeMs === sourceBinary.mtimeMs;
  if (!fresh) {
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    const stage = `${target}.stage-${randomUUID()}`;
    await rm(stage, { recursive: true, force: true });
    await cp(source, stage, { recursive: true, force: true });
    await rm(target, { recursive: true, force: true });
    await rename(stage, target);
    await writeFile(marker, `${JSON.stringify({ bundleIdentifier: LINK_ROUTER_BUNDLE_ID, size: sourceBinary.size, mtimeMs: sourceBinary.mtimeMs }, null, 2)}\n`, { mode: 0o600 });
    // LaunchServices must know this copy for the system to offer it as a handler.
    await execFileAsync('/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister', ['-f', target], { timeout: 30000 }).catch(() => {});
  }
  return target;
}
// Internal links stay enabled independently of explicit system-handler consent.
const linkPreferencesFile = () => path.join(app.getPath('userData'), 'link-preferences.json');
const linkPreferences = new LinkPreferences({ file: linkPreferencesFile });
async function linkRouterStatus() {
  const saved = linkPreferences.snapshot();
  const preference = { preference: saved.openInEnvironment, declined: Boolean(saved.declinedAt) };
  if (process.platform !== 'darwin') return { available: false, enabled: false, handler: null, previous: null, ...preference };
  try {
    // The bundled helper reads the same per-user state without installing or
    // registering a system handler merely because Settings asks for its status.
    const status = JSON.parse(await linkRouterRun(['--status'], linkRouterResources()) || '{}');
    if (status.router !== LINK_ROUTER_BUNDLE_ID) throw Object.assign(new Error('链接路由标识无效。'), { code: 'LINK_ROUTER_UNAVAILABLE' });
    return { available: true, enabled: status.enabled === true, handler: typeof status.handler === 'string' ? status.handler : null,
      previous: typeof status.previous === 'string' && status.previous ? status.previous : null, ...preference };
  } catch (error) { return { available: false, enabled: false, handler: null, previous: null, ...preference, errorCode: error.code ?? 'LINK_ROUTER_UNAVAILABLE' }; }
}
async function requestLinkRouter() {
  await ensureLinkRouterInstalled();
  let output;
  try {
    output = await linkRouterRun(['--enable']);
  } catch (error) {
    await linkPreferences.patch({ declinedAt: new Date().toISOString() }).catch(() => {});
    return { granted: false, output: String(error?.stdout || error?.message || '').trim().slice(0, 200) };
  }
  // A persistence failure after OS authorization is not a declined OS prompt.
  await linkPreferences.patch({ declinedAt: null });
  return { granted: true, output };
}
const linkRoutingControls = createLinkRoutingControls({ preferences: linkPreferences,
  status: linkRouterStatus, requestSystem: requestLinkRouter,
  restoreSystem: () => linkRouterRun(['--disable'], linkRouterResources()) });

let signInNames = null;
let linkChannel = null;
let routerChannel = null;
let linkRouter = null;
async function signInDataSnapshot() {
  if (process.platform !== 'darwin' || !applications || !service) return { items: [], totalBytes: 0 };
  const [attached, workspace, inventory] = await Promise.all([applications.snapshot(), service.snapshot(), attachedApplicationDataInventory()]);
  const names = signInNames ? await signInNames.remember(attached.applications).catch(() => signInNames.read()) : {};
  const trial = applications.routing?.controlledNotionTrialSnapshot?.() ?? null, running = new Set();
  if (trial?.active === true || trial?.cleanupUncertain === true) {
    const id = runningSignInDataId(attached.applications.find(item => item.id === trial.applicationId));
    if (id) running.add(id);
  }
  for (const item of attached.applications) if (signInDataInUse(item)) { const id = runningSignInDataId(item); if (id) running.add(id); }
  const items = signInDataRows({ applications: attached.applications, profiles: workspace.profiles, names, inventory, running });
  return { items, totalBytes: items.reduce((sum, item) => sum + item.bytes, 0) };
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
        defaultPath: `Envara-Application-${report.runId}.json`, filters: [{ name: 'JSON', extensions: ['json'] }] });
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
      const compatibility = await inspectApplicationCompatibility(application);
      if (!compatibility.supported) throw Object.assign(new Error('暂不支持此软件的网络隔离。'), { code: 'APPLICATION_ADAPTER_UNSUPPORTED' });
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
  if (method === 'clearApplicationData') {
    /* Sign-in data is removed only on request (removing an application keeps
     * it), and never while this application is starting, running or awaiting
     * cleanup. Another application's attachment uses its own data folder. */
    if (!applications || typeof args.id !== 'string') throw Object.assign(new Error('未找到此附加软件。'), { code: 'APPLICATION_NOT_FOUND' });
    // A live trial owns the queue until it ends. Refuse now instead of leaving
    // a destructive request queued to run after the user later stops the app.
    if (notionTrialReserved) throw Object.assign(new Error('请先停止此软件。'), { code: 'APPLICATION_RUNNING' });
    return applications.serialized(async () => {
      const item = (await applications.snapshot()).applications.find(entry => entry.id === args.id);
      if (!item?.path || !item.profileId) throw Object.assign(new Error('未找到此附加软件。'), { code: 'APPLICATION_NOT_FOUND' });
      const trial = applications.routing?.controlledNotionTrialSnapshot?.() ?? null;
      if (notionTrialReserved || signInDataInUse(item) ||
        trial?.applicationId === item.id && (trial.active === true || trial.cleanupUncertain === true)) throw Object.assign(new Error('请先停止此软件。'), { code: 'APPLICATION_RUNNING' });
      const erased = await eraseAttachedApplicationData(item.profileId, { registrationId: pfApplicationRegistrationId(item.path) });
      if (!erased.length) throw Object.assign(new Error('此软件尚未生成境舱应用数据。'), { code: 'APPLICATION_DATA_NOT_FOUND' });
      return { cleared: true, erased: erased.length };
    });
  }
  if (method === 'linkRouterStatus') return linkRouterStatus();
  if (method === 'setLinkRouter') return linkRoutingControls.setPreference(args.enabled);
  if (method === 'requestSystemLinkRouting') return linkRoutingControls.requestSystem();
  if (method === 'disableSystemLinkRouting') return linkRoutingControls.disableSystem();
  if (method === 'signInData') return signInDataSnapshot();
  if (method === 'deleteSignInData') {
    if (typeof args.id !== 'string' || args.id.length > 80) throw Object.assign(new Error('未找到这份登录数据。'), { code: 'SIGN_IN_DATA_NOT_FOUND' });
    if (!applications) throw Object.assign(new Error('未找到这份登录数据。'), { code: 'SIGN_IN_DATA_NOT_FOUND' });
    if (notionTrialReserved) throw Object.assign(new Error('请先停止此软件。'), { code: 'APPLICATION_RUNNING' });
    return applications.serialized(async () => {
      // Only a row main itself reports can be removed, and never while it is in use.
      const item = (await signInDataSnapshot()).items.find(entry => entry.id === args.id);
      if (!item) throw Object.assign(new Error('未找到这份登录数据。'), { code: 'SIGN_IN_DATA_NOT_FOUND' });
      if (item.dataScope !== 'environment') throw Object.assign(new Error('此软件尚未生成境舱应用数据。'), { code: 'APPLICATION_DATA_NOT_FOUND' });
      if (notionTrialReserved || item.running) throw Object.assign(new Error('请先停止此软件。'), { code: 'APPLICATION_RUNNING' });
      const erased = await eraseEnvironmentData(item.environmentId, { registrationId: item.registrationId });
      if (!erased.length) throw Object.assign(new Error('此软件尚未生成境舱应用数据。'), { code: 'APPLICATION_DATA_NOT_FOUND' });
      return { cleared: true, erased: erased.length };
    });
  }
  if (method === 'showApplicationWindow') {
    if (process.platform !== 'darwin' || !applications || typeof args.id !== 'string') throw Object.assign(new Error('软件没有在境舱中运行。'), { code: 'APPLICATION_WINDOW_UNAVAILABLE' });
    const item = (await applications.snapshot()).applications.find(entry => entry.id === args.id);
    if (!item?.path) throw Object.assign(new Error('未找到此附加软件。'), { code: 'APPLICATION_NOT_FOUND' });
    return showManagedApplicationWindow({ registrationId: pfApplicationRegistrationId(item.path) });
  }
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
  if (method === 'searchNetworkAddress') return service.searchNetworkAddress(args);
  if (applicationMethods.has(method)) {
    if (!applications) throw new Error('附加软件需要完整桌面应用。');
    if (['saveApplication', 'deleteApplication', 'setupApplicationRouting'].includes(method)) assertNotionTrialContextIdle();
    if (method === 'saveApplication' && process.platform === 'darwin') {
      const compatibility = await inspectApplicationCompatibility(args.application?.path);
      if (!compatibility.supported) throw Object.assign(new Error('暂不支持此软件的网络隔离。'), { code: 'APPLICATION_ADAPTER_UNSUPPORTED' });
    }
    if (method !== 'setupApplicationRouting') return applications[method](args);
    // Refresh availability after installation, even when the installation fails.
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
    return { path: selected.path, name: selected.name,
      ...(process.platform === 'darwin' ? { compatibility: await inspectApplicationCompatibility(selected, { verifySignature: false }) } : {}) };
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
    const urls = { 'map-attribution': 'https://www.openstreetmap.org/copyright', project: 'https://github.com/ink-scholar/Envara', 'runtime-license': 'https://github.com/CloakHQ/CloakBrowser/blob/main/BINARY-LICENSE.md', automation: 'https://github.com/nczz/BrowseForge/blob/fa9e0bb670e749706a9c8f2d4095333347d6c521/docs/developer-integration.md', upstream: 'https://github.com/nczz/BrowseForge' };
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
  if (method === 'exportEnvironment') {
    const password = checkedExportPassword(args?.password);
    const scope = args?.scope;
    if (!['browser', 'terminal', 'application'].includes(scope)) throw Object.assign(new Error('请选择要导出的浏览器、终端或软件。'), { code: 'EXPORT_SCOPE_INVALID' });
    const profile = (await service.snapshot()).profiles.find(item => item.id === args?.id);
    if (!profile) throw new Error('环境不存在。');
    await assertEnvironmentIdle({ profile, terminal, applications, scope, applicationId: args.applicationId });
    const name = String(profile.name ?? '').replace(/[\/\\:*?"<>|\x00-\x1f]/g, '_').slice(0, 60) || 'environment';
    const choice = await dialog.showSaveDialog(window, { title: '导出数据', defaultPath: `Envara-${scope}-${name}.envara`, filters: [{ name: 'Envara 数据', extensions: ['envara'] }] });
    if (choice.canceled || !choice.filePath) return { canceled: true };
    return environmentTransferLock.transfer(async () => {
      // The save dialog may have stayed open while another IPC started a
      // consumer. Reserve first, then wait for already-stopped application data
      // housekeeping and re-read the browser's actual current desktop status.
      for (;;) {
        const housekeeping = applications?.routing?.notionTrial?.housekeeping;
        if (!housekeeping) break;
        await housekeeping;
        if (applications?.routing?.notionTrial?.housekeeping === housekeeping) break;
      }
      const current = (await service.snapshot()).profiles.find(item => item.id === args?.id);
      if (!current) throw new Error('环境不存在。');
      await assertEnvironmentIdle({ profile: current, terminal, applications, scope, applicationId: args.applicationId });
      const result = await exportEnvironment({ profile: current, password, file: choice.filePath, service, terminal, applications,
        appVersion: app.getVersion(), dataDir: app.getPath('userData'), scope, accountId: args.accountId, applicationId: args.applicationId });
      return { canceled: false, ...result };
    }, args.id);
  }
  if (method === 'exportProfiles') {
    const data = await service.call(method, args);
    const choice = await dialog.showSaveDialog(window, { title: '导出环境配置', defaultPath: 'envara-profiles.json', filters: [{ name: 'Envara JSON', extensions: ['json'] }] });
    if (choice.canceled || !choice.filePath) return { canceled: true };
    await writeFile(choice.filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
    return { canceled: false, count: data.profiles.length };
  }
  if (method === 'cancelImport') { await discardImport(args.importId); return { canceled: true }; }
  if (method === 'importProfiles') {
    await expirePendingEnvironmentImports({ imports: pendingImports, discard: discardImport });
    if (args.importId) {
      const pending = pendingImports.get(args.importId);
      if (!pending) throw new Error('待导入配置已过期，请重新选择文件');
      return withPendingEnvironmentImport(pending, async () => {
        if (pending.file && !pending.bundle) {
          if (!sidecar) throw new Error('多内核后端尚未就绪');
          const staging = path.join(app.getPath('userData'), 'imports', `staging-${randomUUID()}`);
          await mkdir(path.dirname(staging), { recursive: true, mode: 0o700 });
          const manifest = await readEnvironmentExport({ file: pending.file, password: args.password, staging });
          pending.bundle = { staging, manifest };
          try { checkedExportManifest(manifest); } catch (error) { await discardImport(args.importId, { completed: true }); throw error; }
          pending.document = manifest.profile;
          const mapping = proxyMappingRequest(args.importId, pending.document, manifest.scope ?? 'environment');
          if (mapping) return mapping;
        }
        return environmentTransferLock.transfer(() => finishPendingEnvironmentImport({ pending, service, proxyMap: args.proxyMap ?? {},
          restore: profileId => restoreEnvironment({ ...pending.bundle, profileId, service, terminal, applications,
            dataDir: app.getPath('userData') }), discard: () => discardImport(args.importId, { completed: true }) }));
      });
    }
    const choice = await dialog.showOpenDialog(window, { title: '导入环境', properties: ['openFile'], filters: [{ name: 'Envara 环境', extensions: ['envara', 'json'] }] });
    if (choice.canceled || !choice.filePaths[0]) return { canceled: true };
    if (await isEnvironmentExport(choice.filePaths[0])) {
      const importId = randomUUID();
      await registerPendingEnvironmentImport({ imports: pendingImports, importId,
        pending: { file: choice.filePaths[0], createdAt: Date.now() }, discard: discardImport,
        removeStaging: staging => rm(staging, { recursive: true, force: true }) });
      return { needsPassword: true, importId, fileName: path.basename(choice.filePaths[0]) };
    }
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
        await registerPendingEnvironmentImport({ imports: pendingImports, importId,
          pending: { document: data, createdAt: Date.now() }, discard: discardImport,
          removeStaging: staging => rm(staging, { recursive: true, force: true }) });
        return { needsProxyMapping: true, importId, profileCount: data.profiles.length, proxyRefs: refs.map(id => {
          const proxy = Array.isArray(data.proxies) ? data.proxies.find(item => item.id === id) : null;
          return { id, name: typeof proxy?.name === 'string' ? proxy.name.slice(0, 100) : '原配置出口', protocol: typeof proxy?.protocol === 'string' ? proxy.protocol.slice(0, 16) : null, host: typeof proxy?.host === 'string' ? proxy.host.slice(0, 253) : null, port: Number.isInteger(proxy?.port) ? proxy.port : null, requiresCredentials: !!proxy?.requiresCredentials };
        }) };
      }
    }
    return environmentTransferLock.transfer(() => service.call(method,
      sidecar ? { document: data, proxyMap: args.proxyMap ?? {} } : { profiles: data.profiles }));
  }
  const result = await protectApplicationMutation(method, args, () => terminalController ? terminalController.protectMutation(method, args, () => service.call(method, args)) : service.call(method, args));
  return finishEnvironmentDeletion({ method, args, result, applications, eraseData: eraseAttachedApplicationData,
    releaseImport: profileId => releaseDeletedEnvironmentImportProfile({ imports: pendingImports, profileId }) });
}

function registerView(view, kind, profileId = null) {
  const contents = view.webContents;
  views.set(contents, { window: view, kind, profileId });
  contents.on('dom-ready', () => appearance.updateWindow(view));
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
  const theme = appearance.snapshot();
  return { backgroundColor: appearanceBackground(theme.effective), titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 18, y: 17 }, icon: path.join(root, 'build/icon.png'), webPreferences: { preload: path.join(root, 'electron/preload.cjs'), additionalArguments: [`--envara-appearance=${theme.preference}`, `--envara-theme=${theme.effective}`], contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, devTools: !app.isPackaged } };
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
  startupDiagnostics?.mark('window-create-start');
  const view = new BrowserWindow({ ...viewOptions(), width: 1500, height: 940, minWidth: 1120, minHeight: 720, title: 'Envara · 境舱' });
  startupDiagnostics?.mark('window-created');
  window = view;
  registerView(view, 'workspace');
  view.webContents.once('dom-ready', () => startupDiagnostics?.mark('renderer-dom-ready'));
  try { await startupStep('window-load', () => loadView(view)); }
  catch (error) { if (!view.isDestroyed()) view.close(); throw error; }
  if (isSmoke) {
    await desktopStartup.ready;
    const { runSmoke } = await import('./smoke.mjs');
    await runSmoke({ app, window, service, runtime: service.runtime });
  }
  if (isWorkspaceSmoke) {
    await desktopStartup.ready;
    const { runWorkspaceSmoke } = await import('./workspace-smoke.mjs');
    await runWorkspaceSmoke({ app, window, service, terminal, applications, shutdown: shutdownOwnedServices });
  }
  return view;
}

const workspaceWindow = createWorkspaceWindowController({ current: () => window, create: createWindow,
  canOpen: () => ownsLock && !quitting });
const showWorkspaceWindow = () => { void workspaceWindow.open().catch(error => console.error('Unable to open workspace:', error.message)); };
app.on('second-instance', showWorkspaceWindow);
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
app.on('activate', showWorkspaceWindow);
app.on('accessibility-support-changed', () => { void publish(); });
const desktopStartup = createDesktopStartup({ initialize: initializeDesktopServices });
const ownedQuit = createOwnedQuitController({
  hasResources: () => desktopStartup.phase === 'starting' || !!(service || sidecar || terminal || proxyCore), startup: () => desktopStartup.settled,
  shutdown: shutdownOwnedServices, quit: () => app.quit(), onStateChange: value => {
    quitting = value;
    if (value) requestEpoch++;
    if (value && ['idle', 'starting'].includes(desktopStartup.phase)) void desktopStartup.close();
  },
  onFailure: () => {
    showWorkspaceWindow();
    dialog.showErrorBox('附加软件清理未确认', '网络会话仍保留。请先停止附加软件并完成清理，再退出境舱。');
  },
});
app.on('before-quit', event => { void ownedQuit.handle(event).catch(error => console.error('Unable to complete shutdown:', error.message)); });
async function initializeDesktopServices({ checkOpen }) {
  const initializeStep = async (name, operation) => {
    checkOpen();
    const value = await startupStep(name, operation);
    checkOpen();
    return value;
  };
  const dataDir = app.getPath('userData');
  await initializeStep('data-directory', () => mkdir(dataDir, { recursive: true, mode: 0o700 }));
  signInNames = new SignInDataNames({ dataDir });
  if (isSmoke || process.env.ENVARA_BACKEND === 'legacy') {
    const runtime = new BrowserRuntime({ cacheDir: isSmoke && process.env.ENVARA_SMOKE_ENGINE_DIR ? process.env.ENVARA_SMOKE_ENGINE_DIR : path.join(dataDir, 'engines'), onChange: publish });
    service = new EnvaraService(dataDir, runtime, { platform: process.platform, appVersion: app.getVersion() }, publish);
    await initializeStep('workspace-store', () => service.ready);
  } else {
    proxyCore = new ProxyCoreManager({ dataDir, resourcesDir: app.isPackaged ? path.join(process.resourcesPath, 'proxy-core') : path.join(root, 'build/proxy-core'), onChange: event => {
      if (event?.id && event.status === 'failed') {
        service?.invalidateManagedProxy?.(event.id);
        // Revoke matching dedicated Claude sessions immediately; the core's
        // event delivery must not wait for slow child-process cleanup.
        void terminal?.invalidateManagedProxy?.(event.id)?.catch(() => {});
      }
      return publish();
    } });
    await initializeStep('proxy-initialize', () => proxyCore.initialize().catch(() => {}));
    sidecar = new SidecarManager({ dataDir, resourcesDir: app.isPackaged ? path.join(process.resourcesPath, 'backend') : path.join(root, 'build/backend'), onChange: publish, startupStep: initializeStep });
    await initializeStep('sidecar-initialize', () => sidecar.initialize());
    service = new BrowseForgeService(dataDir, sidecar.client, { platform: process.platform, appVersion: app.getVersion(), backend: 'BrowseForge (Envara desktop)', upstreamVersion: '2.1.15', localApi: sidecar.baseUrl }, publish, {
      profilesDir: path.join(sidecar.baseDir, 'profiles'), getEngineStates: () => sidecar.getEngineStates(), proxyCore,
      ...(isWorkspaceSmoke ? {
        networkProbe: new ProxyNetworkProbe({ transport: async () => ({ success: true, ip: '8.8.8.8', country: 'Philippines', country_code: 'PH', city: 'Manila', latitude: 14.6, longitude: 121, timezone: { id: 'Asia/Manila' } }) }),
        addressGeocoder: { search: async () => ({ source: 'Photon', attribution: '© OpenStreetMap contributors', candidates: [{ id: 'owned-place-fixture', label: 'Synthetic public landmark, Manila', latitude: 14.58, longitude: 120.98 }] }) },
      } : {}),
      installEngine: id => sidecar.installEngine(id), getMetrics: profiles => sidecar.metrics(profiles),
      getConnectionInfo: () => ({ apiUrl: sidecar.baseUrl + '/api', mcpUrl: sidecar.baseUrl + '/mcp', status: sidecar.process ? 'ready' : 'stopped', version: '2.1.15', sourceCommit: 'fa9e0bb670e749706a9c8f2d4095333347d6c521' }),
      cancelInstall: () => sidecar.cancelInstall(),
      assertLegacyStopped: () => sidecar.assertLegacyStopped(), shutdown: () => sidecar.shutdown(),
    });
    await initializeStep('workspace-store', () => service.ready);
    // Terminal shims and macOS link handling share the same routing decision.
    const reportLink = (request, source) => linkRouter.openFromProfile({ profileId: request.profileId, url: request.url, source });
    linkChannel = new TerminalLinkChannel({ root: dataDir, onLink: request => reportLink(request, '终端'),
      log: message => console.info(`Envara link channel: ${message}`) });
    await initializeStep('terminal-link-listen', () => linkChannel.listen().catch(error => { console.error(`Envara link channel unavailable: ${error.message}`); linkChannel = null; }));
    routerChannel = new LinkSocketServer({ root: dataDir, socketPath: LINK_ROUTER_SOCKET_PATH, sender: 'owner',
      onLink: request => linkRouter.openFromProcess(request),
      log: message => console.info(`Envara link router: ${message}`) });
    await initializeStep('system-link-listen', () => routerChannel.listen().catch(error => { console.error(`Envara link router unavailable: ${error.message}`); routerChannel = null; }));
    terminalBrowserBroker = new TerminalBrowserBroker({ service, dataDir, protectBrowserOperation,
      nodeExecutable: path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), 'backend', 'playwright-driver', process.platform === 'win32' ? 'node.exe' : 'node'),
      onError: event => { for (const { window: view, kind } of views.values()) if (!view.isDestroyed() && kind === 'workspace') view.webContents.send('envara:link-event', { ...event, type: 'error' }); } });
    terminal = new TerminalService({
      dataDir,
      linkChannel,
      sshManager: new TerminalSshManager({ dataDir, hostHome: app.getPath('home'),
        nodeExecutable: path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), 'backend', 'playwright-driver', process.platform === 'win32' ? 'node.exe' : 'node') }),
      browserBroker: terminalBrowserBroker,
      additionalExecutablePaths: [path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), 'backend', 'playwright-driver')],
      resolveContext: id => service.resolveWorkspaceContext(id),
      onEvent: event => {
        for (const { window: view, kind, profileId } of views.values()) if (!view.isDestroyed() && (kind === 'workspace' || profileId === event.profileId)) view.webContents.send('envara:terminal-event', event);
        if (event.type === 'exit' && !views.size) void quitWhenIdle().catch(() => app.quit());
      },
    });
    await initializeStep('terminal-store', () => terminal.ready);
    await initializeStep('link-preferences', () => linkPreferences.load());
    // Resolve applications lazily: the router is constructed before their service.
    linkRouter = new LinkRouter({ service, terminal, protectBrowserOperation, applications: { snapshot: async () => applications ? applications.snapshot() : { applications: [] } },
      enabled: () => linkPreferences.snapshot().openInEnvironment,
      registrationRoot: '/Library/PrivilegedHelperTools/io.envara.pf-apps',
      openDefault: async url => { await openOutsideEnvironment(url); },
      notify: event => { for (const { window: view, kind } of views.values()) if (!view.isDestroyed() && kind === 'workspace') view.webContents.send('envara:link-event', event); } });
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
    }, pickSSHIdentity: async (_target, context) => {
      const parent = context?.window;
      if (!parent || parent.isDestroyed()) throw Object.assign(new Error('终端窗口已关闭。'), { code: 'SSH_WINDOW_CLOSED' });
      if (process.platform !== 'darwin') throw Object.assign(new Error('SSH 连接目前仅支持 macOS。'), { code: 'SSH_UNSUPPORTED' });
      parent.show(); parent.focus();
      const choice = await dialog.showOpenDialog(parent, { properties: ['openFile'] });
      if (parent.isDestroyed()) throw Object.assign(new Error('终端窗口已关闭。'), { code: 'SSH_WINDOW_CLOSED' });
      return { canceled: choice.canceled, path: choice.filePaths[0] };
    } });
    const routingRoot = path.join(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), 'app-routing');
    notionDiagnostics = new NotionDiagnosticsStore(path.join(dataDir, 'notion-trial-diagnostics'));
    const helperPath = process.platform === 'darwin'
      ? path.join(routingRoot, 'macos/EnvaraAppRouting.app/Contents/MacOS/EnvaraAppRoutingHelper')
      : process.platform === 'win32' ? path.join(routingRoot, 'win32', process.arch, 'EnvaraAppRouting.exe') : null;
    const bundledPF = bundledPFRoutingPaths(app.isPackaged ? process.resourcesPath : path.join(root, 'build'), { packaged: app.isPackaged });
    let pfHelperPath = bundledPF.helperPath;
    if (process.platform === 'darwin') {
      const installedPFHelper = '/Library/PrivilegedHelperTools/io.envara.pf-routing/EnvaraPFHelper';
      const installedPF = await initializeStep('pf-installation-verify', verifyPFInstallation);
      if (installedPF.verified === true && installedPF.manifestVerified === true) pfHelperPath = installedPFHelper;
    }
    const applicationRouting = process.platform === 'darwin'
      ? process.env.ENVARA_MAC_ROUTING_BACKEND === 'app-proxy'
        ? new MacOSApplicationRouting({
        helperPath,
        peerVerifierPath: path.join(routingRoot, 'macos-local/EnvaraPeerVerifier'),
        bundledAppPath: path.join(routingRoot, 'macos-local/Resources/Mitmproxy Redirector.app'),
      }) : new MacOSPFApplicationRouting({ helperPath: pfHelperPath, installerPath: bundledPF.installerPath,
        notionAuthorizerPath: bundledPF.authorizerPath,
        onNotionTrialEvent: event => { console.info('Envara attached application', JSON.stringify(event)); void publish(); },
        onNotionTrialDiagnostics: report => notionDiagnostics.save(report),
        onApplicationHousekeeping: async ({ applicationId }) => {
          const application = (await applications.snapshot()).applications.find(item => item.id === applicationId);
          if (!application) return;
          try { if ((await applyPendingApplicationData({ application, dataDir })).applied) void publish(); }
          catch (error) {
            const code = ['IMPORT_TARGET_UNSAFE', 'IMPORT_TARGET_NOT_EMPTY', 'IMPORT_RESTORE_FAILED'].includes(error?.code)
              ? error.code : 'IMPORT_APPLICATION_RESTORE_FAILED';
            console.error('Envara imported application data restore failed', code);
            throw Object.assign(new Error('附加软件的导入资料尚未恢复，请停止软件后重试。'), { code });
          }
        },
      })
      : new NativeApplicationRouting({ helperPath });
    applications = new ApplicationService({ dataDir, routing: applicationRouting,
      resolveContext: id => applicationWorkspaceContext(id, { service, terminal }),
      profileExists: async id => (await service.snapshot()).profiles.some(profile => profile.id === id), onEvent: publish });
    await initializeStep('applications-store', () => applications.ready);
    await initializeStep('application-routing-status', () => applications.getApplicationRoutingStatus());
  }
}

function reportStartupFailure(error) {
  if (quitting || error?.code === 'APP_CLOSING') return;
  startupDiagnostics?.fail(error?.code);
  console.error(error);
  if (isSmoke || isWorkspaceSmoke) process.exitCode = 1;
  dialog.showErrorBox('境舱无法启动', error.message);
  app.quit();
}
// Loading the first window must not depend on backend startup or the renderer's
// initial snapshot. IPC is installed first; only bootstrap reads wait for ready.
// Electron waits for this entry module before emitting ready: no top-level await.
if (ownsLock) void startupStep('electron-ready', () => app.whenReady()).then(() => {
  if (quitting) return;
  registerDesktopIPC({ ipcMain, views, startup: desktopStartup,
    lifecycle: () => ({ quitting, requestEpoch }), services: () => ({ applications, terminal }),
    transferLock: environmentTransferLock, handleCall, fullWorkspaceSnapshot,
    onReady: () => startupDiagnostics?.mark('ipc-ready') });
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    { label: 'Envara', submenu: [{ label: '关于境舱', role: 'about' }, { type: 'separator' }, { label: '退出境舱', role: 'quit' }] },
    { label: '编辑', submenu: [{ role: 'undo' }, { role: 'redo' }, { type: 'separator' }, { role: 'cut' }, { role: 'copy' }, { role: 'paste' }, { role: 'selectAll' }] },
    { label: '窗口', submenu: [{ role: 'minimize' }, { role: 'zoom' }, { role: 'front' }] },
  ]));
  if (process.platform === 'darwin') app.dock?.setIcon(nativeImage.createFromPath(path.join(root, 'build/icon.png')));
  workspaceWindow.markReady();
  void workspaceWindow.open().catch(reportStartupFailure);
  void desktopStartup.start().then(() => {
    startupDiagnostics?.mark('startup-complete');
    if (quitting) return;
    void publish();
    const refreshTimer = setInterval(() => { void publish(); }, 4000);
    refreshTimer.unref();
  }).catch(reportStartupFailure);
}).catch(reportStartupFailure);
