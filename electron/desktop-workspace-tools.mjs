import { exportSupportDiagnostics, existingNetworkDiagnostics } from './support-diagnostics.mjs';
import { exportPFNotionTrialDiagnostics } from './macos-pf-notion-trial.mjs';
import { readComponentVersions } from './component-versions.mjs';
import { BrowserSiteData } from './browser-site-data.mjs';
import { WorkCombinations } from './work-combinations.mjs';
import { createDesktopCacheMaintenance } from './desktop-cache-maintenance.mjs';
import { RuntimeVerificationService } from './runtime-verification.mjs';

// These tools share workspace authority, but retain their own locks and lazy
// resources. Service getters resolve only when an operation actually needs one.
export function createDesktopWorkspaceTools({ dataDir, appVersion, platform, arch,
  getService, getTerminal, getTerminalController, getApplications, transferLock,
  fullWorkspaceSnapshot, isClosing, showSaveDialog, readStartup, readRuntime,
  readRecovery, getNotionDiagnostics,
  createSiteData = options => new BrowserSiteData(options),
  createCombinations = options => new WorkCombinations(options),
  createCacheMaintenance = createDesktopCacheMaintenance,
  createRuntimeVerification = options => new RuntimeVerificationService(options),
  readVersions = readComponentVersions, exportDiagnostics = exportSupportDiagnostics,
}) {
  const siteData = createSiteData({ getService });
  let combinations = null, cacheMaintenance = null, runtimeVerification = null, supportExportPending = null;

  async function getCombinations() {
    if (!getTerminal() || !getTerminalController()) throw Object.assign(new Error('当前运行路径尚未启用终端。'), { code: 'WORK_COMBINATION_PROFILE_UNAVAILABLE' });
    await getTerminal().ready;
    const terminal = getTerminal();
    combinations ??= createCombinations({ root: terminal.root, terminal,
      getProfile: async id => (await getService().snapshot()).profiles.find(profile => profile.id === id),
      ensureBrowser: id => getService().call('startProfile', { id }),
    });
    await combinations.ready;
    return combinations;
  }

  async function combinationCall(operation, args, serialize = true) {
    const current = await getCombinations();
    return serialize ? getTerminalController().serialize(() => current[operation](args)) : current[operation](args);
  }

  function cacheCall(operation, args) {
    cacheMaintenance ??= createCacheMaintenance({ dataDir, service: getService(), terminal: getTerminal(),
      applications: getApplications(), transferLock });
    return cacheMaintenance[operation](args);
  }

  function runtimeCall(method, args) {
    const service = getService();
    if (typeof service.captureRuntimeVerificationContext !== 'function') throw Object.assign(new Error('无法读取当前环境，请刷新后重试。'), { code: 'RUNTIME_VERIFICATION_UNAVAILABLE' });
    runtimeVerification ??= createRuntimeVerification({ browserService: service, terminalService: getTerminal() });
    return runtimeVerification[method](args);
  }

  function exportSupport(args, caller) {
    if (Object.keys(args).length) throw new Error('操作参数无效。');
    if (!supportExportPending) supportExportPending = exportDiagnostics({ args, appVersion, platform, arch,
      checkOpen: () => { if (isClosing() || !caller || caller.isDestroyed()) throw Object.assign(new Error('应用正在退出。'), { code: 'APP_CLOSING' }); },
      showSaveDialog: options => showSaveDialog(caller, options),
      readers: {
        startup: readStartup, runtime: readRuntime,
        network: () => existingNetworkDiagnostics(getService()), recovery: readRecovery,
        applications: async () => {
          const applications = getApplications();
          const reports = [];
          const active = exportPFNotionTrialDiagnostics(applications?.routing?.controlledNotionTrialSnapshot?.());
          if (active) reports.push(active);
          for (const application of [...(applications?.applications?.values() ?? [])].slice(0, 49)) {
            const report = await getNotionDiagnostics()?.readExisting(application.id);
            if (report) reports.push(report);
          }
          return reports;
        },
      },
    }).finally(() => { supportExportPending = null; });
    return supportExportPending;
  }

  const handlers = Object.freeze({
    runtimeVerificationSnapshot: args => runtimeCall('runtimeVerificationSnapshot', args),
    checkRuntimeVerification: args => runtimeCall('checkRuntimeVerification', args),
    cacheMaintenanceInventory: args => cacheCall('inventory', args),
    quarantineBrowserCaches: args => cacheCall('quarantine', args),
    restoreBrowserCaches: args => cacheCall('restore', args),
    purgeBrowserCacheBatch: args => cacheCall('purge', args),
    listWorkCombinations: args => combinationCall('list', args, false),
    saveWorkCombination: args => combinationCall('save', args),
    deleteWorkCombination: args => combinationCall('remove', args),
    openWorkCombination: args => combinationCall('open', args),
    componentVersions: async args => {
      if (Object.keys(args).length) throw new Error('操作参数无效。');
      return readVersions({ snapshot: await fullWorkspaceSnapshot(await getService().snapshot()), terminal: getTerminal() });
    },
    listBrowserSiteData: args => siteData.list(args),
    clearBrowserSiteCookies: args => {
      const service = getService();
      return typeof service.profileSerialize === 'function'
        ? service.profileSerialize(args.profileId, () => siteData.clear(args)) : siteData.clear(args);
    },
    exportSupportDiagnostics: exportSupport,
  });
  return {
    handles: method => Object.hasOwn(handlers, method),
    async call(method, args, caller) {
      if (!Object.hasOwn(handlers, method)) throw new Error('不支持的操作');
      if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('操作参数无效。');
      return handlers[method](args, caller);
    },
    getCombinations,
    get workCombinations() { return combinations; },
    get cacheMaintenance() { return cacheMaintenance; },
    get supportExportPending() { return !!supportExportPending; },
    // A pending diagnostic export has its own closing checks; quit must not
    // wait for a save dialog. Only the already-created cache service closes.
    close: async () => { await cacheMaintenance?.close(); },
  };
}
