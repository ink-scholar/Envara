import path from 'node:path';
import { createApplicationUpdater } from './application-updates.mjs';
import { createMacApplicationUpdateAdapter } from './macos-application-updater.mjs';
import { createApplicationUpdateLifecycle } from './application-update-lifecycle.mjs';
import { waitForApplicationUpdateStartup } from './application-update-startup.mjs';

export function createDesktopApplicationUpdateController({ currentVersion, platform, arch, packaged,
  dataDir, helperDirectory, executablePath, fetch, getResources, isClosing, beginClosing, restoreOpen,
  shutdownStrict, quitApplication, exitStartup, relaunchStartup,
  createUpdater = createApplicationUpdater, createAdapter = createMacApplicationUpdateAdapter,
  createLifecycle = createApplicationUpdateLifecycle, waitForStartup = waitForApplicationUpdateStartup,
  scheduleInstall = setImmediate,
}) {
  let updater = null, lifecycle = null, quitAuthorized = false;
  const cacheDir = path.join(dataDir, 'application-updates');
  const newAdapter = () => createAdapter({ executablePath, currentVersion, helperDirectory });

  function getUpdater() {
    if (updater) return updater;
    const adapter = newAdapter();
    updater = createUpdater({ currentVersion, platform, arch, packaged, cacheDir, fetch,
      prepare: args => adapter.prepare(args),
      // Defer shutdown until the updater has persisted the installer pointer
      // and returned its accepted response to the workspace renderer.
      install: prepared => ({ accepted: true, completion: new Promise((resolve, reject) => scheduleInstall(async () => {
        let armed;
        try {
          const assertUpdatingOpen = () => { if (isClosing()) throw Object.assign(new Error('Application is closing.'), { code: 'APP_UPDATE_CLOSED' }); };
          assertUpdatingOpen();
          lifecycle = createLifecycle({ getResources, beginClosing, restoreOpen,
            shutdown: shutdownStrict, authorizeInstall: () => armed.commit(),
            quit: () => { quitAuthorized = true; quitApplication(); },
          });
          const readiness = await lifecycle.readiness();
          assertUpdatingOpen();
          if (!readiness.ready) throw Object.assign(new Error('End active work before updating.'), { code: 'APP_UPDATE_BUSY' });
          armed = await adapter.arm(prepared);
          assertUpdatingOpen();
          await lifecycle.install();
          resolve();
        } catch (error) {
          await armed?.abort().catch(() => {});
          reject(error);
        }
      })) }),
    });
    return updater;
  }

  function snapshot() {
    const value = getUpdater().snapshot();
    return lifecycle?.phase === 'blocked' ? { ...value, canInstall: false, restartRequired: true } : value;
  }

  async function action(name) { const current = getUpdater(); await current.ready; await current[name](); return snapshot(); }
  const handlers = Object.freeze({
    applicationUpdateStatus: async () => { const current = getUpdater(); await current.ready; await current.refreshResult(); return snapshot(); },
    checkApplicationUpdate: () => action('check'),
    downloadApplicationUpdate: () => action('download'),
    cancelApplicationUpdate: () => action('cancel'),
    installApplicationUpdate: () => action('install'),
  });
  return {
    handles: method => Object.hasOwn(handlers, method),
    async call(method, args) {
      if (!Object.hasOwn(handlers, method)) throw new Error('不支持的操作');
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).length) throw new Error('操作参数无效。');
      return handlers[method]();
    },
    get active() { return !!lifecycle; },
    get quitAuthorized() { return quitAuthorized; },
    close: async () => { await updater?.close(); },
    async beforeStartup({ checkOpen, step }) {
      if (!packaged || platform !== 'darwin' || arch !== 'arm64') return true;
      const adapter = newAdapter();
      const result = await step('application-update', () => waitForStartup({ cacheDir, currentVersion, checkOpen,
        inspectInstaller: record => adapter.inspectInstaller(record),
      }));
      if (result.status === 'ready') return true;
      // No consumer exists yet. A process that loaded the old entry while a
      // replacement completed must restart from disk before opening services.
      if (result.status === 'restart-required') relaunchStartup();
      exitStartup(0);
      return false;
    },
  };
}
