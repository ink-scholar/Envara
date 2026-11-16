import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { createDesktopApplicationUpdateController } from '../electron/desktop-application-update-controller.mjs';

function fixture(overrides = {}) {
  const events = [], scheduled = [];
  let closing = false, resources = { revision: 1 }, updaterOptions, lifecycleOptions, completion, phase = 'idle';
  const controller = createDesktopApplicationUpdateController({ currentVersion: '1.2.3', platform: 'darwin', arch: 'arm64', packaged: true,
    dataDir: '/fixture-only', helperDirectory: '/fixture-only/helpers', executablePath: '/fixture-only/Envara.app/executable',
    fetch: () => assert.fail('No network request is expected'), getResources: () => resources,
    isClosing: () => closing, beginClosing: () => { closing = true; events.push('closing'); },
    restoreOpen: () => { closing = false; events.push('open'); }, shutdownStrict: async () => events.push('shutdown-strict'),
    quitApplication: () => events.push('quit'), exitStartup: code => events.push(`exit:${code}`), relaunchStartup: () => events.push('relaunch'),
    scheduleInstall: callback => scheduled.push(callback),
    createAdapter: () => { events.push('adapter'); return {
      inspectInstaller: async record => ({ ...record, inspected: true }), prepare: async args => args,
      arm: async prepared => { events.push(`arm:${prepared.id}`); return {
        commit: async () => events.push('commit'), abort: async () => events.push('abort'),
      }; },
    }; },
    createUpdater: options => {
      updaterOptions = options; events.push('updater');
      return { ready: Promise.resolve(), snapshot: () => ({ status: 'ready', canInstall: true }),
        refreshResult: async () => events.push('refresh'), close: async () => events.push('close-updater'),
        check: async () => events.push('check'), download: async () => events.push('download'), cancel: async () => events.push('cancel'),
        install: async () => { const result = options.install({ id: 'owned-stage' }); assert.equal(result.accepted, true);
          completion = result.completion; completion.catch(() => {}); events.push('persist-pointer'); },
      };
    },
    createLifecycle: options => {
      lifecycleOptions = options; events.push('lifecycle');
      return { get phase() { return phase; }, readiness: async () => { events.push('readiness'); return { ready: true }; },
        install: async () => { options.beginClosing(); await options.shutdown(); await options.authorizeInstall(); options.quit(); },
      };
    },
    waitForStartup: async ({ inspectInstaller }) => { assert.equal((await inspectInstaller({ id: 'owned-stage' })).inspected, true); return { status: 'ready' }; },
    ...overrides,
  });
  return { controller, events, scheduled, get updaterOptions() { return updaterOptions; }, get lifecycleOptions() { return lifecycleOptions; },
    get completion() { return completion; }, setClosing: value => { closing = value; }, setResources: value => { resources = value; },
    setPhase: value => { phase = value; } };
}

test('construction, unknown methods, and closing an unused controller do not initialize the updater', async () => {
  const f = fixture();
  assert.equal(f.controller.active, false); assert.equal(f.controller.quitAuthorized, false);
  for (const method of ['constructor', 'toString', 'snapshot']) {
    assert.equal(f.controller.handles(method), false);
    await assert.rejects(f.controller.call(method, {}));
  }
  for (const args of [null, [], { path: '/fixture-only' }]) await assert.rejects(f.controller.call('checkApplicationUpdate', args));
  await f.controller.close();
  assert.deepEqual(f.events, []);
});

test('status reads local results while the fixed action dispatch uses one lazy updater', async () => {
  const f = fixture();
  await f.controller.call('applicationUpdateStatus', {});
  for (const method of ['checkApplicationUpdate', 'downloadApplicationUpdate', 'cancelApplicationUpdate']) await f.controller.call(method, {});
  await f.controller.close();
  assert.deepEqual(f.events, ['adapter', 'updater', 'refresh', 'check', 'download', 'cancel', 'close-updater']);
});

test('install returns after pointer persistence before closing, then observes live resources and authorizes quit last', async () => {
  const f = fixture();
  await f.controller.call('installApplicationUpdate', {});
  assert.deepEqual(f.events, ['adapter', 'updater', 'persist-pointer']);
  assert.equal(f.controller.active, false); assert.equal(f.controller.quitAuthorized, false);
  f.setResources({ revision: 2 });
  await f.scheduled.shift()(); await f.completion;
  assert.equal(f.lifecycleOptions.getResources().revision, 2);
  f.setResources({ revision: 3 });
  assert.equal(f.lifecycleOptions.getResources().revision, 3);
  assert.deepEqual(f.events, ['adapter', 'updater', 'persist-pointer', 'lifecycle', 'readiness', 'arm:owned-stage', 'closing', 'shutdown-strict', 'commit', 'quit']);
  assert.equal(f.controller.active, true); assert.equal(f.controller.quitAuthorized, true);
});

test('quit before deferred install neither arms an installer nor starts a lifecycle', async () => {
  const f = fixture(); await f.controller.call('installApplicationUpdate', {}); f.setClosing(true);
  await f.scheduled.shift()();
  await assert.rejects(f.completion, { code: 'APP_UPDATE_CLOSED' });
  assert.deepEqual(f.events, ['adapter', 'updater', 'persist-pointer']);
  assert.equal(f.controller.active, false); assert.equal(f.controller.quitAuthorized, false);
});

test('closing during arm aborts only that owned installer and never reaches shutdown', async () => {
  let f;
  f = fixture({ createAdapter: () => ({ arm: async () => {
    f.setClosing(true); return { abort: async () => f.events.push('abort'), commit: () => assert.fail('must not commit') };
  } }) });
  await f.controller.call('installApplicationUpdate', {}); await f.scheduled.shift()();
  await assert.rejects(f.completion, { code: 'APP_UPDATE_CLOSED' });
  assert.equal(f.events.includes('abort'), true); assert.equal(f.events.includes('shutdown-strict'), false);
  assert.equal(f.controller.quitAuthorized, false);
});

test('readiness refusal preserves open services and blocked cleanup prevents another install in snapshots', async () => {
  let phase = 'idle';
  const f = fixture({ createLifecycle: () => ({ get phase() { return phase; }, readiness: async () => ({ ready: false }),
    install: () => assert.fail('busy work cannot be stopped') }) });
  await f.controller.call('installApplicationUpdate', {}); await f.scheduled.shift()();
  await assert.rejects(f.completion, { code: 'APP_UPDATE_BUSY' });
  assert.equal(f.events.some(event => event.startsWith('arm:') || event === 'closing'), false);
  phase = 'blocked';
  const result = await f.controller.call('applicationUpdateStatus', {});
  assert.equal(result.canInstall, false); assert.equal(result.restartRequired, true);
});

test('failed cleanup aborts owned helper without granting quit authority', async () => {
  const f = fixture({ createLifecycle: options => ({ phase: 'blocked', readiness: async () => ({ ready: true }),
    install: async () => { options.beginClosing(); throw Object.assign(new Error('fixture'), { code: 'APP_UPDATE_CLEANUP' }); },
  }) });
  await f.controller.call('installApplicationUpdate', {}); await f.scheduled.shift()();
  await assert.rejects(f.completion, { code: 'APP_UPDATE_CLEANUP' });
  assert.equal(f.events.includes('abort'), true); assert.equal(f.events.includes('commit'), false);
  assert.equal(f.controller.quitAuthorized, false);
  assert.equal((await f.controller.call('applicationUpdateStatus', {})).restartRequired, true);
});

test('startup gate is supported-platform only and does not initialize the updater', async () => {
  for (const overrides of [{ packaged: false }, { platform: 'win32' }, { arch: 'x64' }]) {
    const f = fixture(overrides);
    assert.equal(await f.controller.beforeStartup({ checkOpen() {}, step: () => assert.fail('unsupported gate') }), true);
    assert.deepEqual(f.events, []);
  }
  const f = fixture();
  assert.equal(await f.controller.beforeStartup({ checkOpen() {}, step: async (name, operation) => {
    f.events.push(name); return operation();
  } }), true);
  assert.deepEqual(f.events, ['adapter', 'application-update']);
});

test('startup gate exits before desktop service initialization and only relaunches a replaced entry', async () => {
  const main = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const initialize = main.match(/async function initializeDesktopServices\(\{ checkOpen \}\) \{[\s\S]*?\n\}/)[0];
  for (const status of ['installer-active', 'restart-required']) {
    const f = fixture({ waitForStartup: async () => ({ status }) });
    const context = { app: { getPath: () => '/fixture-only' }, applicationUpdates: f.controller,
      startupStep: async (_name, operation) => operation(), mkdir: () => assert.fail('cannot initialize data or services while replacing'),
    };
    vm.runInNewContext(initialize, context);
    await context.initializeDesktopServices({ checkOpen() {} });
    assert.deepEqual(f.events, status === 'restart-required' ? ['adapter', 'relaunch', 'exit:0'] : ['adapter', 'exit:0']);
  }
});

test('main strict shutdown closes updater and cache before services without waiting for support exports', async () => {
  const main = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const declaration = main.match(/const shutdownOwnedServices = async[\s\S]*?\n\};/)[0];
  const events = [];
  const context = { applicationUpdates: { close: async () => events.push('updater') }, workspaceTools: { close: async () => events.push('cache') },
    shutdownDesktopServices: async ({ strict }) => { assert.equal(strict, true); events.push('services'); },
    ...Object.fromEntries(['applications', 'notionDiagnostics', 'terminal', 'terminalBrowserBroker', 'linkChannel', 'routerChannel',
      'service', 'sidecar', 'proxyCore', 'networkRecovery', 'runtimeDiagnostics'].map(name => [name, undefined])),
  };
  vm.runInNewContext(`${declaration}\nglobalThis.shutdown = shutdownOwnedServices`, context);
  await context.shutdown({ strict: true });
  assert.deepEqual(events, ['updater', 'cache', 'services']);
});
