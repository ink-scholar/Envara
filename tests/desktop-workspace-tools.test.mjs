import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { createDesktopWorkspaceTools } from '../electron/desktop-workspace-tools.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
function fixture(overrides = {}) {
  const events = [], queued = [];
  const state = { service: null, terminal: null, terminalController: null, applications: null, closing: false };
  let combinationOptions, runtimeOptions, cacheOptions, supportOptions;
  const support = deferred();
  const controller = createDesktopWorkspaceTools({ dataDir: '/fixture-only', appVersion: '1.2.3', platform: 'darwin', arch: 'arm64',
    getService: () => state.service, getTerminal: () => state.terminal, getTerminalController: () => state.terminalController,
    getApplications: () => state.applications, transferLock: { owned: true },
    fullWorkspaceSnapshot: async snapshot => ({ ...snapshot, complete: true }), isClosing: () => state.closing,
    showSaveDialog: async (caller, options) => ({ caller, options }), readStartup: () => 'startup', readRuntime: () => 'runtime',
    readRecovery: () => 'recovery', getNotionDiagnostics: () => ({ readExisting: async id => ({ id }) }),
    createSiteData: ({ getService }) => ({ list: async args => ({ service: getService(), args }), clear: async args => { events.push('clear-cookies'); return args; } }),
    createCombinations: options => { combinationOptions = options; events.push('create-combinations'); return {
      ready: Promise.resolve(), list: async args => ({ listed: args }), save: async args => ({ saved: args }),
      remove: async args => ({ removed: args }), open: async args => ({ opened: args }), removeProfile: async id => ({ removedProfile: id }),
    }; },
    createCacheMaintenance: options => { cacheOptions = options; events.push('create-cache'); return {
      inventory: async args => ({ inventory: args }), quarantine: async args => ({ quarantine: args }),
      restore: async args => ({ restore: args }), purge: async args => ({ purge: args }), close: async () => events.push('close-cache'),
    }; },
    createRuntimeVerification: options => { runtimeOptions = options; events.push('create-runtime'); return {
      runtimeVerificationSnapshot: async args => ({ snapshot: args }), checkRuntimeVerification: async args => ({ checked: args }),
    }; },
    readVersions: async options => options,
    exportDiagnostics: options => { supportOptions = options; events.push('export'); return support.promise; },
    ...overrides,
  });
  const loadServices = () => {
    state.service = { captureRuntimeVerificationContext() {}, snapshot: async () => ({ profiles: [{ id: 'profile-one' }] }),
      call: async (method, args) => ({ method, args }), profileSerialize: async (id, operation) => { events.push(`profile-lock:${id}`); return operation(); } };
    state.terminal = { ready: Promise.resolve(), root: '/fixture-only/terminals' };
    state.terminalController = { serialize: operation => { queued.push(operation); return operation(); } };
    state.applications = { applications: new Map([['fixture-app', { id: 'fixture-app' }]]) };
  };
  return { controller, events, state, queued, support, loadServices,
    get combinationOptions() { return combinationOptions; }, get cacheOptions() { return cacheOptions; },
    get runtimeOptions() { return runtimeOptions; }, get supportOptions() { return supportOptions; } };
}

test('unused tools and blocker getters do not create workspace stores or launch checks', async () => {
  const f = fixture();
  assert.equal(f.controller.workCombinations, null); assert.equal(f.controller.cacheMaintenance, null);
  assert.equal(f.controller.supportExportPending, false);
  for (const method of ['constructor', 'toString', 'close', 'getCombinations']) {
    assert.equal(f.controller.handles(method), false); await assert.rejects(f.controller.call(method, {}));
  }
  await assert.rejects(f.controller.call('componentVersions', { path: '/fixture-only' }));
  await assert.rejects(f.controller.call('exportSupportDiagnostics', []));
  await assert.rejects(f.controller.getCombinations(), { code: 'WORK_COMBINATION_PROFILE_UNAVAILABLE' });
  await f.controller.close(); assert.deepEqual(f.events, []);
});

test('combination mutations retain terminal serialization; listing and deletion hook remain lazy', async () => {
  const f = fixture(); f.loadServices();
  assert.deepEqual(await f.controller.call('listWorkCombinations', { profileId: 'profile-one' }), { listed: { profileId: 'profile-one' } });
  assert.equal(f.queued.length, 0);
  for (const [method, key] of [['saveWorkCombination', 'saved'], ['deleteWorkCombination', 'removed'], ['openWorkCombination', 'opened']]) {
    assert.deepEqual(await f.controller.call(method, { id: 'fixture' }), { [key]: { id: 'fixture' } });
  }
  assert.equal(f.queued.length, 3); assert.deepEqual(f.events, ['create-combinations']);
  assert.equal(f.combinationOptions.terminal, f.state.terminal);
  assert.deepEqual(await (await f.controller.getCombinations()).removeProfile('profile-one'), { removedProfile: 'profile-one' });
  f.state.service = { snapshot: async () => ({ profiles: [{ id: 'profile-two' }] }), call: async () => 'current-service' };
  assert.deepEqual(await f.combinationOptions.getProfile('profile-two'), { id: 'profile-two' });
  assert.equal(await f.combinationOptions.ensureBrowser('profile-two'), 'current-service');
});

test('cookie clear retains the selected profile lock and list resolves the current service', async () => {
  const f = fixture(); f.loadServices();
  assert.equal((await f.controller.call('listBrowserSiteData', {})).service, f.state.service);
  const args = { profileId: 'profile-one', site: 'fixture.invalid' };
  assert.equal(await f.controller.call('clearBrowserSiteCookies', args), args);
  assert.deepEqual(f.events, ['profile-lock:profile-one', 'clear-cookies']);
  f.state.service = {};
  assert.equal((await f.controller.call('listBrowserSiteData', {})).service, f.state.service);
  await f.controller.call('clearBrowserSiteCookies', args);
  assert.deepEqual(f.events, ['profile-lock:profile-one', 'clear-cookies', 'clear-cookies']);
});

test('runtime checks and cache actions initialize only on demand with the available services', async () => {
  const f = fixture(); f.loadServices();
  f.state.service.captureRuntimeVerificationContext = undefined;
  await assert.rejects(f.controller.call('checkRuntimeVerification', { id: 'profile-one' }), { code: 'RUNTIME_VERIFICATION_UNAVAILABLE' });
  assert.deepEqual(f.events, []);
  f.state.service.captureRuntimeVerificationContext = () => {};
  assert.deepEqual(await f.controller.call('runtimeVerificationSnapshot', {}), { snapshot: {} });
  assert.deepEqual(await f.controller.call('checkRuntimeVerification', { id: 'profile-one' }), { checked: { id: 'profile-one' } });
  assert.equal(f.runtimeOptions.browserService, f.state.service); assert.equal(f.runtimeOptions.terminalService, f.state.terminal);
  for (const [method, key] of [['cacheMaintenanceInventory', 'inventory'], ['quarantineBrowserCaches', 'quarantine'],
    ['restoreBrowserCaches', 'restore'], ['purgeBrowserCacheBatch', 'purge']]) {
    assert.deepEqual(await f.controller.call(method, { id: 'fixture' }), { [key]: { id: 'fixture' } });
  }
  assert.equal(f.cacheOptions.service, f.state.service); assert.equal(f.cacheOptions.terminal, f.state.terminal);
  assert.equal(f.cacheOptions.applications, f.state.applications); assert.equal(f.cacheOptions.transferLock.owned, true);
  await f.controller.close(); assert.deepEqual(f.events, ['create-runtime', 'create-cache', 'close-cache']);
});

test('component versions uses the full current workspace snapshot and rejects paths before reading', async () => {
  const f = fixture(); f.loadServices();
  await assert.rejects(f.controller.call('componentVersions', { path: '/fixture-only' }));
  const value = await f.controller.call('componentVersions', {});
  assert.equal(value.terminal, f.state.terminal); assert.equal(value.snapshot.complete, true);
  assert.deepEqual(value.snapshot.profiles, [{ id: 'profile-one' }]);
  assert.deepEqual(f.events, []);
});

test('diagnostic export remains single flight, bound to the first caller, and does not block close', async () => {
  const f = fixture(); f.loadServices(); let destroyed = false;
  const firstCaller = { isDestroyed: () => destroyed }, otherCaller = { isDestroyed: () => false };
  const first = f.controller.call('exportSupportDiagnostics', {}, firstCaller);
  const second = f.controller.call('exportSupportDiagnostics', {}, otherCaller);
  assert.deepEqual(f.events, ['export']); assert.equal(f.controller.supportExportPending, true);
  const options = f.supportOptions;
  assert.equal((await options.showSaveDialog({ title: 'fixture' })).caller, firstCaller);
  assert.equal(await options.readers.startup(), 'startup'); assert.equal(await options.readers.runtime(), 'runtime');
  assert.equal(await options.readers.recovery(), 'recovery');
  f.state.applications = { applications: new Map([['later-app', { id: 'later-app' }]]) };
  assert.deepEqual(await options.readers.applications(), [{ id: 'later-app' }]);
  options.checkOpen(); destroyed = true; assert.throws(options.checkOpen, { code: 'APP_CLOSING' });
  destroyed = false; f.state.closing = true; assert.throws(options.checkOpen, { code: 'APP_CLOSING' });
  await f.controller.close(); assert.equal(f.controller.supportExportPending, true);
  f.support.resolve({ canceled: true });
  assert.deepEqual(await first, { canceled: true }); assert.deepEqual(await second, { canceled: true });
  assert.equal(f.controller.supportExportPending, false);
  await f.controller.call('exportSupportDiagnostics', {}, otherCaller);
  assert.deepEqual(f.events, ['export', 'export']);
});

test('shipped main keeps its allowlist and delegates caller authority only for explicit workspace tool methods', async () => {
  const source = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const allowed = source.match(/const allowedMethods = new Set\(\[[\s\S]*?\n\]\);/)[0];
  const handler = source.match(/async function handleCall\([\s\S]*?\n\}/)[0];
  const f = fixture(); f.loadServices();
  const caller = { isDestroyed: () => false };
  const context = { quitting: false, window: caller, TERMINAL_METHODS: new Set(),
    applicationUpdates: { active: false, handles: () => false }, workspaceTools: f.controller };
  vm.runInNewContext(`${allowed}\n${handler}`, context);
  await assert.rejects(context.handleCall('constructor', {}));
  await assert.rejects(context.handleCall('componentVersions', { url: 'https://fixture.invalid' }));
  assert.equal((await context.handleCall('componentVersions', {})).snapshot.complete, true);
  const pending = context.handleCall('exportSupportDiagnostics', {});
  assert.equal((await f.supportOptions.showSaveDialog({})).caller, caller);
  context.quitting = true;
  await assert.rejects(context.handleCall('listWorkCombinations', {}), { code: 'APP_CLOSING' });
  f.support.resolve({ canceled: true }); await pending;
});
