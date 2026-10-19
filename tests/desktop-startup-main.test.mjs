import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { createDesktopStartup } from '../electron/desktop-startup.mjs';
import { createOwnedQuitController, createWorkspaceWindowController } from '../electron/desktop-lifecycle.mjs';
import { createInterfaceLanguageController } from '../src/interface-language-state.mjs';
import { terminalViewSnapshot } from '../electron/terminal-view.mjs';
import { registerDesktopIPC } from '../electron/desktop-ipc.mjs';
import { shutdownDesktopServices } from '../electron/desktop-services.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
const main = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
const preload = await readFile(new URL('../electron/preload.cjs', import.meta.url), 'utf8');
const snapshot = () => ({ profiles: [], proxies: [], settings: { language: 'ja' }, system: { platform: 'darwin', appVersion: 'fixture' } });

function shutdownFixture(overrides) {
  const context = { applications: null, diagnostics: null, terminal: null, terminalBrowserBroker: null,
    linkChannel: null, routerChannel: null, service: null, sidecar: null, proxyCore: null, ...overrides };
  return () => shutdownDesktopServices(context);
}

// Exercise the shipped handler and preload without loading Electron's main entry.
function fixture({ initialize = async () => {} } = {}) {
  const events = [], calls = [], handlers = new Map(), listeners = new Map();
  const startup = createDesktopStartup({ initialize });
  const view = { destroyed: false, isDestroyed() { return this.destroyed; }, isMinimized: () => false, show() { events.push('window-show'); }, focus() {} };
  const sender = { mainFrame: {}, isDestroyed: () => view.destroyed }, event = { sender, senderFrame: sender.mainFrame };
  view.webContents = sender;
  const views = new Map([[sender, { window: view, kind: 'workspace' }]]);
  const context = {
    views,
    quitting: false, requestEpoch: 0,
    ipcMain: { handle(name, callback) { handlers.set(name, callback); events.push('ipc-ready'); } },
    terminal: { snapshot: async () => ({ profiles: [] }) }, applications: {},
    environmentTransferLock: { mutate: async (_method, _args, operation) => operation() },
    fullWorkspaceSnapshot: async value => value,
    handleCall: async (method, args) => { calls.push({ method, args }); return method === 'snapshot' ? snapshot() : { method }; },
  };
  registerDesktopIPC({ ipcMain: context.ipcMain, views, startup,
    lifecycle: () => context, services: () => context,
    transferLock: { mutate: (...args) => context.environmentTransferLock.mutate(...args) },
    handleCall: (...args) => context.handleCall(...args),
    fullWorkspaceSnapshot: (...args) => context.fullWorkspaceSnapshot(...args) });
  let api;
  vm.runInNewContext(preload, { require(name) {
    assert.equal(name, 'electron');
    return { contextBridge: { exposeInMainWorld(name, value) { assert.equal(name, 'envara'); api = value; } },
      ipcRenderer: {
        invoke: (name, request) => handlers.get(name)(event, request),
        on(name, callback) { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name).add(callback); },
        removeListener(name, callback) { listeners.get(name)?.delete(callback); },
      } };
  } }, { filename: 'preload-fixture.cjs' });
  let currentWindow = null;
  const window = createWorkspaceWindowController({ current: () => currentWindow,
    canOpen: () => !context.quitting,
    create: async () => { events.push('window-create'); currentWindow = view; return view; } });
  return { api, startup, events, calls, view, event, views, context, window,
    emit(value) { for (const callback of listeners.get('envara:snapshot') ?? []) callback({}, value); } };
}

test('the real IPC/preload keep both initial settings reads pending behind a visible loading window', async () => {
  const hold = deferred(); const f = fixture({ initialize: async () => hold.promise });
  const language = createInterfaceLanguageController({ api: f.api, preferences: ['en-US'] });
  language.start();
  const workspace = f.api.call('snapshot');
  f.startup.start(); f.window.markReady(); await f.window.open(); await turn();
  assert.deepEqual(f.events, ['ipc-ready', 'window-create']);
  assert.equal(f.startup.phase, 'starting');
  assert.equal(language.getState().phase, 'loading');
  assert.equal(language.getState().error, null);
  assert.equal(f.calls.length, 0, 'Settings cannot be read from partly constructed services');
  await assert.rejects(f.api.call('startProfile', { id: 'fixture' }), error => error.code === 'APP_STARTING');
  assert.equal(f.calls.length, 0, 'A refused action must never be queued');
  hold.resolve();
  assert.equal((await workspace).settings.language, 'ja'); await turn();
  assert.equal(language.getState().phase, 'ready'); assert.equal(language.getState().language, 'ja');
  assert.deepEqual(f.calls.map(item => item.method), ['snapshot', 'snapshot']);
  language.stop();
});

test('the actual Electron-ready entry opens its window and installs IPC without awaiting held backend stages', async () => {
  const electronReady = deferred(), backend = deferred();
  const f = fixture({ initialize: async () => { f.events.push('backend-start'); await backend.promise; } });
  const entry = main.slice(main.indexOf("if (ownsLock) void startupStep('electron-ready'"));
  assert.match(entry, /^if \(ownsLock\)/);
  f.events.length = 0;
  const context = {
    ...f.context,
    ownsLock: true, quitting: false, desktopStartup: f.startup, workspaceWindow: f.window,
    startupStep: async (_name, operation) => operation(),
    app: { whenReady: () => electronReady.promise },
    registerDesktopIPC: () => f.events.push('ipc-ready'),
    Menu: { buildFromTemplate: value => value, setApplicationMenu() {} },
    process: { platform: 'linux' }, startupDiagnostics: null,
    reportStartupFailure: error => assert.fail(error.message),
    publish: async () => f.events.push('published'),
    isSmoke: true, isWorkspaceSmoke: false,
    setInterval: () => ({ unref() {} }),
  };
  vm.runInNewContext(entry, context, { filename: 'main-electron-ready-fixture.mjs' });
  assert.deepEqual(f.events, []);
  electronReady.resolve(); await turn();
  assert.ok(f.events.includes('ipc-ready')); assert.ok(f.events.includes('window-create'));
  assert.ok(f.events.indexOf('ipc-ready') < f.events.indexOf('window-create'));
  assert.ok(f.events.includes('backend-start'));
  assert.equal(f.startup.phase, 'starting');
  assert.ok(!f.events.includes('published'), 'No snapshot is published from partly initialized services');
  backend.resolve(); await f.startup.ready; await turn();
  assert.ok(f.events.includes('published'));
});

test('the actual publish callback suppresses partial settings snapshots while backend readiness is pending', async () => {
  const hold = deferred(), f = fixture({ initialize: async () => hold.promise });
  const declaration = main.match(/async function publish\(\) \{[\s\S]*?\n\}/);
  assert.ok(declaration);
  let reads = 0, sends = 0;
  const context = {
    desktopStartup: f.startup, quitting: false, requestEpoch: 0, publishing: false, needsPublish: false,
    service: { snapshot: async () => { reads++; return snapshot(); } },
    views: new Map([[{}, { window: { isDestroyed: () => false, webContents: { send() { sends++; } } }, kind: 'workspace' }]]),
    fullWorkspaceSnapshot: async value => value, terminalViewSnapshot, console,
  };
  vm.runInNewContext(declaration[0], context, { filename: 'main-publish-fixture.mjs' });
  f.startup.start();
  await context.publish();
  assert.equal(reads, 0); assert.equal(sends, 0);
  hold.resolve(); await f.startup.ready;
  await context.publish();
  assert.equal(reads, 1); assert.equal(sends, 1);
  const lateSnapshot = deferred();
  context.service.snapshot = async () => { reads++; await lateSnapshot.promise; return snapshot(); };
  const pending = context.publish(); await turn();
  context.quitting = true; context.requestEpoch++; context.quitting = false;
  lateSnapshot.resolve(); await pending;
  assert.equal(sends, 1, 'A snapshot from before a failed quit cannot be published after quitting resets');
  await context.publish();
  assert.equal(sends, 2, 'New requests remain available after cleanup failure');
});

test('terminal bootstrap reads wait too, while pre-ready writes fail and are never replayed', async () => {
  const hold = deferred(), f = fixture({ initialize: async () => hold.promise });
  f.startup.start();
  const reading = f.api.call('terminalSnapshot');
  await turn(); assert.equal(f.calls.length, 0);
  await assert.rejects(f.api.call('saveSettings', { settings: { language: 'de' } }), error => error.code === 'APP_STARTING');
  await assert.rejects(f.api.call('openTerminal', { id: 'fixture' }), error => error.code === 'APP_STARTING');
  hold.resolve();
  assert.equal((await reading).method, 'terminalSnapshot');
  assert.deepEqual(f.calls.map(item => item.method), ['terminalSnapshot']);
});

test('an independent terminal window cannot dispatch workspace actions or another environment session', async () => {
  const f = fixture();
  Object.assign(f.views.get(f.event.sender), { kind: 'terminal', profileId: 'prof_fixture' });
  f.context.terminal.snapshot = async ({ id }) => {
    assert.equal(id, 'prof_fixture');
    return { profiles: [{ sessions: [{ sessionId: 'owned-session' }] }] };
  };
  await f.startup.start();
  await assert.rejects(f.api.call('createProfile'), /此窗口仅支持终端操作/);
  await assert.rejects(f.api.call('openTerminal', { id: 'other-profile' }), /此窗口仅操作当前环境/);
  await assert.rejects(f.api.call('deleteClaudeAccount', { id: 'other-profile', accountId: 'selected', confirmed: true }), /此窗口仅操作当前环境/);
  await assert.rejects(f.api.call('closeTerminal', { sessionId: 'other-session' }), /该会话不属于此终端窗口/);
  assert.equal(f.calls.length, 0);
  await f.api.call('writeTerminal', { sessionId: 'owned-session', data: 'fixture' });
  assert.deepEqual(f.calls.map(item => item.method), ['writeTerminal']);
  await f.api.call('deleteClaudeAccount', { id: 'prof_fixture', accountId: 'selected', confirmed: true });
  assert.equal(f.calls.at(-1).method, 'deleteClaudeAccount');
  f.event.senderFrame = {};
  await assert.rejects(f.api.call('deleteClaudeAccount', { id: 'prof_fixture', accountId: 'selected', confirmed: true }), /不允许的请求来源/);
  assert.equal(f.calls.length, 2);
});

test('all SSH connection actions remain inside the independent terminal window environment', async () => {
  const f = fixture();
  Object.assign(f.views.get(f.event.sender), { kind: 'terminal', profileId: 'prof_fixture' });
  await f.startup.start();
  const methods = ['listTerminalSshConnections', 'prepareTerminalSshIdentity', 'prepareTerminalSshPassword', 'setTerminalSshPassword', 'saveTerminalSshConnection', 'removeTerminalSshConnection'];
  for (const method of methods) {
    await assert.rejects(f.api.call(method, { id: 'other-profile' }), /此窗口仅操作当前环境/);
    await assert.rejects(f.api.call(method, {}), /此窗口仅操作当前环境/);
  }
  assert.equal(f.calls.length, 0);
  for (const method of methods) await f.api.call(method, { id: 'prof_fixture' });
  assert.deepEqual(f.calls.map(item => item.method), methods);
  f.event.senderFrame = {};
  await assert.rejects(f.api.call('prepareTerminalSshIdentity', { id: 'prof_fixture' }), /不允许的请求来源/);
  assert.equal(f.calls.length, methods.length);
});

test('terminal bootstrap uses its bound environment and workspace snapshots omit proxy credentials', async () => {
  const f = fixture();
  Object.assign(f.views.get(f.event.sender), { kind: 'terminal', profileId: 'prof_fixture' });
  await f.startup.start();
  await f.api.call('terminalSnapshot', { id: 'other-profile' });
  assert.deepEqual(f.calls[0].args, { id: 'prof_fixture' });
  f.context.handleCall = async () => ({ ...snapshot(), proxies: [{ password: 'fixture-only-password' }],
    profiles: [{ id: 'prof_fixture', name: 'Fixture', proxyPassword: 'fixture-only-password' }] });
  const value = await f.api.call('snapshot');
  assert.deepEqual(value.proxies, []);
  assert.equal(value.profiles[0].id, 'prof_fixture');
  assert.equal(value.profiles[0].proxyPassword, undefined);
});

test('a queued snapshot must revalidate its sender after backend initialization', async () => {
  const hold = deferred(), f = fixture({ initialize: async () => hold.promise });
  f.startup.start();
  const reading = f.api.call('snapshot');
  await turn(); f.view.destroyed = true; f.views.delete(f.event.sender); hold.resolve();
  await assert.rejects(reading);
  assert.equal(f.calls.length, 0, 'A closed renderer must not operate on newly ready services');
});

test('a source that closes while its ready-state action waits for the transfer lock cannot launch later', async () => {
  const f = fixture(), transfer = deferred();
  await f.startup.start();
  f.context.environmentTransferLock = { mutate: async (_method, _args, operation) => { await transfer.promise; return operation(); } };
  const action = f.api.call('startProfile', { id: 'fixture' });
  await turn(); f.view.destroyed = true; f.views.delete(f.event.sender); transfer.resolve();
  await assert.rejects(action);
  assert.equal(f.calls.length, 0, 'Rejecting the late response cannot undo an already executed launch');
});

test('a failed quit invalidates older snapshots and locked actions even when the same source remains open', async () => {
  const f = fixture(), response = deferred(), transfer = deferred();
  await f.startup.start();
  f.context.environmentTransferLock = { mutate: async (method, _args, operation) => {
    if (method === 'startProfile') await transfer.promise;
    return operation();
  } };
  f.context.handleCall = async method => { f.calls.push({ method }); await response.promise; return snapshot(); };
  const oldSnapshot = f.api.call('snapshot'), oldAction = f.api.call('startProfile', { id: 'fixture' });
  await turn();
  f.context.quitting = true; f.context.requestEpoch++; f.context.quitting = false;
  const refused = Promise.all([
    assert.rejects(oldSnapshot, error => error.code === 'APP_CLOSING'),
    assert.rejects(oldAction, error => error.code === 'APP_CLOSING'),
  ]);
  response.resolve(); transfer.resolve(); await refused;
  assert.deepEqual(f.calls.map(item => item.method), ['snapshot'], 'The old action must never execute after cleanup failure');
  assert.equal((await f.api.call('snapshot')).settings.language, 'ja');
  assert.deepEqual(f.calls.map(item => item.method), ['snapshot', 'snapshot']);
});

test('closing during initialization blocks later allocations and repeated quits wait for complete cleanup', async () => {
  const hold = deferred(), events = []; let quitting = false, prevented = 0, cleaned = false;
  const f = fixture({ initialize: async ({ checkOpen }) => {
    events.push('allocate-first'); await hold.promise; checkOpen(); events.push('allocate-second');
  } });
  f.startup.start(); await turn();
  const quit = createOwnedQuitController({ hasResources: () => f.startup.phase === 'starting' || !cleaned,
    startup: () => f.startup.settled,
    onStateChange: value => { quitting = value; if (value) f.startup.close(); },
    shutdown: async () => { events.push('cleanup-first'); cleaned = true; },
    quit: () => events.push('quit'), onFailure: error => assert.fail(error.message) });
  const event = { preventDefault() { prevented++; } };
  const first = quit.handle(event), second = quit.handle(event);
  await turn();
  assert.equal(quitting, true); assert.equal(prevented, 2);
  assert.deepEqual(events, ['allocate-first']);
  hold.resolve(); await Promise.all([first, second]);
  assert.deepEqual(events, ['allocate-first', 'cleanup-first', 'quit']);
  assert.equal(f.startup.phase, 'closing');
});

test('the actual initialization stage wrapper checks shutdown before creating the next service', async () => {
  const hold = deferred(), events = [];
  const declaration = main.match(/async function initializeDesktopServices\(\{ checkOpen \}\) \{[\s\S]*?\n\}/);
  assert.ok(declaration);
  const context = {
    app: { getPath: () => '/fixture-only' },
    startupStep: async (_name, operation) => operation(),
    mkdir: async () => { events.push('mkdir-start'); await hold.promise; events.push('mkdir-finished'); },
    SignInDataNames: class { constructor() { events.push('next-service'); } },
  };
  vm.runInNewContext(declaration[0], context, { filename: 'main-initialize-fixture.mjs' });
  const startup = createDesktopStartup({ initialize: context.initializeDesktopServices });
  startup.start(); await turn();
  const closing = startup.close();
  hold.resolve(); await closing;
  assert.deepEqual(events, ['mkdir-start', 'mkdir-finished']);
  assert.equal(startup.phase, 'closing');
});

test('a failed backend preserves its error through the real bridge and never blocks the cleanup barrier', async () => {
  const error = Object.assign(new Error('fixture backend unavailable'), { code: 'FIXTURE_BACKEND_FAILED' });
  const f = fixture({ initialize: () => { throw error; } });
  const reading = f.api.call('snapshot'); f.startup.start();
  await assert.rejects(reading, actual => actual.code === error.code && actual.message === error.message);
  await f.startup.settled;
  assert.equal(f.startup.phase, 'failed'); assert.equal(f.calls.length, 0);
  const events = [];
  const quit = createOwnedQuitController({ hasResources: () => true, startup: () => f.startup.settled,
    shutdown: async () => events.push('cleanup'), onStateChange() {}, onFailure: failure => assert.fail(failure.message), quit: () => events.push('quit') });
  await quit.handle({ preventDefault() {} });
  assert.deepEqual(events, ['cleanup', 'quit']);
});

test('the actual shutdown closes the owned backend when workspace initialization itself rejected', async () => {
  const events = [], error = Object.assign(new Error('fixture workspace store failed'), { code: 'FIXTURE_STORAGE_FAILED' });
  const service = { ready: Promise.reject(error),
    shutdown: async () => { assert.fail('Normal consumer shutdown would repeat the failed workspace load'); },
    networkProbe: { close() { events.push('network-probe'); } } };
  const shutdown = shutdownFixture({ service,
    sidecar: { shutdown: async () => events.push('sidecar') }, proxyCore: { close: async () => events.push('proxy-core') } });
  const startup = createDesktopStartup({ initialize: async () => service.ready });
  await assert.rejects(startup.start(), actual => actual === error);
  const quit = createOwnedQuitController({ hasResources: () => true, startup: () => startup.settled, shutdown,
    onStateChange() {}, onFailure: actual => assert.fail(`Initialization must not prevent cleanup: ${actual.message}`), quit: () => events.push('quit') });
  await quit.handle({ preventDefault() {} });
  assert.deepEqual(events, ['network-probe', 'sidecar', 'proxy-core', 'quit']);
});

test('the actual shutdown can clean remaining resources after the application store rejected before consumers existed', async () => {
  const events = [], error = new Error('fixture application store failed');
  const applications = { ready: Promise.reject(error), shutdown: async () => { await applications.ready; } };
  const shutdown = shutdownFixture({ applications,
    terminal: { shutdown: async () => events.push('terminal') },
    linkChannel: { close: async () => events.push('terminal-links') }, routerChannel: { close: async () => events.push('system-links') },
    service: { ready: Promise.resolve(), shutdown: async () => events.push('service') },
    proxyCore: { close: async () => events.push('proxy-core') } });
  await shutdown();
  assert.deepEqual(events, ['terminal', 'terminal-links', 'system-links', 'service', 'proxy-core']);
});

test('a genuine attached-application cleanup failure still retains its network and later owned resources', async () => {
  const error = new Error('fixture native cleanup uncertain'), events = [];
  const shutdown = shutdownFixture({ applications: { ready: Promise.resolve(), shutdown: async () => { throw error; } },
    terminal: { shutdown: async () => events.push('terminal') }, sidecar: { shutdown: async () => events.push('sidecar') },
    proxyCore: { close: async () => events.push('proxy-core') } });
  await assert.rejects(shutdown(), actual => actual === error);
  assert.deepEqual(events, []);
});

test('the existing loading shell remains noninteractive until real settings arrive', async () => {
  const [app, welcome] = await Promise.all([
    readFile(new URL('../src/App.jsx', import.meta.url), 'utf8'), readFile(new URL('../src/LanguageWelcome.jsx', import.meta.url), 'utf8'),
  ]);
  assert.match(app, /const initializing = phase !== "ready"/);
  assert.match(app, /inert=\{initializing \? true : undefined\}/);
  assert.match(welcome, /if \(phase === 'loading'\).*role="status"/);
});

test('independent terminal saved-entry operations retain their bound environment scope', async () => {
  const f = fixture(); f.startup.start(); await f.startup.ready;
  f.views.set(f.event.sender, { window: f.view, kind: 'terminal', profileId: 'prof_fixture' });
  for (const method of ['reopenSavedTerminal', 'renameSavedTerminal', 'removeSavedTerminal']) {
    await assert.rejects(f.api.call(method, { id: 'another-profile', entryId: 'savedterm_1234567890abcdef1234567890abcdef' }), /此窗口仅操作当前环境/);
    assert.equal(f.calls.length, 0);
    await f.api.call(method, { id: 'prof_fixture', entryId: 'savedterm_1234567890abcdef1234567890abcdef' });
    assert.equal(f.calls.pop().method, method);
  }
});
