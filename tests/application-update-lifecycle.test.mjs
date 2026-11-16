import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createApplicationUpdateLifecycle } from '../electron/application-update-lifecycle.mjs';
import { DesktopEnvironmentTransferLock } from '../electron/environment-import-lifecycle.mjs';
import { shutdownDesktopServices } from '../electron/desktop-services.mjs';
import { TerminalController } from '../electron/terminal-controller.mjs';
import { TerminalBrowserBroker } from '../electron/terminal-browser-broker.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
function fixture() {
  const events = [], token = 'a'.repeat(64), remote = { sessions: [] };
  const resources = {
    service: { closed: false, starting: new Set(), profileQueues: new Map(), remote: async () => { events.push('read'); return remote; },
      request: async (_method, route, args) => { events.push(route.endsWith('acquire') ? 'acquire' : 'release'); if (route.endsWith('release')) assert.equal(args.token, token); return { data: route.endsWith('acquire') ? { token } : { released: true } }; } },
    terminal: { closed: false, sessions: new Map(), profileQueues: new Map(), pendingClaudeStarts: new Map() },
    applications: { closed: false, sessions: new Map(), routing: { controlledNotionTrialSnapshot: () => null } },
    sidecar: { closed: false, process: { owned: true }, installations: new Map(), commands: new Set() },
    transferLock: new DesktopEnvironmentTransferLock(), pendingImports: new Map(),
    terminalController: { pendingCount: 0, attachments: { transfers: new Map() } },
    workCombinations: { requests: new Map() }, cacheMaintenance: { pendingCount: 0 },
  };
  const callbacks = {
    getResources: () => resources,
    beginClosing: () => events.push('closing'), restoreOpen: () => events.push('restored'),
    shutdown: async options => { assert.deepEqual(options, { strict: true }); events.push('shutdown'); for (const key of ['service', 'terminal', 'applications', 'sidecar']) resources[key].closed = true; resources.sidecar.process = null; },
    authorizeInstall: async () => { events.push('commit'); }, quit: async () => { events.push('quit'); },
    onPhaseChange: value => events.push(value.phase),
  };
  return { resources, remote, events, callbacks, token, create: () => createApplicationUpdateLifecycle(callbacks) };
}

test('update readiness only reads state and exposes counts, never names, credentials or filesystem paths', async () => {
  const f = fixture(), gate = f.create();
  assert.deepEqual(await gate.readiness(), { ready: true, phase: 'idle', blockers: [] });
  assert.deepEqual(f.events, ['read']);
  f.remote.sessions.push({ profile_id: 'private-profile', endpoint: 'private-credential' });
  const result = await gate.readiness();
  assert.deepEqual(result.blockers, [{ code: 'browsers', count: 1 }]);
  assert.doesNotMatch(JSON.stringify(result), /private/);
  assert.deepEqual(f.events, ['read', 'read']);
});

test('every local activity refuses update before closing services or terminating sessions', async t => {
  const cases = {
    terminal: r => r.terminal.sessions.set('owned', { status: 'running', finished: false }),
    terminalCleanup: r => r.terminal.sessions.set('owned', { status: 'closed', finished: true, cleanupError: 'uncertain' }),
    application: r => r.applications.sessions.set('owned', { status: 'running' }),
    applicationCleanup: r => r.applications.sessions.set('owned', { status: 'error', routeId: 'retained-route' }),
    trial: r => { r.notionTrialReserved = true; },
    transfer: r => { r.transferLock.transferring = true; },
    mutation: r => { r.transferLock.mutations = 1; },
    import: r => r.pendingImports.set('owned', { busy: false }),
    installing: r => { r.service.installingEngine = 'cloakbrowser'; },
    installCommand: r => r.sidecar.commands.add({ owned: true }),
    missingOwnedBackend: r => { r.sidecar.process = null; },
    picker: r => { r.terminalController.pendingCount = 1; },
    start: r => r.service.starting.add('owned'),
    profileOperation: r => r.service.profileQueues.set('owned', Promise.resolve()),
    accountReservation: r => r.terminal.pendingClaudeStarts.set('owned', 1),
    attachment: r => r.terminalController.attachments.transfers.set('owned', {}),
    combination: r => r.workCombinations.requests.set('owned', { completed: false }),
    maintenance: r => { r.cacheMaintenance.pendingCount = 1; },
    broker: r => { r.terminalBrowserBroker = { sessions: new Map([['owned', {}]]) }; },
    unknownOperation: r => { r.extraBusy = true; },
  };
  for (const [name, change] of Object.entries(cases)) await t.test(name, async () => {
    const f = fixture(); change(f.resources); const gate = f.create();
    const before = [...f.resources.terminal.sessions.entries()];
    await assert.rejects(gate.install(), { code: 'APP_UPDATE_BUSY', restartRequired: false });
    assert.equal(gate.phase, 'idle'); assert.deepEqual(f.events, []);
    assert.deepEqual([...f.resources.terminal.sessions.entries()], before);
  });
});

test('idle installation closes local admission synchronously, shares repeated clicks, then commits only after strict shutdown', async () => {
  const f = fixture(), read = deferred(); f.resources.service.remote = () => read.promise;
  const gate = f.create(), first = gate.install();
  assert.deepEqual(f.events, ['admitting', 'closing']); assert.equal(gate.install(), first);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.resources.transferLock.transferring, true);
  await assert.rejects(f.resources.transferLock.mutate('openTerminal', {}, () => assert.fail('late launch executed')), { code: 'ENVIRONMENT_TRANSFER_BUSY' });
  read.resolve(f.remote);
  assert.deepEqual(await first, { accepted: true });
  assert.deepEqual(f.events, ['admitting', 'closing', 'acquire', 'shutting-down', 'shutdown', 'commit', 'authorized', 'quit']);
  assert.equal(f.resources.transferLock.transferring, false);
  await assert.rejects(gate.install(), { code: 'APP_UPDATE_CLEANUP', restartRequired: true });
  assert.equal(f.events.filter(value => value === 'commit').length, 1);
});

test('a browser appearing before atomic backend admission rejects without closing it and restores local admission', async () => {
  const f = fixture(); f.remote.sessions.push({ profile_id: 'owned' }); const gate = f.create();
  await assert.rejects(gate.install(), { code: 'APP_UPDATE_BUSY', restartRequired: false });
  assert.deepEqual(f.events, ['admitting', 'closing', 'read', 'restored', 'idle']);
  assert.equal(f.remote.sessions.length, 1);
});

test('a definite backend busy refusal is reversible, while unknown acquisition cannot invent an unlock token', async t => {
  for (const scenario of ['busy', 'timeout', 'malformed']) await t.test(scenario, async () => {
    const f = fixture(); f.resources.service.request = async () => {
      f.events.push('acquire');
      if (scenario === 'malformed') return { data: { token: 'not-a-token' } };
      throw Object.assign(new Error('private provider detail'), { code: scenario === 'busy' ? 'UPDATE_MAINTENANCE_BUSY' : 'TIMEOUT' });
    };
    const gate = f.create();
    await assert.rejects(gate.install(), error => {
      assert.equal(error.code, scenario === 'busy' ? 'APP_UPDATE_BUSY' : 'APP_UPDATE_CLEANUP');
      assert.equal(error.restartRequired, scenario !== 'busy'); assert.doesNotMatch(error.message, /private/); return true;
    });
    assert.equal(gate.phase, scenario === 'busy' ? 'idle' : 'blocked');
    assert.equal(f.events.includes('shutdown'), false); assert.equal(f.events.includes('release'), false);
    assert.equal(f.events.includes('restored'), scenario === 'busy');
  });
});

test('activity found after acquiring the lease releases only that token and never stops the new session', async () => {
  const f = fixture(), request = f.resources.service.request;
  f.resources.service.request = async (...args) => {
    const result = await request(...args);
    if (args[1].endsWith('acquire')) f.resources.terminal.sessions.set('owned', { status: 'running', finished: false });
    return result;
  };
  const gate = f.create(); await assert.rejects(gate.install(), { code: 'APP_UPDATE_BUSY', restartRequired: false });
  assert.ok(f.events.includes('release')); assert.ok(f.events.includes('restored')); assert.equal(f.events.includes('shutdown'), false);
  assert.equal(f.resources.terminal.sessions.get('owned').status, 'running');
});

test('failed release keeps local admission blocked and withholds installer authority', async () => {
  const f = fixture(); f.resources.service.request = async (_method, route) => {
    if (route.endsWith('release')) return { data: { released: false } };
    f.resources.extraBusy = true; return { data: { token: f.token } };
  };
  const gate = f.create(); await assert.rejects(gate.install(), { code: 'APP_UPDATE_CLEANUP', restartRequired: true });
  assert.equal(gate.phase, 'blocked'); assert.equal(f.events.includes('restored'), false); assert.equal(f.events.includes('commit'), false);
});

test('strict shutdown failure or an unconfirmed process never authorizes replacement or pretends services reopened', async t => {
  for (const scenario of ['throw', 'process-remains', 'terminal-remains']) await t.test(scenario, async () => {
    const f = fixture(), shutdown = f.callbacks.shutdown;
    f.callbacks.shutdown = async options => {
      await shutdown(options);
      if (scenario === 'throw') throw new Error('private shutdown path');
      if (scenario === 'process-remains') f.resources.sidecar.process = { owned: true };
      if (scenario === 'terminal-remains') f.resources.terminal.sessions.set('owned', { finished: false, status: 'closing' });
    };
    const gate = f.create(); await assert.rejects(gate.install(), { code: 'APP_UPDATE_CLEANUP', restartRequired: true });
    assert.equal(gate.phase, 'blocked');
    for (const event of ['commit', 'quit', 'restored', 'release']) assert.equal(f.events.includes(event), false, event);
  });
});

test('installer authorization failure preserves application and account files and never calls quit', async t => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'envara-update-lifecycle-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const files = [path.join(root, 'application'), path.join(root, 'account-config')];
  await Promise.all(files.map(file => writeFile(file, 'synthetic retained data')));
  const f = fixture(); f.callbacks.authorizeInstall = async () => { throw new Error('fixture helper unavailable'); };
  const gate = f.create(); await assert.rejects(gate.install(), { code: 'APP_UPDATE_INSTALL_FAILED', restartRequired: true });
  assert.equal(gate.phase, 'blocked'); assert.equal(f.events.includes('quit'), false);
  assert.deepEqual(await Promise.all(files.map(file => readFile(file, 'utf8'))), ['synthetic retained data', 'synthetic retained data']);
});

test('strict desktop shutdown propagates each previously optional failure before releasing later resources', async t => {
  for (const failing of ['terminal', 'broker', 'links', 'router', 'backend']) await t.test(failing, async () => {
    const events = [], fault = new Error('owned cleanup failed');
    const action = name => async () => { events.push(name); if (name === failing) throw fault; };
    await assert.rejects(shutdownDesktopServices({ strict: true,
      applications: { ready: Promise.resolve(), shutdown: action('applications') },
      terminal: { shutdown: action('terminal') }, terminalBrowserBroker: { shutdown: action('broker') },
      linkChannel: { close: action('links') }, routerChannel: { close: action('router') },
      service: { ready: Promise.resolve(), shutdown: action('backend') }, proxyCore: { close: action('proxy') },
    }), error => error === fault);
    const order = ['applications', 'terminal', 'broker', 'links', 'router', 'backend', 'proxy'];
    assert.deepEqual(events, order.slice(0, order.indexOf(failing) + 1));
  });
});

test('strict broker shutdown propagates cleanup failures while ordinary shutdown retains compatibility', async () => {
  for (const strict of [false, true]) {
    const broker = Object.create(TerminalBrowserBroker.prototype);
    broker.sessions = new Map([['owned', {}]]); broker.dispose = async () => { throw new Error('owned cleanup failed'); };
    if (strict) await assert.rejects(broker.shutdown({ strict }), /owned cleanup failed/);
    else await broker.shutdown();
    assert.equal(broker.closed, true);
  }
});

test('strict browser-service shutdown retains proxy resources when owned sidecar exit is unconfirmed', async () => {
  for (const strict of [false, true]) {
    const service = Object.create(BrowseForgeService.prototype), events = [];
    Object.assign(service, { ready: Promise.resolve(), queue: Promise.resolve(), profileQueues: new Map(),
      locationPreviews: new Map(), proxyWires: new Map([['owned', {}]]), networkProbe: {}, addressGeocoder: {},
      options: { shutdown: async () => { throw new Error('sidecar still alive'); }, proxyCore: { close: async () => events.push('proxy') } } });
    await assert.rejects(service.shutdown({ strict }), /sidecar still alive/);
    assert.deepEqual(events, strict ? [] : ['proxy']); assert.equal(service.proxyWires.size, strict ? 1 : 0);
  }
});

test('a resource replacement during admission or shutdown never acquires installer authority', async t => {
  for (const stage of ['admission', 'shutdown']) await t.test(stage, async () => {
    const f = fixture();
    if (stage === 'admission') f.resources.service.remote = async () => { f.resources.terminal = { ...f.resources.terminal }; return f.remote; };
    else {
      const shutdown = f.callbacks.shutdown;
      f.callbacks.shutdown = async options => { await shutdown(options); f.resources.sidecar = { ...f.resources.sidecar, closed: false, process: { other: true } }; };
    }
    const gate = f.create();
    await assert.rejects(gate.install(), { code: stage === 'admission' ? 'APP_UPDATE_BUSY' : 'APP_UPDATE_CLEANUP' });
    assert.equal(f.events.includes('commit'), false);
  });
});

test('terminal native-picker admission remains busy for queued operations and releases on failure', async () => {
  const controller = new TerminalController({ terminal: {}, service: {} }), hold = deferred();
  const first = controller.serialize(() => hold.promise), second = controller.serialize(() => { throw new Error('fixture refusal'); });
  const refused = assert.rejects(second, /fixture refusal/);
  assert.equal(controller.pendingCount, 2); hold.resolve(); await first; await refused;
  assert.equal(controller.pendingCount, 0);
});
