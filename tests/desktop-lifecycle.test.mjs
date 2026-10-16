import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createWorkspaceWindowController, createOwnedQuitController } from '../electron/desktop-lifecycle.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
function fixture() {
  const events = []; let view = null, allowed = true, create;
  const make = () => ({ destroyed: false, minimized: false,
    isDestroyed() { return this.destroyed; }, isMinimized() { return this.minimized; },
    restore() { events.push('restore'); this.minimized = false; },
    show() { events.push('show'); }, focus() { events.push('focus'); } });
  create = async () => { events.push('load'); view = make(); return view; };
  return { events, make, get view() { return view; }, setCreate(value) { create = value; }, stop() { allowed = false; },
    controller: createWorkspaceWindowController({ current: () => view, create: () => create(), canOpen: () => allowed }) };
}

test('activation and second-instance requests before IPC readiness cannot load a window', async () => {
  const f = fixture();
  assert.deepEqual(await Promise.all([f.controller.open(), f.controller.open()]), [null, null]);
  assert.deepEqual(f.events, []);
  f.controller.markReady(); const view = await f.controller.open();
  assert.equal(view, f.view); assert.deepEqual(f.events, ['load']);
});

test('requests racing the startup load share one window and propagate its completion', async () => {
  const f = fixture(), load = deferred(); let count = 0;
  const expected = f.make(); f.setCreate(async () => { count++; await load.promise; return expected; });
  f.controller.markReady();
  const first = f.controller.open(), activation = f.controller.open(), secondInstance = f.controller.open();
  await Promise.resolve(); assert.equal(count, 1);
  load.resolve();
  assert.deepEqual(await Promise.all([first, activation, secondInstance]), [expected, expected, expected]);
  assert.equal(count, 1);
});

test('an existing minimized workspace is restored and a closed one can be reopened', async () => {
  const f = fixture(); f.controller.markReady();
  const original = await f.controller.open(); original.minimized = true;
  assert.equal(await f.controller.open(), original);
  assert.deepEqual(f.events, ['load', 'restore', 'show', 'focus']);
  original.destroyed = true;
  assert.notEqual(await f.controller.open(), original);
  assert.equal(f.events.filter(value => value === 'load').length, 2);
});

test('a failed load releases the pending operation and a later request can retry', async () => {
  const f = fixture(), load = deferred(); let count = 0;
  const expected = f.make(); f.setCreate(async () => { if (++count === 1) return load.promise; return expected; });
  f.controller.markReady();
  const first = f.controller.open(), second = f.controller.open();
  const rejected = Promise.all([assert.rejects(first, /fixture load failure/), assert.rejects(second, /fixture load failure/)]);
  load.reject(new Error('fixture load failure')); await rejected;
  assert.equal(await f.controller.open(), expected); assert.equal(count, 2);
});

test('quitting or lack of the single-instance lock prevents deferred creation', async () => {
  const f = fixture(); f.controller.markReady();
  const opening = f.controller.open(); f.stop();
  assert.equal(await opening, null); assert.equal(await f.controller.open(), null); assert.deepEqual(f.events, []);
});

test('desktop event entrypoints share the readiness gate, after the IPC handler is registered', async () => {
  const main = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const registered = main.indexOf('registerDesktopIPC({');
  assert.ok(registered >= 0 && registered < main.indexOf('workspaceWindow.markReady()'));
  assert.match(main, /app\.on\('activate', showWorkspaceWindow\)/);
  assert.match(main, /app\.on\('second-instance', showWorkspaceWindow\)/);
  assert.doesNotMatch(main, /(?:await|void) createWindow\(/);
});

test('repeated quits during initialization and cleanup remain prevented until all owned services finish', async () => {
  const starting = deferred(), cleaning = deferred(), events = [];
  const controller = createOwnedQuitController({ hasResources: () => true, startup: () => starting.promise,
    shutdown: async () => { events.push('cleanup'); await cleaning.promise; },
    onStateChange: value => events.push(`closing:${value}`), onFailure: () => events.push('failure'), quit: () => events.push('quit') });
  let prevented = 0; const event = { preventDefault() { prevented++; } };
  const first = controller.handle(event), duringStartup = controller.handle(event);
  await Promise.resolve(); assert.equal(prevented, 2); assert.deepEqual(events, ['closing:true']);
  starting.resolve(); await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(events, ['closing:true', 'cleanup']);
  const duringCleanup = controller.handle(event); assert.equal(prevented, 3);
  cleaning.resolve(); await Promise.all([first, duringStartup, duringCleanup]);
  assert.deepEqual(events, ['closing:true', 'cleanup', 'quit']);
  await controller.handle(event); assert.equal(prevented, 3, 'only the cleanup-authorized quit may pass through');
});

test('failed cleanup keeps the application alive and permits an explicit retry', async () => {
  const events = []; let count = 0, prevented = 0;
  const controller = createOwnedQuitController({ hasResources: () => true, startup: async () => {},
    shutdown: async () => { if (++count === 1) throw new Error('owned cleanup remains uncertain'); },
    onStateChange: value => events.push(`closing:${value}`), onFailure: error => events.push(error.message), quit: () => events.push('quit') });
  const event = { preventDefault() { prevented++; } };
  await controller.handle(event);
  assert.deepEqual(events, ['closing:true', 'closing:false', 'owned cleanup remains uncertain']);
  await controller.handle(event);
  assert.deepEqual(events.slice(-2), ['closing:true', 'quit']); assert.equal(prevented, 2); assert.equal(count, 2);
});

test('a failed startup does not authorize quitting without cleanup, and absence of owned resources needs no gate', async () => {
  const error = new Error('startup failed'), events = [];
  const controller = createOwnedQuitController({ hasResources: () => true, startup: async () => { throw error; },
    shutdown: async () => events.push('cleanup'), quit: () => events.push('quit'),
    onStateChange: value => events.push(value), onFailure: failure => events.push(failure) });
  await controller.handle({ preventDefault() { events.push('prevented'); } });
  assert.deepEqual(events, ['prevented', true, false, error]);
  const idle = createOwnedQuitController({ hasResources: () => false });
  await idle.handle({ preventDefault() { assert.fail('An idle process need not wait for nonexistent services'); } });
});


test('a repeated quit still waits after startup cancellation removes apparent resources', async () => {
  let release, resources = true, prevented = 0, cleaned = false, quit = false;
  const pendingStartup = new Promise(resolve => { release = resolve; });
  const controller = createOwnedQuitController({ hasResources: () => resources, startup: () => pendingStartup,
    shutdown: () => { cleaned = true; }, quit: () => { quit = true; },
    onStateChange: value => { if (value) resources = false; }, onFailure: error => { throw error; } });
  const event = { preventDefault() { prevented++; } };
  const first = controller.handle(event), second = controller.handle(event);
  assert.equal(prevented, 2); assert.equal(cleaned, false); assert.equal(quit, false);
  release(); await Promise.all([first, second]);
  assert.equal(cleaned, true); assert.equal(quit, true);
});
