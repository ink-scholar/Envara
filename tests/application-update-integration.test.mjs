import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
import { registerDesktopIPC } from '../electron/desktop-ipc.mjs';
import { createDesktopApplicationUpdateController } from '../electron/desktop-application-update-controller.mjs';

function fixture(kind = 'workspace') {
  let handler;
  const frame = {}, sender = { isDestroyed: () => false, mainFrame: frame };
  const window = { isDestroyed: () => false };
  const views = new Map([[sender, { kind, window, profileId: 'fixture' }]]);
  const state = { quitting: false, requestEpoch: 0, applicationUpdateActive: false };
  const calls = [];
  registerDesktopIPC({ ipcMain: { handle(channel, callback) { assert.equal(channel, 'envara:call'); handler = callback; } }, views,
    startup: { assertReady() {}, read: operation => operation() }, lifecycle: () => state, services: () => ({}),
    transferLock: { mutate: (method, args, operation) => operation() },
    handleCall: async (method, args) => { calls.push({ method, args }); return { status: 'ready', restartRequired: state.quitting }; },
    fullWorkspaceSnapshot: value => value });
  return { state, calls, call: (method, args = {}, senderFrame = frame) => handler({ sender, senderFrame }, { method, args }) };
}

test('only the trusted workspace can read updater state during update shutdown', async () => {
  const f = fixture(); f.state.quitting = true;
  assert.equal((await f.call('applicationUpdateStatus')).ok, false);
  f.state.applicationUpdateActive = true;
  const status = await f.call('applicationUpdateStatus');
  assert.equal(status.ok, true); assert.equal(status.value.restartRequired, true);
  for (const method of ['installApplicationUpdate', 'checkApplicationUpdate', 'downloadApplicationUpdate', 'snapshot', 'startProfile']) {
    assert.equal((await f.call(method)).error.code, 'APP_CLOSING');
  }
  assert.equal((await f.call('applicationUpdateStatus', {}, {})).ok, false, 'child frame does not gain update authority');
  assert.deepEqual(f.calls.map(value => value.method), ['applicationUpdateStatus']);
});

test('independent terminal window cannot inspect or operate application updates', async () => {
  const f = fixture('terminal');
  for (const method of ['applicationUpdateStatus', 'checkApplicationUpdate', 'downloadApplicationUpdate', 'installApplicationUpdate', 'cancelApplicationUpdate']) {
    assert.equal((await f.call(method)).ok, false);
  }
  f.state.quitting = true; f.state.applicationUpdateActive = true;
  assert.equal((await f.call('applicationUpdateStatus')).ok, false);
  assert.equal(f.calls.length, 0);
});

test('production main update dispatch rejects renderer URLs and paths; status is a local read', async () => {
  const source = await readFile(new URL('../electron/main.mjs', import.meta.url), 'utf8');
  const allowed = source.match(/const allowedMethods = new Set\(\[[\s\S]*?\n\]\);/);
  const handler = source.match(/async function handleCall\([\s\S]*?\n\}/);
  const actions = [];
  const snapshot = () => ({ status: 'idle', currentVersion: '1.2.3' });
  const updater = { ready: Promise.resolve(), refreshResult: async () => {}, snapshot, ...Object.fromEntries(['check', 'download', 'cancel', 'install'].map(name => [name, async () => actions.push(name)])) };
  const applicationUpdates = createDesktopApplicationUpdateController({ dataDir: '/fixture-only',
    createUpdater: () => updater, createAdapter: () => ({}) });
  const context = { quitting: false, window: {}, applicationUpdates, TERMINAL_METHODS: new Set() };
  vm.runInNewContext(`${allowed[0]}\n${handler[0]}`, context);
  assert.equal((await context.handleCall('applicationUpdateStatus', {})).status, 'idle');
  assert.equal(actions.length, 0);
  for (const method of ['applicationUpdateStatus', 'checkApplicationUpdate', 'downloadApplicationUpdate', 'installApplicationUpdate', 'cancelApplicationUpdate']) {
    await assert.rejects(context.handleCall(method, { url: 'https://example.invalid', appPath: '/unrelated.app' }));
  }
  for (const method of ['checkApplicationUpdate', 'downloadApplicationUpdate', 'cancelApplicationUpdate', 'installApplicationUpdate']) await context.handleCall(method, {});
  assert.deepEqual(actions, ['check', 'download', 'cancel', 'install']);
});
