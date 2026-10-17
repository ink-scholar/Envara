import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { EnvaraStore } from '../electron/store.mjs';
import { EnvaraService } from '../electron/service.mjs';
import { BrowseForgeService } from '../electron/browseforge-service.mjs';
import { createAppearanceManager, readInitialAppearance } from '../electron/appearance.mjs';
import { terminalViewSnapshot } from '../electron/terminal-view.mjs';
import { createAppearanceController } from '../src/appearance-state.mjs';

const snapshot = appearance => ({ profiles: [], proxies: [], settings: { appearance }, system: { platform: 'darwin', appVersion: 'fixture' } });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const turn = () => new Promise(resolve => setImmediate(resolve));
async function directory(t) { const dir = await mkdtemp(path.join(os.tmpdir(), 'envara-appearance-')); t.after(() => rm(dir, { recursive: true, force: true })); return dir; }

test('fresh workspaces follow the system while existing missing and saved choices preserve appearance and data', async t => {
  const dir = await directory(t), file = path.join(dir, 'workspace.json');
  assert.equal(readInitialAppearance(file), 'system');
  const fresh = new EnvaraStore(dir);
  assert.equal((await fresh.read()).settings.appearance, 'system');
  const saved = await fresh.read();
  saved.profiles.push({ id: 'fixture', locale: 'ja-JP', seed: 481 });
  delete saved.settings.appearance;
  await writeFile(file, JSON.stringify(saved));
  const bytes = await readFile(file, 'utf8');
  const old = new EnvaraStore(dir);
  assert.equal((await old.read()).settings.appearance, 'dark');
  assert.equal(readInitialAppearance(file), 'dark');
  assert.deepEqual((await old.read()).profiles, saved.profiles);
  assert.equal(await readFile(file, 'utf8'), bytes, 'Opening old settings must not rewrite their data');
  for (const choice of ['system', 'light', 'dark']) {
    await old.transaction(next => { next.settings.appearance = choice; });
    assert.equal((await new EnvaraStore(dir).read()).settings.appearance, choice);
    assert.equal(readInitialAppearance(file), choice);
  }
});

test('both backend validators persist only the three appearance choices without browser or process operations', async t => {
  const dir = await directory(t), store = new EnvaraStore(dir); await store.ready;
  const values = await store.read();
  values.profiles.push({ id: 'fixture', locale: 'ja-JP', timezone: 'Asia/Tokyo', seed: 481 });
  await store.transaction(next => Object.assign(next, values));
  const browse = Object.create(BrowseForgeService.prototype); browse.store = store;
  const legacy = Object.create(EnvaraService.prototype); legacy.store = store; legacy.changed = () => {};
  for (const service of [browse, legacy]) {
    for (const appearance of ['light', 'dark', 'system']) {
      await service.saveSettings({ settings: { appearance, closeBrowsersOnExit: true } });
      const saved = await store.read();
      assert.equal(saved.settings.appearance, appearance);
      assert.deepEqual(saved.profiles, values.profiles);
    }
    for (const appearance of [null, undefined, true, 'auto', {}, ['dark']]) await assert.rejects(service.saveSettings({ settings: { appearance, closeBrowsersOnExit: true } }), { code: 'VALIDATION_ERROR' });
  }
});

function fixture(preference = 'system') {
  const listeners = new Set(), nativeListeners = new Set(), mediaListeners = new Set(), calls = [];
  let saved = snapshot(preference), read = async () => saved, save;
  const emit = value => { saved = value; listeners.forEach(listener => listener(value)); };
  save = async args => { emit(snapshot(args.settings.appearance)); return saved; };
  const mediaQuery = { matches: false, addEventListener(_event, listener) { mediaListeners.add(listener); }, removeEventListener(_event, listener) { mediaListeners.delete(listener); } };
  const api = { subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); }, onAppearance(listener) { nativeListeners.add(listener); return () => nativeListeners.delete(listener); }, call(method, args) { calls.push({ method, args }); return method === 'snapshot' ? read() : save(args); } };
  return { api, mediaQuery, calls, listeners, nativeListeners, mediaListeners, emit, setRead(value) { read = value; }, setSave(value) { save = value; }, system(dark) { mediaQuery.matches = dark; mediaListeners.forEach(listener => listener({ matches: dark })); }, native(value) { nativeListeners.forEach(listener => listener(value)); } };
}

test('system changes update both mounted windows; explicit themes and saves never dispatch process operations', async () => {
  const f = fixture();
  const main = createAppearanceController({ ...f }), terminal = createAppearanceController({ ...f });
  main.start(); terminal.start(); await turn();
  assert.equal(main.getState().effective, 'light'); f.system(true);
  assert.equal(main.getState().effective, 'dark'); assert.equal(terminal.getState().effective, 'dark');
  await main.setPreference('light');
  assert.equal(main.getState().effective, 'light'); assert.equal(terminal.getState().effective, 'light');
  f.system(false); f.system(true); assert.equal(main.getState().effective, 'light');
  await main.setPreference('system'); assert.equal(terminal.getState().effective, 'dark');
  assert.ok(f.calls.every(call => ['snapshot', 'saveSettings'].includes(call.method)));
  main.stop(); terminal.stop(); assert.equal(f.listeners.size + f.nativeListeners.size + f.mediaListeners.size, 0);
});

test('failed saves roll back and pending persistence cannot accept another choice', async () => {
  const f = fixture('dark'), controller = createAppearanceController({ ...f }); controller.start(); await turn();
  const hold = deferred(); f.setSave(() => hold.promise);
  const saving = controller.setPreference('light');
  assert.equal(controller.getState().effective, 'light'); assert.equal(controller.getState().saving, true);
  assert.equal(await controller.setPreference('system'), false);
  hold.reject(new Error('disk failure')); await assert.rejects(saving);
  assert.equal(controller.getState().preference, 'dark'); assert.equal(controller.getState().saving, false);
  controller.stop();
});

test('appearance saves preserve a saved exit preference and do not copy unrelated settings', async () => {
  const f = fixture('dark');
  f.emit({ ...snapshot('dark'), settings: { appearance: 'dark', closeBrowsersOnExit: false, unrelated: 'keep-private' } });
  const controller = createAppearanceController({ ...f }); controller.start(); await turn();
  await controller.setPreference('light');
  assert.deepEqual(f.calls.find(call => call.method === 'saveSettings').args, { settings: { closeBrowsersOnExit: false, appearance: 'light' } });
  controller.stop();
});

test('newer settings and native events win over a delayed startup snapshot', async () => {
  const f = fixture(), hold = deferred(); f.setRead(() => hold.promise);
  const controller = createAppearanceController({ ...f }); controller.start();
  f.native({ preference: 'light', effective: 'light' });
  hold.resolve(snapshot('dark')); await turn();
  assert.equal(controller.getState().preference, 'light');
  controller.stop();
});

test('Electron themes change only owned window backgrounds and the app scoped nativeTheme source', () => {
  const nativeTheme = new EventEmitter(); nativeTheme.shouldUseDarkColors = false;
  const events = [];
  const view = name => ({ isDestroyed: () => false, setBackgroundColor(value) { events.push([name, 'background', value]); }, webContents: { send(channel, value) { events.push([name, channel, value]); } } });
  const views = new Map([['main', { window: view('main') }], ['terminal', { window: view('terminal') }]]);
  const manager = createAppearanceManager({ nativeTheme, views, preference: 'system' });
  assert.equal(manager.snapshot().effective, 'light');
  nativeTheme.shouldUseDarkColors = true; nativeTheme.emit('updated');
  assert.equal(events.filter(value => value[1] === 'envara:appearance').length, 2);
  manager.setPreference('light'); assert.equal(nativeTheme.themeSource, 'light');
  assert.equal(manager.snapshot().effective, 'light');
  assert.ok(events.slice(-4).every(value => value[1] === 'background' ? value[2] === '#f6f7f9' : value[2].effective === 'light'));
  manager.dispose(); assert.equal(nativeTheme.listenerCount('updated'), 0);
});

test('terminal safe snapshots admit only a primitive validated appearance preference', () => {
  for (const appearance of ['system', 'light', 'dark']) assert.equal(terminalViewSnapshot(snapshot(appearance)).settings.appearance, appearance);
  for (const appearance of ['auto', { private: 'secret' }, ['light'], null]) assert.equal(terminalViewSnapshot(snapshot(appearance)).settings.appearance, undefined);
});

test('first paint uses saved desktop or preview appearance before React, including a new system workspace', async () => {
  const source = await readFile(new URL('../public/appearance.js', import.meta.url), 'utf8');
  const paint = ({ native, preview, systemDark = false } = {}) => {
    const root = { dataset: {}, style: {} };
    vm.runInNewContext(source, { window: { ...(native ? { envara: { getAppearance: () => native } } : {}), matchMedia: () => ({ matches: systemDark }) }, document: { documentElement: root, querySelector: () => null }, localStorage: { getItem: () => preview ?? null } });
    return root;
  };
  assert.equal(paint().dataset.theme, 'light');
  assert.equal(paint({ systemDark: true }).dataset.theme, 'dark');
  assert.equal(paint({ preview: JSON.stringify({ settings: {} }) }).dataset.theme, 'dark');
  assert.equal(paint({ preview: JSON.stringify({ settings: { appearance: 'light' } }), systemDark: true }).dataset.theme, 'light');
  assert.equal(paint({ native: { preference: 'dark', effective: 'dark' }, systemDark: false }).dataset.theme, 'dark');
});
