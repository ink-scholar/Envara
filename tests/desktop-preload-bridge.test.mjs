import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';

// Exercise Electron's real isolated-world serialization, the production preload
// and the renderer client. The main entry is only a synthetic IPC responder.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const root = fileURLToPath(new URL('../', import.meta.url));
const failures = [
  { method: 'prepareTerminalSshPassword', code: 'SSH_HOST_UNTRUSTED', message: 'Synthetic untrusted SSH host.' },
  { method: 'startProfile', code: 'APP_STARTING', message: 'Synthetic startup is still pending.' },
  { method: 'openTerminal', code: 'TERMINAL_ROUTE_UNAVAILABLE', message: '合成线路不可用，请重试。' },
];
let directory, desktop, page, exited;
const rendererErrors = [];

before(async () => {
  if (noDisplay) return;
  directory = await realpath(await mkdtemp(path.join(tmpdir(), 'envara-preload-bridge-test-')));
  const directories = Object.fromEntries(['home', 'appData', 'userData', 'sessionData', 'temp', 'logs', 'crashDumps']
    .map(name => [name, path.join(directory, name)]));
  await Promise.all(Object.values(directories).map(value => mkdir(value, { mode: 0o700 })));
  // A byte copy keeps the fixture independent of concurrent package builds;
  // no implementation of the preload or client is replaced in the renderer.
  const preload = await readFile(path.join(root, 'electron/preload.cjs'));
  await writeFile(path.join(directory, 'preload.cjs'), preload, { mode: 0o600 });
  const bundle = await build({
    stdin: {
      contents: "import { api } from './src/client.js'; window.fixtureApi = api;",
      resolveDir: root,
      sourcefile: 'desktop-preload-bridge-entry.js',
    },
    bundle: true, platform: 'browser', format: 'iife', write: false,
  });
  await writeFile(path.join(directory, 'renderer.js'), bundle.outputFiles[0].text, { mode: 0o600 });
  await writeFile(path.join(directory, 'index.html'),
    '<!doctype html><meta charset="utf-8"><title>Owned preload bridge fixture</title><script src="renderer.js"></script>',
    { mode: 0o600 });
  const main = path.join(directory, 'main.cjs');
  await writeFile(main, `
const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('node:path');
app.setName('Envara owned preload bridge test');
for (const [name, value] of Object.entries(${JSON.stringify(directories)})) app.setPath(name, value);
const failures = ${JSON.stringify(failures)};
ipcMain.handle('envara:call', (_event, { method, args }) => {
  const failure = failures.find(item => item.method === method);
  if (failure) return { ok: false, error: { code: failure.code, message: failure.message } };
  if (method === 'uncodedFailure') return { ok: false, error: { message: 'Synthetic uncoded failure.' } };
  if (method === 'success') return { ok: true, value: { method, args, nested: [null, false, 0, '合成数据'] } };
  if (method === 'nullSuccess') return { ok: true, value: null };
  throw new Error('Unexpected synthetic operation: ' + method);
});
app.whenReady().then(() => {
  app.dock?.hide();
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => callback({ cancel: !details.url.startsWith('file:') }));
  const window = new BrowserWindow({ show: false, width: 480, height: 320,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false } });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.loadFile(path.join(__dirname, 'index.html'));
});
`, { mode: 0o600 });
  const environment = {
    PATH: process.env.PATH || '/usr/bin:/bin', HOME: directories.home, USERPROFILE: directories.home,
    TMPDIR: `${directories.temp}${path.sep}`, TMP: directories.temp, TEMP: directories.temp,
    LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8',
  };
  for (const name of ['SystemRoot', 'WINDIR', 'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY']) {
    if (process.env[name]) environment[name] = process.env[name];
  }
  desktop = await _electron.launch({ args: [main], env: environment, cwd: directory, timeout: 15000 });
  exited = once(desktop.process(), 'exit');
  page = await desktop.firstWindow();
  page.on('pageerror', error => rendererErrors.push(error.message));
  await page.waitForFunction(() => typeof window.fixtureApi?.call === 'function');
});

after(async () => {
  try {
    if (desktop) {
      await desktop.close();
      const [code, signal] = await exited;
      assert.equal(signal, null, 'The owned Electron fixture quits normally');
      assert.equal(code, 0);
    }
  } finally {
    if (directory) await rm(directory, { recursive: true, force: true });
  }
});

test('the bridge fixture uses a hidden sandboxed window with isolated production preload', { skip: noDisplay }, async () => {
  const options = await desktop.evaluate(({ app, BrowserWindow }) => {
    const window = BrowserWindow.getAllWindows()[0];
    const preferences = window.webContents.getLastWebPreferences();
    return { visible: window.isVisible(), sandbox: preferences.sandbox, contextIsolation: preferences.contextIsolation,
      nodeIntegration: preferences.nodeIntegration, userData: app.getPath('userData') };
  });
  assert.deepEqual(options, { visible: false, sandbox: true, contextIsolation: true, nodeIntegration: false,
    userData: path.join(directory, 'userData') });
  assert.deepEqual(await page.evaluate(() => ({
    desktop: window.fixtureApi.isDesktop, require: typeof window.require, process: typeof window.process,
  })), { desktop: true, require: 'undefined', process: 'undefined' });
  assert.deepEqual(rendererErrors, []);
});

test('production preload retains SSH, startup and terminal failure codes across the real context bridge', { skip: noDisplay }, async () => {
  for (const failure of failures) {
    const result = await page.evaluate(async ({ method }) => {
      try { return { unexpectedSuccess: await window.envara.call(method, { id: 'synthetic-environment' }) }; }
      catch (error) { return { code: error.code, message: error.message }; }
    }, failure);
    assert.deepEqual(result, { code: failure.code, message: failure.message }, failure.method);
  }
});

test('the actual renderer client reconstructs normal Error instances without losing IPC codes', { skip: noDisplay }, async () => {
  for (const failure of failures) {
    const result = await page.evaluate(async ({ method }) => {
      try { return { unexpectedSuccess: await window.fixtureApi.call(method, { id: 'synthetic-environment' }) }; }
      catch (error) {
        return { code: error.code, message: error.message, name: error.name, isError: error instanceof Error,
          hasStack: typeof error.stack === 'string' && error.stack.includes(error.message) };
      }
    }, failure);
    assert.deepEqual(result, { code: failure.code, message: failure.message, name: 'Error', isError: true,
      hasStack: true }, failure.method);
  }
});

test('the desktop client preserves successful values and arguments, including default arguments and null', { skip: noDisplay }, async () => {
  const args = { id: 'synthetic-environment', nested: { enabled: false, count: 0, name: '合成环境' } };
  const values = await page.evaluate(async args => ({
    supplied: await window.fixtureApi.call('success', args),
    omitted: await window.fixtureApi.call('success'),
    empty: await window.fixtureApi.call('nullSuccess'),
  }), args);
  assert.deepEqual(values, {
    supplied: { method: 'success', args, nested: [null, false, 0, '合成数据'] },
    omitted: { method: 'success', args: {}, nested: [null, false, 0, '合成数据'] },
    empty: null,
  });
});

test('uncoded desktop failures remain ordinary renderer Errors without inventing a code', { skip: noDisplay }, async () => {
  const result = await page.evaluate(async () => {
    try { return { unexpectedSuccess: await window.fixtureApi.call('uncodedFailure') }; }
    catch (error) { return { message: error.message, isError: error instanceof Error, hasCode: error.code != null }; }
  });
  assert.deepEqual(result, { message: 'Synthetic uncoded failure.', isError: true, hasCode: false });
  assert.deepEqual(rendererErrors, []);
});
