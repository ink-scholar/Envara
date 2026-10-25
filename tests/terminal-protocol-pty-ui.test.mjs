import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';

// A disposable raw TTY program, real node-pty, the production main-process
// protocol owner, and the production TerminalDock/xterm. No saved workspace,
// account, shell configuration, host clipboard, or external network is used.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const rootDirectory = fileURLToPath(new URL('../', import.meta.url));
let directory, desktop, page;
const errors = [];

const program = String.raw`
const fs = require('node:fs');
if (!process.stdin.isTTY) throw new Error('The query fixture requires a real PTY.');
process.stdin.setRawMode(true);
process.stdin.setEncoding('utf8');
let waiting = '', allInput = '';
const state = { tty: true, rounds: 0, ready: false, cprReplies: 0, colorReplies: 0, echoed: '' };
const cpr = /\x1b\[\d+;\d+R/g;
const color = /\x1b\]11;rgb:[\da-f]+\/[\da-f]+\/[\da-f]+\x1b\\/g;
const save = () => {
  fs.writeFileSync(process.argv[2] + '.tmp', JSON.stringify(state));
  fs.renameSync(process.argv[2] + '.tmp', process.argv[2]);
};
process.stdin.on('data', data => {
  if (data === '\x04') { process.stdin.setRawMode(false); process.exit(0); }
  if (data === 'G' && (state.rounds === 0 || state.ready)) {
    waiting = ''; state.ready = false; state.rounds++; save();
    process.stdout.write('\x1b[6n\x1b]11;?\x07');
    return;
  }
  allInput += data;
  state.cprReplies = [...allInput.matchAll(cpr)].length;
  state.colorReplies = [...allInput.matchAll(color)].length;
  if (!state.ready) {
    waiting += data;
    if ([...waiting.matchAll(cpr)].length && [...waiting.matchAll(color)].length) {
      state.ready = true;
      process.stdout.write('QUERY_OK\r\n');
    }
  } else if (!data.includes('\x1b')) {
    state.echoed += data; process.stdout.write(data);
  }
  save();
});
save();
process.stdout.write('READY\r\n');
`;

const renderer = `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { Terminal } from '@xterm/xterm';
import { TerminalDock } from './src/TerminalPane.jsx';
import { I18nProvider } from './src/i18n.jsx';
import { AppearanceProvider } from './src/appearance.jsx';
const profile = { id: 'protocol-fixture', name: 'Protocol fixture', timezone: 'UTC', locale: 'en-US' };
const api = window.envara;
const originalOpen = Terminal.prototype.open;
Terminal.prototype.open = function (...args) {
  const value = originalOpen.apply(this, args);
  window.fixture.terminals.push(this);
  this.onData(data => window.fixture.raw.push(data));
  return value;
};
let root, options;
function render() {
  root.render(<I18nProvider api={api}><AppearanceProvider api={api}>
    {Array.from({ length: options.views }, (_, index) => <TerminalDock key={index}
      profiles={[profile]} selectedProfileId={profile.id} visible={options.visible} />)}
  </AppearanceProvider></I18nProvider>);
}
window.fixture.mount = (next = {}) => {
  root?.unmount(); options = { visible: true, views: 1, ...next };
  window.fixture.terminals = []; window.fixture.raw = [];
  root = createRoot(document.querySelector('#root')); render();
};
window.fixture.update = next => { options = { ...options, ...next }; render(); };
window.fixture.unmount = () => { root?.unmount(); root = null; };
`;

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-terminal-protocol-pty-'));
  await mkdir(path.join(directory, 'data'));
  const programPath = path.join(directory, 'query.cjs');
  const reportPath = path.join(directory, 'report.json');
  const preload = path.join(directory, 'preload.cjs');
  await writeFile(programPath, program);
  await writeFile(preload, `const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('ownedTerminal', {
  call: (method, args) => ipcRenderer.invoke('owned-terminal:call', method, args),
  onEvent(listener) { const handler = (_event, value) => listener(value); ipcRenderer.on('owned-terminal:event', handler); return () => ipcRenderer.removeListener('owned-terminal:event', handler); },
});`);
  const main = path.join(directory, 'main.cjs');
  await writeFile(main, `const { app, BrowserWindow, ipcMain, session } = require('electron');
const fs = require('node:fs/promises');
const ptyModule = require(${JSON.stringify(path.join(rootDirectory, 'node_modules/node-pty'))});
app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))});
app.on('window-all-closed', () => {});
app.whenReady().then(async () => {
  const { TerminalProtocol } = await import(${JSON.stringify(pathToFileURL(path.join(rootDirectory, 'electron/terminal-protocol.mjs')).href)});
  app.dock?.hide();
  session.defaultSession.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*'] }, (_, done) => done({ cancel: true }));
  const view = new BrowserWindow({ show: false, width: 1200, height: 760, webPreferences: { sandbox: true, preload: ${JSON.stringify(preload)} } });
  let sequence = 0, replay = '', columns = 100, rows = 12;
  const replies = [], userWrites = [], failures = [];
  const child = ptyModule.spawn(process.execPath, [${JSON.stringify(programPath)}, ${JSON.stringify(reportPath)}], {
    name: 'xterm-256color', cols: columns, rows, cwd: ${JSON.stringify(directory)}, encoding: 'utf8', handleFlowControl: false,
    env: { PATH: process.env.PATH || '', TERM: 'xterm-256color', ELECTRON_RUN_AS_NODE: '1' },
  });
  let exited = false;
  const exit = new Promise(resolve => child.onExit(() => { exited = true; resolve(); }));
  const protocol = new TerminalProtocol({ columns, rows, write(data) { replies.push(data); child.write(data); } });
  child.onData(data => {
    protocol.write(data).catch(error => failures.push(error.message));
    replay += data;
    if (!view.isDestroyed()) view.webContents.send('owned-terminal:event', { type: 'data', sessionId: 'protocol-session', profileId: 'protocol-fixture', sequence: ++sequence, data });
    else sequence++;
  });
  ipcMain.handle('owned-terminal:call', async (_event, method, args = {}) => {
    if (method === 'terminalSnapshot') return { profiles: [{ profileId: 'protocol-fixture', sessions: [{
      sessionId: 'protocol-session', profileId: 'protocol-fixture', kind: 'shell', status: 'running', sequence, replay, columns, rows,
    }] }] };
    if (method === 'writeTerminal') { userWrites.push(args.data); child.write(args.data); return { accepted: true }; }
    if (method === 'resizeTerminal') { await protocol.resize(args.columns, args.rows, () => child.resize(args.columns, args.rows)); columns = args.columns; rows = args.rows; return {}; }
    throw new Error('Unexpected fixture operation: ' + method);
  });
  globalThis.protocolFixture = {
    trigger() { child.write('G'); },
    async state() {
      const report = await fs.readFile(${JSON.stringify(reportPath)}, 'utf8').then(JSON.parse, error => { if (error.code === 'ENOENT') return null; throw error; });
      return { report, replies: replies.slice(), userWrites: userWrites.slice(), failures: failures.slice(), exited, output: replay };
    },
    async stop() { protocol.dispose(); if (!exited) child.write('\x04'); await Promise.race([exit, new Promise(resolve => setTimeout(resolve, 1000))]); if (!exited) child.kill(); },
  };
  await view.loadURL('data:text/html;charset=utf-8,%3C!doctype%20html%3E%3Cdiv%20id%3D%22root%22%3E%3C%2Fdiv%3E');
});`);
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [main], env, timeout: 15000 });
  page = await desktop.firstWindow();
  page.on('pageerror', error => errors.push(error.message));
  await page.locator('#root').waitFor({ state: 'attached' });
  const css = await Promise.all(['src/styles.css', 'src/terminal.css', 'node_modules/@xterm/xterm/css/xterm.css']
    .map(filename => readFile(path.join(rootDirectory, filename), 'utf8')));
  await page.addStyleTag({ content: css.join('\n') + '\nhtml,body,#root{height:100%;margin:0}' });
  await page.evaluate(() => {
    window.fixture = { raw: [], terminals: [], listeners: 0 };
    window.envara = {
      isDesktop: true,
      subscribe() { window.fixture.listeners++; return () => window.fixture.listeners--; },
      onTerminalEvent(listener) { window.fixture.listeners++; const remove = window.ownedTerminal.onEvent(listener); return () => { remove(); window.fixture.listeners--; }; },
      async call(method, args) {
        if (method === 'snapshot') return { settings: { language: 'en', appearance: 'dark' }, system: { platform: 'darwin' } };
        return window.ownedTerminal.call(method, args);
      },
    };
  });
  const bundle = await build({ stdin: { contents: renderer, resolveDir: rootDirectory, loader: 'jsx' },
    bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' } });
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
  await waitState(value => value.report?.tty === true);
});

after(async () => {
  try {
    if (page && !page.isClosed()) {
      await page.evaluate(() => window.fixture.unmount?.());
      assert.equal(await page.evaluate(() => window.fixture.listeners), 0);
    }
    if (desktop) await desktop.evaluate(() => globalThis.protocolFixture?.stop());
    assert.deepEqual(errors, []);
  } finally {
    try { await desktop?.close(); }
    finally { if (directory) await rm(directory, { recursive: true, force: true }); }
  }
});

const state = () => desktop.evaluate(() => globalThis.protocolFixture.state());
async function waitState(predicate) {
  const deadline = Date.now() + 5000;
  let value;
  while (Date.now() < deadline) {
    value = await state();
    if (predicate(value)) return value;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail(`Owned PTY did not reach its expected state: ${JSON.stringify(value)}`);
}
async function query(round) {
  await desktop.evaluate(() => globalThis.protocolFixture.trigger());
  const value = await waitState(value => value.report.rounds === round && value.report.ready);
  assert.equal(value.report.cprReplies, round, 'one canonical cursor reply per query');
  assert.equal(value.report.colorReplies, round, 'one canonical colour reply per query');
  assert.equal(value.replies.length, round * 2);
  assert.deepEqual(value.failures, []);
  return value;
}

test('real PTY queries survive hidden, absent and multiple views without stealing keyboard input', { skip: noDisplay }, async () => {
  await page.evaluate(() => window.fixture.mount({ visible: false }));
  await page.locator('.xterm-helper-textarea').waitFor({ state: 'attached' });
  let value = await query(1);
  assert.equal(value.report.tty, true);
  assert.deepEqual(value.userWrites, [], 'a hidden renderer sends neither user input nor protocol answers');

  await page.evaluate(() => window.fixture.update({ visible: true }));
  await page.locator('.xterm-helper-textarea').focus();
  await page.keyboard.type('abc');
  value = await waitState(value => value.report.echoed === 'abc');
  assert.equal(value.userWrites.join(''), 'abc', 'ordinary typing reaches the ready program and is echoed');
  await query(2);

  await page.evaluate(() => window.fixture.unmount());
  assert.equal(await page.evaluate(() => window.fixture.listeners), 0);
  await query(3);

  await page.evaluate(() => window.fixture.mount({ views: 2 }));
  await page.waitForFunction(() => window.fixture.terminals.length === 2);
  await page.waitForTimeout(100);
  value = await state();
  assert.equal(value.replies.length, 6, 'mounting two views and replaying old queries never answers again');
  assert.equal(value.userWrites.join(''), 'abc');
  await query(4);
  await page.waitForTimeout(100);
  value = await state();
  assert.equal(value.replies.length, 8, 'two live renderers leave the same single protocol owner');
  assert.equal(value.userWrites.join(''), 'abc');
});
