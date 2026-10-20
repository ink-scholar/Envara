import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages, translate } from '../src/i18n.mjs';

// Real independent-window and SSH UI, synthetic metadata and a stub dock.
// No Envara main, PTY, host trust files, credentials or external connections.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const root = fileURLToPath(new URL('../', import.meta.url));
let directory, desktop, page;
const errors = [];

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-window-navigation-'));
  const bundle = await build({ stdin: { resolveDir: root, loader: 'jsx', contents: `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { TerminalWindowApp } from './src/TerminalWindowApp.jsx';
const root = createRoot(document.querySelector('#root'));
let revision = 0;
window.mountWindow = (options = {}) => {
  window.windowFixture = { language: 'zh-CN', desktop: true, calls: [], dockInstances: 0, requestRefs: new Set(), ...options };
  window.windowFixture.profile = { id: 'window-env', name: options.name || 'Demo workspace' };
  document.documentElement.lang = window.windowFixture.language;
  document.documentElement.dataset.theme = options.theme || 'dark';
  root.render(<TerminalWindowApp key={++revision} profileId="window-env" sessionId="window-session" />);
};
window.mountWindow();
` }, bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"' }, plugins: [{ name: 'isolated-window-navigation', setup(builder) {
      const stubs = {
        './client.js': `
export const api = { get isDesktop() { return window.windowFixture.desktop; }, subscribe: () => () => {},
  call: async (method, args) => {
    const fixture = window.windowFixture; fixture.calls.push({ method, args });
    if (method === 'snapshot') return { profiles: fixture.missing ? [] : [fixture.profile], system: { accessibilitySupportEnabled: true } };
    if (method === 'listTerminalSshConnections') return { supported: true, connections: [{ id: 'demo-host', alias: 'envara-demo', name: 'Demo host', host: 'ssh.example.invalid', port: 22, user: 'demo', authType: 'password', passwordReady: false, hostFingerprints: ['SHA256:synthetic'] }] };
    throw new Error('Unexpected window fixture operation: ' + method);
  } };
`,
        './i18n.jsx': `
import { translate } from ${JSON.stringify(path.join(root, 'src/i18n.mjs'))};
export const useI18n = () => ({ t: (value, vars) => translate(value, window.windowFixture.language, vars) });
`,
        './TerminalPane.jsx': `
import React, { useEffect, useRef } from 'react';
export function TerminalDock(props) {
  const instance = useRef(null);
  if (!instance.current) instance.current = ++window.windowFixture.dockInstances;
  window.windowFixture.dockProps = props;
  window.windowFixture.requestRefs.add(props.openRequest);
  useEffect(() => { props.onProfilesChange([{ profileId: 'window-env', sessions: [{ sessionId: 'window-session', status: 'running' }] }]); }, [props.onProfilesChange]);
  return <section className="terminal-dock is-standalone" hidden={!props.visible} data-instance={instance.current}>Synthetic existing terminal</section>;
}
`,
      };
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|TerminalPane\.jsx)$/ }, args => ({ path: args.path, namespace: 'window-navigation' }));
      builder.onLoad({ filter: /.*/, namespace: 'window-navigation' }, args => ({ contents: stubs[args.path], resolveDir: root, loader: 'jsx' }));
    } }],
  });
  await writeFile(path.join(directory, 'fixture.js'), bundle.outputFiles[0].text);
  // Load the window override first to catch accidental dependence on CSS order.
  const css = await Promise.all(['terminal-window.css', 'styles.css', 'terminal.css', 'ssh-workspace.css']
    .map(name => readFile(path.join(root, 'src', name), 'utf8')));
  await writeFile(path.join(directory, 'fixture.css'), css.join('\n'));
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><meta charset="utf-8"><link rel="stylesheet" href="fixture.css"><div id="root"></div><script src="fixture.js"></script>');
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow, session } = require('electron');
app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))});
app.whenReady().then(() => { app.dock?.hide(); session.defaultSession.webRequest.onBeforeRequest({ urls: ['http://*/*', 'https://*/*'] }, (_, done) => done({ cancel: true })); const view = new BrowserWindow({ show: false, width: 1120, height: 720, webPreferences: { sandbox: true } }); view.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [entry], env, timeout: 15000 });
  page = await desktop.firstWindow(); page.on('pageerror', error => errors.push(error.message));
  await page.getByRole('heading', { name: 'Demo workspace', exact: true }).waitFor();
});

after(async () => {
  try { await desktop?.close(); }
  finally { if (directory) await rm(directory, { recursive: true, force: true }); }
});

async function mount(options = {}) {
  await page.evaluate(options => window.mountWindow(options), options);
  if (options.missing) await page.getByRole('heading', { name: translate('当前环境不可用', options.language), exact: true }).waitFor();
  else await page.getByRole('heading', { name: options.name || 'Demo workspace', exact: true }).waitFor();
  await page.waitForFunction(missing => missing || window.windowFixture.dockProps?.visible === true, options.missing === true);
}

test('independent SSH tabs retain the existing dock, initial request and session locks, and only navigate back to the terminal', { skip: noDisplay }, async () => {
  await mount();
  const dock = page.locator('.terminal-dock'), instance = await dock.getAttribute('data-instance');
  const ssh = page.getByRole('tab', { name: 'SSH 连接', exact: true });
  await ssh.click();
  assert.equal(await dock.isVisible(), false);
  assert.equal(await page.evaluate(() => window.windowFixture.dockProps.visible), false);
  await page.getByRole('status').filter({ hasText: translate('先结束此环境的终端会话，再修改连接。', 'zh-CN') }).waitFor();
  assert.equal(await page.getByRole('button', { name: '添加连接', exact: true }).isDisabled(), true);
  assert.equal(await page.getByLabel('选择环境', { exact: true }).isVisible(), false);
  await page.locator('.ssh-workspace-host').click();
  await page.getByRole('button', { name: '打开终端', exact: true }).click();
  assert.equal(await dock.isVisible(), true);
  assert.equal(await dock.getAttribute('data-instance'), instance);
  assert.deepEqual(await page.evaluate(() => ({ request: window.windowFixture.dockProps.openRequest, refs: window.windowFixture.requestRefs.size, instances: window.windowFixture.dockInstances })),
    { request: { profileId: 'window-env', sessionId: 'window-session', nonce: 'window-initial' }, refs: 1, instances: 1 });
  const terminal = page.getByRole('tab', { name: '终端', exact: true });
  await terminal.focus(); await page.keyboard.press('ArrowRight');
  assert.equal(await ssh.getAttribute('aria-selected'), 'true');
  assert.equal(await ssh.evaluate(element => element === document.activeElement), true);
  await page.keyboard.press('Home');
  assert.equal(await terminal.getAttribute('aria-selected'), 'true');
  assert.deepEqual(await page.evaluate(() => [...new Set(window.windowFixture.calls.map(call => call.method))]), ['snapshot', 'listTerminalSshConnections']);
  assert.deepEqual(errors, []);
});

test('nine-language independent headers stay compact and the dock fills the remaining height in both themes', { skip: noDisplay }, async () => {
  for (const language of Object.keys(languages)) for (const theme of ['light', 'dark']) {
    const name = `${language} · ${'Demonstration workspace '.repeat(15)}`;
    await mount({ language, theme, name });
    for (const width of [640, 1120]) {
      await page.setViewportSize({ width, height: 720 });
      const heading = await page.locator('.terminal-window-workspace-heading').boundingBox();
      const panel = await page.locator('.terminal-window-terminal-panel').boundingBox();
      const dock = await page.locator('.terminal-dock').boundingBox();
      assert.equal(heading.height, 80); assert.equal(panel.height, 640); assert.equal(dock.height, 640);
      assert.equal(dock.width, width);
      assert.equal(await page.locator('.terminal-window-workspace-heading p').count(), 0);
      for (const label of ['终端', 'SSH 连接']) {
        const tab = page.getByRole('tab', { name: translate(label, language), exact: true });
        assert.equal(await tab.evaluate(element => element.scrollWidth <= element.clientWidth), true);
        assert.ok((await tab.boundingBox()).height >= 30);
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    }
  }
  await mount({ desktop: false });
  assert.equal((await page.locator('.terminal-window-workspace-heading').boundingBox()).height, 48);
  assert.deepEqual(errors, []);
});

test('an unavailable independent environment disables both views without reading SSH or starting a terminal', { skip: noDisplay }, async () => {
  await mount({ missing: true });
  assert.equal(await page.locator('.terminal-dock').count(), 0);
  for (const tab of await page.getByRole('tab').all()) assert.equal(await tab.isDisabled(), true);
  assert.deepEqual(await page.evaluate(() => window.windowFixture.calls.map(call => call.method)), ['snapshot']);
  assert.deepEqual(errors, []);
});
