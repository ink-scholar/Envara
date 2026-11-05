import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';

// Exercise the production WorkspaceApp in an owned Electron renderer. Network
// events and IPC replies are controlled fixtures; host networking is unchanged.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const project = fileURLToPath(new URL('../', import.meta.url));
const proxy = { id: 'network-fixture', name: 'Synthetic route', protocol: 'socks5', host: 'route.invalid', port: 1080,
  location: { confirmed: true, mode: 'manual', timezone: 'Asia/Tokyo', locale: 'ja-JP' } };
const profile = { id: 'environment-fixture', name: 'Synthetic environment', status: 'stopped', engine: 'cloakbrowser',
  proxyId: proxy.id, seed: 314159, timezone: 'Asia/Tokyo', locale: 'ja-JP' };
const stamp = offset => new Date(Date.now() + offset).toISOString();
const measured = (ip = '203.0.113.9', checkedAt = stamp(0)) => ({ ok: true, scope: 'egress', ip, timezone: 'Asia/Tokyo', checkedAt });
const snapshot = (networkRevision = 0, network = null) => ({ networkRevision, profiles: [profile], proxies: [{ ...proxy, network }],
  settings: { closeBrowsersOnExit: false, language: 'zh-CN', appearance: 'dark' }, system: { platform: 'darwin' } });
let directory, desktop, page;

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-network-ui-'));
  const output = await build({ stdin: { resolveDir: project, loader: 'jsx', contents: `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { WorkspaceApp } from './src/App.jsx';
const root = createRoot(document.querySelector('#root'));
let version = 0;
window.mountNetworkWorkspace = snapshot => {
  window.networkFixture = snapshot; window.networkCalls = []; window.networkPending = [];
  root.render(<WorkspaceApp key={++version} />);
};
window.networkReady = true;
` }, bundle: true, write: false, platform: 'browser', format: 'iife', loader: { '.css': 'empty' },
    define: { 'process.env.NODE_ENV': '"test"', 'import.meta.env.BASE_URL': '"./"' },
    plugins: [{ name: 'owned-network-ui', setup(builder) {
      builder.onLoad({ filter: /[/\\]src[/\\]App\.jsx$/ }, async args => ({
        contents: `${await readFile(args.path, 'utf8')}\nexport { WorkspaceApp };`, loader: 'jsx',
      }));
      const stubs = {
        './client.js': `export const api = { isDesktop: true,
          subscribe(listener) { window.networkListener = listener; return () => { if (window.networkListener === listener) delete window.networkListener; }; },
          call: async (method, args) => {
            window.networkCalls.push({ method, args });
            if (method === 'snapshot') return structuredClone(window.networkFixture);
            if (method === 'linkRouterStatus') return { enabled: false, supported: false };
            if (method === 'checkProxy') return new Promise((resolve, reject) => window.networkPending.push({ resolve, reject }));
            throw new Error('Unexpected network fixture operation: ' + method);
          } };`,
        './i18n.jsx': `import { translate } from ${JSON.stringify(path.join(project, 'src/i18n.mjs'))};
          export const useI18n = () => ({ language: 'zh-CN', phase: 'ready', t: (value, vars) => translate(value, 'zh-CN', vars) });`,
        './TerminalPane.jsx': `export const TerminalDock = () => null;`,
        './workspace-pages.jsx': `import React from 'react';
          export function EnvironmentOverview({ profiles }) { return <div data-testid="fixture-profiles">{JSON.stringify(profiles)}</div>; }
          export const ContextDetail = () => null;
          export const ApplicationsWorkspace = () => null;
          export const MonitorWorkspace = () => null;`,
      };
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|TerminalPane\.jsx|workspace-pages\.jsx)$/ }, args => ({ path: args.path, namespace: 'network-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'network-fixture' }, args => ({ contents: stubs[args.path], resolveDir: project, loader: 'jsx' }));
    } }],
  });
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  await writeFile(path.join(directory, 'styles.css'), await readFile(new URL('../src/styles.css', import.meta.url), 'utf8'));
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><meta charset="utf-8"><html data-theme="dark"><link rel="stylesheet" href="styles.css"><div id="root"></div><script src="fixture.js"></script></html>');
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow } = require('electron');
app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))});
app.whenReady().then(() => { app.dock?.hide(); const window = new BrowserWindow({ show: false, width: 1280, height: 900, webPreferences: { sandbox: true } }); window.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [entry], env, timeout: 15000 });
  page = await desktop.firstWindow();
  page.setDefaultTimeout(5000);
  await page.context().route('**/*', route => route.request().url().startsWith(pathToFileURL(directory + path.sep).href) ? route.continue() : route.abort());
  await page.waitForFunction(() => window.networkReady === true);
});

after(async () => {
  try { await desktop?.close(); }
  finally { if (directory) await rm(directory, { recursive: true, force: true }); }
});

async function open(value = snapshot()) {
  await page.evaluate(value => window.mountNetworkWorkspace(value), value);
  await page.waitForFunction(() => window.networkCalls.some(call => call.method === 'snapshot'));
  await page.getByRole('button', { name: '网络出口', exact: true }).click();
  await page.locator('.proxy-row').waitFor();
  return page.locator('.proxy-row').filter({ hasText: proxy.name });
}
async function publish(value, current = true) {
  await page.evaluate(({ value, current }) => {
    if (current) window.networkFixture = value;
    window.networkListener(value);
  }, { value, current });
}
async function settle(index, value, reject = false) {
  await page.evaluate(({ index, value, reject }) => {
    const request = window.networkPending[index];
    if (reject) request.reject(new Error(value)); else request.resolve(value);
  }, { index, value, reject });
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

test('network recovery clears an outstanding spinner and rejects late old-network failure without changing saved settings', { skip: noDisplay }, async () => {
  const row = await open();
  await row.getByRole('button', { name: '识别', exact: true }).click();
  await row.getByText('正在识别出口…', { exact: true }).waitFor();
  const recovered = measured();
  await publish(snapshot(1, recovered));
  await row.getByText(recovered.ip, { exact: true }).waitFor();
  assert.equal(await row.getByRole('button', { name: '识别', exact: true }).isEnabled(), true);
  await settle(0, 'Synthetic stale offline failure', true);
  assert.equal(await row.getByText(recovered.ip, { exact: true }).count(), 1);
  assert.equal(await page.locator('.toast-error').count(), 0);
  assert.equal(await row.getByText('正在识别出口…', { exact: true }).count(), 0);
  await page.getByRole('button', { name: '环境', exact: true }).click();
  assert.deepEqual(JSON.parse(await page.getByTestId('fixture-profiles').textContent()), [profile]);
  await page.getByRole('button', { name: '设置', exact: true }).click();
  assert.equal(await page.getByRole('checkbox', { name: '退出时关闭浏览器', exact: true }).isChecked(), false);
  assert.deepEqual(await page.evaluate(() => window.networkCalls.map(call => call.method)), ['snapshot', 'checkProxy', 'linkRouterStatus']);
});

test('request tokens remain distinct after recovery and an older snapshot cannot roll back the network generation', { skip: noDisplay }, async () => {
  const row = await open();
  await row.getByRole('button', { name: '识别', exact: true }).click();
  await publish(snapshot(2, measured('203.0.113.20')));
  await row.getByText('203.0.113.20', { exact: true }).waitFor();
  await row.getByRole('button', { name: '识别', exact: true }).click();
  await page.waitForFunction(() => window.networkPending.length === 2);
  await publish(snapshot(1, measured('203.0.113.1')), false);
  await settle(0, measured('203.0.113.2'));
  assert.equal(await row.getByText('正在识别出口…', { exact: true }).count(), 1);
  assert.equal(await row.getByRole('button', { name: '识别', exact: true }).isDisabled(), true);
  assert.equal(await page.locator('.toast').count(), 0);
  await settle(1, measured('203.0.113.30', stamp(1000)));
  await row.getByText('203.0.113.30', { exact: true }).waitFor();
  assert.equal(await row.getByRole('button', { name: '识别', exact: true }).isEnabled(), true);
  await publish(snapshot(1, measured('203.0.113.1', stamp(10000))), false);
  assert.equal(await row.getByText('203.0.113.30', { exact: true }).count(), 1);
});

test('a newer backend measurement replaces a finished local failure in the same network generation', { skip: noDisplay }, async () => {
  const row = await open(snapshot(3, measured('203.0.113.5', stamp(-10000))));
  await row.getByRole('button', { name: '识别', exact: true }).click();
  await settle(0, 'Synthetic current offline failure', true);
  await row.getByText('出口识别失败', { exact: true }).waitFor();
  await publish(snapshot(3, measured('203.0.113.6', stamp(-5000))));
  assert.equal(await row.getByText('出口识别失败', { exact: true }).count(), 1, 'an older measurement must not hide the latest failure');
  await publish(snapshot(3, measured('203.0.113.7', stamp(10000))));
  await row.getByText('203.0.113.7', { exact: true }).waitFor();
  assert.equal(await row.getByText('出口识别失败', { exact: true }).count(), 0);
  assert.equal(await row.getByRole('button', { name: '识别', exact: true }).isEnabled(), true);
});
