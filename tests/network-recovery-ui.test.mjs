import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages, translate } from '../src/i18n.mjs';

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
  document.documentElement.lang = snapshot.settings?.language || 'zh-CN';
  document.documentElement.dataset.theme = snapshot.settings?.appearance || 'dark';
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
            if (method === 'listWorkCombinations') return { combinations: [] };
            if (method === 'componentVersions') return { schema: 'envara.component-versions', version: 1, rows: [] };
            if (method === 'applicationUpdateStatus') return { status: 'idle', currentVersion: '1.2.3', latestVersion: null, error: null, canInstall: false };
            if (method === 'linkRouterStatus') return { enabled: false, supported: false };
            if (method === 'retryNetwork') {
              const previous = window.networkFixture.networkRecovery;
              if (window.networkRetryFailure) throw new Error('Synthetic retry unavailable');
              window.networkFixture.networkRecovery = { ...previous, revision: previous.revision + 1, phase: 'checking', reason: 'manual', retryAt: null };
              return structuredClone(window.networkFixture);
            }
            if (method === 'checkProxy') return new Promise((resolve, reject) => window.networkPending.push({ resolve, reject }));
            throw new Error('Unexpected network fixture operation: ' + method);
          } };`,
        './i18n.jsx': `import { translate } from ${JSON.stringify(path.join(project, 'src/i18n.mjs'))};
          export const useI18n = () => ({ language: window.networkFixture?.settings?.language || 'zh-CN', phase: 'ready', t: (value, vars) => translate(value, window.networkFixture?.settings?.language || 'zh-CN', vars) });`,
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
  await mkdir(path.join(directory, 'assets'));
  await writeFile(path.join(directory, 'assets/envara-icon.png'), await readFile(path.join(project, 'public/assets/envara-icon.png')));
  await writeFile(path.join(directory, 'fixture.js'), output.outputFiles[0].text);
  await writeFile(path.join(directory, 'styles.css'), await readFile(new URL('../src/styles.css', import.meta.url), 'utf8'));
  await writeFile(path.join(directory, 'index.html'), '<!doctype html><meta charset="utf-8"><html data-theme="dark"><link rel="stylesheet" href="styles.css"><div id="root"></div><script src="fixture.js"></script></html>');
  const entry = path.join(directory, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow } = require('electron');
app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))});
app.whenReady().then(() => { app.dock?.hide(); const window = new BrowserWindow({ ...(process.platform === 'win32' ? { show: true, x: -3000, y: 0, frame: false, thickFrame: false } : { show: false }), width: 1280, height: 900, webPreferences: { sandbox: true } }); window.loadURL(${JSON.stringify(pathToFileURL(path.join(directory, 'index.html')).href)}); });`);
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
  await page.getByRole('button', { name: translate('网络出口', value.settings?.language || 'zh-CN'), exact: true }).click();
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
  // Other workspace pages may load their local read-only panels. No extra
  // network, launch, settings or account mutation is allowed by this assertion.
  assert.deepEqual(await page.evaluate(() => window.networkCalls.map(call => call.method).filter(method => !['listWorkCombinations', 'componentVersions', 'applicationUpdateStatus'].includes(method))), ['snapshot', 'checkProxy', 'linkRouterStatus']);
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

const recovery = (phase, revision = 1) => ({ revision, phase, reason: 'network-change', attempt: 1,
  retryAt: phase === 'waiting' ? stamp(30000) : null, checkedAt: null });
const withRecovery = (phase, revision = 1) => ({ ...snapshot(4), networkRecovery: recovery(phase, revision) });
const diagnostics = { version: 1, attempts: [
  { source: 'ipwho.is', elapsedMs: 10000, outcome: 'failure', errorCode: 'NETWORK_TIMEOUT',
    stages: [{ stage: 'configuration', status: 'passed' }, { stage: 'https', status: 'failed' }] },
  { source: 'ipapi.co', elapsedMs: 248, outcome: 'success', stages: ['configuration', 'https', 'response', 'validation'].map(stage => ({ stage, status: 'passed' })) },
] };

test('recovery status supports one immediate retry and ignores older status-only snapshots', { skip: noDisplay }, async () => {
  await open(withRecovery('waiting', 3));
  const notice = page.getByRole('region', { name: '网络恢复' });
  await notice.getByText('等待重新检查', { exact: true }).waitFor();
  assert.match(await notice.locator('.network-retry-time').textContent(), /\d+ 秒后重试/);
  await notice.getByRole('button', { name: '立即重试', exact: true }).click();
  await notice.getByText('正在恢复网络连接', { exact: true }).waitFor();
  assert.equal(await notice.getByRole('button').count(), 0);
  await publish(withRecovery('waiting', 2), false);
  assert.equal(await notice.getByText('正在恢复网络连接', { exact: true }).count(), 1);
  await publish({ ...withRecovery('recovered', 5), proxies: [{ ...proxy, network: measured() }] });
  await notice.getByText('本轮网络重检已完成', { exact: true }).waitFor();
  assert.deepEqual(await page.evaluate(() => window.networkCalls.map(item => item.method).filter(method => method !== 'listWorkCombinations')), ['snapshot', 'retryNetwork']);
  assert.deepEqual(await page.evaluate(() => window.networkFixture.profiles), [profile]);
});

test('diagnostics preserve earlier failures and keep unobserved stages distinct from failures', { skip: noDisplay }, async () => {
  const row = await open(snapshot(5, { ...measured(), diagnostics }));
  const details = row.locator('.network-diagnostics');
  assert.equal(await details.evaluate(element => element.open), false);
  await details.locator('summary').click();
  assert.equal(await details.locator('.network-attempt').count(), 2);
  assert.equal(await details.locator('.network-stage.unobserved').count(), 2);
  assert.equal(await details.locator('.network-stage.failed').count(), 1);
  assert.equal(await details.getByText('连接超时', { exact: true }).count(), 1);
  assert.equal(await row.getByText('出口识别失败', { exact: true }).count(), 0);
  await publish(snapshot(5, { ...measured(), diagnostics: { version: 1, attempts: [{ ...diagnostics.attempts[0],
    source: 'https://secret-user:secret-token@private-route.invalid/', errorCode: 'secret-token', raw: 'secret-token' }] } }));
  await details.getByText('出口查询服务', { exact: true }).waitFor();
  assert.equal(await page.getByText(/secret-token|secret-user|private-route/).count(), 0);
  assert.deepEqual(await page.evaluate(() => window.networkCalls.map(item => item.method).filter(method => method !== 'listWorkCombinations')), ['snapshot']);
});

test('a refused manual retry stays actionable without changing saved data', { skip: noDisplay }, async () => {
  const value = { ...withRecovery('waiting', 10), settings: { ...snapshot().settings, language: 'en' } };
  await open(value);
  await page.evaluate(() => { window.networkRetryFailure = true; });
  try {
    const button = page.getByRole('button', { name: translate('立即重试', 'en'), exact: true });
    await button.click();
    await page.getByText(translate('无法开始网络重检，请重试。', 'en'), { exact: true }).waitFor();
    assert.equal(await button.isEnabled(), true);
    assert.deepEqual(await page.evaluate(() => window.networkFixture), value);
  } finally { await page.evaluate(() => { window.networkRetryFailure = false; }); }
});

test('network diagnostics and recovery remain readable across nine languages and both themes', { skip: noDisplay }, async () => {
  const artifacts = path.join(project, 'test-artifacts/network-status-ui');
  await mkdir(artifacts, { recursive: true });
  for (const language of languages) for (const theme of ['dark', 'light']) {
    await desktop.browserWindow(page).then(window => window.evaluate((win, size) => win.setSize(size.width, size.height), { width: language === 'de' ? 960 : 1280, height: 900 }));
    const value = { ...withRecovery('waiting', 8), proxies: [{ ...proxy, network: { ok: false, scope: 'egress', errorCode: 'NETWORK_TIMEOUT', diagnostics: { version: 1, attempts: [diagnostics.attempts[0], { ...diagnostics.attempts[0], source: 'ipapi.co' }] } } }],
      settings: { ...snapshot().settings, language, appearance: theme } };
    const row = await open(value);
    const notice = page.getByRole('region', { name: translate('网络恢复', language) });
    const retry = notice.getByRole('button', { name: translate('立即重试', language), exact: true });
    await retry.waitFor();
    await row.getByText(translate('连接超时', language), { exact: true }).first().waitFor();
    await row.locator('.network-diagnostics > summary').click();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${language}/${theme}: page fits`);
    for (const target of [retry, row.locator('.network-diagnostic-content')]) {
      assert.equal(await target.evaluate(element => element.scrollWidth <= element.clientWidth + 1), true, `${language}/${theme}: content fits`);
    }
    assert.equal(await retry.evaluate(element => { const box = element.getBoundingClientRect(); const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2); return element === hit || element.contains(hit); }), true, `${language}/${theme}: retry remains clickable`);
    if (language === 'zh-CN' || language === 'en') await page.screenshot({ path: path.join(artifacts, `${language}-${theme}.png`) });
  }
});
