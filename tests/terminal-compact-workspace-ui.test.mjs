import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';

// Actual TerminalDock and xterm in a hidden, disposable renderer. The fake
// backend owns only JSON state: it cannot create a PTY, shell, SSH or browser.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const profileId = 'compact_terminal_environment';
const otherId = 'compact_terminal_other';
const profiles = [{ id: profileId, name: 'Synthetic terminal workspace', timezone: 'UTC' },
  { id: otherId, name: 'Second synthetic workspace', timezone: 'UTC' }];
const saved = { id: 'compact_saved_entry', name: 'Saved synthetic terminal', profileId, kind: 'shell',
  cwd: '/synthetic/project', browserProfileId: profileId, claudeAccountId: null, claudeAccountName: null,
  sessionId: null, status: 'saved', activeSessionCount: 0, networkRef: { kind: 'direct', proxyId: null } };
const sessions = count => Array.from({ length: count }, (_, index) => ({
  sessionId: `compact_session_${index}`, profileId, kind: 'shell', status: 'running', sequence: 0,
  savedTerminalId: index === 0 ? saved.id : null,
  savedTerminalName: `Synthetic terminal ${index + 1} with a deliberately long session name`,
  cwd: '/synthetic/project', browserProfileId: profileId, browserName: 'Synthetic browser',
  columns: 80, rows: 24, replay: `Synthetic session ${index + 1} prompt\r\n`,
  startedAt: `2026-01-01T00:00:${String(index).padStart(2, '0')}.000Z`,
}));
let directory, desktop, page;

before(async () => {
  if (noDisplay) return;
  directory = await mkdtemp(path.join(tmpdir(), 'envara-compact-terminal-ui-'));
  const pane = fileURLToPath(new URL('../src/TerminalPane.jsx', import.meta.url));
  const messages = fileURLToPath(new URL('../src/i18n.mjs', import.meta.url));
  const output = await build({ stdin: { resolveDir: path.dirname(pane), loader: 'jsx', contents: `
import React, { useLayoutEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { TerminalDock } from ${JSON.stringify(pane)};
import { TerminalWindowApp } from './TerminalWindowApp.jsx';
const root = createRoot(document.querySelector('#root'));
const clone = value => JSON.parse(JSON.stringify(value));
const listeners = new Set();
window.compactSubscribe = listener => { listeners.add(listener); return () => listeners.delete(listener); };
window.compactListenerCount = () => listeners.size;
window.compactApi = async (method, args = {}) => {
  window.compactCalls.push({ method, args: clone(args) });
  const state = window.compactFixture;
  if (method === 'snapshot') return clone({ profiles: state.environments, system: {} });
  if (method === 'listTerminalSshConnections') return { supported: true, connections: [],
    routeOptions: [{ route: { kind: 'host' }, label: '本机网络', available: true }], defaultRoute: { kind: 'host' } };
  if (method === 'terminalSnapshot') return clone({ profiles: state.snapshot.profiles.filter(profile => !args.id || profile.profileId === args.id) });
  if (method === 'resizeTerminal' || method === 'writeTerminal') return {};
  if (method === 'closeTerminal') {
    const session = state.snapshot.profiles.flatMap(profile => profile.sessions).find(item => item.sessionId === args.sessionId);
    if (!session) throw new Error('Unknown synthetic session');
    session.status = 'closed';
    return clone(session);
  }
  throw new Error('Unexpected compact fixture operation: ' + method);
};
function Fixture() {
  const [visible, setVisible] = useState(window.compactFixture.visible !== false);
  useLayoutEffect(() => { window.compactSetVisible = setVisible; }, []);
  const standalone = window.compactFixture.standalone === true;
  if (window.compactFixture.windowApp) return <TerminalWindowApp profileId=${JSON.stringify(profileId)} sessionId="compact_session_0" />;
  return <div className={standalone ? 'terminal-window-shell' : 'app-shell terminal-visible terminal-workspace'}>
    {!standalone && <><aside className="sidebar" /><main className="main-panel">Synthetic workspace only</main></>}
    <TerminalDock profiles={window.compactFixture.environments} selectedProfileId=${JSON.stringify(profileId)}
      workspace={!standalone} expanded={!standalone} standalone={standalone} visible={visible} screenReaderMode={window.compactFixture.screenReaderMode === true}
      onHide={() => setVisible(false)} onProfilesChange={value => { window.compactRendered = value; }} />
  </div>;
}
let revision = 0;
window.mountCompact = options => {
  window.compactFixture = options; window.compactCalls = []; window.compactRendered = null;
  document.documentElement.dataset.theme = options.theme || 'dark';
  root.render(<Fixture key={++revision} />);
};
window.compactReady = true;
` }, bundle: true, platform: 'browser', format: 'iife', write: false, mainFields: ['module', 'main'], loader: { '.css': 'empty' },
    plugins: [{ name: 'isolated-compact-terminal-ipc', setup(builder) {
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|appearance\.jsx)$/ }, args => ({ path: args.path, namespace: 'compact-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'compact-fixture' }, args => ({
        contents: args.path.endsWith('client.js')
          ? 'export const api = { isDesktop: true, subscribe: () => () => {}, onTerminalEvent: listener => window.compactSubscribe(listener), call: (...args) => window.compactApi(...args) };'
          : args.path.endsWith('appearance.jsx') ? 'export const useAppearance = () => ({ effective: window.compactFixture.theme || "dark" });'
            : `import { translate } from ${JSON.stringify(messages)}; export const useI18n = () => ({ language: 'zh-CN', t: (text, vars) => translate(text, 'zh-CN', vars) });`,
        resolveDir: path.dirname(pane), loader: 'js',
      }));
    } }],
  });
  await writeFile(path.join(directory, 'renderer.js'), output.outputFiles[0].text);
  const css = await Promise.all(['styles.css', 'terminal.css', 'terminal-window.css', 'ssh-workspace.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  css.unshift(await readFile(new URL('../node_modules/@xterm/xterm/css/xterm.css', import.meta.url), 'utf8'));
  await writeFile(path.join(directory, 'index.html'), `<html lang="zh-CN" data-theme="dark"><head><meta charset="utf-8"><style>${css.join('\n')}</style></head><body><div id="root"></div><script src="renderer.js"></script></body></html>`);
  const main = path.join(directory, 'main.cjs');
  await writeFile(main, `const { app, BrowserWindow } = require('electron'); app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))}); app.whenReady().then(() => { app.dock?.hide(); const view = new BrowserWindow({ show: false, width: 1120, height: 720, webPreferences: { sandbox: true, backgroundThrottling: false } }); view.loadFile(${JSON.stringify(path.join(directory, 'index.html'))}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [main], env, timeout: 15000 });
  page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  await page.waitForFunction(() => window.compactReady === true);
});

after(async () => {
  try { await desktop?.close(); }
  finally { if (directory) await rm(directory, { recursive: true, force: true }); }
});

const calls = () => page.evaluate(() => window.compactCalls);
const frames = () => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
async function mount(options = {}) {
  const active = options.sessions ?? sessions(2);
  const snapshot = { profiles: [{ profileId, cwd: '/synthetic/project', savedTerminals: [saved], sessions: active },
    { profileId: otherId, cwd: '/synthetic/other-project', savedTerminals: [], sessions: [] }] };
  await page.evaluate(value => window.mountCompact(value), { snapshot, environments: profiles, ...options });
  if (!options.windowApp) await page.waitForFunction(() => window.compactRendered !== null);
  if (active.length) await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor({ state: options.visible === false ? 'attached' : 'visible' });
  await frames();
}
async function setSize(width, height) {
  await desktop.evaluate(({ BrowserWindow }, size) => BrowserWindow.getAllWindows()[0].setContentSize(size.width, size.height), { width, height });
  await frames();
}
async function assertNoCommandOrSpawn() {
  const forbidden = (await calls()).filter(call => ['writeTerminal', 'openTerminal', 'duplicateTerminal', 'reopenSavedTerminal'].includes(call.method));
  assert.deepEqual(forbidden, []);
}
const rect = locator => locator.evaluate(element => { const box = element.getBoundingClientRect(); return { x: box.x, y: box.y, width: box.width, height: box.height }; });

test('workspace devotes at least eighty percent of its height to the terminal at both desktop sizes', { skip: noDisplay }, async () => {
  for (const [width, height] of [[1120, 720], [1500, 940]]) for (const theme of ['dark', 'light']) {
    await setSize(width, height); await mount({ theme });
    const dock = await rect(page.locator('.terminal-dock'));
    const content = await rect(page.locator('.terminal-content'));
    assert.ok(content.height / dock.height >= .8, `${width}x${height}/${theme}: content ${content.height}, dock ${dock.height}`);
    assert.ok(content.height / height >= .75, 'the terminal fills the right workspace rather than a short bottom panel');
    assert.equal(await page.getByRole('combobox', { name: '终端环境', exact: true }).count(), 1);
    assert.equal(await page.locator('.terminal-environment-tabs').count(), 0);
    assert.equal(await page.locator('.terminal-context-menu').evaluate(element => element.open), false);
    assert.equal(await page.locator('.terminal-saved-terminals').evaluate(element => element.open), false);
    await assertNoCommandOrSpawn();
    if (width === 1120 && theme === 'dark') {
      const artifacts = fileURLToPath(new URL('../test-artifacts/terminal-compact-ui/', import.meta.url));
      await mkdir(artifacts, { recursive: true, mode: 0o700 });
      await page.screenshot({ path: path.join(artifacts, 'zh-CN-terminal.png') });
    }
  }
});

test('long session tabs scroll within one toolbar without horizontal page overflow or terminal input', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(14) });
  const list = page.getByRole('tablist', { name: '终端会话', exact: true });
  const tabs = list.getByRole('tab');
  assert.equal(await tabs.count(), 14);
  assert.equal(await list.evaluate(element => element.scrollWidth > element.clientWidth), true);
  await tabs.last().focus(); await tabs.last().press('Home');
  await page.waitForFunction(() => document.querySelector('.terminal-session-tab')?.getAttribute('aria-selected') === 'true');
  assert.equal(await list.evaluate(element => element.scrollLeft <= 1), true);
  await tabs.first().press('End');
  await page.waitForFunction(() => [...document.querySelectorAll('.terminal-session-tab')].at(-1)?.getAttribute('aria-selected') === 'true');
  assert.ok(await list.evaluate(element => element.scrollLeft > 0));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  const first = await rect(tabs.first()), last = await rect(tabs.last());
  assert.ok(Math.abs(first.y - last.y) <= 1, 'session tabs stay in a single toolbar row');
  await assertNoCommandOrSpawn();
});

test('settings and saved entries float without shrinking content and remain hittable inside the viewport', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount();
  const content = await rect(page.locator('.terminal-content'));
  for (const [detailsSelector, panelSelector] of [['.terminal-context-menu', '.terminal-context-panel'], ['.terminal-saved-terminals', '.terminal-saved-panel']]) {
    const details = page.locator(detailsSelector);
    await details.locator('summary').press('Enter');
    await details.locator(panelSelector).waitFor({ state: 'visible' });
    assert.equal((await rect(page.locator('.terminal-content'))).height, content.height);
    const panel = await rect(details.locator(panelSelector));
    assert.ok(panel.x >= 0 && panel.y >= 0 && panel.x + panel.width <= 1121 && panel.y + panel.height <= 721);
    const button = details.locator(panelSelector).getByRole('button').first();
    await button.scrollIntoViewIfNeeded();
    assert.equal(await button.evaluate(element => { const box = element.getBoundingClientRect(); const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2); return element === hit || element.contains(hit); }), true, `${panelSelector} is not clipped by a toolbar ancestor`);
    await button.focus();
    await page.keyboard.press('Escape');
    await frames();
    assert.equal(await details.evaluate(element => element.open), false);
    assert.equal(await details.locator('summary').evaluate(element => document.activeElement === element), true, `${detailsSelector} retains summary focus after Escape`);
  }
  await assertNoCommandOrSpawn();
});

test('close acts only on the selected session and keeps the other process view', { skip: noDisplay }, async () => {
  await mount();
  const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
  await tabs.first().click();
  await page.evaluate(() => { window.otherCompactView = document.querySelectorAll('.terminal-session-view')[1]; });
  await page.getByRole('button', { name: '关闭会话', exact: true }).click();
  await page.waitForFunction(() => window.compactFixture.snapshot.profiles[0].sessions[0].status === 'closed');
  await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab').length === 1);
  assert.equal(await page.locator('.terminal-session-view:not([hidden])').evaluate(element => element === window.otherCompactView), true);
  assert.deepEqual((await calls()).filter(call => call.method === 'closeTerminal'), [{ method: 'closeTerminal', args: { sessionId: 'compact_session_0' } }]);
  await assertNoCommandOrSpawn();
});

test('hiding and restoring workspace and standalone views retains xterm and subscriptions without closing sessions', { skip: noDisplay }, async () => {
  for (const standalone of [false, true]) {
    await mount({ standalone, visible: false });
    assert.equal(await page.locator('.terminal-dock').isVisible(), false);
    assert.equal(await page.evaluate(() => window.compactListenerCount()), 1);
    await page.evaluate(() => { window.compactRetainedXterm = document.querySelector('.terminal-session-view.is-selected .xterm'); window.compactSetVisible(true); });
    await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor({ state: 'visible' });
    assert.equal(await page.locator('.terminal-session-view:not([hidden]) .xterm').evaluate(element => element === window.compactRetainedXterm), true);
    await page.evaluate(() => window.compactSetVisible(false));
    await page.locator('.terminal-dock').waitFor({ state: 'hidden' });
    await page.evaluate(() => window.compactSetVisible(true));
    await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor({ state: 'visible' });
    assert.equal(await page.locator('.terminal-session-view:not([hidden]) .xterm').evaluate(element => element === window.compactRetainedXterm), true);
    assert.equal((await calls()).filter(call => call.method === 'closeTerminal').length, 0);
    await assertNoCommandOrSpawn();
  }
});

test('independent window keyboard tabs retain focus when the real xterm view becomes visible', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ windowApp: true });
  const terminal = page.getByRole('tab', { name: '终端', exact: true });
  const ssh = page.getByRole('tab', { name: 'SSH 连接', exact: true });
  await terminal.focus();
  for (const returnKey of ['Home', 'ArrowLeft']) {
    await terminal.press('ArrowRight');
    await frames();
    assert.equal(await ssh.evaluate(element => document.activeElement === element), true);
    assert.equal(await page.locator('.terminal-dock').isVisible(), false);
    await ssh.press(returnKey);
    await frames();
    assert.equal(await page.locator('.terminal-dock').isVisible(), true);
    assert.equal(await terminal.evaluate(element => document.activeElement === element), true, `${returnKey} preserves the outer tab focus after xterm resumes`);
  }
  await assertNoCommandOrSpawn();
});

test('an empty environment shows saved entries and the new-session chooser never auto-starts a terminal', { skip: noDisplay }, async () => {
  await mount({ sessions: [] });
  assert.equal(await page.locator('.terminal-saved-terminals').evaluate(element => element.open), true);
  assert.equal(await page.locator('.terminal-session-tab').count(), 0);
  await assertNoCommandOrSpawn();
  await page.getByRole('button', { name: '新建会话', exact: true }).click();
  await page.locator('.terminal-new-session').waitFor({ state: 'visible' });
  await page.locator('.terminal-new-session-actions').getByRole('button', { name: '取消', exact: true }).click();
  await page.locator('.terminal-new-session').waitFor({ state: 'hidden' });
  await assertNoCommandOrSpawn();
});
