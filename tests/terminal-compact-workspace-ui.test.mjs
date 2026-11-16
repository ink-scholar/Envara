import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages, translate } from '../src/i18n.mjs';

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
window.compactEmit = (sessionId, type, data) => {
  const session = window.compactFixture.snapshot.profiles.flatMap(profile => profile.sessions).find(item => item.sessionId === sessionId);
  if (!session) throw new Error('Unknown synthetic session');
  session.sequence++;
  if (type === 'data') session.replay += data;
  const event = { type, sessionId, profileId: session.profileId, sequence: session.sequence,
    ...(session.requestId ? { requestId: session.requestId } : {}),
    ...(type === 'data' ? { data } : { status: session.status }) };
  listeners.forEach(listener => listener(clone(event)));
};
window.compactUpload = async (args, files) => {
  window.compactCalls.push({ method: 'stageTerminalAttachments', args: clone(args), files: files.map(file => ({ name: file.name, size: file.size, type: file.type })) });
  const state = window.compactFixture;
  if (state.deferAttachment) await new Promise(resolve => { window.compactFinishAttachment = resolve; });
  if (state.attachmentError) throw Object.assign(new Error('Synthetic attachment refusal'), { code: state.attachmentError });
  return { transferId: args.transferId, quotedPaths: "'/synthetic/attachments/image.png'" };
};
window.compactApi = async (method, args = {}) => {
  window.compactCalls.push({ method, args: clone(args) });
  const state = window.compactFixture;
  if (method === 'snapshot') return clone({ profiles: state.environments, system: {} });
  if (method === 'listTerminalSshConnections') return { supported: true, connections: [],
    routeOptions: [{ route: { kind: 'host' }, label: '本机网络', available: true }], defaultRoute: { kind: 'host' } };
  if (method === 'terminalSnapshot') return clone({ profiles: state.snapshot.profiles.filter(profile => !args.id || profile.profileId === args.id) });
  if (method === 'listClaudeAccounts') return clone({ accounts: state.accountsByProfile?.[args.id] ?? [] });
  if (method === 'claudeInstallationStatus') return { installed: true };
  if (method === 'cancelTerminalAttachments' || method === 'commitTerminalAttachments') return {};
  if (method === 'resizeTerminal' || method === 'writeTerminal') return {};
  if (method === 'openTerminal' && state.deferOpen) {
    const profile = state.snapshot.profiles.find(profile => profile.profileId === args.id);
    if (!profile || !args.requestId) throw new Error('Deferred synthetic launch requires a valid request');
    const session = { sessionId: 'compact_open_' + profile.sessions.length, profileId: args.id,
      kind: args.kind || 'shell', status: 'starting', sequence: 0, replay: '', requestId: args.requestId,
      cwd: profile.cwd, columns: args.columns, rows: args.rows, savedTerminalName: 'Synthetic pending terminal',
      startedAt: '2026-01-01T02:00:00.000Z' };
    profile.sessions.push(session);
    window.compactEmit(session.sessionId, 'status');
    return await new Promise(resolve => {
      window.compactPendingOpen = { sessionId: session.sessionId, requestId: session.requestId, finish: () => {
        session.status = 'running'; session.replay = 'Synthetic newly opened shell prompt\\r\\n';
        window.compactEmit(session.sessionId, 'status');
        resolve(clone(session));
      } };
    });
  }
  if (method === 'duplicateTerminal') {
    const profile = state.snapshot.profiles.find(profile => profile.sessions.some(item => item.sessionId === args.sessionId));
    const source = profile?.sessions.find(item => item.sessionId === args.sessionId);
    if (!source || source.status !== 'running') throw new Error('Unknown running synthetic session');
    const duplicate = { ...clone(source), sessionId: 'compact_duplicate_' + profile.sessions.length, sequence: 0,
      replay: 'Synthetic independent shell prompt\\r\\n', startedAt: '2026-01-01T01:00:00.000Z' };
    profile.sessions.push(duplicate);
    if (state.deferDuplicate) {
      duplicate.status = 'starting'; duplicate.replay = '';
      window.compactEmit(duplicate.sessionId, 'status');
      return await new Promise(resolve => {
        window.compactPendingDuplicate = { sessionId: duplicate.sessionId, finish: () => {
          duplicate.status = 'running'; duplicate.replay = 'Synthetic independent shell prompt\\r\\n';
          window.compactEmit(duplicate.sessionId, 'status');
          resolve(clone(duplicate));
        } };
      });
    }
    return clone(duplicate);
  }
  if (method === 'reopenSavedTerminal' && state.deferReopen) {
    const profile = state.snapshot.profiles.find(profile => profile.profileId === args.id);
    const entry = profile?.savedTerminals.find(entry => entry.id === args.entryId);
    if (!entry || !args.requestId) throw new Error('Unknown synthetic saved terminal');
    const session = { ...clone(entry), sessionId: 'compact_reopen_' + profile.sessions.length, profileId: args.id,
      requestId: args.requestId, status: 'starting', sequence: 0, replay: '', columns: 80, rows: 24,
      savedTerminalName: entry.name, startedAt: '2026-01-01T03:00:00.000Z' };
    profile.sessions.push(session);
    window.compactEmit(session.sessionId, 'status');
    return await new Promise(resolve => {
      window.compactPendingReopen = { sessionId: session.sessionId, finish: () => {
        session.status = 'running'; session.replay = 'Synthetic reopened shell prompt\\r\\n';
        window.compactEmit(session.sessionId, 'status');
        resolve(clone(session));
      } };
    });
  }
  if (method === 'closeTerminal') {
    const session = state.snapshot.profiles.flatMap(profile => profile.sessions).find(item => item.sessionId === args.sessionId);
    if (!session) throw new Error('Unknown synthetic session');
    if (state.deferClose) {
      session.status = 'closing'; window.compactEmit(session.sessionId, 'status');
      return await new Promise(resolve => {
        window.compactPendingClose = { finish: () => {
          session.status = 'closed'; window.compactEmit(session.sessionId, 'status'); resolve(clone(session));
        } };
      });
    }
    session.status = 'closed';
    return clone(session);
  }
  throw new Error('Unexpected compact fixture operation: ' + method);
};
function Fixture() {
  const [visible, setVisible] = useState(window.compactFixture.visible !== false);
  const [, setTerminalProfiles] = useState([]);
  useLayoutEffect(() => { window.compactSetVisible = setVisible; }, []);
  const standalone = window.compactFixture.standalone === true;
  if (window.compactFixture.windowApp) return <TerminalWindowApp profileId=${JSON.stringify(profileId)} sessionId="compact_session_0" />;
  return <div className={standalone ? 'terminal-window-shell' : 'app-shell is-desktop terminal-visible terminal-workspace terminal-expanded'}>
    {!standalone && <div className="desktop-titlebar" aria-hidden="true" />}
    {!standalone && <><aside className="sidebar" /><main className="main-panel">Synthetic workspace only</main></>}
    <TerminalDock profiles={window.compactFixture.environments.map(profile => ({ ...profile }))} selectedProfileId=${JSON.stringify(profileId)}
      workspace={!standalone} expanded={!standalone} standalone={standalone} visible={visible} screenReaderMode={window.compactFixture.screenReaderMode === true}
      onConfigureLinkBrowser={profileId => { window.compactCalls.push({ method: 'configureLinkBrowser', args: { profileId } }); }}
      onHide={() => setVisible(false)} onProfilesChange={value => { window.compactRendered = value; setTerminalProfiles(value); }} />
  </div>;
}
let revision = 0;
window.mountCompact = options => {
  window.compactFixture = { language: 'zh-CN', ...options }; window.compactCalls = []; window.compactRendered = null;
  window.compactPendingOpen = null; window.compactPendingDuplicate = null; window.compactPendingReopen = null; window.compactPendingClose = null;
  window.compactFinishAttachment = null;
  document.documentElement.lang = window.compactFixture.language;
  document.documentElement.dataset.theme = options.theme || 'dark';
  root.render(<Fixture key={++revision} />);
};
window.compactReady = true;
` }, bundle: true, platform: 'browser', format: 'iife', write: false, mainFields: ['module', 'main'], loader: { '.css': 'empty' },
    plugins: [{ name: 'isolated-compact-terminal-ipc', setup(builder) {
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|appearance\.jsx)$/ }, args => ({ path: args.path, namespace: 'compact-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'compact-fixture' }, args => ({
        contents: args.path.endsWith('client.js')
          ? 'export const api = { isDesktop: true, subscribe: () => () => {}, onTerminalEvent: listener => window.compactSubscribe(listener), call: (...args) => window.compactApi(...args), stageTerminalAttachments: (...args) => window.compactUpload(...args) };'
          : args.path.endsWith('appearance.jsx') ? 'export const useAppearance = () => ({ effective: window.compactFixture.theme || "dark" });'
            : `import { translate } from ${JSON.stringify(messages)}; export const useI18n = () => ({ language: window.compactFixture.language, t: (text, vars) => translate(text, window.compactFixture.language, vars) });`,
        resolveDir: path.dirname(pane), loader: 'js',
      }));
    } }],
  });
  await writeFile(path.join(directory, 'renderer.js'), output.outputFiles[0].text);
  const css = await Promise.all(['styles.css', 'terminal.css', 'terminal-window.css', 'ssh-workspace.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  css.unshift(await readFile(new URL('../node_modules/@xterm/xterm/css/xterm.css', import.meta.url), 'utf8'));
  await writeFile(path.join(directory, 'index.html'), `<html lang="zh-CN" data-theme="dark"><head><meta charset="utf-8"><style>${css.join('\n')}</style></head><body><div id="root"></div><script src="renderer.js"></script></body></html>`);
  const main = path.join(directory, 'main.cjs');
  await writeFile(main, `const { app, BrowserWindow } = require('electron'); app.setPath('userData', ${JSON.stringify(path.join(directory, 'data'))}); app.whenReady().then(() => { app.dock?.hide(); const view = new BrowserWindow({ show: false, width: 1120, height: 720, ...(process.platform === 'darwin' ? { titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 18, y: 17 } } : {}), webPreferences: { sandbox: true, backgroundThrottling: false } }); view.loadFile(${JSON.stringify(path.join(directory, 'index.html'))}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [main], env, timeout: 15000 });
  page = await desktop.firstWindow(); page.setDefaultTimeout(5000);
  await page.waitForFunction(() => window.compactReady === true);
});

after(async () => {
  try {
    if (desktop && process.env.ENVARA_NATIVE_TERMINAL_CLICK_FIXTURE === '1') {
      await setSize(1120, 720);
      await mount({ sessions: sessions(2).map((session, index) => ({ ...session, savedTerminalName: `Synthetic session ${index ? 'B' : 'A'}` })) });
      const title = 'Envara synthetic terminal click validation';
      await desktop.evaluate(({ BrowserWindow }, title) => { const view = BrowserWindow.getAllWindows()[0]; view.setTitle(title); view.show(); }, title);
      const finishFile = path.join(directory, 'finish-native-click');
      console.log('NATIVE_TERMINAL_FIXTURE ' + JSON.stringify({ pid: desktop.process().pid, executable: desktop.process().spawnfile, title, finishFile }));
      // Opt-in native hit-test handoff: only this synthetic window is shown.
      // A bounded wait and the usual finally block own all cleanup.
      const deadline = Date.now() + 180_000;
      while (Date.now() < deadline) {
        if (await readFile(finishFile).then(() => true, () => false)) break;
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }
  finally {
    try { await desktop?.close(); }
    finally { if (directory) await rm(directory, { recursive: true, force: true }); }
  }
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

test('pointer clicks switch partially visible tabs in the desktop workspace', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(2) });
  const list = page.getByRole('tablist', { name: '终端会话', exact: true });
  const tabs = list.getByRole('tab');
  await tabs.last().focus(); await tabs.last().press('End');
  await frames();
  const target = tabs.first();
  const targetBox = await rect(target), listBox = await rect(list);
  assert.ok(targetBox.x < listBox.x, 'the target begins outside the visible tab strip');
  const x = Math.max(targetBox.x, listBox.x) + 10;
  const y = targetBox.y + targetBox.height / 2;
  assert.ok(x < Math.min(targetBox.x + targetBox.width, listBox.x + listBox.width));
  assert.equal(await target.getAttribute('aria-selected'), 'false');
  // A real click in the visible part of a tab must work without Playwright
  // first scrolling/focusing the locator on the user's behalf.
  await page.mouse.click(x, y);
  await frames();
  assert.equal(await target.getAttribute('aria-selected'), 'true');
  await assertNoCommandOrSpawn();
});

test('desktop and independent session tabs keep their selected views during output and snapshot updates', { skip: noDisplay }, async () => {
  for (const windowApp of [false, true]) {
    await setSize(1120, 720); await mount({ windowApp });
    const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
    await page.evaluate(() => { window.compactViews = [...document.querySelectorAll('.terminal-session-view')]; });
    for (const index of [1, 0, 1, 0]) {
      await tabs.nth(index).click(); await frames();
      assert.equal(await tabs.nth(index).getAttribute('aria-selected'), 'true');
      assert.equal(await page.locator('.terminal-session-view:not([hidden])').evaluate((element, i) => element === window.compactViews[i], index), true);
      const snapshotsBefore = (await calls()).filter(call => call.method === 'terminalSnapshot').length;
      await page.evaluate(() => {
        window.compactEmit('compact_session_0', 'data', 'source output\r\n');
        window.compactEmit('compact_session_1', 'data', 'other output\r\n');
        window.compactEmit('compact_session_0', 'status');
      });
      await page.waitForFunction(count => window.compactCalls.filter(call => call.method === 'terminalSnapshot').length > count, snapshotsBefore);
      await frames();
      assert.equal(await tabs.nth(index).getAttribute('aria-selected'), 'true', 'stream and refresh must not reselect the latest tab');
      assert.equal(await page.locator('.terminal-session-view:not([hidden])').count(), 1);
      assert.equal(await page.locator('.terminal-session-view:not([hidden])').evaluate((element, i) => element === window.compactViews[i], index), true);
    }
    await assertNoCommandOrSpawn();
  }
});

async function startDeferredTerminal({ switchBack = true } = {}) {
  await setSize(1120, 720); await mount({ sessions: sessions(1), deferOpen: true });
  await page.getByRole('button', { name: '新建会话', exact: true }).click();
  await page.locator('.terminal-new-session-actions').getByRole('button', { name: '打开终端', exact: true }).click();
  await page.waitForFunction(() => window.compactPendingOpen && document.querySelectorAll('.terminal-session-tab').length === 2);
  const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
  await frames();
  assert.equal(await tabs.last().getAttribute('aria-selected'), 'true', 'the initial launch selects the new terminal');
  if (switchBack) {
    await tabs.first().click(); await frames();
    assert.equal(await tabs.first().getAttribute('aria-selected'), 'true', 'the user can return to the existing terminal while a new one starts');
  }
  return tabs;
}

test('repeated launch progress preserves a later explicit terminal tab selection', { skip: noDisplay }, async () => {
  const tabs = await startDeferredTerminal();
  for (let progress = 0; progress < 3; progress++) {
    await page.evaluate(() => window.compactEmit(window.compactPendingOpen.sessionId, 'status'));
    await frames();
    assert.equal(await tabs.first().getAttribute('aria-selected'), 'true', 'startup progress must not steal the selected terminal');
  }
  await page.evaluate(() => window.compactPendingOpen.finish());
});

test('a pending launch reply preserves the terminal tab the user selected after starting it', { skip: noDisplay }, async () => {
  const tabs = await startDeferredTerminal();
  await page.evaluate(() => window.compactPendingOpen.finish());
  await page.locator('.terminal-new-session').waitFor({ state: 'hidden' });
  await frames();
  assert.equal(await tabs.first().getAttribute('aria-selected'), 'true', 'launch completion must not overwrite the newer user selection');
  assert.equal(await tabs.last().locator('small').count(), 0, 'the newly opened terminal is still available');
  assert.deepEqual((await calls()).filter(call => ['writeTerminal', 'duplicateTerminal', 'closeTerminal'].includes(call.method)), []);
});

test('a launch remains selected when the user has not switched to another terminal', { skip: noDisplay }, async () => {
  const tabs = await startDeferredTerminal({ switchBack: false });
  await page.evaluate(() => window.compactEmit(window.compactPendingOpen.sessionId, 'status'));
  await frames();
  assert.equal(await tabs.last().getAttribute('aria-selected'), 'true');
  await page.evaluate(() => window.compactPendingOpen.finish());
  await page.locator('.terminal-new-session').waitFor({ state: 'hidden' });
  await frames();
  assert.equal(await tabs.last().getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea').evaluate(element => document.activeElement === element), true);
});

test('a pending copy reply preserves a terminal tab selected while the new shell was starting', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(2), deferDuplicate: true });
  const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
  await tabs.first().click();
  await page.locator('.terminal-toolbar-actions').getByRole('button', { name: '复制会话', exact: true }).click();
  await page.waitForFunction(() => window.compactPendingDuplicate && document.querySelectorAll('.terminal-session-tab').length === 3);
  await tabs.nth(1).click(); await frames();
  assert.equal(await tabs.nth(1).getAttribute('aria-selected'), 'true');
  await page.evaluate(() => window.compactPendingDuplicate.finish());
  await page.waitForFunction(() => document.querySelector('.terminal-duplicate-session')?.disabled === false);
  await frames();
  assert.equal(await tabs.nth(1).getAttribute('aria-selected'), 'true', 'copy completion must not overwrite the newer user selection');
  assert.equal(await tabs.last().locator('small').count(), 0, 'the independent copy is available without taking over the view');
  assert.deepEqual((await calls()).filter(call => ['writeTerminal', 'openTerminal', 'closeTerminal'].includes(call.method)), []);
});

test('copying an implicitly selected terminal preserves it after switching away from and back to its environment', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(1), deferDuplicate: true });
  // The source is initially selected by the existing-session fallback, without
  // a tab click having populated the explicit selection map.
  await page.locator('.terminal-toolbar-actions').getByRole('button', { name: '复制会话', exact: true }).click();
  await page.waitForFunction(() => window.compactPendingDuplicate && document.querySelectorAll('.terminal-session-tab').length === 2);
  const environment = page.getByRole('combobox', { name: '终端环境', exact: true });
  await environment.selectOption(otherId);
  await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab').length === 0);
  await environment.selectOption(profileId);
  await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab').length === 2);
  await page.evaluate(() => window.compactPendingDuplicate.finish());
  await page.waitForFunction(() => document.querySelector('.terminal-duplicate-session')?.disabled === false);
  await frames();
  const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
  assert.equal(await tabs.first().getAttribute('aria-selected'), 'true', 'the source remains selected after an explicit environment round trip');
  assert.equal(await tabs.last().getAttribute('aria-selected'), 'false');
});

test('a pending close reply does not replace a later selection with the last remaining terminal', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(3), deferClose: true });
  const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
  await tabs.first().click();
  await page.getByRole('button', { name: '关闭会话', exact: true }).click();
  await page.waitForFunction(() => Boolean(window.compactPendingClose));
  await tabs.nth(1).click(); await frames();
  assert.equal(await tabs.nth(1).getAttribute('aria-selected'), 'true');
  await page.evaluate(() => window.compactPendingClose.finish());
  await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab').length === 2);
  await frames();
  assert.equal(await tabs.first().getAttribute('aria-selected'), 'true', 'closing the old tab must preserve the explicitly selected middle session');
  assert.equal(await tabs.last().getAttribute('aria-selected'), 'false');
  assert.deepEqual((await calls()).filter(call => call.method === 'closeTerminal'), [{ method: 'closeTerminal', args: { sessionId: 'compact_session_0' } }]);
});

test('a pending saved-terminal reopen respects a later click on an existing session', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(2), deferReopen: true });
  await page.locator('.terminal-saved-terminals > summary').press('Enter');
  await page.getByRole('button', { name: `打开终端「${saved.name}」`, exact: true }).click();
  await page.waitForFunction(() => window.compactPendingReopen && document.querySelectorAll('.terminal-session-tab').length === 3);
  const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
  await tabs.first().click(); await frames();
  assert.equal(await tabs.first().getAttribute('aria-selected'), 'true');
  await page.evaluate(() => window.compactPendingReopen.finish());
  await page.waitForFunction(() => document.querySelector('.terminal-duplicate-session')?.disabled === false);
  await frames();
  assert.equal(await tabs.first().getAttribute('aria-selected'), 'true', 'reopening a saved terminal must not override a newer explicit choice');
  assert.equal(await tabs.last().locator('small').count(), 0);
  assert.deepEqual((await calls()).filter(call => ['writeTerminal', 'openTerminal', 'duplicateTerminal', 'closeTerminal'].includes(call.method)), []);
});

test('visible copy action selects a separate tab, preserves its login context and routes subsequent input to the selected view', { skip: noDisplay }, async () => {
  const source = { ...sessions(1)[0], kind: 'claude-code', claudeAccountId: 'synthetic-login', claudeAccountName: 'Synthetic login',
    replay: 'Synthetic source conversation\r\n', network: { mode: 'direct', routeName: 'Synthetic route' } };
  for (const windowApp of [false, true]) {
    await setSize(1120, 720); await mount({ sessions: [source], windowApp });
    const copy = page.locator('.terminal-toolbar-actions').getByRole('button', { name: '复制会话', exact: true });
    assert.equal(await copy.isVisible(), true, 'copy is available directly in the toolbar');
    assert.equal(await page.locator('.terminal-context-menu').evaluate(element => element.open), false);
    await page.evaluate(() => { window.compactSourceView = document.querySelector('.terminal-session-view'); });
    await copy.click();
    const tabs = page.getByRole('tablist', { name: '终端会话', exact: true }).getByRole('tab');
    await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab').length === 2);
    await frames();
    assert.equal(await tabs.last().getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea').evaluate(element => document.activeElement === element), true, 'the copied terminal receives input focus without an extra click');
    assert.equal(await page.locator('.terminal-session-view:not([hidden])').evaluate(element => element !== window.compactSourceView), true);
    assert.deepEqual((await calls()).filter(call => ['openTerminal', 'writeTerminal', 'duplicateTerminal', 'closeTerminal'].includes(call.method)),
      [{ method: 'duplicateTerminal', args: { sessionId: source.sessionId } }], 'copy does not replay source input or close its session');
    const duplicate = await page.evaluate(() => window.compactFixture.snapshot.profiles[0].sessions.at(-1));
    assert.equal(duplicate.claudeAccountId, source.claudeAccountId);
    assert.equal(duplicate.browserProfileId, source.browserProfileId);
    assert.equal(duplicate.cwd, source.cwd);
    assert.deepEqual(duplicate.network, source.network);
    assert.notEqual(duplicate.sessionId, source.sessionId);
    assert.equal(duplicate.replay.includes('source conversation'), false);
    if (!windowApp) {
      const artifacts = fileURLToPath(new URL('../test-artifacts/terminal-compact-ui/', import.meta.url));
      await mkdir(artifacts, { recursive: true, mode: 0o700 });
      await page.screenshot({ path: path.join(artifacts, 'zh-CN-duplicate-terminal.png') });
    }
    for (const [index, sessionId, text] of [[0, source.sessionId, 'source-only'], [1, duplicate.sessionId, 'copy-only']]) {
      await tabs.nth(index).click(); await frames();
      const active = page.locator('.terminal-session-view:not([hidden])');
      const input = active.locator('.xterm-helper-textarea');
      await input.focus(); await page.keyboard.type(text);
      await page.waitForFunction(({ sessionId, text }) => window.compactCalls.filter(call => call.method === 'writeTerminal' && call.args.sessionId === sessionId).map(call => call.args.data).join('').includes(text), { sessionId, text });
    }
    const writes = (await calls()).filter(call => call.method === 'writeTerminal');
    assert.equal(writes.filter(call => call.args.sessionId === source.sessionId).map(call => call.args.data).join(''), 'source-only');
    assert.equal(writes.filter(call => call.args.sessionId === duplicate.sessionId).map(call => call.args.data).join(''), 'copy-only');
    assert.equal(await page.locator('.terminal-session-view').first().evaluate(element => element === window.compactSourceView), true, 'switching keeps the original renderer');
  }
});

test('keyboard copy dismisses an unsubmitted saved-entry editor and focuses the new terminal', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount({ sessions: sessions(1) });
  await page.locator('.terminal-saved-terminals > summary').press('Enter');
  const rename = page.getByRole('button', { name: `重命名终端「${saved.name}」`, exact: true });
  await rename.focus(); await page.keyboard.press('Enter');
  await page.getByRole('textbox', { name: '终端名称', exact: true }).fill('Unsubmitted synthetic name');
  const copy = page.locator('.terminal-toolbar-actions').getByRole('button', { name: '复制会话', exact: true });
  await copy.focus(); await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab').length === 2);
  await frames();
  assert.equal(await page.locator('.terminal-saved-editor').count(), 0);
  assert.equal(await page.locator('.terminal-saved-terminals').evaluate(element => element.open), false);
  assert.equal(await page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea').evaluate(element => document.activeElement === element), true);
  await page.keyboard.type('copy-focused');
  await page.waitForFunction(() => window.compactCalls.filter(call => call.method === 'writeTerminal').map(call => call.args.data).join('') === 'copy-focused');
  const writes = (await calls()).filter(call => call.method === 'writeTerminal');
  assert.ok(writes.every(call => call.args.sessionId === 'compact_duplicate_1'));
  assert.deepEqual((await calls()).filter(call => ['renameSavedTerminal', 'openTerminal', 'closeTerminal'].includes(call.method)), []);
  assert.equal(await page.evaluate(() => window.compactFixture.snapshot.profiles[0].savedTerminals[0].name), saved.name);
});

test('copy controls and session tabs remain usable across nine languages and narrow desktop layouts', { skip: noDisplay }, async () => {
  assert.deepEqual([...languages], ['zh-CN', 'zh-TW', 'en', 'ja', 'ko', 'es', 'fr', 'de', 'pt-BR']);
  for (const language of languages) for (const theme of ['dark', 'light']) {
    for (const [windowApp, width] of [[false, 900], [false, 1120], [true, 640]]) {
      await setSize(width, 720); await mount({ language, theme, windowApp });
      const copy = page.locator('.terminal-toolbar-actions').getByRole('button', { name: translate('复制会话', language), exact: true });
      const tabs = page.getByRole('tablist', { name: translate('终端会话', language), exact: true }).getByRole('tab');
      assert.equal(await copy.isVisible(), true);
      assert.equal(await copy.isDisabled(), false);
      assert.equal(await copy.evaluate(element => element.scrollWidth <= element.clientWidth), true, `${language}/${width}: copy label fits`);
      assert.equal(await copy.evaluate(element => { const box = element.getBoundingClientRect(); const hit = document.elementFromPoint(box.x + box.width / 2, box.y + box.height / 2); return element === hit || element.contains(hit); }), true, `${language}/${width}: copy remains hittable`);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true, `${language}/${width}: no horizontal page overflow`);
      await tabs.first().click(); await frames();
      assert.equal(await tabs.first().getAttribute('aria-selected'), 'true');
      await tabs.last().click(); await frames();
      assert.equal(await tabs.last().getAttribute('aria-selected'), 'true');
      await assertNoCommandOrSpawn();
    }
  }
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

test('toolbar hints explain every icon on hover and focus without opening or ending a session', { skip: noDisplay }, async () => {
  await mount();
  const controls = [
    [page.getByRole('button', { name: '复制会话', exact: true }), '复制会话', '使用相同登录档案和环境配置，新建独立终端。'],
    [page.locator('.terminal-saved-terminals > summary'), '已保存终端', '新建后自动保存终端入口，可在此重开或重命名。'],
    [page.getByRole('button', { name: '新建会话', exact: true }), '新建会话', '选择网络、浏览器和工作目录。'],
    [page.locator('.terminal-context-menu > summary'), '会话设置', '查看工作目录、网络和会话选项。'],
    [page.getByRole('button', { name: '独立终端窗口', exact: true }), '独立终端窗口', '在独立窗口中查看此环境的终端'],
    [page.getByRole('button', { name: '收起终端', exact: true }), '收起终端', '收起终端，会话继续运行'],
    [page.getByRole('button', { name: '关闭会话', exact: true }), '结束会话', '结束当前会话，已保存的终端入口会保留。'],
  ];
  for (const [control, title, description] of controls) {
    await control.hover();
    const hint = page.getByRole('tooltip');
    await hint.waitFor({ state: 'visible' });
    assert.equal(await hint.count(), 1);
    assert.equal(await hint.locator('strong').textContent(), title);
    assert.equal(await hint.locator('span').textContent(), description);
    assert.equal(await control.getAttribute('aria-describedby'), await hint.getAttribute('id'));
    assert.equal(await control.getAttribute('title'), null, 'native and styled hints must not overlap');
    if (title === '已保存终端') {
      const artifacts = fileURLToPath(new URL('../test-artifacts/terminal-toolbar-hints/', import.meta.url));
      await mkdir(artifacts, { recursive: true, mode: 0o700 });
      await page.screenshot({ path: path.join(artifacts, 'zh-CN-workspace-hint.png') });
    }
    await page.mouse.move(2, 2);
    await hint.waitFor({ state: 'hidden' });
    await control.focus();
    await hint.waitFor({ state: 'visible' });
    await page.keyboard.press('Escape');
    await hint.waitFor({ state: 'hidden' });
    assert.equal(await control.evaluate(element => document.activeElement === element), true);
  }
  assert.equal(await page.locator('.terminal-saved-terminals').evaluate(element => element.open), false);
  assert.equal(await page.locator('.terminal-context-menu').evaluate(element => element.open), false);
  assert.equal(await page.locator('.terminal-new-session').count(), 0);
  assert.deepEqual((await calls()).filter(call => call.method === 'closeTerminal'), []);
  await assertNoCommandOrSpawn();
});

test('toolbar hints stay hoverable, dismiss on activation and disappear with a hidden dock', { skip: noDisplay }, async () => {
  await mount();
  const saved = page.locator('.terminal-saved-terminals > summary'), hint = page.getByRole('tooltip');
  await saved.hover(); await hint.waitFor({ state: 'visible' });
  await hint.hover();
  await page.waitForTimeout(150);
  assert.equal(await hint.isVisible(), true);
  await saved.click();
  await hint.waitFor({ state: 'hidden' });
  assert.equal(await page.locator('.terminal-saved-note').textContent(), '新建后自动保存终端入口，可在此重开或重命名。');
  await saved.click();
  await page.mouse.move(2, 2);
  await saved.hover(); await hint.waitFor({ state: 'visible' });
  await page.evaluate(() => window.compactSetVisible(false));
  assert.equal(await hint.count(), 0, 'a portal cannot outlive the visible terminal view');
  await assertNoCommandOrSpawn();
  await mount({ sessions: [] });
  const close = page.getByRole('button', { name: '关闭会话', exact: true });
  assert.equal(await close.isDisabled(), true);
  await close.hover();
  await hint.waitFor({ state: 'visible' });
  assert.equal(await hint.locator('strong').textContent(), '结束会话');
  assert.deepEqual((await calls()).filter(call => call.method === 'closeTerminal'), []);
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

function accountAssociationFixture(options = {}) {
  const accountName = options.accountName || 'Synthetic named login profile';
  const owned = sessions(6).map((session, index) => ({ ...session, kind: 'claude-code',
    claudeAccountId: 'synthetic_account_a', claudeAccountName: accountName,
    savedTerminalName: index < 2 ? 'Custom task name' : `Other task ${index}`,
  }));
  owned[2].claudeAccountId = 'synthetic_account_b'; // The display name intentionally matches.
  owned[3].claudeAccountId = 'default'; owned[3].claudeAccountName = 'Renamed default profile';
  owned[4].status = 'closed';
  owned[5].kind = 'shell';
  const foreign = { ...owned[0], profileId: otherId, sessionId: 'foreign_account_session', savedTerminalName: 'Foreign environment task' };
  return { environments: profiles.map(profile => ({ ...profile, proxyId: 'synthetic_proxy', proxyName: 'Synthetic route' })),
    accountsByProfile: {
      [profileId]: [{ id: 'default', name: 'Renamed default profile', default: true, inUse: true },
        { id: 'synthetic_account_a', name: accountName, inUse: false },
        { id: 'synthetic_account_b', name: accountName, inUse: true },
        { id: 'synthetic_reserved', name: 'Reserved profile', inUse: true }],
      [otherId]: [{ id: 'default', name: '默认', default: true, inUse: false }, { id: 'synthetic_account_a', name: accountName, inUse: true }],
    }, snapshot: { profiles: [
      { profileId, cwd: '/synthetic/project', savedTerminals: [], sessions: owned },
      { profileId: otherId, cwd: '/synthetic/other-project', savedTerminals: [], sessions: [foreign] },
    ] }, ...options };
}

async function manageAssociatedAccount({ language = 'zh-CN', accountId = 'synthetic_account_a', browserId } = {}) {
  const label = text => translate(text, language);
  await page.getByRole('button', { name: label('新建会话'), exact: true }).click();
  await page.locator('.terminal-session-kind').getByRole('button', { name: 'Claude Code', exact: true }).click();
  if (browserId) await page.locator('.terminal-new-session > label').filter({ hasText: label('浏览器') }).locator('select').selectOption(browserId);
  const accounts = page.getByRole('combobox', { name: label('登录档案'), exact: true });
  await page.waitForFunction(() => !document.querySelector('.terminal-account-field select')?.disabled);
  await accounts.selectOption(accountId);
  await page.getByRole('button', { name: label('管理档案'), exact: true }).click();
  await page.locator('.terminal-account-sessions').waitFor();
}

test('account association keeps named terminal labels and exposes the bound profile in tooltips and settings', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount(accountAssociationFixture());
  const tabs = page.locator('.terminal-session-tab');
  assert.equal(await tabs.first().innerText(), 'Custom task name · 1');
  assert.equal(await tabs.first().getAttribute('title'), 'Custom task name · 1\n登录档案：Synthetic named login profile');
  await tabs.first().click();
  await page.getByLabel('会话设置', { exact: true }).click();
  assert.equal(await page.locator('.terminal-context-account').innerText(), 'Synthetic named login profile');
  await page.getByLabel('会话设置', { exact: true }).click();
  await tabs.nth(3).click();
  await page.getByLabel('会话设置', { exact: true }).click();
  assert.equal(await page.locator('.terminal-context-account').innerText(), 'Renamed default profile');
  await page.getByLabel('会话设置', { exact: true }).click();
  await tabs.last().click();
  assert.equal((await tabs.last().getAttribute('title')).includes('登录档案'), false);
  await page.getByLabel('会话设置', { exact: true }).click();
  assert.equal(await page.locator('.terminal-context-account').count(), 0);
  await assertNoCommandOrSpawn();
});

test('account association filters by environment and account then switches existing tabs by pointer and keyboard', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount(accountAssociationFixture());
  await page.evaluate(() => { window.accountViews = [...document.querySelectorAll('.terminal-session-view')]; });
  for (const keyboard of [false, true]) {
    await manageAssociatedAccount();
    const list = page.locator('.terminal-account-sessions');
    assert.equal(await list.getAttribute('aria-label'), '使用此档案的终端（2）');
    assert.deepEqual(await list.locator('.terminal-account-session-name').allTextContents(), ['Custom task name · 1', 'Custom task name · 2']);
    assert.equal(await page.getByRole('textbox', { name: '修改档案名称', exact: true }).isDisabled(), true, 'live sessions protect mutations even before the account response reports inUse');
    assert.equal(await page.getByRole('button', { name: '删除档案', exact: true }).isDisabled(), true);
    const target = list.getByRole('button').nth(keyboard ? 1 : 0);
    if (keyboard) { await target.focus(); await page.keyboard.press('Enter'); } else await target.click();
    await page.locator('.terminal-new-session').waitFor({ state: 'hidden' }); await frames();
    assert.equal(await page.locator('.terminal-session-tab').nth(keyboard ? 1 : 0).getAttribute('aria-selected'), 'true');
    const input = page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea');
    assert.equal(await input.evaluate(element => document.activeElement === element), true);
    assert.equal(await page.evaluate(() => [...document.querySelectorAll('.terminal-session-view')].every((element, index) => element === window.accountViews[index])), true);
    await page.keyboard.type(keyboard ? 'keyboard-fixture' : 'pointer-fixture');
    await page.waitForFunction(id => window.compactCalls.some(call => call.method === 'writeTerminal' && call.args.sessionId === id), `compact_session_${keyboard ? 1 : 0}`);
  }
  const operations = await calls();
  assert.deepEqual(operations.filter(call => ['openTerminal', 'duplicateTerminal', 'reopenSavedTerminal', 'closeTerminal', 'renameClaudeAccount', 'deleteClaudeAccount'].includes(call.method)), []);
  assert.deepEqual([...new Set(operations.filter(call => call.method === 'writeTerminal').map(call => call.args.sessionId))], ['compact_session_0', 'compact_session_1']);
});

test('account association preserves backend usage guards and never merges the same account ID across environments', { skip: noDisplay }, async () => {
  await setSize(1120, 720); await mount(accountAssociationFixture());
  await manageAssociatedAccount({ accountId: 'synthetic_reserved' });
  assert.equal(await page.locator('.terminal-account-session').count(), 0);
  assert.equal(await page.getByRole('textbox', { name: '修改档案名称', exact: true }).isDisabled(), true);
  assert.equal(await page.getByRole('button', { name: '保存名称', exact: true }).isDisabled(), true);
  assert.equal(await page.getByRole('button', { name: '删除档案', exact: true }).isDisabled(), true);
  await page.locator('.terminal-new-session-head').getByRole('button', { name: '取消', exact: true }).click();
  await manageAssociatedAccount({ browserId: otherId });
  assert.deepEqual(await page.locator('.terminal-account-session-name').allTextContents(), ['Foreign environment task']);
  await page.locator('.terminal-account-session').click(); await frames();
  assert.equal(await page.getByRole('combobox', { name: '终端环境', exact: true }).inputValue(), otherId);
  assert.equal(await page.locator('.terminal-session-tab[aria-selected="true"]').innerText(), 'Foreign environment task');
  await assertNoCommandOrSpawn();
});

test('account association stays bounded and keyboard accessible in nine languages and both terminal windows', { skip: noDisplay }, async () => {
  for (const language of languages) for (const standalone of [false, true]) {
    await setSize(standalone ? 640 : 1120, 720);
    const accountName = 'Synthetic long profile name '.repeat(5);
    const fixture = accountAssociationFixture({ language, standalone, accountName });
    fixture.snapshot.profiles[0].sessions[0].savedTerminalName = 'Synthetic long terminal name '.repeat(6);
    await mount(fixture); await manageAssociatedAccount({ language });
    const countLabel = translate('使用此档案的终端（{count}）', language, { count: 2 });
    assert.equal(await page.locator('.terminal-account-sessions').getAttribute('aria-label'), countLabel);
    if (language !== 'zh-CN') assert.notEqual(countLabel, '使用此档案的终端（2）', 'the new count label uses the selected language');
    if (language === 'zh-CN' && !standalone) {
      const artifacts = fileURLToPath(new URL('../test-artifacts/terminal-compact-ui/', import.meta.url));
      await mkdir(artifacts, { recursive: true });
      await page.screenshot({ path: path.join(artifacts, 'account-association.png') });
    }
    const bounded = await page.locator('.terminal-account-sessions').evaluate(element => {
      const panel = element.closest('.terminal-new-session').getBoundingClientRect();
      return [...element.querySelectorAll('button')].every(button => {
        const box = button.getBoundingClientRect();
        return box.left >= panel.left && box.right <= panel.right + 1 && button.scrollWidth <= button.clientWidth + 1;
      });
    });
    assert.equal(bounded, true, `${language}/${standalone}: account association rows remain bounded`);
    const target = page.locator('.terminal-account-session').first();
    assert.match(await target.getAttribute('title'), /^Synthetic long terminal name/);
    await target.focus(); await page.keyboard.press('Enter'); await frames();
    assert.equal(await page.locator('.terminal-session-tab').first().getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('.terminal-new-session').count(), 0);
  }
});

test('current-session account management opens the bound profile directly without a launch chooser or installation request', { skip: noDisplay }, async () => {
  await mount(accountAssociationFixture());
  await page.locator('.terminal-session-tab').first().click();
  await page.getByLabel('会话设置', { exact: true }).click();
  await page.getByRole('button', { name: '管理登录档案', exact: true }).click();
  await page.locator('.terminal-manage-account .terminal-account-sessions').waitFor();
  assert.equal(await page.locator('.terminal-manage-account .terminal-session-kind').count(), 0);
  assert.equal(await page.locator('.terminal-manage-account .terminal-start-button').count(), 0);
  assert.equal(await page.getByRole('textbox', { name: '修改档案名称', exact: true }).inputValue(), 'Synthetic named login profile');
  assert.equal(await page.locator('.terminal-account-session').count(), 2);
  assert.equal((await calls()).filter(call => call.method === 'claudeInstallationStatus').length, 0);
  await page.locator('.terminal-account-session').nth(1).focus(); await page.keyboard.press('Enter'); await frames();
  assert.equal(await page.locator('.terminal-session-tab').nth(1).getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('.terminal-manage-account').count(), 0);
  await assertNoCommandOrSpawn();
});

test('current-session account management does not substitute the default when a bound profile is missing', { skip: noDisplay }, async () => {
  const fixture = accountAssociationFixture();
  fixture.accountsByProfile[profileId] = fixture.accountsByProfile[profileId].filter(account => account.id !== 'synthetic_account_a');
  await mount(fixture); await page.locator('.terminal-session-tab').first().click();
  await page.getByLabel('会话设置', { exact: true }).click(); await page.getByRole('button', { name: '管理登录档案', exact: true }).click();
  await page.locator('.terminal-manage-account').getByText('登录档案不可用', { exact: true }).waitFor();
  assert.equal(await page.getByRole('textbox', { name: '修改档案名称', exact: true }).inputValue(), 'Synthetic named login profile');
  assert.equal(await page.getByRole('textbox', { name: '修改档案名称', exact: true }).isDisabled(), true);
  await page.getByRole('combobox', { name: '终端环境', exact: true }).selectOption(otherId);
  await page.locator('.terminal-manage-account').waitFor({ state: 'hidden' });
  await assertNoCommandOrSpawn();
});

async function pasteSyntheticAttachment() {
  await page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea').focus();
  await page.evaluate(() => {
    const data = new DataTransfer(); data.items.add(new File([new Uint8Array([1, 2, 3])], 'synthetic-image.png', { type: 'image/png' }));
    document.activeElement.dispatchEvent(new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: data }));
  });
  await page.waitForFunction(() => window.compactFinishAttachment != null);
}

test('terminal attachments block queued Enter and insert only a quoted path into the selected existing terminal', { skip: noDisplay }, async () => {
  await mount({ deferAttachment: true });
  await page.locator('.terminal-session-view:not([hidden]) .xterm-helper-textarea').focus(); await page.keyboard.type('review ');
  await pasteSyntheticAttachment();
  await page.keyboard.press('Enter'); await page.keyboard.type('discard-during-transfer');
  assert.equal(await page.locator('.terminal-attachment-status').count(), 1);
  await page.evaluate(() => window.compactFinishAttachment());
  await page.waitForFunction(() => window.compactCalls.some(call => call.method === 'commitTerminalAttachments'));
  const writes = (await calls()).filter(call => call.method === 'writeTerminal');
  assert.deepEqual([...new Set(writes.map(call => call.args.sessionId))], ['compact_session_1']);
  assert.equal(writes.map(call => call.args.data).join(''), 'review ');
  const commits = (await calls()).filter(call => call.method === 'commitTerminalAttachments');
  assert.equal(commits.length, 1); assert.equal(commits[0].args.sessionId, 'compact_session_1');
  assert.equal(commits[0].args.bracketedPaste, false); assert.equal(typeof commits[0].args.transferId, 'string');
  assert.equal(Object.hasOwn(commits[0].args, 'quotedPaths'), false, 'only main-owned staged paths may be committed');
  assert.deepEqual((await calls()).filter(call => ['openTerminal', 'duplicateTerminal', 'closeTerminal'].includes(call.method)), []);
});

test('terminal attachments cancel on tab switch and discard a late path without affecting another terminal', { skip: noDisplay }, async () => {
  await mount({ deferAttachment: true }); await pasteSyntheticAttachment();
  await page.locator('.terminal-session-tab').first().click(); await frames();
  await page.waitForFunction(() => window.compactCalls.some(call => call.method === 'cancelTerminalAttachments'));
  await page.evaluate(() => window.compactFinishAttachment()); await frames();
  assert.deepEqual((await calls()).filter(call => call.method === 'writeTerminal' || call.method === 'commitTerminalAttachments'), []);
  assert.equal(await page.locator('.terminal-session-tab').first().getAttribute('aria-selected'), 'true');
  assert.equal(await page.locator('.terminal-attachment-status').count(), 0);
});
