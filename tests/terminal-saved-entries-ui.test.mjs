import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages, translate } from '../src/i18n.mjs';

// Real renderer and xterm, with stateful IPC only. This owned hidden window
// never starts production Electron main, a shell, a browser or account storage.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const profileId = 'saved_ui_environment';
const secondProfileId = 'saved_ui_second';
const profile = { id: profileId, name: 'Synthetic environment', timezone: 'UTC' };
const secondProfile = { id: secondProfileId, name: 'Second synthetic environment', timezone: 'UTC' };
const entry = { id: 'saved_ui_entry', name: 'Synthetic work terminal', profileId, kind: 'claude-code',
  cwd: '/synthetic/project', browserProfileId: profileId, claudeAccountId: 'synthetic_work', claudeAccountName: 'Synthetic work account',
  sessionId: null, status: 'saved', activeSessionCount: 0, networkRef: { kind: 'direct', proxyId: null } };
const shellEntry = { ...entry, id: 'saved_ui_shell', name: 'Synthetic shell terminal', kind: 'shell', claudeAccountId: null, claudeAccountName: null };
const sessionFor = (saved, sessionId = 'saved_ui_session') => ({ sessionId, profileId: saved.profileId, savedTerminalId: saved.id, savedTerminalName: saved.name,
  kind: saved.kind, status: 'running', sequence: 0, cwd: saved.cwd, browserProfileId: saved.browserProfileId, browserName: 'Synthetic browser',
  claudeAccountId: saved.claudeAccountId, claudeAccountName: saved.claudeAccountName, columns: 80, rows: 12,
  startedAt: '2026-01-01T00:00:00.000Z', replay: 'Synthetic idle shell prompt\r\n' });
const metadata = (savedTerminals = [], sessions = [], id = profileId) => ({ profileId: id, cwd: '/synthetic/unrelated-latest-folder', savedTerminals, sessions });
let fixture, desktop, page;

before(async () => {
  if (noDisplay) return;
  fixture = await mkdtemp(path.join(tmpdir(), 'envara-saved-terminal-ui-'));
  const pane = fileURLToPath(new URL('../src/TerminalPane.jsx', import.meta.url));
  const messages = fileURLToPath(new URL('../src/i18n.mjs', import.meta.url));
  const output = await build({ stdin: { contents: `
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { TerminalDock } from ${JSON.stringify(pane)};
const root = createRoot(document.getElementById('root'));
const clone = value => JSON.parse(JSON.stringify(value));
let listeners = new Set();
window.savedSubscribe = listener => { listeners.add(listener); return () => listeners.delete(listener); };
window.savedPublish = event => { for (const listener of listeners) listener(event); };
window.savedApi = async (method, args) => {
  window.savedCalls.push({ method, args: clone(args) });
  const state = window.savedFixture;
  const snapshot = id => clone({ profiles: state.snapshot.profiles.filter(item => !id || item.profileId === id) });
  if (method === 'terminalSnapshot') return snapshot(args.id);
  if (method === 'resizeTerminal') return {};
  if (!['reopenSavedTerminal', 'renameSavedTerminal', 'removeSavedTerminal'].includes(method))
    throw Object.assign(new Error('Unexpected fixture call: ' + method), { code: 'SAVED_UI_UNEXPECTED_CALL' });
  if (state.deferMethod === method) await new Promise(resolve => { window.savedFinishOperation = resolve; });
  if (state.failure && (!state.failure.method || state.failure.method === method))
    throw Object.assign(new Error(state.failure.message), { code: state.failure.code });
  const host = state.snapshot.profiles.find(item => item.profileId === args.id);
  const saved = host?.savedTerminals?.find(item => item.id === args.entryId);
  if (!saved) throw Object.assign(new Error('Synthetic entry does not exist in this environment'), { code: 'TERMINAL_ENTRY_NOT_FOUND' });
  if (method === 'reopenSavedTerminal') {
    const existing = host.sessions.find(item => item.sessionId === saved.sessionId && ['starting', 'running', 'closing'].includes(item.status));
    if (existing) return clone(existing);
    const created = { sessionId: 'saved_ui_reopened_' + (++state.createdCount), profileId: args.id, savedTerminalId: saved.id,
      savedTerminalName: saved.name, kind: saved.kind, status: 'running', sequence: 0, cwd: saved.cwd,
      browserProfileId: saved.browserProfileId, browserName: 'Synthetic browser', claudeAccountId: saved.claudeAccountId,
      claudeAccountName: saved.claudeAccountName, requestId: args.requestId, columns: 80, rows: 12,
      startedAt: '2026-01-02T00:00:00.000Z', replay: 'Synthetic reopened idle shell prompt\\r\\n' };
    host.sessions.push(created); Object.assign(saved, { sessionId: created.sessionId, status: 'running', activeSessionCount: 1 });
    return clone(created);
  }
  if (method === 'renameSavedTerminal') {
    saved.name = args.name;
    for (const item of host.sessions) if (item.savedTerminalId === saved.id) item.savedTerminalName = args.name;
  } else {
    host.savedTerminals = host.savedTerminals.filter(item => item.id !== saved.id);
    for (const item of host.sessions) if (item.savedTerminalId === saved.id) { item.savedTerminalId = null; item.savedTerminalName = null; }
  }
  return snapshot(args.id);
};
function Workspace() {
  const [expanded, setExpanded] = useState(window.savedFixture.expanded === true);
  return <div className={window.savedFixture.standalone ? 'terminal-window-shell' : \`app-shell terminal-visible terminal-workspace \${expanded ? 'terminal-expanded' : ''}\`} style={{ '--terminal-height': '360px' }}>
    {!window.savedFixture.standalone && <><aside className="sidebar" /><main className="main-panel">Synthetic renderer</main></>}
    <TerminalDock profiles={window.savedFixture.environments} selectedProfileId={window.savedFixture.selectedProfileId}
      onProfilesChange={value => { window.savedRenderedProfiles = value; }}
      workspace={window.savedFixture.workspace === true} standalone={window.savedFixture.standalone === true} expanded={expanded} onToggleExpanded={() => setExpanded(value => !value)} onHeightChange={() => {}} />
  </div>;
}
let version = 0;
window.savedMount = value => { window.savedFixture = { createdCount: 0, ...value }; window.savedLanguage = value.language || 'zh-CN'; window.savedCalls = []; window.savedRenderedProfiles = null; window.savedFinishOperation = null; root.render(<Workspace key={++version} />); };
window.savedReady = true;
`, resolveDir: path.dirname(pane), loader: 'jsx' }, bundle: true, platform: 'browser', format: 'iife', write: false,
    mainFields: ['module', 'main'], loader: { '.css': 'empty' },
    plugins: [{ name: 'owned-saved-terminal-ipc-fixture', setup(builder) {
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|appearance\.jsx)$/ }, args => ({ path: args.path, namespace: 'saved-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'saved-fixture' }, args => ({ contents: args.path.endsWith('client.js')
        ? `export const api = { isDesktop: true, onTerminalEvent: listener => window.savedSubscribe(listener), call: (...args) => window.savedApi(...args) };`
        : args.path.endsWith('appearance.jsx') ? `export const useAppearance = () => ({ effective: 'dark' });`
          : `import { translate } from ${JSON.stringify(messages)}; export const useI18n = () => ({ language: window.savedLanguage || 'zh-CN', t: (text, vars) => translate(text, window.savedLanguage || 'zh-CN', vars) });`,
        resolveDir: path.dirname(pane) }));
    } }],
  });
  await writeFile(path.join(fixture, 'renderer.js'), output.outputFiles[0].text);
  const css = await Promise.all(['styles.css', 'terminal.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  css.unshift(await readFile(new URL('../node_modules/@xterm/xterm/css/xterm.css', import.meta.url), 'utf8'));
  await writeFile(path.join(fixture, 'index.html'), `<html lang="zh-CN" data-theme="dark"><head><style>${css.join('\n')}</style></head><body><div id="root"></div><script src="renderer.js"></script></body></html>`);
  const main = path.join(fixture, 'main.cjs');
  await writeFile(main, `const { app, BrowserWindow } = require('electron'); app.setPath('userData', ${JSON.stringify(path.join(fixture, 'data'))}); app.whenReady().then(() => { app.dock?.hide(); const view = new BrowserWindow({ show: false, width: 1120, height: 760, webPreferences: { sandbox: true, backgroundThrottling: false } }); view.loadFile(${JSON.stringify(path.join(fixture, 'index.html'))}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [main], env, timeout: 15000 });
  page = await desktop.firstWindow();
  page.setDefaultTimeout(5000);
  await page.waitForFunction(() => window.savedReady === true);
});

after(async () => { await desktop?.close(); if (fixture) await rm(fixture, { recursive: true, force: true }); });

async function mount(options = {}) {
  await page.evaluate(value => window.savedMount(value), { snapshot: { profiles: [metadata()] }, environments: [profile], selectedProfileId: profileId, ...options });
  await page.locator('.terminal-saved-terminals').waitFor({ state: 'visible' });
  await page.waitForFunction(() => window.savedRenderedProfiles != null);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await page.locator('.terminal-empty-start:disabled').waitFor({ state: 'hidden' });
}
const rows = () => page.locator('.terminal-saved-entry');
const rowFor = (id = entry.id) => page.locator(`.terminal-saved-entry[data-entry-id="${id}"]`);
const calls = () => page.evaluate(() => window.savedCalls);
const methods = async () => (await calls()).map(call => call.method);
async function selectEnvironment(id) {
  await page.getByRole('combobox', { name: '终端环境', exact: true }).selectOption(id);
  assert.equal(await page.getByRole('combobox', { name: '终端环境', exact: true }).inputValue(), id);
}
async function revealSettings() {
  const details = page.locator('.terminal-context-menu');
  if (!await details.evaluate(element => element.open)) await details.locator('summary').click();
  await details.locator('.terminal-context-panel').waitFor({ state: 'visible' });
  return details;
}
async function revealEntries() {
  const details = page.locator('.terminal-saved-terminals');
  if (!await details.evaluate(element => element.open)) await details.locator('summary').click();
  return details;
}
async function assertNoFallback() {
  const invoked = await methods();
  assert.ok(invoked.every(method => ['terminalSnapshot', 'resizeTerminal', 'reopenSavedTerminal', 'renameSavedTerminal', 'removeSavedTerminal'].includes(method)), invoked.join(', '));
}

test('empty saved terminals open on request without covering the workspace or starting a session', { skip: noDisplay }, async () => {
  await mount();
  const details = page.locator('.terminal-saved-terminals');
  assert.equal(await details.evaluate(element => element.open), false);
  await revealEntries();
  assert.equal(await details.evaluate(element => element.open), true);
  assert.equal(await details.getByText('新建会话后会自动保存在这里。', { exact: true }).count(), 1);
  assert.equal(await rows().count(), 0);
  assert.equal(await page.locator('.terminal-session-tab').count(), 0);
  assert.ok((await methods()).every(method => method === 'terminalSnapshot'));
});

test('opening a running saved entry selects its exact session ahead of a newer unrelated session', { skip: noDisplay }, async () => {
  const target = sessionFor(entry);
  const unrelated = { ...sessionFor(shellEntry, 'saved_ui_unrelated_session'), startedAt: '2026-01-03T00:00:00.000Z' };
  await mount({ snapshot: { profiles: [metadata([{ ...entry, sessionId: target.sessionId, status: 'running', activeSessionCount: 1 }], [target, unrelated])] } });
  assert.equal(await page.locator('.terminal-saved-terminals').evaluate(element => element.open), false);
  assert.equal(await page.locator('.terminal-session-tab').nth(1).getAttribute('aria-selected'), 'true');
  await page.evaluate(() => { window.savedTargetView = document.querySelector('.terminal-session-view'); });
  await revealEntries();
  await rowFor().getByRole('button', { name: `打开终端「${entry.name}」`, exact: true }).click();
  await page.waitForFunction(() => document.querySelector('.terminal-session-tab')?.getAttribute('aria-selected') === 'true');
  assert.equal(await page.locator('.terminal-session-view:not([hidden])').evaluate(element => element === window.savedTargetView), true);
  assert.equal(await page.locator('.terminal-session-tab').count(), 2);
  const opened = (await calls()).filter(call => call.method === 'reopenSavedTerminal');
  assert.equal(opened.length, 1);
  assert.equal(opened[0].args.id, profileId); assert.equal(opened[0].args.entryId, entry.id);
  assert.equal(typeof opened[0].args.requestId, 'string'); assert.ok(opened[0].args.requestId.length > 0);
  await assertNoFallback();
});

test('same-name live tabs are numbered within their environment and the saved entry opens its latest PTY', { skip: noDisplay }, async () => {
  const first = sessionFor(entry, 'saved_ui_first_same_name');
  const latest = { ...sessionFor(entry, 'saved_ui_latest_same_name'), startedAt: '2026-01-02T00:00:00.000Z' };
  const other = { ...entry, profileId: secondProfileId, browserProfileId: secondProfileId };
  const elsewhere = sessionFor(other, 'saved_ui_other_environment_same_name');
  await mount({ environments: [profile, secondProfile], snapshot: { profiles: [
    metadata([{ ...entry, sessionId: latest.sessionId, status: 'running', activeSessionCount: 2 }], [first, latest]),
    metadata([{ ...other, sessionId: elsewhere.sessionId, status: 'running', activeSessionCount: 1 }], [elsewhere], secondProfileId),
  ] } });
  assert.deepEqual(await page.locator('.terminal-session-tab').evaluateAll(tabs => tabs.map(tab => tab.title)), [`${entry.name} · 1`, `${entry.name} · 2`]);
  assert.equal(await page.locator('.terminal-session-tab').nth(1).getAttribute('aria-selected'), 'true');
  await page.evaluate(() => { window.savedLatestSameNameView = document.querySelectorAll('.terminal-session-view')[1]; });
  await page.locator('.terminal-session-tab').nth(0).click();
  assert.equal(await page.locator('.terminal-session-tab').nth(0).getAttribute('aria-selected'), 'true');
  await revealEntries();
  assert.equal(await rowFor().locator('.terminal-saved-heading strong').textContent(), entry.name, 'entry names stay unchanged');
  await rowFor().getByRole('button', { name: `打开终端「${entry.name}」`, exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll('.terminal-session-tab')[1]?.getAttribute('aria-selected') === 'true');
  assert.equal(await page.locator('.terminal-session-view:not([hidden])').evaluate(element => element === window.savedLatestSameNameView), true);
  assert.equal(await page.locator('.terminal-session-tab').count(), 2);
  await selectEnvironment(secondProfileId);
  await page.locator('.terminal-session-tab').filter({ hasText: other.name }).waitFor();
  assert.equal(await page.locator('.terminal-session-tab').count(), 1);
  assert.equal(await page.locator('.terminal-session-tab').getAttribute('title'), other.name, 'another environment does not contribute to duplicate numbering');
  assert.equal((await methods()).filter(method => method === 'reopenSavedTerminal').length, 1);
  await assertNoFallback();
});

test('reopening a saved Claude entry preserves its named account and folder instead of current defaults', { skip: noDisplay }, async () => {
  await mount({ snapshot: { profiles: [metadata([entry])] } });
  const row = rowFor();
  assert.equal(await row.locator(`[title="${entry.name}"]`).count() > 0, true);
  assert.equal(await row.locator(`[title="${entry.claudeAccountName}"]`).count() > 0, true);
  assert.equal(await row.locator(`[title="${entry.cwd}"]`).count() > 0, true);
  await row.getByRole('button', { name: `打开终端「${entry.name}」`, exact: true }).click();
  await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor({ state: 'visible' });
  await revealSettings();
  assert.equal(await page.locator('.terminal-directory > span').getAttribute('title'), entry.cwd);
  assert.match(await page.locator('.terminal-session-tab[aria-selected="true"]').textContent(), /Synthetic work terminal/);
  const state = await page.evaluate(() => window.savedFixture);
  assert.equal(state.createdCount, 1);
  assert.equal(state.snapshot.profiles[0].sessions[0].claudeAccountId, entry.claudeAccountId);
  assert.equal(state.snapshot.profiles[0].sessions[0].cwd, entry.cwd);
  const opened = (await calls()).filter(call => call.method === 'reopenSavedTerminal');
  assert.equal(opened.length, 1);
  assert.deepEqual(Object.keys(opened[0].args).sort(), ['entryId', 'id', 'requestId']);
  await assertNoFallback();
});

test('renaming and removing an entry keeps its live PTY and named account intact', { skip: noDisplay }, async () => {
  const target = sessionFor(entry);
  const accounts = [{ id: entry.claudeAccountId, name: entry.claudeAccountName }];
  await mount({ accounts, snapshot: { profiles: [metadata([{ ...entry, sessionId: target.sessionId, status: 'running', activeSessionCount: 1 }], [target])] } });
  await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor({ state: 'visible' });
  await page.evaluate(() => { window.savedLiveXterm = document.querySelector('.terminal-session-view .xterm'); });
  await revealEntries();
  await rowFor().getByRole('button', { name: `重命名终端「${entry.name}」`, exact: true }).click();
  const name = 'Renamed synthetic terminal';
  await rowFor().getByLabel('终端名称', { exact: true }).fill(name);
  await rowFor().getByRole('button', { name: '保存', exact: true }).click();
  await rowFor().getByRole('button', { name: `移除终端入口「${name}」`, exact: true }).waitFor();
  await rowFor().getByRole('button', { name: `移除终端入口「${name}」`, exact: true }).click();
  await rowFor().getByText('仅移除此入口，登录资料和终端数据会保留。', { exact: true }).waitFor();
  assert.equal((await methods()).includes('removeSavedTerminal'), false, 'removal requires its local confirmation');
  await rowFor().getByRole('button', { name: '取消', exact: true }).click();
  assert.equal(await rowFor().count(), 1);
  await rowFor().getByRole('button', { name: `移除终端入口「${name}」`, exact: true }).click();
  await rowFor().getByRole('button', { name: '移除入口', exact: true }).click();
  await rowFor().waitFor({ state: 'detached' });
  assert.equal(await page.locator('.terminal-session-tab').count(), 1);
  assert.equal(await page.locator('.terminal-session-view:not([hidden]) .xterm').evaluate(element => element === window.savedLiveXterm), true);
  const state = await page.evaluate(() => window.savedFixture);
  assert.deepEqual(state.accounts, accounts);
  assert.equal(state.snapshot.profiles[0].sessions[0].claudeAccountId, entry.claudeAccountId);
  assert.equal(state.snapshot.profiles[0].sessions[0].status, 'running');
  assert.deepEqual((await calls()).filter(call => ['renameSavedTerminal', 'removeSavedTerminal'].includes(call.method)).map(call => ({ method: call.method, args: call.args })), [
    { method: 'renameSavedTerminal', args: { id: profileId, entryId: entry.id, name } },
    { method: 'removeSavedTerminal', args: { id: profileId, entryId: entry.id } },
  ]);
  await assertNoFallback();
});

test('entries with the same local id remain scoped to the selected environment', { skip: noDisplay }, async () => {
  const other = { ...entry, profileId: secondProfileId, browserProfileId: secondProfileId, name: 'Second environment terminal', cwd: '/synthetic/second-project' };
  await mount({ environments: [profile, secondProfile], snapshot: { profiles: [metadata([entry]), metadata([other], [], secondProfileId)] } });
  assert.equal(await rowFor().getByText(entry.name, { exact: true }).count(), 1);
  assert.equal(await rows().getByText(other.name, { exact: true }).count(), 0);
  await selectEnvironment(secondProfileId);
  await rowFor().getByText(other.name, { exact: true }).waitFor();
  await rowFor().getByRole('button', { name: `打开终端「${other.name}」`, exact: true }).click();
  const settings = await revealSettings();
  await settings.locator('.terminal-directory').filter({ hasText: other.cwd }).waitFor();
  await settings.locator('summary').click();
  await revealEntries();
  await rowFor().getByRole('button', { name: `移除终端入口「${other.name}」`, exact: true }).click();
  await rowFor().getByRole('button', { name: '移除入口', exact: true }).click();
  await rowFor().waitFor({ state: 'detached' });
  await selectEnvironment(profileId);
  await revealEntries();
  await rowFor().getByText(entry.name, { exact: true }).waitFor();
  const invoked = (await calls()).filter(call => ['reopenSavedTerminal', 'removeSavedTerminal'].includes(call.method));
  assert.equal(invoked.length, 2);
  assert.ok(invoked.every(call => call.args.id === secondProfileId && call.args.entryId === entry.id));
  await assertNoFallback();
});

test('a pending reopen is submitted once and cannot select a session after switching environments', { skip: noDisplay }, async () => {
  const other = { ...shellEntry, profileId: secondProfileId, browserProfileId: secondProfileId, name: 'Second environment terminal' };
  await mount({ deferMethod: 'reopenSavedTerminal', environments: [profile, secondProfile],
    snapshot: { profiles: [metadata([entry]), metadata([other], [], secondProfileId)] } });
  await rowFor().locator('.terminal-saved-open').evaluate(element => { element.click(); element.click(); });
  await page.waitForFunction(() => typeof window.savedFinishOperation === 'function');
  assert.equal((await methods()).filter(method => method === 'reopenSavedTerminal').length, 1);
  await selectEnvironment(secondProfileId);
  await rowFor(other.id).getByText(other.name, { exact: true }).waitFor();
  await page.evaluate(() => window.savedFinishOperation());
  await page.waitForFunction(() => window.savedFixture.createdCount === 1
    && window.savedRenderedProfiles?.find(item => item.profileId === 'saved_ui_environment')?.sessions.length === 1);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.getByRole('combobox', { name: '终端环境', exact: true }).inputValue(), secondProfileId);
  assert.equal(await page.locator('.terminal-session-tab').count(), 0);
  assert.equal(await page.locator('.terminal-session-view:not([hidden])').count(), 0);
  assert.equal(await rowFor(other.id).getByText(other.name, { exact: true }).count(), 1);
  assert.equal((await methods()).filter(method => method === 'reopenSavedTerminal').length, 1);
  await assertNoFallback();
});

test('starting and closing entries explain their state without allowing a second reopen', { skip: noDisplay }, async () => {
  for (const status of ['starting', 'closing']) {
    const target = { ...sessionFor(entry), status };
    await mount({ snapshot: { profiles: [metadata([{ ...entry, sessionId: target.sessionId, status, activeSessionCount: 1 }], [target])] } });
    const details = page.locator('.terminal-saved-terminals');
    await details.locator('summary').press('Enter');
    assert.equal(await details.evaluate(element => element.open), true);
    assert.equal(await rowFor().getByRole('button', { name: `打开终端「${entry.name}」`, exact: true }).isDisabled(), true);
    assert.equal(await rowFor().getByText(status === 'starting' ? '启动中' : '关闭中', { exact: true }).count(), 1);
    assert.equal((await methods()).includes('reopenSavedTerminal'), false);
    await assertNoFallback();
  }
});

test('refused context, account and folder reopening displays the error without a new session or fallback', { skip: noDisplay }, async () => {
  for (const failure of [
    { code: 'TERMINAL_ENTRY_CONTEXT_CHANGED', message: '此终端的网络或浏览器配置已改变，请新建终端确认配置。' },
    { code: 'CLAUDE_ACCOUNT_NOT_FOUND', message: '此 Claude 登录档案已不存在，请重新选择。' },
    { code: 'TERMINAL_ENTRY_DIRECTORY_UNAVAILABLE', message: '此终端的工作目录已改变，请重新选择。' },
  ]) {
    await mount({ failure, snapshot: { profiles: [metadata([entry])] } });
    await rowFor().getByRole('button', { name: `打开终端「${entry.name}」`, exact: true }).click();
    await page.getByText(failure.message, { exact: true }).waitFor();
    assert.equal(await page.locator('.terminal-session-tab').count(), 0, failure.code);
    assert.equal(await rowFor().count(), 1, failure.code);
    assert.equal(await page.evaluate(() => window.savedFixture.createdCount), 0, failure.code);
    assert.equal((await methods()).filter(method => method === 'reopenSavedTerminal').length, 1, failure.code);
    await assertNoFallback();
  }
});

test('failed entry mutations retain the row and live terminal for retry', { skip: noDisplay }, async () => {
  for (const method of ['renameSavedTerminal', 'removeSavedTerminal']) {
    const target = sessionFor(entry);
    await mount({ failure: { method, code: 'SYNTHETIC_ENTRY_WRITE_FAILED', message: 'Synthetic entry write failed' },
      snapshot: { profiles: [metadata([{ ...entry, sessionId: target.sessionId, status: 'running', activeSessionCount: 1 }], [target])] } });
    await revealEntries();
    if (method === 'renameSavedTerminal') {
      await rowFor().getByRole('button', { name: `重命名终端「${entry.name}」`, exact: true }).click();
      await rowFor().getByLabel('终端名称', { exact: true }).fill('Not committed');
      await rowFor().getByRole('button', { name: '保存', exact: true }).click();
    } else {
      await rowFor().getByRole('button', { name: `移除终端入口「${entry.name}」`, exact: true }).click();
      await rowFor().getByRole('button', { name: '移除入口', exact: true }).click();
    }
    await page.getByText('Synthetic entry write failed', { exact: true }).waitFor();
    assert.equal(await rowFor().count(), 1);
    assert.equal(await page.locator('.terminal-session-tab').count(), 1);
    assert.equal(await page.evaluate(() => window.savedFixture.snapshot.profiles[0].savedTerminals[0].name), entry.name);
    await assertNoFallback();
  }
});

test('nine languages keep compact saved-entry names, account names, folders and actions usable', { skip: noDisplay }, async () => {
  const long = { ...entry, name: 'Synthetic terminal with a deliberately long descriptive name for compact windows',
    claudeAccountName: 'Synthetic named account with a deliberately long descriptive label',
    cwd: '/synthetic/a-deliberately-long-workspace-folder/another-segment/project-with-long-name' };
  for (const language of languages) {
    if (language !== 'zh-CN') assert.notEqual(translate('已保存终端', language), '已保存终端', `${language} must have a saved-entry translation`);
    await desktop.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setContentSize(760, 680));
    await mount({ language, standalone: true, snapshot: { profiles: [metadata([long, shellEntry])] } });
    const details = page.locator('.terminal-saved-terminals');
    assert.equal(await details.locator('summary').getAttribute('aria-label'), translate('已保存终端', language));
    assert.equal(await details.locator('summary').getAttribute('title'), translate('已保存终端', language));
    const row = rowFor();
    assert.equal(await row.getByRole('button', { name: translate('打开终端「{name}」', language, { name: long.name }), exact: true }).count(), 1, language);
    assert.equal(await row.getByRole('button', { name: translate('重命名终端「{name}」', language, { name: long.name }), exact: true }).count(), 1, language);
    assert.equal(await row.getByRole('button', { name: translate('移除终端入口「{name}」', language, { name: long.name }), exact: true }).count(), 1, language);
    const layout = await details.locator('.terminal-saved-panel').evaluate(element => {
      const box = element.getBoundingClientRect();
      const controls = [...element.querySelectorAll('.terminal-saved-entry button')].map(control => {
        const rect = control.getBoundingClientRect();
        return { width: rect.width, height: rect.height, inside: rect.left >= box.left && rect.right <= box.right };
      });
      return { overflows: element.scrollWidth > element.clientWidth + 1, insideViewport: box.left >= 0 && box.right <= innerWidth && box.top >= 0 && box.bottom <= innerHeight, controls };
    });
    assert.equal(layout.overflows, false, language);
    assert.equal(layout.insideViewport, true, `${language} saved panel must remain inside the viewport`);
    assert.ok(layout.controls.every(control => control.inside && control.width >= 24 && control.height >= 24), language);
    if (language === 'de') {
      const artifacts = fileURLToPath(new URL('../test-artifacts/terminal-compact-ui/', import.meta.url));
      await mkdir(artifacts, { recursive: true, mode: 0o700 });
      await page.screenshot({ path: path.join(artifacts, 'de-saved-panel.png') });
    }
    await row.getByRole('button', { name: translate('重命名终端「{name}」', language, { name: long.name }), exact: true }).click();
    await row.getByLabel(translate('终端名称', language), { exact: true }).waitFor();
    await row.getByRole('button', { name: translate('取消', language), exact: true }).click();
    await assertNoFallback();
  }
  await desktop.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setContentSize(1120, 760));
});
