import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { _electron } from 'playwright-core';
import { languages, translate, translationCatalog } from '../src/i18n.mjs';

// Real renderer/components, mocked IPC only: no shell, SSH, key picker,
// environment data or production Electron main process is started.
const noDisplay = process.platform === 'linux' && !process.env.DISPLAY;
const connection = { id: 'ssh_ui_fixture', alias: 'envara-fixture', name: 'Synthetic server', host: 'ssh-fixture.invalid', port: 2222, user: 'fixture',
  keyLabel: 'Synthetic key', keyFingerprint: 'SHA256:fixture-key', hostFingerprints: ['SHA256:fixture-host'] };
const passwordConnection = { id: 'ssh_password_fixture', alias: 'envara-password-fixture', name: 'Synthetic password server', host: 'password-fixture.invalid', port: 2222, user: 'fixture', authType: 'password', passwordReady: false, hostFingerprints: ['SHA256:fixture-host'] };
let fixture, desktop, page;

before(async () => {
  if (noDisplay) return;
  fixture = await mkdtemp(path.join(tmpdir(), 'envara-ssh-ui-'));
  const pane = fileURLToPath(new URL('../src/TerminalPane.jsx', import.meta.url));
  const messages = fileURLToPath(new URL('../src/i18n.mjs', import.meta.url));
  const output = await build({ stdin: { contents: `
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import { TerminalDock } from ${JSON.stringify(pane)};
const root = createRoot(document.getElementById('root'));
const profile = { id: 'ssh_ui_environment', name: 'Synthetic environment', timezone: 'UTC' };
window.sshCalls = [];
window.sshApi = async (method, args) => {
  window.sshCalls.push({ method, args });
  if (method === 'terminalSnapshot') return { profiles: [{ profileId: profile.id, sessions: window.sshFixture.active ? [{ sessionId: 'ssh_ui_session', profileId: profile.id, kind: 'shell', status: 'running', sequence: 0, cwd: '/synthetic/workspace', columns: 80, rows: 12 }] : [] }] };
  if (method === 'listTerminalSshConnections') return { supported: true, connections: args.id === 'ssh_ui_second' ? [] : window.sshFixture.connections };
  if (method === 'prepareTerminalSshPassword') {
    if (window.sshFixture.deferPrepare) await new Promise(resolve => { window.sshFinishPrepare = resolve; });
    if (window.sshFixture.prepareFailure) throw Object.assign(new Error('Synthetic host trust failure'), { code: window.sshFixture.prepareFailure.code || 'SSH_HOST_UNTRUSTED' });
    return { selectionToken: 'synthetic-password-token', authType: 'password', hostFingerprints: ['SHA256:fixture-host'] };
  }
  if (method === 'prepareTerminalSshIdentity') return { selectionToken: 'synthetic-picker-token', keyLabel: 'Synthetic key', keyFingerprint: 'SHA256:fixture-key', hostFingerprints: ['SHA256:fixture-host'] };
  if (method === 'saveTerminalSshConnection') {
    if (window.sshFixture.deferSave) await new Promise(resolve => { window.sshFinishSave = resolve; });
    if (window.sshFixture.saveFailure) throw Object.assign(new Error('Synthetic save failure'), { code: 'SSH_PASSWORD_INVALID' });
    window.sshFixture.connections = [args.password ? { ...window.sshPasswordConnection, passwordReady: true } : window.sshConnection];
    return { supported: true, connections: window.sshFixture.connections };
  }
  if (method === 'setTerminalSshPassword') {
    if (window.sshFixture.deferPassword) await new Promise(resolve => { window.sshFinishPassword = resolve; });
    if (window.sshFixture.passwordFailure) throw Object.assign(new Error('Synthetic password failure'), { code: 'SSH_PASSWORD_INVALID' });
    window.sshFixture.connections = window.sshFixture.connections.map(item => item.id === args.connectionId ? { ...item, passwordReady: true } : item);
    return { supported: true, connections: window.sshFixture.connections };
  }
  if (method === 'resizeTerminal') return {};
  throw Object.assign(new Error('Unexpected fixture call'), { code: 'SSH_FIXTURE_UNEXPECTED_CALL' });
};
function Workspace({ initialExpanded }) {
  const [expanded, setExpanded] = useState(initialExpanded);
  window.sshSetExpanded = setExpanded;
  return <div className={\`app-shell terminal-visible terminal-workspace \${expanded ? 'terminal-expanded' : ''}\`} style={{ '--terminal-height': '320px' }}>
    <aside className="sidebar" /><main className="main-panel">Synthetic renderer</main>
    <TerminalDock profiles={window.sshFixture.twoProfiles ? [profile, { ...profile, id: 'ssh_ui_second', name: 'Second synthetic environment' }] : [profile]} selectedProfileId={profile.id} expanded={expanded} onToggleExpanded={() => setExpanded(value => !value)} onHeightChange={() => {}} />
  </div>;
}
let version = 0;
window.sshMount = value => { window.sshFixture = value; window.sshLanguage = value.language || 'zh-CN'; window.sshCalls = []; root.render(<Workspace key={++version} initialExpanded={value.expanded === true} />); };
window.sshReady = true;
`, resolveDir: path.dirname(pane), loader: 'jsx' }, bundle: true, platform: 'browser', format: 'iife', write: false,
    mainFields: ['module', 'main'], loader: { '.css': 'empty' },
    plugins: [{ name: 'owned-ssh-ipc-fixture', setup(builder) {
      builder.onResolve({ filter: /^\.\/(client\.js|i18n\.jsx|appearance\.jsx)$/ }, args => ({ path: args.path, namespace: 'ssh-fixture' }));
      builder.onLoad({ filter: /.*/, namespace: 'ssh-fixture' }, args => ({ contents: args.path.endsWith('client.js')
        ? `export const api = { isDesktop: true, onTerminalEvent: () => () => {}, call: (...args) => window.sshApi(...args) };`
        : args.path.endsWith('appearance.jsx') ? `export const useAppearance = () => ({ effective: 'dark' });`
          : `import { translate } from ${JSON.stringify(messages)}; export const useI18n = () => ({ language: window.sshLanguage || 'zh-CN', t: (text, vars) => translate(text, window.sshLanguage || 'zh-CN', vars) });`,
        resolveDir: path.dirname(pane) }));
    } }],
  });
  await writeFile(path.join(fixture, 'renderer.js'), output.outputFiles[0].text);
  const css = await Promise.all(['styles.css', 'terminal.css'].map(name => readFile(new URL(`../src/${name}`, import.meta.url), 'utf8')));
  css.unshift(await readFile(new URL('../node_modules/@xterm/xterm/css/xterm.css', import.meta.url), 'utf8'));
  await writeFile(path.join(fixture, 'index.html'), `<html lang="zh-CN" data-theme="dark"><head><style>${css.join('\n')}</style></head><body><div id="root"></div><script src="renderer.js"></script></body></html>`);
  const entry = path.join(fixture, 'main.cjs');
  await writeFile(entry, `const { app, BrowserWindow } = require('electron'); app.setPath('userData', ${JSON.stringify(path.join(fixture, 'data'))}); app.whenReady().then(() => { app.dock?.hide(); const view = new BrowserWindow({ show: false, width: 1120, height: 720, webPreferences: { sandbox: true } }); view.loadFile(${JSON.stringify(path.join(fixture, 'index.html'))}); });`);
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  desktop = await _electron.launch({ args: [entry], env, timeout: 15000 });
  page = await desktop.firstWindow();
  page.setDefaultTimeout(5000);
  await page.waitForFunction(() => window.sshReady === true);
  await page.evaluate(value => { window.sshConnection = value.connection; window.sshPasswordConnection = value.passwordConnection; }, { connection, passwordConnection });
});

after(async () => { await desktop?.close(); if (fixture) await rm(fixture, { recursive: true, force: true }); });

async function open(options = {}) {
  await page.evaluate(value => window.sshMount({ active: false, connections: [], ...value }), options);
  const label = translate('SSH 连接', options.language || 'zh-CN');
  const button = page.getByRole('button', { name: label, exact: true });
  await button.click();
  const dialog = page.getByRole('dialog', { name: label, exact: true });
  await dialog.waitFor({ state: 'visible' });
  await page.waitForFunction(() => window.sshCalls.some(call => call.method === 'listTerminalSshConnections'));
  await dialog.getByText(translate('已保存主机走本机出口（远端可见 IP）；未保存主机走境舱代理。', options.language || 'zh-CN'), { exact: true }).waitFor();
  return dialog;
}
const permittedCalls = () => page.evaluate(() => window.sshCalls.map(call => call.method));

test('SSH settings open and remain in their own dock at normal and expanded sizes', { skip: noDisplay }, async () => {
  for (const expanded of [false, true]) {
    const dialog = await open({ expanded });
    const visible = await dialog.evaluate(element => {
      const box = element.getBoundingClientRect(), dock = element.closest('.terminal-dock').getBoundingClientRect();
      const x = Math.min(box.right - 2, box.left + 16), y = Math.min(box.bottom - 2, box.top + 16);
      return box.top >= dock.top && box.bottom <= dock.bottom && box.left >= dock.left && box.right <= dock.right && element.contains(document.elementFromPoint(x, y));
    });
    assert.equal(visible, true, `expanded=${expanded}: dialog is visible and not covered`);
    assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections'].includes(method)), 'opening settings never opens or ends a session');
  }
});

test('an empty authorization list keeps discovery and setup details behind a closed help disclosure', { skip: noDisplay }, async () => {
  const dialog = await open();
  assert.equal(await dialog.getByText('暂无已保存主机', { exact: true }).isVisible(), true);
  const help = dialog.locator('.terminal-ssh-help');
  assert.equal(await help.evaluate(element => element.open), false);
  const discovery = help.getByText('让 Claude 运行 envara-ssh list，查看当前会话可用的连接。', { exact: true });
  const boundary = help.getByText('尚未保存 SSH 主机。保存配置不会自动连接。', { exact: true });
  assert.equal(await discovery.isVisible(), false);
  assert.equal(await boundary.isVisible(), false);
  assert.equal(await help.getByText('ssh user@host', { exact: true }).isVisible(), false);
  await help.locator('summary').press('Enter');
  assert.equal(await discovery.isVisible(), true);
  assert.equal(await boundary.isVisible(), true);
  assert.equal(await help.getByText('ssh user@host', { exact: true }).isVisible(), true);
  await help.locator('summary').press('Enter');
  assert.equal(await discovery.isVisible(), false);
  assert.equal(await dialog.locator('.terminal-ssh-connection').count(), 0);
  assert.equal(await dialog.getByRole('button', { name: '保存连接', exact: true }).isDisabled(), true);
  assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections'].includes(method)));
});

test('saved-host authorization refusals stay localized without exposing raw diagnostics', { skip: noDisplay }, async () => {
  const failures = [
    ['SSH_SAVED_CONNECTION_UNAVAILABLE', '此已保存 SSH 连接未载入当前终端。请在「SSH 连接」中补充授权后新建终端。'],
    ['SSH_TARGET_NOT_AUTHORIZED', '此请求与已保存的 SSH 连接不匹配，未切换网络路线。'],
  ];
  for (const language of languages) for (const [code, message] of failures) {
    const dialog = await open({ language, prepareFailure: { code } });
    await dialog.getByLabel(translate('主机', language), { exact: true }).fill('unavailable-fixture.invalid');
    await dialog.getByLabel(translate('用户名', language), { exact: true }).fill('fixture');
    await dialog.getByRole('button', { name: translate('读取主机指纹', language), exact: true }).click();
    await dialog.getByText(translate(message, language), { exact: true }).waitFor();
    assert.equal((await dialog.textContent()).includes('Synthetic host trust failure'), false);
    assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections', 'prepareTerminalSshPassword'].includes(method)));
  }
});

test('authorizing a fixture preserves the alias and displays the strict standard command without automatically connecting', { skip: noDisplay }, async () => {
  const dialog = await open();
  await dialog.getByLabel('连接名称', { exact: true }).fill('Synthetic server');
  await dialog.getByLabel('主机', { exact: true }).fill(connection.host);
  await dialog.getByLabel('端口', { exact: true }).fill(String(connection.port));
  await dialog.getByLabel('用户名', { exact: true }).fill(connection.user);
  await dialog.getByLabel('登录方式', { exact: true }).selectOption('publickey');
  await dialog.getByRole('button', { name: '选择私钥', exact: true }).click();
  await dialog.getByRole('checkbox', { name: '我已核对密钥和已信任的主机指纹' }).check();
  await dialog.getByRole('button', { name: '保存连接', exact: true }).click();
  const row = dialog.locator('.terminal-ssh-connection'); await row.waitFor();
  assert.equal(await row.getByLabel('连接命令', { exact: true }).isVisible(), true);
  assert.equal(await dialog.getByLabel('连接命令', { exact: true }).inputValue(), `ssh ${connection.alias}`);
  const details = row.locator('.terminal-ssh-details');
  assert.equal(await details.evaluate(element => element.open), false);
  assert.equal(await row.getByLabel('常用写法', { exact: true }).isVisible(), false);
  assert.equal(await row.getByText(connection.keyFingerprint, { exact: true }).isVisible(), false);
  assert.equal(await row.getByText(connection.hostFingerprints[0], { exact: true }).isVisible(), false);
  await details.locator('summary').click();
  assert.equal(await row.getByLabel('常用写法', { exact: true }).isVisible(), true);
  assert.equal(await dialog.getByLabel('常用写法', { exact: true }).inputValue(), `ssh -p ${connection.port} ${connection.user}@${connection.host}`);
  assert.equal(await row.getByText(connection.keyFingerprint, { exact: true }).isVisible(), true);
  assert.equal(await row.getByText(connection.hostFingerprints[0], { exact: true }).isVisible(), true);
  assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections', 'prepareTerminalSshIdentity', 'saveTerminalSshConnection'].includes(method)));
});

test('existing sessions keep save and removal disabled and settings cannot end them', { skip: noDisplay }, async () => {
  const dialog = await open({ active: true, connections: [connection] });
  assert.equal(await dialog.getByRole('button', { name: '移除连接', exact: true }).isDisabled(), true);
  assert.equal(await dialog.getByRole('button', { name: '保存连接', exact: true }).isDisabled(), true);
  await dialog.getByRole('status').filter({ hasText: '先结束此环境的终端会话，再修改连接。' }).waitFor();
  const help = dialog.locator('.terminal-ssh-help');
  const scope = help.getByText('先结束此环境的终端会话，再修改连接。', { exact: true });
  assert.equal(await scope.isVisible(), false);
  await help.locator('summary').click();
  assert.equal(await scope.isVisible(), true);
  assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections', 'resizeTerminal'].includes(method)));
});

test('expanding a running terminal does not steal focus from open SSH settings', { skip: noDisplay }, async () => {
  const dialog = await open({ active: true });
  await page.locator('.terminal-session-view:not([hidden]) .xterm').waitFor({ state: 'visible' });
  const field = dialog.getByLabel('连接名称', { exact: true });
  await field.focus();
  await page.evaluate(() => window.sshSetExpanded(true));
  await page.locator('.terminal-dock.is-expanded').waitFor();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await field.evaluate(element => element === document.activeElement), true);
});

test('all nine languages show the new setup, discovery, empty state and standard command', { skip: noDisplay }, async () => {
  for (const language of languages) {
    for (const message of ['已保存主机走本机出口（远端可见 IP）；未保存主机走境舱代理。', '密码仅本次运行有效，退出清除。', '使用说明', '连接详情', '先结束此环境的终端会话，再修改连接。', '暂无已保存主机']) {
      assert.ok(Object.hasOwn(translationCatalog[language], message), `${language}: missing ${message}`);
      assert.equal(typeof translationCatalog[language][message], 'string');
      assert.ok(translationCatalog[language][message].trim(), `${language}: empty ${message}`);
    }
    let dialog = await open({ language });
    assert.equal(await dialog.getByText(translate('暂无已保存主机', language), { exact: true }).isVisible(), true, language);
    let help = dialog.locator('.terminal-ssh-help');
    assert.equal(await help.locator('summary').textContent(), translate('使用说明', language));
    const discovery = help.getByText(translate('让 Claude 运行 envara-ssh list，查看当前会话可用的连接。', language), { exact: true });
    assert.equal(await discovery.isVisible(), false, language);
    await help.locator('summary').click();
    assert.equal(await discovery.isVisible(), true, language);
    dialog = await open({ language, connections: [connection] });
    const details = dialog.locator('.terminal-ssh-details');
    assert.equal(await details.locator('summary').textContent(), translate('连接详情', language));
    assert.equal(await dialog.getByLabel(translate('常用写法', language), { exact: true }).isVisible(), false, language);
    await details.locator('summary').click();
    assert.equal(await dialog.getByLabel(translate('常用写法', language), { exact: true }).isVisible(), true, language);
    assert.equal(await dialog.getByLabel(translate('常用写法', language), { exact: true }).inputValue(), `ssh -p ${connection.port} ${connection.user}@${connection.host}`, language);
    await dialog.getByLabel(translate('登录方式', language), { exact: true }).selectOption('publickey');
    help = dialog.locator('.terminal-ssh-help');
    const lifetime = help.getByText(translate('SSH 密钥授权在本次应用运行期间有效，不会定时到期；结束会话、线路停止或退出应用仍会关闭连接。', language), { exact: true });
    assert.equal(await lifetime.isVisible(), false, language);
    await help.locator('summary').click();
    assert.equal(await lifetime.isVisible(), true, language);
    dialog = await open({ language, active: true });
    assert.equal(await dialog.getByRole('status').filter({ hasText: translate('先结束此环境的终端会话，再修改连接。', language) }).isVisible(), true, language);
  }
});

test('new host authorization keeps prepared fingerprints and consent visible outside collapsed help', { skip: noDisplay }, async () => {
  for (const authType of ['password', 'publickey']) {
    const dialog = await open();
    await dialog.getByLabel('连接名称', { exact: true }).fill('Synthetic consent fixture');
    await dialog.getByLabel('主机', { exact: true }).fill(connection.host);
    await dialog.getByLabel('用户名', { exact: true }).fill(connection.user);
    await dialog.getByLabel('登录方式', { exact: true }).selectOption(authType);
    if (authType === 'password') await dialog.getByLabel('密码', { exact: true }).fill('synthetic-password-not-a-secret');
    await dialog.getByRole('button', { name: authType === 'password' ? '读取主机指纹' : '选择私钥', exact: true }).click();
    const identity = dialog.locator('.terminal-ssh-identity');
    await identity.waitFor({ state: 'visible' });
    assert.equal(await identity.evaluate(element => element.closest('details') == null), true);
    assert.equal(await dialog.locator('.terminal-ssh-help').evaluate(element => element.open), false);
    assert.equal(await identity.getByText(connection.hostFingerprints[0], { exact: true }).isVisible(), true);
    if (authType === 'publickey') assert.equal(await identity.getByText(connection.keyFingerprint, { exact: true }).isVisible(), true);
    const consent = identity.getByRole('checkbox');
    assert.equal(await consent.isVisible(), true);
    assert.equal(await consent.isChecked(), false);
    assert.equal(await dialog.getByRole('button', { name: '保存连接', exact: true }).isDisabled(), true);
    await consent.check();
    assert.equal(await dialog.getByRole('button', { name: '保存连接', exact: true }).isEnabled(), true);
    assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections', 'prepareTerminalSshPassword', 'prepareTerminalSshIdentity'].includes(method)));
  }
});

async function preparePassword(dialog, password = 'synthetic-password-not-a-secret') {
  await dialog.getByLabel('连接名称', { exact: true }).fill('Synthetic password server');
  await dialog.getByLabel('主机', { exact: true }).fill(passwordConnection.host);
  await dialog.getByLabel('端口', { exact: true }).fill(String(passwordConnection.port));
  await dialog.getByLabel('用户名', { exact: true }).fill(passwordConnection.user);
  await dialog.getByLabel('密码', { exact: true }).fill(password);
  await dialog.getByRole('button', { name: '读取主机指纹', exact: true }).click();
  await dialog.getByRole('checkbox', { name: '我已核对已信任的主机指纹', exact: true }).check();
}

test('password is the default and preparing host trust never transmits it', { skip: noDisplay }, async () => {
  const dialog = await open();
  assert.equal(await dialog.getByLabel('登录方式', { exact: true }).inputValue(), 'password');
  const secret = 'synthetic-password-not-a-secret';
  await preparePassword(dialog, secret);
  const input = dialog.getByLabel('密码', { exact: true });
  assert.equal(await input.getAttribute('type'), 'password');
  assert.equal(await input.getAttribute('autocomplete'), 'off');
  assert.equal(await dialog.textContent().then(value => value.includes(secret)), false);
  assert.equal(await dialog.evaluate((element, value) => element.outerHTML.includes(value), secret), false);
  assert.equal(await page.evaluate(() => localStorage.length), 0);
  const calls = await page.evaluate(() => window.sshCalls.filter(call => call.method === 'prepareTerminalSshPassword'));
  assert.deepEqual(calls.map(call => call.args), [{ id: 'ssh_ui_environment', host: passwordConnection.host, port: passwordConnection.port, user: passwordConnection.user }]);
  assert.equal(await permittedCalls().then(methods => methods.includes('saveTerminalSshConnection')), false);
});

test('password save clears the input before IPC completes and exposes only safe commands and readiness', { skip: noDisplay }, async () => {
  const dialog = await open({ deferSave: true });
  const secret = 'synthetic-password-not-a-secret';
  await preparePassword(dialog, secret);
  await dialog.getByRole('button', { name: '保存连接', exact: true }).click();
  await page.waitForFunction(() => typeof window.sshFinishSave === 'function');
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
  const submitted = await page.evaluate(() => window.sshCalls.filter(call => call.method === 'saveTerminalSshConnection'));
  assert.equal(submitted.length, 1); assert.equal(submitted[0].args.password, secret);
  await page.evaluate(() => window.sshFinishSave());
  const row = dialog.locator('.terminal-ssh-connection'); await row.waitFor();
  assert.equal(await row.getByText('密码已就绪', { exact: true }).count(), 1);
  assert.equal(await row.getByLabel('连接命令', { exact: true }).inputValue(), `ssh ${passwordConnection.alias}`);
  assert.equal(await row.getByLabel('常用写法', { exact: true }).isVisible(), false);
  await row.locator('.terminal-ssh-details > summary').click();
  assert.equal(await row.getByLabel('常用写法', { exact: true }).isVisible(), true);
  assert.equal(await row.getByLabel('常用写法', { exact: true }).inputValue(), `ssh -p ${passwordConnection.port} ${passwordConnection.user}@${passwordConnection.host}`);
  assert.equal(await row.textContent().then(value => value.includes(secret)), false);
  assert.equal(await row.getByText('Synthetic key', { exact: true }).count(), 0);
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
  assert.equal(await page.evaluate(() => localStorage.length), 0);
});

test('passwords clear after failed save, failed trust preparation, auth changes and closing settings', { skip: noDisplay }, async () => {
  let dialog = await open({ saveFailure: true });
  await preparePassword(dialog);
  await dialog.getByRole('button', { name: '保存连接', exact: true }).click();
  await dialog.getByText('密码无效，请重新输入。', { exact: true }).waitFor();
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
  assert.equal(await dialog.getByRole('checkbox').count(), 0);
  dialog = await open({ prepareFailure: true });
  await dialog.getByLabel('主机', { exact: true }).fill(passwordConnection.host);
  await dialog.getByLabel('用户名', { exact: true }).fill(passwordConnection.user);
  await dialog.getByLabel('密码', { exact: true }).fill('synthetic-password-not-a-secret');
  await dialog.getByRole('button', { name: '读取主机指纹', exact: true }).click();
  await dialog.getByText('本机 known_hosts 没有匹配的可信主机记录，无法保存此连接。', { exact: true }).waitFor();
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
  dialog = await open();
  await preparePassword(dialog);
  await dialog.getByLabel('登录方式', { exact: true }).selectOption('publickey');
  assert.equal(await dialog.getByLabel('密码', { exact: true }).count(), 0);
  assert.equal(await dialog.getByRole('checkbox').count(), 0);
  await dialog.getByLabel('登录方式', { exact: true }).selectOption('password');
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
  await dialog.getByLabel('密码', { exact: true }).fill('synthetic-password-not-a-secret');
  await dialog.getByLabel('主机', { exact: true }).fill('changed-fixture.invalid');
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
  await dialog.getByLabel('密码', { exact: true }).fill('synthetic-password-not-a-secret');
  await dialog.getByRole('button', { name: '关闭', exact: true }).click();
  await page.getByRole('button', { name: 'SSH 连接', exact: true }).click();
  dialog = page.getByRole('dialog', { name: 'SSH 连接', exact: true });
  assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '');
});

test('saved password connections can be unlocked without adding the password to commands or public metadata', { skip: noDisplay }, async () => {
  const dialog = await open({ connections: [passwordConnection], deferPassword: true });
  const row = dialog.locator('.terminal-ssh-connection');
  await row.getByText('需先提供密码，不会改走代理。', { exact: true }).waitFor();
  await row.getByRole('button', { name: '提供密码', exact: true }).click();
  let input = row.getByLabel('密码', { exact: true });
  await input.fill('synthetic-password-not-a-secret');
  await row.getByRole('button', { name: '取消', exact: true }).click();
  await row.getByRole('button', { name: '提供密码', exact: true }).click();
  input = row.getByLabel('密码', { exact: true });
  assert.equal(await input.inputValue(), '');
  await input.fill('synthetic-password-not-a-secret');
  await row.getByRole('button', { name: '保存密码', exact: true }).click();
  await page.waitForFunction(() => typeof window.sshFinishPassword === 'function');
  assert.equal(await input.inputValue(), '');
  await page.evaluate(() => window.sshFinishPassword());
  await row.getByText('密码已就绪', { exact: true }).waitFor();
  assert.equal(await row.getByRole('button', { name: '更新密码', exact: true }).count(), 1);
  assert.equal(await row.locator('input[type="password"]').count(), 0);
  assert.equal(await row.getByLabel('连接命令', { exact: true }).inputValue(), `ssh ${passwordConnection.alias}`);
  const calls = await page.evaluate(() => window.sshCalls.filter(call => call.method === 'setTerminalSshPassword'));
  assert.equal(calls.length, 1); assert.equal(calls[0].args.connectionId, passwordConnection.id);
  assert.equal(await page.evaluate(() => Object.hasOwn(window.sshFixture.connections[0], 'password')), false);
});

test('a failed password unlock clears the input and active sessions prohibit password mutations', { skip: noDisplay }, async () => {
  let dialog = await open({ connections: [passwordConnection], passwordFailure: true });
  let row = dialog.locator('.terminal-ssh-connection');
  await row.getByRole('button', { name: '提供密码', exact: true }).click();
  await row.getByLabel('密码', { exact: true }).fill('synthetic-password-not-a-secret');
  await row.getByRole('button', { name: '保存密码', exact: true }).click();
  await dialog.getByText('密码无效，请重新输入。', { exact: true }).waitFor();
  assert.equal(await row.getByLabel('密码', { exact: true }).inputValue(), '');
  await row.getByText('需先提供密码，不会改走代理。', { exact: true }).waitFor();
  dialog = await open({ active: true, connections: [passwordConnection] }); row = dialog.locator('.terminal-ssh-connection');
  assert.equal(await row.getByRole('button', { name: '提供密码', exact: true }).isDisabled(), true);
  assert.equal(await row.getByRole('button', { name: '移除连接', exact: true }).isDisabled(), true);
  assert.equal(await dialog.getByRole('button', { name: '保存连接', exact: true }).isDisabled(), true);
  assert.equal(await dialog.locator('.terminal-ssh-fields').getByLabel('密码', { exact: true }).isDisabled(), true);
  assert.ok((await permittedCalls()).every(method => ['terminalSnapshot', 'listTerminalSshConnections', 'resizeTerminal'].includes(method)));
});

test('all nine languages translate password selection, privacy, trust and locked connection state', { skip: noDisplay }, async () => {
  for (const language of languages) {
    const dialog = await open({ language, connections: [passwordConnection] });
    assert.equal(await dialog.getByLabel(translate('登录方式', language), { exact: true }).inputValue(), 'password');
    assert.equal(await dialog.getByText(translate('密码仅本次运行有效，退出清除。', language), { exact: true }).isVisible(), true, language);
    const help = dialog.locator('.terminal-ssh-help');
    const privacy = help.getByText(translate('密码在本次应用运行期间有效，不会定时到期，退出即清除，也不会写入命令或提供给 Claude。结束会话、线路停止或退出应用仍会关闭连接。', language), { exact: true });
    assert.equal(await privacy.isVisible(), false, language);
    await help.locator('summary').click();
    assert.equal(await privacy.isVisible(), true, language);
    assert.equal(await dialog.getByText(translate('需先提供密码，不会改走代理。', language), { exact: true }).count(), 1, language);
    assert.equal(await dialog.getByRole('button', { name: translate('读取主机指纹', language), exact: true }).count(), 1, language);
    assert.equal(await dialog.locator('.terminal-ssh-fields input[type="password"]').getAttribute('autocomplete'), 'off');
  }
});


test('switching environments discards delayed password preparation, save and unlock results', { skip: noDisplay }, async () => {
  for (const action of ['prepare', 'save', 'unlock']) {
    let dialog = await open({ twoProfiles: true, deferPrepare: action === 'prepare', deferSave: action === 'save', deferPassword: action === 'unlock',
      connections: action === 'unlock' ? [passwordConnection] : [] });
    if (action === 'unlock') {
      const row = dialog.locator('.terminal-ssh-connection');
      await row.getByRole('button', { name: '提供密码', exact: true }).click();
      await row.getByLabel('密码', { exact: true }).fill('synthetic-password-not-a-secret');
      await row.getByRole('button', { name: '保存密码', exact: true }).click();
    } else if (action === 'save') {
      await preparePassword(dialog);
      await dialog.getByRole('button', { name: '保存连接', exact: true }).click();
    } else {
      await dialog.getByLabel('主机', { exact: true }).fill(passwordConnection.host);
      await dialog.getByLabel('用户名', { exact: true }).fill(passwordConnection.user);
      await dialog.getByRole('button', { name: '读取主机指纹', exact: true }).click();
    }
    const finish = action === 'prepare' ? 'sshFinishPrepare' : action === 'save' ? 'sshFinishSave' : 'sshFinishPassword';
    await page.waitForFunction(name => typeof window[name] === 'function', finish);
    await page.getByRole('tab', { name: 'Second synthetic environment', exact: true }).click();
    await page.getByRole('button', { name: 'SSH 连接', exact: true }).click();
    dialog = page.getByRole('dialog', { name: 'SSH 连接', exact: true });
    await dialog.getByText('Second synthetic environment', { exact: true }).waitFor();
    await dialog.getByText('暂无已保存主机', { exact: true }).waitFor();
    await page.evaluate(name => window[name](), finish);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await dialog.locator('.terminal-ssh-connection').count(), 0, action);
    assert.equal(await dialog.getByRole('checkbox').count(), 0, action);
    assert.equal(await dialog.getByLabel('密码', { exact: true }).inputValue(), '', action);
    assert.equal(await dialog.getByLabel('主机', { exact: true }).inputValue(), '', action);
    assert.equal(await dialog.getByRole('button', { name: '关闭', exact: true }).isDisabled(), false, action);
  }
});
