import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { terminalNetworks, SYSTEM_BROWSER } from '../src/link-browser.mjs';
import { CLAUDE_SESSION, sessionNetworks, sessionChoiceHost, changeSessionKind, terminalSessionOptions } from '../src/terminal-session-choice.mjs';
import { translationCatalog, translate } from '../src/i18n.mjs';

const profiles = [
  { id: 'local', name: 'Local' },
  { id: 'ph_one', name: 'PH One', proxyId: 'ph' },
  { id: 'ph_two', name: 'PH Two', proxyId: 'ph' },
  { id: 'us_one', name: 'US One', proxyId: 'us' },
];
const networks = terminalNetworks(profiles);

test('Claude choices require a proxy network and exact browser on that network', () => {
  assert.deepEqual(sessionNetworks(networks, CLAUDE_SESSION).map(item => item.id), ['ph', 'us']);
  assert.equal(sessionChoiceHost(networks, { kind: CLAUDE_SESSION, networkId: 'ph', browserId: 'ph_two' }, 'ph_one').id, 'ph_two');
  for (const choice of [
    { networkId: 'direct', browserId: 'local' },
    { networkId: 'ph', browserId: SYSTEM_BROWSER },
    { networkId: 'ph', browserId: 'us_one' },
    { networkId: 'ph', browserId: 'deleted' },
  ]) assert.equal(sessionChoiceHost(networks, { ...choice, kind: CLAUDE_SESSION }, 'ph_one'), null, 'invalid or removed choice cannot silently select another browser');
});

test('switching to Claude replaces host-network and system-browser choices with a valid explicit choice', () => {
  const shell = { kind: 'shell', networkId: 'direct', browserId: SYSTEM_BROWSER, directory: { token: 'picked-token', path: '/work' } };
  const claude = changeSessionKind(networks, shell, CLAUDE_SESSION, 'ph_two');
  assert.equal(claude.networkId, 'ph');
  assert.equal(claude.browserId, 'ph_two');
  assert.equal(claude.directory.token, 'picked-token', 'changing the type keeps the independently selected folder');
  assert.equal(sessionChoiceHost(networks, claude, 'local').id, 'ph_two');
  assert.equal(changeSessionKind(terminalNetworks([profiles[0]]), shell, CLAUDE_SESSION, 'local').networkId, null, 'without a managed browser the session stays unavailable');
});

test('ordinary terminal preserves its existing direct and system-browser options', () => {
  assert.equal(sessionNetworks(networks, 'shell'), networks);
  assert.equal(sessionChoiceHost(networks, { kind: 'shell', networkId: 'direct', browserId: SYSTEM_BROWSER }, 'local').id, 'local');
  assert.deepEqual(terminalSessionOptions('shell', SYSTEM_BROWSER), {});
  const shell = { kind: 'shell', networkId: 'ph', browserId: SYSTEM_BROWSER };
  assert.equal(changeSessionKind(networks, shell, 'shell', 'ph_one').browserId, SYSTEM_BROWSER);
});

test('the desktop launch request carries the exact Claude browser, never a renderer executable or folder path', () => {
  assert.deepEqual(terminalSessionOptions(CLAUDE_SESSION, 'ph_two'), { kind: 'claude-code', browserProfileId: 'ph_two' });
  for (const id of [null, SYSTEM_BROWSER, '../host', '', 'x'.repeat(97)]) assert.throws(() => terminalSessionOptions(CLAUDE_SESSION, id));
  assert.throws(() => terminalSessionOptions('arbitrary-command', 'ph_one'));
});

test('the terminal chooser wires its tested constraints and keeps ordinary link preferences separate', async () => {
  const pane = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  assert.match(pane, /sessionChoiceHost\(networks, choice, activeProfileId\)/);
  assert.match(pane, /sessionNetworks\(networks, newSession\.kind\)/);
  assert.match(pane, /newSession\.kind !== CLAUDE_SESSION &&/);
  assert.match(pane, /kind: newSession\.kind, browserProfileId: newSession\.browserId/);
  assert.match(pane, /\.\.\.terminalSessionOptions\(kind, browserProfileId, claudeAccountId\)/);
  assert.match(pane, /\{!claude && <option value=\{SYSTEM_BROWSER\}/);
  assert.match(pane, /selectedSession\?\.kind === CLAUDE_SESSION/);
  assert.match(pane, /session\.kind === CLAUDE_SESSION\s*\? `Claude Code/);
  assert.match(pane, /className="terminal-claude-settings"><summary>\{t\('会话设置'\)\}/);
  assert.match(pane, /<dt>\{t\('Claude 安装'\)\}<\/dt><dd>\{t\('首次可下载或从本机初始化，之后复用境舱安装。'\)\}/);
  assert.match(pane, /const privacyMode = host\?\.privacy\?\.mode \?\? 'standard'/);
  assert.match(pane, /privacyMode !== 'off' && <small className="terminal-claude-privacy-note">\{t\('关闭遥测可能影响 Remote Control 等功能。'\)\}/);
  assert.match(pane, /账号登录；启动前检查 API 配置冲突/);
  assert.match(pane, /进入终端后运行 claude，可自行添加参数。/);
  assert.doesNotMatch(pane, /'启动 Claude Code'/, 'creation opens the prepared terminal, not Claude itself');
  assert.match(pane, /if \(event\.type === 'status' \|\| event\.type === 'exit'\) retainFailure\(event\)/);
  assert.match(pane, /retainFailure\(session\)/);
  assert.match(pane, /dockError && dockErrorCode && <code/);
  assert.match(pane, /dockError && dockCleanupError && <span/);
  assert.match(pane, /notice\.updateOnly && \(currentFailureRef\.current\?\.sessionId !== notice\.sessionId/);
});

test('dedicated-session copy is available in all nine interface languages', () => {
  const keys = ['会话类型', '普通终端', '独立 Claude · 账号登录', '运行此境舱独立安装的 Claude；MCP 与 Playwright 固定使用所选浏览器。', 'Claude 安装', '首次自动安装，更新只影响此境舱。', '固定使用所选网络和浏览器，保留境舱配置。', '会话设置', '登录方式', '账号登录；启动前检查 API 配置冲突', '配置与历史', '境舱独立保存', '网络与浏览器', '固定绑定；网络组件退出时结束会话', '官方隐私设置', '不额外关闭遥测与错误上报。', '关闭遥测与错误上报。', '同时关闭非必要网络请求。', 'MCP 与 Playwright 仅使用所选浏览器。会话内关闭自动更新。', '先添加网络出口，并为它创建一个境舱浏览器。', '请选择此网络的境舱浏览器。', '启动 Claude Code', '浏览器固定为：{name}', '此境舱的 Claude 设置含 API、网关或外部登录配置；请移除冲突后使用账号登录会话。', '此境舱的 Claude 设置会覆盖会话网络或目录；请移除冲突后重试。', '此境舱的 Claude 设置无法安全读取，请检查 settings.json。'];
  for (const [language, catalog] of Object.entries(translationCatalog)) {
    assert.equal(typeof catalog['关闭遥测可能影响 Remote Control 等功能。'], 'string', language);
    for (const key of ['进入终端后运行 claude，可自行添加参数。', '同一境舱保留 Claude 登录信息。']) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    assert.equal(typeof catalog['所选网络的代理内核已停止，Claude Code 会话已中止。请检查网络后新建会话。'], 'string', language);
    for (const key of ['终端进程清理未完成，请重试关闭会话。', '终端进程清理未完成，请查看应用状态。']) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    for (const key of keys) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    assert.ok(translate('浏览器固定为：{name}', language, { name: 'PH One' }).includes('PH One'));
  }
});
