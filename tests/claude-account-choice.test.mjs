import test from 'node:test';
import assert from 'node:assert/strict';
import { NEW_CLAUDE_ACCOUNT, validClaudeAccountChoice, claudeAccountLabel, reconcileClaudeAccountChoice, claudeSessionForRequest, claudeInstallPresentation, claudeErrorMessage, validClaudeInstallationChoice, claudeInstallationOptions } from '../src/claude-account-choice.mjs';
import { terminalSessionOptions } from '../src/terminal-session-choice.mjs';
import { TerminalStreamStore } from '../src/terminal-state.mjs';
import { translate, translationCatalog } from '../src/i18n.mjs';

test('installation source is explicit only for a first install and cannot reuse another environment status', () => {
  const missing = { profileId: 'ph', status: 'ready', installed: false };
  for (const source of ['download', 'local']) assert.deepEqual(claudeInstallationOptions(missing, 'ph', source), { claudeInstallSource: source });
  assert.equal(validClaudeInstallationChoice(missing, 'ph', 'automatic'), false);
  assert.equal(validClaudeInstallationChoice(missing, 'us', 'local'), false);
  assert.equal(validClaudeInstallationChoice({ ...missing, status: 'loading' }, 'ph', 'download'), false);
  assert.equal(validClaudeInstallationChoice({ ...missing, status: 'error' }, 'ph', 'download'), false);
  assert.deepEqual(claudeInstallationOptions({ ...missing, installed: true }, 'ph', 'local'), {}, 'an existing environment installation never requests replacement');
  assert.throws(() => claudeInstallationOptions(missing, 'us', 'download'));
  assert.equal(claudeErrorMessage('CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE'), '本机未找到可用的 Claude 原生安装，请选择下载独立安装。');
  assert.equal(claudeErrorMessage('未找到可复制的本机 Claude Code 官方原生安装，请检查本机安装或选择下载新版本。', 'CLAUDE_CODE_LOCAL_INSTALL_UNAVAILABLE'), '本机未找到可用的 Claude 原生安装，请选择下载独立安装。');
});

test('first-install choices and recovery copy exist in every interface language', () => {
  const keys = ['下载独立安装（推荐）', '从本机 Claude 初始化', '只复制程序，登录档案仍独立。', '正在检查 Claude 安装…', '无法读取 Claude 安装状态，请重试。', '本机未找到可用的 Claude 原生安装，请选择下载独立安装。', '首次可下载或从本机初始化，之后复用境舱安装。'];
  for (const [language, catalog] of Object.entries(translationCatalog)) for (const key of keys) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
});

test('account choices remain bound to the loaded environment and require a real saved record or a new name', () => {
  const loaded = { profileId: 'ph', status: 'ready', items: [{ id: 'default' }, { id: 'work' }] };
  assert.equal(validClaudeAccountChoice(loaded, 'ph', { accountId: 'work' }), true);
  for (const [state, profile, choice] of [
    [loaded, 'us', { accountId: 'work' }],
    [{ ...loaded, status: 'loading' }, 'ph', { accountId: 'default' }],
    [loaded, 'ph', { accountId: 'deleted' }],
    [loaded, 'ph', { accountId: NEW_CLAUDE_ACCOUNT, accountName: '   ' }],
  ]) assert.equal(validClaudeAccountChoice(state, profile, choice), false);
  assert.equal(validClaudeAccountChoice(loaded, 'ph', { accountId: NEW_CLAUDE_ACCOUNT, accountName: ' Work ' }), true);
  assert.deepEqual(terminalSessionOptions('claude-code', 'browser_ph', 'work'), { kind: 'claude-code', browserProfileId: 'browser_ph', claudeAccountId: 'work' });
  assert.throws(() => terminalSessionOptions('claude-code', 'browser_ph', '../other'));
  assert.deepEqual(terminalSessionOptions('shell', 'browser_ph', 'work'), {});
});

test('renamed defaults are displayed literally and account reload only replaces a missing selection', () => {
  const items = [{ id: 'default', name: 'Primary', default: true }, { id: 'work', name: 'Work' }];
  const t = key => ({ 默认档案: 'Default profile' })[key];
  assert.equal(claudeAccountLabel(items[0], t), 'Primary');
  assert.equal(claudeAccountLabel({ ...items[0], name: '默认' }, t), 'Default profile');
  assert.equal(claudeAccountLabel({ id: 'work', name: '默认' }, t), '默认');
  assert.equal(reconcileClaudeAccountChoice(items, 'work'), 'work');
  assert.equal(reconcileClaudeAccountChoice(items, NEW_CLAUDE_ACCOUNT), NEW_CLAUDE_ACCOUNT);
  assert.equal(reconcileClaudeAccountChoice(items, 'deleted'), 'default');
  assert.equal(reconcileClaudeAccountChoice([], 'deleted'), NEW_CLAUDE_ACCOUNT);
});

test('only the exact Claude request may drive cancellation and download progress', () => {
  const wanted = { sessionId: 'new', kind: 'claude-code', requestId: 'request-new' };
  const profiles = [{ profileId: 'ph', sessions: [{ sessionId: 'old', kind: 'claude-code', requestId: 'request-old' }, wanted] }, { profileId: 'us', sessions: [{ sessionId: 'other', kind: 'shell', requestId: 'request-new' }] }];
  assert.equal(claudeSessionForRequest(profiles, 'ph', 'request-new'), wanted);
  assert.equal(claudeSessionForRequest(profiles, 'us', 'request-new'), null);
  assert.equal(claudeSessionForRequest(profiles, 'ph', null), null);
  assert.deepEqual(claudeInstallPresentation({ phase: 'downloading', receivedBytes: 42, totalBytes: 100 }), { label: '下载 Claude…', percent: 42 });
  assert.equal(claudeInstallPresentation({ phase: 'downloading', receivedBytes: 120, totalBytes: 100 }).percent, 100);
  for (const totalBytes of [undefined, 0, -1, Infinity]) assert.equal(claudeInstallPresentation({ phase: 'downloading', receivedBytes: 10, totalBytes }).percent, null);
  assert.equal(claudeInstallPresentation({ phase: 'untrusted-stage' }), null);
  assert.equal(claudeErrorMessage('CLAUDE_CODE_DOWNLOAD_CANCELLED'), 'Claude 下载已取消。');
  assert.equal(claudeErrorMessage('Existing specific reason'), 'Existing specific reason');
});

test('installer progress follows ordered events and cannot regress to a stale snapshot', () => {
  const store = new TerminalStreamStore();
  const initial = { sessionId: 'install', profileId: 'ph', requestId: 'request', kind: 'claude-code', status: 'starting', sequence: 0, claudeInstall: { phase: 'metadata' } };
  store.applySnapshot({ profiles: [{ profileId: 'ph', sessions: [initial] }] });
  store.applyEvent({ type: 'status', ...initial, sequence: 1, claudeInstall: { phase: 'downloading', receivedBytes: 50, totalBytes: 100 } });
  store.applySnapshot({ profiles: [{ profileId: 'ph', sessions: [initial] }] });
  assert.equal(store.getSession('install').claudeInstall.receivedBytes, 50);
  assert.equal(store.getSession('install').requestId, 'request');
  store.applyEvent({ type: 'status', ...initial, sequence: 2, status: 'running', claudeInstall: null });
  assert.equal(store.getSession('install').claudeInstall, null);
  assert.equal(store.getSession('install').status, 'running');
});

test('Claude cleanup failures have fixed actionable copy in all nine interface languages', () => {
  const installation = 'Claude 安装临时文件清理未完成，请重试关闭会话。';
  assert.equal(claudeErrorMessage('CLAUDE_CODE_INSTALLATION_CLEANUP_FAILED'), installation);
  assert.equal(claudeErrorMessage('internal cleanup detail', 'CLAUDE_CODE_INSTALLATION_CLEANUP_FAILED'), installation);
  for (const [language, catalog] of Object.entries(translationCatalog)) {
    for (const key of [installation, 'Claude 会话临时文件清理未完成，请重试关闭会话。']) {
      assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
      assert(catalog[key].trim());
      if (language !== 'zh-CN') assert.notEqual(catalog[key], key, language);
    }
  }
});

test('Keychain failures explain recovery without displaying native details', () => {
  const locked = '登录钥匙串已锁定。请在 macOS“钥匙串访问”中解锁后，新建 Claude 终端。';
  const missing = '未找到可用的系统登录钥匙串。请在 macOS“钥匙串访问”中检查后重试。';
  const cleanup = 'Claude 钥匙串准备的临时资料未能完成清理。请保留现有资料并联系维护者处理。';
  const finalCheck = 'Claude 钥匙串准备的收尾检查未通过。请保留现有资料并联系维护者处理。';
  const unavailable = 'Claude 登录凭据存储暂不可用，请检查钥匙串后重试。';
  const detail = 'native failure at /private/fixture/login.keychain-db, status=-25307';
  assert.equal(claudeErrorMessage(detail, 'CLAUDE_KEYCHAIN_LOCKED'), locked);
  assert.equal(claudeErrorMessage(detail, 'CLAUDE_KEYCHAIN_MISSING'), missing);
  assert.equal(claudeErrorMessage(detail, 'CLAUDE_KEYCHAIN_CLEANUP_FAILED'), cleanup);
  assert.equal(claudeErrorMessage(detail, 'CLAUDE_KEYCHAIN_HOST_CHECK_FAILED'), finalCheck);
  assert.equal(claudeErrorMessage('CLAUDE_KEYCHAIN_HOST_CHECK_FAILED'), finalCheck);
  assert.notEqual(finalCheck, cleanup, 'an incomplete check does not establish a cleanup failure');
  for (const code of ['CLAUDE_KEYCHAIN_INVALID_ARGUMENT', 'CLAUDE_KEYCHAIN_UNSAFE_PATH',
    'CLAUDE_KEYCHAIN_UNAVAILABLE', 'CLAUDE_KEYCHAIN_PREPARATION_FAILED', 'CLAUDE_KEYCHAIN_PROTOCOL_ERROR',
    'CLAUDE_KEYCHAIN_FUTURE_FAILURE', `CLAUDE_KEYCHAIN_${detail}`]) {
    assert.equal(claudeErrorMessage(detail, code), unavailable, code);
    assert.equal(claudeErrorMessage(code), unavailable, code);
  }
  assert.equal(claudeErrorMessage('Unrelated failure'), 'Unrelated failure');
});

test('all Keychain recovery messages are translated in all nine interface languages', () => {
  const codes = ['INVALID_ARGUMENT', 'UNSAFE_PATH', 'BUSY', 'MISSING', 'LOCKED', 'UNAVAILABLE',
    'EXISTING_SELECTION', 'PREPARATION_FAILED', 'HOST_CHANGED', 'HOST_CHECK_FAILED', 'CLEANUP_FAILED', 'RESOURCE_INVALID',
    'PROTOCOL_ERROR', 'TIMEOUT', 'FUTURE_FAILURE'].map(suffix => `CLAUDE_KEYCHAIN_${suffix}`);
  assert.equal(Object.keys(translationCatalog).length, 9);
  for (const code of codes) {
    const message = claudeErrorMessage('private native detail', code);
    for (const [language, catalog] of Object.entries(translationCatalog)) {
      assert.equal(typeof catalog[message], 'string', `${language}: ${code}`);
      assert(catalog[message].trim(), `${language}: ${code}`);
      assert(!catalog[message].includes('CLAUDE_KEYCHAIN_'), `${language}: ${code}`);
      assert.equal(translate(message, language), catalog[message], `${language}: secondary ${code}`);
      if (language !== 'zh-CN') assert.notEqual(catalog[message], message, `${language}: ${code}`);
    }
  }
});
