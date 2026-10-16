import test from 'node:test';
import assert from 'node:assert/strict';
import { NEW_CLAUDE_ACCOUNT, validClaudeAccountChoice, claudeSessionForRequest, claudeInstallPresentation, claudeErrorMessage, validClaudeInstallationChoice, claudeInstallationOptions } from '../src/claude-account-choice.mjs';
import { terminalSessionOptions } from '../src/terminal-session-choice.mjs';
import { TerminalStreamStore } from '../src/terminal-state.mjs';
import { translationCatalog } from '../src/i18n.mjs';

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
