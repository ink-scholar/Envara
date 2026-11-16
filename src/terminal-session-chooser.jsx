import React from 'react';
import { X, FolderOpen, ArrowsClockwise } from '@phosphor-icons/react';
import { SYSTEM_BROWSER } from './link-browser.mjs';
import { CLAUDE_SESSION, sessionNetworks, changeSessionKind } from './terminal-session-choice.mjs';
import { NEW_CLAUDE_ACCOUNT, claudeAccountLabel, claudeSessionForRequest, claudeInstallPresentation,
  validClaudeAccountChoice, validClaudeInstallationChoice } from './claude-account-choice.mjs';
import { terminalDirectoryChoice } from './terminal-directory-choice.mjs';
import { terminalSessionName, terminalsForAccount } from './terminal-account-context.mjs';
import { liveSessions, statusLabels } from './terminal-session-status.mjs';

// Render the dock-owned launch/account draft. Requests and stale-selection
// guards stay in the dock so opening or closing this form cannot reset them.
export function TerminalSessionChooser({ t, newSession, setNewSession, networks, activeProfileId, host,
  directoryFor, defaultBrowser, terminalProfiles, claudeAccounts, claudeInstallation, accountEditor, setAccountEditor,
  pending, cancellingSessionId, setAccountsReload, setInstallationReload, createChosenAccount, mutateAccount,
  chooseNewSessionDirectory, confirmNewSession, closeSession, onFocusAccountSession }) {
  const claude = newSession.kind === CLAUDE_SESSION;
  const manageOnly = newSession.manageAccount === true;
  const availableNetworks = sessionNetworks(networks, newSession.kind);
  const network = availableNetworks.find(item => item.id === newSession.networkId);
  const directory = terminalDirectoryChoice(newSession, directoryFor(host?.id)?.cwd);
  const folder = directory.path;
  const egress = network?.egress;
  const privacyMode = host?.privacy?.mode ?? 'standard';
  const startingSession = claudeSessionForRequest(terminalProfiles, host?.id, newSession.requestId);
  const installation = claudeInstallPresentation(startingSession?.claudeInstall);
  const accountLoading = claudeAccounts.profileId !== host?.id || claudeAccounts.status === 'loading';
  const scopedAccounts = claudeAccounts.profileId === host?.id ? claudeAccounts.items : [];
  const selectedAccount = scopedAccounts.find(account => account.id === newSession.accountId);
  const editorAccount = accountEditor && scopedAccounts.find(account => account.id === accountEditor.id);
  const editingAccount = accountEditor?.profileId === host?.id ? accountEditor : null;
  const accountSessions = editingAccount ? terminalsForAccount(terminalProfiles, host.id, editingAccount.id) : [];
  const editorAccountInUse = Boolean(editorAccount?.inUse || accountSessions.length);
  const hostSessions = liveSessions(directoryFor(host?.id)?.sessions);
  const focusAccountSession = session => onFocusAccountSession(host.id, editingAccount.id, session);
  const installationLoading = claudeInstallation.profileId !== host?.id || claudeInstallation.status === 'loading';
  const opening = pending.startsWith('open:');
  const dismissAccountEditor = () => { setAccountEditor(null); if (manageOnly) setNewSession(null); };
  const cancelCreation = () => { if (opening && startingSession?.status === 'starting') void closeSession(startingSession); else if (!pending) { setNewSession(null); if (manageOnly) setAccountEditor(null); } };
  return <div className={`terminal-new-session ${manageOnly ? 'terminal-manage-account' : ''}`} role="dialog" aria-modal="false" aria-label={t(manageOnly ? '管理登录档案' : '新建终端')}>
    <div className="terminal-new-session-head"><strong>{t(manageOnly ? '管理登录档案' : '新建终端')}</strong><button className="terminal-icon-button" aria-label={t(opening && claude ? '取消安装' : '取消')} disabled={!!pending && (!startingSession || !!cancellingSessionId)} onClick={cancelCreation}><X size={14} /></button></div>
    {!manageOnly && <>
    <div className="terminal-session-kind" role="group" aria-label={t('会话类型')}><button disabled={!!pending} aria-pressed={!claude} onClick={() => setNewSession(changeSessionKind(networks, newSession, 'shell', activeProfileId))}>{t('普通终端')}</button><button disabled={!!pending} aria-pressed={claude} onClick={() => setNewSession(changeSessionKind(networks, newSession, CLAUDE_SESSION, activeProfileId))}>Claude Code</button></div>
    {claude && <p className="terminal-claude-note"><strong>{t('进入终端后运行 claude。')}</strong></p>}
    {claude && !availableNetworks.length && <div className="terminal-new-session-error">{t('先添加网络出口，并为它创建一个境舱浏览器。')}</div>}
    <label><span>{t('网络出口')}</span><select value={network?.id || ''} disabled={!!pending || !availableNetworks.length} onChange={event => { const next = availableNetworks.find(item => item.id === event.target.value); if (next) setNewSession({ ...newSession, networkId: next.id, browserId: defaultBrowser(next), error: '' }); }}>{availableNetworks.map(item => <option key={item.id} value={item.id}>{item.name || t('本机网络')}</option>)}</select>
      <small className="terminal-new-session-egress">{egress?.ip ? [egress.ip, egress.country || egress.countryCode, egress.timezone].filter(Boolean).join(' · ') : t('出口待识别')}</small></label>
    <label><span>{t('浏览器')}</span><select value={newSession.browserId || ''} disabled={!!pending || !network} onChange={event => setNewSession({ ...newSession, browserId: event.target.value, error: '' })}>{(network?.profiles ?? []).map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}{!claude && <option value={SYSTEM_BROWSER}>{`${t('系统默认浏览器')} · ${t('不经过境舱网络')}`}</option>}</select></label>
    {claude && !claudeInstallation.installed && <div className="terminal-account-field terminal-install-source">{installationLoading ? <small role="status">{t('正在检查 Claude 安装…')}</small> : claudeInstallation.status === 'error' ? <div className="terminal-account-error" role="status"><span>{t(claudeInstallation.error)}</span><button className="terminal-text-button" onClick={() => setInstallationReload(value => value + 1)}>{t('重试')}</button></div> : <label><span>{t('Claude 安装')}</span><select value={newSession.installSource || 'download'} disabled={!!pending} onChange={event => setNewSession(value => ({ ...value, installSource: event.target.value, error: '' }))}><option value="download">{t('下载（推荐）')}</option><option value="local">{t('复制本机程序')}</option></select></label>}{!installationLoading && claudeInstallation.status === 'ready' && newSession.installSource === 'local' && <small>{t('只复制程序，登录档案仍独立。')}</small>}</div>}
    </>}
    {claude && <div className="terminal-account-field">
      {!manageOnly && <>
      <label><span>{t('登录档案')}</span><select aria-label={t('登录档案')} value={newSession.accountId || 'default'} disabled={!!pending || accountLoading || claudeAccounts.status !== 'ready'} onChange={event => { setAccountEditor(null); setNewSession(value => ({ ...value, accountId: event.target.value, accountName: '', error: '' })); }}>{accountLoading ? <option value={newSession.accountId || 'default'}>{t('正在读取登录档案…')}</option> : <>{claudeAccounts.items.map(account => <option key={account.id} value={account.id}>{claudeAccountLabel(account, t)}</option>)}<option value={NEW_CLAUDE_ACCOUNT}>{t('新建登录档案…')}</option></>}</select></label>
      {newSession.accountId === NEW_CLAUDE_ACCOUNT && <><input aria-label={t('档案名称')} maxLength={80} value={newSession.accountName || ''} disabled={!!pending} onChange={event => setNewSession(value => ({ ...value, accountName: event.target.value, error: '' }))} placeholder={t('例如：工作账号')} /><button className="terminal-text-button terminal-account-manage" disabled={!!pending || !newSession.accountName?.trim()} onClick={() => void createChosenAccount()}>{t(pending.startsWith('account:') ? '正在创建档案…' : '创建档案')}</button></>}
      {selectedAccount && !editingAccount && <button className="terminal-text-button terminal-account-manage" disabled={!!pending || accountLoading} onClick={() => setAccountEditor({ profileId: host.id, id: selectedAccount.id, name: selectedAccount.name, originalName: claudeAccountLabel(selectedAccount, t), confirmDelete: false, error: '' })}>{t('管理档案')}</button>}
      </>}
      {editingAccount && <div className="terminal-account-editor" role="group" aria-label={t('管理档案')}>
        {editingAccount.cleanupPending ? <><p role="status">{t('档案已移除，剩余资料尚未清理完成。请重试清理。')}</p><div className="terminal-account-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => void mutateAccount('delete')}>{t('重试清理')}</button><button className="terminal-text-button" disabled={!!pending} onClick={dismissAccountEditor}>{t('完成')}</button></div></> : editingAccount.confirmDelete ? <>
          <strong>{t('删除「{name}」？', { name: editingAccount.originalName })}</strong><p>{t('这会删除此档案的登录信息、Claude 配置与会话历史。其他档案和共享终端配置会保留。')}</p>
          <div className="terminal-account-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => setAccountEditor(value => ({ ...value, confirmDelete: false, error: '' }))}>{t('取消')}</button><button className="terminal-text-button terminal-account-delete" disabled={!!pending || accountLoading || !editorAccount || editorAccountInUse} onClick={() => void mutateAccount('delete')}>{t('确认删除档案')}</button></div>
        </> : <><label><span>{t('档案名称')}</span><input aria-label={t('修改档案名称')} maxLength={80} value={editingAccount.name} disabled={!!pending || accountLoading || !editorAccount || editorAccountInUse} onChange={event => setAccountEditor(value => ({ ...value, name: event.target.value, error: '' }))} /></label>
          <div className="terminal-account-sessions" role="group" aria-label={t('使用此档案的终端（{count}）', { count: accountSessions.length })}>
            <strong>{t('使用此档案的终端（{count}）', { count: accountSessions.length })}</strong>
            {accountSessions.length ? <div className="terminal-account-session-list">{accountSessions.map(session => {
              const name = terminalSessionName(session, hostSessions, t);
              return <button key={session.sessionId} type="button" className="terminal-account-session" disabled={!!pending} title={`${name}\n${session.cwd || ''}`} aria-label={t('切换到终端「{name}」', { name })} onClick={() => focusAccountSession(session)}>
                <span className="terminal-account-session-name">{name}</span><small>{t(statusLabels[session.status] || session.status)}</small>
                <span className="terminal-account-session-directory" title={session.cwd}>{session.cwd}</span>
              </button>;
            })}</div> : <p>{t('暂无活动终端')}</p>}
          </div>
          {editorAccountInUse && <p>{t('请先关闭使用此登录档案的 Claude 终端，再管理档案。')}</p>}
          {editorAccount?.default && <p>{t('默认登录档案不能删除，可以重命名。')}</p>}
          <div className="terminal-account-actions"><button className="terminal-text-button terminal-account-delete" disabled={!!pending || accountLoading || !editorAccount || editorAccount.default || editorAccountInUse} onClick={() => setAccountEditor(value => ({ ...value, confirmDelete: true, error: '' }))}>{t('删除档案')}</button><button className="terminal-text-button" disabled={!!pending} onClick={dismissAccountEditor}>{t('取消')}</button><button className="terminal-text-button" disabled={!!pending || accountLoading || !editorAccount || editorAccountInUse || !editingAccount.name.trim() || editingAccount.name.trim() === editorAccount.name} onClick={() => void mutateAccount('rename')}>{t('保存名称')}</button></div>
        </>}
        {!accountLoading && claudeAccounts.status === 'ready' && !editorAccount && !editingAccount.cleanupPending && <p role="status">{t('登录档案不可用')}</p>}
        {editingAccount.error && <div className="terminal-account-error" role="status">{t(editingAccount.error)}</div>}
      </div>}
      {claudeAccounts.status === 'error' && <div className="terminal-account-error" role="status"><span>{t(claudeAccounts.error)}</span><button className="terminal-text-button" onClick={() => setAccountsReload(value => value + 1)}>{t('重试')}</button></div>}
    </div>}
    {!manageOnly && <>
    <div className="terminal-new-session-field"><span>{t('工作目录')}</span><div className="terminal-new-session-directory"><FolderOpen size={14} /><span title={folder || ''}>{folder || t('尚未选择工作目录')}</span><button className="terminal-text-button" disabled={!!pending || !host} onClick={() => void chooseNewSessionDirectory()}>{t(pending.startsWith('directory:') ? '选择中…' : folder ? '更换目录' : '选择目录')}</button></div></div>
    {claude && <details className="terminal-claude-settings"><summary>{t('会话设置')}</summary><dl>
      <div><dt>{t('登录方式')}</dt><dd>{t('账号登录；启动前检查 API 配置冲突')}</dd></div>
      <div><dt>{t('配置与历史')}</dt><dd>{t('境舱独立保存')}</dd></div>
      <div><dt>{t('网络与浏览器')}</dt><dd>{t('固定绑定；网络组件退出时结束会话')}</dd></div>
      <div><dt>{t('官方隐私设置')}</dt><dd>{t({ off: '停用', standard: '标准', strict: '严格' }[privacyMode] ?? '标准')}<small>{t({ off: '不额外关闭遥测与错误上报。', standard: '关闭遥测与错误上报。', strict: '同时关闭非必要网络请求。' }[privacyMode] ?? '关闭遥测与错误上报。')}</small>{privacyMode !== 'off' && <small className="terminal-claude-privacy-note">{t('关闭遥测可能影响 Remote Control 等功能。')}</small>}</dd></div>
    </dl><p>{t('内置浏览器工具绑定所选浏览器；支持此境舱的自定义 MCP。会话内关闭自动更新。')}</p></details>}
    </>}
    {newSession.error && <div className="terminal-new-session-error">{t(newSession.error)}{newSession.keychainDiagnostic && <code className="terminal-keychain-diagnostic">{newSession.keychainDiagnostic}</code>}</div>}
    {opening && <div className="terminal-install-progress" role="status"><div><ArrowsClockwise className="spin" size={14} /><span>{t(installation?.label || '准备中…')}</span>{installation?.percent != null && <strong>{installation.percent}%</strong>}</div>{installation?.percent != null && <progress max="100" value={installation.percent} />}</div>}
    {!manageOnly && <div className="terminal-new-session-actions"><button className="terminal-text-button" disabled={!!pending && (!startingSession || !!cancellingSessionId)} onClick={cancelCreation}>{t(cancellingSessionId ? '关闭中…' : opening && claude ? '取消安装' : '取消')}</button><button className="terminal-text-button terminal-start-button" aria-busy={!!pending || undefined} disabled={!!pending || !!editingAccount || !host || !directory.ready || (claude && (!validClaudeAccountChoice(claudeAccounts, host.id, newSession) || !validClaudeInstallationChoice(claudeInstallation, host.id, newSession.installSource)))} onClick={() => void confirmNewSession()}>{t(pending.startsWith('account:') ? '正在创建档案…' : opening ? '启动中…' : newSession.error ? '重试' : '打开终端')}</button></div>}
  </div>;
}
