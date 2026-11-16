import React from 'react';
import { SlidersHorizontal, FolderOpen, Browsers, DownloadSimple } from '@phosphor-icons/react';
import { TerminalToolbarHint } from './TerminalToolbarHint.jsx';
import { TerminalDeviceIdentifierDetails } from './terminal-device-identifiers.mjs';
import { terminalTimezonePresentation } from './network-flow-state.mjs';
import { terminalAccountName } from './terminal-account-context.mjs';
import { CLAUDE_SESSION } from './terminal-session-choice.mjs';

const timezoneSources = { proxy: '代理出口检测', 'proxy-egress': '代理出口检测', 'saved-configuration': '已保存配置', direct: '直连出口检测', manual: '手动设置', local: '本机时区回退', unknown: '来源未确认' };

export function TerminalSessionContext({ t, shown, contextOpen, selectedSession, selectedProfile, selectedMetadata,
  activeProfileId, hasLiveSession, networkDescription, pending, manageCurrentAccount,
  onConfigureLinkBrowser, onExport, exportDisabled, onToggle, onDismiss }) {
  const sessionDirectory = selectedSession?.cwd || selectedMetadata?.cwd || null;
  const { timezone, source: timezoneSource } = terminalTimezonePresentation({ profile: selectedProfile, metadata: selectedMetadata, session: selectedSession, hasLiveSession });
  const timezoneLabel = timezone ? `${timezone} · ${t(timezoneSources[timezoneSource] || '来源未确认')}` : t('时区待确认');
  const sessionLanguage = selectedSession?.language ?? selectedMetadata?.language;
  const languageLabel = sessionLanguage?.effective
    ? sessionLanguage.fallback
      ? t('{requested} → {effective}（系统未提供所选语言）', { requested: sessionLanguage.requested, effective: sessionLanguage.effective })
      : `${t('有效语言')} · ${sessionLanguage.effective}`
    : '';
  return <details className="terminal-context-menu" open={contextOpen}>
    <TerminalToolbarHint enabled={shown} label={t('会话设置')} description={t('查看工作目录、网络和会话选项。')}><summary aria-label={t('会话设置')} title={t('会话设置')} onClick={onToggle}><SlidersHorizontal size={17} /></summary></TerminalToolbarHint>
    <div className="terminal-context-panel">
      <div className="terminal-menu-heading"><strong>{t('会话设置')}</strong></div>
      <dl className="terminal-context-values">
        <div><dt>{t('工作目录')}</dt><dd className="terminal-directory"><FolderOpen size={14} /><span title={sessionDirectory || t('尚未选择工作目录')}>{sessionDirectory || t('尚未选择工作目录')}</span></dd></div>
        <div><dt>{t('网络出口')}</dt><dd>{networkDescription}</dd></div>
        <div><dt>{t('时区')}</dt><dd className={timezoneSource === 'local' ? 'is-fallback' : ''}>{timezoneLabel}</dd></div>
        {languageLabel && <div><dt>{t('有效语言')}</dt><dd className={sessionLanguage.fallback ? 'is-fallback' : ''}>{languageLabel}</dd></div>}
        {selectedSession?.kind === CLAUDE_SESSION && <>
          <div><dt>{t('登录档案')}</dt><dd className="terminal-context-account" title={terminalAccountName(selectedSession, t)}>{terminalAccountName(selectedSession, t)}</dd></div>
          <div><dt>{t('浏览器')}</dt><dd>{selectedSession.browserName || selectedSession.browserProfileId}</dd></div>
        </>}
      </dl>
      <TerminalDeviceIdentifierDetails session={selectedSession} t={t} inline />
      <p className="terminal-attachment-hint">{t('图片或文件可粘贴、拖入；仅插入本地路径，不会执行。')}</p>
      <div className="terminal-context-actions">
        {selectedSession?.kind === CLAUDE_SESSION && <button type="button" className="terminal-text-button" disabled={!selectedSession.claudeAccountId || !!pending} onClick={manageCurrentAccount}>{t('管理登录档案')}</button>}
        {onConfigureLinkBrowser && <button className="terminal-text-button" disabled={!selectedProfile || !!pending} onClick={() => { onDismiss(); onConfigureLinkBrowser(activeProfileId); }}><Browsers size={14} />{t('链接浏览器')}</button>}
        {onExport && <button className="terminal-text-button" disabled={!selectedProfile || exportDisabled || !!pending} onClick={() => { onDismiss(); onExport(activeProfileId); }}><DownloadSimple size={14} />{t('导出终端')}</button>}
      </div>
    </div>
  </details>;
}
