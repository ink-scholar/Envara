import React from 'react';
import { BookmarksSimple, MagnifyingGlass, FolderOpen, PushPin, PushPinSlash, ArrowUp, ArrowDown, PencilSimple, Trash } from '@phosphor-icons/react';
import { TerminalToolbarHint } from './TerminalToolbarHint.jsx';
import { CLAUDE_SESSION } from './terminal-session-choice.mjs';
import { claudeAccountLabel } from './claude-account-choice.mjs';
import { activeStatuses, statusLabels } from './terminal-session-status.mjs';

// The dock owns mutations and per-environment query/editor state, including
// keyboard focus restoration after its frame-batched snapshot publication.
export function TerminalSavedMenu({ t, shown, savedMenuOpen, savedEntries, savedQuery, entryEditor,
  activeProfileId, desktopAvailable, pending, setSavedEntryEditor, actOnSavedEntry, onQueryChange, onToggle }) {
  const queryTerms = savedQuery.normalize('NFKC').trim().toLocaleLowerCase().split(/\s+/).filter(Boolean);
  const matchingSavedEntries = savedEntries.filter(entry => {
    const accountName = entry.kind === CLAUDE_SESSION ? claudeAccountLabel({ default: entry.claudeAccountId === 'default', name: entry.claudeAccountName || t('登录档案不可用') }, t) : t('普通终端');
    const text = [entry.name, entry.cwd, accountName].join('\n').normalize('NFKC').toLocaleLowerCase();
    return queryTerms.every(term => text.includes(term));
  });
  return <details className="terminal-saved-terminals" open={savedMenuOpen}>
    <TerminalToolbarHint enabled={shown} label={t('已保存终端')} description={t('新建后自动保存终端入口，可在此重开或重命名。')}><summary aria-label={t('已保存终端')} title={t('已保存终端')} onClick={onToggle}><BookmarksSimple size={17} /></summary></TerminalToolbarHint>
    <div className="terminal-saved-panel"><div className="terminal-menu-heading"><strong>{t('已保存终端')}</strong><small>{queryTerms.length ? `${matchingSavedEntries.length} / ${savedEntries.length}` : savedEntries.length}</small></div>
    <p className="terminal-saved-note">{t('新建后自动保存终端入口，可在此重开或重命名。')}</p>
    <label className="terminal-saved-search"><MagnifyingGlass size={14} /><input type="search" value={savedQuery} aria-label={t('搜索已保存终端')} placeholder={t('搜索名称、目录或登录档案')} onChange={event => onQueryChange(event.target.value)} /></label>
    <div className="terminal-saved-list">
      {!savedEntries.length && <p className="terminal-saved-empty">{t('新建会话后会自动保存在这里。')}</p>}
      {!!savedEntries.length && !matchingSavedEntries.length && <p className="terminal-saved-empty" role="status">{t('没有匹配的终端。')}</p>}
      {matchingSavedEntries.map(entry => {
        const editor = entryEditor?.entryId === entry.id ? entryEditor : null;
        const group = savedEntries.filter(item => (item.pinned === true) === (entry.pinned === true));
        const position = group.findIndex(item => item.id === entry.id);
        const accountName = entry.kind === CLAUDE_SESSION ? entry.claudeAccountName || t('登录档案不可用') : null;
        const accountLabel = accountName && claudeAccountLabel({ default: entry.claudeAccountId === 'default', name: accountName }, t);
        const busy = entry.status === 'starting' || entry.status === 'closing';
        return <div className="terminal-saved-entry" data-entry-id={entry.id} key={entry.id}>
          <div className="terminal-saved-row">
            <button className="terminal-saved-open" disabled={!desktopAvailable || !!pending || busy} aria-label={t('打开终端「{name}」', { name: entry.name })} title={entry.name} onClick={() => void actOnSavedEntry(entry, 'open')}>
              <span className="terminal-saved-heading">{entry.pinned && <PushPin className="terminal-saved-pin-mark" size={12} aria-label={t('已置顶')} />}<strong>{entry.name}</strong>{activeStatuses.has(entry.status) && <small><span className={`terminal-tab-dot ${entry.status === 'running' ? 'is-running' : ''}`} />{t(statusLabels[entry.status])}</small>}</span>
              <span className="terminal-saved-context"><span className="terminal-saved-account" title={accountLabel || t('普通终端')}>{entry.kind === CLAUDE_SESSION ? `Claude Code · ${accountLabel}` : t('普通终端')}</span><span className="terminal-saved-directory" title={entry.cwd}><FolderOpen size={12} /><span>{entry.cwd}</span></span></span>
            </button>
            <div className="terminal-saved-actions">
              <button type="button" className="terminal-icon-button" data-saved-entry-action="pin" disabled={!desktopAvailable || !!pending} aria-label={t(entry.pinned ? '取消置顶终端「{name}」' : '置顶终端「{name}」', { name: entry.name })} title={t(entry.pinned ? '取消置顶终端「{name}」' : '置顶终端「{name}」', { name: entry.name })} onClick={() => void actOnSavedEntry(entry, 'pin')}>{entry.pinned ? <PushPinSlash size={14} /> : <PushPin size={14} />}</button>
              <button type="button" className="terminal-icon-button" data-saved-entry-action="up" disabled={!desktopAvailable || !!pending || !!queryTerms.length || position === 0} aria-label={t('上移终端「{name}」', { name: entry.name })} title={queryTerms.length ? t('清除搜索后调整顺序') : t('上移终端「{name}」', { name: entry.name })} onClick={() => void actOnSavedEntry(entry, 'up')}><ArrowUp size={14} /></button>
              <button type="button" className="terminal-icon-button" data-saved-entry-action="down" disabled={!desktopAvailable || !!pending || !!queryTerms.length || position === group.length - 1} aria-label={t('下移终端「{name}」', { name: entry.name })} title={queryTerms.length ? t('清除搜索后调整顺序') : t('下移终端「{name}」', { name: entry.name })} onClick={() => void actOnSavedEntry(entry, 'down')}><ArrowDown size={14} /></button>
              <button className="terminal-icon-button terminal-saved-rename" disabled={!desktopAvailable || !!pending} aria-label={t('重命名终端「{name}」', { name: entry.name })} title={t('重命名终端「{name}」', { name: entry.name })} onClick={() => setSavedEntryEditor({ profileId: activeProfileId, entryId: entry.id, mode: 'rename', name: entry.name })}><PencilSimple size={14} /></button>
              <button className="terminal-icon-button terminal-saved-remove" disabled={!desktopAvailable || !!pending} aria-label={t('移除终端入口「{name}」', { name: entry.name })} title={t('移除终端入口「{name}」', { name: entry.name })} onClick={() => setSavedEntryEditor({ profileId: activeProfileId, entryId: entry.id, mode: 'remove' })}><Trash size={14} /></button>
            </div>
          </div>
          {editor?.mode === 'rename' && <form className="terminal-saved-editor" onSubmit={event => { event.preventDefault(); if (editor.name.trim()) void actOnSavedEntry(entry, 'rename', editor.name); }}>
            <label>{t('终端名称')}<input autoFocus value={editor.name} maxLength={80} disabled={!!pending} onChange={event => setSavedEntryEditor({ ...editor, name: event.target.value })} onKeyDown={event => { if (event.key === 'Escape' && !pending) { event.preventDefault(); setSavedEntryEditor(null); } }} /></label>
            <div className="terminal-saved-editor-actions"><button type="button" className="terminal-text-button" disabled={!!pending} onClick={() => setSavedEntryEditor(null)}>{t('取消')}</button><button type="submit" className="terminal-text-button" disabled={!!pending || !editor.name.trim()}>{t('保存')}</button></div>
          </form>}
          {editor?.mode === 'remove' && <div className="terminal-saved-editor"><p>{t('仅移除此入口，登录资料和终端数据会保留。')}</p><div className="terminal-saved-editor-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => setSavedEntryEditor(null)}>{t('取消')}</button><button className="terminal-text-button terminal-saved-remove" disabled={!!pending} onClick={() => void actOnSavedEntry(entry, 'remove')}>{t('移除入口')}</button></div></div>}
        </div>;
      })}
    </div></div>
  </details>;
}
