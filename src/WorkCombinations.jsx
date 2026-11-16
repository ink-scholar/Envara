import React, { useEffect, useRef, useState } from 'react';
import { CaretDown, Plus, Play, Trash, Stack } from '@phosphor-icons/react';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';
import './work-combinations.css';

const errorMessages = {
  WORK_COMBINATION_INVALID: '工作组合参数无效。',
  WORK_COMBINATION_NOT_FOUND: '此工作组合已不存在。',
  WORK_COMBINATION_STORAGE_INVALID: '无法读取工作组合，原有资料已保留。',
  WORK_COMBINATION_STORAGE_FAILED: '无法保存工作组合，请重试。',
  WORK_COMBINATION_UNSAFE_PATH: '工作组合存储路径不安全。',
  WORK_COMBINATION_LIMIT: '工作组合数量或终端数量已达上限。',
  WORK_COMBINATION_CONTEXT_CHANGED: '组合中的终端或浏览器配置已改变，请重新保存组合。',
  WORK_COMBINATION_ENTRY_UNAVAILABLE: '组合中的终端、目录或登录档案已不可用。',
  WORK_COMBINATION_PROFILE_UNAVAILABLE: '此环境已不可用。',
  WORK_COMBINATION_OPEN_FAILED: '工作组合未能全部打开。已打开的会话会保留，请先检查现有会话。',
  WORK_COMBINATION_BUSY: '工作组合正在处理中，请稍后重试。',
};
const errorText = error => errorMessages[error?.code] || '无法完成工作组合操作，请重试。';
const blank = () => ({ name: '', entryIds: [], includeBrowser: false });

export function WorkCombinations({ profileId, savedTerminals = [], onOpened }) {
  const { t } = useI18n();
  const [combinations, setCombinations] = useState([]), [draft, setDraft] = useState(null);
  const [pending, setPending] = useState(''), [error, setError] = useState(''), [result, setResult] = useState(null);
  const [deleting, setDeleting] = useState(null), [reload, setReload] = useState(0), [loading, setLoading] = useState(true);
  const scopeRef = useRef({ id: profileId }), operationRef = useRef(null), requestIds = useRef(new Map());
  const mounted = useRef(false);
  if (scopeRef.current.id !== profileId) scopeRef.current = { id: profileId };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    const scope = scopeRef.current; let cancelled = false;
    setCombinations([]); setDraft(null); setDeleting(null); setResult(null); setError(''); setPending(''); setLoading(true);
    if (!profileId || !api.isDesktop) { setLoading(false); return; }
    api.call('listWorkCombinations', { id: profileId }).then(value => {
      if (cancelled || !mounted.current || scopeRef.current !== scope) return;
      if (!Array.isArray(value?.combinations)) throw new Error();
      setCombinations(value.combinations);
    }).catch(reason => { if (!cancelled && mounted.current && scopeRef.current === scope) setError(errorText(reason)); })
      .finally(() => { if (!cancelled && mounted.current && scopeRef.current === scope) setLoading(false); });
    return () => { cancelled = true; };
  }, [profileId, reload]);
  const operate = async (key, action) => {
    const scope = scopeRef.current;
    if (!profileId || operationRef.current?.scope === scope) return;
    const operation = { scope }; operationRef.current = operation;
    setPending(key); setError(''); setResult(null);
    const current = () => mounted.current && scopeRef.current === scope;
    try { await action(current); }
    catch (reason) { if (current()) setError(errorText(reason)); }
    finally {
      if (operationRef.current === operation) operationRef.current = null;
      if (current()) setPending('');
    }
  };
  const save = event => {
    event.preventDefault();
    if (!draft?.name.trim() || !draft.entryIds.length) return;
    void operate('save', async current => {
      const value = await api.call('saveWorkCombination', { id: profileId, name: draft.name.trim(), entryIds: [...draft.entryIds], includeBrowser: draft.includeBrowser });
      if (current()) { setCombinations(items => [...items, value.combination]); setDraft(null); }
    });
  };
  const open = combination => void operate(`open:${combination.id}`, async current => {
    const key = `${profileId}:${combination.id}`;
    let requestId = requestIds.current.get(key);
    if (!requestId) {
      requestId = crypto.randomUUID();
      if (requestIds.current.size >= 128) requestIds.current.delete(requestIds.current.keys().next().value);
      requestIds.current.set(key, requestId);
    }
    const value = await api.call('openWorkCombination', { id: profileId, combinationId: combination.id, requestId });
    if (!value || !['opened', 'partial', 'failed'].includes(value.status) || !Array.isArray(value.sessions)) throw new Error();
    requestIds.current.delete(key);
    if (current()) {
      setResult(value);
      if (value.error) setError(errorText(value.error));
      if (value.sessions.length || value.browserOpened) onOpened?.(value);
    }
  });
  const remove = combination => void operate(`delete:${combination.id}`, async current => {
    await api.call('deleteWorkCombination', { id: profileId, combinationId: combination.id });
    if (current()) { setCombinations(items => items.filter(item => item.id !== combination.id)); setDeleting(null); }
  });
  const toggleEntry = entryId => setDraft(value => ({ ...value, entryIds: value.entryIds.includes(entryId)
    ? value.entryIds.filter(id => id !== entryId) : [...value.entryIds, entryId] }));
  if (!profileId) return null;
  return <details className="work-combinations">
    <summary><Stack size={17} /><span>{t('工作组合')}</span><small>{combinations.length}</small><CaretDown size={15} /></summary>
    <div className="work-combinations-body">
      <p>{t('一起打开常用终端，可带上此环境的浏览器。')}</p>
      {error && <div className="work-combinations-error" role="alert">{t(error)}{!combinations.length && !pending && <button type="button" className="terminal-text-button" onClick={() => setReload(value => value + 1)}>{t('重试')}</button>}</div>}
      {result && <p role="status">{t(result.status === 'opened' ? '已打开 {count} 个终端。' : result.status === 'partial' ? '已保留 {count} 个已打开终端，请检查后再操作。' : '此次未完成工作组合。', { count: result.sessions.length })}</p>}
      {loading ? <p role="status">{t('正在读取工作组合…')}</p> : !combinations.length && <p>{t('还没有工作组合。')}</p>}
      <div className="work-combination-list">{combinations.map(combination => <div className="work-combination-row" key={combination.id}>
        <div className="work-combination-description"><strong title={combination.name}>{combination.name}</strong><small>{t('{count} 个终端', { count: combination.entryIds.length })}{combination.includeBrowser && ` · ${t('包含环境浏览器')}`}</small></div>
        {deleting === combination.id ? <div className="work-combination-actions"><span>{t('仅删除组合，终端与登录资料会保留。')}</span><button type="button" className="terminal-text-button" disabled={!!pending} onClick={() => setDeleting(null)}>{t('取消')}</button><button type="button" className="terminal-text-button" disabled={!!pending} onClick={() => remove(combination)}>{t('确认删除组合')}</button></div>
          : <div className="work-combination-actions"><button type="button" className="terminal-text-button" disabled={!!pending || loading} onClick={() => open(combination)} aria-label={t('打开组合「{name}」', { name: combination.name })}><Play size={14} />{t(pending === `open:${combination.id}` ? '打开中…' : '打开')}</button><button type="button" className="terminal-icon-button" disabled={!!pending} onClick={() => setDeleting(combination.id)} aria-label={t('删除组合「{name}」', { name: combination.name })}><Trash size={15} /></button></div>}
      </div>)}</div>
      {!draft ? <button type="button" className="terminal-text-button" disabled={!api.isDesktop || !!pending || loading || !savedTerminals.length} onClick={() => { setDraft(blank()); setDeleting(null); }}><Plus size={14} />{t('保存工作组合')}</button>
        : <form className="work-combination-form" onSubmit={save}>
          <label>{t('组合名称')}<input aria-label={t('组合名称')} maxLength={80} value={draft.name} disabled={!!pending} onChange={event => setDraft(value => ({ ...value, name: event.target.value }))} /></label>
          <fieldset disabled={!!pending}><legend>{t('选择已保存终端（最多 8 个）')}</legend><div className="work-combination-choices">{savedTerminals.map(entry => <label key={entry.id}>
            <input type="checkbox" checked={draft.entryIds.includes(entry.id)} disabled={!!entry.unavailableReason || draft.entryIds.length >= 8 && !draft.entryIds.includes(entry.id)} onChange={() => toggleEntry(entry.id)} />
            <span><strong>{entry.name}</strong><small>{[entry.claudeAccountName, entry.cwd].filter(Boolean).join(' · ')}</small></span>
          </label>)}</div></fieldset>
          <label className="work-combination-browser"><input type="checkbox" checked={draft.includeBrowser} disabled={!!pending} onChange={event => setDraft(value => ({ ...value, includeBrowser: event.target.checked }))} />{t('同时打开此环境浏览器')}</label>
          <p>{t('每次打开都新建空闲终端，不恢复运行中的命令。')}</p>
          <div className="work-combination-actions"><button type="button" className="terminal-text-button" disabled={!!pending} onClick={() => setDraft(null)}>{t('取消')}</button><button type="submit" className="terminal-text-button" disabled={!!pending || !draft.name.trim() || !draft.entryIds.length}>{t(pending === 'save' ? '保存中…' : '保存组合')}</button></div>
        </form>}
    </div>
  </details>;
}
