import React, { useId, useState } from 'react';
import { ArrowsClockwise, ArrowCounterClockwise, Archive, Trash } from '@phosphor-icons/react';
import { useI18n } from './i18n.jsx';
import './cache-maintenance.css';

const statusLabels = { busy: '使用中或状态未确认', unsafe: '目录检查未通过', unavailable: '维护边界尚不可用' };
function size(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

/** Controlled main-process inventory: callbacks receive IDs only, never paths.
 * The parent owns IPC, operation errors and refreshing after every mutation.
 */
export function CacheMaintenance({ inventory = null, pending = false, onRefresh, onQuarantine, onRestore, onPurge }) {
  const { t, language } = useI18n();
  const labelId = useId(), [selection, setSelection] = useState({ inventoryId: null, ids: [] }), [confirmBatch, setConfirmBatch] = useState(null);
  const entries = inventory?.entries ?? [], batches = inventory?.batches ?? [];
  const selected = selection.inventoryId === inventory?.inventoryId ? selection.ids.filter(id => entries.some(item => item.id === id && item.status === 'ready')) : [];
  const choose = (id, checked) => setSelection({ inventoryId: inventory.inventoryId, ids: checked ? [...new Set([...selected, id])] : selected.filter(item => item !== id) });
  const batchDate = value => {
    const date = new Date(value);
    return value && Number.isFinite(date.getTime()) ? date.toLocaleString(language) : t('日期未知');
  };
  return <details className="cache-maintenance">
    <summary>{t('缓存维护')}</summary>
    <div className="cache-maintenance-content" aria-busy={pending || undefined}>
      <p id={labelId}>{t('仅处理浏览器可重建的缓存；登录信息、历史记录和离线内容会保留。')}</p>
      <div className="cache-maintenance-actions">
        <button type="button" className="button" disabled={pending || !onRefresh} onClick={() => onRefresh()}><ArrowsClockwise size={16} aria-hidden="true" />{t(pending ? '处理中…' : '检查缓存')}</button>
        <button type="button" className="button" aria-describedby={labelId} disabled={pending || !inventory?.maintenanceAvailable || !onQuarantine || !selected.length} onClick={() => onQuarantine({ inventoryId: inventory.inventoryId, entryIds: selected })}>
          <Archive size={16} aria-hidden="true" />{t('移入恢复批次')}{selected.length > 0 && <span>({selected.length})</span>}
        </button>
      </div>
      {inventory && <>
        {!inventory.maintenanceAvailable && <p role="status">{t('维护边界尚不可用')}</p>}
        {!entries.length ? <p className="cache-maintenance-empty">{t('没有可清理的已知缓存。')}</p> : <ul className="cache-maintenance-list" aria-label={t('可重建缓存')}>
          {entries.map(item => <li key={item.id}>
            <label className="cache-maintenance-choice"><input type="checkbox" checked={selected.includes(item.id)} disabled={pending || !inventory.maintenanceAvailable || item.status !== 'ready'} onChange={event => choose(item.id, event.target.checked)} />
              <span><strong>{item.profileName}</strong><span>{item.cacheName}</span></span>
            </label>
            <span className="cache-maintenance-size">{size(item.bytes)}</span>
            {item.status !== 'ready' && <span className="cache-maintenance-state">{t(statusLabels[item.status] ?? '目录检查未通过')}</span>}
          </li>)}
        </ul>}
        <div className="cache-maintenance-recovery"><h4>{t('恢复批次')}</h4><p>{t('恢复批次仍占用磁盘。永久删除后无法恢复。')}</p>
          {!batches.length ? <p className="cache-maintenance-empty">{t('没有恢复批次。')}</p> : <ul className="cache-maintenance-list">
            {batches.map(batch => <li className="cache-maintenance-batch" key={batch.id}>
              <div className="cache-maintenance-batch-heading"><span>{batchDate(batch.createdAt)}</span><span className="cache-maintenance-size">{size(batch.bytes)}</span>
                {batch.status === 'ready' && <span>{t('{count} 项缓存', { count: batch.entryCount })}</span>}
              </div>
              {batch.status !== 'ready' ? <p>{t('目录检查未通过')}</p> : <>
                <div className="cache-maintenance-actions">
                  <button type="button" className="button" disabled={pending || !onRestore || !inventory.maintenanceAvailable || !batch.entryCount} onClick={() => onRestore({ batchId: batch.id })}><ArrowCounterClockwise size={16} aria-hidden="true" />{t('恢复缓存')}</button>
                  <button type="button" className="button" disabled={pending || !onPurge || inventory.purgeAvailable === false} onClick={() => setConfirmBatch(batch.id)}><Trash size={16} aria-hidden="true" />{t('永久删除')}</button>
                </div>
                {confirmBatch === batch.id && <div className="cache-maintenance-confirm" role="group" aria-label={t('确认永久删除这一批缓存？')}>
                  <p>{t('确认永久删除这一批缓存？')}</p><p>{t('此操作无法撤销，仅删除这一批已移出的缓存。')}</p>
                  <div className="cache-maintenance-actions"><button type="button" className="button" disabled={pending} onClick={() => setConfirmBatch(null)}>{t('取消')}</button>
                    <button type="button" className="button danger" disabled={pending || !onPurge || inventory.purgeAvailable === false} onClick={() => { setConfirmBatch(null); onPurge({ batchId: batch.id, confirmed: true }); }}>{t('确认永久删除')}</button></div>
                </div>}
              </>}
            </li>)}
          </ul>}
          <p>{t('恢复时若已有新缓存，将保留新缓存与恢复批次，不会覆盖。')}</p>
        </div>
      </>}
    </div>
  </details>;
}
