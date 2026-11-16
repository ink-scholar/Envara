import React, { useId } from 'react';
import { ArrowsClockwise, DownloadSimple } from '@phosphor-icons/react';
import { useI18n } from './i18n.jsx';

export function SupportDiagnostics({ onExport, pending = false, disabled = false }) {
  const { t } = useI18n();
  const descriptionId = useId();
  const Icon = pending ? ArrowsClockwise : DownloadSimple;
  return <div className="settings-row support-diagnostics">
    <div><span id={descriptionId}>{t('脱敏记录，保存到本机。')}</span></div>
    <button type="button" className="button" disabled={pending || disabled || typeof onExport !== 'function'}
      aria-busy={pending || undefined} aria-describedby={descriptionId} onClick={() => onExport()}>
      <Icon size={17} className={pending ? 'spin' : undefined} aria-hidden="true" />
      {t(pending ? '处理中…' : '导出支持诊断')}
    </button>
  </div>;
}
