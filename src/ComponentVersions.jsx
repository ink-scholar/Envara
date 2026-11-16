import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowsClockwise, CaretDown, Package, WarningCircle } from '@phosphor-icons/react';
import { useI18n } from './i18n.jsx';
import './component-versions.css';

const statusLabels = { running: '运行中', installed: '已安装', missing: '未安装', ready: '已就绪', updating: '正在更新',
  unavailable: '不可用', 'needs-attention': '需要检查', unknown: '未知' };
const sourceLabels = { 'running-app': '来自当前应用', 'installation-record': '来自安装记录', 'bundled-package': '随应用提供的版本',
  'installation-report': '来自组件检查', 'validated-installation-entry': '来自已验证的安装入口', unknown: '版本来源未知' };
const impactLabels = {
  application: '更新应用需要重启；请先保存并结束运行任务。',
  browser: '安装或更新内核会重启浏览器服务；请先结束运行会话。',
  bundled: '代理核心随完整应用更新；当前运行版本未单独观测。',
  routing: '使用现有组件安装流程；系统授权与兼容检查仍会执行。',
  claude: '在此环境终端手动运行 claude update；下次调用生效，当前进程不变。',
};
const kindLabels = { browser: '浏览器', terminal: '终端', application: '附加软件' };

/** load is a read-only main-process request; all mutations remain explicit callbacks. */
export function ComponentVersions({ load, onInstallEngine, onSetupRouting, onOpenTerminal, onOpenProject, onOpenUpdates, refreshKey = 0 }) {
  const { t, language } = useI18n();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [pending, setPending] = useState('');
  const request = useRef(0), mounted = useRef(false), loadRef = useRef(load), actionPending = useRef(false);
  loadRef.current = load;
  const refresh = useCallback(async () => {
    const generation = ++request.current;
    setLoading(true); setError('');
    try {
      const result = await loadRef.current?.();
      if (result?.schema !== 'envara.component-versions' || result.version !== 1 || !Array.isArray(result.rows)) throw new Error('invalid snapshot');
      if (mounted.current && generation === request.current) setData(result);
    } catch {
      if (mounted.current && generation === request.current) setError('无法读取组件状态，请重试。');
    } finally { if (mounted.current && generation === request.current) setLoading(false); }
  }, []);
  useEffect(() => {
    mounted.current = true; void refresh();
    return () => { mounted.current = false; request.current++; };
  }, [refresh, refreshKey]);
  const act = async (row, callback) => {
    if (!callback || row.blocked || actionPending.current) return;
    actionPending.current = true; setPending(row.id); setError('');
    try {
      const result = await callback();
      if (result?.ok === false) throw new Error('action failed');
      if (mounted.current) await refresh();
    } catch { if (mounted.current) setError('组件操作未完成，请检查提示后重试。'); }
    finally { actionPending.current = false; if (mounted.current) setPending(''); }
  };
  const action = row => {
    const callbacks = { 'install-engine': onInstallEngine && (() => onInstallEngine(row.id)), routing: onSetupRouting,
      terminal: onOpenTerminal && (() => onOpenTerminal(row.profileId)), project: row.impact === 'bundled' ? onOpenUpdates : onOpenProject,
      'application-update': onOpenUpdates };
    const callback = callbacks[row.action];
    if (!callback) return null;
    const label = row.action === 'install-engine' ? row.status === 'missing' ? '安装内核' : '手动更新内核'
      : row.action === 'routing' ? '安装或更新组件' : row.action === 'terminal' ? '打开终端'
      : row.action === 'application-update' || row.impact === 'bundled' ? '应用更新' : '项目主页';
    return <button type="button" className="button component-action" disabled={row.blocked || !!pending || loading}
      aria-busy={pending === row.id || undefined} onClick={() => void act(row, callback)}>{t(label)}</button>;
  };
  const time = data?.checkedAt && Number.isFinite(Date.parse(data.checkedAt))
    ? new Intl.DateTimeFormat(language, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(data.checkedAt)) : null;
  return <section className="component-versions" aria-label={t('组件版本')}>
    <div className="section-heading component-versions-heading"><h2>{t('组件版本')}</h2>
      <button type="button" className="button" onClick={() => void refresh()} disabled={loading || !!pending} aria-busy={loading || undefined}
        title={time ? t('读取时间：{time}', { time }) : undefined}>
        <ArrowsClockwise size={15} className={loading ? 'spin' : ''} aria-hidden="true" />{t('刷新')}</button></div>
    {error && <p className="component-versions-error" role="alert"><WarningCircle size={16} aria-hidden="true" />{t(error)}</p>}
    {!data && loading && <p role="status">{t('正在读取组件状态…')}</p>}
    {data && <div className="component-version-list">{data.rows.map(row => <details key={row.id} className="component-version-card">
      <summary><Package size={17} aria-hidden="true" /><span className="component-name"><strong>{row.kind === 'routing' ? t('应用网络组件') : row.name}</strong>
        <small>{row.profileName || (row.kind === 'proxy' ? t('内置代理核心') : row.kind === 'routing' ? row.name : '')}</small></span>
        <span className="component-version-value">{row.version || t('未知')}</span>
        <span className={`component-status ${row.status}`}>{t(statusLabels[row.status] || '未知')}</span><CaretDown size={15} aria-hidden="true" /></summary>
      <div className="component-version-detail">
        <dl className="component-version-fields">
          <div><dt>{t('版本来源')}</dt><dd>{t(sourceLabels[row.versionSource] || '版本来源未知')}</dd></div>
          <div><dt>{t('运行中版本')}</dt><dd>{row.runningVersion || t('未观测')}</dd></div>
          <div><dt>{t('平台支持')}</dt><dd>{t(row.support === 'supported' ? '平台声明支持' : row.support === 'unsupported' ? '平台不支持' : '未确认')}</dd></div>
          {row.bundledVersion && <div><dt>{t('随应用提供的版本')}</dt><dd>{row.bundledVersion}</dd></div>}
        </dl>
        <p className="component-impact">{t(impactLabels[row.impact])}</p>
        <div className="component-session-impact"><strong>{t('关联运行会话（{count}）', { count: row.sessions.length })}</strong>
          {!row.sessionsKnown && <p>{t('部分运行状态未知，请先确认任务已结束。')}</p>}
          {!!row.sessions.length && <ul>{row.sessions.map(session => <li key={`${session.kind}:${session.id}`}>
            <span>{session.name || t(kindLabels[session.kind])}</span><small>{t(kindLabels[session.kind])}{session.profileName ? ` · ${session.profileName}` : ''}</small>
          </li>)}</ul>}
          {row.sessionsKnown && !row.sessions.length && <p>{t('本次未发现关联运行会话。')}</p>}
        </div>
        <div className="component-version-actions">{action(row)}</div>
      </div>
    </details>)}</div>}
  </section>;
}
