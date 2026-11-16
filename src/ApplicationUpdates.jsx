import React, { useEffect, useId, useRef, useState } from 'react';
import { ArrowsClockwise, DownloadSimple, ArrowClockwise, WarningCircle } from '@phosphor-icons/react';
import { useI18n } from './i18n.jsx';
import './application-updates.css';

const statuses = new Set(['idle', 'checking', 'current', 'available', 'downloading', 'verifying', 'ready', 'installing', 'error', 'unsupported']);
const busyStates = new Set(['checking', 'downloading', 'verifying', 'installing']);
const errorMessages = {
  APPLICATION_UPDATE_BUSY: '请先保存并结束运行任务，再重试安装。',
  APP_UPDATE_BUSY: '请先保存并结束运行任务，再重试安装。',
  APP_UPDATE_APP_RUNNING: '请先保存并结束运行任务，再重试安装。',
  APP_UPDATE_LOCATION: '当前位置无法更新。请将境舱移到有写入权限的“应用程序”目录后重试。',
  APP_UPDATE_SYSTEM_UNSUPPORTED: '当前 macOS 版本不满足新版要求，未安装更新。',
  APP_UPDATE_UNSUPPORTED_PLATFORM: '此平台暂不支持应用内更新。',
  APP_UPDATE_DEVELOPMENT: '开发版本不执行应用替换，请使用完整安装包。',
  APP_UPDATE_HASH_MISMATCH: '更新包校验未通过，请重新下载。',
  APP_UPDATE_ASSET_UNAVAILABLE: '此版本尚无适合当前平台的更新包。',
  APP_UPDATE_NETWORK: '无法连接更新服务，请稍后重试。',
  APP_UPDATE_TIMEOUT: '更新请求超时，请稍后重试。',
  APP_UPDATE_CLEANUP: '请先保存并结束运行任务，再重试安装。',
  APP_UPDATE_INSTALL_FAILED: '安装未完成；现有环境和登录资料已保留。',
};
const phaseMessages = {
  checking: '正在检查更新…', current: '当前已是最新版本。', downloading: '正在下载更新…', verifying: '正在验证更新包…',
  ready: '更新已下载并验证，可以安装。', installing: '正在安装；完成后应用会重新启动。', unsupported: '此安装方式暂不支持应用内更新。',
};
function checkedState(value) {
  if (!value || !statuses.has(value.status)) throw new Error('Invalid application update snapshot');
  const version = input => typeof input === 'string' && input.length <= 128 && !/[\x00-\x1f\x7f]/.test(input) ? input : null;
  const percent = value.progress?.percent;
  const lastResult = ['installed', 'failed', 'pending'].includes(value.lastResult?.status)
    ? { status: value.lastResult.status, version: version(value.lastResult.version) } : null;
  return { status: value.status, currentVersion: version(value.currentVersion), latestVersion: version(value.latestVersion),
    progress: typeof percent === 'number' && Number.isFinite(percent) ? Math.max(0, Math.min(100, Math.floor(percent))) : null,
    error: typeof value.error === 'string' ? value.error : null, canInstall: value.canInstall === true, restartRequired: value.restartRequired === true, lastResult };
}

/** Initial/poll requests inspect local updater state. Network access and restart
 * always originate from explicit actions; no install result is assumed. */
export function ApplicationUpdates({ call }) {
  const { t } = useI18n();
  const titleId = useId();
  const [state, setState] = useState(null), [loading, setLoading] = useState(true), [action, setAction] = useState('');
  const [readError, setReadError] = useState(false), [confirmation, setConfirmation] = useState(false);
  const mounted = useRef(false), generation = useRef(0), readSequence = useRef(0), callRef = useRef(call), actionRef = useRef(''), stateRef = useRef(null);
  callRef.current = call;
  const apply = value => { const checked = checkedState(value); stateRef.current = checked; setState(checked); setReadError(false); };
  const read = async () => {
    const epoch = generation.current, request = ++readSequence.current;
    try {
      const value = await callRef.current('applicationUpdateStatus', {});
      if (mounted.current && epoch === generation.current && request === readSequence.current) apply(value);
    } catch { if (mounted.current && epoch === generation.current && request === readSequence.current) setReadError(true); }
    finally { if (mounted.current && epoch === generation.current && request === readSequence.current) setLoading(false); }
  };
  useEffect(() => {
    mounted.current = true; void read();
    return () => { mounted.current = false; generation.current++; readSequence.current++; };
  }, []);
  const busy = !state?.restartRequired && (busyStates.has(state?.status) || !!action);
  useEffect(() => {
    if (!busy) return;
    let closed = false, timer;
    const poll = async () => { await read(); if (!closed) timer = setTimeout(poll, 750); };
    timer = setTimeout(poll, 750);
    return () => { closed = true; clearTimeout(timer); };
  }, [busy]);
  useEffect(() => { setConfirmation(false); }, [state?.status, state?.latestVersion]);
  const run = async (method, kind) => {
    if (actionRef.current && !(kind === 'cancel' && actionRef.current === 'download')) return;
    actionRef.current = kind; setAction(kind); setConfirmation(false); setReadError(false);
    const epoch = ++generation.current; readSequence.current++;
    try {
      const value = await callRef.current(method, {});
      if (mounted.current && generation.current === epoch) { readSequence.current++; apply(value); }
    } catch (error) {
      if (!mounted.current || generation.current !== epoch) return;
      // Installation may revoke ordinary IPC while its accepted work continues.
      // The status endpoint remains read-only and tells us whether restart or
      // cleanup is pending; a rejected action reply is not install failure.
      let recovered = null;
      try { recovered = checkedState(await callRef.current('applicationUpdateStatus', {})); } catch { /* retain a safe local failure */ }
      if (mounted.current && generation.current === epoch) {
        readSequence.current++;
        const next = recovered || { ...stateRef.current, status: 'error', error: typeof error?.code === 'string' ? error.code : null,
          restartRequired: error?.restartRequired === true };
        stateRef.current = next; setState(next);
      }
    } finally {
      if (mounted.current && generation.current === epoch) { actionRef.current = ''; setAction(''); setLoading(false); }
    }
  };
  const canInstall = state?.canInstall === true;
  const retryDownload = state?.status === 'error' && !!state.latestVersion;
  const primary = state?.status === 'ready' || canInstall && state?.status === 'error' ? 'install'
    : state?.status === 'available' || retryDownload ? 'download' : 'check';
  const primaryText = primary === 'install' ? '安装并重启' : primary === 'download' ? '下载更新' : '检查更新';
  const Icon = primary === 'install' ? ArrowClockwise : primary === 'download' ? DownloadSimple : ArrowsClockwise;
  const showCancel = !state?.restartRequired && (state?.status === 'downloading' || action === 'download' && ['available', 'error'].includes(state?.status));
  const errorText = state?.restartRequired ? '更新准备未完成，请手动重启境舱后再试。' : errorMessages[state?.error] || (state?.status === 'error' || state?.error ? '更新未完成，请重试。' : null);
  const start = () => {
    if (primary === 'install') setConfirmation(true);
    else void run(primary === 'download' ? 'downloadApplicationUpdate' : 'checkApplicationUpdate', primary);
  };
  return <section id="application-updates" className="application-updates" tabIndex={-1} aria-labelledby={titleId}>
    <div className="application-updates-heading"><div><h2 id={titleId}>{t('应用更新')}</h2></div>
      {!busy && !confirmation && !state?.restartRequired && (state?.status !== 'unsupported' || state?.error === 'APP_UPDATE_ASSET_UNAVAILABLE') && <button type="button" className="button" disabled={loading || typeof call !== 'function' || state?.status === 'ready' && !canInstall} onClick={start}><Icon size={16} aria-hidden="true" />{t(primaryText)}</button>}
      {showCancel && <button type="button" className="button" disabled={action === 'cancel'} onClick={() => void run('cancelApplicationUpdate', 'cancel')}>{t('取消下载')}</button>}
    </div>
    <div className="application-updates-versions"><span>{t('当前版本：{version}', { version: state?.currentVersion || '—' })}</span>
      {state?.latestVersion && state.latestVersion !== state.currentVersion && ['available', 'downloading', 'verifying', 'ready', 'installing', 'error'].includes(state.status) && <span>{t('可更新至 {version}', { version: state.latestVersion })}</span>}</div>
    <details className="application-update-help"><summary>{t('使用说明')}</summary>
      <p>{t('更新只替换应用，保留环境、配置和登录资料。')}</p><p>{t('通过本机网络连接官方发布源。')}</p>
    </details>
    {loading && <p role="status">{t('正在读取更新状态…')}</p>}
    {readError && <p role="alert" className="application-updates-error"><WarningCircle size={16} aria-hidden="true" />{t('无法读取更新状态，请重试。')}</p>}
    {errorText && <p role="alert" className="application-updates-error"><WarningCircle size={16} aria-hidden="true" />{t(errorText)}</p>}
    {phaseMessages[state?.status] && !state?.restartRequired && !(state?.status === 'unsupported' && state?.error === 'APP_UPDATE_ASSET_UNAVAILABLE') && <p role="status">{t(phaseMessages[state.status])}</p>}
    {action && !busyStates.has(state?.status) && !state?.restartRequired && <p role="status">{t('正在处理更新请求…')}</p>}
    {state?.status === 'downloading' && <div className="application-update-progress"><progress aria-label={t('更新下载进度')} max={100} {...(state.progress !== null ? { value: state.progress } : {})} />
      {state.progress !== null && <span>{state.progress}%</span>}</div>}
    {state?.status === 'ready' && !canInstall && !state?.restartRequired && <p>{t('请先保存并结束运行任务，再重试安装。')}</p>}
    {confirmation && !busy && !state?.restartRequired && <div className="application-update-confirm" role="group" aria-label={t('确认安装应用更新？')}>
      <strong>{t('确认安装应用更新？')}</strong><p>{t('安装会重启境舱。请先保存工作并结束运行任务，环境和登录资料会保留。')}</p>
      <div><button type="button" className="button" onClick={() => setConfirmation(false)}>{t('取消')}</button>
        <button type="button" className="button primary" disabled={!canInstall} onClick={() => void run('installApplicationUpdate', 'install')}>{t('确认安装并重启')}</button></div>
    </div>}
    {state?.lastResult && <p className={`application-update-last-result ${state.lastResult.status}`}>{t({ installed: '上次更新已完成：{version}',
      failed: '上次更新未完成：{version}', pending: '上次更新结果尚未确认：{version}' }[state.lastResult.status], { version: state.lastResult.version || '—' })}</p>}
  </section>;
}
