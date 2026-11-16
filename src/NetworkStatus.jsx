import React, { useEffect, useState } from 'react';
import { ArrowsClockwise, CheckCircle, Clock, MinusCircle, WarningCircle } from '@phosphor-icons/react';
import { sanitizeNetworkDiagnostics } from '../shared/proxy-network-diagnostics.mjs';
import { useI18n } from './i18n.jsx';

const stageLabels = { configuration: '连接配置', https: 'HTTPS 连接', response: '响应读取', validation: '出口资料校验' };
const statusLabels = { passed: '已确认', failed: '未通过', unobserved: '未观测' };
const outcomeLabels = { success: '成功', failure: '失败', cancelled: '已取消' };
const failureLabels = {
  NETWORK_TIMEOUT: '连接超时', PROXY_AUTH_FAILED: '代理认证失败', NETWORK_FAILED: '连接未完成',
  GEO_HTTP_ERROR: '服务响应异常', GEO_BODY_TOO_LARGE: '响应超出限制',
  INVALID_GEO_RESPONSE: '出口资料无效', GEO_PROVIDER_REJECTED: '查询服务暂不可用',
  NETWORK_CHANGED: '网络已变化', APP_CLOSING: '应用正在退出',
};

export function networkFailureText(code, t) {
  return Object.hasOwn(failureLabels, code) ? t(failureLabels[code]) : null;
}

export function NetworkDiagnostics({ diagnostics }) {
  const { t } = useI18n();
  const safe = sanitizeNetworkDiagnostics(diagnostics);
  if (!safe?.attempts?.length) return null;
  return <details className="network-diagnostics">
    <summary>{t('查看检测过程')}<span>{t('{count} 次尝试', { count: safe.attempts.length })}</span></summary>
    <div className="network-diagnostic-content">
      <p className="network-diagnostic-note">{t('仅反映本次出口查询；未观测不代表失败。')}</p>
      <ol className="network-attempts">{safe.attempts.map((attempt, index) => <li key={index} className="network-attempt">
        <div className="network-attempt-heading"><span>{attempt.source === 'custom' ? t('出口查询服务') : attempt.source}</span>
          <span className={`network-outcome ${attempt.outcome}`}>{t(outcomeLabels[attempt.outcome])}</span>
          <span className="network-attempt-duration">{t('{duration} 毫秒', { duration: attempt.elapsedMs })}</span></div>
        <ul className="network-stages">{attempt.stages.map(item => {
          const Icon = item.status === 'passed' ? CheckCircle : item.status === 'failed' ? WarningCircle : MinusCircle;
          return <li className={`network-stage ${item.status}`} key={item.stage}><Icon size={14} aria-hidden="true" /><span>{t(stageLabels[item.stage])}</span><span>{t(statusLabels[item.status])}</span></li>;
        })}</ul>
        {attempt.errorCode && <p className="network-attempt-error">{t(failureLabels[attempt.errorCode])}</p>}
      </li>)}</ol>
    </div>
  </details>;
}

export function NetworkRecoveryNotice({ recovery, pending = false, onRetry }) {
  const { t } = useI18n();
  const [now, setNow] = useState(Date.now);
  const phase = recovery?.phase;
  const retryAt = Date.parse(recovery?.retryAt);
  useEffect(() => {
    setNow(Date.now());
    if (phase !== 'waiting' || !Number.isFinite(retryAt)) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [phase, retryAt]);
  if (!['checking', 'waiting', 'recovered'].includes(phase)) return null;
  const checking = phase === 'checking';
  const title = checking ? '正在恢复网络连接' : phase === 'waiting' ? '等待重新检查' : '本轮网络重检已完成';
  const detail = checking ? recovery.reason === 'resume' ? '唤醒后重新检查使用过的网络出口。' : '正在重新检查使用过的网络出口。'
    : phase === 'waiting' ? '上次重检未完成，现有环境配置保持不变。' : '结果仅适用于本轮检查的网络出口。';
  const seconds = Number.isFinite(retryAt) ? Math.max(0, Math.ceil((retryAt - now) / 1000)) : null;
  const Icon = checking ? ArrowsClockwise : phase === 'waiting' ? Clock : CheckCircle;
  return <section className={`network-recovery-notice ${phase}`} aria-label={t('网络恢复')}>
    <Icon size={18} className={checking ? 'spin' : ''} aria-hidden="true" />
    <div className="network-recovery-copy"><div role="status" aria-live="polite"><strong>{t(title)}</strong><p>{t(detail)}</p></div>
      {phase === 'waiting' && seconds !== null && <span className="network-retry-time" aria-live="off">{seconds > 0 ? t('{seconds} 秒后重试', { seconds }) : t('即将重试')}</span>}
    </div>
    {phase === 'waiting' && onRetry && <button type="button" className="button" disabled={pending} onClick={onRetry}>{t(pending ? '正在重试…' : '立即重试')}</button>}
  </section>;
}
