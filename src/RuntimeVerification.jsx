import React, { useEffect, useRef, useState } from 'react';
import { ArrowsClockwise } from '@phosphor-icons/react';
import { useI18n } from './i18n.jsx';
import './runtime-verification.css';

const statuses = { match: '相符', mismatch: '有差异', unknown: '未观测' };
const fields = { locale: '语言区域', timezone: '时区', ip: '出口 IP（上次测量）' };

export function RuntimeVerification({ profiles = [], api }) {
  const { t, language } = useI18n();
  const [selected, setSelected] = useState('');
  const [result, setResult] = useState(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const generation = useRef(0);
  const readRevision = useRef(0);
  const localChecks = useRef(new Set());
  const profileId = profiles.some(profile => profile.id === selected) ? selected : profiles[0]?.id ?? '';
  const profile = profiles.find(item => item.id === profileId);
  // The outer workspace refreshes regularly. Only relevant changes reload the
  // local snapshot; this never starts a browser or contacts a lookup provider.
  const profileRevision = JSON.stringify([profile?.status, profile?.updatedAt, profile?.proxyId, profile?.locale, profile?.timezone]);
  useEffect(() => {
    const current = ++generation.current;
    setResult(null); setError(false); setPending(false);
    if (!profileId || typeof api !== 'function') return;
    const refresh = async () => {
      const read = ++readRevision.current;
      try {
        const snapshot = await api('runtimeVerificationSnapshot', { id: profileId });
        if (generation.current !== current || readRevision.current !== read || localChecks.current.has(profileId)) return;
        setResult(snapshot?.results?.find(item => item.profileId === profileId) ?? null);
        setPending(snapshot?.pending?.includes(profileId) === true);
      } catch { if (generation.current === current && readRevision.current === read && !localChecks.current.has(profileId)) setError(true); }
    };
    void refresh();
    const timer = setInterval(refresh, 30_000);
    return () => { ++generation.current; clearInterval(timer); };
  }, [profileId, profileRevision, api]);
  async function check() {
    if (!profileId || pending || localChecks.current.has(profileId)) return;
    const current = generation.current;
    localChecks.current.add(profileId); ++readRevision.current;
    setPending(true); setError(false);
    try {
      const value = await api('checkRuntimeVerification', { id: profileId });
      if (generation.current === current) setResult(value);
    } catch { if (generation.current === current) setError(true); }
    finally { localChecks.current.delete(profileId); if (generation.current === current) { ++readRevision.current; setPending(false); } }
  }
  return <section className="runtime-verification" aria-labelledby="runtime-verification-title">
    <div className="runtime-verification-heading"><h3 id="runtime-verification-title">{t('运行实测核验')}</h3>
      <button type="button" className="button" onClick={check} disabled={!profileId || pending || typeof api !== 'function'}>
        <ArrowsClockwise size={15} className={pending ? 'spin' : ''} aria-hidden="true" />{t(pending ? '正在核验…' : '核验当前运行状态')}
      </button>
    </div>
    <label className="runtime-verification-select"><span>{t('环境')}</span><select value={profileId} onChange={event => setSelected(event.target.value)} disabled={!profiles.length}>
      {!profiles.length && <option value="">{t('暂无环境')}</option>}
      {profiles.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}
    </select></label>
    <details className="runtime-verification-instructions"><summary>{t('使用说明')}</summary>
      <p className="runtime-verification-note">{t('仅检查已有可信线路的运行中浏览器。点击核验时，通过该浏览器访问 ipwho.is；不发送站点登录数据。')}</p>
    </details>
    {error && <p role="alert" className="runtime-verification-warning">{t('无法完成运行核验，请重试。')}</p>}
    {!result && !pending && <p className="runtime-verification-note">{t('尚无实测结果。')}</p>}
    {pending && <p role="status" className="sr-only">{t('正在核验…')}</p>}
    {result && <>
      <div className="runtime-verification-time"><span>{t('测量时间：{time}', { time: new Date(result.checkedAt).toLocaleString(language) })}</span>
        {result.stale && <strong>{t('结果已过期，请重新核验。')}</strong>}</div>
      <div className="runtime-verification-table-wrap"><table className="runtime-verification-table"><thead><tr>
        <th scope="col">{t('核验项目')}</th><th scope="col">{t('环境配置 / 先前测量')}</th><th scope="col">{t('浏览器实测')}</th><th scope="col">{t('核对结果')}</th>
      </tr></thead><tbody>{Object.entries(fields).map(([key, label]) => <tr key={key}>
        <th scope="row">{t(label)}</th><td>{result.expected?.[key] ?? '—'}</td><td>{result.browser?.observed?.[key] ?? '—'}</td>
        <td className={`runtime-verification-check ${result.stale ? 'unknown' : result.browser?.checks?.[key] ?? 'unknown'}`}>{t(result.stale ? '未观测' : statuses[result.browser?.checks?.[key]] ?? '未观测')}</td>
      </tr>)}</tbody></table></div>
      {result.browser?.reason && <p className="runtime-verification-note">{t(result.browser.reason === 'route-unverified'
        ? '浏览器未运行或当前线路未确认，未发起网络核验。'
        : result.browser.reason === 'unsupported-runtime' ? '后台核验当前支持 CloakBrowser 和 BrowseForge Chromium；Camoufox 暂未支持。'
        : '部分项目未能观测；这不代表线路已通过或失败。')}</p>}
      <details className="runtime-verification-terminal"><summary>{t('终端启动上下文（{count} 个会话）', { count: result.terminal?.sessions?.length ?? 0 })}</summary>
        <p className="runtime-verification-note">{t('以下为进程启动时传入的设置。未向终端输入命令，当前 shell、子进程和 SSH 远端的实际出口与语言仍未观测。')}</p>
        {(result.terminal?.sessions ?? []).map(session => <div key={session.sessionId} className="runtime-verification-session">
          <span>{session.timezone ?? '—'} · {session.language ?? '—'}</span>
          <span>{t(session.networkFence ? '启动时已启用网络围栏' : '启动时未确认网络围栏')}</span>
          {session.configurationMatches === false && <span className="runtime-verification-warning">{t('启动设置与当前配置有差异。')}</span>}
        </div>)}
      </details>
    </>}
  </section>;
}
