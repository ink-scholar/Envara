import React, { useEffect, useRef, useState } from 'react';
import { useI18n } from './i18n.jsx';
import './browser-site-data.css';

const errors = {
  SITE_DATA_NOT_RUNNING: '请先启动所选环境的浏览器，再查看网站 Cookie。',
  SITE_DATA_UNSUPPORTED: '此内核暂不支持安全的单网站 Cookie 清理。',
  SITE_DATA_STALE: '浏览器已重新启动，请刷新 Cookie 列表。',
  SITE_DATA_PARTITION_UNSUPPORTED: '此网站包含无法精确定位的分区 Cookie，未执行清理。',
  SITE_DATA_CLEAR_INCOMPLETE: '部分 Cookie 可能已清理，请刷新确认。',
};
const partitionLabels = { partitioned: '已分区', unpartitioned: '未分区', opaque: '不透明分区', unavailable: '分区信息不可用' };

export function BrowserSiteData({ profileId, call }) {
  const { t } = useI18n();
  const [report, setReport] = useState(null), [query, setQuery] = useState(''), [confirm, setConfirm] = useState(null);
  const [busy, setBusy] = useState(false), [notice, setNotice] = useState('');
  const generation = useRef(0);
  useEffect(() => { generation.current++; setReport(null); setQuery(''); setConfirm(null); setBusy(false); setNotice('');
    return () => { generation.current++; }; }, [profileId]);
  const load = async () => {
    const revision = ++generation.current; setBusy(true); setNotice(''); setConfirm(null); setReport(null);
    try { const value = await call('listBrowserSiteData', { profileId }); if (revision === generation.current) setReport(value); }
    catch (error) { if (revision === generation.current) setNotice(errors[error?.code] || '无法读取网站 Cookie，请稍后重试。'); }
    finally { if (revision === generation.current) setBusy(false); }
  };
  const clear = async () => {
    if (!report || !confirm) return;
    const revision = ++generation.current, domain = confirm, instanceId = report.instanceId;
    setBusy(true); setNotice('');
    try {
      await call('clearBrowserSiteCookies', { profileId, instanceId, domain });
      if (revision !== generation.current) return;
      setConfirm(null); setReport(null);
      const value = await call('listBrowserSiteData', { profileId });
      if (revision === generation.current) { setReport(value); setNotice('清理操作已完成；仍在运行的网站可能重新写入 Cookie。'); }
    } catch (error) { if (revision === generation.current) { setConfirm(null); setReport(null); setNotice(errors[error?.code] || '部分 Cookie 可能已清理，请刷新确认。'); } }
    finally { if (revision === generation.current) setBusy(false); }
  };
  const groups = new Map();
  for (const cookie of report?.cookies || []) { if (!groups.has(cookie.domain)) groups.set(cookie.domain, []); groups.get(cookie.domain).push(cookie); }
  const filter = query.trim().toLocaleLowerCase();
  const visible = [...groups].sort(([a], [b]) => a.localeCompare(b)).filter(([domain, cookies]) => !filter || domain.toLocaleLowerCase().includes(filter) || cookies.some(cookie => `${cookie.name} ${cookie.path}`.toLocaleLowerCase().includes(filter)));
  return <section className="browser-site-data" aria-label={t('网站 Cookie')}>
    <div className="site-data-heading"><div><h3>{t('网站 Cookie')}</h3><p>{t('查看名称与作用域，不显示 Cookie 内容。仅包含此环境的持久浏览器上下文，不含其他隐私窗口。')}</p></div>
      <button type="button" className="button" disabled={busy || !profileId} onClick={load}>{t(busy ? '正在读取…' : '刷新 Cookie')}</button></div>
    <p className="site-data-note">{t('按 Cookie 存储域精确清理，包含该域所有分区；共享域 Cookie 也可能影响其子网站。浏览历史及其他存储不会清理。')}</p>
    {notice && <p role="status" className="site-data-notice">{t(notice)}</p>}
    {report && <>
      {!report.canClear && <p className="site-data-note">{t('此内核仅支持查看；定点清理及分区信息尚不可用。')}</p>}
      <label className="site-cookie-search"><span>{t('搜索网站、Cookie 名称或路径')}</span><input type="search" value={query} onChange={event => { setQuery(event.target.value); setConfirm(null); }} /></label>
      <div className="site-cookie-list">{!visible.length ? <p className="site-data-note">{t(report.cookies.length ? '没有匹配的 Cookie。' : '当前浏览器没有 Cookie。')}</p> : visible.map(([domain, cookies]) => <details key={domain}>
        <summary><span>{domain}</span><span>{t('{count} 个 Cookie', { count: cookies.length })}</span></summary>
        <ul>{cookies.map((cookie, index) => <li key={index}><strong>{cookie.name || t('空名称')}</strong><span>{cookie.path}</span><span>{t(partitionLabels[cookie.partitionState])}{cookie.partitionKey ? ` · ${cookie.partitionKey}` : ''}</span><span>{[cookie.secure && 'Secure', cookie.httpOnly && 'HttpOnly', cookie.sameSite && `SameSite=${cookie.sameSite}`].filter(Boolean).join(' · ')}</span></li>)}</ul>
        {report.canClear && <div className="site-cookie-actions">{confirm === domain ? <div className="site-cookie-confirm" role="group" aria-label={t('确认清理网站 Cookie')}>
          <p>{t('将清理「{domain}」的全部 Cookie，可能退出此网站的登录。', { domain })}</p>
          <button className="button danger" type="button" disabled={busy} onClick={clear}>{t('确认清理网站 Cookie')}</button>
          <button className="button" type="button" disabled={busy} onClick={() => setConfirm(null)}>{t('取消')}</button>
        </div> : <button className="button" type="button" disabled={busy || cookies.some(cookie => cookie.partitionState === 'opaque')} onClick={() => setConfirm(domain)}>{t('清理此网站 Cookie')}</button>}
        {cookies.some(cookie => cookie.partitionState === 'opaque') && <p>{t('此网站包含无法精确定位的分区 Cookie，未执行清理。')}</p>}</div>}
      </details>)}</div>
    </>}
  </section>;
}
