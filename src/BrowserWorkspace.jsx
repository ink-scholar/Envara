import React, { useMemo, useState } from 'react';
import {
  ArrowSquareOut,
  Browsers,
  CaretDown,
  CheckCircle,
  DownloadSimple,
  MagnifyingGlass,
  PencilSimple,
  Play,
  Plus,
  Stop,
  WarningCircle,
} from '@phosphor-icons/react';

const statusLabels = {
  stopped: '已停止',
  starting: '启动中',
  running: '运行中',
  error: '异常',
};

const isActive = (profile) => ['running', 'starting'].includes(profile.status);
const identity = (label) => label;

export function BrowserWorkspace({
  profiles = [],
  proxies = [],
  engines = [],
  selectedId,
  onSelect,
  onStart,
  onStop,
  onFocus,
  onEdit,
  onCreate,
  onInstall,
  busyProfile,
  editingDisabled,
  pending = {},
  t = identity,
}) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const translate = typeof t === 'function' ? t : identity;
  const runtimeById = useMemo(
    () => new Map(engines.map((runtime) => [runtime.id, runtime])),
    [engines],
  );
  const proxyById = useMemo(
    () => new Map(proxies.map((proxy) => [proxy.id, proxy])),
    [proxies],
  );
  const activeCount = profiles.filter(isActive).length;
  const installedCount = engines.filter((runtime) => runtime.installed).length;
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visibleProfiles = profiles.filter((profile) => {
    const runtime = runtimeById.get(profile.engine);
    const proxy = proxyById.get(profile.proxyId);
    const searchText = [profile.name, profile.group, runtime?.displayName, proxy?.name]
      .filter(Boolean)
      .join(' ')
      .toLocaleLowerCase();
    return (filter === 'all' || isActive(profile))
      && searchText.includes(normalizedQuery);
  });

  const isBusy = (id) => typeof busyProfile === 'function'
    ? busyProfile(id)
    : Boolean(busyProfile?.[id]);
  const installationBusy = (runtime) => Boolean(
    runtime.installing || pending[`installEngine:${runtime.id}`],
  );
  const cannotEdit = (id) => typeof editingDisabled === 'function'
    ? editingDisabled(id)
    : Boolean(editingDisabled?.[id]);
  const engineState = (runtime) => {
    if (runtime.supported === false) return translate('当前平台不可用');
    if (runtime.installed) return translate('已就绪');
    if (installationBusy(runtime)) {
      return typeof runtime.progress === 'number'
        ? `${translate('安装中')} ${Math.round(runtime.progress)}%`
        : translate('安装中…');
    }
    return translate('未安装');
  };

  return (
    <div className="browser-workspace">
      {profiles.length > 0 && <div className="workspace-toolbar">
        <div className="workspace-segments" aria-label={translate('浏览器筛选')}>
          <button
            type="button"
            className={filter === 'all' ? 'active' : ''}
            aria-pressed={filter === 'all'}
            onClick={() => setFilter('all')}
          >
            {translate('全部')} <span>{profiles.length}</span>
          </button>
          <button
            type="button"
            className={filter === 'running' ? 'active' : ''}
            aria-pressed={filter === 'running'}
            onClick={() => setFilter('running')}
          >
            {translate('运行中')} <span>{activeCount}</span>
          </button>
        </div>
        <label className="workspace-search">
          <MagnifyingGlass size={17} aria-hidden="true" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={translate('搜索环境')}
            aria-label={translate('搜索环境')}
          />
        </label>
        <button type="button" className="button primary" onClick={() => onCreate?.()} disabled={!onCreate}>
          <Plus size={17} aria-hidden="true" />
          {translate('新建环境')}
        </button>
      </div>}

      {visibleProfiles.length > 0 ? (
        <table className="browser-profile-list" aria-label={translate('浏览器环境')}>
          <thead>
            <tr className="browser-list-head">
              <th scope="col">{translate('环境')}</th>
              <th scope="col">{translate('浏览器')}</th>
              <th scope="col">{translate('网络出口')}</th>
              <th scope="col">{translate('状态')}</th>
              <th scope="col">{translate('操作')}</th>
            </tr>
          </thead>
          <tbody>
            {visibleProfiles.map((profile) => {
              const runtime = runtimeById.get(profile.engine);
              const proxy = proxyById.get(profile.proxyId);
              const busy = isBusy(profile.id);
              const active = isActive(profile);
              const supported = Boolean(runtime) && runtime.supported !== false;
              const installing = runtime && installationBusy(runtime);
              const networkName = proxy?.name || translate(profile.proxyId ? '出口不可用' : '直接连接');
              const status = statusLabels[profile.status] || '未知状态';
              const actionLabel = profile.status === 'running'
                ? translate('打开')
                : profile.status === 'starting' || pending[`startProfile:${profile.id}`]
                  ? translate('启动中…')
                  : !supported
                    ? translate('不可用')
                    : !runtime.installed
                      ? translate(installing ? '安装中…' : '安装内核')
                      : translate('启动');
              const ActionIcon = profile.status === 'running'
                ? ArrowSquareOut
                : supported && !runtime.installed
                  ? DownloadSimple
                  : Play;
              const launch = () => {
                onSelect?.(profile.id);
                if (profile.status === 'running') onFocus?.(profile);
                else if (supported && !runtime.installed) onInstall?.(runtime);
                else if (supported) onStart?.(profile);
              };

              return (
                <tr
                  key={profile.id}
                  className={`browser-profile-row ${selectedId === profile.id ? 'selected' : ''}`}
                  onClick={() => onSelect?.(profile.id)}
                >
                  <td>
                    <button
                      type="button"
                      className="browser-profile-main"
                      onClick={(event) => { event.stopPropagation(); onSelect?.(profile.id); }}
                      aria-pressed={selectedId === profile.id}
                    >
                      <Browsers size={21} aria-hidden="true" />
                      <span className="browser-profile-meta">
                        <strong title={profile.name}>{profile.name}</strong>
                        <small>{profile.group || translate('未分组')}</small>
                      </span>
                    </button>
                  </td>
                  <td className="browser-runtime-cell">
                    <span title={runtime?.displayName || profile.engine}>
                      {runtime?.displayName || profile.engine || translate('未知内核')}
                    </span>
                  </td>
                  <td className="browser-network-cell"><span title={networkName}>{networkName}</span></td>
                  <td><span className={`status status-${profile.status || 'stopped'}`}><span className="status-dot" />{translate(status)}</span></td>
                  <td>
                    <div className="browser-row-actions" onClick={(event) => event.stopPropagation()}>
                      <button
                        type="button"
                        className={`button ${active ? '' : 'primary'}`}
                        disabled={busy || profile.status === 'starting'
                          || (profile.status === 'running'
                            ? !onFocus
                            : Boolean(installing) || !supported || (runtime?.installed ? !onStart : !onInstall))}
                        onClick={launch}
                      >
                        <ActionIcon size={16} aria-hidden="true" />{actionLabel}
                      </button>
                      {active && (
                        <button
                          type="button"
                          className="icon-button"
                          aria-label={translate('停止浏览器')}
                          title={translate('停止浏览器')}
                          disabled={busy || !onStop}
                          onClick={() => onStop?.(profile)}
                        >
                          <Stop size={17} aria-hidden="true" />
                        </button>
                      )}
                      <button
                        type="button"
                        className="icon-button"
                        aria-label={translate('编辑环境')}
                        title={translate('编辑环境')}
                        disabled={busy || active || cannotEdit(profile.id) || !onEdit}
                        onClick={() => onEdit?.(profile)}
                      >
                        <PencilSimple size={17} aria-hidden="true" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div className="browser-empty">
          <Browsers size={34} weight="duotone" aria-hidden="true" />
          <h2>{translate(profiles.length ? '没有匹配的环境' : '添加第一个浏览器环境')}</h2>
          {profiles.length === 0 && (
            <button type="button" className="button primary" onClick={() => onCreate?.()} disabled={!onCreate}>
              <Plus size={17} aria-hidden="true" />{translate('新建环境')}
            </button>
          )}
          {profiles.length > 0 && (
            <button type="button" className="button" onClick={() => { setQuery(''); setFilter('all'); }}>
              {translate('显示全部')}
            </button>
          )}
        </div>
      )}

      {engines.length > 0 && (
        <details className="browser-engine-details">
          <summary className="browser-engine-summary">
            <Browsers size={18} aria-hidden="true" />
            <span>{translate('浏览器内核')}</span>
            <small>{installedCount} / {engines.length} {translate('已就绪')}</small>
            <CaretDown size={16} aria-hidden="true" />
          </summary>
          <div className="browser-engine-list">
            {engines.map((runtime) => {
              const installing = installationBusy(runtime);
              return (
                <div key={runtime.id} className="browser-engine-item">
                  <div className="browser-engine-copy">
                    <strong>{runtime.displayName || runtime.id}</strong>
                    <span className="browser-engine-state">
                      {engineState(runtime)}
                      {runtime.installed && runtime.version ? ` · ${runtime.version}` : ''}
                      {runtime.experimental ? ` · ${translate('实验性')}` : ''}
                    </span>
                  </div>
                  <button
                    type="button"
                    className="button"
                    disabled={runtime.installed || installing || runtime.supported === false || !onInstall}
                    onClick={() => onInstall?.(runtime)}
                  >
                    {runtime.installed
                      ? <CheckCircle size={16} aria-hidden="true" />
                      : <DownloadSimple size={16} aria-hidden="true" />}
                    {translate(runtime.installed ? '已就绪' : runtime.supported === false ? '不可用' : installing ? '安装中…' : '安装')}
                  </button>
                  {runtime.error && (
                    <div className="browser-engine-error" role="alert">
                      <WarningCircle size={16} aria-hidden="true" /><span>{translate(runtime.error)}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </details>
      )}
    </div>
  );
}

export default BrowserWorkspace;
