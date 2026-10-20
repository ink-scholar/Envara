import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, CaretRight, Key, LockKey, MagnifyingGlass, Plus, TerminalWindow, X } from '@phosphor-icons/react';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';
import './ssh-workspace.css';

const emptyDraft = () => ({ name: '', host: '', port: '22', user: '' });
const busyMessage = '先结束此环境的终端会话，再修改连接。';
const sshErrors = {
  SSH_UNSUPPORTED: 'SSH 连接目前仅支持 macOS。',
  SSH_INVALID_INPUT: '请检查连接名称、主机、端口和用户名。',
  SSH_UNSAFE_PATH: '无法安全读取所选密钥，请重新选择。',
  SSH_PUBLIC_KEY_REQUIRED: '所选私钥旁需要有对应的 .pub 公钥文件。',
  SSH_KEY_INVALID: '所选 SSH 密钥无效或格式不受支持。',
  SSH_HOST_UNTRUSTED: '无法核验此主机的可信指纹，请重新读取并确认。',
  SSH_ROUTE_INVALID: '请选择可用的 SSH 连接线路。',
  SSH_ROUTE_UNCONFIGURED: '请选择可用的 SSH 连接线路。',
  SSH_ROUTE_UNAVAILABLE: 'SSH 连接线路不可用，请检查后重试。',
  SSH_ROUTE_CHANGED: 'SSH 连接线路已改变，请重新核对主机指纹。',
  SSH_ROUTE_CANCELLED: '主机指纹探测已取消。',
  SSH_ROUTE_CLEANUP_FAILED: 'SSH 资源清理未完成，请重试。',
  SSH_HOST_KEY_CONFIRMATION_REQUIRED: '请核对并确认主机指纹。',
  SSH_HOST_CONFIRMATION_REQUIRED: '请核对并确认主机指纹。',
  SSH_HOST_PROBE_INVALID: '无法读取主机指纹，请检查线路和主机。',
  SSH_HOST_PROBE_FAILED: '无法读取主机指纹，请检查线路和主机。',
  SSH_HOST_PROBE_CANCELLED: '主机指纹探测已取消。',
  SSH_HOST_PROBE_TIMEOUT: '主机指纹探测超时，请重试。',
  SSH_HOST_PROBE_REVOKED: 'SSH 连接线路已改变，请重新核对主机指纹。',
  SSH_HOST_PROBE_CLEANUP_FAILED: '主机指纹探测清理未完成，请重试。',
  SSH_IDENTITY_CHANGED: '密钥或主机信任记录已改变，请重新选择并核对。',
  SSH_SELECTION_EXPIRED: 'SSH 连接授权已失效，请重新核对主机指纹。',
  SSH_SELECTION_MISMATCH: 'SSH 连接授权不属于当前窗口或环境，请重新核对。',
  SSH_PASSWORD_INVALID: '密码无效，请重新输入。',
  SSH_PASSWORD_REQUIRED: '请重新提供 SSH 密码后新建会话。',
  SSH_PASSWORD_EXPIRED: '请重新提供 SSH 密码后新建会话。',
  SSH_SAVED_CONNECTION_UNAVAILABLE: '此已保存 SSH 连接未载入当前终端。请在「SSH 连接」中补充授权后新建终端。',
  SSH_TARGET_NOT_AUTHORIZED: '此请求与已保存的 SSH 连接不匹配，未切换网络路线。',
  SSH_NAME_EXISTS: '此环境已存在同名 SSH 连接。',
  SSH_CONNECTION_NOT_FOUND: '此 SSH 连接已不存在，请重新打开连接设置。',
  SSH_CONNECTION_LIMIT: '此环境的 SSH 连接数量已达上限。',
  SSH_STORAGE_INVALID: '无法读取 SSH 配置，原有数据已保留。',
  SSH_STORAGE_UNAVAILABLE: '无法保存 SSH 配置，原有数据已保留。',
  SSH_AGENT_FAILED: 'SSH 密钥服务不可用，请重新选择密钥。',
  SSH_KEY_LOCKED: '此密钥需要口令，当前版本暂不支持。',
  SSH_CLEANUP_FAILED: 'SSH 资源清理未完成，请重试。',
  SSH_TERMINAL_BUSY: busyMessage,
  TERMINAL_SSH_BUSY: busyMessage,
  TERMINAL_SSH_UNAVAILABLE: '无法读取 SSH 连接，请重试。',
  SSH_WINDOW_CLOSED: '终端窗口已关闭，请重新打开连接设置。',
  ENVIRONMENT_TRANSFER_BUSY: '环境正在导入、导出或修改，请等待完成后重试。',
};

function checkedRoute(value, legacy = false) {
  if (value === undefined && legacy) return { kind: 'host' };
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
  if (!Object.hasOwn(value, 'kind')) throw new Error();
  if (value.kind === 'host' && Object.keys(value).length === 1) return { kind: 'host' };
  if (value.kind === 'environment' && Object.keys(value).length === 2 && Object.hasOwn(value, 'profileId') && typeof value.profileId === 'string' && value.profileId.trim()) return { kind: 'environment', profileId: value.profileId };
  throw new Error();
}
const routeKey = route => route?.kind === 'host' ? 'host' : route?.kind === 'environment' ? `environment:${route.profileId}` : '';
const sameRoute = (left, right) => !!left && !!right && routeKey(left) === routeKey(right);

function checkedList(value) {
  if (typeof value?.supported !== 'boolean' || !Array.isArray(value.connections)) throw new Error();
  const routeOptions = (value.routeOptions ?? (value.supported ? null : []))?.map(option => {
    if (typeof option?.label !== 'string' || !option.label.trim() || typeof option.available !== 'boolean') throw new Error();
    return { route: checkedRoute(option.route), label: option.label, available: option.available };
  });
  if (!routeOptions || new Set(routeOptions.map(option => routeKey(option.route))).size !== routeOptions.length) throw new Error();
  const defaultRoute = value.defaultRoute === undefined && !value.supported ? null : checkedRoute(value.defaultRoute);
  if (value.supported && !routeOptions.some(option => option.available && sameRoute(option.route, defaultRoute))) throw new Error();
  const fields = ['id', 'alias', 'name', 'host', 'port', 'user', 'keyLabel', 'keyFingerprint', 'hostFingerprints'];
  return { supported: value.supported, routeOptions, defaultRoute, connections: value.connections.map(connection => {
    const authType = connection.authType ?? 'publickey';
    if (!['publickey', 'password'].includes(authType)) throw new Error();
    return { ...Object.fromEntries(fields.filter(key => Object.hasOwn(connection, key)).map(key => [key, connection[key]])),
      route: checkedRoute(connection.route, true), authType, ...(authType === 'password' ? { passwordReady: connection.passwordReady === true } : {}) };
  }) };
}

/** Only public connection metadata and one-use authorization tokens enter state.
 * Passwords stay in uncontrolled inputs until submission, then are cleared. */
export function TerminalSshConnections({ profileId, profileName, hasActiveSessions, onClose, onOpenTerminal }) {
  const { t } = useI18n();
  const desktopAvailable = api.isDesktop === true;
  const [state, setState] = useState({ profileId, status: 'loading', supported: false, connections: [], routeOptions: [], defaultRoute: null });
  const [selectedId, setSelectedId] = useState(null);
  const [adding, setAdding] = useState(false);
  const [query, setQuery] = useState('');
  const [draft, setDraft] = useState(emptyDraft);
  const [authType, setAuthType] = useState('password');
  const [route, setRoute] = useState(null);
  const [prepared, setPrepared] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [unlocking, setUnlocking] = useState(null);
  const [hasPassword, setHasPassword] = useState(false);
  const [hasUnlockPassword, setHasUnlockPassword] = useState(false);
  const [pending, setPending] = useState('');
  const [error, setError] = useState('');
  const mounted = useRef(false), inFlight = useRef(false), loadVersion = useRef(0);
  const passwordInput = useRef(null), unlockInput = useRef(null);
  const routeVersion = useRef(0);
  const activeSessions = useRef(hasActiveSessions);
  activeSessions.current = hasActiveSessions;
  const scope = useRef({ profileId });
  if (scope.current.profileId !== profileId) scope.current = { profileId };
  const clearPasswords = () => {
    if (passwordInput.current) passwordInput.current.value = '';
    if (unlockInput.current) unlockInput.current.value = '';
    setHasPassword(false); setHasUnlockPassword(false);
  };

  const resetEditor = () => {
    routeVersion.current += 1;
    clearPasswords(); setDraft(emptyDraft()); setAuthType('password');
    setRoute(state.profileId === profileId ? state.defaultRoute : null);
    setPrepared(null); setConfirmed(false); setUnlocking(null); setRemoving(null); setError('');
  };
  const acceptList = result => {
    setState({ ...result, profileId, status: 'ready' });
    setSelectedId(current => result.connections.some(connection => connection.id === current) ? current : result.connections[0]?.id ?? null);
    setRoute(current => current ?? result.defaultRoute);
  };

  const load = async () => {
    if (!desktopAvailable || !profileId) return;
    const version = ++loadVersion.current, requestedScope = scope.current;
    setError(''); setState(value => value.profileId === profileId ? { ...value, status: 'loading' } : { profileId, status: 'loading', supported: false, connections: [], routeOptions: [], defaultRoute: null });
    try {
      const result = checkedList(await api.call('listTerminalSshConnections', { id: profileId }));
      if (mounted.current && requestedScope === scope.current && version === loadVersion.current) acceptList(result);
    } catch (failure) {
      if (mounted.current && requestedScope === scope.current && version === loadVersion.current) { setState(value => ({ ...value, status: 'error' })); setError(sshErrors[failure.code] || '无法读取 SSH 连接，请重试。'); }
    }
  };
  useEffect(() => {
    mounted.current = true; inFlight.current = false; setPending('');
    resetEditor(); setSelectedId(null); setAdding(false); setQuery('');
    if (desktopAvailable && profileId) void load();
    else setState({ profileId, status: 'ready', supported: false, connections: [], routeOptions: [], defaultRoute: null });
    return () => {
      mounted.current = false; loadVersion.current += 1;
      if (passwordInput.current) passwordInput.current.value = '';
      if (unlockInput.current) unlockInput.current.value = '';
    };
  }, [profileId, desktopAvailable]);
  useEffect(() => { if (hasActiveSessions) { clearPasswords(); setUnlocking(null); setPrepared(null); setConfirmed(false); } }, [hasActiveSessions]);

  const run = async (action, operation, fallback = '无法更新 SSH 连接，请重试。') => {
    if (inFlight.current || !desktopAvailable || !profileId) return;
    const operationScope = scope.current, operationVersion = routeVersion.current;
    const isCurrent = () => mounted.current && operationScope === scope.current && operationVersion === routeVersion.current;
    inFlight.current = true; setPending(action); setError('');
    try { await operation(isCurrent); }
    catch (failure) { if (isCurrent()) { clearPasswords(); setError(sshErrors[failure.code] || fallback); } }
    finally { if (operationScope === scope.current) { inFlight.current = false; if (mounted.current) setPending(''); } }
  };
  const updateTarget = (field, value) => {
    setDraft(current => ({ ...current, [field]: value }));
    clearPasswords(); setPrepared(null); setConfirmed(false); setError('');
  };
  const changeAuthType = value => {
    clearPasswords(); setAuthType(value); setPrepared(null); setConfirmed(false); setError('');
  };
  const routeOptions = state.profileId === profileId ? state.routeOptions : [];
  const optionForRoute = value => routeOptions.find(option => sameRoute(option.route, value));
  const optionLabel = option => option.route.kind === 'host' ? t('本机网络') : option.label;
  const validRoute = optionForRoute(route)?.available === true;
  const routeLabel = value => { const option = optionForRoute(value); return option ? optionLabel(option) : t('线路不可用'); };
  const changeRoute = key => {
    const option = routeOptions.find(item => routeKey(item.route) === key);
    if (!option?.available) return;
    routeVersion.current += 1;
    clearPasswords(); setPrepared(null); setConfirmed(false); setError(''); setRoute(option.route);
  };
  const validTarget = draft.host.trim() && draft.user.trim() && Number.isInteger(Number(draft.port)) && Number(draft.port) >= 1 && Number(draft.port) <= 65535;
  const chooseIdentity = () => {
    if (hasActiveSessions || !validRoute) return;
    return run('pick', async isCurrent => {
      const result = await api.call(authType === 'password' ? 'prepareTerminalSshPassword' : 'prepareTerminalSshIdentity', {
        id: profileId, host: draft.host.trim(), port: Number(draft.port), user: draft.user.trim(), route,
      });
      if (!isCurrent() || activeSessions.current || result?.canceled) return;
      if (typeof result?.selectionToken !== 'string' || !Array.isArray(result.hostFingerprints) || !result.hostFingerprints.length
        || !result.hostFingerprints.every(value => typeof value === 'string' && value)
        || !['probe', 'host-known-hosts'].includes(result.trustSource)
        || (authType === 'password' ? result.authType !== 'password' : typeof result.keyFingerprint !== 'string')) throw new Error();
      const selectedRoute = checkedRoute(result.route);
      if (!sameRoute(selectedRoute, route)) throw Object.assign(new Error(), { code: 'SSH_ROUTE_CHANGED' });
      setPrepared({ selectionToken: result.selectionToken, hostFingerprints: result.hostFingerprints, route: selectedRoute, trustSource: result.trustSource,
        ...(authType === 'publickey' ? { keyLabel: result.keyLabel, keyFingerprint: result.keyFingerprint } : {}) });
      setConfirmed(false);
    }, authType === 'password' ? '无法读取主机指纹，请检查线路和主机。' : '无法更新 SSH 连接，请重试。');
  };
  const save = () => {
    if (hasActiveSessions || inFlight.current || !prepared || !confirmed || !draft.name.trim() || !validRoute || !sameRoute(prepared.route, route)) return;
    const password = authType === 'password' ? passwordInput.current?.value : undefined;
    if (authType === 'password' && !password) return;
    clearPasswords();
    void run('save', async isCurrent => {
      try {
        const result = checkedList(await api.call('saveTerminalSshConnection', { id: profileId, name: draft.name.trim(), selectionToken: prepared.selectionToken, hostKeyConfirmed: true,
          ...(authType === 'password' ? { password } : {}) }));
        if (isCurrent()) {
          const created = result.connections.find(connection => !state.connections.some(previous => previous.id === connection.id));
          acceptList(result); if (created) setSelectedId(created.id);
          setDraft(emptyDraft()); setAdding(false);
        }
      } finally {
        // Saving consumes the authorization even when validation fails.
        if (isCurrent()) { setPrepared(null); setConfirmed(false); }
      }
    });
  };
  const unlock = connection => {
    if (hasActiveSessions || inFlight.current) return;
    const password = unlockInput.current?.value;
    if (!password) return;
    clearPasswords();
    void run('password', async isCurrent => {
      const result = checkedList(await api.call('setTerminalSshPassword', { id: profileId, connectionId: connection.id, password }));
      if (isCurrent()) { acceptList(result); setUnlocking(null); }
    }, '无法保存密码，请重试。');
  };
  const remove = connection => {
    if (hasActiveSessions) return;
    clearPasswords();
    void run('remove', async isCurrent => {
      const result = checkedList(await api.call('removeTerminalSshConnection', { id: profileId, connectionId: connection.id }));
      if (isCurrent()) { acceptList(result); setRemoving(null); }
    });
  };
  const cancel = () => { if (inFlight.current) return; resetEditor(); setAdding(false); };
  const close = () => { if (inFlight.current) return; resetEditor(); onClose?.(); };
  const connections = state.profileId === profileId ? state.connections : [];
  const selected = connections.find(connection => connection.id === selectedId);
  const ready = desktopAvailable && state.profileId === profileId && state.status === 'ready' && state.supported;
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const visibleConnections = connections.filter(connection => [connection.name, connection.host, connection.user, connection.alias, connection.port].join(' ').toLocaleLowerCase().includes(normalizedQuery));
  const editDisabled = !ready || !!pending || hasActiveSessions;
  const currentAuthType = adding ? authType : selected?.authType;
  const selectConnection = connection => {
    if (inFlight.current) return;
    resetEditor(); setAdding(false); setSelectedId(connection.id);
  };

  const help = <details className="terminal-ssh-help"><summary>{t('使用说明')}</summary><div>
    <p className="terminal-ssh-note">{t('让 Claude 运行 envara-ssh list，查看当前会话可用的连接。')}</p>
    <dl><dt>{t('常用写法')}</dt><dd><code>ssh user@host</code></dd></dl>
    <p className="terminal-ssh-note">{t(currentAuthType === 'password'
      ? '密码在本次应用运行期间有效，不会定时到期，退出即清除，也不会写入命令或提供给 Claude。结束会话、线路停止或退出应用仍会关闭连接。'
      : 'SSH 密钥授权在本次应用运行期间有效，不会定时到期；结束会话、线路停止或退出应用仍会关闭连接。')}</p>
    {currentAuthType === 'publickey' && <p className="terminal-ssh-note">{t('私钥不会复制到环境。')}</p>}
    {connections.length === 0 && <p className="terminal-ssh-note">{t('尚未保存 SSH 主机。保存配置不会自动连接。')}</p>}
  </div></details>;

  return <section className="terminal-ssh-connections ssh-connections-workspace" aria-label={t('SSH 连接')}>
    <div className="ssh-workspace-toolbar">
      <label className="ssh-workspace-search"><MagnifyingGlass size={17} aria-hidden="true" /><input type="search" aria-label={t('搜索 SSH 主机')} placeholder={t('搜索 SSH 主机')} value={query} onChange={event => setQuery(event.target.value)} /></label>
      <button className="ssh-workspace-button is-primary" disabled={editDisabled} onClick={() => { resetEditor(); setAdding(true); }}><Plus size={16} />{t('添加连接')}</button>
      {onClose && <button className="ssh-workspace-icon-button" disabled={!!pending} onClick={close} aria-label={t('关闭')}><X size={17} /></button>}
    </div>
    <p className="ssh-workspace-route">{t('连接固定使用所选线路，失败不会切换。')}</p>
    {!desktopAvailable && <p className="ssh-workspace-notice" role="status">{t('SSH 连接需要境舱桌面应用。')}</p>}
    {desktopAvailable && state.status === 'ready' && !state.supported && <p className="ssh-workspace-notice" role="status">{t('SSH 连接目前仅支持 macOS。')}</p>}
    {hasActiveSessions && <p className="ssh-workspace-notice" role="status">{t(busyMessage)}</p>}
    {error && <div className="terminal-new-session-error ssh-workspace-error" role="status">{t(error)}{state.status === 'error' && <button className="ssh-workspace-button" disabled={!!pending} onClick={() => void load()}>{t('重试')}</button>}</div>}
    <div className="ssh-workspace-columns">
      <div className="ssh-workspace-hosts">
        <div className="ssh-workspace-list-heading"><span>{t('全部')}</span><span>{connections.length}</span></div>
        {state.status === 'loading' && <p className="ssh-workspace-list-message" role="status">{t('正在读取 SSH 连接…')}</p>}
        <ul className="terminal-ssh-list ssh-workspace-host-list" aria-label={t('SSH 连接')}>{visibleConnections.map(connection => <li key={connection.id}><button className={`ssh-workspace-host ${!adding && selectedId === connection.id ? 'is-selected' : ''}`} aria-pressed={!adding && selectedId === connection.id} disabled={!!pending} onClick={() => selectConnection(connection)}>
          <span className="ssh-workspace-host-icon">{connection.authType === 'password' ? <LockKey size={20} /> : <Key size={20} />}</span>
          <span className="ssh-workspace-host-label"><strong>{connection.name}</strong><span>{connection.user}@{connection.host}:{connection.port}</span><small className={connection.authType === 'password' && !connection.passwordReady || !optionForRoute(connection.route)?.available ? 'needs-password' : ''}>{t(connection.authType === 'password' ? connection.passwordReady ? '密码已就绪' : '提供密码' : '私钥登录')} · <span className="ssh-workspace-route-summary">{routeLabel(connection.route)}{optionForRoute(connection.route) && !optionForRoute(connection.route).available && ` · ${t('线路不可用')}`}</span></small></span>
          <CaretRight size={15} className="ssh-workspace-host-chevron" />
        </button></li>)}</ul>
        {state.status === 'ready' && visibleConnections.length === 0 && <div className="ssh-workspace-list-empty"><TerminalWindow size={28} weight="duotone" /><strong>{t(connections.length ? '未找到匹配的主机' : '暂无已保存主机')}</strong></div>}
      </div>
      <aside className="ssh-workspace-detail" aria-label={t('连接详情')}>
        {adding ? <form className="ssh-workspace-editor" aria-label={t('添加连接')} onSubmit={event => { event.preventDefault(); save(); }}>
          <div className="ssh-workspace-detail-heading"><span className="ssh-workspace-detail-icon"><Plus size={22} /></span><div><h2>{t('添加连接')}</h2><p>{profileName}</p></div></div>
          <div className="terminal-ssh-fields">
        <label><span>{t('连接名称')}</span><input autoFocus maxLength={80} value={draft.name} disabled={!!pending} onChange={event => setDraft(value => ({ ...value, name: event.target.value }))} /></label>
        <div className="terminal-ssh-target"><label><span>{t('主机')}</span><input autoCapitalize="none" spellCheck={false} maxLength={253} value={draft.host} disabled={!!pending} onChange={event => updateTarget('host', event.target.value)} /></label><label><span>{t('端口')}</span><input type="number" min="1" max="65535" step="1" value={draft.port} disabled={!!pending} onChange={event => updateTarget('port', event.target.value)} /></label></div>
        <label><span>{t('用户名')}</span><input autoCapitalize="none" spellCheck={false} maxLength={64} value={draft.user} disabled={!!pending} onChange={event => updateTarget('user', event.target.value)} /></label>
        <label><span>{t('连接线路')}</span><select aria-label={t('连接线路')} value={routeKey(route)} disabled={!ready || hasActiveSessions || (!!pending && pending !== 'pick')} onChange={event => changeRoute(event.target.value)}>{!route && <option value="" disabled>{t('请选择可用的 SSH 连接线路。')}</option>}{routeOptions.map(option => <option key={routeKey(option.route)} value={routeKey(option.route)} disabled={!option.available}>{optionLabel(option)}{!option.available && ` · ${t('线路不可用')}`}</option>)}</select></label>
        {route?.kind === 'host' && <p className="terminal-ssh-note">{t('本机网络会向远端显示该出口 IP。')}</p>}
        <label><span>{t('登录方式')}</span><select aria-label={t('登录方式')} value={authType} disabled={!!pending} onChange={event => changeAuthType(event.target.value)}><option value="password">{t('密码登录')}</option><option value="publickey">{t('私钥登录')}</option></select></label>
        {authType === 'password' ? <>
          <label><span>{t('密码')}</span><input ref={passwordInput} type="password" autoComplete="off" maxLength={1024} disabled={!!pending || hasActiveSessions} onChange={event => setHasPassword(!!event.currentTarget.value)} /></label>
          <p className="terminal-ssh-note">{t('密码仅本次运行有效，退出清除。')}</p>
          <button type="button" className="ssh-workspace-button" disabled={editDisabled || !validTarget || !validRoute} onClick={() => void chooseIdentity()}>{t(pending === 'pick' ? '正在读取指纹…' : '读取主机指纹')}</button>
        </> : <>
          <button type="button" className="ssh-workspace-button" disabled={editDisabled || !validTarget || !validRoute} onClick={() => void chooseIdentity()}><Key size={14} />{t(pending === 'pick' ? '正在检查密钥…' : prepared ? '更换私钥' : '选择私钥')}</button>
        </>}
      </div>
      {prepared && <div className="terminal-ssh-identity"><dl>{authType === 'publickey' && <div><dt>{prepared.keyLabel}</dt><dd>{prepared.keyFingerprint}</dd></div>}<div><dt>{t(prepared.trustSource === 'probe' ? '主机指纹（首次探测，尚未确认）' : '主机指纹（来自本机 known_hosts）')}</dt><dd>{prepared.hostFingerprints.map(value => <code key={value}>{value}</code>)}</dd></div></dl><label><input type="checkbox" checked={confirmed} disabled={!!pending} onChange={event => setConfirmed(event.target.checked)} /><span>{t(prepared.trustSource === 'probe' ? authType === 'password' ? '我已核对并信任此主机指纹' : '我已核对密钥并信任此主机指纹' : authType === 'password' ? '我已核对已信任的主机指纹' : '我已核对密钥和已信任的主机指纹')}</span></label></div>}
          {help}
          <div className="ssh-workspace-actions"><button type="button" className="ssh-workspace-button" disabled={!!pending} onClick={cancel}>{t('取消')}</button><button type="submit" className="ssh-workspace-button is-primary" aria-busy={pending === 'save' || undefined} disabled={editDisabled || !validRoute || !prepared || !confirmed || !draft.name.trim() || (authType === 'password' && !hasPassword)}>{t(pending === 'save' ? '保存中…' : '保存连接')}</button></div>
        </form> : selected ? <div className="terminal-ssh-connection ssh-workspace-selected" key={selected.id}>
          <div className="ssh-workspace-detail-heading"><span className="ssh-workspace-detail-icon">{selected.authType === 'password' ? <LockKey size={22} /> : <Key size={22} />}</span><div><h2>{selected.name}</h2><p>{selected.user}@{selected.host}:{selected.port}</p></div></div>
          <span className={`ssh-workspace-auth-badge ${selected.authType === 'password' && !selected.passwordReady ? 'needs-password' : ''}`}>{t(selected.authType === 'password' ? selected.passwordReady ? '密码已就绪' : '需先提供密码，不会切换线路。' : '私钥登录')}</span>
          <label className="ssh-workspace-route-summary"><span>{t('连接线路')}</span><input readOnly aria-label={t('连接线路')} value={routeLabel(selected.route)} /></label>
          {!optionForRoute(selected.route)?.available && <p className="terminal-ssh-note" role="status">{t('线路不可用')}</p>}
          {selected.route.kind === 'host' && <p className="terminal-ssh-note">{t('本机网络会向远端显示该出口 IP。')}</p>}
          <label><span>{t('连接命令')}</span><input readOnly value={`ssh ${selected.alias}`} aria-label={t('连接命令')} onFocus={event => event.currentTarget.select()} /></label>
          {onOpenTerminal && <button className="ssh-workspace-button is-primary" disabled={!desktopAvailable} onClick={() => onOpenTerminal(profileId)}><TerminalWindow size={16} />{t('打开终端')}<ArrowRight size={15} /></button>}
          {selected.authType === 'password' && <>
            <p className="terminal-ssh-note">{t('密码仅本次运行有效，退出清除。')}</p>
            {unlocking === selected.id ? <form className="terminal-ssh-unlock" onSubmit={event => { event.preventDefault(); unlock(selected); }}>
              <label><span>{t('密码')}</span><input ref={unlockInput} type="password" autoComplete="off" maxLength={1024} disabled={editDisabled || !optionForRoute(selected.route)?.available} onChange={event => setHasUnlockPassword(!!event.currentTarget.value)} autoFocus /></label>
              <div className="ssh-workspace-actions"><button type="button" className="ssh-workspace-button" disabled={!!pending} onClick={() => { clearPasswords(); setUnlocking(null); }}>{t('取消')}</button><button type="submit" className="ssh-workspace-button" disabled={editDisabled || !optionForRoute(selected.route)?.available || !hasUnlockPassword}>{t(pending === 'password' ? '保存中…' : '保存密码')}</button></div>
            </form> : <button className="ssh-workspace-button" disabled={editDisabled || !optionForRoute(selected.route)?.available} onClick={() => { clearPasswords(); setUnlocking(selected.id); setRemoving(null); }}>{t(selected.passwordReady ? '更新密码' : '提供密码')}</button>}
          </>}
          <details className="terminal-ssh-details"><summary>{t('连接详情')}</summary><label><span>{t('常用写法')}</span><input readOnly value={`ssh -p ${selected.port} ${selected.user}@${selected.host}`} aria-label={t('常用写法')} onFocus={event => event.currentTarget.select()} /></label><dl>{selected.authType === 'publickey' && <div><dt>{selected.keyLabel}</dt><dd>{selected.keyFingerprint}</dd></div>}<div><dt>{t('主机指纹')}</dt><dd>{selected.hostFingerprints.map(value => <code key={value}>{value}</code>)}</dd></div></dl></details>
          {help}
          <div className="ssh-workspace-remove">{removing === selected.id ? <><p>{t(selected.authType === 'password' ? '仅移除此环境的连接配置。' : '仅移除此环境的连接配置，原私钥保留。')}</p><div className="ssh-workspace-actions"><button className="ssh-workspace-button" disabled={!!pending} onClick={() => setRemoving(null)}>{t('取消')}</button><button className="ssh-workspace-button is-danger" disabled={editDisabled} onClick={() => remove(selected)}>{t('确认移除')}</button></div></> : <button className="ssh-workspace-button is-danger is-quiet" disabled={editDisabled} onClick={() => { clearPasswords(); setRemoving(selected.id); setUnlocking(null); }}>{t('移除连接')}</button>}</div>
        </div> : <div className="ssh-workspace-detail-empty"><Key size={28} weight="duotone" /><p>{t('选择主机以查看连接详情。')}</p></div>}
      </aside>
    </div>
  </section>;
}

export function SshWorkspace({ profiles = [], selectedId, onSelect, terminalProfiles = [], onOpenTerminal }) {
  const { t } = useI18n();
  const profile = profiles.find(item => item.id === selectedId) ?? profiles[0];
  const terminalProfile = terminalProfiles.find(item => item.profileId === profile?.id);
  const hasActiveSessions = (terminalProfile?.sessions ?? []).some(session => ['starting', 'running', 'closing'].includes(session.status));
  return <div className="ssh-workspace">
    <div className="ssh-workspace-environment"><label><span>{t('选择环境')}</span><select aria-label={t('选择环境')} value={profile?.id ?? ''} disabled={!profiles.length} onChange={event => onSelect?.(event.target.value)}>{!profiles.length && <option value="">{t('请选择环境')}</option>}{profiles.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label></div>
    {profile ? <TerminalSshConnections profileId={profile.id} profileName={profile.name} hasActiveSessions={hasActiveSessions} onOpenTerminal={onOpenTerminal} /> : <div className="ssh-workspace-no-environment"><TerminalWindow size={32} weight="duotone" /><h2>{t('选择一个环境')}</h2></div>}
  </div>;
}
