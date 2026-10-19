import React, { useEffect, useRef, useState } from 'react';
import { Key, X } from '@phosphor-icons/react';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';

const emptyDraft = () => ({ name: '', host: '', port: '22', user: '' });
const busyMessage = '先结束此环境的终端会话，再修改连接。';
const sshErrors = {
  SSH_UNSUPPORTED: 'SSH 连接目前仅支持 macOS。',
  SSH_INVALID_INPUT: '请检查连接名称、主机、端口和用户名。',
  SSH_UNSAFE_PATH: '无法安全读取所选密钥，请重新选择。',
  SSH_PUBLIC_KEY_REQUIRED: '所选私钥旁需要有对应的 .pub 公钥文件。',
  SSH_KEY_INVALID: '所选 SSH 密钥无效或格式不受支持。',
  SSH_HOST_UNTRUSTED: '本机 known_hosts 没有匹配的可信主机记录，无法保存此连接。',
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

function checkedList(value) {
  if (typeof value?.supported !== 'boolean' || !Array.isArray(value.connections)) throw new Error();
  const fields = ['id', 'alias', 'name', 'host', 'port', 'user', 'keyLabel', 'keyFingerprint', 'hostFingerprints'];
  return { supported: value.supported, connections: value.connections.map(connection => {
    const authType = connection.authType ?? 'publickey';
    if (!['publickey', 'password'].includes(authType)) throw new Error();
    return { ...Object.fromEntries(fields.filter(key => Object.hasOwn(connection, key)).map(key => [key, connection[key]])),
      authType, ...(authType === 'password' ? { passwordReady: connection.passwordReady === true } : {}) };
  }) };
}

/** Only public connection metadata and one-use authorization tokens enter state.
 * Passwords stay in uncontrolled inputs until submission, then are cleared. */
export function TerminalSshConnections({ profileId, profileName, hasActiveSessions, onClose }) {
  const { t } = useI18n();
  const [state, setState] = useState({ status: 'loading', supported: false, connections: [] });
  const [draft, setDraft] = useState(emptyDraft);
  const [authType, setAuthType] = useState('password');
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
  const scope = useRef({ profileId });
  if (scope.current.profileId !== profileId) scope.current = { profileId };
  const clearPasswords = () => {
    if (passwordInput.current) passwordInput.current.value = '';
    if (unlockInput.current) unlockInput.current.value = '';
    setHasPassword(false); setHasUnlockPassword(false);
  };

  const load = async () => {
    const version = ++loadVersion.current, requestedScope = scope.current;
    setError(''); setState(value => ({ ...value, status: 'loading' }));
    try {
      const result = checkedList(await api.call('listTerminalSshConnections', { id: profileId }));
      if (mounted.current && requestedScope === scope.current && version === loadVersion.current) setState({ ...result, status: 'ready' });
    } catch (failure) {
      if (mounted.current && requestedScope === scope.current && version === loadVersion.current) { setState(value => ({ ...value, status: 'error' })); setError(sshErrors[failure.code] || '无法读取 SSH 连接，请重试。'); }
    }
  };
  useEffect(() => {
    mounted.current = true; inFlight.current = false; setPending('');
    clearPasswords(); setDraft(emptyDraft()); setAuthType('password'); setPrepared(null); setConfirmed(false); setUnlocking(null); setRemoving(null);
    void load();
    return () => {
      mounted.current = false; loadVersion.current += 1;
      if (passwordInput.current) passwordInput.current.value = '';
      if (unlockInput.current) unlockInput.current.value = '';
    };
  }, [profileId]);
  useEffect(() => { if (hasActiveSessions) { clearPasswords(); setUnlocking(null); } }, [hasActiveSessions]);

  const run = async (action, operation, fallback = '无法更新 SSH 连接，请重试。') => {
    if (inFlight.current) return;
    const operationScope = scope.current;
    const isCurrent = () => mounted.current && operationScope === scope.current;
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
  const validTarget = draft.host.trim() && draft.user.trim() && Number.isInteger(Number(draft.port)) && Number(draft.port) >= 1 && Number(draft.port) <= 65535;
  const chooseIdentity = () => run('pick', async isCurrent => {
    const result = await api.call(authType === 'password' ? 'prepareTerminalSshPassword' : 'prepareTerminalSshIdentity', {
      id: profileId, host: draft.host.trim(), port: Number(draft.port), user: draft.user.trim(),
    });
    if (!isCurrent() || result?.canceled) return;
    if (typeof result?.selectionToken !== 'string' || !Array.isArray(result.hostFingerprints) || !result.hostFingerprints.length
      || (authType === 'password' ? result.authType !== 'password' : typeof result.keyFingerprint !== 'string')) throw new Error();
    setPrepared({ selectionToken: result.selectionToken, hostFingerprints: result.hostFingerprints,
      ...(authType === 'publickey' ? { keyLabel: result.keyLabel, keyFingerprint: result.keyFingerprint } : {}) });
    setConfirmed(false);
  }, authType === 'password' ? '无法读取已信任的主机指纹，请重试。' : '无法更新 SSH 连接，请重试。');
  const save = () => {
    if (hasActiveSessions || inFlight.current || !prepared || !confirmed || !draft.name.trim()) return;
    const password = authType === 'password' ? passwordInput.current?.value : undefined;
    if (authType === 'password' && !password) return;
    clearPasswords();
    void run('save', async isCurrent => {
      try {
        const result = checkedList(await api.call('saveTerminalSshConnection', { id: profileId, name: draft.name.trim(), selectionToken: prepared.selectionToken,
          ...(authType === 'password' ? { password } : {}) }));
        if (isCurrent()) { setState({ ...result, status: 'ready' }); setDraft(emptyDraft()); }
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
      if (isCurrent()) { setState({ ...result, status: 'ready' }); setUnlocking(null); }
    }, '无法保存密码，请重试。');
  };
  const remove = connection => {
    if (hasActiveSessions) return;
    clearPasswords();
    void run('remove', async isCurrent => {
      const result = checkedList(await api.call('removeTerminalSshConnection', { id: profileId, connectionId: connection.id }));
      if (isCurrent()) { setState({ ...result, status: 'ready' }); setRemoving(null); }
    });
  };
  const close = () => { clearPasswords(); onClose(); };

  return <div className="terminal-new-session terminal-ssh-connections" role="dialog" aria-modal="false" aria-label={t('SSH 连接')}>
    <div className="terminal-new-session-head"><strong>{t('SSH 连接')}</strong><button className="terminal-icon-button" disabled={!!pending} onClick={close} aria-label={t('关闭')}><X size={14} /></button></div>
    <p className="terminal-ssh-note">{profileName}</p>
    {state.status === 'loading' && <p role="status" className="terminal-ssh-note">{t('正在读取 SSH 连接…')}</p>}
    {state.status === 'ready' && !state.supported && <p className="terminal-ssh-note">{t('SSH 连接目前仅支持 macOS。')}</p>}
    {state.status === 'ready' && state.supported && <>
      <p className="terminal-ssh-note">{t('已保存主机走本机出口（远端可见 IP）；未保存主机走境舱代理。')}</p>
      {authType === 'password' && <p className="terminal-ssh-note">{t('密码仅本次运行有效，退出清除。')}</p>}
      {state.connections.length === 0 && <p className="terminal-ssh-note" role="status">{t('暂无已保存主机')}</p>}
      {state.connections.length > 0 && <div className="terminal-ssh-list">{state.connections.map(connection => {
        const passwordAuth = connection.authType === 'password';
        return <div className="terminal-ssh-connection" key={connection.id}>
          <strong>{connection.name}</strong><span>{connection.user}@{connection.host}:{connection.port}</span>
          <span>{t(passwordAuth ? connection.passwordReady ? '密码已就绪' : '需先提供密码，不会改走代理。' : '私钥登录')}</span>
          <label><span>{t('连接命令')}</span><input readOnly value={`ssh ${connection.alias}`} aria-label={t('连接命令')} onFocus={event => event.currentTarget.select()} /></label>
          <details className="terminal-ssh-details"><summary>{t('连接详情')}</summary><label><span>{t('常用写法')}</span><input readOnly value={`ssh -p ${connection.port} ${connection.user}@${connection.host}`} aria-label={t('常用写法')} onFocus={event => event.currentTarget.select()} /></label><dl>{!passwordAuth && <div><dt>{connection.keyLabel}</dt><dd>{connection.keyFingerprint}</dd></div>}<div><dt>{t('主机指纹（来自本机 known_hosts）')}</dt><dd>{connection.hostFingerprints.map(value => <code key={value}>{value}</code>)}</dd></div></dl></details>
          {passwordAuth && (unlocking === connection.id ? <form className="terminal-ssh-unlock" onSubmit={event => { event.preventDefault(); unlock(connection); }}>
            <label><span>{t('密码')}</span><input ref={unlockInput} type="password" autoComplete="off" maxLength={1024} disabled={!!pending || hasActiveSessions} onChange={event => setHasUnlockPassword(!!event.currentTarget.value)} autoFocus /></label>
            <div className="terminal-new-session-actions"><button type="button" className="terminal-text-button" disabled={!!pending} onClick={() => { clearPasswords(); setUnlocking(null); }}>{t('取消')}</button><button type="submit" className="terminal-text-button terminal-start-button" disabled={!!pending || hasActiveSessions || !hasUnlockPassword}>{t(pending === 'password' ? '保存中…' : '保存密码')}</button></div>
          </form> : <button className="terminal-text-button terminal-ssh-remove-button" disabled={!!pending || hasActiveSessions} onClick={() => { clearPasswords(); setUnlocking(connection.id); setRemoving(null); }}>{t(connection.passwordReady ? '更新密码' : '提供密码')}</button>)}
          {removing === connection.id ? <div className="terminal-ssh-remove"><p>{t(passwordAuth ? '仅移除此环境的连接配置。' : '仅移除此环境的连接配置，原私钥保留。')}</p><div className="terminal-new-session-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => setRemoving(null)}>{t('取消')}</button><button className="terminal-text-button" disabled={!!pending || hasActiveSessions} onClick={() => remove(connection)}>{t('确认移除')}</button></div></div> : <button className="terminal-text-button terminal-ssh-remove-button" disabled={!!pending || hasActiveSessions} onClick={() => { clearPasswords(); setRemoving(connection.id); setUnlocking(null); }}>{t('移除连接')}</button>}
        </div>;
      })}</div>}
      <div className="terminal-ssh-fields">
        <label><span>{t('连接名称')}</span><input maxLength={80} value={draft.name} disabled={!!pending} onChange={event => setDraft(value => ({ ...value, name: event.target.value }))} /></label>
        <div className="terminal-ssh-target"><label><span>{t('主机')}</span><input autoCapitalize="none" spellCheck={false} maxLength={253} value={draft.host} disabled={!!pending} onChange={event => updateTarget('host', event.target.value)} /></label><label><span>{t('端口')}</span><input type="number" min="1" max="65535" step="1" value={draft.port} disabled={!!pending} onChange={event => updateTarget('port', event.target.value)} /></label></div>
        <label><span>{t('用户名')}</span><input autoCapitalize="none" spellCheck={false} maxLength={64} value={draft.user} disabled={!!pending} onChange={event => updateTarget('user', event.target.value)} /></label>
        <label><span>{t('登录方式')}</span><select aria-label={t('登录方式')} value={authType} disabled={!!pending} onChange={event => changeAuthType(event.target.value)}><option value="password">{t('密码登录')}</option><option value="publickey">{t('私钥登录')}</option></select></label>
        {authType === 'password' ? <>
          <label><span>{t('密码')}</span><input ref={passwordInput} type="password" autoComplete="off" maxLength={1024} disabled={!!pending || hasActiveSessions} onChange={event => setHasPassword(!!event.currentTarget.value)} /></label>
          <button className="terminal-text-button" disabled={!!pending || !validTarget} onClick={() => void chooseIdentity()}>{t(pending === 'pick' ? '正在读取指纹…' : '读取主机指纹')}</button>
        </> : <>
          <button className="terminal-text-button" disabled={!!pending || !validTarget} onClick={() => void chooseIdentity()}><Key size={14} />{t(pending === 'pick' ? '正在检查密钥…' : prepared ? '更换私钥' : '选择私钥')}</button>
        </>}
      </div>
      {prepared && <div className="terminal-ssh-identity"><dl>{authType === 'publickey' && <div><dt>{prepared.keyLabel}</dt><dd>{prepared.keyFingerprint}</dd></div>}<div><dt>{t('主机指纹（来自本机 known_hosts）')}</dt><dd>{prepared.hostFingerprints.map(value => <code key={value}>{value}</code>)}</dd></div></dl><label><input type="checkbox" checked={confirmed} disabled={!!pending} onChange={event => setConfirmed(event.target.checked)} /><span>{t(authType === 'password' ? '我已核对已信任的主机指纹' : '我已核对密钥和已信任的主机指纹')}</span></label></div>}
      <details className="terminal-ssh-help"><summary>{t('使用说明')}</summary><div>
        <p className="terminal-ssh-note">{t('让 Claude 运行 envara-ssh list，查看当前会话可用的连接。')}</p>
        <dl><dt>{t('常用写法')}</dt><dd><code>ssh user@host</code></dd></dl>
        <p className="terminal-ssh-note">{t(authType === 'password' || state.connections.some(connection => connection.authType === 'password')
          ? '密码在本次应用运行期间有效，不会定时到期，退出即清除，也不会写入命令或提供给 Claude。结束会话、线路停止或退出应用仍会关闭连接。'
          : 'SSH 密钥授权在本次应用运行期间有效，不会定时到期；结束会话、线路停止或退出应用仍会关闭连接。')}</p>
        {authType === 'publickey' && <p className="terminal-ssh-note">{t('私钥不会复制到环境。')}</p>}
        <p className="terminal-ssh-note">{t(busyMessage)}</p>
        {state.connections.length === 0 && <p className="terminal-ssh-note">{t('尚未保存 SSH 主机。保存配置不会自动连接。')}</p>}
      </div></details>
      {hasActiveSessions && <p className="terminal-ssh-note" role="status">{t(busyMessage)}</p>}
      <div className="terminal-new-session-actions"><button className="terminal-text-button terminal-start-button" aria-busy={pending === 'save' || undefined} disabled={!!pending || hasActiveSessions || !prepared || !confirmed || !draft.name.trim() || (authType === 'password' && !hasPassword)} onClick={save}>{t(pending === 'save' ? '保存中…' : '保存连接')}</button></div>
    </>}
    {error && <div className="terminal-new-session-error" role="status">{t(error)}</div>}
    {state.status === 'error' && <button className="terminal-text-button" disabled={!!pending} onClick={() => void load()}>{t('重试')}</button>}
  </div>;
}
