import React, { useEffect, useRef, useState } from 'react';
import { Key, X } from '@phosphor-icons/react';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';

const emptyDraft = () => ({ name: '', host: '', port: '22', user: '' });
const busyMessage = '请先关闭此环境的终端会话，再保存或移除 SSH 连接。更改在新会话中生效。';
const sshErrors = {
  SSH_UNSUPPORTED: 'SSH 连接目前仅支持 macOS。',
  SSH_INVALID_INPUT: '请检查连接名称、主机、端口和用户名。',
  SSH_UNSAFE_PATH: '无法安全读取所选密钥，请重新选择。',
  SSH_PUBLIC_KEY_REQUIRED: '所选私钥旁需要有对应的 .pub 公钥文件。',
  SSH_KEY_INVALID: '所选 SSH 密钥无效或格式不受支持。',
  SSH_HOST_UNTRUSTED: '本机 known_hosts 没有匹配的可信主机记录，无法保存此连接。',
  SSH_IDENTITY_CHANGED: '密钥或主机信任记录已改变，请重新选择并核对。',
  SSH_SELECTION_EXPIRED: '所选 SSH 密钥已失效，请重新选择。',
  SSH_SELECTION_MISMATCH: '所选 SSH 密钥不属于当前窗口或环境，请重新选择。',
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
  return value;
}

/** Environment connections are available to both shell and Claude sessions.
 * Only public identity metadata and a one-use picker token enter this view. */
export function TerminalSshConnections({ profileId, profileName, hasActiveSessions, onClose }) {
  const { t } = useI18n();
  const [state, setState] = useState({ status: 'loading', supported: false, connections: [] });
  const [draft, setDraft] = useState(emptyDraft);
  const [prepared, setPrepared] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [pending, setPending] = useState('');
  const [error, setError] = useState('');
  const mounted = useRef(false), inFlight = useRef(false);

  const load = async () => {
    setError(''); setState(value => ({ ...value, status: 'loading' }));
    try {
      const result = checkedList(await api.call('listTerminalSshConnections', { id: profileId }));
      if (mounted.current) setState({ ...result, status: 'ready' });
    } catch (failure) {
      if (mounted.current) { setState(value => ({ ...value, status: 'error' })); setError(sshErrors[failure.code] || '无法读取 SSH 连接，请重试。'); }
    }
  };
  useEffect(() => {
    mounted.current = true;
    void load();
    return () => { mounted.current = false; };
  }, [profileId]);

  const run = async (action, operation) => {
    if (inFlight.current) return;
    inFlight.current = true; setPending(action); setError('');
    try { await operation(); }
    catch (failure) { if (mounted.current) setError(sshErrors[failure.code] || '无法更新 SSH 连接，请重试。'); }
    finally { inFlight.current = false; if (mounted.current) setPending(''); }
  };
  const updateTarget = (field, value) => {
    setDraft(current => ({ ...current, [field]: value }));
    setPrepared(null); setConfirmed(false); setError('');
  };
  const validTarget = draft.host.trim() && draft.user.trim() && Number.isInteger(Number(draft.port)) && Number(draft.port) >= 1 && Number(draft.port) <= 65535;
  const chooseIdentity = () => run('pick', async () => {
    const result = await api.call('prepareTerminalSshIdentity', { id: profileId, host: draft.host.trim(), port: Number(draft.port), user: draft.user.trim() });
    if (!mounted.current || result?.canceled) return;
    if (typeof result?.selectionToken !== 'string' || typeof result.keyFingerprint !== 'string' || !Array.isArray(result.hostFingerprints) || !result.hostFingerprints.length) throw new Error();
    setPrepared(result); setConfirmed(false);
  });
  const save = () => {
    if (hasActiveSessions || !prepared || !confirmed || !draft.name.trim()) return;
    void run('save', async () => {
      try {
        const result = checkedList(await api.call('saveTerminalSshConnection', { id: profileId, name: draft.name.trim(), selectionToken: prepared.selectionToken }));
        if (mounted.current) { setState({ ...result, status: 'ready' }); setDraft(emptyDraft()); }
      } finally {
        // Saving consumes the picker capability even when validation fails.
        if (mounted.current) { setPrepared(null); setConfirmed(false); }
      }
    });
  };
  const remove = connection => {
    if (hasActiveSessions) return;
    void run('remove', async () => {
      const result = checkedList(await api.call('removeTerminalSshConnection', { id: profileId, connectionId: connection.id }));
      if (mounted.current) { setState({ ...result, status: 'ready' }); setRemoving(null); }
    });
  };

  return <div className="terminal-new-session terminal-ssh-connections" role="dialog" aria-modal="false" aria-label={t('SSH 连接')}>
    <div className="terminal-new-session-head"><strong>{t('SSH 连接')}</strong><button className="terminal-icon-button" disabled={!!pending} onClick={onClose} aria-label={t('关闭')}><X size={14} /></button></div>
    <p className="terminal-ssh-note">{profileName}</p>
    {state.status === 'loading' && <p role="status" className="terminal-ssh-note">{t('正在读取 SSH 连接…')}</p>}
    {state.status === 'ready' && !state.supported && <p className="terminal-ssh-note">{t('SSH 连接目前仅支持 macOS。')}</p>}
    {state.status === 'ready' && state.supported && <>
      <p className="terminal-ssh-note">{t('通过环境代理连接；私钥不复制到环境。')}</p>
      <p className="terminal-ssh-note">{t('SSH 密钥授权有效 1 小时；过期后请新建终端会话。')}</p>
      {state.connections.length > 0 && <div className="terminal-ssh-list">{state.connections.map(connection => <div className="terminal-ssh-connection" key={connection.id}>
        <strong>{connection.name}</strong><span>{connection.user}@{connection.host}:{connection.port}</span>
        <label><span>{t('连接命令')}</span><input readOnly value={`ssh ${connection.alias}`} aria-label={t('连接命令')} onFocus={event => event.currentTarget.select()} /></label>
        <details><summary>{t('密钥与主机指纹')}</summary><dl><div><dt>{connection.keyLabel}</dt><dd>{connection.keyFingerprint}</dd></div><div><dt>{t('主机指纹（来自本机 known_hosts）')}</dt><dd>{connection.hostFingerprints.map(value => <code key={value}>{value}</code>)}</dd></div></dl></details>
        {removing === connection.id ? <div className="terminal-ssh-remove"><p>{t('仅移除此环境的连接配置，原私钥保留。')}</p><div className="terminal-new-session-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => setRemoving(null)}>{t('取消')}</button><button className="terminal-text-button" disabled={!!pending || hasActiveSessions} onClick={() => remove(connection)}>{t('确认移除')}</button></div></div> : <button className="terminal-text-button terminal-ssh-remove-button" disabled={!!pending || hasActiveSessions} onClick={() => setRemoving(connection.id)}>{t('移除连接')}</button>}
      </div>)}</div>}
      <div className="terminal-ssh-fields">
        <label><span>{t('连接名称')}</span><input maxLength={80} value={draft.name} disabled={!!pending} onChange={event => setDraft(value => ({ ...value, name: event.target.value }))} /></label>
        <div className="terminal-ssh-target"><label><span>{t('主机')}</span><input autoCapitalize="none" spellCheck={false} maxLength={253} value={draft.host} disabled={!!pending} onChange={event => updateTarget('host', event.target.value)} /></label><label><span>{t('端口')}</span><input type="number" min="1" max="65535" step="1" value={draft.port} disabled={!!pending} onChange={event => updateTarget('port', event.target.value)} /></label></div>
        <label><span>{t('用户名')}</span><input autoCapitalize="none" spellCheck={false} maxLength={64} value={draft.user} disabled={!!pending} onChange={event => updateTarget('user', event.target.value)} /></label>
        <button className="terminal-text-button" disabled={!!pending || !validTarget} onClick={() => void chooseIdentity()}><Key size={14} />{t(pending === 'pick' ? '正在检查密钥…' : prepared ? '更换私钥' : '选择私钥')}</button>
      </div>
      {prepared && <div className="terminal-ssh-identity"><dl><div><dt>{prepared.keyLabel}</dt><dd>{prepared.keyFingerprint}</dd></div><div><dt>{t('主机指纹（来自本机 known_hosts）')}</dt><dd>{prepared.hostFingerprints.map(value => <code key={value}>{value}</code>)}</dd></div></dl><label><input type="checkbox" checked={confirmed} disabled={!!pending} onChange={event => setConfirmed(event.target.checked)} /><span>{t('我已核对密钥和已信任的主机指纹')}</span></label></div>}
      <p className="terminal-ssh-note" role={hasActiveSessions ? 'status' : undefined}>{t(hasActiveSessions ? busyMessage : '保存后请新建终端会话。普通终端和 Claude 会话共用这些连接。')}</p>
      <div className="terminal-new-session-actions"><button className="terminal-text-button terminal-start-button" aria-busy={pending === 'save' || undefined} disabled={!!pending || hasActiveSessions || !prepared || !confirmed || !draft.name.trim()} onClick={save}>{t(pending === 'save' ? '保存中…' : '保存连接')}</button></div>
    </>}
    {error && <div className="terminal-new-session-error" role="status">{t(error)}</div>}
    {state.status === 'error' && <button className="terminal-text-button" disabled={!!pending} onClick={() => void load()}>{t('重试')}</button>}
  </div>;
}
