import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { TerminalWindow, WarningCircle, ArrowsClockwise } from '@phosphor-icons/react';
import { api } from './client.js';
import { TerminalDock } from './TerminalPane.jsx';
import { SshWorkspace } from './TerminalSshConnections.jsx';
import { useI18n } from './i18n.jsx';
import './terminal-window.css';

/** A terminal view attaches to an existing environment; it never spawns on load. */
export function TerminalWindowApp({ profileId, sessionId }) {
  const { t } = useI18n();
  const [snapshot,setSnapshot] = useState(null);
  const [error,setError] = useState('');
  const [loading,setLoading] = useState(true);
  const [view,setView] = useState('terminal');
  const [terminalProfiles,setTerminalProfiles] = useState([]);
  const acceptSnapshot=useCallback((value)=>{
    if(!Array.isArray(value?.profiles))return false;
    setSnapshot(value);
    setLoading(false);
    return true;
  },[]);
  const refresh=useCallback(async()=>{
    setError('');
    try{acceptSnapshot(await api.call('snapshot'));}
    catch(failure){setError(failure.message||'无法读取环境，请重试。');setLoading(false);}
  },[acceptSnapshot]);
  useEffect(()=>{
    void refresh();
    return api.subscribe((value)=>{if(!acceptSnapshot(value))void refresh();});
  },[acceptSnapshot,refresh]);
  const profile=snapshot?.profiles.find((item)=>item.id===profileId);
  useEffect(()=>{document.title=profile?t('{name} · 终端 · Envara', { name: profile.name }):t('终端 · Envara');},[profile?.name,t]);
  const reportError=useCallback((message)=>setError(message),[]);
  const request=useMemo(()=>profile?{profileId:profile.id,sessionId,nonce:'window-initial'}:null,[profile?.id,sessionId]);
  const navigateView = (event, current) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 'terminal' : event.key === 'End' ? 'ssh' : current === 'terminal' ? 'ssh' : 'terminal';
    setView(next);
    document.getElementById(`terminal-window-tab-${next}`)?.focus();
  };
  return <main className={`terminal-window-shell terminal-window-workspace ${api.isDesktop?'is-desktop':''}`} aria-label={t('独立终端窗口')}>
    {api.isDesktop&&<div className="desktop-titlebar" aria-hidden="true"/>}
    <header className="terminal-window-heading terminal-window-workspace-heading"><h1 title={profile?.name}>{profile?.name||t('环境终端')}</h1><div className="terminal-window-view-tabs" role="tablist" aria-label={t('工作区')}>
      {['terminal', 'ssh'].map(target=><button key={target} id={`terminal-window-tab-${target}`} type="button" role="tab" aria-selected={view===target} aria-controls={`terminal-window-panel-${target}`} tabIndex={view===target?0:-1} disabled={!profile} onClick={()=>setView(target)} onKeyDown={event=>navigateView(event,target)}>{t(target==='terminal'?'终端':'SSH 连接')}</button>)}
    </div></header>
    {error&&<div className="terminal-window-error" role="status"><WarningCircle size={17}/><span>{t(error)}</span><button onClick={()=>setError('')} aria-label={t('关闭提示')}>{t('关闭')}</button></div>}
    {profile?<>
      <section id="terminal-window-panel-terminal" className="terminal-window-terminal-panel" role="tabpanel" aria-labelledby="terminal-window-tab-terminal" hidden={view!=='terminal'}><TerminalDock standalone profiles={[profile]} screenReaderMode={snapshot.system?.accessibilitySupportEnabled === true} visible={view==='terminal'} openRequest={request} onError={reportError} onProfilesChange={setTerminalProfiles}/></section>
      {view==='ssh'&&<section id="terminal-window-panel-ssh" className="terminal-window-ssh-panel" role="tabpanel" aria-labelledby="terminal-window-tab-ssh"><SshWorkspace profiles={[profile]} selectedId={profile.id} terminalProfiles={terminalProfiles} onOpenTerminal={id=>{if(id===profile.id)setView('terminal');}}/></section>}
    </>:<div className="terminal-window-unavailable"><TerminalWindow size={32}/><h2>{t(loading?'正在读取环境…':profileId?'当前环境不可用':'未指定终端环境')}</h2><p>{t(loading?'终端不会自动启动新的进程。':profileId?'环境可能已被删除。请返回境舱选择有效环境。':'请从境舱环境详情打开独立终端窗口。')}</p>{!loading&&profileId&&<button className="button" onClick={()=>{setLoading(true);void refresh();}}><ArrowsClockwise size={16}/>{t('重新读取')}</button>}</div>}
  </main>;
}
