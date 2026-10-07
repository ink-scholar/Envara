import React, { useCallback, useEffect, useState } from 'react';
import { TerminalWindow, WarningCircle, ArrowsClockwise } from '@phosphor-icons/react';
import { api } from './client.js';
import { TerminalDock } from './TerminalPane.jsx';

/** A terminal view attaches to an existing environment; it never spawns on load. */
export function TerminalWindowApp({ profileId, sessionId }) {
  const [snapshot,setSnapshot] = useState(null);
  const [error,setError] = useState('');
  const [loading,setLoading] = useState(true);
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
  useEffect(()=>{document.title=profile?`${profile.name} · 终端 · Envara`:'终端 · Envara';},[profile?.name]);
  const reportError=useCallback((message)=>setError(message),[]);
  const request=profile?{profileId:profile.id,sessionId,nonce:'window-initial'}:null;
  return <main className={`terminal-window-shell ${api.isDesktop?'is-desktop':''}`} aria-label="独立终端窗口">
    {api.isDesktop&&<div className="desktop-titlebar" aria-hidden="true"/>}
    <header className="terminal-window-heading"><TerminalWindow size={20}/><div><h1>{profile?.name||'环境终端'}</h1><p>独立会话，共用此环境的工具配置与历史</p></div>{!api.isDesktop&&<span className="preview-badge">界面预览</span>}</header>
    {error&&<div className="terminal-window-error" role="status"><WarningCircle size={17}/><span>{error}</span><button onClick={()=>setError('')} aria-label="关闭提示">关闭</button></div>}
    {profile?<TerminalDock standalone profiles={[profile]} visible openRequest={request} onError={reportError}/>:<div className="terminal-window-unavailable"><TerminalWindow size={32}/><h2>{loading?'正在读取环境…':profileId?'当前环境不可用':'未指定终端环境'}</h2><p>{loading?'终端不会自动启动新的进程。':profileId?'环境可能已被删除。请返回境舱选择有效环境。':'请从境舱环境详情打开独立终端窗口。'}</p>{!loading&&profileId&&<button className="button" onClick={()=>{setLoading(true);void refresh();}}><ArrowsClockwise size={16}/>重新读取</button>}</div>}
  </main>;
}
