import React, { useState } from "react";
import { Stack, GlobeHemisphereWest, FolderOpen, Plus, Play, Stop, Trash, Desktop, ShieldCheck, WarningCircle, ArrowRight, PencilSimple, Browsers, TerminalWindow, Clock } from "@phosphor-icons/react";
const live = new Set(["starting", "running", "stopping"]);
function WorkspaceEmpty({
  icon: Icon = Stack,
  title,
  action,
  onAction,
  t
}) {
  return <div className="workspace-empty">
    <div className="empty-icon"><Icon size={30} weight="duotone" /></div>
    <h2>{t(title)}</h2>
    {action && <button className="button primary" onClick={onAction}><Plus size={16} />{t(action)}</button>}
  </div>;
}
export function EnvironmentOverview({
  profiles,
  proxies,
  selectedId,
  onSelect,
  checkedIds,
  onToggleChecked,
  onToggleAll,
  allChecked,
  loading,
  onCreate,
  onEdit,
  t,
  hasProfiles,
  onReset
}) {
  if (loading) return <div className="table-loading">{t("正在读取环境…")}</div>;
  if (!profiles.length) return <WorkspaceEmpty title={hasProfiles ? "没有匹配的环境" : "创建你的第一个环境"} action={hasProfiles ? "显示全部" : "新建环境"} onAction={hasProfiles ? onReset : onCreate} t={t} />;
  return <div className="environment-table common-environment-table">
    <div className="table-head common-profile-grid">
      <input type="checkbox" className="row-checkbox" checked={allChecked} ref={input => {if (input) input.indeterminate = !allChecked && profiles.some(profile => checkedIds.includes(profile.id));}} onChange={onToggleAll} aria-label={t("选择全部环境")} />
      <span>{t("名称")}</span><span>{t("网络出口")}</span><span>{t("地区与时区")}</span><span>{t("工作目录")}</span><span />
    </div>
    {profiles.map(profile => {
      const proxy = proxies.find(item => item.id === profile.proxyId);
      const network = profile.network?.ok ? profile.network : proxy?.network?.ok ? proxy.network : null;
      const location = [network?.country || network?.countryCode, network?.city].filter(Boolean).join(" · ");
      return <div className={`profile-row common-profile-grid ${selectedId === profile.id ? "selected" : ""}`} key={profile.id} onClick={() => onSelect(profile.id)}>
        <input className="row-checkbox" type="checkbox" checked={checkedIds.includes(profile.id)} aria-label={t("选择 {name}", {
          name: profile.name
        })} onClick={event => event.stopPropagation()} onChange={() => onToggleChecked(profile.id)} />
        <button className="profile-open cell-stack" onClick={() => onSelect(profile.id)} aria-pressed={selectedId === profile.id}><strong>{profile.name}</strong><small>{profile.group || t("未分组")}</small></button>
        <span className="cell-stack"><span>{proxy?.name || t("本机网络")}</span><small>{network?.ip || t("出口待识别")}</small></span>
        <span className="cell-stack"><span>{location || t("启动时自动匹配")}</span><small>{profile.resolvedTimezone || network?.timezone || profile.timezone || t("自动时区")}</small></span>
        <span className="cell-stack workspace-directory-cell" title={profile.workspace?.cwd || profile.cwd || ""}><span>{profile.workspace?.cwd || profile.cwd || t("尚未选择")}</span><small>{t("配置与历史独立")}</small></span>
        <button className="icon-button" aria-label={t("编辑环境")} onClick={event => {
          event.stopPropagation();
          onEdit(profile);
        }}><PencilSimple size={17} /></button>
      </div>;
    })}
  </div>;
}
export function ContextDetail({
  profile,
  proxy,
  workspace,
  onEdit,
  onDirectory,
  directoryDisabled,
  onNavigate,
  onClone,
  onExport,
  onDelete,
  editingDisabled,
  t
}) {
  if (!profile) return <div className="detail-empty"><Stack size={32} /><h2>{t("环境详情")}</h2><p>{t("选择一个环境")}</p></div>;
  const network = profile.network?.ok ? profile.network : proxy?.network?.ok ? proxy.network : null;
  return <>
    <div className="detail-heading"><h2>{profile.name}</h2><p>{profile.group || t("未分组")}</p></div>
    <div className="context-network-card"><div className="context-card-icon"><GlobeHemisphereWest size={23} /></div><strong>{proxy?.name || t("本机网络")}</strong><span>{network?.ip || t("出口待识别")}</span>{network && <small>{[network.country || network.countryCode, network.city].filter(Boolean).join(" · ")}</small>}</div>
    <dl className="detail-properties compact-context-properties">
      <div><dt>{t("时区")}</dt><dd>{profile.timezone || profile.resolvedTimezone || network?.timezone || t("启动时自动匹配")}</dd></div>
      <div><dt>{t("定位")}</dt><dd>{network ? [network.country || network.countryCode, network.city].filter(Boolean).join(" · ") || t("待识别") : t("跟随网络出口")}</dd></div>
      <div><dt>{t("语言")}</dt><dd>{profile.locale || t("跟随网络出口")}</dd></div>
      <div><dt>{t("隐私防护")}</dt><dd>{t({
            standard: "标准",
            strict: "严格",
            off: "停用"
          }[profile.privacy?.mode || "standard"])}</dd></div>
    </dl>
    <div className="context-directory"><span>{t("工作目录")}</span><strong title={workspace?.cwd || profile.workspace?.cwd || ""}>{workspace?.cwd || profile.workspace?.cwd || t("尚未选择")}</strong><button className="button" disabled={directoryDisabled} onClick={onDirectory}><FolderOpen size={15} />{t(workspace?.cwd ? "更换目录" : "选择目录")}</button></div>
    <div className="context-launches">
      {[["browsers", "浏览器"], ["terminals", "终端"], ["applications", "附加软件"]].map(([page, label]) => <button key={page} onClick={() => onNavigate(page)}><span>{t(label)}</span><ArrowRight size={16} /></button>)}
    </div>
    <div className="detail-actions"><button className="button" disabled={editingDisabled} onClick={onEdit}>{t("编辑")}</button><button className="button" onClick={onClone}>{t("克隆")}</button><button className="button" onClick={onExport}>{t("导出")}</button></div>
    <div className="danger-actions"><button disabled={editingDisabled} onClick={onDelete}>{t("删除环境…")}</button></div>
  </>;
}
export function ApplicationsWorkspace({
  profiles,
  proxies,
  applications = [],
  routing,
  selectedId,
  onSelect,
  onPick,
  onStart,
  onStop,
  onDelete,
  onSetup,
  pending,
  t,
  desktop
}) {
  const [tab, setTab] = useState("environment");
  const profile = profiles.find(item => item.id === selectedId);
  const selectedProxy = proxies.find(item => item.id === profile?.proxyId);
  const rows = tab === "all" ? applications : applications.filter(item => item.profileId === selectedId);
  const ready = routing?.ready === true;
  return <div className="applications-workspace">
    <div className="application-context-strip">
      <label><span>{t("境舱")}</span><select value={selectedId || ""} onChange={event => onSelect(event.target.value)} aria-label={t("选择境舱")} disabled={!profiles.length}><option value="" disabled>{t("选择境舱")}</option>{profiles.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <div className="application-network"><GlobeHemisphereWest size={17} /><span>{selectedProxy?.name || t("本机网络")}</span></div>
      <button className="button primary" onClick={onPick} disabled={!desktop || !profile || pending["pickApplication:"] || pending["saveApplication:"]}><Plus size={16} />{t("添加本地软件")}</button>
    </div>
    {!ready && <div className="routing-readiness" role="status"><ShieldCheck size={19} /><div><strong>{t(!desktop ? "本地软件需要桌面应用" : routing?.status === "authorization-required" ? "需要系统授权" : "网络接管尚未就绪")}</strong><span>{t(routing?.message || "完成系统网络组件安装后，才能启动附加软件。")}</span></div>{desktop && <button className="button" onClick={onSetup} disabled={pending["setupApplicationRouting:"]}>{t(pending["setupApplicationRouting:"] ? "检查中…" : "检查系统组件")}</button>}</div>}
    {ready && <div className="routing-ready"><ShieldCheck size={16} /><span>{t("网络接管已就绪")}</span></div>}
    <div className="workspace-segments"><button className={tab === "environment" ? "selected" : ""} onClick={() => setTab("environment")}>{t("当前境舱")}</button><button className={tab === "all" ? "selected" : ""} onClick={() => setTab("all")}>{t("全部软件")}<span>{applications.length}</span></button></div>
    {rows.length ? <div className="application-list">{rows.map(application => {
        const owner = profiles.find(item => item.id === application.profileId);
        const active = live.has(application.status);
        const busy = pending[`startApplication:${application.id}`] || pending[`stopApplication:${application.id}`] || pending[`deleteApplication:${application.id}`];
        return <div className="application-row" key={application.id}>
        <div className="application-icon"><Desktop size={24} /></div>
        <div className="application-copy"><strong>{application.name}</strong><span>{owner?.name || t("环境不可用")}</span><small title={application.path}>{application.path}</small>{application.lastError && <p className="application-error"><WarningCircle size={14} />{t(typeof application.lastError === "string" ? application.lastError : application.lastError.message)}</p>}</div>
        <span className={`status status-${application.status}`}><span className="status-dot" />{t({
              stopped: "已停止",
              starting: "启动中",
              running: "运行中",
              stopping: "停止中",
              error: "异常"
            }[application.status] || application.status)}</span>
        <div className="application-actions"><button className={`button ${active ? "" : "primary"}`} disabled={busy || (active ? application.status !== "running" : !ready || !owner)} onClick={() => active ? onStop(application) : onStart(application)}>{active ? <Stop size={15} /> : <Play size={15} />}{t(active ? "停止" : "启动")}</button><button className="icon-button" disabled={active || busy} onClick={() => onDelete(application)} aria-label={t("移除软件")}><Trash size={17} /></button></div>
      </div>;
      })}</div> : <WorkspaceEmpty icon={Desktop} title={profile ? "添加软件到这个境舱" : "先创建一个环境"} action={desktop && profile ? "添加本地软件" : undefined} onAction={onPick} t={t} />}
  </div>;
}
export function MonitorWorkspace({
  profiles,
  terminalProfiles,
  applications,
  events,
  onNavigate,
  t,
  language
}) {
  const browsers = profiles.filter(profile => ["running", "starting"].includes(profile.status));
  const terminals = terminalProfiles.flatMap(profile => (profile.sessions || []).filter(session => ["running", "starting", "closing"].includes(session.status)).map(session => ({
    ...session,
    profileId: profile.profileId
  })));
  const apps = applications.filter(application => live.has(application.status));
  const categories = [{
    id: "browsers",
    label: "浏览器",
    icon: Browsers,
    rows: browsers.map(profile => ({
      id: profile.id,
      name: profile.name,
      status: profile.status,
      detail: profile.engine
    }))
  }, {
    id: "terminals",
    label: "终端",
    icon: TerminalWindow,
    rows: terminals.map((session, index) => ({
      id: session.sessionId,
      name: profiles.find(profile => profile.id === session.profileId)?.name || t("环境不可用"),
      status: session.status,
      detail: `${t("会话")} ${index + 1}`
    }))
  }, {
    id: "applications",
    label: "附加软件",
    icon: Desktop,
    rows: apps.map(application => ({
      id: application.id,
      name: application.name,
      status: application.status,
      detail: profiles.find(profile => profile.id === application.profileId)?.name
    }))
  }];
  return <div className="monitor-content">
    <div className="monitor-summary">{categories.map(({
        id,
        label,
        icon: Icon,
        rows
      }) => <div key={id}><span><Icon size={19} />{t(label)}</span><strong>{rows.length}<small>{t("运行中")}</small></strong></div>)}</div>
    <div className="section-heading"><h2>{t("正在运行")}</h2></div>
    <div className="monitor-runtime-list">{categories.flatMap(({
        id,
        icon: Icon,
        rows
      }) => rows.map(row => <div className="monitor-runtime-row" key={`${id}:${row.id}`}><Icon size={22} /><div><strong>{row.name}</strong><span>{row.detail}</span></div><span className={`status status-${row.status}`}><span className="status-dot" />{t({
            running: "运行中",
            starting: "启动中",
            stopping: "停止中",
            closing: "关闭中"
          }[row.status] || row.status)}</span><button className="button" onClick={() => onNavigate(id)}>{t("查看")}</button></div>))}{!browsers.length && !terminals.length && !apps.length && <div className="empty-activity">{t("当前没有运行中的会话")}</div>}</div>
    <div className="section-heading activity-heading"><h2>{t("运行记录")}</h2></div>
    <div className="activity-list">{events.length ? [...events].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 80).map(event => <div className="activity-row" key={event.id}><span className={`activity-dot ${event.type === "error" ? "failure" : ""}`} /><span className="activity-message">{t(event.message)}</span><time>{new Date(event.time).toLocaleTimeString(language === "en" ? "en-US" : "zh-CN", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
          })}</time></div>) : <div className="empty-activity"><Clock size={20} />{t("暂无运行记录")}</div>}</div>
  </div>;
}
