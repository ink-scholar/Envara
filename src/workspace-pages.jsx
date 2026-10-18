import React, { useEffect, useState } from "react";
import { SYSTEM_BROWSER, linkBrowserChoice } from "./link-browser.mjs";
import { localeForInterfaceLanguage } from "../shared/interface-languages.mjs";
import { savedNetworkPresentation } from "./network-flow-state.mjs";
import { ProxyCompatibilityDetails } from "./proxy-compatibility.mjs";
import { notionTrialControls, notionTrialLogLine, notionTrialTimingLine, notionTrialFailureLine, notionTrialErrorHint, attachedApplicationStatus, safeNotionTrial } from "./notion-trial-state.mjs";
import { Stack, GlobeHemisphereWest, FolderOpen, Plus, Play, Stop, Trash, Desktop, ShieldCheck, WarningCircle, ArrowRight, PencilSimple, Browsers, TerminalWindow, Clock, Info, ArrowSquareOut, CaretRight, DownloadSimple } from "@phosphor-icons/react";
import { ApplicationIcon } from "./ApplicationIcon.jsx";
import { supportsAttachedApplication, canDeleteApplicationData } from "./application-capability.mjs";
const live = new Set(["starting", "running", "stopping"]);
const networkLocation = network => [network?.country || network?.countryCode, network?.city].filter(Boolean).join(" · ");
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
  onEdit,
  t,
  hasProfiles,
  onReset
}) {
  if (loading) return <div className="table-loading">{t("正在读取环境…")}</div>;
  if (!profiles.length) return <WorkspaceEmpty title={hasProfiles ? "没有匹配的环境" : "创建你的第一个环境"} action={hasProfiles ? "显示全部" : undefined} onAction={onReset} t={t} />;
  return <div className="environment-table common-environment-table">
    <div className="table-head common-profile-grid">
      <input type="checkbox" className="row-checkbox" checked={allChecked} ref={input => {if (input) input.indeterminate = !allChecked && profiles.some(profile => checkedIds.includes(profile.id));}} onChange={onToggleAll} aria-label={t("选择全部环境")} />
      <span>{t("名称")}</span><span>{t("网络出口")}</span><span>{t("地区与时区")}</span><span>{t("工作目录")}</span><span />
    </div>
    {profiles.map(profile => {
      const proxy = proxies.find(item => item.id === profile.proxyId);
      const presentation = savedNetworkPresentation(profile, proxy);
      const { network } = presentation;
      const location = proxy?.location?.confirmed ? proxy.location.label : networkLocation(network);
      return <div className={`profile-row common-profile-grid ${selectedId === profile.id ? "selected" : ""}`} key={profile.id} onClick={() => onSelect(profile.id)}>
        <input className="row-checkbox" type="checkbox" checked={checkedIds.includes(profile.id)} aria-label={t("选择 {name}", {
          name: profile.name
        })} onClick={event => event.stopPropagation()} onChange={() => onToggleChecked(profile.id)} />
        <button className="profile-open cell-stack" onClick={() => onSelect(profile.id)} aria-pressed={selectedId === profile.id} title={profile.name}><strong>{profile.name}</strong>{profile.group ? <small title={profile.group}>{profile.group}</small> : null}</button>
        <span className="cell-stack"><span>{proxy?.name || t("本机网络")}</span><small>{network?.ip || t("待检测")}</small></span>
        <span className="cell-stack"><span>{location || t("启动时自动匹配")}</span><small>{presentation.timezone || network?.timezone || t("自动时区")}{presentation.savedOnly ? ` · ${t("已保存配置")}` : ""}</small></span>
        <span className="cell-stack workspace-directory-cell" title={profile.workspace?.cwd || profile.cwd || ""}><span>{profile.workspace?.cwd || profile.cwd || t("选择目录")}</span></span>
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
  onDelete,
  editingDisabled,
  t
}) {
  if (!profile) return <div className="detail-empty"><Stack size={32} /><h2>{t("环境详情")}</h2><p>{t("选择一个环境")}</p></div>;
  const presentation = savedNetworkPresentation(profile, proxy);
  const { network } = presentation;
  const location = networkLocation(network);
  const nearbyAddress = proxy?.location?.confirmed && proxy.location.mode === "ip" ? proxy.location.referenceLocation?.label : null;
  return <>
    <div className="detail-heading"><h2>{profile.name}</h2>{profile.group && <p>{profile.group}</p>}</div>
    <div className="context-network-card"><div className="context-card-icon"><GlobeHemisphereWest size={23} /></div><strong>{proxy?.name || t("本机网络")}</strong><span>{network?.ip || t("出口待识别")}</span>{network && <small>{location}</small>}</div>
    <dl className="detail-properties compact-context-properties">
      <div><dt>{t("时区")}</dt><dd>{presentation.timezone || network?.timezone || t("启动时自动匹配")}{presentation.savedOnly && <small>{t("已保存配置")}</small>}</dd></div>
      <div><dt>{t(nearbyAddress ? "附近地址" : "定位")}</dt><dd>{proxy?.location?.confirmed ? <>{nearbyAddress || proxy.location.label || t("跟随网络出口")}{nearbyAddress ? <><small>{t("仅供参考，可手动调整。")}</small><small>Photon · © OpenStreetMap contributors</small></> : <small>{t(proxy.location.mode === "ip" ? "自动定位" : "手动选择位置")}</small>}</> : network ? location || t("待识别") : t("跟随网络出口")}</dd></div>
      <div><dt>{t("语言")}</dt><dd>{profile.locale || t("跟随网络出口")}</dd></div>
      <div><dt>{t("隐私防护")}</dt><dd>{t({
            standard: "标准",
            strict: "严格",
            off: "停用"
          }[profile.privacy?.mode || "standard"])}</dd></div>
    </dl>
    <ProxyCompatibilityDetails compatibility={proxy?.compatibility} t={t} />
    <div className="context-directory"><span>{t("工作目录")}</span><strong className={workspace?.cwd || profile.workspace?.cwd ? "" : "is-empty"} title={workspace?.cwd || profile.workspace?.cwd || ""}>{workspace?.cwd || profile.workspace?.cwd || t("未选择")}</strong><button className="button" disabled={directoryDisabled} onClick={onDirectory}><FolderOpen size={15} />{t(workspace?.cwd ? "更换目录" : "选择目录")}</button></div>
    <div className="context-launches">
      {[["browsers", "浏览器"], ["terminals", "终端"], ["applications", "附加软件"]].map(([page, label]) => <button key={page} onClick={() => onNavigate(page)}><span>{t(label)}</span><ArrowRight size={16} /></button>)}
    </div>
    <div className="detail-actions"><button className="button" disabled={editingDisabled} onClick={onEdit}>{t("编辑")}</button><button className="button" onClick={onClone}>{t("克隆")}</button></div>
    <div className="danger-actions"><button disabled={editingDisabled} onClick={onDelete}>{t("删除环境…")}</button></div>
  </>;
}
/* Only a real environment-owned data directory is removable. A saved binding
 * alone does not prove that the application has isolated data. */
export function ApplicationDataPanel({ items, totalBytes, pending, onReload, onDelete, formatBytes, t }) {
  const loaded = Array.isArray(items);
  const row = item => {
    const name = item.application?.name || t("已移除的软件");
    return <div className={`sign-in-row${item.running ? " is-running" : ""}`} key={item.id}>
      {item.application?.path ? <ApplicationIcon path={item.application.path} size={34} /> : <span className="application-icon"><Desktop size={19} /></span>}
      <div className="sign-in-copy"><strong title={item.application?.path || ""}>{name}</strong>
        <span>{item.environment?.name || t("已删除的境舱")}</span></div>
      <span className="sign-in-size">{item.dataScope !== "environment" || item.hasDataDirectory !== true ? t("未生成应用数据") : item.bytes > 0 ? formatBytes(item.bytes) : t("没有应用数据")}</span>
      {item.running ? <span className="sign-in-lock">{t("停止后可删除")}</span>
        : canDeleteApplicationData(item) && <button className="icon-button" disabled={pending["deleteSignInData:" + item.id]} onClick={() => onDelete(item)} aria-label={t("删除")} title={t("删除")}><Trash size={16} /></button>}
    </div>;
  };
  return <div className="sign-in-data">
    <div className="sign-in-head"><span>{t("境舱内的软件登录、设置与本地内容。停止或移除软件不会删除。")}</span>
      {loaded && <span className="sign-in-total">{t("共 {value1}", { value1: formatBytes(totalBytes) })}</span>}
      <button className="button" onClick={onReload} disabled={pending["signInData:"]}>{t(pending["signInData:"] ? "检查中…" : "刷新")}</button></div>
    {!loaded ? <div className="table-loading">{t("正在读取…")}</div>
      : items.length ? <div className="sign-in-list">{items.map(row)}</div>
        : <WorkspaceEmpty icon={Desktop} title="没有应用数据" t={t} />}
  </div>;
}
export function ApplicationsWorkspace({
  profiles,
  proxies,
  applications = [],
  routing,
  systemPlatform,
  selectedId,
  onSelect,
  onPick,
  onStart,
  onStop,
  onRunNotionTrial,
  onStopNotionTrial,
  onShowApplicationWindow,
  onExportNotionDiagnostics,
  onExport,
  onCheckSignInData,
  onDeleteSignInData,
  onChooseLinkBrowser,
  linkCandidates,
  formatBytes,
  onDelete,
  onInstall,
  pending,
  t,
  desktop
}) {
  const [tab, setTab] = useState("environment");
  const [data, setData] = useState(null);
  /* Sign-in data is only read when its tab is opened, and re-read after a
   * delete; the page never polls the disk on its own. */
  useEffect(() => {
    if (tab !== "signInData" || typeof onCheckSignInData !== "function") return;
    let current = true;
    onCheckSignInData().then(result => { if (current && result?.ok) setData(result.result); });
    return () => { current = false; };
  }, [tab]);
  const profile = profiles.find(item => item.id === selectedId);
  const selectedProxy = proxies.find(item => item.id === profile?.proxyId);
  const rows = tab === "all" ? applications : applications.filter(item => item.profileId === selectedId);
  const ready = routing?.ready === true;
  const canInstall = desktop && routing?.backend === "pf-utun" && routing?.installed !== true && routing?.component?.available === true && routing?.component?.verified === true;
  /* An installed component that predates this app build is self-consistent, so
   * it still reports installed. The fixed carrier pin is what detects it, which
   * is why the upgrade button keys off that error rather than installed. */
  const staleComponent = desktop && routing?.backend === "pf-utun" && routing?.controlledNotionTrialErrorCode === "PF_INSTALLED_CANDIDATE_MISMATCH";
  const canUpgrade = staleComponent && routing?.component?.available === true && routing?.component?.verified === true;
  const startable = desktop && routing?.controlledNotionTrialAvailable === true;
  return <div className="applications-workspace">
    <div className="application-context-strip">
      <label><span>{t("境舱")}</span><select value={selectedId || ""} onChange={event => onSelect(event.target.value)} aria-label={t("选择境舱")} disabled={!profiles.length}><option value="" disabled>{t("选择境舱")}</option>{profiles.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <div className="application-network"><GlobeHemisphereWest size={17} /><span>{selectedProxy?.name || t("本机网络")}</span></div>
      <button className="button primary" onClick={onPick} disabled={!desktop || pending["attachApplication:"]}><Plus size={16} />{t("添加软件")}</button>
    </div>
    {/* While software can start there is nothing to say here. Only a state that
       * stops it from starting is shown, with the action that resolves it. */}
    {!ready && !startable && <div className="routing-readiness" role="status"><ShieldCheck size={17} /><strong>{t(!desktop ? "本地软件需要桌面应用" : routing?.status === "prepared" ? "网络组件已准备" : routing?.status === "authorization-required" ? "需要系统授权" : "网络接管尚未就绪")}</strong><span>{t(routing?.message || "完成系统网络组件安装后，才能启动附加软件。")}</span>{canUpgrade && <button className="button primary" title={t("已安装的网络组件早于当前应用版本，需要更新后才能附加软件。")} onClick={onInstall} disabled={pending["setupApplicationRouting:"]}>{t(pending["setupApplicationRouting:"] ? "更新中…" : "更新网络组件")}</button>}{canInstall && <button className="button" onClick={onInstall} disabled={pending["setupApplicationRouting:"]}>{t(pending["setupApplicationRouting:"] ? "安装中…" : "安装网络组件")}</button>}</div>}
    <div className="workspace-segments"><button className={tab === "environment" ? "selected" : ""} onClick={() => setTab("environment")}>{t("当前境舱")}</button><button className={tab === "all" ? "selected" : ""} onClick={() => setTab("all")}>{t("全部软件")}<span>{applications.length}</span></button>{desktop && typeof onCheckSignInData === "function" && <button className={tab === "signInData" ? "selected" : ""} onClick={() => setTab("signInData")}>{t("应用数据")}</button>}</div>
    {tab === "signInData" ? <ApplicationDataPanel items={data?.items} totalBytes={data?.totalBytes ?? 0} pending={pending} formatBytes={formatBytes} t={t}
      onReload={async () => { const result = await onCheckSignInData(); if (result?.ok) setData(result.result); }}
      onDelete={item => onDeleteSignInData(item, async () => { const result = await onCheckSignInData(); if (result?.ok) setData(result.result); })} />
      : rows.length ? <div className="application-list">{rows.map(application => {
        const owner = profiles.find(item => item.id === application.profileId);
        const ownerNetwork = proxies.find(item => item.id === owner?.proxyId);
        const active = live.has(application.status);
        const controlled = notionTrialControls(application, routing, desktop, pending);
        const diagnostics = controlled.trial?.events.length > 0 ? controlled.trial : controlled.history;
        const historicalDiagnostics = diagnostics != null && diagnostics === controlled.history;
        const capabilityError = desktop && typeof application.identity === "string" && application.identity && !controlled.available && typeof routing?.controlledNotionTrialErrorCode === "string" && /^PF_[A-Z0-9_]{1,80}$/.test(routing.controlledNotionTrialErrorCode) ? routing.controlledNotionTrialErrorCode : null;
        const trialHint = notionTrialErrorHint(controlled.trial?.errorCode ?? diagnostics?.initialFailure?.code);
        const busy = pending[`startApplication:${application.id}`] || pending[`stopApplication:${application.id}`] || pending[`deleteApplication:${application.id}`] || controlled.active || controlled.stopPending;
        /* An application with an environment flow starts, runs and stops through
         * that flow; the row's one button is its start and stop. */
        const inEnvironment = controlled.show;
        const rowStatus = inEnvironment ? attachedApplicationStatus(controlled) : application.status;
        const rowLive = inEnvironment ? live.has(rowStatus) : active;
        const cleanupRetryable = inEnvironment && controlled.trial?.cleanupRetryable === true;
        const rowStoppable = rowLive || cleanupRetryable;
        const supported = supportsAttachedApplication(application, systemPlatform);
        // Only a start that did not complete explains itself; a running row needs no text.
        const issue = inEnvironment && !rowLive && Boolean(controlled.trial?.errorCode || diagnostics?.initialFailure || diagnostics?.cleanupFailure);
        return <div className={`application-row${issue ? " has-issue" : ""}`} key={application.id}>
          <div className="application-main">
            {inEnvironment && rowStatus === "running" && typeof onShowApplicationWindow === "function"
              ? <button type="button" className="application-icon-button" onClick={() => onShowApplicationWindow(application)} title={t("打开窗口")} aria-label={t("打开窗口")}><ApplicationIcon path={application.path} /></button>
              : <ApplicationIcon path={application.path} />}
            <div className="application-copy"><strong title={application.path}>{application.name}</strong><span>{owner ? [owner.name, ownerNetwork?.name || t("本机网络")].join(" · ") : t("环境不可用")}</span>
              {inEnvironment && <button type="button" className="link-browser-chip" onClick={() => onChooseLinkBrowser(application)} title={t("此软件的链接")} disabled={pending[`setApplicationLinkBrowser:${application.id}`]}><Browsers size={13} /><strong>{(() => { const candidates = linkCandidates(application), value = linkBrowserChoice(candidates, application.browserProfileId); return value === SYSTEM_BROWSER ? t("系统默认浏览器") : candidates.find(item => item.id === value)?.name || t("系统默认浏览器"); })()}</strong><CaretRight size={11} /></button>}
              {!supported && !rowLive && <span className="application-compatibility-hint" role="status">{t("暂不支持此软件的网络隔离")}</span>}
              {application.lastError && <p className="application-error"><WarningCircle size={14} />{t(typeof application.lastError === "string" ? application.lastError : application.lastError.message)}</p>}
              {capabilityError && <p className="notion-trial-error" role="status">{t("错误码")} · <code>{capabilityError}</code></p>}
            </div>
            <span className={`status status-${rowStatus}`}><span className="status-dot" />{t({
              stopped: "已停止",
              starting: "启动中",
              running: "运行中",
              stopping: "停止中",
              error: "异常"
            }[rowStatus] || rowStatus)}</span>
            <div className="application-actions">{inEnvironment && rowStatus === "running" && typeof onShowApplicationWindow === "function" && <button className="icon-button" disabled={pending[`showApplicationWindow:${application.id}`]} onClick={() => onShowApplicationWindow(application)} aria-label={t("打开窗口")} title={t("打开窗口")}><ArrowSquareOut size={17} /></button>}<button className={`button ${rowStoppable ? "" : "primary"}`} disabled={!rowStoppable && !supported || (inEnvironment ? (rowStoppable ? !controlled.canStop : !owner || !controlled.canRun) : busy || (active ? application.status !== "running" : !ready || !owner))} onClick={() => inEnvironment ? (rowStoppable ? onStopNotionTrial(application) : onRunNotionTrial(application)) : active ? onStop(application) : onStart(application)}>{rowStoppable ? <Stop size={15} /> : <Play size={15} />}{t(cleanupRetryable ? "重试清理" : rowLive ? "停止" : "启动")}</button>{typeof onExport === "function" && <button className="icon-button" disabled={!desktop || !owner || rowLive || busy || controlled.trial?.cleanupUncertain === true} onClick={() => onExport(application)} aria-label={t("导出软件")} title={t("导出软件")}><DownloadSimple size={17} /></button>}<button className="icon-button" disabled={active || busy || controlled.trial?.cleanupUncertain === true} onClick={() => onDelete(application)} aria-label={t("移除软件")} title={t("移除软件")}><Trash size={17} /></button></div>
          </div>
          {issue && <div className="application-issue" role="status">
            <div className="application-issue-head"><WarningCircle size={15} /><strong>{t(controlled.trial?.phase === "cleanup-required" ? "清理未确认" : historicalDiagnostics ? "上次附加" : "上次启动未完成")}</strong>{controlled.trial?.errorCode && <code>{controlled.trial.errorCode}</code>}</div>
            {diagnostics?.initialFailure && <p><span>{t("首次错误")} · </span><code>{notionTrialFailureLine(diagnostics.initialFailure)}</code></p>}
            {trialHint && <p className="application-issue-hint">{t(trialHint)}</p>}
            {diagnostics?.cleanupFailure && <p><span>{t("清理错误")} · </span><code>{notionTrialFailureLine(diagnostics.cleanupFailure)}</code></p>}
            {(diagnostics?.events.length > 0 || typeof onExportNotionDiagnostics === "function") && <div className="application-issue-actions">
              {(diagnostics?.events.length > 0 || diagnostics?.nativeTimings?.length > 0) && <details className="notion-trial-log"><summary>{t("查看日志")}</summary><div>{diagnostics.events.map((event, index) => <code key={`${event.sequence}-${index}`}>{notionTrialLogLine(event)}</code>)}{(diagnostics.nativeTimings ?? []).map((item, index) => <code key={`timing-${index}`}>{notionTrialTimingLine(item)}</code>)}</div></details>}
              {(diagnostics?.events.length > 0 || diagnostics?.initialFailure) && typeof onExportNotionDiagnostics === "function" && <button className="button" disabled={pending[`exportNotionDiagnostics:${application.id}`]} onClick={() => onExportNotionDiagnostics(application)}>{t("导出诊断")}</button>}
            </div>}
          </div>}
        </div>;
      })}</div> : <WorkspaceEmpty icon={Desktop} title={profile ? "添加软件到这个境舱" : "先创建网络环境"} t={t} />}
    {tab !== "signInData" && startable && rows.length > 0 && <details className="application-notes">
      <summary><Info size={14} /><span>{t("运行方式与应用数据")}</span></summary>
      <ul>{["附加的应用会一直运行，直到你停止它、它自行退出，或你退出境舱。指纹浏览器和终端不计入其中。",
        "关闭窗口不会退出软件，点「打开窗口」或程序坞图标即可重新打开。",
        "再次启动会沿用此境舱的应用数据；停止和移除软件都不会删除。",
        "独立数据目录不等于系统沙箱；软件的硬件信息、系统定位与钥匙串不会被替换。"].map(text => <li key={text}><span>{t(text)}</span></li>)}</ul>
    </details>}
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
  // An application started inside its environment reports through its run.
  const apps = applications.map(application => {
    const trial = safeNotionTrial(application);
    return { ...application, status: trial ? attachedApplicationStatus({ trial }) : application.status };
  }).filter(application => live.has(application.status));
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
      path: application.path,
      detail: profiles.find(profile => profile.id === application.profileId)?.name
    }))
  }];
  return <div className="monitor-content">
    <div className="monitor-summary">{categories.map(({
        id,
        label,
        icon: Icon,
        rows
      }) => <div key={id}><span><Icon size={17} />{t(label)}</span><strong>{rows.length}</strong></div>)}</div>
    <div className="section-heading"><h2>{t("正在运行")}</h2></div>
    <div className="monitor-runtime-list">{categories.flatMap(({
        id,
        icon: Icon,
        rows
      }) => rows.map(row => <div className="monitor-runtime-row" key={`${id}:${row.id}`}>{row.path ? <ApplicationIcon path={row.path} size={26} className="choice-icon" /> : <Icon size={22} />}<div><strong>{row.name}</strong><span>{row.detail}</span></div><span className={`status status-${row.status}`}><span className="status-dot" />{t({
            running: "运行中",
            starting: "启动中",
            stopping: "停止中",
            closing: "关闭中"
          }[row.status] || row.status)}</span><button className="button" onClick={() => onNavigate(id)}>{t("查看")}</button></div>))}{!browsers.length && !terminals.length && !apps.length && <div className="empty-activity">{t("当前没有运行中的会话")}</div>}</div>
    {events.length > 0 && <div className="section-heading activity-heading"><h2>{t("运行记录")}</h2></div>}
    <div className={`activity-list${events.length ? "" : " is-empty"}`}>{events.length ? [...events].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 80).map(event => <div className="activity-row" key={event.id}><span className={`activity-dot ${event.type === "error" ? "failure" : ""}`} /><span className="activity-message">{t(event.message)}</span><time>{new Date(event.time).toLocaleTimeString(localeForInterfaceLanguage(language), {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
          })}</time></div>) : <div className="empty-activity"><Clock size={17} />{t("暂无运行记录")}</div>}</div>
  </div>;
}
