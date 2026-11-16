import React from "react";
import { GlobeHemisphereWest, DownloadSimple, Play, Stop, PencilSimple, ArrowSquareOut, WarningCircle, Browsers } from "@phosphor-icons/react";
import { api } from "./client.js";
import { savedNetworkPresentation } from "./network-flow-state.mjs";
import { browserSessionControls } from "./browser-session-state.mjs";
import { browserExportActive } from "./environment-transfer-ui.mjs";
import { Status, Button, IconButton } from "./workspace-ui.jsx";
import { allows, platforms } from "./workspace-profile.mjs";
import { profileDimensions, networkPlace, bytes } from "./workspace-display.mjs";

export function BrowserDetail({
  profile,
  proxy,
  runtime,
  pending,
  busy,
  onStart,
  onInstall,
  onFocus,
  onStop,
  onEdit,
  onClear,
  onExport,
  editingDisabled,
  t
}) {
  if (!profile) return <div className="detail-empty"><Browsers size={32} /><h2>{t("选择一个环境")}</h2></div>;
  const networkPresentation = savedNetworkPresentation(profile, proxy);
  const controls = browserSessionControls(profile, runtime, { pending, busy });
  const { running, starting } = controls;
  const actionHandler = { focus: onFocus, install: onInstall, start: onStart }[controls.action];
  const ActionIcon = { focus: ArrowSquareOut, install: DownloadSimple, start: Play }[controls.action];
  return <>
    <div className="detail-heading"><div className="detail-title-line"><h2 title={profile.name}>{profile.name}</h2><Status status={profile.status} /></div><p>{runtime.displayName || runtime.id}</p></div>
    <div className={`browser-preview ${profile.screenshot ? "has-screenshot" : ""}`}>{profile.screenshot ? <img src={profile.screenshot} alt={t("{name} 的浏览器窗口", {
        name: profile.name
      })} /> : <div className="preview-placeholder"><Browsers size={34} weight="duotone" /><strong>{t(running ? "会话正在运行" : starting ? "正在启动浏览器" : "浏览器待启动")}</strong></div>}</div>
    <div className="session-controls"><Button className="primary session-primary" icon={ActionIcon} disabled={controls.primaryDisabled || !actionHandler} onClick={actionHandler}>{t(controls.detailLabel)}</Button><IconButton icon={Stop} label="停止浏览器" disabled={controls.stopDisabled || !onStop} onClick={onStop} /></div>
    {profile.lastError && <div className="detail-error"><WarningCircle size={17} /><span>{t(profile.lastError)}</span></div>}
    {profile.networkLastError && <div className="detail-error network-warning"><GlobeHemisphereWest size={17} /><span>{t(profile.networkLastError)}</span></div>}
    <dl className="detail-properties">
      <div><dt>{t("网络出口")}</dt><dd>{proxy?.name || t("本机网络")}</dd></div>
      <div><dt>{t("指纹平台")}</dt><dd>{allows(runtime, "platform") ? platforms[profile.platform] || t("内核默认") : t("本机平台")}</dd></div>
      <div><dt>{t("屏幕尺寸")}</dt><dd>{t(profileDimensions(profile))}</dd></div>
      <div><dt>{t("时区")}</dt><dd>{networkPresentation.failed ? networkPresentation.timezone || t("跟随网络出口") : profile.observed?.timezone || networkPresentation.timezone || t("跟随网络出口")}{networkPresentation.savedOnly && <small>{t("已保存配置")}</small>}</dd></div>
      <div><dt>{t("语言")}</dt><dd>{profile.observed?.language || profile.locale || t("跟随网络出口")}</dd></div>
      <div><dt>{t("隐私防护")}</dt><dd>{t({
            standard: "标准",
            strict: "严格",
            off: "停用"
          }[profile.privacy?.mode || "standard"])}{profile.privacy?.mode !== "off" && profile.privacyProtection?.enabled && <small>{t(profile.privacyProtection.blockedWebSockets === null ? "HTTP(S) 已拦截 {count} 次" : "本次已拦截 {count} 个追踪请求", { count: profile.privacyProtection.blockedRequests ?? 0 })}</small>}{profile.privacyProtection?.enabled && profile.privacyProtection.blockedWebSockets === null && <small>{t("WS/WSS 防护已启用，次数不可读取。")}</small>}</dd></div>
      {profile.network?.ok && <div><dt>{t("实际出口")}</dt><dd>{profile.network.ip}<small>{networkPlace(profile.network)}</small></dd></div>}
      <div><dt>{t("资源占用")}</dt><dd>{profile.cpuPercent == null ? "—" : `${Number(profile.cpuPercent).toFixed(0)}% CPU`} · {bytes(profile.memoryBytes)}</dd></div>
      <div><dt>{t("浏览数据")}</dt><dd>{bytes(profile.dataBytes)}</dd></div>
    </dl>
    <div className="detail-actions"><Button icon={PencilSimple} disabled={editingDisabled} onClick={onEdit}>编辑配置</Button><Button icon={DownloadSimple} disabled={!api.isDesktop || browserExportActive(profile, pending) || busy} onClick={onExport}>{t("导出浏览器")}</Button></div>
    <div className="danger-actions"><button disabled={editingDisabled} onClick={onClear}>{t("清空浏览数据…")}</button></div>
  </>;
}
