import React, { useEffect, useState } from "react";
import { Stack, GlobeHemisphereWest, ChartLine, Gear, Browsers, CaretLeft, CaretRight, TerminalWindow, HardDrives, Desktop } from "@phosphor-icons/react";
import { IconButton } from "./workspace-ui.jsx";
import { bytes } from "./workspace-display.mjs";

export const navItems = [{
  id: "profiles",
  label: "环境",
  icon: Stack
}, {
  id: "proxies",
  label: "网络出口",
  icon: GlobeHemisphereWest
}, {
  id: "browsers",
  label: "浏览器",
  icon: Browsers
}, {
  id: "terminals",
  label: "终端",
  icon: TerminalWindow
}, {
  id: "ssh",
  label: "SSH 连接",
  icon: HardDrives
}, {
  id: "applications",
  label: "附加软件",
  icon: Desktop
}, {
  id: "monitor",
  label: "运行监控",
  icon: ChartLine
}];

const sidebarPreferenceKey = "envara.sidebar.collapsed.v1";

export function useSidebarPreference() {
  const [collapsed, setCollapsed] = useState(() => {
    try { return window.localStorage.getItem(sidebarPreferenceKey) === "true"; }
    catch { return false; }
  });
  useEffect(() => {
    try { window.localStorage.setItem(sidebarPreferenceKey, String(collapsed)); }
    catch { /* The navigation remains usable when browser storage is unavailable. */ }
  }, [collapsed]);
  return [collapsed, setCollapsed];
}

export function WorkspaceSidebar({ collapsed, onToggle, page, onNavigate, count, totalBytes, language, t }) {
  return <aside className="sidebar">
    <div className="brand"><img className="brand-mark" src={`${import.meta.env.BASE_URL}assets/envara-icon.png`} alt="" /><div className="brand-copy"><div className="brand-name">Envara{language.startsWith("zh") && <span>境舱</span>}</div><div className="brand-caption">{t("独立工作空间")}</div></div></div>
    <div className="sidebar-section"><span>{t("工作区")}</span><IconButton className="icon-button sidebar-toggle" icon={collapsed ? CaretRight : CaretLeft} label={collapsed ? "展开侧栏" : "收起侧栏"} aria-expanded={!collapsed} aria-controls="workspace-navigation" onClick={onToggle} /></div>
    <nav id="workspace-navigation" className="navigation" aria-label={t("主导航")}>{navItems.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? "active" : ""}`} aria-label={t(label)} title={t(label)} aria-current={page === id ? "page" : undefined} onClick={() => onNavigate(id)}><Icon size={20} weight={page === id ? "fill" : "regular"} /><span className="nav-label">{t(label)}</span>{id === "profiles" && <span className="nav-count">{count}</span>}</button>)}</nav>
    <div className="sidebar-bottom"><button className={`nav-item settings-navigation ${page === "settings" ? "active" : ""}`} aria-label={t("设置")} title={t("设置")} aria-current={page === "settings" ? "page" : undefined} onClick={() => onNavigate("settings")}><Gear size={20} weight={page === "settings" ? "fill" : "regular"} /><span className="nav-label">{t("设置")}</span></button><div className="owner" title={`${t("本地工作区")} · ${t("设备所有者")}`}><div className="owner-avatar">{t("境")}</div><div className="owner-copy"><strong>{t("本地工作区")}</strong><span>{totalBytes > 0 ? `${t("环境数据")} ${bytes(totalBytes)}` : t("设备所有者")}</span></div><span className="local-dot" /></div></div>
  </aside>;
}
