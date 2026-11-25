import React, { useCallback, useEffect, useRef, useState } from "react";
import { GlobeHemisphereWest, Plus, MagnifyingGlass, UploadSimple, Play, Stop, PencilSimple, Trash, FolderOpen, ArrowSquareOut, X, CheckCircle, WarningCircle, Browsers, ShieldCheck } from "@phosphor-icons/react";
import { api } from "./client.js";
import { TerminalDock } from "./TerminalPane.jsx";
import { NetworkDiagnostics, NetworkRecoveryNotice } from "./NetworkStatus.jsx";
import { SupportDiagnostics } from "./SupportDiagnostics.jsx";
import { ComponentVersions } from "./ComponentVersions.jsx";
import { ApplicationUpdates } from "./ApplicationUpdates.jsx";
import { BrowserSiteData } from "./BrowserSiteData.jsx";
import { WorkCombinations } from "./WorkCombinations.jsx";
import { CacheMaintenance } from "./CacheMaintenance.jsx";
import { RuntimeVerification } from "./RuntimeVerification.jsx";
import { SshWorkspace } from "./TerminalSshConnections.jsx";
import { TerminalWindowApp } from "./TerminalWindowApp.jsx";
import { networkApplicationChoices, chooseApplicationProfile, isApplicationAlreadyAttached, createdProfileFromSnapshot } from "./network-flow-state.mjs";
import { preferredEngine } from "../shared/engine-choice.mjs";
import { safeNotionTrial, notionTrialLocksConfiguration, applyNotionTrialOperationResult } from "./notion-trial-state.mjs";
import { useI18n } from "./i18n.jsx";
import { useAppearance } from "./appearance.jsx";
import { linkBrowsersFor as linkBrowsersOf, linkBrowserChoice } from "./link-browser.mjs";
import { LanguageWelcome } from "./LanguageWelcome.jsx";
import { languageOptions, localeForInterfaceLanguage } from "../shared/interface-languages.mjs";
import { BrowserWorkspace } from "./BrowserWorkspace.jsx";
import { ApplicationsWorkspace, ContextDetail, EnvironmentOverview, MonitorWorkspace } from "./workspace-pages.jsx";
import { supportsAttachedApplication } from "./application-capability.mjs";
import { environmentTransferModalPending, cancelEnvironmentImportModal } from "./environment-transfer-ui.mjs";
import { completeWorkspaceOperation, workspaceOperationWarning } from "./workspace-operation.mjs";
import { Button, IconButton, Modal } from "./workspace-ui.jsx";
import { navItems, useSidebarPreference, WorkspaceSidebar } from "./WorkspaceSidebar.jsx";
import { ProfileForm, GroupForm } from "./ProfileForm.jsx";
import { MigrationForm, ExportDataForm, ImportPasswordForm, ImportMappingForm } from "./EnvironmentTransferForms.jsx";
import { NetworkResult, ProxyForm } from "./ProxyForm.jsx";
import { LinkBrowserChoices, AttachApplicationForm } from "./AttachApplicationForm.jsx";
import { BrowserDetail } from "./BrowserDetail.jsx";
import { profileConfig, runtimeCatalog, allows } from "./workspace-profile.mjs";
import { protocolLabel, bytes } from "./workspace-display.mjs";
const SEARCH_SHORTCUT = typeof navigator !== 'undefined' && /Mac/i.test(navigator.userAgent || '') ? '⌘ K' : 'Ctrl K';

const initialSnapshot = {
  profiles: [],
  proxies: [],
  settings: {},
  engine: {},
  engines: [],
  groups: [],
  events: [],
  networkRevision: 0,
  system: {}
};

export function App() {
  const route = new URLSearchParams(window.location.search);
  const { phase } = useI18n();
  if (route.get("view") === "terminal") return <TerminalWindowApp profileId={route.get("profileId")} sessionId={route.get("sessionId")} />;
  const initializing = phase !== "ready";
  return <><div className="workspace-content" inert={initializing ? true : undefined} aria-hidden={initializing ? true : undefined}><WorkspaceApp /></div><LanguageWelcome /></>;
}

function WorkspaceApp() {
  const { preference: appearance, setPreference: setAppearance, saving: savingAppearance } = useAppearance();
  const [sidebarCollapsed, setSidebarCollapsed] = useSidebarPreference();
  const {
    t,
    language,
    setLanguage,
    saving: savingLanguage,
    phase: languagePhase
  } = useI18n();
  const [snapshot, setSnapshot] = useState(initialSnapshot),
    [loading, setLoading] = useState(true),
    [page, setPage] = useState("profiles"),
    [selectedId, setSelectedId] = useState(null),
    [query, setQuery] = useState(""),
    [groupFilter, setGroupFilter] = useState("*"),
    [modal, setModal] = useState(null),
    [pending, setPending] = useState({}),
    [toast, setToast] = useState(null),
    [proxyTests, setProxyTests] = useState({}),
    [checkedIds, setCheckedIds] = useState([]),
    [bulkResults, setBulkResults] = useState([]),
    [bulkRunning, setBulkRunning] = useState(false),
    [resumeId, setResumeId] = useState(null),
    [migration, setMigration] = useState(null),
    [terminalVisible, setTerminalVisible] = useState(false),
    [terminalRequest, setTerminalRequest] = useState(null),
    [terminalProfiles, setTerminalProfiles] = useState([]);
  const searchRef = useRef(null),
    pendingRef = useRef(new Set()),
    snapshotRef = useRef(initialSnapshot),
    proxyTestTokens = useRef({}),
    proxyTestsRef = useRef({}),
    modalRef = useRef(null);
  const [terminalExpanded, setTerminalExpanded] = useState(false);
  const [terminalHeight, setTerminalHeight] = useState(360);
  const [viewportHeight, setViewportHeight] = useState(window.innerHeight);
  useEffect(() => {
    const resize = () => setViewportHeight(window.innerHeight);
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);
  const terminalMaxHeight = Math.max(320, viewportHeight - 180);
  const resizeTerminalDock = useCallback(height => setTerminalHeight(Math.round(Math.max(320, Math.min(height, Math.max(320, window.innerHeight - 180))))), []);
  modalRef.current = modal;
  const updateProxyTests = useCallback(update => {
    const next = typeof update === "function" ? update(proxyTestsRef.current) : update;
    proxyTestsRef.current = next;
    setProxyTests(next);
  }, []);
  const acceptSnapshot = useCallback(value => {
    if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system || typeof value.system !== "object") return false;
    const networkRevision = value.networkRevision ?? 0;
    if (!Number.isSafeInteger(networkRevision) || networkRevision < 0) return false;
    const previous = snapshotRef.current;
    // Delayed snapshots and probe promises belong to the network they started
    // on. Invalidate synchronously, before another promise can update the UI.
    if (networkRevision < previous.networkRevision) return true;
    if (networkRevision > previous.networkRevision) {
      for (const id of Object.keys(proxyTestTokens.current)) proxyTestTokens.current[id] += 1;
      updateProxyTests({});
    } else {
      const tests = { ...proxyTestsRef.current };
      for (const proxy of value.proxies) {
        const local = tests[proxy.id];
        if (!local || local.checking) continue;
        const measuredAt = Date.parse(proxy.network?.checkedAt);
        const localAt = Date.parse(local.checkedAt);
        if (Number.isFinite(measuredAt) && Number.isFinite(localAt) && measuredAt > localAt) delete tests[proxy.id];
      }
      if (Object.keys(tests).length !== Object.keys(proxyTestsRef.current).length) updateProxyTests(tests);
    }
    const next = {
      ...initialSnapshot,
      ...value,
      networkRevision,
      // Status-only events can race a slower snapshot from the same network.
      networkRecovery: networkRevision === previous.networkRevision &&
        (previous.networkRecovery?.revision ?? -1) > (value.networkRecovery?.revision ?? -1)
        ? previous.networkRecovery : value.networkRecovery
    };
    snapshotRef.current = next;
    setSnapshot(next);
    setSelectedId(current => value.profiles.some(profile => profile.id === current) ? current : value.profiles[0]?.id || null);
    setCheckedIds(ids => ids.filter(id => value.profiles.some(profile => profile.id === id)));
    return true;
  }, [updateProxyTests]);
  const refresh = useCallback(async () => {
    const value = await api.call("snapshot");
    acceptSnapshot(value);
    return value;
  }, [acceptSnapshot]);
  useEffect(() => {
    refresh().catch(error => setToast({
      type: "error",
      message: error.message || t("无法读取环境数据。")
    })).finally(() => setLoading(false));
    return api.subscribe(value => {
      if (!acceptSnapshot(value)) refresh().catch(() => {});
    });
  }, [refresh, acceptSnapshot]);
  /* Where each link from an environment went: its browser, the host browser,
   * or nowhere because the browser refused. */
  useEffect(() => typeof api.onLinkEvent === "function" ? api.onLinkEvent(event => {
    if (!event?.message) return;
    setToast({ type: event.type === "error" ? "error" : event.type === "link" ? "success" : "info", message: event.message });
  }) : undefined, []);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 6000);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    const onKey = event => {
      if (languagePhase !== "ready") return;
      if ((event.metaKey || event.ctrlKey) && event.key === "k" && !modal && !event.target?.closest?.(".terminal-dock")) {
        event.preventDefault();
        setPage("profiles");
        setTerminalVisible(false);
        setTerminalExpanded(false);
        requestAnimationFrame(() => searchRef.current?.focus());
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [modal, languagePhase]);
  const closeModal = useCallback(async () => {
    if (pendingRef.current.has("attachApplication:")) return;
    if (environmentTransferModalPending(modalRef.current, pendingRef.current)) return;
    const current = modalRef.current;
    try {
      const canceled = await cancelEnvironmentImportModal({ modal: current, pending: pendingRef.current,
        cancel: importId => api.call("cancelImport", { importId }) });
      if (canceled) setModal(value => value === current ? null : value);
    } catch (error) {
      setToast({ type: "error", message: error.message || t("操作未完成，请重试。") });
    }
  }, [t]);
  const perform = async (method, args = {}, success, key = `${method}:${args.id || args.runtimeId || ""}`, quiet = false) => {
    if (pendingRef.current.has(key)) return {
      ok: false,
      message: t("此操作正在进行中。")
    };
    pendingRef.current.add(key);
    const previousRunId = safeNotionTrial(snapshotRef.current.applications?.find(item => item.id === args.id))?.runId ?? null;
    setPending(value => ({
      ...value,
      [key]: true
    }));
    try {
      const acceptOperationResult = value => {
        if (acceptSnapshot(value)) return true;
        const next = applyNotionTrialOperationResult(snapshotRef.current, value, { method, applicationId: args.id, previousRunId });
        return next ? acceptSnapshot(next) : false;
      };
      const { result, refreshFailed } = await completeWorkspaceOperation({ execute: () => api.call(method, args), acceptSnapshot: acceptOperationResult, refresh });
      const warning = workspaceOperationWarning(result);
      if (warning && !quiet) setToast({ type: "error", message: t(warning) });
      else if (success && !result?.canceled && !quiet) setToast({
        type: "success",
        message: success
      });
      return {
        ok: true,
        result,
        refreshFailed
      };
    } catch (error) {
      const message = error.message || t("操作未完成，请重试。");
      if (!quiet) setToast({
        type: "error",
        message
      });
      return {
        ok: false,
        message
      };
    } finally {
      pendingRef.current.delete(key);
      setPending(value => {
        const next = {
          ...value
        };
        delete next[key];
        return next;
      });
    }
  };
  const {
    profiles,
    proxies,
    events,
    system
  } = snapshot;
  const engines = runtimeCatalog(snapshot),
    runtimeFor = profile => engines.find(item => item.id === profile?.engine) || {
      id: profile?.engine,
      displayName: profile?.engine || t("未知内核"),
      supported: false,
      message: t("此内核不在当前可用目录中。"),
      capabilities: {}
    };
  const groups = [...new Set([...profiles.map(profile => profile.group), ...(snapshot.groups || []).map(group => typeof group === "string" ? group : group.name)].filter(Boolean))].sort((a, b) => a.localeCompare(b, localeForInterfaceLanguage(language)));
  const selected = profiles.find(profile => profile.id === selectedId),
    selectedRuntime = runtimeFor(selected);
  const filteredProfiles = profiles.filter(profile => {
    const proxy = proxies.find(item => item.id === profile.proxyId);
    return (groupFilter === "*" || (profile.group || "") === groupFilter) && `${profile.name} ${profile.group || ""} ${proxy?.name || ""} ${proxy?.host || ""}`.toLowerCase().includes(query.toLowerCase());
  });
  const totalBytes = profiles.reduce((sum, profile) => sum + (profile.dataBytes || 0), 0);
  const busyProfile = id => Object.keys(pending).some(key => key.endsWith(`:${id}`));
  const start = async (profile, quiet = false) => {
    const runtime = runtimeFor(profile);
    if (runtime.supported === false) {
      const message = runtime.message || t("当前平台不支持此内核。");
      if (!quiet) setToast({
        type: "error",
        message
      });
      return {
        ok: false,
        message
      };
    }
    if (!runtime.installed) {
      const message = t("请先安装 {value1}。", {
        value1: runtime.displayName || runtime.id
      });
      if (!quiet) {
        setResumeId(profile.id);
        setPage("browsers");
        setToast({
          type: "info",
          message
        });
      }
      return {
        ok: false,
        message
      };
    }
    return perform("startProfile", {
      id: profile.id
    }, undefined, `startProfile:${profile.id}`, quiet);
  };
  const saveProfile = async profile => {
    const editing = modal?.type === "editProfile";
    const before = new Set(profiles.map(item => item.id));
    const response = await perform(editing ? "updateProfile" : "createProfile", editing ? {
      id: modal.profile.id,
      profile
    } : {
      profile
    }, editing ? t("环境配置已更新") : t("环境已创建"));
    if (response.ok) {
      closeModal();
      const next = response.result?.profiles ? response.result : snapshotRef.current;
      if (!editing) setSelectedId(next.profiles.find(item => !before.has(item.id))?.id || selectedId);
      setGroupFilter("*");
      setQuery("");
      setPage("profiles");
    }
  };
  const cloneProfile = async profile => {
    const before = new Set(profiles.map(item => item.id));
    const response = await perform("cloneProfile", {
      id: profile.id
    }, t("环境配置已克隆"));
    if (response.ok) {
      const next = response.result?.profiles ? response.result : snapshotRef.current;
      setSelectedId(next.profiles.find(item => !before.has(item.id))?.id || selectedId);
      setGroupFilter("*");
      setQuery("");
    }
  };
  const importProfiles = async (args = {}) => {
    if (args.importId && pendingRef.current.has(`cancelImport:${args.importId}`)) return;
    const before = new Set(profiles.map(profile => profile.id));
    const response = await perform("importProfiles", args, undefined, `importProfiles:${args.importId || ""}`);
    if (!response.ok || response.result?.canceled) return;
    if (response.result?.needsPassword) {
      setModal({
        type: "importPassword",
        session: response.result
      });
      return;
    }
    if (response.result?.needsProxyMapping) {
      setModal({
        type: "importMapping",
        session: response.result
      });
      return;
    }
    if (!Array.isArray(response.result?.profiles)) {
      setToast({
        type: "error",
        message: t("导入结果不完整，请重新选择文件。")
      });
      return;
    }
    setModal(null);
    setPage("profiles");
    setGroupFilter("*");
    setQuery("");
    setSelectedId(response.result.profiles.find(profile => !before.has(profile.id))?.id || selectedId);
    const restored = response.result.restored;
    const importedLabel = { browser: "浏览器数据已导入", terminal: "终端数据已导入", application: "软件数据已导入" }[restored?.scope];
    const waiting = (restored?.applications || []).filter(item => item.bound).map(item => item.name);
    const unbound = (restored?.applications || []).filter(item => !item.bound).map(item => item.name);
    setToast({
      type: "success",
      message: !restored ? t("环境配置已导入") : [t(importedLabel || "环境与登录数据已导入"), waiting.length ? t("{value1} 首次启动并停止后恢复登录数据，再次启动生效。", { value1: waiting.join("、") }) : "", unbound.length ? t("{value1} 未绑定：请先添加该软件或解除原绑定，再启动并停止一次。", { value1: unbound.join("、") }) : ""].filter(Boolean).join(" ")
    });
  };
  const saveProxy = async (proxy, locationPreviewToken, previewNetwork) => {
    const existingIds = new Set(proxies.map(item => item.id));
    const networkRevision = snapshotRef.current.networkRevision;
    if (proxy.id) {
      proxyTestTokens.current[proxy.id] = (proxyTestTokens.current[proxy.id] || 0) + 1;
      updateProxyTests(value => {
        const next = {
          ...value
        };
        delete next[proxy.id];
        return next;
      });
    }
    const response = await perform("saveProxy", {
      proxy, ...(locationPreviewToken ? { locationPreviewToken } : {})
    }, t("网络出口已保存"));
    if (response.ok) {
      closeModal();
      const next = response.result?.proxies || snapshotRef.current.proxies;
      const saved = proxy.id ? next.find(item => item.id === proxy.id) : next.find(item => !existingIds.has(item.id));
      if (api.isDesktop && saved && previewNetwork?.ok === true && networkRevision === snapshotRef.current.networkRevision) updateProxyTests(value => ({ ...value, [saved.id]: previewNetwork }));
      else if (api.isDesktop && saved) checkProxy(saved);
    }
  };
  const confirmAction = async () => {
    const current = modal;
    const response = await perform(current.method, {
      id: current.id,
      ...(current.args ?? {})
    }, current.success);
    if (response.ok) { closeModal(); current.onDone?.(response.result); }
  };
  const confirmDelete = profile => setModal({
    type: "confirm",
    title: t("删除「{value1}」？", {
      value1: profile.name
    }),
    description: t("此环境的配置与本机浏览数据将被删除，删除后无法恢复。"),
    method: "deleteProfile",
    id: profile.id,
    button: t("删除环境"),
    success: t("环境已删除")
  });
  const confirmClear = profile => setModal({
    type: "confirm",
    title: t("清空浏览数据？"),
    description: t("「{value1}」的 Cookie、缓存与浏览历史将被清空，环境配置会保留。", {
      value1: profile.name
    }),
    method: "clearProfile",
    id: profile.id,
    button: t("清空数据"),
    success: t("浏览数据已清空")
  });
  const checkProxy = async proxy => {
    if (!api.isDesktop) return;
    const token = (proxyTestTokens.current[proxy.id] || 0) + 1;
    proxyTestTokens.current[proxy.id] = token;
    updateProxyTests(value => ({
      ...value,
      [proxy.id]: {
        checking: true
      }
    }));
    try {
      const result = await api.call("checkProxy", {
        id: proxy.id
      });
      if (proxyTestTokens.current[proxy.id] !== token) return;
      updateProxyTests(value => ({
        ...value,
        [proxy.id]: result
      }));
      const verified = result.ok === true && result.scope === "egress" && !!result.ip;
      setToast({
        type: verified ? "success" : "error",
        message: verified ? `${proxy.name}：${result.ip}${result.timezone ? ` · ${result.timezone}` : ""}` : result.message || t("未获得有效的出口资料。")
      });
      await refresh().catch(() => {});
    } catch (error) {
      if (proxyTestTokens.current[proxy.id] !== token) return;
      updateProxyTests(value => ({
        ...value,
        [proxy.id]: {
          ok: false,
          checkedAt: new Date().toISOString(),
          message: error.message || t("出口识别未完成，请重试。")
        }
      }));
      setToast({
        type: "error",
        message: error.message || t("出口识别失败。")
      });
    }
  };
  const toggleChecked = id => setCheckedIds(ids => ids.includes(id) ? ids.filter(value => value !== id) : [...ids, id]);
  const allVisibleChecked = filteredProfiles.length > 0 && filteredProfiles.every(profile => checkedIds.includes(profile.id));
  const toggleAllVisible = () => setCheckedIds(ids => allVisibleChecked ? ids.filter(id => !filteredProfiles.some(profile => profile.id === id)) : [...new Set([...ids, ...filteredProfiles.map(profile => profile.id)])]);
  const runBulk = async (action, group = "") => {
    const chosen = profiles.filter(profile => checkedIds.includes(profile.id));
    if (!chosen.length || bulkRunning) return;
    setBulkRunning(true);
    setBulkResults(chosen.map(profile => ({
      id: profile.id,
      name: profile.name,
      state: "pending",
      message: t("等待处理")
    })));
    if (action === "group") closeModal();
    await Promise.all(chosen.map(async profile => {
      let response;
      let message;
      if (busyProfile(profile.id)) {
        response = {
          ok: false,
          message: t("此环境已有操作正在进行。")
        };
      } else if (action === "start" && ["running", "starting"].includes(profile.status)) {
        response = {
          ok: true
        };
        message = profile.status === "running" ? t("会话已经运行") : t("会话正在启动");
      } else if (action === "stop" && !["running", "starting"].includes(profile.status)) {
        response = {
          ok: true
        };
        message = t("会话已经停止");
      } else if (action === "group" && ["running", "starting"].includes(profile.status)) {
        response = {
          ok: false,
          message: t("请先停止会话，再修改分组。")
        };
      } else if (action === "start") {
        response = await start(profile, true);
        message = t("已提交启动");
      } else if (action === "stop") {
        response = await perform("stopProfile", {
          id: profile.id
        }, undefined, `stopProfile:${profile.id}`, true);
        message = t("会话已停止");
      } else {
        response = await perform("updateProfile", {
          id: profile.id,
          profile: {
            ...profileConfig(profile),
            group,
            ...(!allows(runtimeFor(profile), "seed") ? {
              seed: undefined
            } : {})
          }
        }, undefined, `updateProfile:${profile.id}`, true);
        message = group ? t("已移到 {value1}", {
          value1: group
        }) : t("已移到未分组");
      }
      setBulkResults(rows => rows.map(row => row.id === profile.id ? {
        ...row,
        state: response.ok ? "success" : "error",
        message: response.ok ? message : response.message
      } : row));
    }));
    if (action === "group") setGroupFilter("*");
    setBulkRunning(false);
  };
  const previewMigration = async () => {
    const response = await perform("previewLegacyMigration");
    if (response.ok) {
      if (response.result?.detected || response.result?.available) {
        setMigration(response.result);
        setModal({
          type: "migration"
        });
      } else setToast({
        type: "info",
        message: t("没有发现可迁移的旧工作区。")
      });
    }
  };
  const migrate = async ids => {
    const response = await perform("migrateLegacy", {
      ids,
      copyBrowserData: true
    }, t("旧环境已复制迁移，原资料和备份已保留"));
    if (response.ok) {
      closeModal();
      setMigration(null);
    }
  };
  const selectedProxy = proxies.find(proxy => proxy.id === selected?.proxyId);
  const resumeProfile = profiles.find(profile => profile.id === resumeId);
  const installRuntime = async runtime => {
    const response = await perform("installEngine", {
      runtimeId: runtime.id
    }, t("{value1} 已安装", {
      value1: runtime.displayName || runtime.id
    }));
    if (response.ok && resumeProfile?.engine === runtime.id) {
      setToast({
        type: "success",
        message: t("内核已就绪，可以启动刚才的环境。")
      });
    }
  };
  const terminalActive = id => terminalProfiles.some(profile => profile.profileId === id && profile.sessions?.some(session => ["running", "starting", "closing"].includes(session.status)));
  const terminalError = useCallback(message => setToast({
    type: "error",
    message
  }), []);
  const applications = snapshot.applications || [];
  const trialPollingIds = applications.filter(application => typeof application.identity === "string" && application.identity && (pending[`runNotionTrial:${application.id}`] || pending[`stopNotionTrial:${application.id}`] || application.notionTrial?.active === true)).map(application => application.id).sort().join("|");
  useEffect(() => {
    if (!api.isDesktop || !trialPollingIds) return;
    let closed = false;
    let timer;
    const poll = async () => {
      const results = await Promise.allSettled(trialPollingIds.split("|").map(async id => {
        const value = await api.call("notionTrialSnapshot", { id });
        if (value?.applicationId !== id) return null;
        const notionTrial = safeNotionTrial({ id, notionTrial: value.notionTrial });
        return notionTrial ? { id, notionTrial } : null;
      }));
      if (closed) return;
      const updates = results.flatMap(result => result.status === "fulfilled" && result.value ? [result.value] : []);
      if (updates.length) acceptSnapshot({ ...snapshotRef.current, applications: (snapshotRef.current.applications || []).map(application => {
        const update = updates.find(item => item.id === application.id);
        return update ? { ...application, notionTrial: update.notionTrial } : application;
      }) });
      timer = setTimeout(poll, 1500);
    };
    void poll();
    return () => { closed = true; clearTimeout(timer); };
  }, [trialPollingIds, acceptSnapshot]);
  const selectedWorkspace = terminalProfiles.find(item => item.profileId === selectedId);
  const contextualProfiles = profiles.map(profile => ({
    ...profile,
    workspace: terminalProfiles.find(item => item.profileId === profile.id)
  }));
  /* The browsers an environment's links may use: the same network group and the
   * same node as the environment itself. */
  const [linkRouter, setLinkRouter] = useState(null);
  const linkRoutingPending = !!(pending["setLinkRouter:"] || pending["requestSystemLinkRouting:"] || pending["disableSystemLinkRouting:"]);
  useEffect(() => {
    if (!api.isDesktop || page !== "settings") return;
    api.call("linkRouterStatus").then(value => setLinkRouter(value)).catch(() => setLinkRouter(null));
  }, [page, snapshot.settings]);
  const linkBrowsersFor = profile => linkBrowsersOf(profiles, profile);
  const terminalLinkBrowsers = linkBrowsersFor(selected);
  /* Save where an environment's terminal links open, then have the dock read
   * the stored value back so every view names the same browser. */
  const [terminalRefresh, setTerminalRefresh] = useState(0);
  const [cacheInventory, setCacheInventory] = useState(null);
  const [cacheMaintenancePending, setCacheMaintenancePending] = useState(false);
  const cacheMaintenanceBusy = useRef(false);
  const maintainCache = async (method, args = {}) => {
    if (cacheMaintenanceBusy.current) return;
    cacheMaintenanceBusy.current = true; setCacheMaintenancePending(true);
    try {
      const result = await api.call(method, args);
      if (method === "cacheMaintenanceInventory") setCacheInventory(result);
      else {
        setCacheInventory(null);
        if (result.conflicts) setToast({ type: "info", message: t("目标位置已有新缓存，恢复副本已保留。") });
        else if (result.complete === false) setToast({ type: "info", message: t("部分缓存未能处理，已保留可恢复的数据。") });
        setCacheInventory(await api.call("cacheMaintenanceInventory", {}));
      }
    } catch {
      setCacheInventory(null);
      setToast({ type: "error", message: t("缓存维护未完成，请刷新后重试。") });
    } finally { cacheMaintenanceBusy.current = false; setCacheMaintenancePending(false); }
  };
  const saveTerminalLinkBrowser = async (profile, value) => {
    const result = await perform("setTerminalLinkBrowser", { id: profile.id, browserProfileId: value === profile.id ? null : value }, t("链接浏览器已保存"));
    if (!result.ok) return;
    const updates = result.result?.profiles ?? [];
    setTerminalProfiles(current => [...current.filter(item => !updates.some(update => update.profileId === item.profileId)), ...updates.map(update => ({ ...(current.find(item => item.profileId === update.profileId) ?? {}), ...update }))]);
    setTerminalRefresh(value => value + 1);
    closeModal();
  };
  const terminalContextProfiles = profiles.map(profile => {
    const proxy = proxies.find(item => item.id === profile.proxyId);
    const measured = profile.network?.ok ? profile.network : proxy?.network?.ok ? proxy.network : null;
    const network = { networkName: proxy?.name || null, networkEgress: measured ? { ip: measured.ip, country: measured.country, countryCode: measured.countryCode, city: measured.city, timezone: measured.timezone } : null };
    return proxy?.location?.confirmed && proxy.location.timezone ? { ...profile, ...network, savedNetworkTimezone: proxy.location.timezone, savedNetworkLocation: proxy.location } : { ...profile, ...network };
  });
  const withDetail = ["profiles", "browsers", "applications"].includes(page);
  const terminalWorkspace = page === "terminals";
  const effectiveTerminalExpanded = terminalWorkspace || terminalExpanded;
  const openTerminalWorkspace = (profileId = selectedId) => {
    if (profileId && !profiles.some(profile => profile.id === profileId)) return;
    if (profileId) setSelectedId(profileId);
    setPage("terminals");
    setTerminalVisible(true);
    setTerminalExpanded(false);
    if (profileId) setTerminalRequest({ profileId, nonce: Date.now() });
  };
  const navigate = target => {
    if (target === "terminals") { openTerminalWorkspace(); return; }
    setPage(target);
    setTerminalExpanded(false);
    setTerminalVisible(false);
  };
  const activeInEnvironment = profile => ["running", "starting"].includes(profile?.status) || terminalActive(profile?.id) || applications.some(item => item.profileId === profile?.id && (["running", "starting", "stopping"].includes(item.status) || notionTrialLocksConfiguration(item, pending)));
  const editSelected = profile => {
    if (activeInEnvironment(profile)) {
      setToast({
        type: "info",
        message: t("请先停止这个境舱的运行会话。")
      });
      return;
    }
    setModal({
      type: "editProfile",
      profile
    });
  };
  const chooseDirectory = async () => {
    if (!selected || !api.isDesktop) return;
    await perform("chooseWorkspaceDirectory", {
      id: selected.id
    });
    const value = await api.call("terminalSnapshot").catch(() => null);
    if (value?.profiles) setTerminalProfiles(value.profiles);
  };
  const pickApplication = () => { if (api.isDesktop) setModal({ type: "attachApplication" }); };
  const saveAttachedApplication = async (choice, application, browserProfileId = null) => {
    const key = "attachApplication:";
    if (pendingRef.current.has(key)) return { ok: false, message: t("此操作正在进行中。") };
    pendingRef.current.add(key);
    setPending(value => ({ ...value, [key]: true }));
    let created = null;
    try {
      const current = snapshotRef.current;
      const currentChoice = networkApplicationChoices(current.proxies, current.groups, current.profiles).find(item => item.id === choice.id && item.proxyId === choice.proxyId);
      if (!currentChoice) return { ok: false, message: t("网络分组已改变，请重新选择。") };
      if (!supportsAttachedApplication(application, system.platform)) return { ok: false, message: t("暂不支持此软件的网络隔离") };
      if (isApplicationAlreadyAttached(application, current.applications || [])) return { ok: false, message: t("软件已附加到其他境舱，请先移除原绑定。") };
      let owner = chooseApplicationProfile(currentChoice, current.profiles, selectedId, activeInEnvironment);
      if (!owner) {
        const beforeIds = new Set(current.profiles.map(profile => profile.id));
        const creation = await perform("createProfile", { profile: {
          name: `${application.name || t("选择软件")} · ${currentChoice.name}`.slice(0, 100), group: currentChoice.group, proxyId: currentChoice.proxyId,
          engine: preferredEngine(engines, snapshot.settings?.defaultEngine), platform: { darwin: "macos", win32: "windows", linux: "linux" }[system.platform] || "macos",
        } });
        if (!creation.ok) return creation;
        owner = createdProfileFromSnapshot(beforeIds, snapshotRef.current, currentChoice);
        if (!owner) return { ok: false, message: t("未能确认新境舱，请在环境页检查。") };
        created = owner;
      }
      const linkBrowser = browserProfileId && browserProfileId !== owner.id ? browserProfileId : null;
      const result = await perform("saveApplication", { application: { profileId: owner.id, path: application.path, name: application.name, ...(linkBrowser ? { browserProfileId: linkBrowser } : {}) } }, t("软件已添加"));
      if (result.ok) { setSelectedId(owner.id); setModal(null); return result; }
      if (created) {
        // Remove only the fresh, unused environment we created, after reading
        // current application and terminal state. An uncertain save preserves it.
        const fresh = await refresh().catch(() => null);
        const terminals = await api.call("terminalSnapshot").catch(() => null);
        const unused = fresh?.profiles.find(profile => profile.id === created.id && profile.status === "stopped" && !profile.lastLaunchedAt && !profile.dataBytes);
        const noBinding = fresh && !(fresh.applications || []).some(item => item.profileId === created.id);
        const noTerminal = Array.isArray(terminals?.profiles) && !terminals.profiles.some(item => item.profileId === created.id && item.sessions?.length);
        if (unused && noBinding && noTerminal) {
          const removal = await perform("deleteProfile", { id: created.id }, undefined, `deleteProfile:${created.id}`, true);
          if (!removal.ok) return { ...result, message: `${result.message} ${t("软件未添加；已保留新建境舱。")}` };
        }
        else return { ...result, message: `${result.message} ${t("软件未添加；已保留新建境舱。")}` };
      }
      return result;
    } catch (error) { return { ok: false, message: error.message || t("操作未完成，请重试。") }; }
    finally { pendingRef.current.delete(key); setPending(value => { const next = { ...value }; delete next[key]; return next; }); }
  };
  return <div className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""} ${api.isDesktop ? "is-desktop" : ""} ${withDetail ? "with-detail" : ""} ${terminalVisible ? "terminal-visible" : ""} ${terminalVisible && effectiveTerminalExpanded ? "terminal-expanded" : ""} ${terminalWorkspace ? "terminal-workspace" : ""}`} style={{
    "--terminal-height": `${Math.min(terminalHeight, terminalMaxHeight)}px`
  }}>
    {api.isDesktop && <div className="desktop-titlebar" aria-hidden="true" />}
    <WorkspaceSidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(value => !value)} page={page} onNavigate={navigate} count={profiles.length} totalBytes={totalBytes} language={language} t={t} />
    <main className={`main-panel${page === "ssh" ? " ssh-main-panel" : ""}`}>
      {!terminalWorkspace && <header className="page-header"><div className="page-heading"><div className="heading-line"><h1 tabIndex={-1}>{t(page === "settings" ? "设置" : navItems.find(item => item.id === page)?.label)}</h1>{!api.isDesktop && <span className="preview-badge">{t("界面预览")}</span>}</div></div>
        {page === "profiles" && <div className="header-actions"><Button icon={UploadSimple} onClick={() => importProfiles()} disabled={pending["importProfiles:"]}>{t("导入")}</Button><Button icon={Plus} className="primary" onClick={() => setModal({
            type: "createProfile"
          })}>{t("新建环境")}</Button></div>}
        {page === "proxies" && <Button icon={Plus} className="primary" onClick={() => setModal({
          type: "createProxy"
        })}>{t("添加网络出口")}</Button>}
      </header>}
      {!terminalWorkspace && (page === "proxies" || ["checking", "waiting"].includes(snapshot.networkRecovery?.phase)) && <NetworkRecoveryNotice recovery={snapshot.networkRecovery} pending={!!pending["retryNetwork:"]} onRetry={api.isDesktop ? async () => { const result = await perform("retryNetwork", {}, undefined, "retryNetwork:", true); if (!result.ok) setToast({ type: "error", message: t("无法开始网络重检，请重试。") }); } : undefined} />}
      {page === "profiles" && <>
        {api.isDesktop && snapshot.legacyMigration?.available && <div className="section-note migration-discovery"><FolderOpen size={18} /><span>{t("发现 {count} 个旧环境", {
              count: snapshot.legacyMigration.count || 0
            })}</span><Button onClick={previewMigration} disabled={pending["previewLegacyMigration:"]}>{t("查看旧环境")}</Button></div>}
        <div className="environment-toolbar"><div className="search-input"><MagnifyingGlass size={17} /><input ref={searchRef} value={query} onChange={event => setQuery(event.target.value)} placeholder={t("搜索环境")} aria-label={t("搜索环境")} /><kbd>{SEARCH_SHORTCUT}</kbd></div><label className="group-filter"><select aria-label={t("分组筛选")} value={groupFilter} onChange={event => setGroupFilter(event.target.value)}><option value="*">{t("全部分组")}</option><option value="">{t("未分组")}</option>{groups.map(group => <option key={group} value={group}>{group}</option>)}</select></label></div>
        {checkedIds.length > 0 && <div className="bulk-toolbar"><span>{t("已选 {count} 个环境", {
              count: checkedIds.length
            })}</span><Button icon={Play} disabled={bulkRunning} onClick={() => runBulk("start")}>{t("启动浏览器")}</Button><Button icon={Stop} disabled={bulkRunning} onClick={() => runBulk("stop")}>{t("停止浏览器")}</Button><Button icon={FolderOpen} disabled={bulkRunning} onClick={() => setModal({
            type: "moveGroup"
          })}>{t("移动分组")}</Button><Button disabled={bulkRunning} onClick={() => setCheckedIds([])}>{t("取消选择")}</Button></div>}
        {bulkResults.length > 0 && <details className="bulk-results" open><summary>{t("批量结果")}</summary>{bulkResults.map(row => <div key={row.id} className={`bulk-result-row ${row.state}`}><strong>{row.name}</strong><span>{row.message}</span></div>)}{!bulkRunning && <Button onClick={() => setBulkResults([])}>{t("收起结果")}</Button>}</details>}
        <EnvironmentOverview profiles={contextualProfiles.filter(profile => filteredProfiles.some(item => item.id === profile.id))} proxies={proxies} selectedId={selectedId} onSelect={setSelectedId} checkedIds={checkedIds} onToggleChecked={toggleChecked} onToggleAll={toggleAllVisible} allChecked={allVisibleChecked} loading={loading} onEdit={editSelected} t={t} hasProfiles={profiles.length > 0} onReset={() => {
          setQuery("");
          setGroupFilter("*");
        }} />
        <div className="table-footer"><span>{t("{count} 个环境", {
              count: filteredProfiles.length
            })}</span></div>
        {api.isDesktop && selected && <WorkCombinations key={selected.id} profileId={selected.id} savedTerminals={selectedWorkspace?.savedTerminals ?? []} onOpened={result => {
          setTerminalRefresh(value => value + 1);
          if (result.status === "opened" && result.sessions.length) {
            openTerminalWorkspace(result.profileId);
            setTerminalRequest({ profileId: result.profileId, sessionId: result.sessions[0].sessionId, nonce: Date.now() });
          }
        }} />}
      </>}
      {page === "browsers" && <><BrowserWorkspace profiles={profiles} proxies={proxies} engines={engines} selectedId={selectedId} onSelect={setSelectedId} onStart={start} onStop={profile => perform("stopProfile", {
        id: profile.id
      }, t("会话已停止"))} onFocus={profile => perform("focusProfile", {
        id: profile.id
      })} onEdit={editSelected} onCreate={() => setModal({
        type: "createProfile"
      })} onInstall={installRuntime} busyProfile={busyProfile} editingDisabled={id => activeInEnvironment(profiles.find(profile => profile.id === id))} pending={pending} t={t} />
        {api.isDesktop && selected && <details className="workspace-tool-disclosure"><summary>{t("网站 Cookie")} · {selected.name}</summary><BrowserSiteData key={selected.id} profileId={selected.id} call={api.call} /></details>}
      </>}
      {page === "ssh" && <SshWorkspace profiles={profiles} selectedId={selectedId} onSelect={setSelectedId} terminalProfiles={terminalProfiles} onOpenTerminal={openTerminalWorkspace} />}
      {page === "applications" && <ApplicationsWorkspace profiles={profiles} proxies={proxies} applications={applications} routing={snapshot.applicationRouting} systemPlatform={system.platform} selectedId={selectedId} onSelect={setSelectedId} onPick={pickApplication} onStart={application => perform("startApplication", {
        id: application.id
      })} onStop={application => perform("stopApplication", {
        id: application.id
      }, t("软件已停止"))} onRunNotionTrial={async application => { const result = await perform("runNotionTrial", { id: application.id }); if (!result.ok) await refresh().catch(() => {}); }} onStopNotionTrial={async application => { const result = await perform("stopNotionTrial", { id: application.id }); if (!result.ok) await refresh().catch(() => {}); }} onExport={application => { const profile = profiles.find(item => item.id === application.profileId); if (profile) setModal({ type: "exportData", scope: "application", profile, application }); }} onExportNotionDiagnostics={application => perform("exportNotionDiagnostics", { id: application.id })} onChooseLinkBrowser={application => setModal({ type: "linkBrowser", application })} linkCandidates={application => linkBrowsersFor(profiles.find(item => item.id === application.profileId))} onCheckSignInData={() => perform("signInData", {})} onDeleteSignInData={(item, after) => setModal({
        type: "confirm",
        title: t("删除「{value1}」的应用数据？", { value1: item.application?.name || t("已移除的软件") }),
        description: t("将删除此境舱内该软件的登录信息、设置与本地内容，无法恢复。软件本身和外部项目文件不受影响。"),
        method: "deleteSignInData",
        id: item.id,
        button: t("删除"),
        success: t("应用数据已删除"),
        onDone: () => after()
      })} formatBytes={bytes} onDelete={application => setModal({
        type: "confirm",
        title: t("移除「{value1}」？", {
          value1: application.name
        }),
        description: t("只移除绑定，应用数据会保留；要删除，请到「应用数据」里删除。"),
        method: "deleteApplication",
        id: application.id,
        button: t("移除软件"),
        success: t("软件已移除")
      })} onShowApplicationWindow={application => perform("showApplicationWindow", { id: application.id })} onInstall={() => perform("setupApplicationRouting", { activate: true })} pending={pending} t={t} desktop={api.isDesktop} />}
      {page === "proxies" && <div className="page-content">{!api.isDesktop && <div className="section-note"><ShieldCheck size={18} /><span>{t("真实出口识别需要境舱桌面应用。")}</span></div>}{proxies.length ? <div className="proxy-table"><div className="proxy-grid table-head"><span>{t("网络出口")}</span><span>{t("服务器")}</span><span>{t("实际出口")}</span><span>{t("操作")}</span></div>{proxies.map(proxy => <div className="proxy-grid proxy-row" key={proxy.id}><div className="proxy-name"><div className="proxy-icon"><GlobeHemisphereWest size={20} /></div><div><strong>{proxy.name}</strong><small>{t("关联环境：{count}", { count: profiles.filter(profile => profile.proxyId === proxy.id).length })}{snapshot.groups?.some(group => group.proxyId === proxy.id) && t(" · 绑定分组：{count}", {
                    count: snapshot.groups.filter(group => group.proxyId === proxy.id).length
                  })}</small>{proxy.location?.confirmed && proxy.location.mode === "ip" && proxy.location.referenceLocation && <small title={t("仅供参考，可手动调整。")}>{t("附近地址")}: {proxy.location.referenceLocation.label}</small>}</div></div><div className="proxy-server"><span className="server-address">{proxy.host}:{proxy.port}</span><span className="protocol-tag">{protocolLabel(proxy.protocol)}</span></div><NetworkResult compact showDiagnostics={false} network={proxyTests[proxy.id]?.checking ? null : proxyTests[proxy.id] || proxy.network} checking={proxyTests[proxy.id]?.checking} /><div className="row-actions"><Button onClick={() => checkProxy(proxy)} disabled={!api.isDesktop || proxyTests[proxy.id]?.checking} title={api.isDesktop ? t("识别实际网络出口") : t("出口识别需要桌面应用")}>{t("识别")}</Button><IconButton icon={PencilSimple} label={t("编辑网络出口")} onClick={() => setModal({
                type: "editProxy",
                proxy
              })} /><IconButton icon={Trash} label={t("删除网络出口")} onClick={() => setModal({
                type: "confirm",
                title: t("删除「{value1}」？", {
                  value1: proxy.name
                }),
                description: t("请先解除环境或分组对该网络出口的绑定，再删除。"),
                method: "deleteProxy",
                id: proxy.id,
                button: t("删除出口"),
                success: t("网络出口已删除")
              })} /></div>{!proxyTests[proxy.id]?.checking && <NetworkDiagnostics diagnostics={(proxyTests[proxy.id] || proxy.network)?.diagnostics} />}</div>)}</div> : <div className="page-empty"><div className="empty-icon"><GlobeHemisphereWest size={31} /></div><h2>{t("还没有网络出口")}</h2></div>}</div>}

      {page === "monitor" && <><MonitorWorkspace profiles={profiles} terminalProfiles={terminalProfiles} applications={applications} events={events} onNavigate={navigate} t={t} language={language} />
        {api.isDesktop && <RuntimeVerification profiles={profiles} api={api.call} />}
      </>}
      {page === "settings" && <div className="page-content settings-content">
        <div className="settings-layout">
          <div className="settings-column">
            <section className="settings-section">
        <div className="section-heading first"><h2>{t("偏好设置")}</h2></div>
        <div className="settings-card settings-rows"><div className="settings-row"><div><strong>{t("界面外观")}</strong></div><select className="appearance-select" value={appearance} disabled={savingAppearance} onChange={event => void setAppearance(event.target.value).catch(() => setToast({ type: "error", message: t("无法保存外观，请重试。") }))} aria-label={t("界面外观")}><option value="system">{t("跟随系统")}</option><option value="light">{t("浅色")}</option><option value="dark">{t("深色")}</option></select></div><div className="settings-row"><div><strong>{t("界面语言")}</strong></div><select className="language-select" value={language} disabled={savingLanguage} onChange={event => void setLanguage(event.target.value).catch(() => setToast({ type: "error", message: t("无法保存语言，请重试。") }))} aria-label={t("界面语言")}>{languageOptions.map(option => <option key={option.code} value={option.code} lang={option.code}>{option.nativeName}</option>)}</select></div><div className="settings-row"><div><strong>{t("退出时关闭浏览器")}</strong></div><input type="checkbox" className="row-checkbox" aria-label={t("退出时关闭浏览器")} checked={snapshot.settings?.closeBrowsersOnExit !== false} onChange={event => perform("saveSettings", {
              settings: {
                ...snapshot.settings,
                closeBrowsersOnExit: event.target.checked
              }
            })} /></div><div className="settings-row"><div><strong>{t("本地数据")}</strong><span className="path-label">{t(system.dataDir)}</span></div><Button icon={FolderOpen} disabled={!api.isDesktop} onClick={() => perform("openDataDirectory")}>{t("打开目录")}</Button></div></div>
        {api.isDesktop && snapshot.legacyMigration?.available && <div className="settings-card settings-rows migration-settings"><div className="settings-row"><div><strong>{t("旧版本工作区")}</strong></div><Button onClick={previewMigration} disabled={pending["previewLegacyMigration:"]}>{t("迁移旧环境")}</Button></div></div>}
            </section>
            {api.isDesktop && linkRouter && <section className="settings-section"><div className="section-heading"><h2>{t("打开链接")}</h2></div><div className="settings-card settings-rows">
          <div className="settings-row"><div><strong>{t("境舱内打开链接")}</strong><details className="settings-help"><summary>{t("使用说明")}</summary><p>{t("境舱及普通终端链接使用所选浏览器；关闭后转到系统浏览器（环境外）。Claude 会话不变。")}</p></details></div>
            <label className="proxy-check-option settings-switch"><input type="checkbox" aria-label={t("境舱内打开链接")} checked={linkRouter.preference !== false} disabled={linkRoutingPending} onChange={async event => { const result = await perform("setLinkRouter", { enabled: event.target.checked }); if (result.ok && result.result) setLinkRouter(result.result); }} /><span>{t(linkRouter.preference !== false ? "已开启" : "已关闭")}</span></label>
          </div>
          {linkRouter.available && <div className="settings-row"><div><strong>{t("附加应用链接接管（可选）")}</strong>
            <span>{t(linkRouter.enabled ? "已接管系统链接；恢复原默认浏览器不影响境舱内偏好。" : "仅接管附加应用的系统链接。macOS 将请求把境舱设为默认浏览器；无关应用仍用原浏览器，终端无需此授权。")}</span>
            {!linkRouter.enabled && linkRouter.preference === false && <span>{t("请先开启境舱内链接。")}</span>}
          </div>
            {linkRouter.enabled ? <Button disabled={linkRoutingPending} onClick={async () => { const result = await perform("disableSystemLinkRouting"); if (result.ok && result.result) setLinkRouter(result.result); }}>{t("恢复原默认浏览器")}</Button>
              : <Button disabled={linkRoutingPending || linkRouter.preference === false} onClick={async () => { const result = await perform("requestSystemLinkRouting"); if (result.ok && result.result) setLinkRouter(result.result); }}>{t("启用系统链接接管")}</Button>}
          </div>}
        </div></section>}
            {api.isDesktop && <ApplicationUpdates call={api.call} />}
          </div>
          <div className="settings-column">
            {api.isDesktop && <>
              <ComponentVersions load={() => api.call("componentVersions")} onInstallEngine={id => installRuntime(engines.find(item => item.id === id) || { id })}
            onSetupRouting={() => perform("setupApplicationRouting", { activate: true })} onOpenTerminal={openTerminalWorkspace}
            onOpenUpdates={() => { const panel = document.getElementById("application-updates"); panel?.scrollIntoView({ behavior: "smooth", block: "center" }); panel?.focus({ preventScroll: true }); }}
            onOpenProject={() => perform("openDocumentation", { target: "project" })} />
              <section className="settings-section settings-maintenance">
                <div className="section-heading"><h2>{t("高级")}</h2></div>
                <div className="settings-card settings-maintenance-card">
                  <CacheMaintenance inventory={cacheInventory} pending={cacheMaintenancePending}
            onRefresh={() => maintainCache("cacheMaintenanceInventory")}
            onQuarantine={args => maintainCache("quarantineBrowserCaches", args)}
            onRestore={args => maintainCache("restoreBrowserCaches", args)}
            onPurge={args => maintainCache("purgeBrowserCacheBatch", args)} />
                  <SupportDiagnostics pending={!!pending["exportSupportDiagnostics:"]} onExport={async () => {
            const result = await perform("exportSupportDiagnostics", {}, undefined, "exportSupportDiagnostics:", true);
            if (!result.ok) setToast({ type: "error", message: t("支持诊断导出失败，请重试。") });
          }} />
                </div>
              </section>
            </>}
            <section className="settings-section">
        <div className="section-heading"><h2>{t("关于")}</h2></div><div className="settings-card settings-rows"><div className="settings-row"><div><strong>{t("Envara 境舱")}</strong><span>{t("开源的本地独立工作空间")}</span></div><span className="version-label">{system.appVersion || "—"}</span></div><div className="settings-row"><div><strong>{t("浏览器内核许可")}</strong></div><Button onClick={() => perform("openDocumentation", {
              target: "runtime-license"
            })}>{t("查看许可")}</Button></div><div className="settings-row"><div><strong>GitHub</strong></div><Button icon={ArrowSquareOut} onClick={() => perform("openDocumentation", {
              target: "project"
            })}>{t("项目主页")}</Button></div></div>
            </section>
          </div>
        </div>
      </div>}
    </main>
    {withDetail && <aside className="detail-panel">{page === "browsers" ? <BrowserDetail profile={selected} proxy={selectedProxy} runtime={selectedRuntime} pending={pending} busy={selected && busyProfile(selected.id)} onStart={() => start(selected)} onInstall={() => installRuntime(selectedRuntime)} onFocus={() => perform("focusProfile", {
        id: selected.id
      })} onStop={() => perform("stopProfile", {
        id: selected.id
      }, t("会话已停止"))} onEdit={() => editSelected(selected)} onClear={() => confirmClear(selected)} onExport={() => setModal({ type: "exportData", scope: "browser", profile: selected })} editingDisabled={activeInEnvironment(selected)} t={t} /> : <ContextDetail profile={selected} proxy={selectedProxy} workspace={selectedWorkspace} onEdit={() => editSelected(selected)} onDirectory={chooseDirectory} directoryDisabled={!api.isDesktop || !selected || activeInEnvironment(selected) || !!pending[`chooseWorkspaceDirectory:${selected?.id}`]} onNavigate={navigate} onClone={() => cloneProfile(selected)} onDelete={() => confirmDelete(selected)} editingDisabled={activeInEnvironment(selected)} t={t} />}</aside>}
    <TerminalDock profiles={terminalContextProfiles} screenReaderMode={snapshot.system?.accessibilitySupportEnabled === true} selectedProfileId={selectedId} onSelectProfile={setSelectedId} visible={terminalVisible} workspace={terminalWorkspace} onExport={profileId => {
      const profile = profiles.find(item => item.id === profileId);
      if (api.isDesktop && profile && !terminalActive(profile.id)) { setSelectedId(profile.id); setModal({ type: "exportData", scope: "terminal", profile }); }
    }} onConfigureLinkBrowser={profileId => {
      if (profiles.some(profile => profile.id === profileId)) { setSelectedId(profileId); setModal({ type: "terminalLinkBrowser" }); }
    }} exportDisabled={!api.isDesktop || !selected || terminalActive(selected.id)} onHide={() => {
      setTerminalVisible(false);
      setTerminalExpanded(false);
      if (page === "terminals") setPage("profiles");
    }} expanded={effectiveTerminalExpanded} onToggleExpanded={() => setTerminalExpanded(value => !value)} onHeightChange={resizeTerminalDock} minHeight={320} maxHeight={terminalMaxHeight} openRequest={terminalRequest} refreshKey={terminalRefresh} onError={terminalError} onProfilesChange={setTerminalProfiles} />
    {modal?.type === "attachApplication" && <AttachApplicationForm profiles={profiles} proxies={proxies} groups={snapshot.groups} applications={applications} selectedId={selectedId} systemPlatform={system.platform} isActive={activeInEnvironment} onSave={saveAttachedApplication} onClose={closeModal} onAddNetwork={() => { setPage("proxies"); setModal({ type: "createProxy" }); }} saving={pending["attachApplication:"]} />}
    {(modal?.type === "createProfile" || modal?.type === "editProfile") && <ProfileForm profile={modal.profile} proxies={proxies} systemPlatform={system.platform} engines={engines} defaultEngine={snapshot.settings?.defaultEngine} groups={groups} groupDescriptors={snapshot.groups} onSave={saveProfile} onClose={closeModal} saving={pending[`updateProfile:${modal.profile?.id}`] || pending["createProfile:"]} />}{(modal?.type === "createProxy" || modal?.type === "editProxy") && <ProxyForm proxy={modal.proxy} proxyCore={system.proxyCore} onSave={saveProxy} onClose={closeModal} saving={pending["saveProxy:"]} />}{modal?.type === "importMapping" && <ImportMappingForm session={modal.session} proxies={proxies} onImport={proxyMap => importProfiles({
      importId: modal.session.importId,
      proxyMap
    })} onAddProxy={() => {
      closeModal();
      setPage("proxies");
    }} onClose={closeModal} saving={pending[`importProfiles:${modal.session.importId}`]} />}{modal?.type === "exportData" && <ExportDataForm key={`${modal.scope}:${modal.profile.id}:${modal.application?.id || ""}`} scope={modal.scope} application={modal.application} profile={modal.profile} saving={pending[`exportEnvironment:${modal.profile.id}`]} onClose={closeModal} onExport={async ({ password, accountId }) => {
      const response = await perform("exportEnvironment", { id: modal.profile.id, scope: modal.scope, password,
        ...(modal.scope === "terminal" ? { accountId } : {}), ...(modal.scope === "application" ? { applicationId: modal.application.id } : {}) }, undefined, `exportEnvironment:${modal.profile.id}`);
      if (response.ok && !response.result?.canceled) { setModal(null); setToast({ type: "success", message: t("数据已导出") }); }
    }} />}{modal?.type === "importPassword" && <ImportPasswordForm session={modal.session} saving={pending[`importProfiles:${modal.session.importId}`]} onClose={closeModal} onSubmit={password => importProfiles({ importId: modal.session.importId, password })} />}{modal?.type === "migration" && migration && <MigrationForm migration={migration} onMigrate={migrate} onClose={closeModal} saving={pending["migrateLegacy:"]} />}{modal?.type === "moveGroup" && <GroupForm groups={groups} count={checkedIds.length} onSave={group => runBulk("group", group)} onClose={closeModal} saving={bulkRunning} />}{modal?.type === "terminalLinkBrowser" && selected && <Modal title={t("选择此环境的浏览器")} onClose={closeModal} className="attach-application-modal"><div className="modal-body">
      <LinkBrowserChoices candidates={terminalLinkBrowsers} chosen={linkBrowserChoice(terminalLinkBrowsers, selectedWorkspace?.browserProfileId)} disabled={!!pending[`setTerminalLinkBrowser:${selected?.id}`]} onChoose={value => void saveTerminalLinkBrowser(selected, value)} />
    </div></Modal>}{modal?.type === "linkBrowser" && <Modal title={t("链接使用的浏览器")} onClose={closeModal} className="attach-application-modal"><div className="modal-body">
      {(() => {
        const candidates = linkBrowsersFor(profiles.find(row => row.id === modal.application.profileId));
        return <LinkBrowserChoices candidates={candidates} chosen={linkBrowserChoice(candidates, modal.application.browserProfileId)} disabled={!!pending[`setApplicationLinkBrowser:${modal.application.id}`]}
          onChoose={async value => { const result = await perform("setApplicationLinkBrowser", { id: modal.application.id, browserProfileId: value === modal.application.profileId ? null : value }, t("链接浏览器已保存")); if (result.ok) closeModal(); }} />;
      })()}
    </div></Modal>}{modal?.type === "confirm" && <Modal title={modal.title} onClose={closeModal} className="confirm-modal"><div className="modal-body"><div className="confirm-warning"><WarningCircle size={23} /><p>{modal.description}</p></div>{modal.items?.length > 0 && <ul className="confirm-items">{modal.items.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>}</div><div className="modal-footer"><Button onClick={closeModal}>{t("取消")}</Button><Button className="danger" onClick={confirmAction} disabled={pending[`${modal.method}:${modal.id}`]}>{pending[`${modal.method}:${modal.id}`] ? t("处理中…") : modal.button}</Button></div></Modal>}{toast && <div className={`toast toast-${toast.type}`} role="status">{toast.type === "error" ? <WarningCircle size={19} /> : toast.type === "success" ? <CheckCircle size={19} /> : <Browsers size={19} />}<span>{t(toast.message)}</span><IconButton icon={X} label={t("关闭通知")} onClick={() => setToast(null)} /></div>}
  </div>;
}
