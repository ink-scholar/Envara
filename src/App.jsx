import React, { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { Stack, GlobeHemisphereWest, ChartLine, Gear, Plus, MagnifyingGlass, DownloadSimple, UploadSimple, Play, Stop, Copy, PencilSimple, Trash, ArrowsClockwise, FolderOpen, ArrowSquareOut, X, CheckCircle, WarningCircle, Browsers, CaretRight, Cpu, HardDrives, Clock, Eye, EyeSlash, ArrowRight, ShieldCheck, TerminalWindow, Desktop, Translate } from "@phosphor-icons/react";
import { api } from "./client.js";
import { TerminalDock } from "./TerminalPane.jsx";
import { TerminalWindowApp } from "./TerminalWindowApp.jsx";
import { initialProxyForm, proxyConfig, proxyFormError } from "./proxy-form-state.mjs";
import { locationFormState, verifiedLocationPreview, locationConfirmation, proxyRouteFields, networkApplicationChoices, chooseApplicationProfile, isApplicationAlreadyAttached, createdProfileFromSnapshot, savedNetworkPresentation } from "./network-flow-state.mjs";
import { googleMapsLocationURL, normalizeNetworkLocation } from "../shared/network-location.mjs";
import { browseForgeRegionFor, preferredEngine } from "../shared/engine-choice.mjs";
import { BROWSER_DEVICE_PROFILES, PROVIDER_DEFAULT_DEVICE_PROFILE_ID, defaultBrowserDeviceProfileId, getBrowserDeviceProfile, supportsBrowserDeviceProfiles } from "../shared/browser-device-profile.mjs";
import { initialBrowserDeviceFields, selectBrowserDeviceProfile, changeBrowserDeviceEngine } from "./browser-device-form.mjs";
import { safeNotionTrial, notionTrialLocksConfiguration } from "./notion-trial-state.mjs";
import { useI18n } from "./i18n.jsx";
import { SYSTEM_BROWSER, linkBrowsersFor as linkBrowsersOf, linkBrowserChoice } from "./link-browser.mjs";
import { LanguageWelcome } from "./LanguageWelcome.jsx";
import { languageOptions, localeForInterfaceLanguage } from "../shared/interface-languages.mjs";
import { BrowserWorkspace } from "./BrowserWorkspace.jsx";
import { ApplicationsWorkspace, ContextDetail, EnvironmentOverview, MonitorWorkspace } from "./workspace-pages.jsx";
import { ApplicationIcon } from "./ApplicationIcon.jsx";
const initialSnapshot = {
  profiles: [],
  proxies: [],
  settings: {},
  engine: {},
  engines: [],
  groups: [],
  events: [],
  system: {}
};
const profileFields = ["name", "group", "notes", "engine", "platform", "seed", "locale", "timezone", "width", "height", "startUrl", "proxyId", "privacy", "deviceProfileId"];
const profileConfig = profile => ({
  ...Object.fromEntries(profileFields.filter(key => profile[key] != null || key === "proxyId").map(key => [key, profile[key]])),
  proxyId: Object.hasOwn(profile, "profileProxyId") ? profile.profileProxyId : profile.proxyId
});
const familyLabel = runtime => runtime?.family === "firefox" ? "Firefox" : runtime?.family === "chromium" ? "Chromium" : runtime?.family || "浏览器";
const runtimeCatalog = snapshot => [...(snapshot.engines?.length ? snapshot.engines : [{
  id: "cloakbrowser",
  displayName: "CloakBrowser",
  family: "chromium",
  supported: true,
  capabilities: {},
  ...snapshot.engine
}])].sort((a, b) => (["cloakbrowser", "camoufox", "browseforge-chromium"].indexOf(a.id) < 0 ? 99 : ["cloakbrowser", "camoufox", "browseforge-chromium"].indexOf(a.id)) - (["cloakbrowser", "camoufox", "browseforge-chromium"].indexOf(b.id) < 0 ? 99 : ["cloakbrowser", "camoufox", "browseforge-chromium"].indexOf(b.id)));
const allows = (runtime, key) => {
  const capability = {
    seed: "supports_seed_fingerprint",
    proxy: "supports_native_proxy"
  }[key];
  return capability && Object.hasOwn(runtime?.capabilities || {}, capability) ? runtime.capabilities[capability] !== false : runtime?.capabilities?.[key] !== false;
};
const profileDimensions = profile => profile?.width && profile?.height ? `${profile.width} × ${profile.height}` : "内核默认";
const protocolLabel = protocol => protocol === "anytls" ? "AnyTLS" : String(protocol || "代理").toUpperCase();
const networkPlace = network => [...new Set([network?.country || network?.countryCode, network?.region, network?.city].filter(Boolean))].join(" · ");
const timezoneSourceLabel = source => ({
  manual: "固定时区",
  proxy: "代理出口",
  direct: "本机出口",
  local: "本机时区 · 出口未确认"
})[source] || "尚未识别";
const platforms = {
  macos: "macOS",
  windows: "Windows",
  linux: "Linux"
};
const statuses = {
  stopped: "已停止",
  starting: "启动中",
  running: "运行中",
  error: "异常"
};
const navItems = [{
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
  id: "applications",
  label: "附加软件",
  icon: Desktop
}, {
  id: "monitor",
  label: "运行监控",
  icon: ChartLine
}];
function bytes(value) {
  if (value == null || !Number.isFinite(Number(value))) return "—";
  if (Number(value) === 0) return "0 B";
  const i = Math.min(Math.floor(Math.log(Number(value)) / Math.log(1024)), 3);
  return `${(Number(value) / 1024 ** i).toFixed(i > 0 ? 1 : 0)} ${["B", "KB", "MB", "GB"][i]}`;
}
function relativeTime(value, language, t) {
  if (!value) return t("尚未启动");
  const difference = Math.max(0, Date.now() - new Date(value).getTime());
  if (!Number.isFinite(difference)) return "—";
  if (difference < 60000) return t("刚刚");
  const locale = localeForInterfaceLanguage(language);
  const relative = new Intl.RelativeTimeFormat(locale, { numeric: "always" });
  if (difference < 3600000) return relative.format(-Math.floor(difference / 60000), "minute");
  if (difference < 86400000) return relative.format(-Math.floor(difference / 3600000), "hour");
  return new Date(value).toLocaleDateString(locale);
}
function Status({
  status = "stopped"
}) {
  const {
    t
  } = useI18n();
  return <span className={`status status-${status}`}><span className="status-dot" />{t(statuses[status] || status)}</span>;
}
function Button({
  children,
  icon: Icon,
  className = "",
  ...props
}) {
  const {
    t
  } = useI18n();
  return <button className={`button ${className}`} {...props}>{Icon && <Icon size={17} />}{typeof children === "string" ? t(children) : children}</button>;
}
function IconButton({
  icon: Icon,
  label,
  ...props
}) {
  const {
    t
  } = useI18n();
  return <button className="icon-button" aria-label={t(label)} title={t(label)} {...props}><Icon size={18} /></button>;
}
function Modal({
  title,
  subtitle,
  children,
  onClose,
  className = ""
}) {
  const {
    t
  } = useI18n();
  const panelRef = useRef(null),
    openerRef = useRef(document.activeElement);
  useEffect(() => {
    const previous = openerRef.current;
    const panel = panelRef.current;
    const focusable = () => Array.from(panel.querySelectorAll("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex=\"0\"]")).filter(element => element.getClientRects().length > 0);
    const focusFrame = requestAnimationFrame(() => (panel.querySelector("input:not(:disabled)") || focusable()[0] || panel).focus());
    const onKey = event => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
      if (event.key === "Tab") {
        const elements = focusable();
        if (!elements.length) return;
        if (!panel.contains(document.activeElement)) {
          event.preventDefault();
          elements[0].focus();
        } else if (event.shiftKey && document.activeElement === elements[0]) {
          event.preventDefault();
          elements.at(-1).focus();
        } else if (!event.shiftKey && document.activeElement === elements.at(-1)) {
          event.preventDefault();
          elements[0].focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      cancelAnimationFrame(focusFrame);
      requestAnimationFrame(() => {
        if (document.querySelector("[aria-modal=\"true\"]")) return;
        if (previous?.isConnected && !previous.disabled) previous.focus?.();else document.querySelector(".page-heading h1")?.focus();
      });
    };
  }, [onClose]);
  return <div className="modal-backdrop" onMouseDown={event => {
    if (event.target === event.currentTarget) onClose();
  }}><section className={`modal ${className}`} role="dialog" aria-modal="true" aria-labelledby="modal-title" ref={panelRef} tabIndex={-1}><div className="modal-heading"><div><h2 id="modal-title">{t(title)}</h2>{subtitle && <p>{t(subtitle)}</p>}</div><IconButton icon={X} label={t("关闭")} onClick={onClose} /></div>{children}</section></div>;
}
function Field({
  label,
  hint,
  error,
  errorId,
  className = "",
  children
}) {
  const {
    t
  } = useI18n();
  return <label className={`field ${className}`}><span className="field-label">{t(label)}</span>{children}{hint && <span className="field-hint">{t(hint)}</span>}{error && <span id={errorId} className="field-error">{t(error)}</span>}</label>;
}
function ProfileForm({
  profile,
  proxies,
  systemPlatform,
  engines,
  defaultEngine,
  groups,
  groupDescriptors,
  onSave,
  onClose,
  saving
}) {
  const {
    t
  } = useI18n();
  const [form, setForm] = useState(() => ({
    name: "",
    group: "",
    engine: preferredEngine(engines, defaultEngine),
    platform: {
      darwin: "macos",
      win32: "windows",
      linux: "linux"
    }[systemPlatform] || "macos",
    seed: Math.floor(Math.random() * 2147483646) + 1,
    locale: "",
    timezone: "",
    privacy: {
      mode: "standard"
    },
    width: 1440,
    height: 900,
    startUrl: "about:blank",
    proxyId: "",
    notes: "",
    ...Object.fromEntries(Object.entries(profile || {}).filter(([, value]) => value != null)),
    ...(profile ? {
      locale: profile.locale ?? "",
      timezone: profile.timezone ?? ""
    } : {}),
    ...(profile && Object.hasOwn(profile, "profileProxyId") ? {
      proxyId: profile.profileProxyId || ""
    } : {}),
    ...initialBrowserDeviceFields(profile, systemPlatform, profile?.engine || preferredEngine(engines, defaultEngine))
  }));
  const [errors, setErrors] = useState({});
  const [fixedModes, setFixedModes] = useState({
    locale: profile ? !!profile.locale : false,
    timezone: profile ? !!profile.timezone : false
  });
  const [advanced, setAdvanced] = useState(false);
  const formRef = useRef(null),
    manualValues = useRef({
      locale: profile?.locale || "zh-CN",
      timezone: profile?.timezone || "Asia/Shanghai"
    });
  const runtime = engines.find(item => item.id === form.engine);
  const deviceProfilesSupported = supportsBrowserDeviceProfiles(form.engine);
  const selectedDevice = getBrowserDeviceProfile(form.deviceProfileId);
  const deviceChoices = BROWSER_DEVICE_PROFILES.filter(device => device.id === defaultBrowserDeviceProfileId(systemPlatform));
  const groupDescriptor = groupDescriptors?.find(item => typeof item === "object" && item.name === form.group);
  const groupProxy = proxies.find(item => item.id === groupDescriptor?.proxyId);
  const groupEnforced = groupDescriptor?.proxy_mode === "enforced" && !!groupProxy;
  const effectiveProxy = groupEnforced ? groupProxy : proxies.find(item => item.id === form.proxyId) || groupProxy;
  const confirmedNetworkTimezone = effectiveProxy?.location?.confirmed ? effectiveProxy.location.timezone : null;
  const change = key => event => {
    setForm(value => key === "engine" ? changeBrowserDeviceEngine(value, event.target.value) : ({
      ...value,
      [key]: event.target.value
    }));
    setErrors(value => ({
      ...value,
      [key]: ""
    }));
  };
  const changeDeviceProfile = event => {
    setForm(value => selectBrowserDeviceProfile(value, event.target.value));
    setErrors(value => ({ ...value, deviceProfileId: "", platform: "", width: "", height: "" }));
  };
  const changeMode = key => event => {
    setFixedModes(value => ({
      ...value,
      [key]: event.target.value !== "auto"
    }));
    setForm(value => {
      if (event.target.value === "auto") {
        if (value[key]) manualValues.current[key] = value[key];
        return {
          ...value,
          [key]: ""
        };
      }
      return {
        ...value,
        [key]: manualValues.current[key]
      };
    });
    setErrors(value => ({
      ...value,
      [key]: ""
    }));
  };
  const invalid = key => ({
    name: key,
    "aria-invalid": errors[key] ? true : undefined,
    "aria-describedby": errors[key] ? `profile-error-${key}` : undefined
  });
  const fail = (key, message) => {
    setErrors({
      [key]: message
    });
    if (["seed", "width", "height", "platform", "locale", "timezone", "engine", "deviceProfileId"].includes(key)) setAdvanced(true);
    requestAnimationFrame(() => formRef.current?.elements.namedItem(key)?.focus());
  };
  const submit = event => {
    event.preventDefault();
    if (!form.name.trim()) {
      fail("name", t("请为环境填写名称。"));
      return;
    }
    if (!profile && runtime?.supported === false) {
      fail("engine", runtime.message || t("此内核暂不支持当前平台。"));
      return;
    }
    try {
      const url = new URL(form.startUrl || "about:blank");
      if (!["https:", "http:"].includes(url.protocol) && url.href !== "about:blank") throw new Error();
    } catch {
      fail("startUrl", t("请输入 http、https 地址或 about:blank。"));
      return;
    }
    if (fixedModes.locale && !form.locale.trim()) {
      fail("locale", t("请填写固定语言，或选择自动匹配。"));
      return;
    }
    if (!confirmedNetworkTimezone && fixedModes.timezone && !form.timezone.trim()) {
      fail("timezone", t("请填写固定时区，或选择自动匹配。"));
      return;
    }
    if (form.locale) {
      try {
        if (Intl.getCanonicalLocales(form.locale).length !== 1) throw new Error();
      } catch {
        fail("locale", t("请输入有效的语言代码，例如 zh-CN。"));
        return;
      }
    }
    if (!confirmedNetworkTimezone && form.timezone) {
      try {
        new Intl.DateTimeFormat("en", {
          timeZone: form.timezone
        });
      } catch {
        fail("timezone", t("请输入有效的时区，例如 Asia/Shanghai。"));
        return;
      }
    }
    const selectedProxy = groupEnforced ? groupProxy : proxies.find(item => item.id === form.proxyId) || groupProxy;
    if (form.engine === "browseforge-chromium" && selectedProxy && !browseForgeRegionFor(selectedProxy)) {
      fail("proxyId", t("BrowseForge Chromium 只支持美国纽约、加州、得州和加拿大安大略、不列颠哥伦比亚的网络；这个网络请用 CloakBrowser。"));
      return;
    }
    onSave({
      name: form.name.trim(),
      group: form.group.trim(),
      notes: form.notes,
      engine: form.engine,
      deviceProfileId: form.deviceProfileId,
      platform: form.platform,
      ...(allows(runtime, "seed") ? {
        seed: Number(form.seed)
      } : {}),
      locale: form.locale,
      timezone: confirmedNetworkTimezone ? "" : form.timezone,
      width: Number(form.width),
      height: Number(form.height),
      startUrl: form.startUrl || "about:blank",
      proxyId: form.proxyId || null,
      privacy: form.privacy || {
        mode: "standard"
      }
    });
  };
  const field = (key, label, children, props = {}) => <Field label={label} error={errors[key]} errorId={`profile-error-${key}`} {...props}>{children}</Field>;
  return <Modal title={profile ? t("编辑环境") : t("新建环境")} onClose={onClose} className="profile-modal"><form ref={formRef} onSubmit={submit}>
    <div className="modal-body">
      <div className="form-grid">
        {field("name", t("环境名称"), <input required maxLength={80} value={form.name} onChange={change("name")} placeholder={t("例如：日常工作")} {...invalid("name")} />, {
            className: "span-two"
          })}
        {field("proxyId", t("网络出口"), <select value={form.proxyId || ""} onChange={change("proxyId")} disabled={!allows(runtime, "proxy") || groupEnforced} {...invalid("proxyId")}><option value="">{groupProxy ? t("跟随分组 · {value1}", {
                value1: groupProxy.name
              }) : t("本机网络")}</option>{proxies.map(proxy => <option key={proxy.id} value={proxy.id}>{proxy.name}</option>)}</select>, {
            className: "span-two",
            hint: groupEnforced ? t("分组固定使用 {value1}", {
              value1: groupProxy.name
            }) : undefined
          })}
      </div>
      <div className="automatic-context-note"><ShieldCheck size={16} /><span>{t(confirmedNetworkTimezone ? "创建时确认位置与时区，浏览器、终端和附加软件共同使用。" : "时区、语言和定位自动跟随实际网络出口")}</span></div>
      <details className="advanced-settings" open={advanced} onToggle={event => setAdvanced(event.currentTarget.open)}>
        <summary>{t("高级设置")}<span>{t("浏览器、指纹与隐私")}</span></summary>
        <div className="form-grid">
          {field("engine", t("浏览器内核"), <select value={form.engine} onChange={change("engine")} disabled={!!profile} {...invalid("engine")}>{engines.map(item => <option key={item.id} value={item.id} disabled={item.supported === false}>{item.displayName || item.id}{item.supported === false ? t(" · 不可用") : ""}</option>)}{!runtime && <option value={form.engine}>{form.engine}</option>}</select>, {
              className: "span-two"
            })}
          <div className="browser-device-settings span-two">
            {field("deviceProfileId", t("设备档案"), <select value={form.deviceProfileId} onChange={changeDeviceProfile} disabled={!deviceProfilesSupported} {...invalid("deviceProfileId")}><option value={PROVIDER_DEFAULT_DEVICE_PROFILE_ID}>{t("自定义（保留当前配置）")}</option>{deviceChoices.map(device => <option key={device.id} value={device.id} disabled={!deviceProfilesSupported}>{t(device.label)}</option>)}</select>, {
              hint: t(deviceProfilesSupported ? "选择档案会填写平台与屏幕；切换网络不改变设备。" : "当前内核暂不支持固定设备档案。")
            })}
            {selectedDevice && <dl className="browser-device-summary" aria-label={t("设备档案")}><div><dt>{t("平台")}</dt><dd>{platforms[selectedDevice.platform]}</dd></div><div><dt>{t("屏幕")}</dt><dd>{selectedDevice.width} × {selectedDevice.height}</dd></div><div><dt>{t("逻辑处理器")}</dt><dd>{selectedDevice.hardwareConcurrency}</dd></div><div><dt>{t("浏览器内存")}</dt><dd>{selectedDevice.deviceMemory} GB</dd></div></dl>}
          </div>
          {field("group", t("分组"), <><input maxLength={60} list="profile-groups" value={form.group} onChange={change("group")} placeholder={t("未分组")} /><datalist id="profile-groups">{groups.map(group => <option key={group} value={group} />)}</datalist></>)}
          <Field label={t("隐私防护")} hint={t({ standard: "拦截已知的第三方追踪：内置规则加 EasyPrivacy 名单，不影响登录和网站功能。", strict: "在标准之上，再拦截标签管理器、错误上报和广告网络；个别网站可能缺少功能。", off: "不拦截追踪请求。" }[form.privacy?.mode || "standard"])}><select value={form.privacy?.mode || "standard"} onChange={event => setForm(value => ({
                ...value,
                privacy: {
                  mode: event.target.value
                }
              }))}><option value="standard">{t("标准")}</option><option value="strict">{t("严格")}</option><option value="off">{t("停用")}</option></select></Field>
          {field("locale", t("语言"), <><select aria-label={t("语言模式")} value={fixedModes.locale ? "fixed" : "auto"} onChange={changeMode("locale")}><option value="auto">{t("跟随网络出口")}</option><option value="fixed">{t("固定语言")}</option></select>{fixedModes.locale && <input aria-label={t("固定语言")} value={form.locale} onChange={change("locale")} disabled={!allows(runtime, "locale")} placeholder="zh-CN" {...invalid("locale")} />}</>, { hint: t("浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。") })}
          {field("timezone", t("时区"), confirmedNetworkTimezone ? <span className="field-hint">{confirmedNetworkTimezone}<br />{t("已保存配置")}</span> : <><select aria-label={t("时区模式")} value={fixedModes.timezone ? "fixed" : "auto"} onChange={changeMode("timezone")}><option value="auto">{t("跟随网络出口")}</option><option value="fixed">{t("固定时区")}</option></select>{fixedModes.timezone && <input aria-label={t("固定时区")} value={form.timezone} onChange={change("timezone")} disabled={!allows(runtime, "timezone")} placeholder="Asia/Shanghai" {...invalid("timezone")} />}</>)}
          {!selectedDevice && field("platform", t("指纹平台"), <select value={form.platform} onChange={change("platform")} disabled={!allows(runtime, "platform")} {...invalid("platform")}><option value="macos">macOS</option><option value="windows">Windows</option><option value="linux">Linux</option></select>)}
          {field("seed", t("指纹种子"), <div className="input-action"><input type="number" min="1" max="4294967295" required readOnly={!!profile} disabled={!allows(runtime, "seed")} value={allows(runtime, "seed") ? form.seed : ""} placeholder={t("不适用")} onChange={change("seed")} {...invalid("seed")} /><IconButton disabled={!!profile || !allows(runtime, "seed")} icon={ArrowsClockwise} label={t("随机生成种子")} type="button" onClick={() => setForm(value => ({
                ...value,
                seed: Math.floor(Math.random() * 2147483646) + 1
              }))} /></div>)}
          {!selectedDevice && field("width", t("屏幕宽度"), <div className="input-unit"><input required type="number" min="800" max="7680" value={form.width} onChange={change("width")} {...invalid("width")} /><span>px</span></div>)}
          {!selectedDevice && field("height", t("屏幕高度"), <div className="input-unit"><input required type="number" min="600" max="4320" value={form.height} onChange={change("height")} {...invalid("height")} /><span>px</span></div>)}
          {field("startUrl", t("启动页面"), <input value={form.startUrl} onChange={change("startUrl")} placeholder="about:blank" {...invalid("startUrl")} />, {
              className: "span-two"
            })}
          {field("notes", t("备注"), <textarea rows={2} value={form.notes} maxLength={1000} onChange={change("notes")} placeholder={t("选填")} />, {
              className: "span-two"
            })}
        </div>
      </details>
      {Object.values(errors).some(Boolean) && <div className="form-error" role="alert"><WarningCircle size={16} />{t("请修正标出的配置后再保存。")}</div>}
    </div>
    <div className="modal-footer"><Button type="button" onClick={onClose}>{t("取消")}</Button><Button type="submit" className="primary" disabled={saving}>{saving ? t("保存中…") : profile ? t("保存更改") : t("创建环境")}</Button></div>
  </form></Modal>;
}
function GroupForm({
  groups,
  count,
  onSave,
  onClose,
  saving
}) {
  const {
    t
  } = useI18n();
  const [group, setGroup] = useState("");
  return <Modal title={t("移动到分组")} subtitle={t("为 {value1} 个已选环境设置分组；留空可移到未分组。", {
    value1: count
  })} onClose={onClose} className="confirm-modal"><form onSubmit={event => {
      event.preventDefault();
      onSave(group.trim());
    }}><div className="modal-body"><Field label={t("分组名称")}><input maxLength={60} list="bulk-groups" value={group} onChange={event => setGroup(event.target.value)} placeholder={t("未分组")} /></Field><datalist id="bulk-groups">{groups.map(value => <option key={value} value={value} />)}</datalist></div><div className="modal-footer"><Button type="button" onClick={onClose}>{t("取消")}</Button><Button type="submit" className="primary" disabled={saving}>{saving ? t("处理中…") : t("移动分组")}</Button></div></form></Modal>;
}
function MigrationForm({
  migration,
  onMigrate,
  onClose,
  saving
}) {
  const {
    t
  } = useI18n();
  const [confirmed, setConfirmed] = useState(false);
  const candidates = (migration.profiles || []).filter(profile => !profile.migrated);
  return <Modal title={t("复制迁移旧环境")} subtitle={t("原资料保留，迁移前会创建本机备份。")} onClose={onClose}><form onSubmit={event => {
      event.preventDefault();
      if (confirmed && candidates.length) onMigrate(candidates.map(profile => profile.id));
    }}><div className="modal-body"><p className="form-note">{migration.notice || t("复制选定环境的配置与浏览资料，旧工作区不会被删除。")}</p><div className="migration-profiles">{(migration.profiles || []).map(profile => <div key={profile.id}><strong>{profile.name}</strong><span>{profile.migrated ? t("已迁移") : t("等待迁移")}</span></div>)}</div><p className="form-note">{t("本次复制")}{candidates.length}{t("个尚未迁移的环境。")}{migration.proxyCount ? t("同时保留 {value1} 个旧网络出口的本机绑定。", {
            value1: migration.proxyCount
          }) : ""}</p><label className="migration-confirm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /><span>{t("我已关闭旧版本启动的所有浏览器会话")}</span></label></div><div className="modal-footer"><Button type="button" onClick={onClose}>{t("取消")}</Button><Button className="primary" type="submit" disabled={saving || !confirmed || !candidates.length}>{saving ? t("正在复制…") : t("备份并复制迁移")}</Button></div></form></Modal>;
}
function ImportMappingForm({
  session,
  proxies,
  onImport,
  onAddProxy,
  onClose,
  saving
}) {
  const {
    t
  } = useI18n();
  const [proxyMap, setProxyMap] = useState({}),
    [errors, setErrors] = useState({});
  const formRef = useRef(null),
    refs = session.proxyRefs || [];
  const submit = event => {
    event.preventDefault();
    const missing = refs.filter(ref => !proxies.some(proxy => proxy.id === proxyMap[ref.id]));
    if (missing.length) {
      setErrors(Object.fromEntries(missing.map(ref => [ref.id, t("请选择一个本机网络出口。")])));
      requestAnimationFrame(() => formRef.current?.elements.namedItem(`map-${missing[0].id}`)?.focus());
      return;
    }
    onImport(Object.fromEntries(refs.map(ref => [ref.id, proxyMap[ref.id]])));
  };
  return <Modal title={t("映射导入的网络出口")} subtitle={t("即将导入 {value1} 个环境。为每个原出口选择本机代理。", {
    value1: session.profileCount || 0
  })} onClose={onClose} className="import-modal"><form ref={formRef} onSubmit={submit}><div className="modal-body"><p className="form-note import-notice">{t("导出文件不含代理密码。确认映射后，导入的环境会绑定你选择的本机出口。")}</p>{!proxies.length ? <div className="import-empty"><GlobeHemisphereWest size={27} /><strong>{t("请先添加网络出口")}</strong><p>{t("本机还没有可映射的代理。添加出口及凭据后，再重新导入此文件。")}</p><Button type="button" icon={Plus} onClick={onAddProxy}>{t("前往网络出口")}</Button></div> : <div className="import-mappings">{refs.map(ref => <div className="import-mapping" key={ref.id}><div className="import-source"><strong>{ref.name || t("未命名出口")}</strong><span>{(ref.protocol || t("代理")).toUpperCase()} · {ref.host ? `${ref.host}${ref.port ? `:${ref.port}` : ""}` : t("服务器信息已隐藏")}</span>{ref.requiresCredentials && <small>{t("此出口原本需要认证，请确认本机代理已填写凭据。")}</small>}</div><Field label={t("映射到本机出口")} error={errors[ref.id]} errorId={`import-error-${ref.id}`}><select name={`map-${ref.id}`} value={proxyMap[ref.id] || ""} aria-label={t("映射 {value1}", {
                value1: ref.name || ref.id
              })} aria-invalid={errors[ref.id] ? true : undefined} aria-describedby={errors[ref.id] ? `import-error-${ref.id}` : undefined} onChange={event => {
                setProxyMap(value => ({
                  ...value,
                  [ref.id]: event.target.value
                }));
                setErrors(value => ({
                  ...value,
                  [ref.id]: ""
                }));
              }}><option value="" disabled>{t("请选择本机网络出口")}</option>{proxies.map(proxy => <option key={proxy.id} value={proxy.id}>{proxy.name} · {protocolLabel(proxy.protocol)}</option>)}</select></Field></div>)}</div>}</div><div className="modal-footer"><Button type="button" onClick={onClose} disabled={saving}>{t("取消")}</Button><Button type="submit" className="primary" disabled={saving || !proxies.length || !refs.length}>{saving ? t("正在导入…") : t("确认映射并导入")}</Button></div></form></Modal>;
}
function NetworkResult({
  network,
  checking = false,
  compact = false
}) {
  const {
    t,
    language
  } = useI18n();
  const verified = network?.ok === true && network?.scope === "egress" && !!network.ip;
  return <div role="status" aria-live="polite" className={`network-result ${compact ? "compact" : ""} ${verified ? "verified" : network?.ok === false ? "failed" : ""}`}>
    {checking ? <><ArrowsClockwise size={16} className="spin" /><div><strong>{t("正在识别出口…")}</strong><small>{t("通过代理访问出口查询服务")}</small></div></> : verified ? <><CheckCircle size={17} /><div><strong className="mono-value">{network.ip}</strong>{networkPlace(network) && <small>{networkPlace(network)}</small>}<small>{network.timezone || t("时区尚未识别")}</small><span className="network-source">{network.source || t("出口查询")}{network.checkedAt ? ` · ${relativeTime(network.checkedAt, language, t)}` : ""}</span></div></> : network ? <><WarningCircle size={17} /><div><strong>{t("出口识别失败")}</strong><small>{network.message || t("未获得有效的出口资料，请检查代理参数后重试。")}</small></div></> : <><GlobeHemisphereWest size={17} /><div><strong>{t("尚未识别")}</strong><small>{t("检测实际出口 IP、地区和时区")}</small></div></>}
  </div>;
}
function ProxyForm({
  proxy,
  proxyCore,
  onSave,
  onClose,
  saving
}) {
  const {
    t
  } = useI18n();
  const [form, setForm] = useState(() => initialProxyForm(proxy));
  const [visible, setVisible] = useState(false),
    [preview, setPreview] = useState(null),
    [location, setLocation] = useState(() => locationFormState(proxy?.location)),
    [step, setStep] = useState("connection"),
    [checking, setChecking] = useState(false),
    [checkError, setCheckError] = useState("");
  const network = preview?.network;
  const recommendation = preview?.locationRecommendation;
  const verified = verifiedLocationPreview(preview);
  const anytls = form.protocol === "anytls";
  const checkSequence = useRef(0);
  useEffect(() => () => {
    checkSequence.current++;
  }, []);
  const update = (key, value) => {
    if (proxyRouteFields.has(key)) {
      checkSequence.current++;
      setChecking(false);
      setPreview(null);
      setLocation(previous => ({ ...previous, confirmed: false }));
    }
    setCheckError("");
    setForm(previous => ({
      ...previous,
      [key]: value
    }));
  };
  const change = key => event => update(key, event.target.value);
  const detect = async () => {
    if (!api.isDesktop) return;
    const error = proxyFormError(form);
    if (error) {
      setCheckError(error);
      return;
    }
    const sequence = ++checkSequence.current;
    setChecking(true);
    setCheckError("");
    setPreview(null);
    setLocation(previous => ({ ...previous, confirmed: false }));
    try {
      const result = await api.call("previewProxyNetwork", {
        proxy: proxyConfig({
          ...form,
          name: form.name.trim() || t("待检测出口")
        })
      });
      if (sequence === checkSequence.current) {
        setPreview(result);
        if (verifiedLocationPreview(result)) setStep("location");
        else setCheckError(result?.network?.message || t("出口识别未完成，请重试。"));
      }
    } catch (error) {
      if (sequence === checkSequence.current) setCheckError(error.message || t("出口识别未完成，请重试。"));
    } finally {
      if (sequence === checkSequence.current) setChecking(false);
    }
  };
  const updateLocation = (key, value) => {
    setLocation(previous => ({ ...previous, [key]: value, confirmed: false }));
    setCheckError("");
  };
  let manualLocation = null;
  if (location.mode === "manual") {
    try { manualLocation = normalizeNetworkLocation({ ...location, confirmed: true }); } catch {}
  }
  const mapsUrl = location.mode === "ip" ? recommendation?.mapsUrl : manualLocation?.mapsUrl || googleMapsLocationURL({ label: location.label });
  const openMap = async () => {
    if (!mapsUrl) return;
    try {
      if (api.isDesktop) await api.call("openNetworkLocationMap", { url: mapsUrl });
      else window.open(mapsUrl, "_blank", "noopener,noreferrer");
    } catch (error) { setCheckError(error.message || t("地图链接未打开，请重试。")); }
  };
  return <Modal title={proxy ? t("编辑网络环境") : t("创建网络环境")} subtitle={t("先验证代理，再确认位置与时区。")} onClose={onClose} className="proxy-modal"><form onSubmit={event => {
      event.preventDefault();
      const error = proxyFormError(form);
      if (error) {
        setCheckError(error);
        return;
      }
      if (api.isDesktop && step === "connection") { detect(); return; }
      try {
        const config = proxyConfig(form);
        if (api.isDesktop) config.location = locationConfirmation(location, preview);
        onSave(config, preview?.locationPreviewToken, preview?.network);
      } catch (error) { setCheckError(error.message); }
    }}><div className="network-flow-steps" aria-label={t("创建网络环境")}><span className={step === "connection" ? "current" : "complete"}><span>1</span>{t("代理连接")}</span><CaretRight size={14} /><span className={step === "location" ? "current" : ""}><span>2</span>{t("位置与时区")}</span></div><div className="modal-body">{step === "connection" ? <><div className="form-grid">
    <Field label={t("名称")} className="span-two"><input required maxLength={80} value={form.name} onChange={change("name")} placeholder={t("例如：东京节点")} /></Field>
    <Field label={t("协议")}><select value={form.protocol} onChange={change("protocol")}><option value="http">HTTP</option><option value="https">HTTPS</option><option value="socks5">SOCKS5</option><option value="anytls">{t("AnyTLS · 内置连接")}</option></select></Field>
    <Field label={t("端口")}><input required type="number" min="1" max="65535" value={form.port} onChange={change("port")} placeholder={anytls ? "443" : "8080"} /></Field>
    <Field label={t("服务器地址")} className="span-two"><input required value={form.host} onChange={change("host")} placeholder={anytls ? "node.example.com" : t("127.0.0.1 或 proxy.example.com")} /></Field>
    {!anytls && <Field label={t("用户名（选填）")}><input value={form.username} onChange={change("username")} autoComplete="off" /></Field>}
    <Field label={anytls ? t("节点密码") : t("密码（选填）")} className={anytls ? "span-two" : ""}><div className="input-action"><input required={anytls} type={visible ? "text" : "password"} value={form.password} onChange={change("password")} autoComplete="new-password" /><IconButton type="button" icon={visible ? EyeSlash : Eye} label={visible ? t("隐藏密码") : t("显示密码")} onClick={() => setVisible(!visible)} /></div></Field>
    {anytls && <Field label={t("TLS 服务器名称 / SNI（选填）")} className="span-two" hint={t("留空时使用服务器地址；如果服务商提供了 SNI，请填写指定值。")}><input value={form.serverName || ""} onChange={change("serverName")} placeholder={form.host.trim() || t("默认使用服务器地址")} autoComplete="off" /></Field>}
    </div>
    {anytls && <><div className={`anytls-core-note ${api.isDesktop && proxyCore?.supported === false ? "unavailable" : ""}`} role={api.isDesktop && proxyCore?.supported === false ? "status" : undefined}><ShieldCheck size={17} /><span>{!api.isDesktop ? t("AnyTLS 由境舱桌面应用内置连接，浏览器与终端共用节点，无需单独运行 Clash。") : proxyCore?.supported === false ? proxyCore.message || t("当前安装无法使用内置 AnyTLS。可先保存节点配置，检测或启动时会显示具体问题。") : t("境舱在应用内连接 AnyTLS 节点，浏览器与终端共用出口，无需单独运行 Clash。")}</span></div>
      <details className="advanced-settings proxy-tls-settings"><summary>{t("高级节点设置")}<span>{form.skipCertVerify ? t("证书验证已关闭") : t("验证服务器证书")}</span></summary><div className="proxy-tls-options">
        <label className="proxy-check-option"><input type="checkbox" checked={!form.skipCertVerify} onChange={event => update("skipCertVerify", !event.target.checked)} /><span>{t("验证 TLS 证书")}</span></label>
        <p className="field-hint">{t("如果服务商使用自签名证书，可按其配置关闭验证。TLS 客户端指纹使用 Chrome。")}</p>
        <Field label={t("ALPN（选填）")} hint={t("按服务商配置填写，用英文逗号分隔；留空使用内核默认值。")}><input value={Array.isArray(form.alpn) ? form.alpn.join(", ") : form.alpn || ""} onChange={change("alpn")} placeholder="h2, http/1.1" autoComplete="off" /></Field>
        <div className="proxy-udp-option"><label className="proxy-check-option"><input type="checkbox" checked={form.udp !== false} onChange={event => update("udp", event.target.checked)} /><span>{t("启用节点 UDP")}</span></label><p className="field-hint">{t("控制此节点的 UDP 转发，不会自动接管本机程序的全部 UDP 流量。")}</p></div>
      </div></details></>}
    <details className="advanced-settings proxy-region-settings"><summary>{t("高级设置")}</summary><div className="form-grid"><Field label={t("代理地域（选填）")} className="span-two" hint={t("BrowseForge Chromium 使用代理时必填，例如 us-ny；此标签不会替代实际出口检测。")}><input maxLength={64} value={form.region || ""} onChange={change("region")} placeholder="us-ny" /></Field></div></details>
    {checking && <div className="proxy-detect-card"><NetworkResult checking /></div>}
    {!api.isDesktop && <p className="native-feature-note">{t("真实出口识别需要境舱桌面应用。")}</p>}
    <div className="form-note">{t("代理凭据仅保存在本机。导出的环境配置不包含密码。")}</div></> : <>
      <NetworkResult network={network} compact />
      <div className="location-mode-control" role="group" aria-label={t("出口位置")}><button type="button" className={location.mode === "ip" ? "selected" : ""} aria-pressed={location.mode === "ip"} onClick={() => updateLocation("mode", "ip")}>{t("IP 推荐位置")}</button><button type="button" className={location.mode === "manual" ? "selected" : ""} aria-pressed={location.mode === "manual"} onClick={() => updateLocation("mode", "manual")}>{t("手动选择位置")}</button></div>
      {location.mode === "ip" ? <div className="location-recommendation"><strong>{recommendation?.label || networkPlace(network) || network?.countryCode}</strong>{recommendation?.latitude != null && <small className="mono-value">{Number(recommendation.latitude).toFixed(4)}, {Number(recommendation.longitude).toFixed(4)}</small>}<p className="field-hint">{t("IP 定位为城市级估计，不代表住宅地址。")}</p></div> : <div className="form-grid location-manual-fields">
        <Field label={t("地址或地点")} className="span-two"><input maxLength={500} value={location.label} onChange={event => updateLocation("label", event.target.value)} autoComplete="off" /></Field>
        <Field label={t("Google Maps 链接（选填）")} className="span-two"><input type="url" maxLength={2048} value={location.mapsUrl} onChange={event => updateLocation("mapsUrl", event.target.value)} placeholder="https://www.google.com/maps/…" /></Field>
        <details className="advanced-settings span-two"><summary>{t("坐标（选填）")}</summary><div className="form-grid"><Field label={t("纬度")}><input type="number" min="-90" max="90" step="any" value={location.latitude} onChange={event => updateLocation("latitude", event.target.value)} /></Field><Field label={t("经度")}><input type="number" min="-180" max="180" step="any" value={location.longitude} onChange={event => updateLocation("longitude", event.target.value)} /></Field></div></details>
        {manualLocation?.latitude == null && <p className="field-hint span-two">{t("地址文字未转换为坐标；可粘贴地图地点链接或填写坐标。")}</p>}
      </div>}
      <div className="location-map-row"><Button type="button" icon={ArrowSquareOut} onClick={openMap} disabled={!mapsUrl}>{t("在 Google Maps 中查看")}</Button></div>
      <div className="location-timezone"><Clock size={16} /><strong>{network?.timezone || t("时区尚未识别")}</strong><span>{t("时区跟随实际代理出口。")}</span></div>
      <label className="location-confirmation"><input type="checkbox" checked={location.confirmed} onChange={event => { setLocation(previous => ({ ...previous, confirmed: event.target.checked })); setCheckError(""); }} /><span>{t("我确认这个网络环境的位置与时区")}</span></label>
    </>}{checkError && <p className="field-error network-flow-error" role="alert">{t(checkError)}</p>}</div><div className="modal-footer"><Button type="button" onClick={step === "location" ? () => setStep("connection") : onClose} disabled={saving}>{t(step === "location" ? "上一步" : "取消")}</Button><Button type="submit" className="primary" disabled={saving || checking || step === "location" && (!verified || !location.confirmed)}>{saving ? t("保存中…") : checking ? t("检测中…") : !api.isDesktop ? t("保存网络出口") : step === "connection" ? t("检测并继续") : t("保存网络环境")}</Button></div></form></Modal>;
}
/* Where links from an environment open: its own browser first, the other
 * browsers of its network next, and the system browser last, which is said to
 * leave the environment. */
function LinkBrowserChoices({ candidates, chosen, onChoose, disabled = false }) {
  const { t } = useI18n();
  return <div className="network-choice-list">{[...candidates, null].map((item, index) => {
    const value = item ? item.id : SYSTEM_BROWSER, selected = chosen === value;
    return <button type="button" key={value || "own"} disabled={disabled} className={`network-choice ${selected ? "selected" : ""}`} aria-pressed={selected} onClick={() => onChoose(value)}>
      {item ? <Browsers size={20} /> : <GlobeHemisphereWest size={20} />}
      <span><strong>{item ? item.name : t("系统默认浏览器")}</strong><small>{item ? `${index === 0 ? `${t("本境舱")} · ` : ""}${t(item.status === "running" ? "运行中" : "已停止")}` : t("不使用境舱浏览器；链接会交给系统默认浏览器，不经过境舱网络。")}</small></span>
      {selected && <CheckCircle size={19} />}</button>;
  })}</div>;
}
function AttachApplicationForm({ profiles, proxies, groups, applications, selectedId, isActive = () => false, onSave, onClose, onAddNetwork, saving }) {
  const { t } = useI18n();
  const choices = networkApplicationChoices(proxies, groups, profiles);
  const preferred = choices.find(choice => choice.profileIds.includes(selectedId));
  const [choiceId, setChoiceId] = useState(preferred?.id || choices[0]?.id || "");
  const [step, setStep] = useState("network");
  const [query, setQuery] = useState("");
  const [catalog, setCatalog] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [picked, setPicked] = useState(null);
  const [retry, setRetry] = useState(0);
  const [browserId, setBrowserId] = useState("");
  const choice = choices.find(item => item.id === choiceId);
  /* The software runs in the environment the save will choose (or create); its
   * own browser is the default, then the group's other browsers. */
  const owner = choice ? chooseApplicationProfile(choice, profiles, selectedId, isActive) : null;
  const ownBrowser = owner ?? (choice ? { id: "", name: `${picked?.name || t("选择软件")} · ${choice.name}`, status: "stopped" } : null);
  const browsers = owner ? linkBrowsersOf(profiles, owner) : ownBrowser ? [ownBrowser] : [];
  useEffect(() => {
    if (step !== "application") return;
    let current = true;
    setLoading(true);
    setError("");
    const timer = setTimeout(async () => {
      try {
        const result = await api.call("listLocalApplications", { query, limit: 200 });
        if (!current) return;
        if (result?.available !== true || !Array.isArray(result.applications)) throw new Error(t("本地软件需要桌面应用"));
        setCatalog(result);
      } catch (value) { if (current) setError(value.message || t("软件列表读取失败，请重试。")); }
      finally { if (current) setLoading(false); }
    }, query ? 180 : 0);
    return () => { current = false; clearTimeout(timer); };
  }, [step, query, retry]);
  const chooseFromFile = async () => {
    setError("");
    try {
      const result = await api.call("pickApplication");
      if (result?.path) {
        if (isApplicationAlreadyAttached(result, applications)) throw new Error(t("软件已附加到其他境舱，请先移除原绑定。"));
        setPicked(result);
      }
    } catch (value) { setError(value.message || t("操作未完成，请重试。")); }
  };
  const steps = ["network", "application", "browser"];
  const stepIndex = steps.indexOf(step);
  return <Modal title={t(step === "network" ? "选择网络分组" : step === "application" ? "选择本地软件" : "链接使用的浏览器")} onClose={onClose} className="attach-application-modal">
    <div className="network-flow-steps">{steps.map((name, index) => <React.Fragment key={name}>{index > 0 && <CaretRight size={14} />}<span className={step === name ? "current" : index < stepIndex ? "complete" : ""}><span>{index + 1}</span>{t(name === "network" ? "网络分组" : name === "application" ? "选择软件" : "浏览器")}</span></React.Fragment>)}</div>
    <div className="modal-body">{step === "browser" ? <>
      <p className="field-hint">{t("选定后，终端命令和软件发起的登录链接都在这个浏览器中打开。")}</p>
      <LinkBrowserChoices candidates={browsers} chosen={browserId || ownBrowser?.id || ""} onChoose={value => setBrowserId(value === ownBrowser?.id ? "" : value)} />
    </> : step === "network" ? choices.length ? <div className="network-choice-list">{choices.map(item => <button type="button" key={item.id} className={`network-choice ${choiceId === item.id ? "selected" : ""}`} aria-pressed={choiceId === item.id} onClick={() => setChoiceId(item.id)}><GlobeHemisphereWest size={21} /><span><strong>{item.name}</strong><small>{item.group ? item.proxy.name : protocolLabel(item.proxy.protocol)} · {item.proxy.location?.confirmed ? item.proxy.location.label || item.proxy.location.timezone : t("位置尚未确认")}</small></span>{choiceId === item.id && <CheckCircle size={19} />}</button>)}</div> : <div className="application-picker-empty"><GlobeHemisphereWest size={30} /><strong>{t("先创建网络环境")}</strong><Button type="button" onClick={onAddNetwork} icon={Plus}>{t("创建网络环境")}</Button></div> : <>
      <div className="selected-network-context"><GlobeHemisphereWest size={18} /><strong>{choice?.name}</strong><span>{choice?.proxy.location?.timezone || choice?.proxy.network?.timezone || t("自动时区")}</span></div>
      <div className="search-input application-picker-search"><MagnifyingGlass size={17} /><input value={query} onChange={event => setQuery(event.target.value)} maxLength={256} placeholder={t("搜索本地软件")} aria-label={t("搜索本地软件")} /></div>
      <div className="local-application-list" aria-live="polite">{loading ? <div className="application-picker-empty"><ArrowsClockwise className="spin" size={23} /><span>{t("正在读取本地软件…")}</span></div> : error ? <div className="application-picker-empty"><WarningCircle size={24} /><span>{t(error)}</span><Button type="button" onClick={() => setRetry(value => value + 1)}>{t("重新读取")}</Button></div> : catalog?.applications.length ? catalog.applications.map(application => {
        const attached = isApplicationAlreadyAttached(application, applications);
        return <button type="button" key={application.identity || application.path} className={`local-application-choice ${picked?.path === application.path ? "selected" : ""}`} disabled={attached} aria-pressed={picked?.path === application.path} title={application.path} onClick={() => setPicked(application)}><ApplicationIcon path={application.path} size={30} className="choice-icon" /><span>{application.name}</span>{attached ? <small>{t("已附加")}</small> : picked?.path === application.path && <CheckCircle size={18} />}</button>;
      }) : <div className="application-picker-empty"><Desktop size={27} /><span>{t(query ? "没有匹配的软件" : "未找到本地软件")}</span></div>}</div>
      {catalog?.truncated && <p className="field-hint">{t("列表可能不完整，可搜索名称或选择文件。")}</p>}
      <div className="application-picker-file"><Button type="button" icon={FolderOpen} onClick={chooseFromFile} disabled={saving}>{t("从文件选择…")}</Button>{picked && <span className="application-picked"><ApplicationIcon path={picked.path} size={22} className="choice-icon" /><strong title={picked.path}>{picked.name || picked.path.split(/[\\/]/).pop()}</strong></span>}</div>
      <p className="field-hint">{t("使用已确认的网络环境；定位支持取决于软件。")}</p>
    </>}{step === "network" && error && <p className="field-error" role="alert">{t(error)}</p>}</div>
    <div className="modal-footer"><Button type="button" disabled={saving} onClick={step === "network" ? onClose : () => { setStep(steps[stepIndex - 1]); setError(""); }}>{t(step === "network" ? "取消" : "上一步")}</Button><Button className="primary" disabled={saving || !choice || step === "application" && (!picked || isApplicationAlreadyAttached(picked, applications))} onClick={async () => {
      if (!choice) { setError(t("网络分组已改变，请重新选择。")); return; }
      setError("");
      if (step !== steps.at(-1)) { setStep(steps[stepIndex + 1]); return; }
      const result = await onSave(choice, picked, browserId || null);
      if (!result?.ok) setError(result?.message || t("操作未完成，请重试。"));
    }}>{saving ? t("保存中…") : step === steps.at(-1) ? t("添加软件") : t(step === "network" ? "选择软件" : "下一步")}</Button></div>
  </Modal>;
}
function BrowserDetail({
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
  editingDisabled,
  t
}) {
  if (!profile) return <div className="detail-empty"><Browsers size={32} /><h2>{t("浏览器详情")}</h2><p>{t("选择一个环境")}</p></div>;
  const networkPresentation = savedNetworkPresentation(profile, proxy);
  const running = profile.status === "running";
  const starting = profile.status === "starting" || pending[`startProfile:${profile.id}`];
  return <>
    <div className="detail-heading"><div className="detail-title-line"><h2 title={profile.name}>{profile.name}</h2><Status status={profile.status} /></div><p>{runtime.displayName || runtime.id}</p></div>
    <div className={`browser-preview ${profile.screenshot ? "has-screenshot" : ""}`}>{profile.screenshot ? <img src={profile.screenshot} alt={t("{name} 的浏览器窗口", {
        name: profile.name
      })} /> : <div className="preview-placeholder"><Browsers size={34} weight="duotone" /><strong>{t(running ? "会话正在运行" : starting ? "正在启动浏览器" : "浏览器待启动")}</strong></div>}</div>
    <div className="session-controls"><Button className="primary session-primary" icon={running ? ArrowSquareOut : runtime.installed ? Play : DownloadSimple} disabled={starting || busy || runtime.installing || !running && runtime.supported === false} onClick={running ? onFocus : runtime.installed ? onStart : onInstall}>{t(running ? "打开浏览器" : starting ? "启动中…" : runtime.installed ? "启动浏览器" : "安装浏览器内核")}</Button><IconButton icon={Stop} label="停止浏览器" disabled={!running || busy} onClick={onStop} /></div>
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
          }[profile.privacy?.mode || "standard"])}<small>{profile.privacy?.mode === "off" ? t("防护已关闭") : profile.privacyProtection?.enabled ? t("本次已拦截 {count} 个追踪请求", { count: profile.privacyProtection.blockedRequests ?? 0 }) : t("内置规则与 EasyPrivacy 名单")}</small></dd></div>
      {profile.network?.ok && <div><dt>{t("实际出口")}</dt><dd>{profile.network.ip}<small>{networkPlace(profile.network)}</small></dd></div>}
      <div><dt>{t("资源占用")}</dt><dd>{profile.cpuPercent == null ? "—" : `${Number(profile.cpuPercent).toFixed(0)}% CPU`} · {bytes(profile.memoryBytes)}</dd></div>
      <div><dt>{t("浏览数据")}</dt><dd>{bytes(profile.dataBytes)}</dd></div>
    </dl>
    <div className="detail-actions"><Button icon={PencilSimple} disabled={editingDisabled} onClick={onEdit}>编辑配置</Button></div>
    <div className="danger-actions"><button disabled={editingDisabled} onClick={onClear}>{t("清空浏览数据…")}</button></div>
  </>;
}
export function App() {
  const route = new URLSearchParams(window.location.search);
  const { phase } = useI18n();
  if (route.get("view") === "terminal") return <TerminalWindowApp profileId={route.get("profileId")} sessionId={route.get("sessionId")} />;
  const initializing = phase !== "ready";
  return <><div className="workspace-content" inert={initializing ? true : undefined} aria-hidden={initializing ? true : undefined}><WorkspaceApp /></div><LanguageWelcome /></>;
}
function WorkspaceApp() {
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
    [filter, setFilter] = useState("all"),
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
  const acceptSnapshot = useCallback(value => {
    if (!value || !Array.isArray(value.profiles) || !Array.isArray(value.proxies) || !value.system || typeof value.system !== "object") return false;
    const next = {
      ...initialSnapshot,
      ...value
    };
    snapshotRef.current = next;
    setSnapshot(next);
    setSelectedId(current => value.profiles.some(profile => profile.id === current) ? current : value.profiles[0]?.id || null);
    setCheckedIds(ids => ids.filter(id => value.profiles.some(profile => profile.id === id)));
    return true;
  }, []);
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
  const closeModal = useCallback(() => {
    if (pendingRef.current.has("attachApplication:")) return;
    const session = modalRef.current?.type === "importMapping" ? modalRef.current.session : null;
    if (session && pendingRef.current.has(`importProfiles:${session.importId}`)) return;
    if (session?.importId) api.call("cancelImport", {
      importId: session.importId
    }).catch(() => {});
    setModal(null);
  }, []);
  const perform = async (method, args = {}, success, key = `${method}:${args.id || args.runtimeId || ""}`, quiet = false) => {
    if (pendingRef.current.has(key)) return {
      ok: false,
      message: t("此操作正在进行中。")
    };
    pendingRef.current.add(key);
    setPending(value => ({
      ...value,
      [key]: true
    }));
    try {
      const result = await api.call(method, args);
      if (!acceptSnapshot(result)) await refresh();
      if (success && !result?.canceled && !quiet) setToast({
        type: "success",
        message: success
      });
      return {
        ok: true,
        result
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
    selectedRuntime = runtimeFor(selected),
    activeProfiles = profiles.filter(profile => ["running", "starting"].includes(profile.status)),
    runningCount = activeProfiles.length,
    startingCount = profiles.filter(profile => profile.status === "starting").length;
  const counts = {
    all: profiles.length,
    running: runningCount,
    stopped: profiles.filter(profile => profile.status === "stopped").length,
    error: profiles.filter(profile => profile.status === "error").length
  };
  const filteredProfiles = profiles.filter(profile => {
    const proxy = proxies.find(item => item.id === profile.proxyId);
    return (groupFilter === "*" || (profile.group || "") === groupFilter) && (filter === "all" || profile.status === filter || filter === "running" && profile.status === "starting") && `${profile.name} ${profile.group || ""} ${proxy?.name || ""} ${proxy?.host || ""}`.toLowerCase().includes(query.toLowerCase());
  });
  const totalBytes = profiles.reduce((sum, profile) => sum + (profile.dataBytes || 0), 0),
    installedCount = engines.filter(item => item.installed).length;
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
      setFilter("all");
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
      setFilter("all");
      setGroupFilter("*");
      setQuery("");
    }
  };
  const importProfiles = async (args = {}) => {
    const before = new Set(profiles.map(profile => profile.id));
    const response = await perform("importProfiles", args, undefined, `importProfiles:${args.importId || ""}`);
    if (!response.ok || response.result?.canceled) return;
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
    setFilter("all");
    setGroupFilter("*");
    setQuery("");
    setSelectedId(response.result.profiles.find(profile => !before.has(profile.id))?.id || selectedId);
    setToast({
      type: "success",
      message: t("环境配置已导入")
    });
  };
  const saveProxy = async (proxy, locationPreviewToken, previewNetwork) => {
    const existingIds = new Set(proxies.map(item => item.id));
    if (proxy.id) {
      proxyTestTokens.current[proxy.id] = (proxyTestTokens.current[proxy.id] || 0) + 1;
      setProxyTests(value => {
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
      if (api.isDesktop && saved && previewNetwork?.ok === true) setProxyTests(value => ({ ...value, [saved.id]: previewNetwork }));
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
    setProxyTests(value => ({
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
      setProxyTests(value => ({
        ...value,
        [proxy.id]: result
      }));
      const verified = result.ok === true && result.scope === "egress" && !!result.ip;
      setToast({
        type: verified ? "success" : "error",
        message: verified ? `${proxy.name}：${result.ip}${result.timezone ? ` · ${result.timezone}` : ""}` : result.message || t("未获得有效的出口资料。")
      });
      await refresh();
    } catch (error) {
      if (proxyTestTokens.current[proxy.id] !== token) return;
      setProxyTests(value => ({
        ...value,
        [proxy.id]: {
          ok: false,
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
  const resumeRuntime = runtimeFor(resumeProfile);
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
  const showTerminal = id => {
    setTerminalVisible(true);
    setTerminalRequest({
      profileId: id,
      nonce: Date.now()
    });
  };
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
  useEffect(() => {
    if (!api.isDesktop || page !== "settings") return;
    api.call("linkRouterStatus").then(value => setLinkRouter(value)).catch(() => setLinkRouter(null));
  }, [page, snapshot.settings]);
  const linkBrowsersFor = profile => linkBrowsersOf(profiles, profile);
  const linkBrowserName = (candidates, chosenId) => { const value = linkBrowserChoice(candidates, chosenId); return value === SYSTEM_BROWSER ? t("系统默认浏览器") : candidates.find(item => item.id === value)?.name || t("系统默认浏览器"); };
  const terminalLinkBrowsers = linkBrowsersFor(selected);
  /* Save where an environment's terminal links open, then have the dock read
   * the stored value back so every view names the same browser. */
  const [terminalRefresh, setTerminalRefresh] = useState(0);
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
  const navigate = target => {
    setPage(target);
    setTerminalExpanded(false);
    setTerminalVisible(target === "terminals");
    if (target === "terminals") setTerminalHeight(Math.max(320, window.innerHeight - 180));
    if (target === "terminals" && selectedId) setTerminalRequest({
      profileId: selectedId,
      nonce: Date.now()
    });
  };
  const editSelected = profile => {
    if (["running", "starting"].includes(profile.status) || terminalActive(profile.id) || applications.some(item => item.profileId === profile.id && (["running", "starting", "stopping"].includes(item.status) || notionTrialLocksConfiguration(item, pending)))) {
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
  const activeInEnvironment = profile => ["running", "starting"].includes(profile?.status) || terminalActive(profile?.id) || applications.some(item => item.profileId === profile?.id && (["running", "starting", "stopping"].includes(item.status) || notionTrialLocksConfiguration(item, pending)));
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
  const subtitle = {
    profiles: t("统一管理网络与工作目录"),
    proxies: t("设置一次，整个境舱共用"),
    browsers: t("独立指纹与浏览数据"),
    terminals: t("本地工具，独立配置与历史"),
    applications: t("让本地软件使用境舱网络"),
    monitor: t("浏览器、终端与软件运行状态"),
    settings: t("语言与应用偏好")
  }[page];
  return <div className={`app-shell ${api.isDesktop ? "is-desktop" : ""} ${withDetail ? "with-detail" : ""} ${terminalVisible ? "terminal-visible" : ""} ${terminalVisible && terminalExpanded ? "terminal-expanded" : ""} ${page === "terminals" ? "terminal-workspace" : ""}`} style={{
    "--terminal-height": `${Math.min(terminalHeight, terminalMaxHeight)}px`
  }}>
    {api.isDesktop && <div className="desktop-titlebar" aria-hidden="true" />}
    <aside className="sidebar">
      <div className="brand"><img className="brand-mark" src={`${import.meta.env.BASE_URL}assets/envara-icon.png`} alt="" /><div><div className="brand-name">Envara{language.startsWith("zh") && <span>境舱</span>}</div><div className="brand-caption">{t("独立工作空间")}</div></div></div>
      <div className="sidebar-section">{t("工作区")}</div>
      <nav className="navigation" aria-label={t("主导航")}>{navItems.map(({
          id,
          label,
          icon: Icon
        }) => <button key={id} className={`nav-item ${page === id ? "active" : ""}`} onClick={() => navigate(id)}><Icon size={20} weight={page === id ? "fill" : "regular"} /><span>{t(label)}</span>{id === "profiles" && <span className="nav-count">{profiles.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><button className={`nav-item settings-navigation ${page === "settings" ? "active" : ""}`} onClick={() => navigate("settings")}><Gear size={20} weight={page === "settings" ? "fill" : "regular"} /><span>{t("设置")}</span></button><div className="owner" title={t("本地工作区 · 设备所有者")}><div className="owner-avatar">{t("境")}</div><div><strong>{t("本地工作区")}</strong><span>{totalBytes > 0 ? `${t("环境数据")} ${bytes(totalBytes)}` : t("设备所有者")}</span></div><span className="local-dot" /></div></div>
    </aside>
    <main className="main-panel">
      <header className="page-header"><div className="page-heading"><div className="heading-line"><h1 tabIndex={-1}>{t(page === "settings" ? "设置" : navItems.find(item => item.id === page)?.label)}</h1>{!api.isDesktop && <span className="preview-badge">{t("界面预览")}</span>}</div><p>{t(subtitle)}</p></div>
        {page === "profiles" && <div className="header-actions"><Button icon={UploadSimple} onClick={() => importProfiles()} disabled={pending["importProfiles:"]}>{t("导入")}</Button><Button icon={Plus} className="primary" onClick={() => setModal({
            type: "createProfile"
          })}>{t("新建环境")}</Button></div>}
        {page === "proxies" && <Button icon={Plus} className="primary" onClick={() => setModal({
          type: "createProxy"
        })}>{t("添加网络出口")}</Button>}
      </header>
      {page === "profiles" && <>
        {api.isDesktop && snapshot.legacyMigration?.available && <div className="section-note migration-discovery"><FolderOpen size={18} /><span>{t("发现 {count} 个旧环境", {
              count: snapshot.legacyMigration.count || 0
            })}</span><Button onClick={previewMigration} disabled={pending["previewLegacyMigration:"]}>{t("查看旧环境")}</Button></div>}
        <div className="environment-toolbar"><div className="search-input"><MagnifyingGlass size={17} /><input ref={searchRef} value={query} onChange={event => setQuery(event.target.value)} placeholder={t("搜索环境")} aria-label={t("搜索环境")} /><kbd>⌘ K</kbd></div><label className="group-filter"><select aria-label={t("分组筛选")} value={groupFilter} onChange={event => setGroupFilter(event.target.value)}><option value="*">{t("全部分组")}</option><option value="">{t("未分组")}</option>{groups.map(group => <option key={group} value={group}>{group}</option>)}</select></label></div>
        {checkedIds.length > 0 && <div className="bulk-toolbar"><span>{t("已选 {count} 个环境", {
              count: checkedIds.length
            })}</span><Button icon={Play} disabled={bulkRunning} onClick={() => runBulk("start")}>{t("启动浏览器")}</Button><Button icon={Stop} disabled={bulkRunning} onClick={() => runBulk("stop")}>{t("停止浏览器")}</Button><Button icon={FolderOpen} disabled={bulkRunning} onClick={() => setModal({
            type: "moveGroup"
          })}>{t("移动分组")}</Button><Button disabled={bulkRunning} onClick={() => setCheckedIds([])}>{t("取消选择")}</Button></div>}
        {bulkResults.length > 0 && <details className="bulk-results" open><summary>{t("批量结果")}</summary>{bulkResults.map(row => <div key={row.id} className={`bulk-result-row ${row.state}`}><strong>{row.name}</strong><span>{row.message}</span></div>)}{!bulkRunning && <Button onClick={() => setBulkResults([])}>{t("收起结果")}</Button>}</details>}
        <EnvironmentOverview profiles={contextualProfiles.filter(profile => filteredProfiles.some(item => item.id === profile.id))} proxies={proxies} selectedId={selectedId} onSelect={setSelectedId} checkedIds={checkedIds} onToggleChecked={toggleChecked} onToggleAll={toggleAllVisible} allChecked={allVisibleChecked} loading={loading} onCreate={() => setModal({
          type: "createProfile"
        })} onEdit={editSelected} t={t} hasProfiles={profiles.length > 0} onReset={() => {
          setQuery("");
          setGroupFilter("*");
        }} />
        <div className="table-footer"><span>{t("{count} 个环境", {
              count: filteredProfiles.length
            })}</span></div>
      </>}
      {page === "browsers" && <BrowserWorkspace profiles={profiles} proxies={proxies} engines={engines} selectedId={selectedId} onSelect={setSelectedId} onStart={start} onStop={profile => perform("stopProfile", {
        id: profile.id
      }, t("会话已停止"))} onFocus={profile => perform("focusProfile", {
        id: profile.id
      })} onEdit={editSelected} onCreate={() => setModal({
        type: "createProfile"
      })} onInstall={installRuntime} busyProfile={busyProfile} editingDisabled={id => terminalActive(id) || applications.some(item => item.profileId === id && (["running", "starting", "stopping"].includes(item.status) || notionTrialLocksConfiguration(item, pending)))} pending={pending} t={t} />}
      {page === "terminals" && <div className="terminal-page-context"><TerminalWindow size={18} /><span>{selectedProxy?.location?.confirmed ? `${selectedProxy.name} · ${selectedProxy.location.label || ""} · ${selectedProxy.location.timezone}` : t("选择境舱和工作目录，打开终端即可使用本地工具。")}</span>
        {selected && <button type="button" className="link-browser-chip" onClick={() => setModal({ type: "terminalLinkBrowser" })} title={t("链接使用的浏览器")}><Browsers size={13} />{t("链接使用的浏览器")}<strong>{linkBrowserName(terminalLinkBrowsers, selectedWorkspace?.browserProfileId)}</strong><CaretRight size={11} /></button>}
      </div>}
      {page === "applications" && <ApplicationsWorkspace profiles={profiles} proxies={proxies} applications={applications} routing={snapshot.applicationRouting} selectedId={selectedId} onSelect={setSelectedId} onPick={pickApplication} onStart={application => perform("startApplication", {
        id: application.id
      })} onStop={application => perform("stopApplication", {
        id: application.id
      }, t("软件已停止"))} onRunNotionTrial={async application => { const result = await perform("runNotionTrial", { id: application.id }); if (!result.ok) await refresh().catch(() => {}); }} onStopNotionTrial={async application => { const result = await perform("stopNotionTrial", { id: application.id }); if (!result.ok) await refresh().catch(() => {}); }} onExportNotionDiagnostics={application => perform("exportNotionDiagnostics", { id: application.id })} onChooseLinkBrowser={application => setModal({ type: "linkBrowser", application })} linkCandidates={application => linkBrowsersFor(profiles.find(item => item.id === application.profileId))} onCheckSignInData={() => perform("signInData", {})} onDeleteSignInData={(item, after) => setModal({
        type: "confirm",
        title: t("删除「{value1}」的登录数据？", { value1: item.application?.name || t("已移除的软件") }),
        description: t("下次启动这个软件需要重新登录；软件本身和它的环境都不受影响。"),
        method: "deleteSignInData",
        id: item.id,
        button: t("删除"),
        success: t("登录数据已删除"),
        onDone: () => after()
      })} formatBytes={bytes} onDelete={application => setModal({
        type: "confirm",
        title: t("移除「{value1}」？", {
          value1: application.name
        }),
        description: t("只移除绑定，登录数据会保留；要删除，请到「登录数据」里删除。"),
        method: "deleteApplication",
        id: application.id,
        button: t("移除软件"),
        success: t("软件已移除")
      })} onShowApplicationWindow={application => perform("showApplicationWindow", { id: application.id })} onInstall={() => perform("setupApplicationRouting", { activate: true })} pending={pending} t={t} desktop={api.isDesktop} />}
      {page === "proxies" && <div className="page-content"><div className="section-note"><ShieldCheck size={18} /><span>{api.isDesktop ? t("创建时确认位置与时区，浏览器、终端和附加软件共同使用。") : t("真实出口识别需要境舱桌面应用；预览中可管理示例代理配置。")}</span></div>{proxies.length ? <div className="proxy-table"><div className="proxy-grid table-head"><span>{t("网络出口")}</span><span>{t("服务器")}</span><span>{t("实际出口")}</span><span>{t("操作")}</span></div>{proxies.map(proxy => <div className="proxy-grid proxy-row" key={proxy.id}><div className="proxy-name"><div className="proxy-icon"><GlobeHemisphereWest size={20} /></div><div><strong>{proxy.name}</strong><small>{profiles.filter(profile => profile.proxyId === proxy.id).length}{t("个环境使用")}{snapshot.groups?.some(group => group.proxyId === proxy.id) && t(" · {value1} 个分组绑定", {
                    value1: snapshot.groups.filter(group => group.proxyId === proxy.id).length
                  })}</small></div></div><div className="proxy-server"><span className="server-address">{proxy.host}:{proxy.port}</span><span className="protocol-tag">{protocolLabel(proxy.protocol)}</span></div><NetworkResult compact network={proxyTests[proxy.id]?.checking ? null : proxyTests[proxy.id] || proxy.network} checking={proxyTests[proxy.id]?.checking} /><div className="row-actions"><Button onClick={() => checkProxy(proxy)} disabled={!api.isDesktop || proxyTests[proxy.id]?.checking} title={api.isDesktop ? t("识别实际网络出口") : t("出口识别需要桌面应用")}>{t("识别")}</Button><IconButton icon={PencilSimple} label={t("编辑网络出口")} onClick={() => setModal({
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
              })} /></div></div>)}</div> : <div className="page-empty"><div className="empty-icon"><GlobeHemisphereWest size={31} /></div><h2>{t("还没有网络出口")}</h2><p>{t("添加代理后，可在环境配置中选择对应的网络出口。")}</p><Button icon={Plus} className="primary" onClick={() => setModal({
            type: "createProxy"
          })}>{t("添加网络出口")}</Button></div>}</div>}

      {page === "monitor" && <MonitorWorkspace profiles={profiles} terminalProfiles={terminalProfiles} applications={applications} events={events} onNavigate={navigate} t={t} language={language} />}
      {page === "settings" && <div className="page-content settings-content">
        <div className="section-heading first"><h2>{t("偏好设置")}</h2></div>
        <div className="settings-card settings-rows"><div className="settings-row"><div><strong>{t("界面语言")}</strong></div><select className="language-select" value={language} disabled={savingLanguage} onChange={event => void setLanguage(event.target.value).catch(() => setToast({ type: "error", message: t("无法保存语言，请重试。") }))} aria-label={t("界面语言")}>{languageOptions.map(option => <option key={option.code} value={option.code} lang={option.code}>{option.nativeName}</option>)}</select></div><div className="settings-row"><div><strong>{t("退出时关闭浏览器")}</strong></div><input type="checkbox" className="row-checkbox" aria-label={t("退出时关闭浏览器")} checked={snapshot.settings?.closeBrowsersOnExit !== false} onChange={event => perform("saveSettings", {
              settings: {
                ...snapshot.settings,
                closeBrowsersOnExit: event.target.checked
              }
            })} /></div><div className="settings-row"><div><strong>{t("本地数据")}</strong><span className="path-label">{t(system.dataDir)}</span></div><Button icon={FolderOpen} disabled={!api.isDesktop} onClick={() => perform("openDataDirectory")}>{t("打开目录")}</Button></div></div>
        {api.isDesktop && snapshot.legacyMigration?.available && <div className="settings-card settings-rows migration-settings"><div className="settings-row"><div><strong>{t("旧版本工作区")}</strong></div><Button onClick={previewMigration} disabled={pending["previewLegacyMigration:"]}>{t("迁移旧环境")}</Button></div></div>}
        {api.isDesktop && linkRouter && <><div className="section-heading"><h2>{t("打开链接")}</h2></div><div className="settings-card settings-rows"><div className="settings-row"><div><strong>{t("链接由境舱浏览器打开")}</strong><span>{t("终端和附加软件的链接用境舱里的浏览器打开；关闭后改用本机浏览器，不经过境舱网络。")}</span></div>
          <label className="proxy-check-option settings-switch"><input type="checkbox" checked={linkRouter.preference !== false} disabled={pending["setLinkRouter:"]} onChange={async event => { const result = await perform("setLinkRouter", { enabled: event.target.checked }); if (result.ok && result.result) setLinkRouter(result.result); }} /><span>{t(linkRouter.preference !== false ? "已开启" : "已关闭")}</span></label></div>
          {linkRouter.preference !== false && linkRouter.available && !linkRouter.enabled && <div className="settings-row"><div><strong>{t("等待 macOS 允许")}</strong><span>{t("附加软件自己打开的链接（例如登录）要 macOS 允许后才能交给境舱浏览器；终端里的链接不受影响。")}</span></div><Button onClick={async () => { const result = await perform("setLinkRouter", { enabled: true }); if (result.ok && result.result) setLinkRouter(result.result); }} disabled={pending["setLinkRouter:"]}>{t("允许")}</Button></div>}</div></>}
        <div className="section-heading"><h2>{t("关于")}</h2></div><div className="settings-card settings-rows"><div className="settings-row"><div><strong>{t("Envara 境舱")}</strong><span>{t("开源的本地独立工作空间")}</span></div><span className="version-label">{system.appVersion || "—"}</span></div><div className="settings-row"><div><strong>{t("浏览器内核许可")}</strong></div><Button onClick={() => perform("openDocumentation", {
              target: "runtime-license"
            })}>{t("查看许可")}</Button></div><div className="settings-row"><div><strong>GitHub</strong></div><Button icon={ArrowSquareOut} onClick={() => perform("openDocumentation", {
              target: "project"
            })}>{t("项目主页")}</Button></div></div>
      </div>}
    </main>
    {withDetail && <aside className="detail-panel">{page === "browsers" ? <BrowserDetail profile={selected} proxy={selectedProxy} runtime={selectedRuntime} pending={pending} busy={selected && busyProfile(selected.id)} onStart={() => start(selected)} onInstall={() => installRuntime(selectedRuntime)} onFocus={() => perform("focusProfile", {
        id: selected.id
      })} onStop={() => perform("stopProfile", {
        id: selected.id
      }, t("会话已停止"))} onEdit={() => editSelected(selected)} onClear={() => confirmClear(selected)} editingDisabled={activeInEnvironment(selected)} t={t} /> : <ContextDetail profile={selected} proxy={selectedProxy} workspace={selectedWorkspace} onEdit={() => editSelected(selected)} onDirectory={chooseDirectory} directoryDisabled={!api.isDesktop || !selected || activeInEnvironment(selected) || !!pending[`chooseWorkspaceDirectory:${selected?.id}`]} onNavigate={navigate} onClone={() => cloneProfile(selected)} onExport={() => perform("exportProfiles", {
        id: selected.id
      }, t("环境配置已导出"))} onDelete={() => confirmDelete(selected)} editingDisabled={activeInEnvironment(selected)} t={t} />}</aside>}
    <TerminalDock profiles={terminalContextProfiles} selectedProfileId={selectedId} visible={terminalVisible} onHide={() => {
      setTerminalVisible(false);
      setTerminalExpanded(false);
      if (page === "terminals") setPage("profiles");
    }} expanded={terminalExpanded} onToggleExpanded={() => setTerminalExpanded(value => !value)} onHeightChange={resizeTerminalDock} minHeight={320} maxHeight={terminalMaxHeight} openRequest={terminalRequest} refreshKey={terminalRefresh} onError={terminalError} onProfilesChange={setTerminalProfiles} />
    {modal?.type === "attachApplication" && <AttachApplicationForm profiles={profiles} proxies={proxies} groups={snapshot.groups} applications={applications} selectedId={selectedId} isActive={activeInEnvironment} onSave={saveAttachedApplication} onClose={closeModal} onAddNetwork={() => { setPage("proxies"); setModal({ type: "createProxy" }); }} saving={pending["attachApplication:"]} />}
    {(modal?.type === "createProfile" || modal?.type === "editProfile") && <ProfileForm profile={modal.profile} proxies={proxies} systemPlatform={system.platform} engines={engines} defaultEngine={snapshot.settings?.defaultEngine} groups={groups} groupDescriptors={snapshot.groups} onSave={saveProfile} onClose={closeModal} saving={pending[`updateProfile:${modal.profile?.id}`] || pending["createProfile:"]} />}{(modal?.type === "createProxy" || modal?.type === "editProxy") && <ProxyForm proxy={modal.proxy} proxyCore={system.proxyCore} onSave={saveProxy} onClose={closeModal} saving={pending["saveProxy:"]} />}{modal?.type === "importMapping" && <ImportMappingForm session={modal.session} proxies={proxies} onImport={proxyMap => importProfiles({
      importId: modal.session.importId,
      proxyMap
    })} onAddProxy={() => {
      closeModal();
      setPage("proxies");
    }} onClose={closeModal} saving={pending[`importProfiles:${modal.session.importId}`]} />}{modal?.type === "migration" && migration && <MigrationForm migration={migration} onMigrate={migrate} onClose={closeModal} saving={pending["migrateLegacy:"]} />}{modal?.type === "moveGroup" && <GroupForm groups={groups} count={checkedIds.length} onSave={group => runBulk("group", group)} onClose={closeModal} saving={bulkRunning} />}{modal?.type === "terminalLinkBrowser" && selected && <Modal title={t("选择此环境的浏览器")} onClose={closeModal} className="attach-application-modal"><div className="modal-body">
      <p className="field-hint">{t("环境中的软件和终端打开链接时使用它。")}</p>
      <LinkBrowserChoices candidates={terminalLinkBrowsers} chosen={linkBrowserChoice(terminalLinkBrowsers, selectedWorkspace?.browserProfileId)} disabled={!!pending[`setTerminalLinkBrowser:${selected?.id}`]} onChoose={value => void saveTerminalLinkBrowser(selected, value)} />
    </div></Modal>}{modal?.type === "linkBrowser" && <Modal title={t("链接使用的浏览器")} onClose={closeModal} className="attach-application-modal"><div className="modal-body">
      <p className="field-hint">{t("选定后，终端命令和软件发起的登录链接都在这个浏览器中打开。")}</p>
      {(() => {
        const candidates = linkBrowsersFor(profiles.find(row => row.id === modal.application.profileId));
        return <LinkBrowserChoices candidates={candidates} chosen={linkBrowserChoice(candidates, modal.application.browserProfileId)} disabled={!!pending[`setApplicationLinkBrowser:${modal.application.id}`]}
          onChoose={async value => { const result = await perform("setApplicationLinkBrowser", { id: modal.application.id, browserProfileId: value === modal.application.profileId ? null : value }, t("链接浏览器已保存")); if (result.ok) closeModal(); }} />;
      })()}
    </div></Modal>}{modal?.type === "confirm" && <Modal title={modal.title} onClose={closeModal} className="confirm-modal"><div className="modal-body"><div className="confirm-warning"><WarningCircle size={23} /><p>{modal.description}</p></div>{modal.items?.length > 0 && <ul className="confirm-items">{modal.items.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}</ul>}</div><div className="modal-footer"><Button onClick={closeModal}>{t("取消")}</Button><Button className="danger" onClick={confirmAction} disabled={pending[`${modal.method}:${modal.id}`]}>{pending[`${modal.method}:${modal.id}`] ? t("处理中…") : modal.button}</Button></div></Modal>}{toast && <div className={`toast toast-${toast.type}`} role="status">{toast.type === "error" ? <WarningCircle size={19} /> : toast.type === "success" ? <CheckCircle size={19} /> : <Browsers size={19} />}<span>{t(toast.message)}</span><IconButton icon={X} label={t("关闭通知")} onClick={() => setToast(null)} /></div>}
  </div>;
}
