import React, { useRef, useState } from "react";
import { ArrowsClockwise, WarningCircle } from "@phosphor-icons/react";
import { browseForgeRegionFor, preferredEngine } from "../shared/engine-choice.mjs";
import { BROWSER_DEVICE_PROFILES, PROVIDER_DEFAULT_DEVICE_PROFILE_ID, defaultBrowserDeviceProfileId, getBrowserDeviceProfile, supportsBrowserDeviceProfiles } from "../shared/browser-device-profile.mjs";
import { initialBrowserDeviceFields, selectBrowserDeviceProfile, changeBrowserDeviceEngine, browserDimensionValue, validBrowserDimension } from "./browser-device-form.mjs";
import { useI18n } from "./i18n.jsx";
import { Button, IconButton, Modal, Field } from "./workspace-ui.jsx";
import { allows, platforms } from "./workspace-profile.mjs";

export function ProfileForm({
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
    width: "",
    height: "",
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
  const deviceChoices = BROWSER_DEVICE_PROFILES.filter(device => device.id === defaultBrowserDeviceProfileId(systemPlatform) || device.id === profile?.deviceProfileId);
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
    if (["seed", "width", "height", "platform", "locale", "timezone", "deviceProfileId"].includes(key)) setAdvanced(true);
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
    for (const [key, minimum, maximum] of [["width", 800, 7680], ["height", 600, 4320]]) {
      if (!validBrowserDimension(form[key], minimum, maximum)) {
        fail(key, t("请修正标出的配置后再保存。"));
        return;
      }
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
      fail("proxyId", t("BrowseForge Chromium 需要有效的地区预设。请先检测并确认网络出口位置，或在高级设置中填写支持的地区代码。"));
      return;
    }
    onSave({
      name: form.name.trim(),
      group: form.group.trim(),
      notes: form.notes,
      engine: form.engine,
      deviceProfileId: form.deviceProfileId,
      ...(form.platform ? { platform: form.platform } : {}),
      ...(!profile && allows(runtime, "seed") ? {
        seed: Number(form.seed)
      } : {}),
      locale: form.locale,
      timezone: confirmedNetworkTimezone ? "" : form.timezone,
      width: browserDimensionValue(form.width),
      height: browserDimensionValue(form.height),
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
        {field("engine", t("浏览器内核"), <select value={form.engine} onChange={change("engine")} disabled={!!profile} {...invalid("engine")}>{engines.map(item => <option key={item.id} value={item.id} disabled={item.supported === false}>{item.displayName || item.id}{item.supported === false ? t(" · 不可用") : ""}</option>)}{!runtime && <option value={form.engine}>{form.engine}</option>}</select>, {
            className: "span-two"
          })}
      </div>
      <details className="advanced-settings" open={advanced} onToggle={event => setAdvanced(event.currentTarget.open)}>
        <summary>{t("高级设置")}</summary>
        <div className="form-grid">
          <div className="browser-device-settings span-two">
            {field("deviceProfileId", t("设备模板（可选）"), <select value={form.deviceProfileId} onChange={changeDeviceProfile} disabled={!deviceProfilesSupported} {...invalid("deviceProfileId")}><option value={PROVIDER_DEFAULT_DEVICE_PROFILE_ID}>{t(profile ? "保留当前配置" : "内核自动生成")}</option>{deviceChoices.map(device => <option key={device.id} value={device.id} disabled={!deviceProfilesSupported}>{t(device.label)}</option>)}</select>, {
              hint: deviceProfilesSupported ? undefined : t("当前内核暂不支持固定设备档案。")
            })}
            {selectedDevice && <dl className="browser-device-summary" aria-label={t("设备档案")}><div><dt>{t("平台")}</dt><dd>{platforms[selectedDevice.platform]}</dd></div><div><dt>{t("屏幕")}</dt><dd>{selectedDevice.width} × {selectedDevice.height}</dd></div><div><dt>{t("逻辑处理器")}</dt><dd>{selectedDevice.hardwareConcurrency}</dd></div>{form.engine !== "camoufox" && <div><dt>{t("内存规格")}</dt><dd>{selectedDevice.deviceMemory} GB</dd></div>}</dl>}
            {selectedDevice && form.engine === "camoufox" && <p className="field-hint">{t("Camoufox 自动管理设备指纹，无需设置内存。固定模板会固定外层窗口尺寸。")}</p>}
          </div>
          {field("group", t("分组"), <><input maxLength={60} list="profile-groups" value={form.group} onChange={change("group")} placeholder={t("未分组")} /><datalist id="profile-groups">{groups.map(group => <option key={group} value={group} />)}</datalist></>)}
          <Field label={t("隐私防护")} hint={t({ standard: "拦截已知第三方追踪；个别网站可能需要调整防护设置。", strict: "在标准之上，再拦截标签管理器、错误上报和广告网络；个别网站可能缺少功能。", off: "不拦截追踪请求。" }[form.privacy?.mode || "standard"])}><select value={form.privacy?.mode || "standard"} onChange={event => setForm(value => ({
                ...value,
                privacy: {
                  mode: event.target.value
                }
              }))}><option value="standard">{t("标准")}</option><option value="strict">{t("严格")}</option><option value="off">{t("停用")}</option></select></Field>
          {field("locale", t("语言"), <><select aria-label={t("语言模式")} value={fixedModes.locale ? "fixed" : "auto"} onChange={changeMode("locale")}><option value="auto">{t("跟随网络出口")}</option><option value="fixed">{t("固定语言")}</option></select>{fixedModes.locale && <input aria-label={t("固定语言")} value={form.locale} onChange={change("locale")} disabled={!allows(runtime, "locale")} placeholder="zh-CN" {...invalid("locale")} />}</>, { hint: t("浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。") })}
          {field("timezone", t("时区"), confirmedNetworkTimezone ? <span className="field-hint">{confirmedNetworkTimezone}<br />{t("已保存配置")}</span> : <><select aria-label={t("时区模式")} value={fixedModes.timezone ? "fixed" : "auto"} onChange={changeMode("timezone")}><option value="auto">{t("跟随网络出口")}</option><option value="fixed">{t("固定时区")}</option></select>{fixedModes.timezone && <input aria-label={t("固定时区")} value={form.timezone} onChange={change("timezone")} disabled={!allows(runtime, "timezone")} placeholder="Asia/Shanghai" {...invalid("timezone")} />}</>)}
          {!selectedDevice && field("platform", t("指纹平台"), <select value={form.platform} onChange={change("platform")} disabled={!allows(runtime, "platform")} {...invalid("platform")}>
            {!profile?.platform && <option value="">{t("自动（由内核决定）")}</option>}
            <option value="macos">macOS</option><option value="windows">Windows</option><option value="linux">Linux</option></select>)}
          {field("seed", t("指纹种子"), <div className="input-action"><input type="number" min="1" max="4294967295" required readOnly={!!profile} disabled={!allows(runtime, "seed")} value={allows(runtime, "seed") ? form.seed : ""} placeholder={t(profile && allows(runtime, "seed") ? "保留当前配置" : "不适用")} onChange={change("seed")} {...invalid("seed")} /><IconButton disabled={!!profile || !allows(runtime, "seed")} icon={ArrowsClockwise} label={t("随机生成种子")} type="button" onClick={() => setForm(value => ({
                ...value,
                seed: Math.floor(Math.random() * 2147483646) + 1
              }))} /></div>)}
          {!selectedDevice && field("width", t("屏幕宽度"), <div className="input-unit"><input type="number" min="800" max="7680" value={form.width} onChange={change("width")} placeholder={t("自动（由内核决定）")} {...invalid("width")} /><span>px</span></div>)}
          {!selectedDevice && field("height", t("屏幕高度"), <div className="input-unit"><input type="number" min="600" max="4320" value={form.height} onChange={change("height")} placeholder={t("自动（由内核决定）")} {...invalid("height")} /><span>px</span></div>)}
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

export function GroupForm({
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
