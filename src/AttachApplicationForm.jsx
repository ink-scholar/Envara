import React, { useEffect, useState } from "react";
import { GlobeHemisphereWest, Plus, MagnifyingGlass, ArrowsClockwise, FolderOpen, CheckCircle, WarningCircle, Browsers, CaretRight, Desktop } from "@phosphor-icons/react";
import { api } from "./client.js";
import { networkApplicationChoices, chooseApplicationProfile, isApplicationAlreadyAttached } from "./network-flow-state.mjs";
import { useI18n } from "./i18n.jsx";
import { SYSTEM_BROWSER, linkBrowsersFor as linkBrowsersOf } from "./link-browser.mjs";
import { ApplicationIcon } from "./ApplicationIcon.jsx";
import { supportsAttachedApplication } from "./application-capability.mjs";
import { Button, Modal } from "./workspace-ui.jsx";
import { protocolLabel } from "./workspace-display.mjs";

/* Where links from an environment open: its own browser first, the other
 * browsers of its network next, and the system browser last, which is said to
 * leave the environment. */
export function LinkBrowserChoices({ candidates, chosen, onChoose, disabled = false }) {
  const { t } = useI18n();
  return <div className="network-choice-list">{[...candidates, null].map((item, index) => {
    const value = item ? item.id : SYSTEM_BROWSER, selected = chosen === value;
    return <button type="button" key={value || "own"} disabled={disabled} className={`network-choice ${selected ? "selected" : ""}`} aria-pressed={selected} onClick={() => onChoose(value)}>
      {item ? <Browsers size={20} /> : <GlobeHemisphereWest size={20} />}
      <span><strong>{item ? item.name : t("系统默认浏览器")}</strong><small>{item ? `${index === 0 ? `${t("本境舱")} · ` : ""}${t(item.status === "running" ? "运行中" : "已停止")}` : t("不使用境舱浏览器；链接会交给系统默认浏览器，不经过境舱网络。")}</small></span>
      {selected && <CheckCircle size={19} />}</button>;
  })}</div>;
}

export function AttachApplicationForm({ profiles, proxies, groups, applications, selectedId, systemPlatform, isActive = () => false, onSave, onClose, onAddNetwork, saving }) {
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
        if (!supportsAttachedApplication(result, systemPlatform)) throw new Error(t("暂不支持此软件的网络隔离"));
        setPicked(result);
      }
    } catch (value) { setError(value.message || t("操作未完成，请重试。")); }
  };
  const steps = ["network", "application", "browser"];
  const stepIndex = steps.indexOf(step);
  return <Modal title={t(step === "network" ? "选择网络分组" : step === "application" ? "选择本地软件" : "链接使用的浏览器")} onClose={onClose} className="attach-application-modal">
    <div className="network-flow-steps">{steps.map((name, index) => <React.Fragment key={name}>{index > 0 && <CaretRight size={14} />}<span className={step === name ? "current" : index < stepIndex ? "complete" : ""}><span>{index + 1}</span>{t(name === "network" ? "网络分组" : name === "application" ? "选择软件" : "浏览器")}</span></React.Fragment>)}</div>
    <div className="modal-body">{step === "browser" ? <>
      <LinkBrowserChoices candidates={browsers} chosen={browserId || ownBrowser?.id || ""} onChoose={value => setBrowserId(value === ownBrowser?.id ? "" : value)} />
    </> : step === "network" ? choices.length ? <div className="network-choice-list">{choices.map(item => <button type="button" key={item.id} className={`network-choice ${choiceId === item.id ? "selected" : ""}`} aria-pressed={choiceId === item.id} onClick={() => setChoiceId(item.id)}><GlobeHemisphereWest size={21} /><span><strong>{item.name}</strong><small>{item.group ? item.proxy.name : protocolLabel(item.proxy.protocol)} · {item.proxy.location?.confirmed ? item.proxy.location.label || item.proxy.location.timezone : t("位置尚未确认")}</small></span>{choiceId === item.id && <CheckCircle size={19} />}</button>)}</div> : <div className="application-picker-empty"><GlobeHemisphereWest size={30} /><strong>{t("先创建网络环境")}</strong><Button type="button" onClick={onAddNetwork} icon={Plus}>{t("创建网络环境")}</Button></div> : <>
      <div className="selected-network-context"><GlobeHemisphereWest size={18} /><strong>{choice?.name}</strong><span>{choice?.proxy.location?.timezone || choice?.proxy.network?.timezone || t("自动时区")}</span></div>
      <div className="search-input application-picker-search"><MagnifyingGlass size={17} /><input value={query} onChange={event => setQuery(event.target.value)} maxLength={256} placeholder={t("搜索本地软件")} aria-label={t("搜索本地软件")} /></div>
      <div className="local-application-list" aria-live="polite">{loading ? <div className="application-picker-empty"><ArrowsClockwise className="spin" size={23} /><span>{t("正在读取本地软件…")}</span></div> : error ? <div className="application-picker-empty"><WarningCircle size={24} /><span>{t(error)}</span><Button type="button" onClick={() => setRetry(value => value + 1)}>{t("重新读取")}</Button></div> : catalog?.applications.length ? catalog.applications.map(application => {
        const attached = isApplicationAlreadyAttached(application, applications);
        const supported = supportsAttachedApplication(application, systemPlatform);
        return <button type="button" key={application.identity || application.path} className={`local-application-choice ${picked?.path === application.path ? "selected" : ""}`} disabled={attached || !supported} aria-pressed={picked?.path === application.path} title={supported ? application.path : t("暂不支持此软件的网络隔离")} onClick={() => setPicked(application)}><ApplicationIcon path={application.path} size={30} className="choice-icon" /><span>{application.name}{!supported && <small className="application-compatibility-hint">{t("暂不支持此软件的网络隔离")}</small>}</span>{attached ? <small>{t("已附加")}</small> : picked?.path === application.path && <CheckCircle size={18} />}</button>;
      }) : <div className="application-picker-empty"><Desktop size={27} /><span>{t(query ? "没有匹配的软件" : "未找到本地软件")}</span></div>}</div>
      {catalog?.truncated && <p className="field-hint">{t("列表可能不完整，可搜索名称或选择文件。")}</p>}
      <div className="application-picker-file"><Button type="button" icon={FolderOpen} onClick={chooseFromFile} disabled={saving}>{t("从文件选择…")}</Button>{picked && <span className="application-picked"><ApplicationIcon path={picked.path} size={22} className="choice-icon" /><strong title={picked.path}>{picked.name || picked.path.split(/[\\/]/).pop()}</strong></span>}</div>
      <p className="field-hint">{t("使用已确认的网络环境；定位支持取决于软件。")}</p>
    </>}{step !== "application" && error && <p className="field-error" role="alert">{t(error)}</p>}</div>
    <div className="modal-footer"><Button type="button" disabled={saving} onClick={step === "network" ? onClose : () => { setStep(steps[stepIndex - 1]); setError(""); }}>{t(step === "network" ? "取消" : "上一步")}</Button><Button className="primary" disabled={saving || !choice || step !== "network" && (!picked || !supportsAttachedApplication(picked, systemPlatform) || isApplicationAlreadyAttached(picked, applications))} onClick={async () => {
      if (!choice) { setError(t("网络分组已改变，请重新选择。")); return; }
      setError("");
      if (step !== steps.at(-1)) { setStep(steps[stepIndex + 1]); return; }
      const result = await onSave(choice, picked, browserId || null);
      if (!result?.ok) setError(result?.message || t("操作未完成，请重试。"));
    }}>{saving ? t("保存中…") : step === steps.at(-1) ? t("添加软件") : t(step === "network" ? "选择软件" : "下一步")}</Button></div>
  </Modal>;
}
