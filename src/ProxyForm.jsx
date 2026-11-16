import React, { useEffect, useRef, useState } from "react";
import { GlobeHemisphereWest, ArrowsClockwise, ArrowSquareOut, CheckCircle, WarningCircle, CaretRight, Clock, Eye, EyeSlash, ShieldCheck } from "@phosphor-icons/react";
import { api } from "./client.js";
import { NetworkDiagnostics, networkFailureText } from "./NetworkStatus.jsx";
import { initialProxyForm, proxyConfig, proxyFormError } from "./proxy-form-state.mjs";
import { locationFormState, verifiedLocationPreview, locationConfirmation, seedManualLocation, proxyRouteFields } from "./network-flow-state.mjs";
import { googleMapsLocationURL, normalizeNetworkLocation } from "../shared/network-location.mjs";
import { useI18n } from "./i18n.jsx";
import { Button, IconButton, Modal, Field } from "./workspace-ui.jsx";
import { networkPlace, relativeTime } from "./workspace-display.mjs";

export function NetworkResult({
  network,
  checking = false,
  compact = false,
  showDiagnostics = true
}) {
  const {
    t,
    language
  } = useI18n();
  const verified = network?.ok === true && network?.scope === "egress" && !!network.ip;
  return <div className="network-result-block"><div role="status" aria-live="polite" className={`network-result ${compact ? "compact" : ""} ${verified ? "verified" : network?.ok === false ? "failed" : ""}`}>
    {checking ? <><ArrowsClockwise size={16} className="spin" /><div><strong>{t("正在识别出口…")}</strong><small>{t("通过代理访问出口查询服务")}</small></div></> : verified ? <><CheckCircle size={17} /><div><strong className="mono-value">{network.ip}</strong>{networkPlace(network) && <small>{networkPlace(network)}</small>}<small>{network.timezone || t("时区尚未识别")}</small><span className="network-source">{network.source || t("出口查询")}{network.checkedAt ? ` · ${relativeTime(network.checkedAt, language, t)}` : ""}</span></div></> : network ? <><WarningCircle size={17} /><div><strong>{t("出口识别失败")}</strong><small>{networkFailureText(network.errorCode, t) || network.message || t("未获得有效的出口资料，请检查代理参数后重试。")}</small></div></> : <><GlobeHemisphereWest size={17} /><div><strong>{t("尚未识别")}</strong><small>{t("检测实际出口 IP、地区和时区")}</small></div></>}
  </div>{!checking && showDiagnostics && <NetworkDiagnostics diagnostics={network?.diagnostics} />}</div>;
}

export function ProxyForm({
  proxy,
  proxyCore,
  onSave,
  onClose,
  saving
}) {
  const {
    t, language
  } = useI18n();
  const [form, setForm] = useState(() => initialProxyForm(proxy));
  const [visible, setVisible] = useState(false),
    [preview, setPreview] = useState(null),
    [location, setLocation] = useState(() => locationFormState(proxy?.location)),
    [step, setStep] = useState("connection"),
    [checking, setChecking] = useState(false),
    [checkError, setCheckError] = useState("");
  const [addressResults, setAddressResults] = useState(null);
  const [addressSearching, setAddressSearching] = useState(false);
  const addressSequence = useRef(0);
  const manualLocationEdited = useRef(proxy?.location?.mode === 'manual');
  const network = preview?.network;
  const recommendation = preview?.locationRecommendation;
  const verified = verifiedLocationPreview(preview);
  const anytls = form.protocol === "anytls";
  const checkSequence = useRef(0);
  useEffect(() => () => {
    checkSequence.current++;
    addressSequence.current++;
  }, []);
  const clearAddressResults = () => {
    addressSequence.current++;
    setAddressSearching(false);
    setAddressResults(null);
  };
  const update = (key, value) => {
    if (proxyRouteFields.has(key)) {
      clearAddressResults();
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
    clearAddressResults();
    setChecking(true);
    setCheckError("");
    setPreview(null);
    setLocation(previous => ({ ...previous, confirmed: false }));
    try {
      const result = await api.call("previewProxyNetwork", {
        proxy: proxyConfig({
          ...form,
          name: form.name.trim() || t("待检测出口")
        }), language
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
    clearAddressResults();
    if (key !== 'mode') manualLocationEdited.current = true;
    setLocation(previous => {
      const next = { ...previous, [key]: value, confirmed: false,
      ...(['label', 'mapsUrl'].includes(key) ? { latitude: '', longitude: '', ...(key === 'label' ? { mapsUrl: '' } : { label: '' }) } : {}),
      ...(['latitude', 'longitude'].includes(key) ? { mapsUrl: '' } : {}) };
      return key === 'mode' && value === 'manual' && !manualLocationEdited.current ? seedManualLocation(next, preview) : next;
    });
    setCheckError("");
  };
  const searchAddress = async () => {
    if (!api.isDesktop || !verified || addressSearching) return;
    const sequence = ++addressSequence.current;
    setAddressSearching(true); setAddressResults(null); setCheckError("");
    setLocation(previous => ({ ...previous, confirmed: false }));
    try {
      const result = await api.call('searchNetworkAddress', { proxy: proxyConfig(form), locationPreviewToken: preview.locationPreviewToken, query: location.label, language });
      if (sequence === addressSequence.current) setAddressResults(result);
    } catch (error) {
      if (sequence === addressSequence.current) setCheckError(error.message || t("无法通过所选代理查询地址，请重试或手动填写坐标。"));
    } finally { if (sequence === addressSequence.current) setAddressSearching(false); }
  };
  const selectAddress = candidate => {
    clearAddressResults();
    manualLocationEdited.current = true;
    setLocation(previous => ({ ...previous, mode: 'manual', label: candidate.label, mapsUrl: '', latitude: String(candidate.latitude), longitude: String(candidate.longitude), confirmed: false }));
    setCheckError('');
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
  return <Modal title={proxy ? t("编辑网络环境") : t("创建网络环境")} onClose={onClose} className="proxy-modal"><form onSubmit={event => {
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
    {anytls && <>{api.isDesktop && proxyCore?.supported === false && <div className="anytls-core-note unavailable" role="status"><ShieldCheck size={17} /><span>{proxyCore.message || t("当前安装无法使用内置 AnyTLS。可先保存节点配置，检测或启动时会显示具体问题。")}</span></div>}
      <details className="advanced-settings proxy-tls-settings"><summary>{t("高级节点设置")}<span>{form.skipCertVerify ? t("证书验证已关闭") : t("验证服务器证书")}</span></summary><div className="proxy-tls-options">
        <p className="field-hint">{t("桌面版内置 AnyTLS；浏览器与终端共用出口，无需另开 Clash。")}</p>
        <label className="proxy-check-option"><input type="checkbox" checked={!form.skipCertVerify} onChange={event => update("skipCertVerify", !event.target.checked)} /><span>{t("验证 TLS 证书")}</span></label>
        <p className="field-hint">{t("如果服务商使用自签名证书，可按其配置关闭验证。")}</p>
        <Field label={t("ALPN（选填）")} hint={t("按服务商配置填写，用英文逗号分隔；留空使用内核默认值。")}><input value={Array.isArray(form.alpn) ? form.alpn.join(", ") : form.alpn || ""} onChange={change("alpn")} placeholder="h2, http/1.1" autoComplete="off" /></Field>
        <div className="proxy-udp-option"><label className="proxy-check-option"><input type="checkbox" checked={form.udp !== false} onChange={event => update("udp", event.target.checked)} /><span>{t("启用节点 UDP")}</span></label><p className="field-hint">{t("控制此节点的 UDP 转发，不会自动接管本机程序的全部 UDP 流量。")}</p></div>
      </div></details></>}
    <details className="advanced-settings proxy-region-settings"><summary>{t("高级设置")}</summary><div className="form-grid"><Field label={t("代理地域（选填）")} className="span-two" hint={t("按已确认位置自动匹配，也可手动指定地区代码；不能替代出口检测。")}><input maxLength={64} value={form.region || ""} onChange={change("region")} placeholder="us-ny" /></Field></div></details>
    {checking && <div className="proxy-detect-card"><NetworkResult checking /></div>}
    {!api.isDesktop && <p className="native-feature-note">{t("真实出口识别需要境舱桌面应用。")}</p>}
    <div className="form-note">{t("代理凭据仅保存在本机。导出的环境配置不包含密码。")}</div></> : <>
      <NetworkResult network={network} compact />
      <div className="location-mode-control" role="group" aria-label={t("出口位置")}><button type="button" className={location.mode === "ip" ? "selected" : ""} aria-pressed={location.mode === "ip"} onClick={() => updateLocation("mode", "ip")}>{t("自动定位")}</button><button type="button" className={location.mode === "manual" ? "selected" : ""} aria-pressed={location.mode === "manual"} onClick={() => updateLocation("mode", "manual")}>{t("手动选择位置")}</button></div>
      {location.mode === "ip" ? <div className="location-recommendation"><strong>{preview?.referenceLocation?.label || recommendation?.label || networkPlace(network) || network?.countryCode}</strong><p className="field-hint">{t("仅供参考，可手动调整。")}</p>{preview?.referenceLocation && <small className="field-hint">Photon · © OpenStreetMap contributors</small>}</div> : <div className="form-grid location-manual-fields">
        <Field label={t("街道、地址或地点")} className="span-two" hint={t("经所选代理查询附近地址。") }><div className="input-action"><input maxLength={500} value={location.label} onChange={event => updateLocation("label", event.target.value)} autoComplete="off" onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); searchAddress(); } }} /><Button type="button" onClick={searchAddress} disabled={!api.isDesktop || !verified || addressSearching || location.label.trim().length < 2}>{addressSearching ? t("查询中…") : t("查询地址")}</Button></div></Field>
        {addressResults && <div className="address-search-results span-two" aria-live="polite">{addressResults.candidates.length ? <>{addressResults.candidates.map(candidate => <button type="button" key={candidate.id} onClick={() => selectAddress(candidate)}><span>{candidate.label}</span><small className="mono-value">{candidate.latitude.toFixed(5)}, {candidate.longitude.toFixed(5)}</small></button>)}</> : <p className="field-hint">{t("未找到匹配地点，请补充城市或国家，或手动填写坐标。")}</p>}</div>}
        <p className="field-hint address-search-attribution span-two">Photon · <button type="button" onClick={() => api.call('openDocumentation', { target: 'map-attribution' }).catch(() => setCheckError(t("地图链接未打开，请重试。")))}>© OpenStreetMap contributors</button></p>
        <Field label={t("Google Maps 链接（选填）")} className="span-two"><input type="url" maxLength={2048} value={location.mapsUrl} onChange={event => updateLocation("mapsUrl", event.target.value)} placeholder="https://www.google.com/maps/…" /></Field>
        <details className="advanced-settings span-two"><summary>{t("坐标（选填）")}</summary><div className="form-grid"><Field label={t("纬度")}><input type="number" min="-90" max="90" step="any" value={location.latitude} onChange={event => updateLocation("latitude", event.target.value)} /></Field><Field label={t("经度")}><input type="number" min="-180" max="180" step="any" value={location.longitude} onChange={event => updateLocation("longitude", event.target.value)} /></Field></div></details>
        {manualLocation?.latitude != null && <p className="field-hint span-two">{t("已选择坐标")}: <span className="mono-value">{Number(manualLocation.latitude).toFixed(5)}, {Number(manualLocation.longitude).toFixed(5)}</span></p>}
      </div>}
      <div className="location-map-row"><Button type="button" icon={ArrowSquareOut} onClick={openMap} disabled={!mapsUrl}>{t("在 Google Maps 中查看")}</Button></div>
      <div className="location-timezone"><Clock size={16} /><strong>{network?.timezone || t("时区尚未识别")}</strong><span>{t("时区跟随实际代理出口。")}</span></div>
      <label className="location-confirmation"><input type="checkbox" checked={location.confirmed} onChange={event => { setLocation(previous => ({ ...previous, confirmed: event.target.checked })); setCheckError(""); }} /><span>{t("我确认这个网络环境的位置与时区")}</span></label>
    </>}{checkError && <p className="field-error network-flow-error" role="alert">{t(checkError)}</p>}</div><div className="modal-footer"><Button type="button" onClick={step === "location" ? () => setStep("connection") : onClose} disabled={saving}>{t(step === "location" ? "上一步" : "取消")}</Button><Button type="submit" className="primary" disabled={saving || checking || addressSearching || step === "location" && (!verified || !location.confirmed)}>{saving ? t("保存中…") : checking ? t("检测中…") : !api.isDesktop ? t("保存网络出口") : step === "connection" ? t("检测并继续") : t("保存网络环境")}</Button></div></form></Modal>;
}
