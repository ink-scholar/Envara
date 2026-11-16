import React, { useEffect, useRef, useState } from "react";
import { GlobeHemisphereWest, Plus } from "@phosphor-icons/react";
import { api } from "./client.js";
import { useI18n } from "./i18n.jsx";
import { importedDataLabel } from "./environment-transfer-ui.mjs";
import { Button, Modal, Field } from "./workspace-ui.jsx";
import { protocolLabel } from "./workspace-display.mjs";

export function MigrationForm({
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

export function ExportDataForm({ profile, scope, application, onExport, onClose, saving }) {
  const { t } = useI18n();
  const [password, setPassword] = useState(""), [confirm, setConfirm] = useState(""), [error, setError] = useState("");
  const [accounts, setAccounts] = useState({ status: "loading", items: [] }), [accountId, setAccountId] = useState("default"), [reload, setReload] = useState(0);
  useEffect(() => {
    if (scope !== "terminal") return;
    let current = true;
    setAccounts({ status: "loading", items: [] });
    api.call("listClaudeAccounts", { id: profile.id }).then(result => {
      if (!current) return;
      if (!Array.isArray(result?.accounts) || !result.accounts.length) throw new Error("Invalid account list");
      setAccounts({ status: "ready", items: result.accounts });
      setAccountId(previous => result.accounts.some(account => account.id === previous) ? previous : result.accounts.some(account => account.id === "default") ? "default" : result.accounts[0].id);
    }).catch(() => { if (current) setAccounts({ status: "error", items: [] }); });
    return () => { current = false; };
  }, [scope, profile.id, reload]);
  const validAccount = scope !== "terminal" || accounts.status === "ready" && accounts.items.some(account => account.id === accountId);
  const title = { browser: "导出浏览器", terminal: "导出终端", application: "导出软件" }[scope];
  const notice = { browser: "仅导出此浏览器的配置与网站登录数据。", terminal: "仅导出此终端的配置、历史和选中的 Claude 登录档案。", application: "仅导出此软件在该境舱内的设置与应用数据。" }[scope];
  const submit = event => {
    event.preventDefault();
    if (saving || !validAccount) return;
    if (password.length < 8) return setError(t("密码至少 8 个字符。"));
    if (password.length > 256) return setError(t("密码至少 8 个字符，最多 256 个字符。"));
    if (password !== confirm) return setError(t("两次输入的密码不一致。"));
    onExport({ password, ...(scope === "terminal" ? { accountId } : {}) });
  };
  return <Modal title={t(title)} subtitle={application ? `${application.name} · ${profile.name}` : profile.name} onClose={onClose}><form onSubmit={submit}><div className="modal-body"><p className="form-note">{t(notice)}</p>
    {scope === "terminal" && <Field label="登录档案">{accounts.status === "loading" ? <span role="status">{t("正在读取登录档案…")}</span> : accounts.status === "error" ? <div className="terminal-account-error" role="status"><span>{t("无法读取登录档案，请重试。")}</span><Button type="button" disabled={saving} onClick={() => setReload(value => value + 1)}>{t("重试")}</Button></div> : <select value={accountId} disabled={saving} onChange={event => setAccountId(event.target.value)}>{accounts.items.map(account => <option key={account.id} value={account.id}>{account.name === "默认" ? t("默认") : account.name}</option>)}</select>}</Field>}
    <p className="form-note">{t("文件使用密码加密。不含本机钥匙串凭据，换机后部分账号需重新登录。")}</p><Field label="设置密码" error={error}><input type="password" autoFocus autoComplete="new-password" maxLength={256} disabled={saving} value={password} onChange={event => { setPassword(event.target.value); setError(""); }} /></Field><Field label="确认密码"><input type="password" autoComplete="new-password" maxLength={256} disabled={saving} value={confirm} onChange={event => { setConfirm(event.target.value); setError(""); }} /></Field></div><div className="modal-footer"><Button type="button" onClick={onClose} disabled={saving}>{t("取消")}</Button><Button type="submit" className="primary" disabled={saving || !validAccount} aria-busy={saving || undefined}>{t(saving ? "处理中…" : "导出")}</Button></div></form></Modal>;
}

export function ImportPasswordForm({ session, onSubmit, onClose, saving }) {
  const { t } = useI18n();
  const [password, setPassword] = useState("");
  return <Modal title={t("导入数据")} subtitle={session.fileName} onClose={onClose}><form onSubmit={event => { event.preventDefault(); if (password && !saving) onSubmit(password); }}><div className="modal-body"><Field label="导出时设置的密码"><input type="password" autoFocus autoComplete="current-password" disabled={saving} value={password} onChange={event => setPassword(event.target.value)} /></Field></div><div className="modal-footer"><Button type="button" onClick={onClose} disabled={saving}>{t("取消")}</Button><Button type="submit" className="primary" disabled={saving || !password}>{t("导入")}</Button></div></form></Modal>;
}

export function ImportMappingForm({
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
  return <Modal title={`${t(importedDataLabel(session.scope))} · ${t("映射导入的网络出口")}`} subtitle={t("即将导入 {value1} 个环境。为每个原出口选择本机代理。", {
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
