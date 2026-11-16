import React, { useEffect, useLayoutEffect, useRef } from "react";
import { X } from "@phosphor-icons/react";
import { useI18n } from "./i18n.jsx";

const statuses = {
  stopped: "已停止",
  starting: "启动中",
  running: "运行中",
  error: "异常"
};

export function Status({
  status = "stopped"
}) {
  const {
    t
  } = useI18n();
  return <span className={`status status-${status}`}><span className="status-dot" />{t(statuses[status] || status)}</span>;
}

export function Button({
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

export function IconButton({
  icon: Icon,
  label,
  ...props
}) {
  const {
    t
  } = useI18n();
  return <button className="icon-button" aria-label={t(label)} title={t(label)} {...props}><Icon size={18} /></button>;
}

export function Modal({
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
    openerRef = useRef(document.activeElement),
    closeRef = useRef(onClose);
  useLayoutEffect(() => { closeRef.current = onClose; }, [onClose]);
  // Background refreshes can replace callbacks without opening a new dialog.
  useEffect(() => {
    const previous = openerRef.current;
    const panel = panelRef.current;
    const focusable = () => Array.from(panel.querySelectorAll("button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex=\"0\"]")).filter(element => element.getClientRects().length > 0);
    const focusFrame = requestAnimationFrame(() => (panel.querySelector("input:not(:disabled)") || focusable()[0] || panel).focus());
    const onKey = event => {
      if (event.key === "Escape") {
        event.preventDefault();
        closeRef.current();
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
  }, []);
  return <div className="modal-backdrop" onMouseDown={event => {
    if (event.target === event.currentTarget) onClose();
  }}><section className={`modal ${className}`} role="dialog" aria-modal="true" aria-labelledby="modal-title" ref={panelRef} tabIndex={-1}><div className="modal-heading"><div><h2 id="modal-title">{t(title)}</h2>{subtitle && <p>{t(subtitle)}</p>}</div><IconButton icon={X} label={t("关闭")} onClick={onClose} /></div>{children}</section></div>;
}

export function Field({
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
