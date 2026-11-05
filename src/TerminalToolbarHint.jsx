import React, { cloneElement, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

// Keep the button or summary as the actual toolbar child. The tooltip is placed
// outside the terminal's clipped viewport and adds no keyboard stop.
export function TerminalToolbarHint({ label, description, enabled = true, children }) {
  const id = useId(), tooltipRef = useRef(null), closeTimer = useRef(null);
  const active = useRef({ hovered: false, focused: false, dismissed: false });
  const [anchor, setAnchor] = useState(null), [position, setPosition] = useState(null);
  const cancelClose = () => { clearTimeout(closeTimer.current); closeTimer.current = null; };
  const dismiss = () => { cancelClose(); active.current.dismissed = true; setAnchor(null); };
  const show = element => { cancelClose(); if (enabled && !active.current.dismissed) setAnchor(element); };
  const closeSoon = () => {
    cancelClose();
    closeTimer.current = setTimeout(() => {
      if (!active.current.hovered && !active.current.focused) setAnchor(null);
    }, 100);
  };
  useEffect(() => () => clearTimeout(closeTimer.current), []);
  useEffect(() => { if (!enabled) { dismiss(); active.current.focused = false; active.current.hovered = false; } }, [enabled]);
  useLayoutEffect(() => {
    if (!anchor || !tooltipRef.current) { setPosition(null); return; }
    const target = anchor.getBoundingClientRect(), hint = tooltipRef.current.getBoundingClientRect();
    const left = Math.max(8, Math.min(target.right - hint.width, window.innerWidth - hint.width - 8));
    const below = target.bottom + 7;
    const top = Math.max(8, below + hint.height <= window.innerHeight - 8 ? below : target.top - hint.height - 7);
    setPosition({ left, top });
  }, [anchor, label, description]);
  useEffect(() => {
    if (!anchor) return;
    const escape = event => { if (event.key === 'Escape') dismiss(); };
    const moved = () => dismiss();
    const otherControl = event => {
      const control = event.target.closest?.('.terminal-toolbar-actions button, .terminal-toolbar-actions summary');
      if (control && control !== anchor) dismiss();
    };
    document.addEventListener('keydown', escape, true);
    document.addEventListener('pointerover', otherControl, true);
    window.addEventListener('resize', moved);
    window.addEventListener('scroll', moved, true);
    return () => {
      document.removeEventListener('keydown', escape, true);
      document.removeEventListener('pointerover', otherControl, true);
      window.removeEventListener('resize', moved);
      window.removeEventListener('scroll', moved, true);
    };
  }, [anchor]);
  const child = cloneElement(children, {
    // Preserve the native fallback while idle, without displaying two hints.
    title: enabled && anchor ? undefined : children.props.title,
    'aria-describedby': enabled && anchor ? [children.props['aria-describedby'], id].filter(Boolean).join(' ') : children.props['aria-describedby'],
    onPointerEnter: event => { active.current.hovered = true; active.current.dismissed = false; show(event.currentTarget); children.props.onPointerEnter?.(event); },
    onPointerLeave: event => { active.current.hovered = false; active.current.dismissed = false; closeSoon(); children.props.onPointerLeave?.(event); },
    onFocus: event => { active.current.focused = true; show(event.currentTarget); children.props.onFocus?.(event); },
    onBlur: event => { active.current.focused = false; active.current.dismissed = false; closeSoon(); children.props.onBlur?.(event); },
    onPointerDown: event => { dismiss(); children.props.onPointerDown?.(event); },
    onClick: event => { dismiss(); children.props.onClick?.(event); },
  });
  return <>{child}{enabled && anchor && createPortal(<div ref={tooltipRef} id={id} role="tooltip" className="terminal-toolbar-hint"
    style={{ ...position, visibility: position ? 'visible' : 'hidden' }}
    onPointerEnter={() => { active.current.hovered = true; cancelClose(); }}
    onPointerLeave={() => { active.current.hovered = false; closeSoon(); }}>
    <strong>{label}</strong>{description && <span>{description}</span>}
  </div>, document.body)}</>;
}
