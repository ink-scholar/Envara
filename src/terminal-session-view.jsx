import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';
import { useAppearance } from './appearance.jsx';
import { getTerminalTheme, terminalFontFamily } from './terminal-theme.mjs';
import { attachTerminalKeyboard } from './terminal-keyboard.mjs';
import { attachTerminalComposition } from './terminal-composition.mjs';
import { attachTerminalProtocol } from './terminal-protocol.mjs';
import { splitTerminalInput } from './terminal-state.mjs';
import { attachTerminalAttachments } from './terminal-attachments.mjs';
import '@xterm/xterm/css/xterm.css';

const bounds = (value, low, high) => Math.max(low, Math.min(high, value));

// One mounted renderer per sessionId. Hiding a view only suspends input/focus;
// its buffer, subscriptions and attachment cancellation remain session-owned.
export function TerminalSession({ session, active, visible, autoFocus, focusRequest, preserveTabFocusRef, register, onError, screenReaderMode }) {
  const { t } = useI18n();
  const { effective } = useAppearance();
  const themeRef = useRef(effective);
  themeRef.current = effective;
  const screenReaderRef = useRef(screenReaderMode === true);
  screenReaderRef.current = screenReaderMode === true;
  const translationRef = useRef(t);
  translationRef.current = t;
  const containerRef = useRef(null);
  const controlRef = useRef(null);
  const [attachmentBusy, setAttachmentBusy] = useState(false);
  const sessionRef = useRef(session);
  const visibleRef = useRef(active && visible);
  sessionRef.current = session;
  visibleRef.current = active && visible;

  useEffect(() => {
    let disposed = false, inputTimer = null, fitTimer = null, input = '', sending = false, inputFlight = null, inputFailure = null, attachments = null;
    let lastSize = `${session.columns || 100}:${session.rows || 12}`;
    let resizeQueue = Promise.resolve();
    const terminal = new Terminal({
      cols: bounds(session.columns || 100, 20, 400), rows: bounds(session.rows || 12, 5, 150),
      cursorBlink: true, fontSize: 13, lineHeight: 1.1, scrollback: 3000, screenReaderMode: screenReaderRef.current,
      fontFamily: terminalFontFamily,
      disableStdin: session.status !== 'running' || !visibleRef.current,
      theme: getTerminalTheme(themeRef.current),
      linkHandler: { activate: event => event.preventDefault(), allowNonHttpProtocols: false },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(containerRef.current);
    const detachKeyboard = attachTerminalKeyboard(terminal);
    const detachComposition = attachTerminalComposition(terminal);
    const protocol = attachTerminalProtocol(terminal);
    terminal.textarea?.setAttribute('aria-label', translationRef.current('环境终端输入'));

    // Serialize xterm writes so a replay repair cannot reset queued live output.
    const output = [];
    let writing = false;
    const pumpOutput = () => {
      if (writing || disposed || !output.length) return;
      const item = output.shift();
      if (item.reset) terminal.reset();
      writing = true;
      terminal.write(item.data, () => { writing = false; pumpOutput(); });
    };
    const receive = item => { if (!disposed) { output.push(item); pumpOutput(); } };
    const unregister = register(session.sessionId, receive);

    const flushInput = () => {
      clearTimeout(inputTimer);
      inputTimer = null;
      if (inputFlight) return inputFlight;
      if (disposed) return Promise.resolve();
      inputFailure = null;
      sending = true;
      inputFlight = (async () => {
        while (input && !disposed && visibleRef.current && sessionRef.current.status === 'running') {
          const chunks = splitTerminalInput(input);
          input = '';
          for (const data of chunks) {
            if (disposed || !visibleRef.current || sessionRef.current.status !== 'running') break;
            await api.call('writeTerminal', { sessionId: session.sessionId, data });
          }
        }
      })().catch(error => { input = ''; inputFailure = error; if (!disposed) onError(error.message || '终端输入未发送，请重试。'); })
        .finally(() => { sending = false; inputFlight = null; });
      return inputFlight;
    };
    const inputSubscription = terminal.onData(data => {
      if (disposed || attachments?.busy || protocol.isResponse(data) || !visibleRef.current || sessionRef.current.status !== 'running') return;
      input += data;
      if (!inputTimer && !sending) inputTimer = setTimeout(() => { void flushInput(); }, 12);
    });
    const availableForAttachment = () => !disposed && visibleRef.current && sessionRef.current.status === 'running';
    const cancelInput = () => { input = ''; clearTimeout(inputTimer); inputTimer = null; };
    attachments = attachTerminalAttachments({ container: containerRef.current, sessionId: session.sessionId,
      upload: api.stageTerminalAttachments, call: (...args) => api.call(...args), isAvailable: availableForAttachment,
      beforeTransfer: async () => { await flushInput(); if (inputFailure) throw inputFailure; },
      insert: async (_quotedPaths, transferId) => {
        if (!availableForAttachment()) throw Object.assign(new Error('附件传输已取消。'), { code: 'TERMINAL_ATTACHMENT_CANCELLED' });
        await api.call('commitTerminalAttachments', { sessionId: session.sessionId, transferId, bracketedPaste: terminal.modes.bracketedPasteMode });
      }, onError, onBusyChange: busy => { if (!disposed) setAttachmentBusy(busy); },
    });
    const fitTerminal = () => {
      fitTimer = null;
      if (disposed || !visibleRef.current || !containerRef.current?.clientWidth || !containerRef.current?.clientHeight) return;
      fit.fit();
      const columns = bounds(terminal.cols, 20, 400), rows = bounds(terminal.rows, 5, 150);
      if (columns !== terminal.cols || rows !== terminal.rows) terminal.resize(columns, rows);
      const size = `${columns}:${rows}`;
      if (sessionRef.current.status !== 'running' || !document.hasFocus() || size === lastSize) return;
      lastSize = size;
      resizeQueue = resizeQueue.then(async () => {
        if (disposed || !visibleRef.current || !document.hasFocus() || sessionRef.current.status !== 'running') return;
        await api.call('resizeTerminal', { sessionId: session.sessionId, columns, rows });
      }).catch(error => { lastSize = ''; if (!disposed && sessionRef.current.status === 'running') onError(error.message || '终端尺寸未更新。'); });
    };
    const scheduleFit = () => { if (!fitTimer && !disposed) fitTimer = setTimeout(fitTerminal, 80); };
    const focusWindow = () => { lastSize = ''; scheduleFit(); };
    const observer = new ResizeObserver(scheduleFit);
    observer.observe(containerRef.current);
    window.addEventListener('focus', focusWindow);
    controlRef.current = { terminal, scheduleFit, cancelInput, attachments };
    scheduleFit();
    return () => {
      disposed = true;
      clearTimeout(inputTimer); clearTimeout(fitTimer);
      input = ''; output.length = 0;
      window.removeEventListener('focus', focusWindow);
      observer.disconnect(); attachments.dispose(); inputSubscription.dispose(); unregister(); detachKeyboard(); detachComposition(); protocol.dispose();
      controlRef.current = null; terminal.dispose();
    };
  }, [session.sessionId, register, onError]);

  // Recolour the existing renderer. Its buffer, subscriptions and PTY stay intact.
  useEffect(() => {
    const terminal = controlRef.current?.terminal;
    if (terminal) terminal.options.theme = getTerminalTheme(effective);
  }, [effective]);

  // xterm's input-only IME path is disabled in screen reader mode. Enable that
  // mode only when requested by the OS, without replacing the live terminal.
  useEffect(() => {
    const terminal = controlRef.current?.terminal;
    if (terminal) terminal.options.screenReaderMode = screenReaderMode === true;
  }, [screenReaderMode]);

  useEffect(() => {
    controlRef.current?.terminal.textarea?.setAttribute('aria-label', t('环境终端输入'));
  }, [t]);

  useEffect(() => {
    const control = controlRef.current;
    if (!control) return;
    control.terminal.options.disableStdin = session.status !== 'running' || !active || !visible;
    if (!active || !visible || session.status !== 'running') { control.attachments.cancel(); control.cancelInput(); }
    if (active && visible) {
      control.scheduleFit();
      if (!autoFocus) return;
      const frame = requestAnimationFrame(() => {
        const focused = document.activeElement;
        if (focused?.closest('.terminal-window-view-tabs')) return;
        if (!(preserveTabFocusRef.current && focused?.closest('[role="tablist"], .terminal-toolbar summary'))) control.terminal.focus();
      });
      return () => cancelAnimationFrame(frame);
    }
    control.terminal.blur();
  }, [active, visible, autoFocus, focusRequest, session.status]);

  return <div className={`terminal-session-view ${active ? 'is-selected' : ''}`} hidden={!active} aria-hidden={!active}>
    <div className="terminal-xterm-host" ref={containerRef} aria-label={t('环境终端')} onPointerDown={event => { if (event.button === 0) controlRef.current?.terminal.focus(); }} />
    {attachmentBusy && <span className="terminal-attachment-status" role="status">{t('正在保存附件…')}</span>}
  </div>;
}
