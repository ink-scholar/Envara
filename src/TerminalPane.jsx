import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { TerminalWindow, FolderOpen, Plus, X, CaretDown, ArrowsOutSimple, ArrowsInSimple, ArrowSquareOut, Copy, DotsThree } from '@phosphor-icons/react';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';
import { SYSTEM_BROWSER, terminalNetworks } from './link-browser.mjs';
import { TerminalStreamStore, splitTerminalInput, terminalHeightForPointer, terminalHeightForKey } from './terminal-state.mjs';
import { terminalTimezonePresentation } from './network-flow-state.mjs';
import '@xterm/xterm/css/xterm.css';
import './terminal.css';

const activeStatuses = new Set(['starting', 'running', 'closing']);
/* A tab is a terminal you can use. Ended sessions stay in the snapshot for
 * their output, but they are not offered as if they were still open. */
const liveSessions = sessions => (sessions ?? []).filter(session => activeStatuses.has(session.status));
const statusLabels = { starting: '启动中', running: '运行中', closing: '关闭中', exited: '已退出', closed: '已关闭', error: '启动失败' };
const timezoneSources = { proxy: '代理出口检测', 'proxy-egress': '代理出口检测', 'saved-configuration': '已保存配置', direct: '直连出口检测', manual: '手动设置', local: '本机时区回退', unknown: '来源未确认' };
const bounds = (value, low, high) => Math.max(low, Math.min(high, value));

function TerminalSession({ session, active, visible, focusRequest, preserveTabFocusRef, register, onError }) {
  const { t } = useI18n();
  const translationRef = useRef(t);
  translationRef.current = t;
  const containerRef = useRef(null);
  const controlRef = useRef(null);
  const sessionRef = useRef(session);
  const visibleRef = useRef(active && visible);
  sessionRef.current = session;
  visibleRef.current = active && visible;

  useEffect(() => {
    let disposed = false, inputTimer = null, fitTimer = null, input = '', sending = false;
    let lastSize = `${session.columns || 100}:${session.rows || 12}`;
    let resizeQueue = Promise.resolve();
    const terminal = new Terminal({
      cols: bounds(session.columns || 100, 20, 400), rows: bounds(session.rows || 12, 5, 150),
      cursorBlink: true, fontSize: 13, lineHeight: 1.1, scrollback: 3000, screenReaderMode: true,
      fontFamily: 'Menlo, Monaco, Consolas, "Liberation Mono", monospace',
      disableStdin: session.status !== 'running' || !visibleRef.current,
      theme: { background: '#19191c', foreground: '#d8d8df', cursor: '#e2e2e8', selectionBackground: '#334c68', black: '#25252b', brightBlack: '#737382', red: '#ed747c', green: '#8bcd9b', yellow: '#d9c58b', blue: '#71aaf5', magenta: '#be9add', cyan: '#83c9d1', white: '#d8d8df' },
      linkHandler: { activate: event => event.preventDefault(), allowNonHttpProtocols: false },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(containerRef.current);
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

    const flushInput = async () => {
      inputTimer = null;
      if (sending || disposed) return;
      sending = true;
      try {
        while (input && !disposed && sessionRef.current.status === 'running') {
          const chunks = splitTerminalInput(input);
          input = '';
          for (const data of chunks) {
            if (disposed || sessionRef.current.status !== 'running') break;
            await api.call('writeTerminal', { sessionId: session.sessionId, data });
          }
        }
      } catch (error) { input = ''; if (!disposed) onError(error.message || '终端输入未发送，请重试。'); }
      finally { sending = false; }
    };
    const inputSubscription = terminal.onData(data => {
      if (disposed || !visibleRef.current || sessionRef.current.status !== 'running') return;
      input += data;
      if (!inputTimer && !sending) inputTimer = setTimeout(() => { void flushInput(); }, 12);
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
    controlRef.current = { terminal, scheduleFit };
    scheduleFit();
    return () => {
      disposed = true;
      clearTimeout(inputTimer); clearTimeout(fitTimer);
      input = ''; output.length = 0;
      window.removeEventListener('focus', focusWindow);
      observer.disconnect(); inputSubscription.dispose(); unregister();
      controlRef.current = null; terminal.dispose();
    };
  }, [session.sessionId, register, onError]);

  useEffect(() => {
    controlRef.current?.terminal.textarea?.setAttribute('aria-label', t('环境终端输入'));
  }, [t]);

  useEffect(() => {
    const control = controlRef.current;
    if (!control) return;
    control.terminal.options.disableStdin = session.status !== 'running' || !active || !visible;
    if (active && visible) {
      control.scheduleFit();
      const frame = requestAnimationFrame(() => {
        if (!(preserveTabFocusRef.current && document.activeElement?.closest('[role="tablist"]'))) control.terminal.focus();
      });
      return () => cancelAnimationFrame(frame);
    }
    control.terminal.blur();
  }, [active, visible, focusRequest, session.status]);

  return <div className={`terminal-session-view ${active ? 'is-selected' : ''}`} hidden={!active} aria-hidden={!active}>
    <div className="terminal-xterm-host" ref={containerRef} aria-label={t('环境终端')} onPointerDown={event => { if (event.button === 0) controlRef.current?.terminal.focus(); }} />
  </div>;
}

export function TerminalDock({ profiles = [], visible = true, onHide, openRequest = null, onError, onProfilesChange, standalone = false, selectedProfileId = null, refreshKey = 0, expanded = false, onToggleExpanded, onHeightChange, onResizeStart, minHeight = 320, maxHeight }) {
  const { t } = useI18n();
  const desktopAvailable = api.isDesktop && typeof api.onTerminalEvent === 'function';
  const storeRef = useRef(new TerminalStreamStore());
  const receiversRef = useRef(new Map());
  const callbacksRef = useRef({ onError, onProfilesChange, onHeightChange, onResizeStart });
  callbacksRef.current = { onError, onProfilesChange, onHeightChange, onResizeStart };
  const scopeRef = useRef({ standalone, profileIds: new Set(profiles.map(profile => profile.id)) });
  scopeRef.current = { standalone, profileIds: new Set(profiles.map(profile => profile.id)) };
  const dockRef = useRef(null), dragRef = useRef(null), dragFrameRef = useRef(null);
  const sessionTabsRef = useRef(null), selectedSessionTabRef = useRef(null);
  const preserveTabFocusRef = useRef(false);
  const mountedRef = useRef(false), refreshRef = useRef(null), refreshFunctionRef = useRef(null);
  const refreshTimerRef = useRef(null), queuedRefreshRef = useRef(false), publishFrameRef = useRef(null);
  const handledRequestRef = useRef(null), openingRef = useRef(new Map());
  const [terminalState, setTerminalState] = useState({ profiles: [] });
  const [activeProfileId, setActiveProfileId] = useState(selectedProfileId || profiles[0]?.id || null);
  const [activeSessions, setActiveSessions] = useState({});
  const [newSession, setNewSession] = useState(null);
  const activeSessionsRef = useRef(activeSessions);
  activeSessionsRef.current = activeSessions;
  const [pending, setPending] = useState('');
  const [focusVersion, setFocusVersion] = useState(0);
  const [dockError, setDockError] = useState('');
  const [loading, setLoading] = useState(desktopAvailable);
  const [resizing, setResizing] = useState(false);
  const [measuredHeight, setMeasuredHeight] = useState(minHeight);
  const profileIds = profiles.map(profile => profile.id).join('|');
  const standaloneProfileId = standalone ? profiles[0]?.id : null;
  const shown = standalone || visible;
  const minimumHeight = Number.isFinite(minHeight) ? Math.max(0, minHeight) : 320;
  const maximumHeight = Math.max(minimumHeight, Number.isFinite(maxHeight) ? maxHeight : window.innerHeight - 180);
  const limitsRef = useRef({ minimum: minimumHeight, maximum: maximumHeight });
  limitsRef.current = { minimum: minimumHeight, maximum: maximumHeight };

  const reportError = useCallback(message => {
    if (!mountedRef.current) return;
    setDockError(message); callbacksRef.current.onError?.(message);
  }, []);
  const publish = useCallback(() => {
    if (publishFrameRef.current != null || !mountedRef.current) return;
    publishFrameRef.current = requestAnimationFrame(() => {
      publishFrameRef.current = null;
      if (!mountedRef.current) return;
      const value = storeRef.current.snapshot();
      setTerminalState(value); callbacksRef.current.onProfilesChange?.(value.profiles);
    });
  }, []);
  const writeOutputs = useCallback(writes => {
    for (const item of writes) receiversRef.current.get(item.sessionId)?.(item);
  }, []);
  const register = useCallback((sessionId, receive) => {
    receiversRef.current.set(sessionId, receive);
    // The store retains output while hidden or before the xterm view mounts.
    // It also restores the view after React StrictMode's setup/cleanup cycle.
    const replay = storeRef.current.replayFor(sessionId);
    if (replay) receive({ sessionId, data: replay });
    return () => { if (receiversRef.current.get(sessionId) === receive) receiversRef.current.delete(sessionId); };
  }, []);
  const scheduleRefresh = useCallback(() => {
    if (!mountedRef.current || refreshTimerRef.current != null) return;
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      if (refreshRef.current) queuedRefreshRef.current = true;
      else void refreshFunctionRef.current?.();
    }, 80);
  }, []);
  const refresh = useCallback(() => {
    if (!desktopAvailable || !mountedRef.current || (standalone && !standaloneProfileId)) return Promise.resolve(null);
    if (refreshRef.current) return refreshRef.current;
    const operation = api.call('terminalSnapshot', standalone ? { id: standaloneProfileId } : {}).then(value => {
      if (!mountedRef.current) return value;
      const result = storeRef.current.applySnapshot(value);
      writeOutputs(result.writes); publish();
      setLoading(false);
      return value;
    }).catch(error => { reportError(error.message || '无法读取终端会话。'); setLoading(false); return null; }).finally(() => {
      refreshRef.current = null;
      if (queuedRefreshRef.current) { queuedRefreshRef.current = false; scheduleRefresh(); }
    });
    refreshRef.current = operation;
    return operation;
  }, [desktopAvailable, standalone, standaloneProfileId, writeOutputs, publish, reportError, scheduleRefresh]);
  refreshFunctionRef.current = refresh;

  useEffect(() => {
    mountedRef.current = true;
    let unsubscribe;
    if (desktopAvailable) {
      // Subscribe first: PTY data can arrive while snapshot/open IPC is pending.
      unsubscribe = api.onTerminalEvent(event => {
        if (!mountedRef.current) return;
        if (scopeRef.current.standalone && !scopeRef.current.profileIds.has(event.profileId)) return;
        const result = storeRef.current.applyEvent(event);
        writeOutputs(result.writes);
        if (event.type !== 'data') publish();
        if (result.refreshNeeded || event.type !== 'data') scheduleRefresh();
      });
      void refresh();
    }
    return () => {
      mountedRef.current = false; unsubscribe?.();
      clearTimeout(refreshTimerRef.current); refreshTimerRef.current = null;
      cancelAnimationFrame(publishFrameRef.current); publishFrameRef.current = null;
    };
  }, [desktopAvailable, refresh, writeOutputs, publish, scheduleRefresh]);

  useEffect(() => {
    if (selectedProfileId && profiles.some(profile => profile.id === selectedProfileId)) { setActiveProfileId(selectedProfileId); return; }
    if (!profiles.some(profile => profile.id === activeProfileId)) setActiveProfileId(profiles[0]?.id ?? null);
  }, [selectedProfileId, profileIds, activeProfileId, profiles]);
  useEffect(() => { if (desktopAvailable) void refresh(); }, [desktopAvailable, refresh, activeProfileId, refreshKey]);

  const acceptSession = useCallback(session => {
    if (!session?.sessionId || !session.profileId) return;
    const profile = storeRef.current.snapshot().profiles.find(item => item.profileId === session.profileId) ?? { profileId: session.profileId };
    const result = storeRef.current.applySnapshot({ profiles: [{ ...profile, sessions: [session] }] });
    writeOutputs(result.writes); publish();
    setActiveSessions(value => ({ ...value, [session.profileId]: session.sessionId }));
  }, [publish, writeOutputs]);

  /* A new terminal is three choices: the network it leaves through, the
   * browser its links open in, and the folder it starts in. The browser is an
   * environment of that network, so choosing it also chooses whose tool
   * configuration, history and timezone the terminal uses. */
  const directoryFor = profileId => terminalState.profiles.find(profile => profile.profileId === profileId) ?? null;
  const networks = terminalNetworks(profiles);
  const defaultBrowser = network => network?.profiles.find(profile => profile.id === activeProfileId)?.id ?? network?.profiles[0]?.id ?? null;
  const chooserHost = choice => {
    const network = networks.find(item => item.id === choice?.networkId);
    if (!network) return null;
    return network.profiles.find(profile => profile.id === (choice.browserId === SYSTEM_BROWSER ? defaultBrowser(network) : choice.browserId)) ?? network.profiles[0] ?? null;
  };
  const openNewSessionChooser = () => {
    const current = profiles.find(profile => profile.id === activeProfileId) ?? profiles[0];
    const network = networks.find(item => item.profiles.some(profile => profile.id === current?.id)) ?? networks[0];
    if (!network) return;
    const saved = directoryFor(current?.id)?.browserProfileId;
    setNewSession({ networkId: network.id, browserId: saved === SYSTEM_BROWSER ? SYSTEM_BROWSER : current?.id ?? defaultBrowser(network), directory: null, error: '' });
  };
  const chooseNewSessionDirectory = async () => {
    const host = chooserHost(newSession);
    if (!host || pending) return;
    setPending(`directory:${host.id}`);
    try {
      const result = await api.call('pickTerminalDirectory', { id: host.id });
      if (result?.canceled || !result?.path) return;
      setNewSession(value => value ? { ...value, directory: { path: result.path, token: result.token }, error: '' } : value);
    } catch (error) { setNewSession(value => value ? { ...value, error: error.message || String(error) } : value); }
    finally { if (mountedRef.current) setPending(''); }
  };
  const confirmNewSession = async () => {
    const host = chooserHost(newSession);
    if (!host || pending) return;
    /* Where this environment's links go is saved with it: its own browser, or
     * the system browser when that was chosen. */
    const wanted = newSession.browserId === SYSTEM_BROWSER ? SYSTEM_BROWSER : null;
    if ((directoryFor(host.id)?.browserProfileId ?? null) !== wanted) {
      try { await api.call('setTerminalLinkBrowser', { id: host.id, browserProfileId: wanted }); }
      catch (error) { setNewSession(value => value ? { ...value, error: error.message || String(error) } : value); return; }
    }
    const result = await openForProfile(host.id, { forceNew: true, directoryToken: newSession.directory?.token ?? null });
    if (result !== false) setNewSession(null);
  };
  const openForProfile = useCallback((profileId, { forceNew = false, directoryToken = null } = {}) => {
    if (!desktopAvailable || !profileId) return Promise.resolve();
    if (openingRef.current.has(profileId)) return openingRef.current.get(profileId);
    const operation = (async () => {
      setActiveProfileId(profileId); setFocusVersion(value => value + 1); setPending(`open:${profileId}`); setDockError('');
      try {
        await refresh();
        if (!mountedRef.current) return;
        const current = storeRef.current.snapshot().profiles.find(item => item.profileId === profileId);
        const source = current?.sessions.find(item => item.sessionId === activeSessionsRef.current[profileId] && item.status === 'running') ?? current?.sessions.find(item => item.status === 'running');
        const session = forceNew
          ? await api.call('openTerminal', { id: profileId, columns: 100, rows: 12, fresh: true, ...(directoryToken ? { directoryToken } : {}) })
          : source ? await api.call('duplicateTerminal', { sessionId: source.sessionId }) : await api.call('openTerminal', { id: profileId, columns: 100, rows: 12 });
        if (!session?.canceled && mountedRef.current) { acceptSession(session); await refresh(); }
        return true;
      } catch (error) {
        reportError(error.message || '终端无法启动。');
        return false;
      }
      finally { if (mountedRef.current) setPending(''); openingRef.current.delete(profileId); }
    })();
    openingRef.current.set(profileId, operation);
    return operation;
  }, [desktopAvailable, refresh, acceptSession, reportError]);

  useEffect(() => {
    if (!openRequest?.profileId) return;
    const key = `${openRequest.profileId}:${openRequest.sessionId || ''}:${openRequest.nonce}`;
    if (handledRequestRef.current === key) return;
    handledRequestRef.current = key;
    preserveTabFocusRef.current = false;
    setActiveProfileId(openRequest.profileId);
    if (openRequest.sessionId) setActiveSessions(value => ({ ...value, [openRequest.profileId]: openRequest.sessionId }));
    setFocusVersion(value => value + 1);
    if (desktopAvailable) void refresh();
  }, [openRequest?.profileId, openRequest?.sessionId, openRequest?.nonce, desktopAvailable, refresh]);

  useEffect(() => { if (shown) setFocusVersion(value => value + 1); }, [expanded]);

  const finishResize = useCallback((commit = true) => {
    const drag = dragRef.current;
    if (!drag) return;
    dragRef.current = null;
    cancelAnimationFrame(dragFrameRef.current); dragFrameRef.current = null;
    try { if (drag.element.hasPointerCapture(drag.pointerId)) drag.element.releasePointerCapture(drag.pointerId); } catch {}
    if (commit) callbacksRef.current.onHeightChange?.(drag.latestHeight);
    if (mountedRef.current) setResizing(false);
  }, []);
  useEffect(() => {
    const observer = new ResizeObserver(entries => {
      const height = Math.round(entries[0]?.target.getBoundingClientRect().height ?? 0);
      if (height > 0) setMeasuredHeight(height);
    });
    if (dockRef.current) observer.observe(dockRef.current);
    const release = event => { if (dragRef.current?.pointerId === event.pointerId) finishResize(event.type !== 'pointercancel'); };
    const blur = () => finishResize();
    window.addEventListener('pointerup', release); window.addEventListener('pointercancel', release); window.addEventListener('blur', blur);
    return () => {
      observer.disconnect(); finishResize(false);
      window.removeEventListener('pointerup', release); window.removeEventListener('pointercancel', release); window.removeEventListener('blur', blur);
    };
  }, [finishResize]);
  const beginResize = event => {
    if (event.button !== 0 || standalone || expanded || !onHeightChange) return;
    event.preventDefault();
    finishResize();
    const height = dockRef.current?.getBoundingClientRect().height || minimumHeight;
    dragRef.current = { pointerId: event.pointerId, startY: event.clientY, startHeight: height, latestHeight: Math.max(minimumHeight, Math.min(maximumHeight, height)), element: event.currentTarget };
    try { event.currentTarget.setPointerCapture(event.pointerId); } catch {}
    event.currentTarget.focus(); setResizing(true); callbacksRef.current.onResizeStart?.();
  };
  const moveResize = event => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    event.preventDefault();
    drag.latestHeight = terminalHeightForPointer(drag.startHeight, drag.startY, event.clientY, limitsRef.current.minimum, limitsRef.current.maximum);
    if (dragFrameRef.current == null) dragFrameRef.current = requestAnimationFrame(() => {
      dragFrameRef.current = null;
      if (dragRef.current) callbacksRef.current.onHeightChange?.(dragRef.current.latestHeight);
    });
  };
  const keyResize = event => {
    const height = dockRef.current?.getBoundingClientRect().height || measuredHeight;
    const next = terminalHeightForKey(height, event.key, minimumHeight, maximumHeight, event.shiftKey ? 64 : 32);
    if (next == null) return;
    event.preventDefault(); callbacksRef.current.onResizeStart?.(); onHeightChange?.(next);
  };

  const closeSession = async session => {
    if (!desktopAvailable || !session || pending || !activeStatuses.has(session.status)) return;
    setPending(`close:${session.sessionId}`); setDockError('');
    try { acceptSession(await api.call('closeTerminal', { sessionId: session.sessionId })); await refresh(); }
    catch (error) { reportError(error.message || '终端会话尚未关闭。'); }
    finally { if (mountedRef.current) setPending(''); }
  };
  const duplicateSession = async session => {
    if (!desktopAvailable || !session || session.status !== 'running' || pending) return;
    setPending(`duplicate:${session.sessionId}`); setDockError('');
    try {
      const created = await api.call('duplicateTerminal', { sessionId: session.sessionId });
      if (!created?.canceled && mountedRef.current) { acceptSession(created); setFocusVersion(value => value + 1); await refresh(); }
    } catch (error) { reportError(error.message || '无法复制终端会话。'); }
    finally { if (mountedRef.current) setPending(''); }
  };
  const openWindow = async (profileId, sessionId) => {
    if (!desktopAvailable || !profileId || pending || standalone) return;
    setPending('window'); setDockError('');
    try { await api.call('openTerminalWindow', { id: profileId, ...(sessionId ? { sessionId } : {}) }); }
    catch (error) { reportError(error.message || '无法打开独立终端窗口。'); }
    finally { if (mountedRef.current) setPending(''); }
  };

  const selectedProfile = profiles.find(profile => profile.id === activeProfileId);
  const selectedMetadata = terminalState.profiles.find(profile => profile.profileId === activeProfileId);
  const sessions = liveSessions(selectedMetadata?.sessions);
  const selectedSession = sessions.find(session => session.sessionId === activeSessions[activeProfileId]) ?? sessions.at(-1) ?? null;
  const sessionUnavailable = Boolean(activeSessions[activeProfileId] && !selectedSession && !loading);
  const hasLiveSession = sessions.length > 0;
  const sessionDirectory = selectedSession?.cwd || selectedMetadata?.cwd || null;
  const { timezone, source: timezoneSource } = terminalTimezonePresentation({ profile: selectedProfile, metadata: selectedMetadata, session: selectedSession, hasLiveSession });
  const timezoneLabel = timezone ? `${timezone} · ${t(timezoneSources[timezoneSource] || '来源未确认')}` : t('时区待确认');
  /* The selected terminal's own route first: which network it leaves through,
   * and whether the fence makes that the only way out. */
  const shownNetwork = selectedSession?.network ?? selectedMetadata?.network ?? null;
  const rawNetworkDescription = shownNetwork?.description || '启动后读取环境网络设置。';
  const proxyDescription = /^([A-Z0-9]+) 代理，仅支持代理配置的命令行工具生效；本机地址直连。$/.exec(rawNetworkDescription);
  const networkDescription = shownNetwork?.fenced
    ? t('经「{name}」出网，已加网络围栏：不支持代理的程序会连不上，不会直连。', { name: shownNetwork.routeName || String(shownNetwork.mode || '').toUpperCase() })
    : proxyDescription
      ? t('{protocol} 代理，仅支持代理配置的命令行工具生效；本机地址直连。', { protocol: proxyDescription[1] })
      : t(rawNetworkDescription);
  const allSessions = terminalState.profiles.filter(profile => !standalone || scopeRef.current.profileIds.has(profile.profileId)).flatMap(profile => liveSessions(profile.sessions));

  const navigateTabs = (event, items, index, select) => {
    if (event.altKey || event.ctrlKey || event.metaKey) return;
    if (event.key === 'Enter' || event.key === ' ') {
      preserveTabFocusRef.current = true; event.stopPropagation(); return;
    }
    const count = items.length;
    if (!count || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault(); event.stopPropagation(); preserveTabFocusRef.current = true;
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? count - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + count) % count;
    select(items[next]);
    const list = event.currentTarget.parentElement;
    const tab = list.querySelectorAll('[role="tab"]')[next];
    if (!tab) return;
    tab.focus({ preventScroll: true });
    const listRect = list.getBoundingClientRect(), tabRect = tab.getBoundingClientRect();
    const left = listRect.left + list.clientLeft + 3, right = listRect.left + list.clientLeft + list.clientWidth - 3;
    if (tabRect.left < left) list.scrollLeft += tabRect.left - left;
    else if (tabRect.right > right) list.scrollLeft += tabRect.right - right;
  };

  useLayoutEffect(() => {
    const list = sessionTabsRef.current;
    if (!list || !shown) return;
    let frame = null;
    const revealSelected = () => {
      const tab = selectedSessionTabRef.current;
      if (!tab || !list.clientWidth || !list.contains(tab)) return;
      const listRect = list.getBoundingClientRect(), tabRect = tab.getBoundingClientRect();
      const left = listRect.left + list.clientLeft + 3, right = listRect.left + list.clientLeft + list.clientWidth - 3;
      // Move only the tab list, never the document or surrounding workspace.
      if (tabRect.left < left) list.scrollLeft += tabRect.left - left;
      else if (tabRect.right > right) list.scrollLeft += tabRect.right - right;
    };
    revealSelected();
    const observer = new ResizeObserver(() => {
      if (frame != null) return;
      frame = requestAnimationFrame(() => { frame = null; revealSelected(); });
    });
    observer.observe(list);
    return () => { observer.disconnect(); cancelAnimationFrame(frame); };
  }, [selectedSession?.sessionId, activeProfileId, sessions.length, shown, expanded]);

  return <section ref={dockRef} className={`terminal-dock ${shown ? 'is-open' : 'is-collapsed'} ${standalone ? 'is-standalone' : ''} ${expanded ? 'is-expanded' : ''} ${resizing ? 'is-resizing' : ''}`} hidden={!shown} aria-label={t('环境终端')} onPointerDownCapture={() => { preserveTabFocusRef.current = false; }}>
    {!standalone && !expanded && onHeightChange && <div className="terminal-height-separator" role="separator" tabIndex={0} aria-label={t('调整终端高度')} aria-orientation="horizontal" aria-valuemin={Math.round(minimumHeight)} aria-valuemax={Math.round(maximumHeight)} aria-valuenow={Math.round(Math.max(minimumHeight, Math.min(maximumHeight, measuredHeight)))} aria-valuetext={t('{height} 像素', { height: Math.round(Math.max(minimumHeight, Math.min(maximumHeight, measuredHeight))) })} onPointerDown={beginResize} onPointerMove={moveResize} onLostPointerCapture={() => finishResize()} onKeyDown={keyResize} title={t('上下拖动调整高度；方向键调整，Home 最小，End 最大')}><DotsThree size={28} weight="bold" /></div>}
    <header className="terminal-dock-heading"><div className="terminal-dock-title"><TerminalWindow size={17} /><strong title={standalone ? selectedProfile?.name : undefined}>{standalone && selectedProfile ? t('{name} · 终端', { name: selectedProfile.name }) : t('终端')}</strong><span>{t('工具配置独立于其他环境')}</span></div>{!standalone && <div className="terminal-heading-actions"><button className="terminal-icon-button" disabled={!desktopAvailable || !selectedProfile || !!pending} onClick={() => void openWindow(activeProfileId, selectedSession?.sessionId)} aria-label={t('独立终端窗口')} title={t('在独立窗口中查看此环境的终端')}><ArrowSquareOut size={16} /></button><button className="terminal-icon-button" disabled={!onToggleExpanded} onClick={onToggleExpanded} aria-label={t(expanded ? '还原终端大小' : '放大终端')} title={t(expanded ? '还原终端大小' : '放大终端')}>{expanded ? <ArrowsInSimple size={17} /> : <ArrowsOutSimple size={17} />}</button><button className="terminal-icon-button" onClick={onHide} aria-label={t('收起终端')} title={t('收起终端，会话继续运行')}><CaretDown size={17} /></button></div>}</header>
    {!standalone && <div className="terminal-environment-tabs" role="tablist" aria-label={t('终端环境')}>{profiles.map((profile, index) => {
      const rows = liveSessions(terminalState.profiles.find(item => item.profileId === profile.id)?.sessions);
      const running = rows.some(session => activeStatuses.has(session.status));
      return <button key={profile.id} id={`terminal-env-${profile.id}`} className={`terminal-environment-tab ${activeProfileId === profile.id ? 'is-active' : ''}`} role="tab" aria-selected={activeProfileId === profile.id} tabIndex={activeProfileId === profile.id || (!selectedProfile && index === 0) ? 0 : -1} aria-controls="terminal-environment-panel" onKeyDown={event => navigateTabs(event, profiles, index, target => { setActiveProfileId(target.id); setDockError(''); })} onClick={() => { setActiveProfileId(profile.id); setDockError(''); }} title={profile.name}><span className={`terminal-tab-dot ${running ? 'is-running' : ''}`} /><span>{profile.name}</span>{rows.length > 0 && <small>{rows.length}</small>}</button>;
    })}</div>}
    <div id="terminal-environment-panel" className="terminal-environment-panel" role="tabpanel" aria-labelledby={!standalone && activeProfileId ? `terminal-env-${activeProfileId}` : undefined} aria-label={standalone ? t('{name}终端工作区', { name: selectedProfile?.name || t('环境') }) : undefined}>
      <div className="terminal-context-bar"><div className="terminal-directory" title={sessionDirectory || t('尚未选择工作目录')}><FolderOpen size={15} /><span>{sessionDirectory || t('尚未选择工作目录')}</span></div><span className={`terminal-timezone ${timezoneSource === 'local' ? 'is-fallback' : ''}`} title={timezoneLabel}>{timezoneLabel}</span><button className="terminal-text-button terminal-start-button" disabled={!desktopAvailable || !selectedProfile || !!pending} onClick={openNewSessionChooser} title={t('选择网络出口、浏览器和工作目录后打开终端')}><Plus size={13} />{t(pending.startsWith('open:') ? '启动中…' : '新建会话')}</button></div>
      {sessions.length > 0 && <div className="terminal-session-bar"><div className="terminal-session-tabs" ref={sessionTabsRef} role="tablist" aria-label={t('终端会话')}>{sessions.map((session, index) => <button key={session.sessionId} ref={session.sessionId === selectedSession?.sessionId ? selectedSessionTabRef : undefined} className={`terminal-session-tab ${session.sessionId === selectedSession?.sessionId ? 'is-active' : ''}`} role="tab" aria-selected={session.sessionId === selectedSession?.sessionId} tabIndex={session.sessionId === selectedSession?.sessionId || (!selectedSession && index === 0) ? 0 : -1} onKeyDown={event => navigateTabs(event, sessions, index, target => setActiveSessions(value => ({ ...value, [activeProfileId]: target.sessionId })))} onClick={() => setActiveSessions(value => ({ ...value, [activeProfileId]: session.sessionId }))}><span className={`terminal-tab-dot ${session.status === 'running' ? 'is-running' : ''}`} />{t('会话 {index}', { index: index + 1 })}<small>{t(statusLabels[session.status] || session.status)}</small></button>)}</div><div className="terminal-session-actions"><button className="terminal-duplicate-session" disabled={!desktopAvailable || selectedSession?.status !== 'running' || !!pending} onClick={() => void duplicateSession(selectedSession)} title={t('创建新进程，共享环境工具配置与历史；不复制正在运行的命令')}><Copy size={13} />{t(pending.startsWith('duplicate:') ? '复制中…' : '复制会话')}</button><button className="terminal-close-session" disabled={!selectedSession || !activeStatuses.has(selectedSession.status) || !!pending} onClick={() => void closeSession(selectedSession)} title={t('关闭当前终端会话')}><X size={13} />{t(pending.startsWith('close:') ? '关闭中…' : '关闭会话')}</button></div></div>}
      <div className="terminal-content">
        {allSessions.map(session => <TerminalSession key={session.sessionId} session={session} active={session.sessionId === selectedSession?.sessionId && session.profileId === activeProfileId} visible={shown} focusRequest={`${openRequest?.profileId === session.profileId ? `${openRequest.nonce}:${openRequest.sessionId || ''}` : ''}:${focusVersion}`} preserveTabFocusRef={preserveTabFocusRef} register={register} onError={reportError} />)}
        {!selectedSession && <div className="terminal-empty"><TerminalWindow size={25} /><div><strong>{t(!desktopAvailable ? '真实终端需使用桌面应用' : !selectedProfile ? '先创建一个环境' : loading ? '正在读取终端会话…' : sessionUnavailable ? '该会话已不可用' : '打开此环境的终端')}</strong><p>{t(!desktopAvailable ? '网页预览不连接本机 Shell。' : sessionUnavailable ? '可选择其他会话或新建会话。' : selectedProfile ? '选择工作目录后，使用此环境独立的工具配置与历史。' : '每个环境可分别选择工作目录。')}</p></div>{desktopAvailable && selectedProfile && <button className="terminal-empty-start" disabled={!!pending || loading} onClick={openNewSessionChooser}>{t(pending.startsWith('open:') ? '启动中…' : sessionUnavailable ? '新建会话' : '打开终端')}</button>}</div>}
      </div>
      {newSession && (() => {
        const network = networks.find(item => item.id === newSession.networkId) ?? networks[0];
        const host = chooserHost(newSession);
        const folder = newSession.directory?.path ?? directoryFor(host?.id)?.cwd ?? null;
        const egress = network?.egress;
        return <div className="terminal-new-session" role="dialog" aria-modal="false" aria-label={t('新建终端')}>
          <div className="terminal-new-session-head"><strong>{t('新建终端')}</strong><button className="terminal-icon-button" aria-label={t('取消')} onClick={() => setNewSession(null)}><X size={14} /></button></div>
          <label><span>{t('网络出口')}</span><select value={network?.id || ''} onChange={event => { const next = networks.find(item => item.id === event.target.value); if (next) setNewSession({ ...newSession, networkId: next.id, browserId: defaultBrowser(next), error: '' }); }}>{networks.map(item => <option key={item.id} value={item.id}>{item.name || t('本机网络')}</option>)}</select>
            <small className="terminal-new-session-egress">{egress?.ip ? [egress.ip, egress.country || egress.countryCode, egress.timezone].filter(Boolean).join(' · ') : t('出口待识别')}</small></label>
          <label><span>{t('浏览器')}</span><select value={newSession.browserId || ''} onChange={event => setNewSession({ ...newSession, browserId: event.target.value, error: '' })}>{(network?.profiles ?? []).map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}<option value={SYSTEM_BROWSER}>{`${t('系统默认浏览器')} · ${t('不经过境舱网络')}`}</option></select></label>
          <div className="terminal-new-session-field"><span>{t('工作目录')}</span><div className="terminal-new-session-directory"><FolderOpen size={14} /><span title={folder || ''}>{folder || t('尚未选择工作目录')}</span><button className="terminal-text-button" disabled={!!pending || !host} onClick={() => void chooseNewSessionDirectory()}>{t(pending.startsWith('directory:') ? '选择中…' : folder ? '更换目录' : '选择目录')}</button></div></div>
          {newSession.error && <div className="terminal-new-session-error">{newSession.error}</div>}
          <div className="terminal-new-session-actions"><button className="terminal-text-button" onClick={() => setNewSession(null)}>{t('取消')}</button><button className="terminal-text-button terminal-start-button" disabled={!!pending || !host} onClick={() => void confirmNewSession()}>{t(pending.startsWith('open:') ? '启动中…' : '打开终端')}</button></div>
        </div>;
      })()}
      <footer className="terminal-footer"><span className="terminal-network-description" title={dockError ? t(dockError) : networkDescription}>{dockError ? t(dockError) : networkDescription}</span>{standalone && <span className="terminal-view-notice">{t('关闭窗口后，会话继续运行。')}</span>}{selectedSession && <span className="terminal-session-state">{t(statusLabels[selectedSession.status] || selectedSession.status)}{selectedSession.exitCode != null && t(' · 退出码 {code}', { code: selectedSession.exitCode })}</span>}</footer>
    </div>
  </section>;
}
