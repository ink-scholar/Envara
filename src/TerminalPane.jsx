import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { TerminalWindow, FolderOpen, Plus, X, CaretDown, ArrowsOutSimple, ArrowsInSimple, ArrowSquareOut, Copy, DotsThree, ArrowsClockwise, PencilSimple, Trash, SlidersHorizontal, BookmarksSimple, GlobeHemisphereWest, DownloadSimple, Browsers } from '@phosphor-icons/react';
import { api } from './client.js';
import { useI18n } from './i18n.jsx';
import { useAppearance } from './appearance.jsx';
import { getTerminalTheme, terminalFontFamily } from './terminal-theme.mjs';
import { attachTerminalKeyboard } from './terminal-keyboard.mjs';
import { attachTerminalComposition } from './terminal-composition.mjs';
import { SYSTEM_BROWSER, terminalNetworks } from './link-browser.mjs';
import { CLAUDE_SESSION, sessionNetworks, sessionChoiceHost, changeSessionKind, terminalSessionOptions } from './terminal-session-choice.mjs';
import { TerminalErrorNotices } from './terminal-error-notices.mjs';
import { TerminalStreamStore, splitTerminalInput, terminalHeightForPointer, terminalHeightForKey } from './terminal-state.mjs';
import { terminalTimezonePresentation } from './network-flow-state.mjs';
import { NEW_CLAUDE_ACCOUNT, validClaudeAccountChoice, claudeAccountLabel, reconcileClaudeAccountChoice, claudeSessionForRequest, claudeInstallPresentation, claudeErrorMessage, validClaudeInstallationChoice, claudeInstallationOptions } from './claude-account-choice.mjs';
import { TerminalDeviceIdentifierDetails } from './terminal-device-identifiers.mjs';
import { reconcileTerminalProfile } from './terminal-profile-selection.mjs';
import { invalidatePickedTerminalDirectory, terminalDirectoryChoice } from './terminal-directory-choice.mjs';
import '@xterm/xterm/css/xterm.css';
import './terminal.css';

const activeStatuses = new Set(['starting', 'running', 'closing']);
/* A tab is a terminal you can use. Ended sessions stay in the snapshot for
 * their output, but they are not offered as if they were still open. */
const liveSessions = sessions => (sessions ?? []).filter(session => activeStatuses.has(session.status));
const statusLabels = { starting: '启动中', running: '运行中', closing: '关闭中', exited: '已退出', closed: '已关闭', error: '启动失败' };
const savedTerminalErrors = {
  TERMINAL_ENTRY_INVALID: '保存的终端配置无效。',
  TERMINAL_ENTRY_NOT_FOUND: '已保存终端已不存在。',
  TERMINAL_ENTRY_STORAGE_INVALID: '保存的终端记录文件无效。',
  TERMINAL_ENTRY_UNSAFE_PATH: '保存的终端记录目录或文件不安全。',
  TERMINAL_ENTRY_STORAGE_FAILED: '无法保存终端记录，请重试。',
  TERMINAL_ENTRY_LIMIT: '最多保存 512 个终端入口。',
  TERMINAL_ENTRY_BUSY: '此终端仍在启动或清理，请稍后重试。',
  TERMINAL_ENTRY_CONTEXT_CHANGED: '此终端的网络或浏览器配置已改变，请新建终端确认配置。',
  TERMINAL_ENTRY_DIRECTORY_UNAVAILABLE: '此终端的工作目录已改变，请重新选择。',
  CLAUDE_ACCOUNT_NOT_FOUND: '此 Claude 登录档案已不存在，请重新选择。',
};
const timezoneSources = { proxy: '代理出口检测', 'proxy-egress': '代理出口检测', 'saved-configuration': '已保存配置', direct: '直连出口检测', manual: '手动设置', local: '本机时区回退', unknown: '来源未确认' };
const bounds = (value, low, high) => Math.max(low, Math.min(high, value));

function TerminalSession({ session, active, visible, autoFocus, focusRequest, preserveTabFocusRef, register, onError, screenReaderMode }) {
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
      observer.disconnect(); inputSubscription.dispose(); unregister(); detachKeyboard(); detachComposition();
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
  </div>;
}

export function TerminalDock({ profiles = [], visible = true, onHide, openRequest = null, onError, onProfilesChange, onSelectProfile, standalone = false, workspace = false, selectedProfileId = null, refreshKey = 0, expanded = false, onToggleExpanded, onHeightChange, onResizeStart, minHeight = 320, maxHeight, screenReaderMode = false, onExport, onConfigureLinkBrowser, exportDisabled = false }) {
  const { t } = useI18n();
  const desktopAvailable = api.isDesktop && typeof api.onTerminalEvent === 'function';
  const storeRef = useRef(new TerminalStreamStore());
  const errorNoticesRef = useRef(new TerminalErrorNotices());
  const currentFailureRef = useRef(null);
  const receiversRef = useRef(new Map());
  const callbacksRef = useRef({ onError, onProfilesChange, onSelectProfile, onHeightChange, onResizeStart });
  callbacksRef.current = { onError, onProfilesChange, onSelectProfile, onHeightChange, onResizeStart };
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
  const previousSelectedProfileRef = useRef(selectedProfileId);
  const selectProfile = useCallback(profileId => {
    setActiveProfileId(profileId);
    callbacksRef.current.onSelectProfile?.(profileId);
  }, []);
  const [activeSessions, setActiveSessions] = useState({});
  const [newSession, setNewSession] = useState(null);
  const [contextOpen, setContextOpen] = useState(false);
  const [savedEntriesOpen, setSavedEntriesOpen] = useState({});
  const [savedEntryEditor, setSavedEntryEditor] = useState(null);
  const savedEntryActionRef = useRef(null), savedEntryScopeRef = useRef({ profileId: activeProfileId });
  if (savedEntryScopeRef.current.profileId !== activeProfileId) savedEntryScopeRef.current = { profileId: activeProfileId };
  const [claudeAccounts, setClaudeAccounts] = useState({ profileId: null, status: 'idle', items: [] });
  const [claudeInstallation, setClaudeInstallation] = useState({ profileId: null, status: 'idle', installed: false });
  const [accountsReload, setAccountsReload] = useState(0);
  const [installationReload, setInstallationReload] = useState(0);
  const [accountEditor, setAccountEditor] = useState(null);
  const accountMutationRef = useRef(false), accountsProfileRef = useRef(null);
  const [cancellingSessionId, setCancellingSessionId] = useState(null);
  const openingRequestsRef = useRef(new Map());
  const activeSessionsRef = useRef(activeSessions);
  activeSessionsRef.current = activeSessions;
  const [pending, setPending] = useState('');
  const [focusVersion, setFocusVersion] = useState(0);
  const [dockError, setDockError] = useState('');
  const [dockErrorCode, setDockErrorCode] = useState('');
  const [dockCleanupError, setDockCleanupError] = useState('');
  const [loading, setLoading] = useState(desktopAvailable);
  const [resizing, setResizing] = useState(false);
  const [measuredHeight, setMeasuredHeight] = useState(minHeight);
  const profileIds = profiles.map(profile => profile.id).join('|');
  const standaloneProfileId = standalone ? profiles[0]?.id : null;
  const shown = visible;
  const minimumHeight = Number.isFinite(minHeight) ? Math.max(0, minHeight) : 320;
  const maximumHeight = Math.max(minimumHeight, Number.isFinite(maxHeight) ? maxHeight : window.innerHeight - 180);
  const limitsRef = useRef({ minimum: minimumHeight, maximum: maximumHeight });
  limitsRef.current = { minimum: minimumHeight, maximum: maximumHeight };

  const clearFailure = useCallback(() => {
    currentFailureRef.current = null;
    setDockError(''); setDockErrorCode(''); setDockCleanupError('');
  }, []);
  const reportError = useCallback((message, code = '') => {
    if (!mountedRef.current) return;
    currentFailureRef.current = null;
    setDockError(message); setDockErrorCode(/^[A-Z][A-Z0-9_]{1,95}$/.test(code) ? code : ''); setDockCleanupError(''); callbacksRef.current.onError?.(message);
  }, []);
  const retainFailure = useCallback(value => {
    const notice = errorNoticesRef.current.take(value);
    if (!notice || !mountedRef.current) return;
    if (notice.updateOnly && (currentFailureRef.current?.sessionId !== notice.sessionId || currentFailureRef.current?.message !== notice.message)) return;
    currentFailureRef.current = notice;
    setDockError(claudeErrorMessage(notice.message, notice.code)); setDockErrorCode(notice.code);
    setDockCleanupError(notice.cleanupError);
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
      const result = storeRef.current.applySnapshot(value, { complete: true });
      for (const session of (value.profiles ?? []).flatMap(profile => profile.sessions ?? []).sort((a, b) => String(a.startedAt ?? '').localeCompare(String(b.startedAt ?? '')))) retainFailure(session);
      writeOutputs(result.writes); publish();
      setLoading(false);
      return value;
    }).catch(error => { reportError(error.message || '无法读取终端会话。'); setLoading(false); return null; }).finally(() => {
      refreshRef.current = null;
      if (queuedRefreshRef.current) { queuedRefreshRef.current = false; scheduleRefresh(); }
    });
    refreshRef.current = operation;
    return operation;
  }, [desktopAvailable, standalone, standaloneProfileId, writeOutputs, publish, reportError, scheduleRefresh, retainFailure]);
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
        if (event.status === 'starting' && event.requestId && openingRequestsRef.current.get(event.profileId) === event.requestId) setActiveSessions(value => ({ ...value, [event.profileId]: event.sessionId }));
        if (event.type === 'status' || event.type === 'exit') retainFailure(event);
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
  }, [desktopAvailable, refresh, writeOutputs, publish, scheduleRefresh, retainFailure]);

  useEffect(() => {
    const previousSelectedProfileId = previousSelectedProfileRef.current;
    previousSelectedProfileRef.current = selectedProfileId;
    setActiveProfileId(current => reconcileTerminalProfile({ activeProfileId: current, selectedProfileId,
      previousSelectedProfileId, profileIds: profileIds ? profileIds.split('|') : [] }));
  }, [selectedProfileId, profileIds]);
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
  const chooserHost = choice => sessionChoiceHost(networks, choice, activeProfileId);
  const accountProfileId = newSession?.kind === CLAUDE_SESSION ? chooserHost(newSession)?.id ?? null : null;
  const accountSessionState = terminalState.profiles.find(profile => profile.profileId === accountProfileId)?.sessions
    ?.filter(session => session.kind === CLAUDE_SESSION).map(session => `${session.sessionId}:${session.status}`).join('|') ?? '';
  useEffect(() => {
    let cancelled = false;
    const changedProfile = accountsProfileRef.current !== accountProfileId;
    accountsProfileRef.current = accountProfileId;
    if (changedProfile) setAccountEditor(null);
    if (!accountProfileId || !desktopAvailable) { setClaudeAccounts({ profileId: null, status: 'idle', items: [] }); return; }
    setClaudeAccounts(value => ({ profileId: accountProfileId, status: 'loading', items: changedProfile ? [] : value.items }));
    if (changedProfile) setNewSession(value => value ? { ...value, accountId: 'default', accountName: '', error: '' } : value);
    api.call('listClaudeAccounts', { id: accountProfileId }).then(result => {
      if (cancelled || !mountedRef.current) return;
      if (!Array.isArray(result?.accounts)) throw new Error('无法读取登录档案，请重试。');
      setClaudeAccounts({ profileId: accountProfileId, status: 'ready', items: result.accounts });
      setNewSession(value => value?.kind === CLAUDE_SESSION && value.browserId === accountProfileId
        ? { ...value, accountId: reconcileClaudeAccountChoice(result.accounts, value.accountId) } : value);
    }).catch(error => {
      if (!cancelled && mountedRef.current) setClaudeAccounts({ profileId: accountProfileId, status: 'error', items: [], error: error.message || '无法读取登录档案，请重试。' });
    });
    return () => { cancelled = true; };
  }, [accountProfileId, desktopAvailable, accountsReload, accountSessionState]);
  useEffect(() => {
    let cancelled = false;
    if (!accountProfileId || !desktopAvailable) { setClaudeInstallation({ profileId: null, status: 'idle', installed: false }); return; }
    setClaudeInstallation({ profileId: accountProfileId, status: 'loading', installed: false });
    setNewSession(value => value ? { ...value, installSource: 'download' } : value);
    api.call('claudeInstallationStatus', { id: accountProfileId }).then(result => {
      if (cancelled || !mountedRef.current) return;
      if (result?.errorCode) throw new Error(claudeErrorMessage(result.errorCode));
      if (typeof result?.installed !== 'boolean') throw new Error('无法读取 Claude 安装状态，请重试。');
      setClaudeInstallation({ profileId: accountProfileId, status: 'ready', installed: result.installed });
    }).catch(error => {
      if (!cancelled && mountedRef.current) setClaudeInstallation({ profileId: accountProfileId, status: 'error', installed: false, error: claudeErrorMessage(error.message) || '无法读取 Claude 安装状态，请重试。' });
    });
    return () => { cancelled = true; };
  }, [accountProfileId, desktopAvailable, installationReload]);
  const openNewSessionChooser = () => {
    const current = profiles.find(profile => profile.id === activeProfileId) ?? profiles[0];
    const network = networks.find(item => item.profiles.some(profile => profile.id === current?.id)) ?? networks[0];
    if (!network) return;
    setContextOpen(false);
    setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: false }));
    setSavedEntryEditor(null);
    const saved = directoryFor(current?.id)?.browserProfileId;
    setNewSession({ kind: 'shell', networkId: network.id, browserId: saved === SYSTEM_BROWSER ? SYSTEM_BROWSER : current?.id ?? defaultBrowser(network), directory: null, error: '' });
  };
  const chooseNewSessionDirectory = async () => {
    const host = chooserHost(newSession);
    if (!host || pending) return;
    setPending(`directory:${host.id}`);
    try {
      const result = await api.call('pickTerminalDirectory', { id: host.id });
      if (result?.canceled || !result?.path) return;
      setNewSession(value => value ? { ...value, directory: { path: result.path, token: result.token }, directoryNeedsSelection: false, error: '' } : value);
    } catch (error) { setNewSession(value => value ? { ...value, error: error.message || String(error) } : value); }
    finally { if (mountedRef.current) setPending(''); }
  };
  const createChosenAccount = async () => {
    const host = chooserHost(newSession);
    if (!host || pending || accountMutationRef.current || !newSession.accountName?.trim() || !validClaudeAccountChoice(claudeAccounts, host.id, newSession)) return null;
    accountMutationRef.current = true; setPending(`account:${host.id}`);
    try {
      const result = await api.call('createClaudeAccount', { id: host.id, name: newSession.accountName.trim() });
      if (!result?.account?.id) throw new Error('无法创建登录档案，请重试。');
      if (mountedRef.current) {
        setClaudeAccounts(value => ({ ...value, items: [...value.items, result.account] }));
        setNewSession(value => value ? { ...value, accountId: result.account.id, accountName: '', error: '' } : value);
      }
      return result.account.id;
    } catch (error) { if (mountedRef.current) setNewSession(value => value ? { ...value, error: error.message || '无法创建登录档案，请重试。' } : value); return null; }
    finally { accountMutationRef.current = false; if (mountedRef.current) setPending(''); }
  };
  const mutateAccount = async action => {
    if (!accountEditor || pending || accountMutationRef.current || accountEditor.profileId !== accountProfileId) return;
    const editor = accountEditor;
    accountMutationRef.current = true; setPending(`account-${action}:${editor.profileId}`);
    try {
      const result = await api.call(action === 'rename' ? 'renameClaudeAccount' : 'deleteClaudeAccount', {
        id: editor.profileId, accountId: editor.id, ...(action === 'rename' ? { name: editor.name.trim() } : { confirmed: true }),
      });
      if (!mountedRef.current) return;
      if (action === 'delete') {
        if (result?.deleted !== true) throw new Error('无法更新登录档案，请重试。');
        setAccountEditor(result.cleanupPending ? { ...editor, cleanupPending: true, confirmDelete: false, error: '' } : null);
      } else {
        if (result?.account?.id !== editor.id) throw new Error('无法更新登录档案，请重试。');
        setAccountEditor(null);
      }
      setAccountsReload(value => value + 1);
    } catch (error) {
      if (mountedRef.current) setAccountEditor(value => value ? { ...value, error: error.message || '无法更新登录档案，请重试。' } : value);
    } finally { accountMutationRef.current = false; if (mountedRef.current) setPending(''); }
  };
  const confirmNewSession = async () => {
    const host = chooserHost(newSession);
    if (!host || pending || accountMutationRef.current || accountEditor || !terminalDirectoryChoice(newSession).ready) return;
    let claudeAccountId;
    if (newSession.kind === CLAUDE_SESSION) {
      if (!validClaudeAccountChoice(claudeAccounts, host.id, newSession) || !validClaudeInstallationChoice(claudeInstallation, host.id, newSession.installSource)) return;
      claudeAccountId = newSession.accountId;
      if (claudeAccountId === NEW_CLAUDE_ACCOUNT) {
        claudeAccountId = await createChosenAccount();
        if (!claudeAccountId) return;
      }
    }
    /* Where this environment's links go is saved with it: its own browser, or
     * the system browser when that was chosen. */
    const wanted = newSession.browserId === SYSTEM_BROWSER ? SYSTEM_BROWSER : null;
    if (newSession.kind !== CLAUDE_SESSION && (directoryFor(host.id)?.browserProfileId ?? null) !== wanted) {
      try { await api.call('setTerminalLinkBrowser', { id: host.id, browserProfileId: wanted }); }
      catch (error) { setNewSession(value => value ? { ...value, error: error.message || String(error) } : value); return; }
    }
    const requestId = crypto.randomUUID();
    setNewSession(value => value ? { ...value, requestId, error: '' } : value);
    const result = await openForProfile(host.id, { forceNew: true, directoryToken: newSession.directory?.token ?? null, kind: newSession.kind, browserProfileId: newSession.browserId, claudeAccountId, requestId, ...(newSession.kind === CLAUDE_SESSION ? claudeInstallationOptions(claudeInstallation, host.id, newSession.installSource) : {}) });
    if (result !== false) setNewSession(null);
  };
  const openForProfile = useCallback((profileId, { forceNew = false, directoryToken = null, kind = 'shell', browserProfileId = null, claudeAccountId, requestId, claudeInstallSource } = {}) => {
    if (!desktopAvailable || !profileId) return Promise.resolve();
    if (openingRef.current.has(profileId)) return openingRef.current.get(profileId);
    if (requestId) openingRequestsRef.current.set(profileId, requestId);
    const operation = (async () => {
      selectProfile(profileId); setFocusVersion(value => value + 1); setPending(`open:${profileId}`); clearFailure();
      try {
        await refresh();
        if (!mountedRef.current) return;
        const current = storeRef.current.snapshot().profiles.find(item => item.profileId === profileId);
        const source = current?.sessions.find(item => item.sessionId === activeSessionsRef.current[profileId] && item.status === 'running') ?? current?.sessions.find(item => item.status === 'running');
        const session = forceNew
          ? await api.call('openTerminal', { id: profileId, columns: 100, rows: 12, fresh: true, ...terminalSessionOptions(kind, browserProfileId, claudeAccountId), ...(claudeInstallSource ? { claudeInstallSource } : {}), ...(requestId ? { requestId } : {}), ...(directoryToken ? { directoryToken } : {}) })
          : source ? await api.call('duplicateTerminal', { sessionId: source.sessionId }) : await api.call('openTerminal', { id: profileId, columns: 100, rows: 12 });
        if (!session?.canceled && mountedRef.current) { acceptSession(session); await refresh(); }
        return true;
      } catch (error) {
        if (requestId) setNewSession(value => value?.requestId === requestId ? { ...invalidatePickedTerminalDirectory(value), requestId: null, error: claudeErrorMessage(error.message, error.code) || '终端无法启动。' } : value);
        reportError(claudeErrorMessage(error.message, error.code) || '终端无法启动。', error.code || (/^CLAUDE_CODE_[A-Z_]+$/.test(error.message) ? error.message : ''));
        return false;
      }
      finally { if (mountedRef.current) setPending(''); openingRef.current.delete(profileId); openingRequestsRef.current.delete(profileId); }
    })();
    openingRef.current.set(profileId, operation);
    return operation;
  }, [desktopAvailable, refresh, acceptSession, reportError, clearFailure, selectProfile]);

  useEffect(() => {
    if (!openRequest?.profileId) return;
    const key = `${openRequest.profileId}:${openRequest.sessionId || ''}:${openRequest.nonce}`;
    if (handledRequestRef.current === key) return;
    handledRequestRef.current = key;
    preserveTabFocusRef.current = false;
    selectProfile(openRequest.profileId);
    if (openRequest.sessionId) setActiveSessions(value => ({ ...value, [openRequest.profileId]: openRequest.sessionId }));
    setFocusVersion(value => value + 1);
    if (desktopAvailable) void refresh();
  }, [openRequest?.profileId, openRequest?.sessionId, openRequest?.nonce, desktopAvailable, refresh, selectProfile]);

  useEffect(() => { if (shown) setFocusVersion(value => value + 1); }, [expanded]);
  useEffect(() => { setContextOpen(false); }, [activeProfileId]);

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
    const cancellingStart = session?.status === 'starting' && pending.startsWith('open:');
    if (!desktopAvailable || !session || (pending && !cancellingStart) || cancellingSessionId || !activeStatuses.has(session.status)) return;
    if (cancellingStart) setCancellingSessionId(session.sessionId);
    else setPending(`close:${session.sessionId}`);
    if (currentFailureRef.current?.sessionId !== session.sessionId) clearFailure();
    try { acceptSession(await api.call('closeTerminal', { sessionId: session.sessionId })); await refresh(); }
    catch (error) { if (currentFailureRef.current?.sessionId !== session.sessionId) reportError(error.message || '终端会话尚未关闭。'); await refresh(); }
    finally { if (mountedRef.current) { if (!cancellingStart) setPending(''); setCancellingSessionId(null); } }
  };
  const duplicateSession = async session => {
    if (!desktopAvailable || !session || session.status !== 'running' || pending) return;
    setPending(`duplicate:${session.sessionId}`); clearFailure();
    try {
      const created = await api.call('duplicateTerminal', { sessionId: session.sessionId });
      if (!created?.canceled && mountedRef.current) { acceptSession(created); setFocusVersion(value => value + 1); await refresh(); }
    } catch (error) { reportError(error.message || '无法复制终端会话。'); }
    finally { if (mountedRef.current) setPending(''); }
  };
  const actOnSavedEntry = async (entry, action, name) => {
    const profileId = activeProfileId;
    if (!desktopAvailable || !profileId || !entry?.id || pending || savedEntryActionRef.current) return;
    const scope = savedEntryScopeRef.current;
    const operation = { profileId, entryId: entry.id };
    const inCurrentScope = () => mountedRef.current && savedEntryScopeRef.current === scope && scopeRef.current.profileIds.has(profileId);
    savedEntryActionRef.current = operation;
    setPending(`saved-${action}:${entry.id}`); clearFailure();
    try {
      const args = { id: profileId, entryId: entry.id };
      if (action === 'open') {
        const session = await api.call('reopenSavedTerminal', { ...args, requestId: crypto.randomUUID() });
        if (inCurrentScope() && !session?.canceled) {
          acceptSession(session); setNewSession(null); setContextOpen(false);
          setSavedEntriesOpen(value => ({ ...value, [profileId]: false }));
          setFocusVersion(value => value + 1);
        }
      } else {
        await api.call(action === 'rename' ? 'renameSavedTerminal' : 'removeSavedTerminal', { ...args, ...(action === 'rename' ? { name: name.trim() } : {}) });
      }
      if (inCurrentScope()) setSavedEntryEditor(null);
      await refresh();
    } catch (error) {
      if (inCurrentScope()) reportError(savedTerminalErrors[error.code] || error.message || (action === 'open' ? '无法打开已保存终端，请重试。' : '无法更新已保存终端，请重试。'), error.code);
    } finally {
      if (savedEntryActionRef.current === operation) {
        savedEntryActionRef.current = null;
        if (mountedRef.current) setPending('');
      }
    }
  };
  useEffect(() => { setSavedEntryEditor(null); }, [activeProfileId]);
  const openWindow = async (profileId, sessionId) => {
    if (!desktopAvailable || !profileId || pending || standalone) return;
    setPending('window'); clearFailure();
    try { await api.call('openTerminalWindow', { id: profileId, ...(sessionId ? { sessionId } : {}) }); }
    catch (error) { reportError(error.message || '无法打开独立终端窗口。'); }
    finally { if (mountedRef.current) setPending(''); }
  };

  const selectedProfile = profiles.find(profile => profile.id === activeProfileId);
  const selectedMetadata = terminalState.profiles.find(profile => profile.profileId === activeProfileId);
  const savedEntries = selectedMetadata?.savedTerminals ?? [];
  const entryEditor = savedEntryEditor?.profileId === activeProfileId ? savedEntryEditor : null;
  const sessions = liveSessions(selectedMetadata?.sessions);
  const selectedSession = sessions.find(session => session.sessionId === activeSessions[activeProfileId]) ?? sessions.at(-1) ?? null;
  const savedMenuOpen = savedEntriesOpen[activeProfileId] ?? (!loading && !selectedSession && savedEntries.length > 0);
  const canCloseSelected = selectedSession && activeStatuses.has(selectedSession.status) && !cancellingSessionId && (!pending || (selectedSession.status === 'starting' && pending.startsWith('open:')));
  const sessionName = (session, index) => {
    if (session.savedTerminalName) {
      const namedSessions = sessions.filter(item => item.savedTerminalName === session.savedTerminalName);
      return namedSessions.length > 1 ? `${session.savedTerminalName} · ${namedSessions.findIndex(item => item.sessionId === session.sessionId) + 1}` : session.savedTerminalName;
    }
    return session.kind === CLAUDE_SESSION
      ? `Claude Code${session.claudeAccountId && session.claudeAccountId !== 'default' ? ` · ${session.claudeAccountName || session.claudeAccountId}` : ''} ${index + 1}`
      : t('会话 {index}', { index: index + 1 });
  };
  const sessionUnavailable = Boolean(activeSessions[activeProfileId] && !selectedSession && !loading);
  const hasLiveSession = sessions.length > 0;
  const sessionDirectory = selectedSession?.cwd || selectedMetadata?.cwd || null;
  const { timezone, source: timezoneSource } = terminalTimezonePresentation({ profile: selectedProfile, metadata: selectedMetadata, session: selectedSession, hasLiveSession });
  const timezoneLabel = timezone ? `${timezone} · ${t(timezoneSources[timezoneSource] || '来源未确认')}` : t('时区待确认');
  const sessionLanguage = selectedSession?.language ?? selectedMetadata?.language;
  const languageLabel = sessionLanguage?.effective
    ? sessionLanguage.fallback
      ? t('{requested} → {effective}（系统未提供所选语言）', { requested: sessionLanguage.requested, effective: sessionLanguage.effective })
      : `${t('有效语言')} · ${sessionLanguage.effective}`
    : '';
  /* The selected terminal's own route first: which network it leaves through,
   * and whether direct public connections are fenced. */
  const shownNetwork = selectedSession?.network ?? selectedMetadata?.network ?? null;
  const rawNetworkDescription = shownNetwork?.description || '启动后读取环境网络设置。';
  const proxyDescription = /^([A-Z0-9]+) 代理，仅支持代理配置的命令行工具生效；本机地址直连。$/.exec(rawNetworkDescription);
  const networkDescription = shownNetwork?.fenced
    ? t('经「{name}」代理访问公网，围栏阻止直接公网连接。本地开发服务仍可访问，其联网不受此围栏控制。', { name: shownNetwork.routeName || String(shownNetwork.mode || '').toUpperCase() })
    : proxyDescription
      ? t('{protocol} 代理，仅支持代理配置的命令行工具生效；本机地址直连。', { protocol: proxyDescription[1] })
      : t(rawNetworkDescription);
  const allSessions = terminalState.profiles.filter(profile => !standalone || scopeRef.current.profileIds.has(profile.profileId)).flatMap(profile => liveSessions(profile.sessions));

  useEffect(() => {
    if (!shown || (!contextOpen && !savedMenuOpen)) return;
    const dismiss = event => {
      if (event.type === 'keydown' && event.key !== 'Escape') return;
      if (event.type === 'pointerdown' && event.target.closest?.('.terminal-context-menu, .terminal-saved-terminals')) return;
      if (event.type === 'keydown') {
        event.preventDefault();
        preserveTabFocusRef.current = true;
        dockRef.current?.querySelector(contextOpen ? '.terminal-context-menu > summary' : '.terminal-saved-terminals > summary')?.focus();
      }
      setContextOpen(false);
      setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: false }));
      setSavedEntryEditor(null);
    };
    document.addEventListener('pointerdown', dismiss);
    document.addEventListener('keydown', dismiss);
    return () => { document.removeEventListener('pointerdown', dismiss); document.removeEventListener('keydown', dismiss); };
  }, [shown, contextOpen, savedMenuOpen, activeProfileId]);

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

  return <section ref={dockRef} className={`terminal-dock ${shown ? 'is-open' : 'is-collapsed'} ${standalone ? 'is-standalone' : ''} ${workspace ? 'is-workspace' : ''} ${expanded ? 'is-expanded' : ''} ${resizing ? 'is-resizing' : ''}`} hidden={!shown} aria-label={t('环境终端')} onPointerDownCapture={() => { preserveTabFocusRef.current = false; }}>
    {!standalone && !workspace && !expanded && onHeightChange && <div className="terminal-height-separator" role="separator" tabIndex={0} aria-label={t('调整终端高度')} aria-orientation="horizontal" aria-valuemin={Math.round(minimumHeight)} aria-valuemax={Math.round(maximumHeight)} aria-valuenow={Math.round(Math.max(minimumHeight, Math.min(maximumHeight, measuredHeight)))} aria-valuetext={t('{height} 像素', { height: Math.round(Math.max(minimumHeight, Math.min(maximumHeight, measuredHeight))) })} onPointerDown={beginResize} onPointerMove={moveResize} onLostPointerCapture={() => finishResize()} onKeyDown={keyResize} title={t('上下拖动调整高度；方向键调整，Home 最小，End 最大')}><DotsThree size={28} weight="bold" /></div>}
    <header className="terminal-toolbar">
      {!standalone && <div className="terminal-environment-picker"><TerminalWindow size={17} /><select aria-label={t('终端环境')} value={activeProfileId || ''} disabled={!profiles.length} onChange={event => { selectProfile(event.target.value); clearFailure(); }} title={selectedProfile?.name || t('终端环境')}>
        {!profiles.length && <option value="">{t('环境终端')}</option>}
        {profiles.map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
      </select></div>}
      <div className="terminal-session-tabs" ref={sessionTabsRef} role="tablist" aria-label={t('终端会话')}>{sessions.map((session, index) => <button key={session.sessionId} ref={session.sessionId === selectedSession?.sessionId ? selectedSessionTabRef : undefined} className={`terminal-session-tab ${session.sessionId === selectedSession?.sessionId ? 'is-active' : ''}`} title={sessionName(session, index)} role="tab" aria-selected={session.sessionId === selectedSession?.sessionId} tabIndex={session.sessionId === selectedSession?.sessionId || (!selectedSession && index === 0) ? 0 : -1} onKeyDown={event => navigateTabs(event, sessions, index, target => setActiveSessions(value => ({ ...value, [activeProfileId]: target.sessionId })))} onClick={() => setActiveSessions(value => ({ ...value, [activeProfileId]: session.sessionId }))}><span className={`terminal-tab-dot ${session.status === 'running' ? 'is-running' : ''}`} /><span className="terminal-session-name">{sessionName(session, index)}</span>{session.status !== 'running' && <small>{t(statusLabels[session.status] || session.status)}</small>}</button>)}</div>
      <div className="terminal-toolbar-actions">
      {selectedProfile && <details className="terminal-saved-terminals" open={savedMenuOpen}>
        <summary aria-label={t('已保存终端')} title={t('已保存终端')} onClick={event => {
          event.preventDefault();
          const open = !savedMenuOpen;
          if (open) { setContextOpen(false); setNewSession(null); }
          setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: open }));
          if (!open) setSavedEntryEditor(null);
        }}><BookmarksSimple size={17} /></summary>
        <div className="terminal-saved-panel"><div className="terminal-menu-heading"><strong>{t('已保存终端')}</strong><small>{savedEntries.length}</small></div>
        <div className="terminal-saved-list">
          {!savedEntries.length && <p className="terminal-saved-empty">{t('新建会话后会自动保存在这里。')}</p>}
          {savedEntries.map(entry => {
            const editor = entryEditor?.entryId === entry.id ? entryEditor : null;
            const accountName = entry.kind === CLAUDE_SESSION ? entry.claudeAccountName || t('登录档案不可用') : null;
            const accountLabel = accountName && claudeAccountLabel({ default: entry.claudeAccountId === 'default', name: accountName }, t);
            const busy = entry.status === 'starting' || entry.status === 'closing';
            return <div className="terminal-saved-entry" data-entry-id={entry.id} key={entry.id}>
              <div className="terminal-saved-row">
                <button className="terminal-saved-open" disabled={!desktopAvailable || !!pending || busy} aria-label={t('打开终端「{name}」', { name: entry.name })} title={entry.name} onClick={() => void actOnSavedEntry(entry, 'open')}>
                  <span className="terminal-saved-heading"><strong>{entry.name}</strong>{activeStatuses.has(entry.status) && <small><span className={`terminal-tab-dot ${entry.status === 'running' ? 'is-running' : ''}`} />{t(statusLabels[entry.status])}</small>}</span>
                  <span className="terminal-saved-context"><span className="terminal-saved-account" title={accountLabel || t('普通终端')}>{entry.kind === CLAUDE_SESSION ? `Claude Code · ${accountLabel}` : t('普通终端')}</span><span className="terminal-saved-directory" title={entry.cwd}><FolderOpen size={12} /><span>{entry.cwd}</span></span></span>
                </button>
                <div className="terminal-saved-actions">
                  <button className="terminal-icon-button terminal-saved-rename" disabled={!desktopAvailable || !!pending} aria-label={t('重命名终端「{name}」', { name: entry.name })} title={t('重命名终端「{name}」', { name: entry.name })} onClick={() => setSavedEntryEditor({ profileId: activeProfileId, entryId: entry.id, mode: 'rename', name: entry.name })}><PencilSimple size={14} /></button>
                  <button className="terminal-icon-button terminal-saved-remove" disabled={!desktopAvailable || !!pending} aria-label={t('移除终端入口「{name}」', { name: entry.name })} title={t('移除终端入口「{name}」', { name: entry.name })} onClick={() => setSavedEntryEditor({ profileId: activeProfileId, entryId: entry.id, mode: 'remove' })}><Trash size={14} /></button>
                </div>
              </div>
              {editor?.mode === 'rename' && <form className="terminal-saved-editor" onSubmit={event => { event.preventDefault(); if (editor.name.trim()) void actOnSavedEntry(entry, 'rename', editor.name); }}>
                <label>{t('终端名称')}<input autoFocus value={editor.name} maxLength={80} disabled={!!pending} onChange={event => setSavedEntryEditor({ ...editor, name: event.target.value })} onKeyDown={event => { if (event.key === 'Escape' && !pending) { event.preventDefault(); setSavedEntryEditor(null); } }} /></label>
                <div className="terminal-saved-editor-actions"><button type="button" className="terminal-text-button" disabled={!!pending} onClick={() => setSavedEntryEditor(null)}>{t('取消')}</button><button type="submit" className="terminal-text-button" disabled={!!pending || !editor.name.trim()}>{t('保存')}</button></div>
              </form>}
              {editor?.mode === 'remove' && <div className="terminal-saved-editor"><p>{t('仅移除此入口，登录资料和终端数据会保留。')}</p><div className="terminal-saved-editor-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => setSavedEntryEditor(null)}>{t('取消')}</button><button className="terminal-text-button terminal-saved-remove" disabled={!!pending} onClick={() => void actOnSavedEntry(entry, 'remove')}>{t('移除入口')}</button></div></div>}
            </div>;
          })}
        </div></div>
      </details>}
        <button className="terminal-icon-button" disabled={!desktopAvailable || !selectedProfile || !!pending} onClick={openNewSessionChooser} aria-label={t('新建会话')} title={t('新建会话')}><Plus size={17} /></button>
        <details className="terminal-context-menu" open={contextOpen}>
          <summary aria-label={t('会话设置')} title={t('会话设置')} onClick={event => { event.preventDefault(); setContextOpen(value => !value); setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: false })); setSavedEntryEditor(null); setNewSession(null); }}><SlidersHorizontal size={17} /></summary>
          <div className="terminal-context-panel">
            <div className="terminal-menu-heading"><strong>{t('会话设置')}</strong></div>
            <dl className="terminal-context-values">
              <div><dt>{t('工作目录')}</dt><dd className="terminal-directory"><FolderOpen size={14} /><span title={sessionDirectory || t('尚未选择工作目录')}>{sessionDirectory || t('尚未选择工作目录')}</span></dd></div>
              <div><dt>{t('网络出口')}</dt><dd>{networkDescription}</dd></div>
              <div><dt>{t('时区')}</dt><dd className={timezoneSource === 'local' ? 'is-fallback' : ''}>{timezoneLabel}</dd></div>
              {languageLabel && <div><dt>{t('有效语言')}</dt><dd className={sessionLanguage.fallback ? 'is-fallback' : ''}>{languageLabel}</dd></div>}
              {selectedSession?.kind === CLAUDE_SESSION && <div><dt>{t('浏览器')}</dt><dd>{selectedSession.browserName || selectedSession.browserProfileId}</dd></div>}
            </dl>
            <TerminalDeviceIdentifierDetails session={selectedSession} t={t} inline />
            <div className="terminal-context-actions">
              {selectedSession && <button className="terminal-text-button terminal-duplicate-session" disabled={!desktopAvailable || selectedSession.status !== 'running' || !!pending} onClick={() => { setContextOpen(false); void duplicateSession(selectedSession); }} title={t('创建新进程，共享环境工具配置与历史；不复制正在运行的命令')}><Copy size={14} />{t(pending.startsWith('duplicate:') ? '复制中…' : '复制会话')}</button>}
              {onConfigureLinkBrowser && <button className="terminal-text-button" disabled={!selectedProfile || !!pending} onClick={() => { setContextOpen(false); onConfigureLinkBrowser(activeProfileId); }}><Browsers size={14} />{t('链接浏览器')}</button>}
              {onExport && <button className="terminal-text-button" disabled={!selectedProfile || exportDisabled || !!pending} onClick={() => { setContextOpen(false); onExport(activeProfileId); }}><DownloadSimple size={14} />{t('导出终端')}</button>}
            </div>
          </div>
        </details>
        {!standalone && <>
          <button className="terminal-icon-button" disabled={!desktopAvailable || !selectedProfile || !!pending} onClick={() => void openWindow(activeProfileId, selectedSession?.sessionId)} aria-label={t('独立终端窗口')} title={t('在独立窗口中查看此环境的终端')}><ArrowSquareOut size={17} /></button>
          {!workspace && <button className="terminal-icon-button" disabled={!onToggleExpanded} onClick={onToggleExpanded} aria-label={t(expanded ? '还原终端大小' : '放大终端')} title={t(expanded ? '还原终端大小' : '放大终端')}>{expanded ? <ArrowsInSimple size={17} /> : <ArrowsOutSimple size={17} />}</button>}
          <button className="terminal-icon-button" onClick={onHide} aria-label={t('收起终端')} title={t('收起终端，会话继续运行')}><CaretDown size={17} /></button>
        </>}
        <button className="terminal-icon-button terminal-close-session" disabled={!canCloseSelected} onClick={() => void closeSession(selectedSession)} aria-label={t(selectedSession?.status === 'starting' && selectedSession?.kind === CLAUDE_SESSION ? '取消安装' : '关闭会话')} title={t('关闭当前终端会话')}><X size={17} /></button>
      </div>
    </header>
    <div id="terminal-environment-panel" className="terminal-environment-panel" aria-label={t('{name}终端工作区', { name: selectedProfile?.name || t('环境') })}>
      <div className="terminal-content">
        {allSessions.map(session => <TerminalSession key={session.sessionId} session={session} active={session.sessionId === selectedSession?.sessionId && session.profileId === activeProfileId} visible={shown} autoFocus={!contextOpen && !savedMenuOpen && !entryEditor && !newSession} focusRequest={`${openRequest?.profileId === session.profileId ? `${openRequest.nonce}:${openRequest.sessionId || ''}` : ''}:${focusVersion}`} preserveTabFocusRef={preserveTabFocusRef} register={register} onError={reportError} screenReaderMode={screenReaderMode} />)}
        {!selectedSession && <div className="terminal-empty"><TerminalWindow size={25} /><div><strong>{t(!desktopAvailable ? '真实终端需使用桌面应用' : !selectedProfile ? '先创建一个环境' : loading ? '正在读取终端会话…' : sessionUnavailable ? '该会话已不可用' : '打开此环境的终端')}</strong>{(!desktopAvailable || sessionUnavailable) && <p>{t(!desktopAvailable ? '网页预览不连接本机 Shell。' : '可选择其他会话或新建会话。')}</p>}</div>{desktopAvailable && selectedProfile && <button className="terminal-empty-start" disabled={!!pending || loading} onClick={openNewSessionChooser}>{t(pending.startsWith('open:') ? '启动中…' : sessionUnavailable ? '新建会话' : '打开终端')}</button>}</div>}
      </div>
      {newSession && (() => {
        const claude = newSession.kind === CLAUDE_SESSION;
        const availableNetworks = sessionNetworks(networks, newSession.kind);
        const network = availableNetworks.find(item => item.id === newSession.networkId);
        const host = chooserHost(newSession);
        const directory = terminalDirectoryChoice(newSession, directoryFor(host?.id)?.cwd);
        const folder = directory.path;
        const egress = network?.egress;
        const privacyMode = host?.privacy?.mode ?? 'standard';
        const startingSession = claudeSessionForRequest(terminalState.profiles, host?.id, newSession.requestId);
        const installation = claudeInstallPresentation(startingSession?.claudeInstall);
        const accountLoading = claudeAccounts.profileId !== host?.id || claudeAccounts.status === 'loading';
        const selectedAccount = claudeAccounts.items.find(account => account.id === newSession.accountId);
        const editorAccount = accountEditor && claudeAccounts.items.find(account => account.id === accountEditor.id);
        const editingAccount = accountEditor?.profileId === host?.id ? accountEditor : null;
        const installationLoading = claudeInstallation.profileId !== host?.id || claudeInstallation.status === 'loading';
        const opening = pending.startsWith('open:');
        const cancelCreation = () => { if (opening && startingSession?.status === 'starting') void closeSession(startingSession); else if (!pending) setNewSession(null); };
        return <div className="terminal-new-session" role="dialog" aria-modal="false" aria-label={t('新建终端')}>
          <div className="terminal-new-session-head"><strong>{t('新建终端')}</strong><button className="terminal-icon-button" aria-label={t(opening && claude ? '取消安装' : '取消')} disabled={!!pending && (!startingSession || !!cancellingSessionId)} onClick={cancelCreation}><X size={14} /></button></div>
          <div className="terminal-session-kind" role="group" aria-label={t('会话类型')}><button disabled={!!pending} aria-pressed={!claude} onClick={() => setNewSession(changeSessionKind(networks, newSession, 'shell', activeProfileId))}>{t('普通终端')}</button><button disabled={!!pending} aria-pressed={claude} onClick={() => setNewSession(changeSessionKind(networks, newSession, CLAUDE_SESSION, activeProfileId))}>Claude Code</button></div>
          {claude && <p className="terminal-claude-note"><strong>{t('进入终端后运行 claude。')}</strong></p>}
          {claude && !availableNetworks.length && <div className="terminal-new-session-error">{t('先添加网络出口，并为它创建一个境舱浏览器。')}</div>}
          <label><span>{t('网络出口')}</span><select value={network?.id || ''} disabled={!!pending || !availableNetworks.length} onChange={event => { const next = availableNetworks.find(item => item.id === event.target.value); if (next) setNewSession({ ...newSession, networkId: next.id, browserId: defaultBrowser(next), error: '' }); }}>{availableNetworks.map(item => <option key={item.id} value={item.id}>{item.name || t('本机网络')}</option>)}</select>
            <small className="terminal-new-session-egress">{egress?.ip ? [egress.ip, egress.country || egress.countryCode, egress.timezone].filter(Boolean).join(' · ') : t('出口待识别')}</small></label>
          <label><span>{t('浏览器')}</span><select value={newSession.browserId || ''} disabled={!!pending || !network} onChange={event => setNewSession({ ...newSession, browserId: event.target.value, error: '' })}>{(network?.profiles ?? []).map(profile => <option key={profile.id} value={profile.id}>{profile.name}</option>)}{!claude && <option value={SYSTEM_BROWSER}>{`${t('系统默认浏览器')} · ${t('不经过境舱网络')}`}</option>}</select></label>
          {claude && !claudeInstallation.installed && <div className="terminal-account-field terminal-install-source">{installationLoading ? <small role="status">{t('正在检查 Claude 安装…')}</small> : claudeInstallation.status === 'error' ? <div className="terminal-account-error" role="status"><span>{t(claudeInstallation.error)}</span><button className="terminal-text-button" onClick={() => setInstallationReload(value => value + 1)}>{t('重试')}</button></div> : <label><span>{t('Claude 安装')}</span><select value={newSession.installSource || 'download'} disabled={!!pending} onChange={event => setNewSession(value => ({ ...value, installSource: event.target.value, error: '' }))}><option value="download">{t('下载（推荐）')}</option><option value="local">{t('复制本机程序')}</option></select></label>}{!installationLoading && claudeInstallation.status === 'ready' && newSession.installSource === 'local' && <small>{t('只复制程序，登录档案仍独立。')}</small>}</div>}
          {claude && <div className="terminal-account-field">
            <label><span>{t('登录档案')}</span><select aria-label={t('登录档案')} value={newSession.accountId || 'default'} disabled={!!pending || accountLoading || claudeAccounts.status !== 'ready'} onChange={event => { setAccountEditor(null); setNewSession(value => ({ ...value, accountId: event.target.value, accountName: '', error: '' })); }}>{accountLoading ? <option value={newSession.accountId || 'default'}>{t('正在读取登录档案…')}</option> : <>{claudeAccounts.items.map(account => <option key={account.id} value={account.id}>{claudeAccountLabel(account, t)}</option>)}<option value={NEW_CLAUDE_ACCOUNT}>{t('新建登录档案…')}</option></>}</select></label>
            {newSession.accountId === NEW_CLAUDE_ACCOUNT && <><input aria-label={t('档案名称')} maxLength={80} value={newSession.accountName || ''} disabled={!!pending} onChange={event => setNewSession(value => ({ ...value, accountName: event.target.value, error: '' }))} placeholder={t('例如：工作账号')} /><button className="terminal-text-button terminal-account-manage" disabled={!!pending || !newSession.accountName?.trim()} onClick={() => void createChosenAccount()}>{t(pending.startsWith('account:') ? '正在创建档案…' : '创建档案')}</button></>}
            {selectedAccount && !editingAccount && <button className="terminal-text-button terminal-account-manage" disabled={!!pending || accountLoading} onClick={() => setAccountEditor({ profileId: host.id, id: selectedAccount.id, name: selectedAccount.name, originalName: claudeAccountLabel(selectedAccount, t), confirmDelete: false, error: '' })}>{t('管理档案')}</button>}
            {editingAccount && <div className="terminal-account-editor" role="group" aria-label={t('管理档案')}>
              {editingAccount.cleanupPending ? <><p role="status">{t('档案已移除，剩余资料尚未清理完成。请重试清理。')}</p><div className="terminal-account-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => void mutateAccount('delete')}>{t('重试清理')}</button><button className="terminal-text-button" disabled={!!pending} onClick={() => setAccountEditor(null)}>{t('完成')}</button></div></> : editingAccount.confirmDelete ? <>
                <strong>{t('删除「{name}」？', { name: editingAccount.originalName })}</strong><p>{t('这会删除此档案的登录信息、Claude 配置与会话历史。其他档案和共享终端配置会保留。')}</p>
                <div className="terminal-account-actions"><button className="terminal-text-button" disabled={!!pending} onClick={() => setAccountEditor(value => ({ ...value, confirmDelete: false, error: '' }))}>{t('取消')}</button><button className="terminal-text-button terminal-account-delete" disabled={!!pending || accountLoading || !editorAccount || editorAccount.inUse} onClick={() => void mutateAccount('delete')}>{t('确认删除档案')}</button></div>
              </> : <><label><span>{t('档案名称')}</span><input aria-label={t('修改档案名称')} maxLength={80} value={editingAccount.name} disabled={!!pending || editorAccount?.inUse} onChange={event => setAccountEditor(value => ({ ...value, name: event.target.value, error: '' }))} /></label>
                {editorAccount?.inUse && <p>{t('请先关闭使用此登录档案的 Claude 终端，再管理档案。')}</p>}
                {editorAccount?.default && <p>{t('默认登录档案不能删除，可以重命名。')}</p>}
                <div className="terminal-account-actions"><button className="terminal-text-button terminal-account-delete" disabled={!!pending || accountLoading || !editorAccount || editorAccount.default || editorAccount.inUse} onClick={() => setAccountEditor(value => ({ ...value, confirmDelete: true, error: '' }))}>{t('删除档案')}</button><button className="terminal-text-button" disabled={!!pending} onClick={() => setAccountEditor(null)}>{t('取消')}</button><button className="terminal-text-button" disabled={!!pending || accountLoading || !editorAccount || editorAccount.inUse || !editingAccount.name.trim() || editingAccount.name.trim() === editorAccount.name} onClick={() => void mutateAccount('rename')}>{t('保存名称')}</button></div>
              </>}
              {editingAccount.error && <div className="terminal-account-error" role="status">{t(editingAccount.error)}</div>}
            </div>}
            {claudeAccounts.status === 'error' && <div className="terminal-account-error" role="status"><span>{t(claudeAccounts.error)}</span><button className="terminal-text-button" onClick={() => setAccountsReload(value => value + 1)}>{t('重试')}</button></div>}
          </div>}
          <div className="terminal-new-session-field"><span>{t('工作目录')}</span><div className="terminal-new-session-directory"><FolderOpen size={14} /><span title={folder || ''}>{folder || t('尚未选择工作目录')}</span><button className="terminal-text-button" disabled={!!pending || !host} onClick={() => void chooseNewSessionDirectory()}>{t(pending.startsWith('directory:') ? '选择中…' : folder ? '更换目录' : '选择目录')}</button></div></div>
          {claude && <details className="terminal-claude-settings"><summary>{t('会话设置')}</summary><dl>
            <div><dt>{t('登录方式')}</dt><dd>{t('账号登录；启动前检查 API 配置冲突')}</dd></div>
            <div><dt>{t('配置与历史')}</dt><dd>{t('境舱独立保存')}</dd></div>
            <div><dt>{t('网络与浏览器')}</dt><dd>{t('固定绑定；网络组件退出时结束会话')}</dd></div>
            <div><dt>{t('官方隐私设置')}</dt><dd>{t({ off: '停用', standard: '标准', strict: '严格' }[privacyMode] ?? '标准')}<small>{t({ off: '不额外关闭遥测与错误上报。', standard: '关闭遥测与错误上报。', strict: '同时关闭非必要网络请求。' }[privacyMode] ?? '关闭遥测与错误上报。')}</small>{privacyMode !== 'off' && <small className="terminal-claude-privacy-note">{t('关闭遥测可能影响 Remote Control 等功能。')}</small>}</dd></div>
          </dl><p>{t('内置浏览器工具绑定所选浏览器；支持此境舱的自定义 MCP。会话内关闭自动更新。')}</p></details>}
          {newSession.error && <div className="terminal-new-session-error">{t(newSession.error)}</div>}
          {opening && <div className="terminal-install-progress" role="status"><div><ArrowsClockwise className="spin" size={14} /><span>{t(installation?.label || '准备中…')}</span>{installation?.percent != null && <strong>{installation.percent}%</strong>}</div>{installation?.percent != null && <progress max="100" value={installation.percent} />}</div>}
          <div className="terminal-new-session-actions"><button className="terminal-text-button" disabled={!!pending && (!startingSession || !!cancellingSessionId)} onClick={cancelCreation}>{t(cancellingSessionId ? '关闭中…' : opening && claude ? '取消安装' : '取消')}</button><button className="terminal-text-button terminal-start-button" aria-busy={!!pending || undefined} disabled={!!pending || !!editingAccount || !host || !directory.ready || (claude && (!validClaudeAccountChoice(claudeAccounts, host.id, newSession) || !validClaudeInstallationChoice(claudeInstallation, host.id, newSession.installSource)))} onClick={() => void confirmNewSession()}>{t(pending.startsWith('account:') ? '正在创建档案…' : opening ? '启动中…' : newSession.error ? '重试' : '打开终端')}</button></div>
        </div>;
      })()}
      <footer className={`terminal-footer ${dockError ? 'has-error' : ''}`}><div className="terminal-footer-messages" role={dockError ? 'status' : undefined}><span className="terminal-network-description" title={dockError ? t(dockError) : networkDescription}>{dockError ? t(dockError) : <><GlobeHemisphereWest size={12} /><span>{shownNetwork?.routeName || (shownNetwork?.mode === 'direct' ? t('本机网络') : shownNetwork?.mode ? String(shownNetwork.mode).toUpperCase() : t('启动后读取环境网络设置。'))}</span></>}</span>{dockError && dockCleanupError && <span className="terminal-cleanup-error" title={t(dockCleanupError)}>{t('清理错误')} · {t(dockCleanupError)}</span>}</div>{dockError && dockErrorCode && <code className="terminal-error-code" title={dockErrorCode}>{dockErrorCode}</code>}{standalone && <span className="terminal-view-notice">{t('关闭窗口后，会话继续运行。')}</span>}{selectedSession && <span className="terminal-session-state">{t(statusLabels[selectedSession.status] || selectedSession.status)}{selectedSession.exitCode != null && t(' · 退出码 {code}', { code: selectedSession.exitCode })}</span>}</footer>
    </div>
  </section>;
}
