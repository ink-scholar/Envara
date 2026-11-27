import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { TerminalWindow, Plus, X, CaretDown, ArrowsOutSimple, ArrowsInSimple, ArrowSquareOut, Copy, DotsThree, GlobeHemisphereWest } from '@phosphor-icons/react';
import { api } from './client.js';
import { TerminalToolbarHint } from './TerminalToolbarHint.jsx';
import { useI18n } from './i18n.jsx';
import { SYSTEM_BROWSER, terminalNetworks } from './link-browser.mjs';
import { CLAUDE_SESSION, sessionChoiceHost, terminalSessionOptions } from './terminal-session-choice.mjs';
import { TerminalErrorNotices } from './terminal-error-notices.mjs';
import { TerminalStreamStore, terminalHeightForPointer, terminalHeightForKey } from './terminal-state.mjs';
import { NEW_CLAUDE_ACCOUNT, validClaudeAccountChoice, reconcileClaudeAccountChoice, claudeErrorMessage, validClaudeInstallationChoice, claudeInstallationOptions } from './claude-account-choice.mjs';
import { TerminalKeychainNotice, terminalKeychainDiagnosticText } from './terminal-keychain-notice.mjs';
import { reconcileTerminalProfile } from './terminal-profile-selection.mjs';
import { invalidatePickedTerminalDirectory, terminalDirectoryChoice } from './terminal-directory-choice.mjs';
import { terminalAccountName, terminalSessionName, terminalsForAccount } from './terminal-account-context.mjs';
import { TerminalSession } from './terminal-session-view.jsx';
import { TerminalSavedMenu } from './terminal-saved-menu.jsx';
import { TerminalSessionContext } from './terminal-session-context.jsx';
import { TerminalSessionChooser } from './terminal-session-chooser.jsx';
import { activeStatuses, liveSessions, statusLabels } from './terminal-session-status.mjs';
import './terminal.css';

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

export function TerminalDock({ systemPlatform = null, profiles = [], visible = true, onHide, openRequest = null, onError, onProfilesChange, onSelectProfile, standalone = false, workspace = false, selectedProfileId = null, refreshKey = 0, expanded = false, onToggleExpanded, onHeightChange, onResizeStart, minHeight = 320, maxHeight, screenReaderMode = false, onExport, onConfigureLinkBrowser, exportDisabled = false }) {
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
  const selectionRevisionRef = useRef(0);
  const mountedRef = useRef(false), refreshRef = useRef(null), refreshFunctionRef = useRef(null);
  const refreshTimerRef = useRef(null), queuedRefreshRef = useRef(false), publishFrameRef = useRef(null);
  const handledRequestRef = useRef(null), openingRef = useRef(new Map());
  const [terminalState, setTerminalState] = useState({ profiles: [] });
  const [activeProfileId, setActiveProfileId] = useState(selectedProfileId || profiles[0]?.id || null);
  const previousSelectedProfileRef = useRef(selectedProfileId);
  const selectProfile = useCallback(profileId => {
    selectionRevisionRef.current++;
    setActiveProfileId(profileId);
    callbacksRef.current.onSelectProfile?.(profileId);
  }, []);
  const [activeSessions, setActiveSessions] = useState({});
  const [newSession, setNewSession] = useState(null);
  const [contextOpen, setContextOpen] = useState(false);
  const [savedEntriesOpen, setSavedEntriesOpen] = useState({});
  const [savedQueries, setSavedQueries] = useState({});
  const [savedEntryEditor, setSavedEntryEditor] = useState(null);
  const savedEntryActionRef = useRef(null), savedEntryScopeRef = useRef({ profileId: activeProfileId });
  const savedEntryFocusRef = useRef(null);
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
  const selectSession = useCallback((profileId, sessionId) => {
    selectionRevisionRef.current++;
    setActiveSessions(value => ({ ...value, [profileId]: sessionId }));
    setFocusVersion(value => value + 1);
  }, []);
  const [dockError, setDockError] = useState('');
  const [dockErrorCode, setDockErrorCode] = useState('');
  const [dockKeychainDiagnostic, setDockKeychainDiagnostic] = useState('');
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
    setDockError(''); setDockErrorCode(''); setDockKeychainDiagnostic(''); setDockCleanupError('');
  }, []);
  const reportError = useCallback((message, code = '', diagnostic = null) => {
    if (!mountedRef.current) return;
    currentFailureRef.current = null;
    setDockKeychainDiagnostic(terminalKeychainDiagnosticText(diagnostic));
    setDockError(message); setDockErrorCode(/^[A-Z][A-Z0-9_]{1,95}$/.test(code) ? code : ''); setDockCleanupError(''); callbacksRef.current.onError?.(message);
  }, []);
  const retainFailure = useCallback(value => {
    const notice = errorNoticesRef.current.take(value);
    if (!notice || !mountedRef.current) return;
    if (notice.updateOnly && (currentFailureRef.current?.sessionId !== notice.sessionId || currentFailureRef.current?.message !== notice.message)) return;
    currentFailureRef.current = notice;
    setDockError(claudeErrorMessage(notice.message, notice.code)); setDockErrorCode(notice.code);
    setDockCleanupError(notice.cleanupError);
    setDockKeychainDiagnostic(terminalKeychainDiagnosticText(notice.keychainDiagnostic));
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
        const opening = openingRequestsRef.current.get(event.profileId);
        if (event.status === 'starting' && event.requestId && opening?.requestId === event.requestId && !opening.selected) {
          // Installation progress repeats "starting". Only its first event may
          // select a new tab, and never after a newer explicit user choice.
          opening.selected = true;
          if (opening.selectionRevision === selectionRevisionRef.current) setActiveSessions(value => ({ ...value, [event.profileId]: event.sessionId }));
        }
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

  const acceptSession = useCallback((session, { select = true } = {}) => {
    if (!session?.sessionId || !session.profileId) return;
    const profile = storeRef.current.snapshot().profiles.find(item => item.profileId === session.profileId) ?? { profileId: session.profileId };
    const result = storeRef.current.applySnapshot({ profiles: [{ ...profile, sessions: [session] }] });
    writeOutputs(result.writes); publish();
    if (select) setActiveSessions(value => ({ ...value, [session.profileId]: session.sessionId }));
  }, [publish, writeOutputs]);

  /* A new terminal is three choices: the network it leaves through, the
   * browser its links open in, and the folder it starts in. The browser is an
   * environment of that network, so choosing it also chooses whose tool
   * configuration, history and timezone the terminal uses. */
  const directoryFor = profileId => terminalState.profiles.find(profile => profile.profileId === profileId) ?? null;
  const networks = terminalNetworks(profiles);
  const defaultBrowser = network => network?.profiles.find(profile => profile.id === activeProfileId)?.id ?? network?.profiles[0]?.id ?? null;
  const chooserHost = choice => choice?.manageAccount ? profiles.find(profile => profile.id === choice.profileId) ?? null : sessionChoiceHost(networks, choice, activeProfileId);
  const accountProfileId = newSession?.kind === CLAUDE_SESSION ? chooserHost(newSession)?.id ?? null : null;
  const accountSessionState = terminalState.profiles.find(profile => profile.profileId === accountProfileId)?.sessions
    ?.filter(session => session.kind === CLAUDE_SESSION).map(session => `${session.sessionId}:${session.status}`).join('|') ?? '';
  useEffect(() => {
    let cancelled = false;
    const changedProfile = accountsProfileRef.current !== accountProfileId;
    accountsProfileRef.current = accountProfileId;
    if (changedProfile) setAccountEditor(value => value?.profileId === accountProfileId ? value : null);
    if (!accountProfileId || !desktopAvailable) { setClaudeAccounts({ profileId: null, status: 'idle', items: [] }); return; }
    setClaudeAccounts(value => ({ profileId: accountProfileId, status: 'loading', items: changedProfile ? [] : value.items }));
    if (changedProfile) setNewSession(value => value && !value.manageAccount ? { ...value, accountId: 'default', accountName: '', error: '' } : value);
    api.call('listClaudeAccounts', { id: accountProfileId }).then(result => {
      if (cancelled || !mountedRef.current) return;
      if (!Array.isArray(result?.accounts)) throw new Error('无法读取登录档案，请重试。');
      setClaudeAccounts({ profileId: accountProfileId, status: 'ready', items: result.accounts });
      setNewSession(value => !value?.manageAccount && value?.kind === CLAUDE_SESSION && value.browserId === accountProfileId
        ? { ...value, accountId: reconcileClaudeAccountChoice(result.accounts, value.accountId) } : value);
    }).catch(error => {
      if (!cancelled && mountedRef.current) setClaudeAccounts({ profileId: accountProfileId, status: 'error', items: [], error: error.message || '无法读取登录档案，请重试。' });
    });
    return () => { cancelled = true; };
  }, [accountProfileId, desktopAvailable, accountsReload, accountSessionState]);
  useEffect(() => {
    let cancelled = false;
    if (!accountProfileId || !desktopAvailable || newSession?.manageAccount) { setClaudeInstallation({ profileId: null, status: 'idle', installed: false }); return; }
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
  }, [accountProfileId, desktopAvailable, installationReload, newSession?.manageAccount]);
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
    if (!host || newSession?.manageAccount || pending || accountMutationRef.current || accountEditor || !terminalDirectoryChoice(newSession).ready) return;
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
    const operation = (async () => {
      selectProfile(profileId); setFocusVersion(value => value + 1); setPending(`open:${profileId}`); clearFailure();
      const selectionRevision = selectionRevisionRef.current;
      if (requestId) openingRequestsRef.current.set(profileId, { requestId, selectionRevision, selected: false });
      try {
        await refresh();
        if (!mountedRef.current) return;
        const current = storeRef.current.snapshot().profiles.find(item => item.profileId === profileId);
        const source = current?.sessions.find(item => item.sessionId === activeSessionsRef.current[profileId] && item.status === 'running') ?? current?.sessions.find(item => item.status === 'running');
        const session = forceNew
          ? await api.call('openTerminal', { id: profileId, columns: 100, rows: 12, fresh: true, ...terminalSessionOptions(kind, browserProfileId, claudeAccountId), ...(claudeInstallSource ? { claudeInstallSource } : {}), ...(requestId ? { requestId } : {}), ...(directoryToken ? { directoryToken } : {}) })
          : source ? await api.call('duplicateTerminal', { sessionId: source.sessionId }) : await api.call('openTerminal', { id: profileId, columns: 100, rows: 12 });
        if (!session?.canceled && mountedRef.current) { acceptSession(session, { select: selectionRevision === selectionRevisionRef.current }); await refresh(); }
        return true;
      } catch (error) {
        if (requestId) setNewSession(value => value?.requestId === requestId ? { ...invalidatePickedTerminalDirectory(value), requestId: null, error: claudeErrorMessage(error.message, error.code) || '终端无法启动。', keychainDiagnostic: terminalKeychainDiagnosticText(error.keychainDiagnostic) } : value);
        reportError(claudeErrorMessage(error.message, error.code) || '终端无法启动。', error.code || (/^CLAUDE_CODE_[A-Z_]+$/.test(error.message) ? error.message : ''), error.keychainDiagnostic);
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
    try { acceptSession(await api.call('closeTerminal', { sessionId: session.sessionId }), { select: false }); await refresh(); }
    catch (error) { if (currentFailureRef.current?.sessionId !== session.sessionId) reportError(error.message || '终端会话尚未关闭。'); await refresh(); }
    finally { if (mountedRef.current) { if (!cancellingStart) setPending(''); setCancellingSessionId(null); } }
  };
  const duplicateSession = async session => {
    if (!desktopAvailable || !session || session.status !== 'running' || pending) return;
    const selectionRevision = selectionRevisionRef.current;
    // A snapshot may be showing the last tab without an explicit selection.
    // Keep that source stable while the new session joins the snapshot.
    setActiveSessions(value => ({ ...value, [session.profileId]: session.sessionId }));
    setPending(`duplicate:${session.sessionId}`); clearFailure();
    try {
      const created = await api.call('duplicateTerminal', { sessionId: session.sessionId });
      if (!created?.canceled && mountedRef.current) {
        const select = selectionRevision === selectionRevisionRef.current;
        acceptSession(created, { select });
        if (select) setFocusVersion(value => value + 1);
        await refresh();
      }
    } catch (error) { reportError(claudeErrorMessage(error.message, error.code) || '无法复制终端会话。', error.code, error.keychainDiagnostic); }
    finally { if (mountedRef.current) setPending(''); }
  };
  const actOnSavedEntry = async (entry, action, name) => {
    const profileId = activeProfileId;
    if (!desktopAvailable || !profileId || !entry?.id || pending || savedEntryActionRef.current) return;
    const scope = savedEntryScopeRef.current;
    const selectionRevision = selectionRevisionRef.current;
    const operation = { profileId, entryId: entry.id };
    const organization = ['pin', 'up', 'down'].includes(action);
    const trigger = organization ? document.activeElement : null;
    const inCurrentScope = () => mountedRef.current && savedEntryScopeRef.current === scope && scopeRef.current.profileIds.has(profileId);
    savedEntryActionRef.current = operation;
    setPending(`saved-${action}:${entry.id}`); clearFailure();
    try {
      const args = { id: profileId, entryId: entry.id };
      if (action === 'open') {
        const session = await api.call('reopenSavedTerminal', { ...args, requestId: crypto.randomUUID() });
        if (inCurrentScope() && !session?.canceled) {
          const select = selectionRevision === selectionRevisionRef.current;
          acceptSession(session, { select }); setNewSession(null); setContextOpen(false);
          setSavedEntriesOpen(value => ({ ...value, [profileId]: false }));
          if (select) setFocusVersion(value => value + 1);
        }
      } else if (action === 'pin') {
        await api.call('setSavedTerminalPinned', { ...args, pinned: entry.pinned !== true });
      } else if (action === 'up' || action === 'down') {
        await api.call('moveSavedTerminal', { ...args, direction: action });
      } else {
        await api.call(action === 'rename' ? 'renameSavedTerminal' : 'removeSavedTerminal', { ...args, ...(action === 'rename' ? { name: name.trim() } : {}) });
      }
      if (inCurrentScope()) setSavedEntryEditor(null);
      await refresh();
    } catch (error) {
      if (inCurrentScope()) reportError(savedTerminalErrors[error.code] || error.message || (action === 'open' ? '无法打开已保存终端，请重试。' : '无法更新已保存终端，请重试。'), error.code, error.keychainDiagnostic);
    } finally {
      if (savedEntryActionRef.current === operation) {
        savedEntryActionRef.current = null;
        if (organization && inCurrentScope()) savedEntryFocusRef.current = { scope, entryId: entry.id, action, trigger };
        if (mountedRef.current) setPending('');
      }
    }
  };
  useLayoutEffect(() => {
    // Snapshot publication is frame-batched. Restore focus only after its
    // reordered rows and newly disabled edge buttons have reached the DOM.
    if (pending || publishFrameRef.current != null || !savedEntryFocusRef.current) return;
    const { scope, entryId, action, trigger } = savedEntryFocusRef.current;
    savedEntryFocusRef.current = null;
    if (scope !== savedEntryScopeRef.current || (document.activeElement !== document.body && document.activeElement !== trigger)) return;
    const row = [...(dockRef.current?.querySelectorAll('.terminal-saved-terminals[open] [data-entry-id]') ?? [])].find(element => element.dataset.entryId === entryId);
    const target = row?.querySelector(`[data-saved-entry-action="${action}"]:not(:disabled)`) ?? row?.querySelector('.terminal-saved-open:not(:disabled)');
    target?.focus();
  }, [pending, terminalState, activeProfileId]);
  useEffect(() => {
    setSavedEntryEditor(null);
    setNewSession(value => value?.manageAccount && value.profileId !== activeProfileId ? null : value);
  }, [activeProfileId]);
  const openWindow = async (profileId, sessionId) => {
    if (!desktopAvailable || !profileId || pending || standalone) return;
    setPending('window'); clearFailure();
    try { await api.call('openTerminalWindow', { id: profileId, ...(sessionId ? { sessionId } : {}) }); }
    catch (error) { reportError(error.message || '无法打开独立终端窗口。'); }
    finally { if (mountedRef.current) setPending(''); }
  };

  const selectedProfile = profiles.find(profile => profile.id === activeProfileId);
  const selectedMetadata = terminalState.profiles.find(profile => profile.profileId === activeProfileId);
  const savedEntries = [...(selectedMetadata?.savedTerminals ?? [])].sort((a, b) => Number(b.pinned === true) - Number(a.pinned === true));
  const savedQuery = savedQueries[activeProfileId] ?? '';
  const entryEditor = savedEntryEditor?.profileId === activeProfileId ? savedEntryEditor : null;
  const sessions = liveSessions(selectedMetadata?.sessions);
  const selectedSession = sessions.find(session => session.sessionId === activeSessions[activeProfileId]) ?? sessions.at(-1) ?? null;
  const manageCurrentAccount = () => {
    if (!selectedSession?.claudeAccountId || selectedSession.kind !== CLAUDE_SESSION || pending) return;
    const name = terminalAccountName(selectedSession, t);
    setContextOpen(false); setSavedEntryEditor(null); setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: false }));
    setNewSession({ kind: CLAUDE_SESSION, manageAccount: true, profileId: activeProfileId, browserId: activeProfileId, accountId: selectedSession.claudeAccountId, error: '' });
    setAccountEditor({ profileId: activeProfileId, id: selectedSession.claudeAccountId, name: selectedSession.claudeAccountName || '', originalName: name, confirmDelete: false, error: '' });
  };
  const focusAccountSession = (profileId, accountId, session) => {
    if (pending || !terminalsForAccount(storeRef.current.snapshot().profiles, profileId, accountId).some(item => item.sessionId === session.sessionId)) return;
    setAccountEditor(null); setNewSession(null); setContextOpen(false); setSavedEntryEditor(null);
    setSavedEntriesOpen(value => ({ ...value, [profileId]: false }));
    selectProfile(profileId); selectSession(profileId, session.sessionId);
  };
  const savedMenuOpen = savedEntriesOpen[activeProfileId] ?? (!loading && !selectedSession && savedEntries.length > 0);
  const canCloseSelected = selectedSession && activeStatuses.has(selectedSession.status) && !cancellingSessionId && (!pending || (selectedSession.status === 'starting' && pending.startsWith('open:')));
  const sessionName = session => terminalSessionName(session, sessions, t);
  const sessionTitle = session => [sessionName(session), session.kind === CLAUDE_SESSION
    ? t('登录档案：{name}', { name: terminalAccountName(session, t) }) : null].filter(Boolean).join('\n');
  const sessionUnavailable = Boolean(activeSessions[activeProfileId] && !selectedSession && !loading);
  const hasLiveSession = sessions.length > 0;
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
      <div className="terminal-session-tabs" ref={sessionTabsRef} role="tablist" aria-label={t('终端会话')}>{sessions.map((session, index) => <button key={session.sessionId} ref={session.sessionId === selectedSession?.sessionId ? selectedSessionTabRef : undefined} className={`terminal-session-tab ${session.sessionId === selectedSession?.sessionId ? 'is-active' : ''}`} title={sessionTitle(session)} role="tab" aria-selected={session.sessionId === selectedSession?.sessionId} tabIndex={session.sessionId === selectedSession?.sessionId || (!selectedSession && index === 0) ? 0 : -1} onKeyDown={event => navigateTabs(event, sessions, index, target => selectSession(activeProfileId, target.sessionId))} onClick={() => selectSession(activeProfileId, session.sessionId)}><span className={`terminal-tab-dot ${session.status === 'running' ? 'is-running' : ''}`} /><span className="terminal-session-name">{sessionName(session, index)}</span>{session.status !== 'running' && <small>{t(statusLabels[session.status] || session.status)}</small>}</button>)}</div>
      <div className="terminal-toolbar-actions">
        <TerminalToolbarHint enabled={shown} label={t('复制会话')} description={t('使用相同登录档案和环境配置，新建独立终端。')}><button type="button" className="terminal-text-button terminal-duplicate-session" disabled={!desktopAvailable || selectedSession?.status !== 'running' || !!pending} aria-label={t('复制会话')} aria-busy={pending.startsWith('duplicate:') || undefined} onClick={() => { setContextOpen(false); setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: false })); setSavedEntryEditor(null); setNewSession(null); void duplicateSession(selectedSession); }}><Copy size={16} /><span>{t(pending.startsWith('duplicate:') ? '复制中…' : '复制会话')}</span></button></TerminalToolbarHint>
        {selectedProfile && <TerminalSavedMenu t={t} shown={shown} savedMenuOpen={savedMenuOpen}
          savedEntries={savedEntries} savedQuery={savedQuery} entryEditor={entryEditor} activeProfileId={activeProfileId}
          desktopAvailable={desktopAvailable} pending={pending} setSavedEntryEditor={setSavedEntryEditor} actOnSavedEntry={actOnSavedEntry}
          onQueryChange={query => setSavedQueries(value => ({ ...value, [activeProfileId]: query }))}
          onToggle={event => {
            event.preventDefault();
            const open = !savedMenuOpen;
            if (open) { setContextOpen(false); setNewSession(null); }
            setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: open }));
            if (!open) setSavedEntryEditor(null);
          }} />}
        <TerminalToolbarHint enabled={shown} label={t('新建会话')} description={t('选择网络、浏览器和工作目录。')}><button className="terminal-icon-button" disabled={!desktopAvailable || !selectedProfile || !!pending} onClick={openNewSessionChooser} aria-label={t('新建会话')} title={t('新建会话')}><Plus size={17} /></button></TerminalToolbarHint>
        <TerminalSessionContext t={t} shown={shown} contextOpen={contextOpen} selectedSession={selectedSession}
          selectedProfile={selectedProfile} selectedMetadata={selectedMetadata} activeProfileId={activeProfileId}
          hasLiveSession={hasLiveSession} networkDescription={networkDescription} pending={pending}
          manageCurrentAccount={manageCurrentAccount} onConfigureLinkBrowser={onConfigureLinkBrowser} onExport={onExport} exportDisabled={exportDisabled}
          onDismiss={() => setContextOpen(false)}
          onToggle={event => { event.preventDefault(); setContextOpen(value => !value); setSavedEntriesOpen(value => ({ ...value, [activeProfileId]: false })); setSavedEntryEditor(null); setNewSession(null); }} />
        {!standalone && <>
          <TerminalToolbarHint enabled={shown} label={t('独立终端窗口')} description={t('在独立窗口中查看此环境的终端')}><button className="terminal-icon-button" disabled={!desktopAvailable || !selectedProfile || !!pending} onClick={() => void openWindow(activeProfileId, selectedSession?.sessionId)} aria-label={t('独立终端窗口')} title={t('在独立窗口中查看此环境的终端')}><ArrowSquareOut size={17} /></button></TerminalToolbarHint>
          {!workspace && <TerminalToolbarHint enabled={shown} label={t(expanded ? '还原终端大小' : '放大终端')}><button className="terminal-icon-button" disabled={!onToggleExpanded} onClick={onToggleExpanded} aria-label={t(expanded ? '还原终端大小' : '放大终端')} title={t(expanded ? '还原终端大小' : '放大终端')}>{expanded ? <ArrowsInSimple size={17} /> : <ArrowsOutSimple size={17} />}</button></TerminalToolbarHint>}
          <TerminalToolbarHint enabled={shown} label={t('收起终端')} description={t('收起终端，会话继续运行')}><button className="terminal-icon-button" onClick={onHide} aria-label={t('收起终端')} title={t('收起终端，会话继续运行')}><CaretDown size={17} /></button></TerminalToolbarHint>
        </>}
        <TerminalToolbarHint enabled={shown} label={t(selectedSession?.status === 'starting' && selectedSession?.kind === CLAUDE_SESSION ? '取消安装' : '结束会话')} description={selectedSession?.status === 'starting' && selectedSession?.kind === CLAUDE_SESSION ? undefined : t('结束当前会话，已保存的终端入口会保留。')}><button className="terminal-icon-button terminal-close-session" disabled={!canCloseSelected} onClick={() => void closeSession(selectedSession)} aria-label={t(selectedSession?.status === 'starting' && selectedSession?.kind === CLAUDE_SESSION ? '取消安装' : '关闭会话')} title={t('关闭当前终端会话')}><X size={17} /></button></TerminalToolbarHint>
      </div>
    </header>
    <div id="terminal-environment-panel" className="terminal-environment-panel" aria-label={t('{name}终端工作区', { name: selectedProfile?.name || t('环境') })}>
      <div className="terminal-content">
        {allSessions.map(session => <TerminalSession key={session.sessionId} session={session} active={session.sessionId === selectedSession?.sessionId && session.profileId === activeProfileId} visible={shown} autoFocus={!contextOpen && !savedMenuOpen && !entryEditor && !newSession} focusRequest={`${openRequest?.profileId === session.profileId ? `${openRequest.nonce}:${openRequest.sessionId || ''}` : ''}:${focusVersion}`} preserveTabFocusRef={preserveTabFocusRef} register={register} onError={reportError} screenReaderMode={screenReaderMode} />)}
        {!selectedSession && <div className="terminal-empty"><TerminalWindow size={25} /><div><strong>{t(!desktopAvailable ? '真实终端需使用桌面应用' : !selectedProfile ? '先创建一个环境' : loading ? '正在读取终端会话…' : sessionUnavailable ? '该会话已不可用' : '打开此环境的终端')}</strong>{(!desktopAvailable || sessionUnavailable) && <p>{t(!desktopAvailable ? '网页预览不连接本机 Shell。' : '可选择其他会话或新建会话。')}</p>}</div>{desktopAvailable && selectedProfile && <button className="terminal-empty-start" disabled={!!pending || loading} onClick={openNewSessionChooser}>{t(pending.startsWith('open:') ? '启动中…' : sessionUnavailable ? '新建会话' : '打开终端')}</button>}</div>}
      </div>
      {newSession && <TerminalSessionChooser t={t} systemPlatform={systemPlatform} newSession={newSession} setNewSession={setNewSession}
        networks={networks} activeProfileId={activeProfileId} host={chooserHost(newSession)} directoryFor={directoryFor} defaultBrowser={defaultBrowser}
        terminalProfiles={terminalState.profiles} claudeAccounts={claudeAccounts} claudeInstallation={claudeInstallation}
        accountEditor={accountEditor} setAccountEditor={setAccountEditor} pending={pending} cancellingSessionId={cancellingSessionId}
        setAccountsReload={setAccountsReload} setInstallationReload={setInstallationReload} createChosenAccount={createChosenAccount}
        mutateAccount={mutateAccount} chooseNewSessionDirectory={chooseNewSessionDirectory} confirmNewSession={confirmNewSession}
        closeSession={closeSession} onFocusAccountSession={focusAccountSession} />}
      <footer className={`terminal-footer ${dockError ? 'has-error' : ''}`}><div className="terminal-footer-messages" role={dockError ? 'status' : undefined}><span className="terminal-network-description" title={dockError ? t(dockError) : networkDescription}>{dockError ? t(dockError) : <><GlobeHemisphereWest size={12} /><span>{shownNetwork?.routeName || (shownNetwork?.mode === 'direct' ? t('本机网络') : shownNetwork?.mode && shownNetwork.mode !== 'unknown' ? String(shownNetwork.mode).toUpperCase() : t('启动后读取环境网络设置。'))}</span></>}</span>{!dockError && <TerminalKeychainNotice session={selectedSession} t={t} />}{dockError && dockCleanupError && <span className="terminal-cleanup-error" title={t(dockCleanupError)}>{t('清理错误')} · {t(dockCleanupError)}</span>}</div>{dockError && dockErrorCode && <code className="terminal-error-code" title={[dockErrorCode, dockKeychainDiagnostic].filter(Boolean).join(' · ')}>{dockErrorCode}{dockKeychainDiagnostic && <span className="terminal-keychain-diagnostic">{dockKeychainDiagnostic}</span>}</code>}{standalone && <span className="terminal-view-notice">{t('关闭窗口后，会话继续运行。')}</span>}{selectedSession && <span className="terminal-session-state">{t(statusLabels[selectedSession.status] || selectedSession.status)}{selectedSession.exitCode != null && t(' · 退出码 {code}', { code: selectedSession.exitCode })}</span>}</footer>
    </div>
  </section>;
}
