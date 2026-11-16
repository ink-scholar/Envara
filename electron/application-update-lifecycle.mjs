const active = new Set(['starting', 'running', 'closing', 'stopping']);
const values = collection => collection instanceof Map ? [...collection.values()] : [];
const size = collection => collection instanceof Map || collection instanceof Set ? collection.size : 0;
const failure = (code, restartRequired = false, blockers = []) => Object.assign(new Error(code === 'APP_UPDATE_BUSY'
  ? '请先结束活动会话并等待当前操作完成，再安装更新。'
  : code === 'APP_UPDATE_INSTALL_FAILED' ? '更新安装未完成，当前配置和登录资料已保留。'
    : '更新前的退出尚未确认，未替换应用。请退出后重试。'), { code, restartRequired, blockers });

function localBlockers(resources, ownsTransfer = false, afterShutdown = false) {
  const { service, terminal, applications, transferLock, sidecar, terminalController,
    terminalBrowserBroker, cacheMaintenance, workCombinations, pendingImports } = resources;
  const blockers = [];
  const add = (code, count) => { if (count) blockers.push({ code, count: Number.isSafeInteger(count) && count > 0 ? count : 1 }); };
  add('not-ready', !service || typeof service.remote !== 'function' || typeof service.request !== 'function'
    || !terminal || !applications || !sidecar || !transferLock || typeof transferLock.transfer !== 'function'
    || !afterShutdown && (service.closed || terminal.closed || applications.closed || sidecar.closed || !sidecar.process));
  add('terminals', values(terminal?.sessions).filter(session => !session.finished || active.has(session.status) || session.cleanupError).length);
  add('applications', values(applications?.sessions).filter(session => active.has(session.status) || session.sessionId || session.routeId || session.cleanupUncertain).length);
  const trial = applications?.routing?.controlledNotionTrialSnapshot?.();
  add('application-trial', resources.notionTrialReserved || trial?.active || trial?.cleanupUncertain);
  add('terminal-operations', size(terminal?.profileQueues) + size(terminal?.pendingClaudeStarts) + size(terminal?.deletingClaudeAccounts) + (terminalController?.pendingCount ?? 0));
  add('browser-operations', size(service?.starting) + size(service?.profileQueues) + (service?.networkRecovery ? 1 : 0));
  add('installations', (service?.installingEngine ? 1 : 0) + size(sidecar?.installations) + size(sidecar?.commands));
  add('attachments', size(terminalController?.attachments?.transfers));
  add('browser-broker', size(terminalBrowserBroker?.sessions) + size(terminalBrowserBroker?.pending));
  add('cache-maintenance', cacheMaintenance?.pendingCount ?? 0);
  add('work-combinations', values(workCombinations?.requests).filter(request => request.completed !== true).length);
  // Even an idle import may hold plaintext retry data and an unfinished user
  // choice. Updating must not silently discard its in-memory continuation.
  add('imports', size(pendingImports));
  add('transfers', (!ownsTransfer && transferLock?.transferring ? 1 : 0) + (transferLock?.mutations ?? 0));
  add('other-operations', resources.extraBusy);
  return blockers;
}

/** Admission only: never ends user sessions, clears data or chooses a package.
 * Main arms its installer first, acknowledges IPC, then schedules install().
 * beginClosing must synchronously close desktop admission and advance its epoch.
 * The backend lease closes REST/MCP admission atomically while still idle.
 */
export function createApplicationUpdateLifecycle({ getResources, beginClosing, restoreOpen, shutdown,
  authorizeInstall, quit, onPhaseChange = () => {} }) {
  if (![getResources, beginClosing, restoreOpen, shutdown, authorizeInstall, quit, onPhaseChange].every(value => typeof value === 'function')) throw new TypeError('Invalid application update lifecycle callbacks.');
  let phase = 'idle', pending = null;
  const transition = (next, detail = {}) => {
    phase = next;
    try { onPhaseChange({ phase, ...detail }); } catch { /* display never grants install authority */ }
  };
  const inspect = async (resources, ownsTransfer = false) => {
    let blockers = localBlockers(resources, ownsTransfer);
    if (blockers.length) return blockers;
    try {
      const remote = await resources.service.remote();
      if (!Array.isArray(remote?.sessions)) return [{ code: 'browser-state-unavailable', count: 1 }];
      if (remote.sessions.length) blockers.push({ code: 'browsers', count: remote.sessions.length });
    } catch { blockers.push({ code: 'browser-state-unavailable', count: 1 }); }
    // Catch desktop work admitted just before beginClosing or during read-only
    // status. install() also holds the transfer gate across every await.
    const current = getResources();
    if (['service', 'terminal', 'applications', 'sidecar', 'transferLock'].some(key => current[key] !== resources[key])) blockers.push({ code: 'workspace-changed', count: 1 });
    blockers = [...blockers, ...localBlockers(current, ownsTransfer)];
    return blockers;
  };
  return {
    get phase() { return phase; },
    async readiness() {
      if (phase !== 'idle') return { ready: false, phase, blockers: [{ code: phase === 'blocked' ? 'restart-required' : 'update-in-progress', count: 1 }] };
      const blockers = await inspect({ ...getResources() });
      return { ready: phase === 'idle' && !blockers.length, phase, blockers };
    },
    install() {
      if (pending) return pending;
      if (phase !== 'idle') return Promise.reject(failure('APP_UPDATE_CLEANUP', true));
      const resources = { ...getResources() };
      const initial = localBlockers(resources);
      if (initial.length) return Promise.reject(failure('APP_UPDATE_BUSY', false, initial));
      let lease = null, acquiring = false, shutdownStarted = false, committing = false;
      transition('admitting');
      // No await before admission closes: no renderer may enqueue a launch
      // between the user selecting Install and the first backend check.
      try { beginClosing(); } catch { transition('blocked', { code: 'APP_UPDATE_CLEANUP', restartRequired: true }); return Promise.reject(failure('APP_UPDATE_CLEANUP', true)); }
      pending = Promise.resolve().then(() => resources.transferLock.transfer(async () => {
        const blockers = await inspect(resources, true);
        if (blockers.length) throw failure('APP_UPDATE_BUSY', false, blockers);
        acquiring = true;
        let reply;
        try { reply = await resources.service.request('POST', '/api/maintenance/update-acquire', {}); }
        catch (error) {
          // A definite refusal granted no lease. A timeout or malformed reply
          // may have acquired one; keep admission closed instead of guessing.
          if (['UPDATE_MAINTENANCE_BUSY', 'UPDATE_MAINTENANCE_INVALID'].includes(error?.code)) { acquiring = false; throw failure('APP_UPDATE_BUSY'); }
          throw failure('APP_UPDATE_CLEANUP', true);
        }
        if (!/^[a-f0-9]{64}$/.test(reply?.data?.token ?? '')) throw failure('APP_UPDATE_CLEANUP', true);
        lease = reply.data.token; acquiring = false;
        const finalBlockers = await inspect(resources, true);
        if (finalBlockers.length) throw failure('APP_UPDATE_BUSY', false, finalBlockers);
        shutdownStarted = true; transition('shutting-down');
        await shutdown({ strict: true });
        const current = getResources();
        const remaining = localBlockers(current, true, true);
        if (['service', 'terminal', 'applications', 'sidecar', 'transferLock'].some(key => current[key] !== resources[key])) remaining.push({ code: 'workspace-changed', count: 1 });
        if (remaining.length || resources.sidecar.process || !resources.sidecar.closed || !resources.service.closed
          || !resources.terminal.closed || !resources.applications.closed) throw failure('APP_UPDATE_CLEANUP', true, remaining);
        // The lease dies with the confirmed sidecar process. Do not reopen
        // admission while the main process is still about to be replaced.
        lease = null;
        committing = true; await authorizeInstall(); transition('authorized');
        await quit();
        return { accepted: true };
      })).catch(async error => {
        let restartRequired = shutdownStarted || acquiring || error?.restartRequired === true;
        if (!shutdownStarted && lease) {
          try {
            const released = await resources.service.request('POST', '/api/maintenance/update-release', { token: lease });
            if (released?.data?.released !== true) throw new Error('release not confirmed');
            lease = null;
          } catch { restartRequired = true; }
        }
        const code = committing ? 'APP_UPDATE_INSTALL_FAILED' : restartRequired ? 'APP_UPDATE_CLEANUP' : 'APP_UPDATE_BUSY';
        const safe = failure(code, restartRequired, Array.isArray(error?.blockers) ? error.blockers : []);
        if (restartRequired) transition('blocked', { code, restartRequired: true });
        else {
          try { restoreOpen(); transition('idle', { code, restartRequired: false }); }
          catch { transition('blocked', { code: 'APP_UPDATE_CLEANUP', restartRequired: true }); throw failure('APP_UPDATE_CLEANUP', true); }
        }
        throw safe;
      }).finally(() => { pending = null; });
      return pending;
    },
  };
}
