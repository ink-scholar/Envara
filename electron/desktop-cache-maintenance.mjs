import { createCacheMaintenance } from './cache-maintenance.mjs';

const fail = code => Object.assign(new Error('缓存维护未完成，请刷新后重试。'), { code });
const identifier = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
const active = new Set(['starting', 'running', 'closing', 'stopping']);

/** Owns the browser-manager reservation as well as the desktop transfer gate.
 * Inspection never reserves, starts, stops or repairs any browser session.
 */
export function createDesktopCacheMaintenance({ dataDir, service, terminal, applications, transferLock,
  factory = createCacheMaintenance } = {}) {
  const supported = typeof service?.remote === 'function' && typeof service?.request === 'function' && !!service.profilesDir;
  let closed = false;
  const pending = new Set();
  const assertOpen = () => { if (closed || service?.closed) throw fail('APP_CLOSING'); };
  const assertProfileIdle = async id => {
    assertOpen();
    if (!identifier(id) || !supported || service.installingEngine || service.starting?.has(id)) throw fail('CACHE_PROFILE_BUSY');
    // Do not use assertStopped: it may remove a stale session. Unknown sessions
    // remain busy even if a health probe elsewhere has failed.
    const remote = await service.remote();
    if (!remote.profiles.some(profile => profile.id === id) || remote.sessions.some(session => session.profile_id === id)) throw fail('CACHE_PROFILE_BUSY');
    if ([...(terminal?.sessions?.values() ?? [])].some(session => session.profileId === id &&
      (!session.finished || active.has(session.status) || session.cleanupError))) throw fail('CACHE_PROFILE_BUSY');
    applications?.assertProfileIdle?.(id);
    const trial = applications?.routing?.controlledNotionTrialSnapshot?.();
    if (trial?.active || trial?.cleanupUncertain) {
      const application = applications?.applications?.get(trial.applicationId);
      if (!application || application.profileId === id) throw fail('CACHE_PROFILE_BUSY');
    }
    assertOpen();
  };
  const withMaintenance = supported ? (ids, operation) => transferLock.transfer(async () => {
    assertOpen();
    for (const id of ids) await assertProfileIdle(id);
    const lease = await service.request('POST', '/api/maintenance/acquire', { profile_ids: ids });
    const token = lease?.data?.token;
    if (!/^[a-f0-9]{64}$/.test(token ?? '')) throw fail('CACHE_MAINTENANCE_UNAVAILABLE');
    let result, firstError;
    try {
      assertOpen();
      for (const id of ids) await assertProfileIdle(id);
      result = await operation();
    } catch (error) { firstError = error; }
    try {
      const release = await service.request('POST', '/api/maintenance/release', { token });
      if (release?.data?.released !== true) throw fail('CACHE_MAINTENANCE_RELEASE_FAILED');
    } catch {
      // A failed release never grants new launch authority. The sidecar retains
      // the reservation; keep the first operation error when there was one.
      if (!firstError) firstError = fail('CACHE_MAINTENANCE_RELEASE_FAILED');
    }
    if (firstError) throw firstError;
    return result;
  }, ids.length === 1 ? ids[0] : null) : undefined;
  const maintenance = factory({ dataDir, profilesRoot: service?.profilesDir, layout: supported ? 'browseforge' : 'legacy',
    listProfiles: async () => {
      assertOpen();
      return supported ? (await service.remote()).profiles.map(({ id, name }) => ({ id, name }))
        : (await service.store.read()).profiles.map(({ id, name }) => ({ id, name }));
    }, assertProfileIdle, withMaintenance });
  const run = (method, args) => {
    assertOpen();
    const operation = Promise.resolve().then(() => { assertOpen(); return maintenance[method](args); });
    pending.add(operation);
    operation.then(() => pending.delete(operation), () => pending.delete(operation));
    return operation;
  };
  return {
    get pendingCount() { return pending.size; },
    inventory: args => run('inventory', args), quarantine: args => run('quarantine', args),
    restore: args => run('restore', args), purge: args => run('purge', args),
    async close() { closed = true; await Promise.allSettled([...pending]); },
  };
}
