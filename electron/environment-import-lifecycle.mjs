// The decrypted staging directory remains the retry source until every section
// has been restored. An import owns at most the profile ids its backend created.
const fail = (message, code) => Object.assign(new Error(message), { code });
const publicFailureCodes = new Set(['IMPORT_TARGET_NOT_EMPTY', 'IMPORT_TARGET_UNSAFE', 'IMPORT_RESTORE_FAILED',
  'IMPORT_TARGET_INVALID', 'EXPORT_FORMAT_INVALID', 'CLAUDE_ACCOUNT_INVALID', 'CLAUDE_ACCOUNT_NAME_EXISTS']);

const dataMutations = new Set(['createProfile', 'updateProfile', 'cloneProfile', 'deleteProfile', 'clearProfile', 'startProfile',
  'saveProxy', 'deleteProxy', 'saveGroup', 'deleteGroup', 'clearGroupProxy', 'bulkProfiles', 'migrateLegacy', 'saveSettings', 'installEngine',
  'chooseWorkspaceDirectory', 'setTerminalLinkBrowser', 'openTerminal', 'duplicateTerminal', 'writeTerminal', 'createClaudeAccount',
  'renameClaudeAccount', 'deleteClaudeAccount', 'saveApplication', 'startApplication', 'runNotionTrial', 'deleteApplication', 'clearApplicationData',
  'deleteSignInData', 'setApplicationLinkBrowser', 'setupApplicationRouting', 'reclaimApplicationStorage',
  'saveTerminalSshConnection', 'setTerminalSshPassword', 'removeTerminalSshConnection']);

export function isEnvironmentDataMutation(method, args = {}) {
  return dataMutations.has(method) && !(method === 'bulkProfiles' && args?.action === 'stop');
}

/** A desktop IPC reservation only. Existing external processes, sidecar REST
 * and MCP callers do not pass through this gate and are not fenced by it.
 * Refuse rather than queue: an application launch can live until it is stopped,
 * so waiting for every launch promise here could otherwise deadlock export. */
export class DesktopEnvironmentTransferLock {
  constructor() { this.transferring = false; this.mutations = 0; this.scopes = new Map(); this.transferProfile = null; }
  busy() { return fail('环境正在导入、导出或修改，请等待完成后重试。', 'ENVIRONMENT_TRANSFER_BUSY'); }
  async mutate(method, args, operation, profileId = null) {
    if (!isEnvironmentDataMutation(method, args)) return operation();
    if (this.transferring && (!this.transferProfile || !profileId || this.transferProfile === profileId)) throw this.busy();
    this.mutations++;
    this.scopes.set(profileId, (this.scopes.get(profileId) ?? 0) + 1);
    try { return await operation(); }
    finally {
      this.mutations--;
      const remaining = this.scopes.get(profileId) - 1;
      if (remaining) this.scopes.set(profileId, remaining); else this.scopes.delete(profileId);
    }
  }
  async transfer(operation, profileId = null) {
    if (this.transferring || (!profileId ? this.mutations : this.scopes.has(null) || this.scopes.has(profileId))) throw this.busy();
    this.transferring = true; this.transferProfile = profileId;
    try { return await operation(); }
    finally { this.transferring = false; this.transferProfile = null; }
  }
}

/** Derive the affected environment from main-owned metadata, not a second
 * profile id supplied alongside an application/session id by the renderer. */
export function environmentMutationProfile(method, args = {}, { applications, terminal } = {}) {
  if (['createProfile', 'cloneProfile', 'saveProxy', 'deleteProxy', 'saveGroup', 'deleteGroup', 'clearGroupProxy', 'bulkProfiles',
    'migrateLegacy', 'saveSettings', 'installEngine', 'deleteSignInData', 'reclaimApplicationStorage', 'setupApplicationRouting'].includes(method)) return null;
  if (method === 'saveApplication') return args.application?.profileId ?? null;
  if (['startApplication', 'deleteApplication', 'clearApplicationData', 'setApplicationLinkBrowser', 'runNotionTrial'].includes(method))
    return applications?.applications?.get(method === 'runNotionTrial' ? args.applicationId ?? args.id : args.id)?.profileId ?? null;
  if (['duplicateTerminal', 'writeTerminal'].includes(method)) return terminal?.sessions?.get(args.sessionId)?.profileId ?? null;
  return typeof args.id === 'string' ? args.id : null;
}

export function assertImportNotBusy(pending) {
  if (pending?.busy || pending?.disposing) throw fail('环境正在导入，请等待完成后重试或取消。', 'IMPORT_BUSY');
}

/** Main calls only after an explicit, successful deletion and consumer cleanup.
 * Forget that exact retained destination, never the decrypted retry source. */
export function releaseDeletedEnvironmentImportProfile({ imports, profileId }) {
  if (typeof profileId !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(profileId)) throw fail('导入环境标识无效。', 'IMPORT_TARGET_INVALID');
  const matching = [...imports.values()].filter(pending => Array.isArray(pending?.createdResult?.actionResult?.createdIds)
    && pending.createdResult.actionResult.createdIds.includes(profileId));
  // Validate the complete matching set before changing any pending record.
  for (const pending of matching) {
    assertImportNotBusy(pending);
    const ids = pending.createdResult.actionResult.createdIds;
    if (ids.length !== 1 || ids[0] !== profileId || pending.restoredResult)
      throw fail('导入结果不完整，原始导入资料已保留。', 'IMPORT_RESULT_INVALID');
  }
  for (const pending of matching) delete pending.createdResult;
  return { released: matching.length };
}

export async function withPendingEnvironmentImport(pending, operation) {
  assertImportNotBusy(pending);
  pending.busy = true;
  try { return await operation(); }
  finally { pending.busy = false; }
}

// Successful completion may dispose its own staging while still holding the
// import lock. User cancellation and expiry never have that permission.
export async function discardPendingEnvironmentImport({ imports, importId, removeStaging, completed = false }) {
  const pending = imports.get(importId);
  if (pending?.disposing) throw fail('环境正在导入，请等待完成后重试或取消。', 'IMPORT_BUSY');
  if (!completed) assertImportNotBusy(pending);
  // If deleting a newly created profile failed, retain its retry record; silently
  // forgetting it would leave a partial environment that cannot be recovered.
  if (!completed && pending?.createdResult) throw fail('新环境尚未完成回滚，请先重试导入。', 'IMPORT_ROLLBACK_INCOMPLETE');
  if (pending) pending.disposing = true;
  try {
    if (pending?.bundle?.staging) await removeStaging(pending.bundle.staging);
    imports.delete(importId);
  } finally { if (pending) pending.disposing = false; }
}

export async function expirePendingEnvironmentImports({ imports, discard, now = Date.now(), lifetime = 15 * 60 * 1000 }) {
  for (const [id, item] of imports) {
    if (!item.busy && !item.disposing && !item.createdResult && now - item.createdAt > lifetime) await discard(id);
  }
}

export async function makePendingImportRoom({ imports, discard, limit = 3 }) {
  if (imports.size < limit) return;
  const idle = [...imports].find(([, item]) => !item.busy && !item.disposing && !item.createdResult);
  if (!idle) throw fail('其他环境正在导入，请先完成或取消后重试。', 'IMPORT_BUSY');
  await discard(idle[0]);
}

const pendingRegistrations = new WeakMap();

/** Capacity check, optional idle eviction and insertion form one reservation.
 * The queue ends after insertion; password/mapping input and restoration never
 * hold it. removeStaging owns only a new, unregistered bundle on failure. */
export function registerPendingEnvironmentImport({ imports, importId, pending, discard, removeStaging, limit = 3 }) {
  if (!(imports instanceof Map) || typeof importId !== 'string' || !importId || !pending || typeof pending !== 'object' ||
      !Number.isSafeInteger(limit) || limit < 1 || typeof discard !== 'function' ||
      pending.bundle?.staging && typeof removeStaging !== 'function')
    return Promise.reject(fail('待导入资料无法安全登记。', 'IMPORT_RESULT_INVALID'));
  const operation = (pendingRegistrations.get(imports) ?? Promise.resolve()).catch(() => {}).then(async () => {
    try {
      if (imports.has(importId)) throw fail('待导入资料已登记，请继续原来的导入。', 'IMPORT_BUSY');
      await makePendingImportRoom({ imports, discard, limit });
      if (imports.size >= limit) throw fail('其他环境正在导入，请先完成或取消后重试。', 'IMPORT_BUSY');
      imports.set(importId, pending);
    } catch (error) {
      const staging = pending.bundle?.staging;
      if (staging && ![...imports.values()].some(item => item?.bundle?.staging === staging)) {
        try { await removeStaging(staging); }
        catch { throw fail('本次导入未登记，临时资料尚未清理，请重试清理。', 'IMPORT_STAGING_CLEANUP_FAILED'); }
      }
      throw error;
    }
  });
  pendingRegistrations.set(imports, operation);
  operation.finally(() => { if (pendingRegistrations.get(imports) === operation) pendingRegistrations.delete(imports); }).catch(() => {});
  return operation;
}

/** Caller holds withPendingEnvironmentImport across decryption, proxy mapping,
 * creation, restoration and disposal. The restore function leaves staging intact
 * and rolls back its own filesystem changes on failure. */
export async function finishPendingEnvironmentImport({ pending, service, proxyMap = {}, restore, discard }) {
  if (pending.restoredResult) { await discard(); return pending.restoredResult; }
  const createdThisAttempt = !pending.createdResult;
  const result = pending.createdResult ?? await service.call('importProfiles', { document: pending.document, proxyMap });
  if (!pending.bundle) { pending.restoredResult = result; await discard(); return result; }
  const ids = result?.actionResult?.createdIds;
  if (!Array.isArray(ids) || ids.length !== 1 || typeof ids[0] !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(ids[0]))
    throw fail('导入结果不完整，原始导入资料已保留。', 'IMPORT_RESULT_INVALID');
  pending.createdResult = result;
  let restored;
  try { restored = await restore(ids[0]); }
  catch (error) {
    // A profile retained after a failed earlier rollback is visible to users
    // and external callers between requests. Its new data is no longer ours
    // to delete automatically, even when the next restore refuses a conflict.
    // Even in this request, a nonempty/unsafe target proves another writer or
    // changed directory may now own data there. Do not erase it indirectly via
    // deleteProfile after restore itself has carefully refused to overwrite it.
    if (!createdThisAttempt || ['IMPORT_TARGET_NOT_EMPTY', 'IMPORT_TARGET_UNSAFE'].includes(error?.code))
      throw fail('环境资料未恢复。目标环境及原始导入资料均已保留，未自动删除；请检查目标资料后重试，或明确删除该环境后重新导入。', 'IMPORT_ROLLBACK_INCOMPLETE');
    let rollbackFailed = false;
    for (const id of ids) {
      try { await service.call('deleteProfile', { id }); }
      catch { rollbackFailed = true; }
    }
    if (!rollbackFailed) delete pending.createdResult;
    // Never surface a raw filesystem path, token, or provider response here.
    throw fail(rollbackFailed
      ? '环境资料未恢复，且新环境未完成回滚。原始导入资料已保留，请重试导入。'
      : '环境资料未恢复，新建环境已回滚。原始导入资料已保留，可重试或取消。',
    rollbackFailed ? 'IMPORT_ROLLBACK_INCOMPLETE' : publicFailureCodes.has(error?.code) ? error.code : 'IMPORT_RESTORE_FAILED');
  }
  pending.restoredResult = { ...result, restored };
  delete pending.createdResult;
  await discard();
  return pending.restoredResult;
}
