const phases = new Set(['idle', 'verifying', 'authorizing', 'preparing', 'staged', 'resuming', 'running', 'stopping', 'cleaned', 'failed', 'cleanup-required']);
const token = value => typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,95}$/.test(value) ? value : null;

const failureStages = new Set([...phases, 'prepare', 'register', 'inspect', 'lock', 'baseline', 'registry-lock', 'root-hook', 'group', 'group-allocation', 'context', 'sealed-context', 'pf-reference', 'transport', 'cold-stage', 'resume', 'cleanup']);
const nativeStages = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn', 'front-handshake', 'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const registerReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const operationReasons = new Set(['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED', 'NATIVE_ORIGINAL_SOCKET_REFUSED', 'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED', 'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED', 'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED', 'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED', 'NATIVE_TICKET_BINDING_REFUSED', 'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED', 'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED', 'NATIVE_NOTION_SUPPORTED_ARGUMENT_REFUSED', 'NATIVE_NOTION_SUPPORTED_PLIST_REFUSED', 'NATIVE_NOTION_SUPPORTED_VERSION_REFUSED', 'NATIVE_NOTION_SUPPORTED_SIGNATURE_REFUSED', 'NATIVE_NOTION_PLAN_ARGUMENT_REFUSED', 'NATIVE_NOTION_PLAN_REGISTRY_REFUSED', 'NATIVE_NOTION_PLAN_CONTEXT_REFUSED', 'NATIVE_NOTION_PLAN_REQUEST_REFUSED', 'NATIVE_NOTION_PLAN_SEALED_REFUSED', 'NATIVE_NOTION_PLAN_SUPPORTED_REFUSED', 'NATIVE_NOTION_PLAN_DIGEST_REFUSED', 'NATIVE_NOTION_PLAN_CDHASH_REFUSED', 'NATIVE_NOTION_PLAN_REQUIREMENT_REFUSED', 'NATIVE_NOTION_PLAN_DATA_REFUSED', 'NATIVE_NOTION_PLAN_ALLOCATION_REFUSED', 'NATIVE_NOTION_DATA_ARGUMENT_REFUSED', 'NATIVE_NOTION_DATA_ENTRY_REFUSED', 'NATIVE_NOTION_DATA_ANCESTOR_REFUSED', 'NATIVE_NOTION_DATA_LEAF_REFUSED', 'NATIVE_NOTION_DATA_DENY_REFUSED', 'NATIVE_NOTION_STAGE_ARGUMENT_REFUSED', 'NATIVE_NOTION_STAGE_AUTHORITY_REFUSED', 'NATIVE_NOTION_STAGE_ENTRY_REFUSED', 'NATIVE_NOTION_STAGE_SESSION_REFUSED', 'NATIVE_NOTION_STAGE_ORIGINAL_RUNNING_REFUSED', 'NATIVE_NOTION_STAGE_ACCOUNT_REFUSED', 'NATIVE_NOTION_STAGE_ENVIRONMENT_REFUSED', 'NATIVE_NOTION_STAGE_DATA_REFUSED', 'NATIVE_NOTION_STAGE_RECHECK_REFUSED', 'NATIVE_NOTION_STAGE_SPAWN_REFUSED', 'NATIVE_NOTION_STAGE_STOPPED_REFUSED', 'NATIVE_NOTION_STAGE_CHILD_REFUSED']);
const codes = new Set(['PF_INSTALLED_CANDIDATE_MISMATCH', 'PF_NOTION_CARRIER_MISMATCH', 'PF_NOTION_SIGNATURE_REFUSED', 'PF_OWNED_RUNTIME_NOT_EMPTY', 'PF_NOTION_TRIAL_BUSY', 'PF_NOTION_TRIAL_NOT_ENABLED', 'PF_NOTION_TRIAL_REQUEST_INVALID', 'PF_NOTION_TRIAL_STOPPED', 'PF_NOTION_TRIAL_FAILED', 'PF_NOTION_TRIAL_CONTEXT_REQUIRED', 'PF_NOTION_TRIAL_PLATFORM_REQUIRED', 'PF_HELPER_REQUEST_INVALID', 'PF_HELPER_RESPONSE_INVALID', 'PF_HELPER_CLEANUP_UNCERTAIN', 'PF_HELPER_DEADLINE', 'PF_HELPER_TIMEOUT', 'PF_HELPER_UNAVAILABLE', 'PF_HELPER_INPUT_FAILED', 'PF_HELPER_UNEXPECTED_EXIT', 'PF_HELPER_RESPONSE_TOO_LARGE', 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'APPLICATION_ROUTING_NOT_READY', 'APPLICATION_PROXY_UNAVAILABLE', 'APPLICATION_ROUTING_PROTOCOL_ERROR', 'APPLICATION_APP_CONTEXT_REFUSED', 'APPLICATION_APP_IDENTITY_REFUSED', 'APPLICATION_APP_NATIVE_REFUSED', 'APPLICATION_APP_STAGE_UNCONFIRMED', 'APPLICATION_APP_TRANSPORT_UNCONFIRMED', 'APPLICATION_APP_STAGE_TIMEOUT', 'APPLICATION_APP_RESUME_TIMEOUT', 'APPLICATION_APP_STOP_TIMEOUT', 'APPLICATION_APP_RELEASE_TIMEOUT', 'APPLICATION_APP_RESUME_UNCONFIRMED', 'APPLICATION_APP_CLEANUP_UNCONFIRMED', 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED', 'APPLICATION_NATIVE_REFUSED']);
const exact = (value, required, optional = []) => value && typeof value === 'object' && !Array.isArray(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => [...required, ...optional].includes(key));
function safeFailure(value) {
  if (!exact(value, ['stage', 'code'], ['native']) || !failureStages.has(value.stage) || !codes.has(value.code)) return null;
  const native = value.native;
  if (Object.hasOwn(value, 'native') && (!exact(native, ['stage', 'reason', 'error']) || !nativeStages.has(native.stage) ||
    !(native.stage === 'register' ? registerReasons : operationReasons).has(native.reason) || !Number.isInteger(native.error) || native.error < 1 || native.error > 1024)) return null;
  return { stage: value.stage, code: value.code, ...(native ? { native: { stage: native.stage, reason: native.reason, error: native.error } } : {}) };
}
function cachedFailure(value, key) {
  const explicit = safeFailure(value[key]); if (explicit) return explicit;
  if (key !== 'initialFailure') return null;
  for (const diagnostic of [value.applicationSnapshotDiagnostic, value.sessionDiagnostics?.lastApplicationSnapshot, value.sessionDiagnostics?.lastLatePrepare]) {
    /* The snapshot validator in the session client does not depend on a profile
     * field, so history written by either profile is usable here. */
    if (diagnostic?.schema !== 'envara.macos-pf-notion-response-diagnostic/v1' || diagnostic.source !== 'verified-authorizer-session-client' ||
      diagnostic.diagnosticOnly !== true || diagnostic.runId !== value.runId || diagnostic.environmentId !== value.environmentId) continue;
    const failure = safeFailure(diagnostic.initialFailure ?? diagnostic.failure); if (failure) return failure;
  }
  return null;
}

export function safeNotionTrial(application) {
  const value = application?.notionTrial;
  if (!value || value.applicationId !== application.id || !phases.has(value.phase)) return null;
  return { applicationId: application.id, active: value.active === true, phase: value.phase,
    cleanupComplete: value.cleanupComplete === true, cleanupUncertain: value.cleanupUncertain === true, errorCode: codes.has(value.errorCode) ? value.errorCode : null, initialFailure: cachedFailure(value, 'initialFailure'), cleanupFailure: cachedFailure(value, 'cleanupFailure'),
    events: Array.isArray(value.events) ? value.events.slice(-24).flatMap(event => {
      if (!event || !Number.isSafeInteger(event.sequence) || event.sequence < 0 || !failureStages.has(event.stage)) return [];
      return [{ sequence: event.sequence, stage: token(event.stage), code: codes.has(event.code) ? event.code : null, nativeStage: nativeStages.has(event.nativeStage) ? event.nativeStage : null,
        nativeReason: (event.nativeStage === 'register' ? registerReasons : operationReasons).has(event.nativeReason) ? event.nativeReason : null,
        errno: Number.isSafeInteger(event.errno) && event.errno > 0 && event.errno <= 1024 ? event.errno : null }];
    }) : [] };
}

export function safeNotionTrialHistory(application) {
  const value = application?.notionTrialHistory;
  /* The profile is a property of the attached application, not of the history
   * shape: a Chromium/Electron application runs the front-only profile and
   * everything else runs cold. Both are legitimate diagnostic history. */
  if (value?.schema !== 'envara.macos-pf-notion-trial-diagnostics/v1' || value.diagnosticOnly !== true ||
      !['seatbelt-front-only', 'cold'].includes(value.profile) ||
      !['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => value[key] === false) ||
      ![value.runId, value.environmentId].every(id => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id ?? ''))) return null;
  return safeNotionTrial({ id: application.id, notionTrial: value });
}

export function notionTrialControls(application, routing, desktop, pending = {}) {
  /* Any locally added application can be attached; the fixed native carrier and
   * registry decide whether a given bundle may actually launch. Nothing here
   * asserts readiness or protection. */
  const canonical = desktop === true && typeof application?.identity === 'string' && application.identity.length > 0;
  const available = canonical && routing?.controlledNotionTrialAvailable === true;
  const trial = canonical ? safeNotionTrial(application) : null;
  const history = canonical ? safeNotionTrialHistory(application) : null;
  const requestPending = !!pending[`runNotionTrial:${application?.id}`];
  const stopPending = !!pending[`stopNotionTrial:${application?.id}`];
  return { available, trial, history, requestPending, stopPending, active: trial?.active === true || requestPending,
    show: canonical && (available || !!trial && (trial.phase !== 'idle' || trial.events.length > 0 || !!trial.errorCode) || !!history),
    canRun: available && !requestPending && !stopPending && trial?.active !== true && trial?.cleanupUncertain !== true,
    canStop: canonical && trial?.active === true && !stopPending && trial.phase !== 'stopping' };
}

export function notionTrialLogLine(event) {
  return [`${event.sequence}. ${event.stage}`, event.code, event.nativeStage, event.nativeReason, event.errno != null ? `errno=${event.errno}` : null].filter(Boolean).join(' · ');
}

export function notionTrialLocksConfiguration(application, pending = {}) {
  if (typeof application?.identity !== 'string' || !application.identity) return false;
  const trial = safeNotionTrial(application);
  return trial?.active === true || trial?.cleanupUncertain === true || !!pending[`runNotionTrial:${application.id}`] || !!pending[`stopNotionTrial:${application.id}`];
}

// Explanations only; they never change what a trial is allowed to do.
export const notionTrialErrorHints = Object.freeze({
  PF_OWNED_RUNTIME_NOT_EMPTY: '系统 PF 当前不是可安全接管的初始状态：可能是上次中断的试运行留下的规则（重启电脑可清除），也可能是其他 VPN 或安全软件启用了 PF。',
});
export function notionTrialErrorHint(code) { return typeof code === 'string' && Object.hasOwn(notionTrialErrorHints, code) ? notionTrialErrorHints[code] : null; }
export const notionTrialPhaseLabels = {
  idle: '已停止', verifying: '检查中…', authorizing: '等待系统授权', preparing: '处理中…', staged: '等待启动', resuming: '启动中', running: '运行中',
  stopping: '停止中', cleaned: '已清理', failed: '异常', 'cleanup-required': '清理未确认',
};

export function notionTrialFailureLine(failure) {
  const value = safeFailure(failure);
  return value ? [value.stage, value.code, value.native?.stage, value.native?.reason, value.native ? `errno=${value.native.error}` : null].filter(Boolean).join(' · ') : '';
}
