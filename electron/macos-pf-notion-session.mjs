// Source-only shared Notion transport. Import and construction are inert.
// The main process must independently verify the authorizer and obtain explicit
// activation authorization before its injected spawn callback may create it.
import { randomUUID } from 'node:crypto';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

export const PF_NOTION_CHANNEL_LIFETIME_MS = 180000;
/* A session-bound attached application keeps running until it is stopped, the
 * application exits, or Envara quits. Its authorized channel therefore has no
 * total lifetime, and only each individual request stays bounded. */
export const PF_SESSION_CHANNEL_LIFETIME_MS = Infinity;
/* The sealed lease only bounds the session from outside; the controller and the
 * native guardian enforce the same 30-day ceiling. Kept as a local constant so
 * this module does not import the controller it is validated against. */
export const PF_SESSION_LEASE_SECONDS = 30 * 24 * 60 * 60;
export const PF_NOTION_CLEANUP_RESERVE_MS = 40000;
export const PF_NOTION_CLOSE_RESERVE_MS = 10000;
export const PF_NOTION_RESUME_TIMEOUT_MS = 60000;
// Node clamps any timer delay above 2^31-1 ms to 1 ms.
const MAXIMUM_TIMER_MS = 2147483647;
const failed = code => Object.assign(new Error('Bounded Notion channel refused'), { code });
const notionMethods = new Set(['prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot']);
const canonicalUUID = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const exact = (value, keys, optional = []) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  keys.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => [...keys, ...optional].includes(key));
const text = value => typeof value === 'string' && value.length > 0 && !/[\0\r\n]/.test(value);
const absolute = value => text(value) && value.startsWith('/') && value.length <= 4095;
/* A bounded candidate executable inside a ".app" bundle: either the bundle
 * itself or a nested path beneath it. The fixed native registry independently
 * inspects and seals the real signed bundle, so this is not an identity claim. */
const boundApplicationPath = value => {
  if (!absolute(value) || !value.endsWith('.app') && !value.includes('.app/')) return false;
  if (value.split('/').some(segment => segment === '.' || segment === '..')) return false;
  const segments = value.split('/');
  const index = segments.findIndex((segment, position) => position > 0 && segment.endsWith('.app'));
  return index > 0 && segments[index].length >= 5;
};
export function validatePFNotionSessionRequest(method, params) {
  if (method === 'status') {
    if (!exact(params, [], ['runId']) || Object.hasOwn(params, 'runId') && !canonicalUUID(params.runId)) throw failed('PF_HELPER_REQUEST_INVALID');
  } else if (method === 'prepareRoute') {
    /* Any locally added application may be bound. The executable must be a
     * bounded absolute path ending in ".app" or lying directly inside such a
     * bundle; the fixed native registry independently inspects and seals the
     * real signed bundle, so this is a candidate path, not an identity claim. */
    if (!exact(params, ['application', 'workspace', 'route', 'managedRoute']) ||
        !exact(params.application, ['id', 'profileId', 'executablePath']) || ['id', 'profileId'].some(key => !/^[A-Za-z0-9_-]{1,128}$/.test(params.application[key] ?? '')) ||
        !boundApplicationPath(params.application.executablePath) ||
        !exact(params.workspace, ['cwd', 'timezone', 'locale'], ['timezoneSource']) || !absolute(params.workspace.cwd) || !text(params.workspace.timezone) || params.workspace.timezone.length > 100 ||
        !/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/.test(params.workspace.locale ?? '') ||
        Object.hasOwn(params.workspace, 'timezoneSource') && !['proxy', 'proxy-egress', 'fixed'].includes(params.workspace.timezoneSource) ||
        !exact(params.route, ['protocol', 'host', 'port', 'username', 'password', 'udpPolicy']) || params.route.protocol !== 'socks5' ||
        !['127.0.0.1', '::1'].includes(params.route.host) || !Number.isInteger(params.route.port) || params.route.port < 1 || params.route.port > 65535 ||
        ['username', 'password'].some(key => !text(params.route[key]) || Buffer.byteLength(params.route[key]) > 255) || !['proxy', 'block'].includes(params.route.udpPolicy) ||
        !exact(params.managedRoute, ['profileId', 'proxyId', 'nodeType', 'routeIdentity', 'coreGeneration', 'corePid', 'coreVersion']) ||
        params.managedRoute.profileId !== params.application.profileId || ['proxyId', 'nodeType'].some(key => !/^[A-Za-z0-9_-]{1,128}$/.test(params.managedRoute[key] ?? '')) ||
        !canonicalUUID(params.managedRoute.routeIdentity) || !canonicalUUID(params.managedRoute.coreGeneration) || !Number.isSafeInteger(params.managedRoute.corePid) || params.managedRoute.corePid < 2 ||
        params.managedRoute.coreVersion !== 'v1.19.32') throw failed('PF_HELPER_REQUEST_INVALID');
    try { new Intl.DateTimeFormat('en', { timeZone: params.workspace.timezone }); } catch { throw failed('PF_HELPER_REQUEST_INVALID'); }
  } else if (notionMethods.has(method)) {
    const keys = method === 'prepareNotionApplication' ? ['routeId', 'runId', 'environmentId', 'lifetimeSeconds', 'activationAuthorized'] :
      method === 'resumeNotionApplication' ? ['runId', 'activationAuthorized'] : ['runId'];
    if (!exact(params, keys) || !canonicalUUID(params.runId) || method === 'prepareNotionApplication' &&
        (!/^[A-Za-z0-9_-]{1,128}$/.test(params.routeId ?? '') || !canonicalUUID(params.environmentId) || !Number.isInteger(params.lifetimeSeconds) ||
          params.lifetimeSeconds < 10 || params.lifetimeSeconds > PF_SESSION_LEASE_SECONDS) ||
        Object.hasOwn(params, 'activationAuthorized') && params.activationAuthorized !== true) throw failed('PF_HELPER_REQUEST_INVALID');
  } else throw failed('PF_HELPER_REQUEST_INVALID');
}
export function validatePFNotionStatusOnlyCloseEvidence(value, requestedRunId = null) {
  const truths = ['readOnlyHistoryVerified', 'freshControllerInventoriesEmpty', 'stdoutEOF', 'authorizerExitConfirmed',
    'pendingRequestsAbsent', 'bufferedOutputAbsent', 'noMutationRequestAttempted'];
  const falsehoods = ['uncertaintyLatched', 'cleanupComplete', 'lifecyclePassed', 'ready', 'protected', 'productionReady'];
  return (requestedRunId === null || canonicalUUID(requestedRunId)) && exact(value, ['schema', 'source', 'runId', 'statusRequests', ...truths, ...falsehoods]) &&
    value.schema === 'envara.macos-pf-notion-status-only-close/v1' && value.source === 'verified-authorizer-session-client' &&
    value.runId === requestedRunId && Number.isInteger(value.statusRequests) && value.statusRequests >= 1 && value.statusRequests <= 64 &&
    truths.every(key => value[key] === true) && falsehoods.every(key => value[key] === false);
}
/* Host PF, routes and DNS are observed, not owned. They must be reported as
 * booleans, but a change there does not make Envara's own cleanup incomplete;
 * every owned-resource fact must still be true. */
const unrelatedObservationKeys = ['unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged'];
const observationsReported = evidence => unrelatedObservationKeys.every(key => typeof evidence?.[key] === 'boolean');
export function validatePFNotionCleanupReceipt(result, requestedRunId) {
  const evidence = result?.cleanupEvidence;
  const truths = ['coreReaped', 'frontReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
    'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
    'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'sealedContextRetired', 'registryReleased'];
  return canonicalUUID(requestedRunId) && result?.runId === requestedRunId && canonicalUUID(result.environmentId) && result.phase === 'cleaned' &&
    result.cleanupComplete === true && result.cleanupUncertain === false && result.profile === 'seatbelt-front-only' &&
    ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => result[key] === false) &&
    exact(evidence, ['schema', 'source', 'runId', 'environmentId', 'profile', 'complete', 'cleanupUncertain', 'childReaped', ...truths, ...unrelatedObservationKeys], ['childAbsent']) &&
    evidence.schema === 'envara.macos-pf-notion-cleanup/v1' && evidence.source === 'native-notion-controller' && evidence.runId === requestedRunId &&
    evidence.environmentId === result.environmentId && evidence.profile === result.profile && evidence.complete === true && evidence.cleanupUncertain === false &&
    (!Object.hasOwn(evidence, 'childAbsent') || typeof evidence.childAbsent === 'boolean') &&
    (evidence.childReaped === true && evidence.childAbsent !== true || evidence.childReaped === false && evidence.childAbsent === true) &&
    truths.every(key => evidence[key] === true) && observationsReported(evidence);
}

// A failed preparation can release its resources without ever staging an app.
// Keep this proof distinct from a successfully staged child's cleanup receipt.
export function validatePFNotionPrestageCleanupReceipt(result, requestedRunId) {
  const evidence = result?.cleanupEvidence;
  const truths = ['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
    'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
    'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased',
    'sealedContextRetired', 'registryReleased'];
  const falsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted'];
  return canonicalUUID(requestedRunId) && result?.runId === requestedRunId && canonicalUUID(result.environmentId) && result.phase === 'prestage-cleaned' &&
    result.prestageAborted === true && result.staged === false && result.resumed === false && result.cleanupComplete === true && result.cleanupUncertain === false &&
    result.profile === 'seatbelt-front-only' && ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => result[key] === false) &&
    exact(evidence, ['schema', 'source', 'runId', 'environmentId', 'profile', 'complete', 'cleanupUncertain', ...truths, ...unrelatedObservationKeys, ...falsehoods]) &&
    evidence.schema === 'envara.macos-pf-notion-prestage-cleanup/v1' && evidence.source === 'native-notion-controller' && evidence.runId === requestedRunId &&
    evidence.environmentId === result.environmentId && evidence.profile === result.profile && evidence.complete === true && evidence.cleanupUncertain === false &&
    truths.every(key => evidence[key] === true) && observationsReported(evidence) && falsehoods.every(key => evidence[key] === false);
}

// A direct native preflight refusal has no app/core/front resource receipt.
// Its independently proved root-resource cleanup must never pass either of
// the established launch or later-factory abort validators.
export function validatePFNotionPreflightCleanupReceipt(result, requestedRunId) {
  const evidence = result?.cleanupEvidence, native = result?.failure?.native;
  const truths = ['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
    'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
    'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
    'receiptRetired', 'ownedPFReferenceReleased', 'sealedContextRetired', 'registryReleased'];
  const falsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted'];
  return canonicalUUID(requestedRunId) && result?.runId === requestedRunId && canonicalUUID(result.environmentId) && result.phase === 'preflight-cleaned' &&
    result.preflightAborted === true && result.prestageAborted === false && result.staged === false && result.resumed === false &&
    result.cleanupComplete === true && result.cleanupUncertain === false && result.profile === 'seatbelt-front-only' &&
    ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => result[key] === false) &&
    result.failure?.stage === 'transport' && result.failure?.code === 'APPLICATION_APP_NATIVE_REFUSED' && exact(native, ['stage', 'reason', 'error']) &&
    native.stage === 'preflight' && operationReasons.has(native.reason) && Number.isInteger(native.error) && native.error > 0 && native.error <= 1024 &&
    exact(evidence, ['schema', 'source', 'runId', 'environmentId', 'profile', 'complete', 'cleanupUncertain', ...truths, ...unrelatedObservationKeys, ...falsehoods]) &&
    evidence.schema === 'envara.macos-pf-notion-preflight-cleanup/v1' && evidence.source === 'native-notion-controller' && evidence.runId === requestedRunId &&
    evidence.environmentId === result.environmentId && evidence.profile === result.profile && evidence.complete === true && evidence.cleanupUncertain === false &&
    truths.every(key => evidence[key] === true) && observationsReported(evidence) && falsehoods.every(key => evidence[key] === false);
}

const methods = new Set(['status', 'prepareRoute', ...notionMethods]);
const cleanupMethods = new Set(['status', 'stopNotionApplication', 'applicationSnapshot']);
const timingSchema = 'envara.macos-pf-notion-call-timing/v1';
const timingSource = 'verified-authorizer-session-client';
export function validatePFNotionCallTimingDiagnostic(value) {
  /* An unbounded session reports its bounded per-request numbers instead of a
   * fabricated remaining lifetime: a request that is still pending has no
   * remaining or elapsed value, and every bound that does exist is the
   * per-request timeout, exactly as before. */
  const boundedMs = number => number === null || Number.isInteger(number) && number >= 0;
  return exact(value, ['schema', 'source', 'diagnosticOnly', 'sequence', 'method', 'requestedTimeoutMs', 'effectiveTimeoutMs',
    'cleanupReserveMs', 'remainingMsAtStart', 'elapsedMs', 'remainingMsAtFinish', 'outcome', 'lateResponseObserved']) &&
    value.schema === timingSchema && value.source === timingSource && value.diagnosticOnly === true &&
    Number.isInteger(value.sequence) && value.sequence >= 1 && value.sequence <= 64 && methods.has(value.method) &&
    Number.isInteger(value.requestedTimeoutMs) && value.requestedTimeoutMs >= 1 &&
    value.requestedTimeoutMs <= (value.method === 'prepareNotionApplication' ? 110000 : 60000) &&
    Number.isInteger(value.effectiveTimeoutMs) && value.effectiveTimeoutMs >= 1 && value.effectiveTimeoutMs <= value.requestedTimeoutMs &&
    (cleanupMethods.has(value.method) ? [PF_NOTION_CLOSE_RESERVE_MS, PF_NOTION_CLEANUP_RESERVE_MS].includes(value.cleanupReserveMs)
      : value.cleanupReserveMs === PF_NOTION_CLEANUP_RESERVE_MS) && boundedMs(value.remainingMsAtStart) &&
    (value.remainingMsAtStart === null || value.effectiveTimeoutMs <= value.remainingMsAtStart - value.cleanupReserveMs) &&
    (value.elapsedMs === null || boundedMs(value.elapsedMs)) && (value.remainingMsAtFinish === null || boundedMs(value.remainingMsAtFinish)) &&
    ['pending', 'result', 'error', 'deadline', 'aborted', 'closed'].includes(value.outcome) && typeof value.lateResponseObserved === 'boolean' &&
    (!value.lateResponseObserved || ['deadline', 'aborted'].includes(value.outcome));
}
const phases = new Set(['preparing', 'staged', 'running', 'stopping', 'cleaned', 'cleanup-required',
  'prestage-aborted', 'prestage-stopping', 'prestage-cleaned', 'preflight-aborted', 'preflight-stopping', 'preflight-cleaned']);
const flags = ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'];
const nativeErrorCodes = new Set(['APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'APPLICATION_ROUTING_NOT_READY',
  'APPLICATION_PROXY_UNAVAILABLE', 'APPLICATION_ROUTING_PROTOCOL_ERROR', 'APPLICATION_APP_CONTEXT_REFUSED',
  'APPLICATION_APP_IDENTITY_REFUSED', 'APPLICATION_APP_NATIVE_REFUSED', 'APPLICATION_APP_STAGE_UNCONFIRMED',
  'APPLICATION_APP_TRANSPORT_UNCONFIRMED', 'APPLICATION_APP_STAGE_TIMEOUT', 'APPLICATION_APP_RESUME_TIMEOUT', 'APPLICATION_APP_STOP_TIMEOUT', 'APPLICATION_APP_RELEASE_TIMEOUT', 'APPLICATION_APP_RESUME_UNCONFIRMED', 'APPLICATION_APP_CLEANUP_UNCONFIRMED',
  'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED', 'APPLICATION_NATIVE_REFUSED']);
const safeNativeCode = error => nativeErrorCodes.has(error?.code) ? error.code : 'PF_HELPER_RESPONSE_INVALID';
const appFailureStages = new Set(['register', 'inspect', 'lock', 'baseline', 'registry-lock', 'root-hook', 'group', 'group-allocation',
  'context', 'sealed-context', 'pf-reference', 'transport', 'cold-stage', 'resume', 'cleanup']);
const appNativeStages = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn', 'front-handshake',
  'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const registerReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const operationReasons = new Set(['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED', 'NATIVE_ORIGINAL_SOCKET_REFUSED', 'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED', 'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED', 'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED', 'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED', 'NATIVE_TICKET_BINDING_REFUSED', 'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED', 'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED', 'NATIVE_NOTION_SUPPORTED_ARGUMENT_REFUSED', 'NATIVE_NOTION_SUPPORTED_PLIST_REFUSED', 'NATIVE_NOTION_SUPPORTED_VERSION_REFUSED', 'NATIVE_NOTION_SUPPORTED_SIGNATURE_REFUSED', 'NATIVE_NOTION_PLAN_ARGUMENT_REFUSED', 'NATIVE_NOTION_PLAN_REGISTRY_REFUSED', 'NATIVE_NOTION_PLAN_CONTEXT_REFUSED', 'NATIVE_NOTION_PLAN_REQUEST_REFUSED', 'NATIVE_NOTION_PLAN_SEALED_REFUSED', 'NATIVE_NOTION_PLAN_SUPPORTED_REFUSED', 'NATIVE_NOTION_PLAN_DIGEST_REFUSED', 'NATIVE_NOTION_PLAN_CDHASH_REFUSED', 'NATIVE_NOTION_PLAN_REQUIREMENT_REFUSED', 'NATIVE_NOTION_PLAN_DATA_REFUSED', 'NATIVE_NOTION_PLAN_ALLOCATION_REFUSED', 'NATIVE_NOTION_DATA_ARGUMENT_REFUSED', 'NATIVE_NOTION_DATA_ENTRY_REFUSED', 'NATIVE_NOTION_DATA_ANCESTOR_REFUSED', 'NATIVE_NOTION_DATA_LEAF_REFUSED', 'NATIVE_NOTION_DATA_DENY_REFUSED', 'NATIVE_NOTION_STAGE_ARGUMENT_REFUSED', 'NATIVE_NOTION_STAGE_AUTHORITY_REFUSED', 'NATIVE_NOTION_STAGE_ENTRY_REFUSED', 'NATIVE_NOTION_STAGE_SESSION_REFUSED', 'NATIVE_NOTION_STAGE_ORIGINAL_RUNNING_REFUSED', 'NATIVE_NOTION_STAGE_ACCOUNT_REFUSED', 'NATIVE_NOTION_STAGE_ENVIRONMENT_REFUSED', 'NATIVE_NOTION_STAGE_DATA_REFUSED', 'NATIVE_NOTION_STAGE_RECHECK_REFUSED', 'NATIVE_NOTION_STAGE_SPAWN_REFUSED', 'NATIVE_NOTION_STAGE_STOPPED_REFUSED', 'NATIVE_NOTION_STAGE_CHILD_REFUSED']);
const safeNativeFailure = value => exact(value, ['stage', 'reason', 'error']) && appNativeStages.has(value.stage) &&
  (value.stage === 'register' ? registerReasons.has(value.reason) : operationReasons.has(value.reason)) &&
  Number.isInteger(value.error) && value.error > 0 && value.error <= 1024 ? { stage: value.stage, reason: value.reason, error: value.error } : null;
const diagnosticSchema = 'envara.macos-pf-notion-response-diagnostic/v1';
const diagnosticSource = 'verified-authorizer-session-client';
const diagnosticFailure = value => value === null ? null : exact(value, ['stage', 'code'], ['native']) &&
  appFailureStages.has(value.stage) && nativeErrorCodes.has(value.code) &&
  (!Object.hasOwn(value, 'native') || safeNativeFailure(value.native)) ? {
    stage: value.stage, code: value.code, ...(Object.hasOwn(value, 'native') ? { native: safeNativeFailure(value.native) } : {}),
  } : undefined;
export const projectPFNotionFailureDiagnostic = value => diagnosticFailure(value) ?? null;
function safeErrorDiagnostic(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const result = {};
  if (Object.hasOwn(value, 'nativeFailure')) {
    const native = safeNativeFailure(value.nativeFailure); if (!native) return null;
    result.nativeFailure = native;
  }
  if (Object.hasOwn(value, 'failureStage')) {
    if (!appFailureStages.has(value.failureStage)) return null;
    result.failureStage = value.failureStage;
  }
  for (const key of ['initialFailure', 'cleanupFailure']) if (Object.hasOwn(value, key)) {
    const failure = diagnosticFailure(value[key]); if (failure === undefined) return null;
    result[key] = failure;
  }
  return result;
}
export function validatePFNotionResponseDiagnostic(value, method, runId, environmentId) {
  if (!['prepareNotionApplication', 'applicationSnapshot'].includes(method) || !canonicalUUID(runId) || !canonicalUUID(environmentId) ||
      value?.schema !== diagnosticSchema || value.source !== diagnosticSource || value.method !== method ||
      value.runId !== runId || value.environmentId !== environmentId || value.profile !== 'seatbelt-front-only' || value.diagnosticOnly !== true) return false;
  if (value.kind === 'error') return method === 'prepareNotionApplication' &&
    exact(value, ['schema', 'source', 'kind', 'method', 'runId', 'environmentId', 'profile', 'diagnosticOnly', 'code', 'native'],
      ['failureStage', 'initialFailure', 'cleanupFailure']) && nativeErrorCodes.has(value.code) && (value.native === null || safeNativeFailure(value.native) !== null) &&
    safeErrorDiagnostic({ ...(value.native ? { nativeFailure: value.native } : {}), ...Object.fromEntries(['failureStage', 'initialFailure', 'cleanupFailure']
      .filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]])) }) !== null;
  return value.kind === 'result' && exact(value, ['schema', 'source', 'kind', 'method', 'runId', 'environmentId', 'profile', 'diagnosticOnly',
    'phase', 'staged', 'resumed', 'cleanupComplete', 'cleanupUncertain', 'failure'], ['initialFailure', 'cleanupFailure', 'applicationEnded']) && phases.has(value.phase) &&
    ['staged', 'resumed', 'cleanupComplete', 'cleanupUncertain'].every(key => typeof value[key] === 'boolean') && diagnosticFailure(value.failure) !== undefined &&
    ['initialFailure', 'cleanupFailure'].every(key => !Object.hasOwn(value, key) || diagnosticFailure(value[key]) !== undefined);
}
export function projectPFNotionResponseDiagnostic(method, result, runId, environmentId) {
  if (!['prepareNotionApplication', 'applicationSnapshot'].includes(method) || result?.runId !== runId || result.environmentId !== environmentId ||
      result.profile !== 'seatbelt-front-only' || flags.some(key => result[key] !== false)) return null;
  const failure = diagnosticFailure(Object.hasOwn(result, 'failure') ? result.failure : null);
  const value = { schema: diagnosticSchema, source: diagnosticSource, kind: 'result', method, runId, environmentId,
    profile: 'seatbelt-front-only', diagnosticOnly: true, phase: result.phase, staged: result.staged, resumed: result.resumed,
    cleanupComplete: result.cleanupComplete, cleanupUncertain: result.cleanupUncertain, failure };
  /* The controller reports whether the guardian already stopped the exact
   * child, which is what distinguishes a run that ended from one that is still
   * running when the observation window closes. */
  if (typeof result.applicationEnded === 'boolean') value.applicationEnded = result.applicationEnded;
  for (const key of ['initialFailure', 'cleanupFailure']) if (Object.hasOwn(result, key)) value[key] = diagnosticFailure(result[key]);
  return validatePFNotionResponseDiagnostic(value, method, runId, environmentId) ? value : null;
}
/* Only a boolean fact and its two booleans cross this boundary; nothing about
 * the native channel or the child's private state does. */
const entryRunningSignals = Object.freeze(['applicationEnded', 'endedChildReaped', 'endedChildSignalled']);
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const cleanupKind = (result, runId, environmentId) => result?.environmentId !== environmentId ? null :
  validatePFNotionCleanupReceipt(result, runId) ? 'normal' : validatePFNotionPrestageCleanupReceipt(result, runId) ? 'prestage' :
    validatePFNotionPreflightCleanupReceipt(result, runId) ? 'preflight' : null;
const uncertainResult = result => result?.cleanupUncertain === true || result?.cleanupRequired === true ||
  result?.phase === 'cleanup-required' || result?.status === 'cleanup-required';

// Return a fixed public shape. Private stdin, stderr, unsolicited result fields
// and arbitrary native error messages never cross back to renderer consumers.
function publicResult(method, result) {
  if (method === 'status') {
    const keys = ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized',
      'privilegedRuntimeVerified', 'ownedRootHookCanCreate', 'priorPFAnchorsCompatible', 'lo0FilteringVerified'];
    return { ...Object.fromEntries(keys.map(key => [key, result[key] === true])), anchor: result.anchor, ready: false, protectedLaunchAllowed: false,
      productionReady: false, protected: false };
  }
  if (method === 'prepareRoute') return { routeId: result.routeId, profileId: result.profileId ?? null,
    ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false };
  const keys = ['runId', 'environmentId', 'routeId', 'profile', 'phase', 'staged', 'resumed', 'prestageAborted',
    'preflightAborted', 'cleanupUncertain', 'cleanupComplete',
    /* The guardian already stopped the exact child: the run has ended even
     * though no stop was requested, and the trial must not keep reporting it
     * as running for the rest of its observation window. */
    ...(entryRunningSignals), ...flags];
  const value = Object.fromEntries(keys.filter(key => Object.hasOwn(result, key)).map(key => [key, result[key]]));
  const kind = cleanupKind(result, result.runId, result.environmentId);
  value.cleanupEvidence = kind ? structuredClone(result.cleanupEvidence) : null;
  value.cleanupComplete = kind != null;
  if (result.cleanupComplete === true && !kind) value.cleanupUncertain = true;
  const native = safeNativeFailure(result.failure?.native);
  value.failure = result.failure && nativeErrorCodes.has(result.failure.code) ? { code: result.failure.code,
    ...(appFailureStages.has(result.failure.stage) ? { stage: result.failure.stage } : {}), ...(native ? { native } : {}) } : null;
  for (const key of ['initialFailure', 'cleanupFailure']) if (Object.hasOwn(result, key)) {
    const failure = diagnosticFailure(result[key]);
    if (failure === undefined) throw failed('PF_HELPER_RESPONSE_INVALID');
    value[key] = failure;
  }
  return value;
}

/**
 * One verified main-process authorizer stream for one attached application.
 * `lifetimeMs` bounds the whole channel: the default 180000 ms is the bounded
 * trial. A session-bound application passes PF_SESSION_CHANNEL_LIFETIME_MS, so
 * only each request is bounded and the run lasts until it is stopped. Passing
 * `acquireChannel` shares one authorized root session between runs: every client
 * gets its own virtual process, and a client that ends never tears down the
 * shared session. This client exposes no protected launch capability and
 * performs no spawning until the first validated RPC invokes the supplied
 * authorization callback.
 */
export function createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle, acquireChannel = null,
  lifetimeMs = PF_NOTION_CHANNEL_LIFETIME_MS, channelKey = null, maximumBytes = 65536,
  now = () => performance.now() } = {}) {
  /* A caller supplies either its own spawn callback or a shared channel. */
  if (typeof spawnRootControlledLifecycle !== 'function' && typeof acquireChannel !== 'function' ||
      typeof now !== 'function' ||
      typeof lifetimeMs !== 'number' || !(lifetimeMs > 0) ||
      channelKey !== null && typeof channelKey !== 'string' ||
      !Number.isInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 131072) throw failed('PF_HELPER_REQUEST_INVALID');
  const bounded = Number.isFinite(lifetimeMs);
  let child, starting, startedAt = null, pending = null, buffer = Buffer.alloc(0), closing = false, closed = false,
    uncertain = false, terminalError = null, terminal = null, closePromise, preparedRoute = null, bound = null,
    stopKind = null, freshCleanupKind = null, resumeAttempted = false, stopAttempted = false, lastClock = null,
    selectedStatusRunId = null, lastStatusRunId = null, lastStatusInventory = null, lastStatusReadOnly = false,
    stdoutEOF = false, nonStatusRequestAttempted = false, historyComplete = true, lastSuccessfulStatusHistoryLength = 0,
    lastLatePrepare = null, lastApplicationSnapshot = null, observationPolls = 0, observationPollFailures = 0;
  const callHistory = [], callTimings = [];
  const retired = new Map(); let settleExit;
  const exit = new Promise(resolve => { settleExit = resolve; });
  const clock = () => {
    const value = now();
    if (!Number.isFinite(value) || value < 0 || lastClock != null && value < lastClock) throw failed('PF_HELPER_REQUEST_INVALID');
    lastClock = value; return value;
  };
  const remaining = () => !bounded ? Infinity : startedAt == null ? lifetimeMs :
    Math.max(0, lifetimeMs - (clock() - startedAt));
  // Diagnostics never carry a number a timer or validator cannot represent.
  const boundedMs = value => !bounded ? Math.min(value, MAXIMUM_TIMER_MS) : value;
  const failChannel = error => {
    uncertain = true; terminalError ??= error;
    if (pending) { const current = pending; pending = null; current.finish(error); }
  };
  const observe = (request, result) => {
    if (uncertainResult(result) || result.applications?.some?.(uncertainResult)) uncertain = true;
    if (request.method === 'status') {
      if (result.anchor !== (request.statusRunId ? pfRoutingAnchor(request.statusRunId) : null) ||
          !request.statusRunId && result.ownedRootHookCanCreate !== false) throw failed('PF_HELPER_RESPONSE_INVALID');
      if (result.ready !== false || result.protectedLaunchAllowed !== false || result.productionReady === true || result.protected === true)
        throw failed('PF_HELPER_RESPONSE_INVALID');
      lastStatusRunId = request.statusRunId ?? null;
      lastStatusInventory = Object.fromEntries(['runs', 'applications', 'routes'].map(key =>
        [key, Array.isArray(result[key]) ? result[key].length : null]));
      lastStatusReadOnly = result.readOnly === true && result.acceptanceOnly === true && result.productionReceiptAllowed === false;
      lastSuccessfulStatusHistoryLength = callHistory.length;
      if (Array.isArray(result.runs) && result.runs.length || Array.isArray(result.applications) && result.applications.some(item =>
        !bound || item.runId !== bound.runId || item.environmentId !== bound.environmentId)) uncertain = true;
      if (Array.isArray(result.applications) && result.applications.some(item =>
        !bound || item.runId !== bound.runId || !cleanupKind(item, bound.runId, bound.environmentId))) freshCleanupKind = null;
    } else if (request.method === 'prepareRoute') {
      if (!safeId(result.routeId) || result.ready !== false || result.failClosed !== false || result.guardArmed !== false ||
          result.managedRouteVerified !== false || result.profileId !== request.profileId) throw failed('PF_HELPER_RESPONSE_INVALID');
      preparedRoute = result.routeId;
    } else {
      if (!bound || result.runId !== bound.runId || result.environmentId !== bound.environmentId ||
          result.profile !== 'seatbelt-front-only' || !phases.has(result.phase) || flags.some(key => result[key] !== false) ||
          typeof result.cleanupUncertain !== 'boolean' || Object.hasOwn(result, 'routeId') && result.routeId !== preparedRoute ||
          ['staged', 'resumed', 'prestageAborted', 'preflightAborted', 'cleanupComplete'].some(key =>
            Object.hasOwn(result, key) && typeof result[key] !== 'boolean')) throw failed('PF_HELPER_RESPONSE_INVALID');
      const kind = cleanupKind(result, bound.runId, bound.environmentId);
      if (request.method === 'stopNotionApplication') { stopKind = kind; freshCleanupKind = null; }
      else if (request.method === 'applicationSnapshot') freshCleanupKind = kind && kind === stopKind ? kind : null;
      else { stopKind = null; freshCleanupKind = null; }
      if (request.method === 'applicationSnapshot') lastApplicationSnapshot = projectPFNotionResponseDiagnostic(
        request.method, result, bound.runId, bound.environmentId);
    }
  };
  const onData = bytes => {
    buffer = Buffer.concat([buffer, bytes]);
    if (buffer.length > maximumBytes * 2) return failChannel(failed('PF_HELPER_RESPONSE_TOO_LARGE'));
    let newline;
    while ((newline = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0, newline); buffer = buffer.subarray(newline + 1);
      if (!line.length || line.length > maximumBytes) return failChannel(failed('PF_HELPER_RESPONSE_INVALID'));
      try {
        const response = JSON.parse(line.toString('utf8'));
        if (response.protocol !== 'envara.application-routing' || response.version !== 1 ||
            Object.hasOwn(response, 'result') === Object.hasOwn(response, 'error')) throw failed('PF_HELPER_RESPONSE_INVALID');
        if (response.id === null && Object.hasOwn(response, 'error') && (!Object.hasOwn(response, 'ok') || response.ok === false)) {
          if (!exact(response, ['protocol', 'version', 'id', 'error'], ['ok', 'nativeAuthorization', 'terminal', 'cleanupUncertain']) ||
              Object.hasOwn(response, 'terminal') && response.terminal !== true ||
              Object.hasOwn(response, 'cleanupUncertain') && response.cleanupUncertain !== true ||
              Object.hasOwn(response, 'nativeAuthorization') && (!exact(response.nativeAuthorization, ['stage', 'status']) ||
                !['AuthorizationCreate', 'AuthorizationCopyRights', 'AuthorizationCopyPrivilegedReference', 'AuthorizationExecuteWithPrivileges'].includes(response.nativeAuthorization.stage) ||
                !Number.isInteger(response.nativeAuthorization.status) || response.nativeAuthorization.status < -2147483648 ||
                response.nativeAuthorization.status > 2147483647)) throw failed('PF_HELPER_RESPONSE_INVALID');
          return failChannel(failed(safeNativeCode(response.error)));
        }
        if (!exact(response, ['protocol', 'version', 'id'], ['ok', 'result', 'error'])) throw failed('PF_HELPER_RESPONSE_INVALID');
        if (response.ok !== Object.hasOwn(response, 'result')) throw failed('PF_HELPER_RESPONSE_INVALID');
        if (typeof response.id !== 'string') throw failed('PF_HELPER_RESPONSE_INVALID');
        // A delayed event-loop timer cannot turn a response past its absolute
        // request deadline into admission or cleanup evidence.
        if (pending?.id === response.id && clock() >= pending.deadline) pending.abandon('PF_HELPER_DEADLINE');
        if (retired.has(response.id)) {
          const prior = retired.get(response.id); retired.delete(response.id);
          if (prior.timing) prior.timing.lateResponseObserved = true;
          if (prior.method === 'prepareNotionApplication') {
            if (!bound || prior.runId !== bound.runId || prior.environmentId !== bound.environmentId) throw failed('PF_HELPER_RESPONSE_INVALID');
            if (Object.hasOwn(response, 'result')) {
              if (Object.hasOwn(response.result ?? {}, 'routeId') && response.result.routeId !== preparedRoute) throw failed('PF_HELPER_RESPONSE_INVALID');
              lastLatePrepare = projectPFNotionResponseDiagnostic(prior.method, response.result, prior.runId, prior.environmentId);
              if (!lastLatePrepare) throw failed('PF_HELPER_RESPONSE_INVALID');
            } else {
              const diagnostic = safeErrorDiagnostic(response.error);
              if (!nativeErrorCodes.has(response.error?.code) || !diagnostic) throw failed('PF_HELPER_RESPONSE_INVALID');
              lastLatePrepare = { schema: diagnosticSchema, source: diagnosticSource, kind: 'error', method: prior.method,
                runId: prior.runId, environmentId: prior.environmentId, profile: 'seatbelt-front-only', diagnosticOnly: true,
                code: response.error.code, native: diagnostic.nativeFailure ?? null, ...Object.fromEntries(['failureStage', 'initialFailure', 'cleanupFailure']
                  .filter(key => Object.hasOwn(diagnostic, key)).map(key => [key, diagnostic[key]])) };
            }
          }
          // A timed-out operation remains abandoned. Its late result is never
          // observed as admission or cleanup evidence and cannot clear the latch.
          continue;
        }
        if (!pending || pending.id !== response.id) throw failed('PF_HELPER_RESPONSE_INVALID');
        const current = pending;
        if (Object.hasOwn(response, 'error')) {
          const diagnostic = safeErrorDiagnostic(response.error);
          if (!diagnostic) throw failed('PF_HELPER_RESPONSE_INVALID');
          pending = null; current.finish(Object.assign(failed(safeNativeCode(response.error)), diagnostic));
        }
        else {
          if (!response.result || typeof response.result !== 'object' || Array.isArray(response.result)) throw failed('PF_HELPER_RESPONSE_INVALID');
          observe(current, response.result);
          pending = null; current.finish(null, publicResult(current.method, response.result));
        }
      } catch { return failChannel(failed('PF_HELPER_RESPONSE_INVALID')); }
    }
    if (buffer.length > maximumBytes) failChannel(failed('PF_HELPER_RESPONSE_TOO_LARGE'));
  };
  /* A shared authorized session outlives this run, so the shared-channel error
   * handlers must never latch this client. Only the direct (owned) child does. */
  const shared = typeof acquireChannel === 'function';
  const attach = process => {
    child = process;
    if (!shared) child.stdin.on('error', () => failChannel(failed('PF_HELPER_INPUT_FAILED')));
    child.stdout.on('data', onData);
    child.stdout.once('end', () => { stdoutEOF = true; });
    child.stderr?.on?.('data', () => {});
    if (!shared) {
      child.once('error', () => failChannel(failed('PF_HELPER_UNAVAILABLE')));
      child.once('close', (exitCode, exitSignal) => {
        closed = true; terminal = { exitCode, exitSignal };
        if (buffer.length || pending || !closing || exitCode !== 0 || exitSignal) failChannel(failed('PF_HELPER_UNEXPECTED_EXIT'));
        settleExit(terminal);
      });
    } else {
      /* The shared session reports its own failure on the run's channel. A
       * request in flight then fails at once with that cause, instead of
       * waiting out its whole deadline for an answer that cannot come. */
      child.once('error', () => failChannel(failed('PF_HELPER_UNAVAILABLE')));
      child.once('close', (exitCode, exitSignal) => {
        closed = true; terminal = { exitCode: exitCode === 0 ? 0 : 1, exitSignal: null };
        /* This run's virtual process ended, but the shared root session is
         * still serving the other attached applications. A close this run did
         * not ask for, with a request still in flight or bytes still buffered,
         * is not a clean end. */
        if (buffer.length || pending || !closing && terminal.exitCode !== 0) failChannel(failed('PF_HELPER_UNEXPECTED_EXIT'));
        settleExit(terminal);
      });
    }
    return child;
  };
  /* start() runs inside a request's promise executor, so it must never throw
   * synchronously: a throw there rejected the request while leaving it marked
   * pending, and refused every later request on this client. The shared
   * channel used to go through a check that required a promise, and the
   * manager hands its channel over synchronously, so the very first attach
   * failed with PF_HELPER_REQUEST_INVALID before anything was sent. */
  const start = () => starting ??= (shared
    ? Promise.resolve().then(() => acquireChannel({ key: channelKey, label: channelKey })).then(process => {
        if (!process?.stdin || !process?.stdout || typeof process.on !== 'function' || typeof process.once !== 'function') throw failed('PF_HELPER_UNAVAILABLE');
        return attach(process);
      })
    : Promise.resolve().then(spawnRootControlledLifecycle).then(process => {
        if (!process?.stdin || !process?.stdout || typeof process.on !== 'function' || typeof process.kill !== 'function') throw failed('PF_HELPER_UNAVAILABLE');
        return attach(process);
      })).then(process => {
    if (closing && !shared) process.stdin.end();
    return process;
  }).catch(() => { closed = true; failChannel(failed('PF_HELPER_UNAVAILABLE')); settleExit(null); throw failed('PF_HELPER_UNAVAILABLE'); });
  const call = async (method, params = {}, { timeoutMs = method === 'resumeNotionApplication' ? PF_NOTION_RESUME_TIMEOUT_MS : 15000, signal,
    observation = false } = {}) => {
    // The multi-step preparation includes a signed snapshot and cold staging.
    // All requests still share the fixed lifetime and reserve cleanup time.
    /* An observation is the routine check that a running application is still
     * running. It is counted rather than recorded one by one: recorded, a run
     * longer than about two minutes filled the bounded history with them, and
     * the stop sequence that explains a failed cleanup was never recorded. */
    if (observation !== false && (observation !== true || method !== 'applicationSnapshot')) throw failed('PF_HELPER_REQUEST_INVALID');
    if (!methods.has(method) || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > (method === 'prepareNotionApplication' ? 110000 : 60000) ||
        signal?.aborted || closing || closed || pending || terminalError || uncertain && !cleanupMethods.has(method))
      throw failed(uncertain ? 'PF_HELPER_CLEANUP_UNCERTAIN' : 'PF_HELPER_REQUEST_INVALID');
    validatePFNotionSessionRequest(method, params);
    if (method !== 'status') nonStatusRequestAttempted = true;
    if (method === 'status' && params.runId && (selectedStatusRunId && params.runId !== selectedStatusRunId || bound && params.runId !== bound.runId) ||
        method === 'prepareNotionApplication' && selectedStatusRunId && params.runId !== selectedStatusRunId) throw failed('PF_HELPER_REQUEST_INVALID');
    if (method === 'prepareRoute' && (preparedRoute || bound) || method === 'prepareNotionApplication' &&
        (bound || params.routeId !== preparedRoute) || notionMethods.has(method) && method !== 'prepareNotionApplication' &&
        (!bound || params.runId !== bound.runId) || method === 'resumeNotionApplication' && (resumeAttempted || stopAttempted)) throw failed('PF_HELPER_REQUEST_INVALID');
    const reserve = cleanupMethods.has(method) && bound ? PF_NOTION_CLOSE_RESERVE_MS : PF_NOTION_CLEANUP_RESERVE_MS;
    const requestedAt = clock(), remainingAtStart = remaining();
    const limit = Math.floor(!bounded ? timeoutMs : Math.min(timeoutMs, remainingAtStart - reserve));
    if (limit < 1) throw failed('PF_HELPER_DEADLINE');
    const id = randomUUID(), input = Buffer.from(JSON.stringify({ protocol: 'envara.application-routing', version: 1, id, method, params }) + '\n');
    if (input.length > maximumBytes) { input.fill(0); throw failed('PF_HELPER_REQUEST_TOO_LARGE'); }
    if (startedAt == null) startedAt = requestedAt;
    if (method === 'status' && params.runId) selectedStatusRunId ??= params.runId;
    if (observation) observationPolls = Math.min(observationPolls + 1, 2147483647);
    else if (callHistory.length < 64) callHistory.push(method); else historyComplete = false;
    if (method === 'prepareNotionApplication') bound = { runId: params.runId, environmentId: params.environmentId };
    if (method === 'resumeNotionApplication') resumeAttempted = true;
    if (method === 'stopNotionApplication') stopAttempted = true;
    const timing = !observation && callTimings.length < 64 ? { schema: timingSchema, source: timingSource, diagnosticOnly: true,
      sequence: callTimings.length + 1, method, requestedTimeoutMs: timeoutMs, effectiveTimeoutMs: limit,
      cleanupReserveMs: reserve, remainingMsAtStart: boundedMs(Math.floor(remainingAtStart)), elapsedMs: null, remainingMsAtFinish: null,
      outcome: 'pending', lateResponseObserved: false } : null;
    if (timing) callTimings.push(timing);
    return new Promise((resolve, reject) => {
      let finished = false;
      const finish = (error, value) => {
        if (finished) return; finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
        if (timing) {
          // Diagnostics never change the outcome if an injected clock fails.
          try { const finishedAt = clock();
            timing.elapsedMs = boundedMs(Math.floor(finishedAt - requestedAt));
            timing.remainingMsAtFinish = boundedMs(Math.floor(remaining()));
          } catch { /* An unavailable timing is diagnostic only. */ }
          timing.outcome = !error ? 'result' : error.code === 'PF_HELPER_DEADLINE' ? 'deadline' :
            error.code === 'PF_HELPER_ABORTED' ? 'aborted' : error.code === 'PF_HELPER_CHANNEL_CLOSED' ? 'closed' : 'error';
        }
        if (error && observation) observationPollFailures = Math.min(observationPollFailures + 1, 2147483647);
        error ? reject(error) : resolve(value);
      };
      const abandon = code => {
        if (pending?.id !== id) return;
        pending = null; uncertain = true;
        if (retired.size >= 64) failChannel(failed('PF_HELPER_RESPONSE_INVALID'));
        else retired.set(id, { method, runId: params.runId, environmentId: params.environmentId, timing });
        input.fill(0); finish(failed(code));
      };
      const abort = () => abandon('PF_HELPER_ABORTED'), timer = setTimeout(() => abandon('PF_HELPER_DEADLINE'), limit);
      pending = { id, method, runId: params.runId, statusRunId: method === 'status' ? params.runId : undefined,
        profileId: params.application?.profileId, deadline: requestedAt + limit, abandon, finish };
      signal?.addEventListener('abort', abort, { once: true });
      start().then(() => {
        if (pending?.id === id && !closing && !closed && !terminalError) {
          try { child.stdin.write(input, () => input.fill(0)); }
          catch { input.fill(0); failChannel(failed('PF_HELPER_INPUT_FAILED')); }
        } else input.fill(0);
      }).catch(() => input.fill(0));
      if (signal?.aborted) abort();
    });
  };
  /* Only a dedicated channel can prove its authorizer exited. */
  const statusOnlyEvidence = () => !shared && startedAt != null && closing && closed && stdoutEOF && !uncertain && !terminalError &&
    !nonStatusRequestAttempted && !preparedRoute && !bound && !pending && !buffer.length && historyComplete && callHistory.length > 0 &&
    callHistory.every(method => method === 'status') && lastStatusReadOnly && lastStatusInventory &&
    lastSuccessfulStatusHistoryLength === callHistory.length && Object.values(lastStatusInventory).every(count => count === 0) && lastStatusRunId === selectedStatusRunId &&
    terminal?.exitCode === 0 && terminal?.exitSignal == null ? {
      schema: 'envara.macos-pf-notion-status-only-close/v1', source: 'verified-authorizer-session-client',
      runId: selectedStatusRunId, statusRequests: callHistory.length, readOnlyHistoryVerified: true,
      freshControllerInventoriesEmpty: true, stdoutEOF: true, authorizerExitConfirmed: true, pendingRequestsAbsent: true,
      bufferedOutputAbsent: true, noMutationRequestAttempted: true, uncertaintyLatched: false,
      cleanupComplete: false, lifecyclePassed: false, ready: false, protected: false, productionReady: false,
    } : null;
  /* A shared channel's root session belongs to Envara and keeps serving other
   * runs, so a run on it cannot show the authorizer exiting, and must not claim
   * to. It can show that it only ever asked for read-only status, every answer
   * arrived, the controller reported no runs, applications or routes, nothing
   * is pending, buffered or uncertain, and its own channel closed normally.
   * Such a run holds nothing, which is all its close has to establish. Without
   * this, a run refused at its first status check (an owned runtime that is
   * not empty, say) was reported as needing cleanup it never caused. */
  const statusOnlyDetached = () => shared && startedAt != null && closing && closed && !uncertain && !terminalError &&
    !nonStatusRequestAttempted && !preparedRoute && !bound && !pending && !buffer.length && historyComplete && callHistory.length > 0 &&
    callHistory.every(method => method === 'status') && lastStatusReadOnly && lastStatusInventory &&
    lastSuccessfulStatusHistoryLength === callHistory.length && Object.values(lastStatusInventory).every(count => count === 0) &&
    lastStatusRunId === selectedStatusRunId && terminal?.exitCode === 0 && terminal?.exitSignal == null;
  call.close = ({ timeoutMs = 10000 } = {}) => {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 20000) return Promise.reject(failed('PF_HELPER_REQUEST_INVALID'));
    return closePromise ??= (async () => {
      closing = true;
      if (!starting) return { closed: true, started: false, cleanupUncertain: false };
      if (pending) { const current = pending; pending = null; uncertain = true; current.finish(failed('PF_HELPER_CHANNEL_CLOSED')); }
      const endAt = clock() + Math.min(timeoutMs, remaining());
      const boundedWait = async promise => {
        const limit = Math.max(1, Math.floor(endAt - clock())); let timer;
        await Promise.race([promise, new Promise(resolve => { timer = setTimeout(resolve, limit); })]); clearTimeout(timer);
      };
      await boundedWait(start().catch(() => {}));
      /* A shared authorized session belongs to Envara, not to one attached
       * application: ending this run must not close the root channel that the
       * other runs still use. Ending the virtual process is the mux's own
       * `end()`, and the shared child is torn down only by the manager's
       * `dispose()` when Envara quits. */
      if (!shared) child?.stdin.end(); // Keep stdout open through the actual close event.
      else child?.stdin?.end?.();      // Ends only this run's virtual channel.
      await boundedWait(exit);
      if (!closed) { uncertain = true; try { child?.kill?.()?.catch?.(() => {}); } catch {} }
      const evidence = statusOnlyEvidence();
      if (evidence) return { closed: true, started: true, cleanupUncertain: false, statusOnlyEvidence: evidence };
      if (statusOnlyDetached()) return { closed: true, started: true, cleanupUncertain: false, statusOnlyDetached: true };
      /* A shared channel reports its own virtual-process close code; 0 means the
       * run ended cleanly, 1 that the root session itself is gone. */
      const expectedExit = shared ? [0, 1] : [0];
      return { closed, started: true, cleanupUncertain: uncertain || !bound || !freshCleanupKind || !closed ||
        !expectedExit.includes(terminal?.exitCode) || terminal?.exitSignal != null };
    })();
  };
  const signals = new Set(['SIGTERM', 'SIGINT', 'SIGHUP', 'SIGPIPE', 'SIGKILL', 'SIGABRT', 'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGTRAP',
    'SIGQUIT', 'SIGALRM', 'SIGUSR1', 'SIGUSR2', 'SIGFPE', 'SIGXCPU', 'SIGXFSZ', 'SIGPROF', 'SIGVTALRM', 'SIGSTOP', 'SIGTSTP',
    'SIGTTIN', 'SIGTTOU', 'SIGCONT', 'SIGCHLD', 'SIGWINCH', 'SIGURG', 'SIGIO', 'SIGSYS']);
  call.snapshot = () => ({ started: startedAt != null, closed, closing, pending: pending != null,
    runId: bound?.runId ?? null, environmentId: bound?.environmentId ?? null,
    cleanupUncertain: uncertain || startedAt != null && !statusOnlyEvidence() && !statusOnlyDetached() && (!bound || !freshCleanupKind), cleanupKind: freshCleanupKind,
    diagnostics: { selectedStatusRunId, lastStatusRunId, lastStatusInventory: lastStatusInventory ? { ...lastStatusInventory } : null,
      lastStatusReadOnly, terminalExitCode: Number.isInteger(terminal?.exitCode) && terminal.exitCode >= 0 && terminal.exitCode <= 255 ? terminal.exitCode : null,
      terminalExitSignal: terminal?.exitSignal == null ? null : signals.has(terminal.exitSignal) ? terminal.exitSignal : 'unknown',
      stdoutEOF, pending: pending != null, bufferedBytes: buffer.length, uncertaintyLatched: uncertain,
      nonStatusRequestAttempted, callHistory: [...callHistory], callHistoryComplete: historyComplete,
      observationPolls, observationPollFailures,
      callTimings: structuredClone(callTimings),
      lastLatePrepare: lastLatePrepare ? structuredClone(lastLatePrepare) : null,
      lastApplicationSnapshot: lastApplicationSnapshot ? structuredClone(lastApplicationSnapshot) : null },
    statusOnlyEvidence: statusOnlyEvidence(),
    maximumLifetimeSeconds: bounded ? lifetimeMs / 1000 : null, remainingMs: bounded ? Math.floor(remaining()) : null,
    cleanupDue: bounded && startedAt != null && remaining() <= PF_NOTION_CLEANUP_RESERVE_MS,
    ready: false, protected: false, productionReady: false, protectedLaunchAllowed: false, genericApplicationRouting: false });
  return call;
}
