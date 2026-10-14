// Main-process-only bounded trial. This is separate from generic app readiness.
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { verifyPFInstallation, PF_INSTALL_ROOT, PF_APP_SESSION_LEASE_SECONDS } from '../native/macos-pf-routing/controller.mjs';
import { pfRoutingAnchor, pfAttachEnvironmentId, pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';
import { pruneAttachedApplicationCache } from './application-data.mjs';
import { createPFAuthorizedChannelMux } from './macos-pf-channel-mux.mjs';
import { createPersistentPFNotionSessionClient, validatePFNotionSessionRequest,
  PF_NOTION_RESUME_TIMEOUT_MS, PF_SESSION_CHANNEL_LIFETIME_MS, validatePFNotionCallTimingDiagnostic,
  validatePFNotionStatusOnlyCloseEvidence,
  validatePFNotionResponseDiagnostic, projectPFNotionResponseDiagnostic, projectPFNotionFailureDiagnostic,
  validatePFNotionCleanupReceipt, validatePFNotionPrestageCleanupReceipt,
  validatePFNotionPreflightCleanupReceipt } from './macos-pf-notion-session.mjs';
/* The controller and this manager are polled, not pushed: a running attached
 * application is checked often enough to notice that it exited on its own,
 * without flooding the one authorized channel. */
export const PF_ATTACH_POLL_INTERVAL_MS = 2000;

export const PF_NOTION_TRIAL_CANDIDATE = Object.freeze({
  authorizerSHA256: 'b09dabba84d54f051c6005d680e14cf15d88c05f29f84cf41e3c3ab5867028bd',
  manifestSHA256: '9b51cf9b161d1add0ea86049adc535ea298b6bb6e44ff7496989cd0662fa4743',
});
/* The bundled carrier is named after the manifest it carries. Deriving the path
 * from the pin keeps a single source of truth: a pinned candidate with a stale
 * hard-coded carrier path made the app look for a carrier it did not ship. */
export const PF_NOTION_TRIAL_CARRIER = `local-authorization/EnvaraPFAuthorization-${PF_NOTION_TRIAL_CANDIDATE.manifestSHA256.slice(0, 12)}.app/Contents/Resources/app-routing/macos-pf/EnvaraPFInstall`;
const fixedFlags = Object.freeze({ ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false });
const suffix = '/Contents/Resources/app-routing/macos-pf/EnvaraPFInstall';
const error = code => Object.assign(new Error('Controlled Notion trial refused'), { code });
const codes = new Set(['PF_INSTALLED_CANDIDATE_MISMATCH', 'PF_NOTION_CARRIER_MISMATCH', 'PF_NOTION_SIGNATURE_REFUSED',
  'PF_OWNED_RUNTIME_NOT_EMPTY', 'PF_NOTION_TRIAL_BUSY', 'PF_NOTION_TRIAL_NOT_ENABLED', 'PF_NOTION_TRIAL_REQUEST_INVALID',
  'PF_NOTION_TRIAL_STOPPED', 'PF_NOTION_TRIAL_FAILED', 'PF_NOTION_TRIAL_CONTEXT_REQUIRED', 'PF_NOTION_TRIAL_PLATFORM_REQUIRED',
  'PF_HELPER_REQUEST_INVALID', 'PF_HELPER_RESPONSE_INVALID', 'PF_HELPER_CLEANUP_UNCERTAIN', 'PF_HELPER_DEADLINE',
  'PF_HELPER_TIMEOUT', 'PF_HELPER_UNAVAILABLE', 'PF_HELPER_INPUT_FAILED', 'PF_HELPER_UNEXPECTED_EXIT', 'PF_HELPER_RESPONSE_TOO_LARGE',
  'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'APPLICATION_ROUTING_NOT_READY', 'APPLICATION_PROXY_UNAVAILABLE',
  'APPLICATION_ROUTING_PROTOCOL_ERROR', 'APPLICATION_APP_CONTEXT_REFUSED', 'APPLICATION_APP_IDENTITY_REFUSED',
  'APPLICATION_APP_NATIVE_REFUSED', 'APPLICATION_APP_STAGE_UNCONFIRMED', 'APPLICATION_APP_TRANSPORT_UNCONFIRMED',
  'APPLICATION_APP_STAGE_TIMEOUT', 'APPLICATION_APP_RESUME_TIMEOUT', 'APPLICATION_APP_STOP_TIMEOUT', 'APPLICATION_APP_RELEASE_TIMEOUT', 'APPLICATION_APP_RESUME_UNCONFIRMED', 'APPLICATION_APP_CLEANUP_UNCONFIRMED', 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED', 'APPLICATION_NATIVE_REFUSED']);
const safeCode = value => codes.has(value?.code) ? value.code : 'PF_NOTION_TRIAL_FAILED';
const nativeStages = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn',
  'front-handshake', 'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const registerReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const operationReasons = new Set(['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED', 'NATIVE_ORIGINAL_SOCKET_REFUSED', 'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED', 'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED', 'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED', 'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED', 'NATIVE_TICKET_BINDING_REFUSED', 'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED', 'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED', 'NATIVE_NOTION_SUPPORTED_ARGUMENT_REFUSED', 'NATIVE_NOTION_SUPPORTED_PLIST_REFUSED', 'NATIVE_NOTION_SUPPORTED_VERSION_REFUSED', 'NATIVE_NOTION_SUPPORTED_SIGNATURE_REFUSED', 'NATIVE_NOTION_PLAN_ARGUMENT_REFUSED', 'NATIVE_NOTION_PLAN_REGISTRY_REFUSED', 'NATIVE_NOTION_PLAN_CONTEXT_REFUSED', 'NATIVE_NOTION_PLAN_REQUEST_REFUSED', 'NATIVE_NOTION_PLAN_SEALED_REFUSED', 'NATIVE_NOTION_PLAN_SUPPORTED_REFUSED', 'NATIVE_NOTION_PLAN_DIGEST_REFUSED', 'NATIVE_NOTION_PLAN_CDHASH_REFUSED', 'NATIVE_NOTION_PLAN_REQUIREMENT_REFUSED', 'NATIVE_NOTION_PLAN_DATA_REFUSED', 'NATIVE_NOTION_PLAN_ALLOCATION_REFUSED', 'NATIVE_NOTION_DATA_ARGUMENT_REFUSED', 'NATIVE_NOTION_DATA_ENTRY_REFUSED', 'NATIVE_NOTION_DATA_ANCESTOR_REFUSED', 'NATIVE_NOTION_DATA_LEAF_REFUSED', 'NATIVE_NOTION_DATA_DENY_REFUSED', 'NATIVE_NOTION_STAGE_ARGUMENT_REFUSED', 'NATIVE_NOTION_STAGE_AUTHORITY_REFUSED', 'NATIVE_NOTION_STAGE_ENTRY_REFUSED', 'NATIVE_NOTION_STAGE_SESSION_REFUSED', 'NATIVE_NOTION_STAGE_ORIGINAL_RUNNING_REFUSED', 'NATIVE_NOTION_STAGE_ACCOUNT_REFUSED', 'NATIVE_NOTION_STAGE_ENVIRONMENT_REFUSED', 'NATIVE_NOTION_STAGE_DATA_REFUSED', 'NATIVE_NOTION_STAGE_RECHECK_REFUSED', 'NATIVE_NOTION_STAGE_SPAWN_REFUSED', 'NATIVE_NOTION_STAGE_STOPPED_REFUSED', 'NATIVE_NOTION_STAGE_CHILD_REFUSED']);
const statusFacts = ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized',
  'privilegedRuntimeVerified', 'ownedRootHookCanCreate', 'priorPFAnchorsCompatible', 'lo0FilteringVerified'];
const canonicalUUID = value => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value ?? '');
const sessionMethods = new Set(['status', 'prepareRoute', 'prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot']);
function sessionDiagnostics(value, runId, environmentId) {
  if (!value || typeof value !== 'object') return null;
  const output = {};
  for (const key of ['stdoutEOF', 'pending', 'uncertaintyLatched', 'nonStatusRequestAttempted', 'callHistoryComplete', 'lastStatusReadOnly'])
    if (typeof value[key] === 'boolean') output[key] = value[key];
  for (const key of ['selectedStatusRunId', 'lastStatusRunId']) if (value[key] === null || canonicalUUID(value[key])) output[key] = value[key];
  if (value.terminalExitCode === null || Number.isInteger(value.terminalExitCode) && value.terminalExitCode >= 0 && value.terminalExitCode <= 255)
    output.terminalExitCode = value.terminalExitCode;
  // Signal diagnostics are produced by the fixed client, but this projection
  // still excludes arbitrary strings supplied by a test or replacement client.
  if (value.terminalExitSignal === null || /^(?:SIG(?:TERM|INT|HUP|PIPE|KILL|ABRT|SEGV|BUS|ILL|TRAP|QUIT|ALRM|USR1|USR2|FPE|XCPU|XFSZ|PROF|VTALRM|STOP|TSTP|TTIN|TTOU|CONT|CHLD|WINCH|URG|IO|SYS)|unknown)$/.test(value.terminalExitSignal ?? ''))
    output.terminalExitSignal = value.terminalExitSignal;
  if (Number.isInteger(value.bufferedBytes) && value.bufferedBytes >= 0 && value.bufferedBytes <= 262144) output.bufferedBytes = value.bufferedBytes;
  for (const key of ['observationPolls', 'observationPollFailures'])
    if (Number.isInteger(value[key]) && value[key] >= 0 && value[key] <= 2147483647) output[key] = value[key];
  if (Array.isArray(value.callHistory) && value.callHistory.length <= 64 && value.callHistory.every(method => sessionMethods.has(method))) output.callHistory = [...value.callHistory];
  if (Array.isArray(value.callTimings) && value.callTimings.length === output.callHistory?.length && value.callTimings.length <= 64 && value.callTimings.every((timing, index) =>
      validatePFNotionCallTimingDiagnostic(timing) && timing.sequence === index + 1 && timing.method === output.callHistory?.[index]))
    output.callTimings = structuredClone(value.callTimings);
  const inventory = value.lastStatusInventory;
  if (inventory === null) output.lastStatusInventory = null;
  else if (inventory && Object.keys(inventory).sort().join('|') === 'applications|routes|runs' &&
      Object.values(inventory).every(count => count === null || Number.isInteger(count) && count >= 0 && count <= 65536)) output.lastStatusInventory = { ...inventory };
  for (const [key, method] of [['lastLatePrepare', 'prepareNotionApplication'], ['lastApplicationSnapshot', 'applicationSnapshot']])
    output[key] = validatePFNotionResponseDiagnostic(value[key], method, runId, environmentId) ? structuredClone(value[key]) : null;
  return output;
}
function nativeDiagnostic(value) {
  const native = value?.native ?? value?.nativeFailure;
  if (!native || Object.keys(native).some(key => !['stage', 'reason', 'error'].includes(key)) ||
      !nativeStages.has(native.stage) || (native.stage === 'register' ? !registerReasons.has(native.reason) : !operationReasons.has(native.reason)) ||
      !Number.isInteger(native.error) || native.error < 1 || native.error > 1024) return {};
  return { nativeStage: native.stage, nativeReason: native.reason, errno: native.error };
}
const trialPhases = new Set(['idle', 'verifying', 'authorizing', 'preparing', 'staged', 'resuming', 'running', 'stopping', 'cleaned', 'failed', 'cleanup-required']);
const failureStages = new Set([...trialPhases, 'register', 'inspect', 'lock', 'baseline', 'registry-lock', 'root-hook', 'group', 'group-allocation',
  'context', 'sealed-context', 'pf-reference', 'transport', 'cold-stage', 'resume', 'cleanup']);
function trialFailure(value, phase) {
  const supplied = projectPFNotionFailureDiagnostic(value?.initialFailure ?? value);
  if (supplied) return supplied;
  if (!codes.has(value?.code)) return null;
  const projected = nativeDiagnostic(value);
  return { stage: failureStages.has(value.failureStage) ? value.failureStage : failureStages.has(phase) ? phase : 'failed', code: value.code,
    ...(projected.nativeStage ? { native: { stage: projected.nativeStage, reason: projected.nativeReason, error: projected.errno } } : {}) };
}
function safeTrialFailure(value) {
  if (value === null || value === undefined) return null;
  if (!value || Object.keys(value).some(key => !['stage', 'code', 'native'].includes(key)) || !failureStages.has(value.stage) || !codes.has(value.code)) return null;
  if (Object.hasOwn(value, 'native') && !nativeDiagnostic(value).nativeStage) return null;
  return { stage: value.stage, code: value.code, ...(Object.hasOwn(value, 'native') ? { native: { ...value.native } } : {}) };
}
/** Export/history data is explanatory only and never authorizes root cleanup. */
export function exportPFNotionTrialDiagnostics(value) {
  if (!value || !/^[A-Za-z0-9_-]{1,128}$/.test(value.applicationId ?? '') || !canonicalUUID(value.runId) || !canonicalUUID(value.environmentId)) return null;
  const events = Array.isArray(value.events) ? value.events.slice(-64).flatMap(event => {
    if (!Number.isInteger(event?.sequence) || event.sequence < 1 || !trialPhases.has(event.stage)) return [];
    return [{ sequence: event.sequence, stage: event.stage, ...(codes.has(event.code) ? { code: event.code } : {}),
      ...nativeDiagnostic({ native: { stage: event.nativeStage, reason: event.nativeReason, error: event.errno } }) }];
  }) : [];
  const diagnostics = sessionDiagnostics(value.sessionDiagnostics, value.runId, value.environmentId);
  const applicationSnapshot = validatePFNotionResponseDiagnostic(value.applicationSnapshotDiagnostic, 'applicationSnapshot', value.runId, value.environmentId)
    ? value.applicationSnapshotDiagnostic : null;
  const cached = [applicationSnapshot, diagnostics?.lastApplicationSnapshot, diagnostics?.lastLatePrepare];
  const first = safeTrialFailure(value.initialFailure) ?? cached.map(item => safeTrialFailure(item?.initialFailure ?? item?.failure)).find(Boolean) ?? null;
  const cleanup = safeTrialFailure(value.cleanupFailure) ?? cached.map(item => safeTrialFailure(item?.cleanupFailure)).find(Boolean) ?? null;
  return { schema: 'envara.macos-pf-notion-trial-diagnostics/v1', diagnosticOnly: true, applicationId: value.applicationId,
    runId: value.runId, environmentId: value.environmentId, profile: 'seatbelt-front-only', phase: trialPhases.has(value.phase) ? value.phase : 'failed',
    initialFailure: first, cleanupFailure: cleanup,
    active: value.active === true, staged: value.staged === true, resumed: value.resumed === true,
    cleanupComplete: value.cleanupComplete === true, cleanupUncertain: value.cleanupUncertain === true,
    events, sessionDiagnostics: diagnostics,
    ...fixedFlags };
}
async function hashFile(filename, refusal) {
  try {
    const before = await lstat(filename);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.mode & 0o022 || await realpath(filename) !== filename) throw error(refusal);
    const hash = createHash('sha256'); for await (const bytes of createReadStream(filename)) hash.update(bytes);
    const after = await lstat(filename);
    if (['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw error(refusal);
    return hash.digest('hex');
  } catch { throw error(refusal); }
}
export async function verifyNotionTrialSignature(application) {
  try {
    await new Promise((resolve, reject) => execFile('/usr/bin/codesign', ['--verify', '--strict', '--deep', '--all-architectures', application],
      { timeout: 10000, maxBuffer: 16384, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } }, failure => failure ? reject(failure) : resolve()));
    return true;
  } catch { throw error('PF_NOTION_SIGNATURE_REFUSED'); }
}
/**
 * Read-only on every invocation; fixed local candidate, never renderer pins.
 * The application to verify is the one this trial was bound to for the current
 * run; candidate verification of the carrier itself stays fixed. Nothing here
 * upgrades a signature check into a routing or protection claim.
 */
export async function verifyNotionTrialCandidate({ authorizerPath, applicationPath, carrierOnly = false } = {}) {
  if (process.platform !== 'darwin') throw error('PF_NOTION_TRIAL_PLATFORM_REQUIRED');
  if (typeof authorizerPath !== 'string' || !path.isAbsolute(authorizerPath) || !authorizerPath.endsWith(`.app${suffix}`) || /[\0\r\n]/.test(authorizerPath))
    throw error('PF_NOTION_TRIAL_NOT_ENABLED');
  const pin = PF_NOTION_TRIAL_CANDIDATE;
  // Check the installation first: an old installed f99 cannot reach authorization.
  if (await hashFile(`${PF_INSTALL_ROOT}/manifest.json`, 'PF_INSTALLED_CANDIDATE_MISMATCH') !== pin.manifestSHA256)
    throw error('PF_INSTALLED_CANDIDATE_MISMATCH');
  const installed = await verifyPFInstallation();
  if (installed.verified !== true || installed.manifestVerified !== true) throw error('PF_INSTALLED_CANDIDATE_MISMATCH');
  if (await hashFile(authorizerPath, 'PF_NOTION_CARRIER_MISMATCH') !== pin.authorizerSHA256 ||
      await hashFile(path.join(path.dirname(authorizerPath), 'manifest.json'), 'PF_NOTION_CARRIER_MISMATCH') !== pin.manifestSHA256)
    throw error('PF_NOTION_CARRIER_MISMATCH');
  await verifyNotionTrialSignature(authorizerPath.slice(0, -suffix.length));
  // The bound application is signature-checked here too. The native fixed
  // registry additionally re-inspects and seals the exact signed bundle, so a
  // caller cannot substitute a different or modified application at this layer.
  // Storage maintenance binds no application: every check above still applies.
  if (carrierOnly === true) return true;
  const bundle = applicationPath ?? '/Applications/Notion.app';
  if (!trialBundlePath(bundle)) throw error('PF_NOTION_TRIAL_REQUEST_INVALID');
  await verifyNotionTrialSignature(bundle);
  return true;
}
const trialBundlePath = value => typeof value === 'string' && path.isAbsolute(value) && value.endsWith('.app') && value.length <= 4096 && !/[\0\r\n]/.test(value) ? value : null;
/* Derive the containing ".app" from a bound executable path. Candidate only:
 * the fixed native registry independently seals the real signed bundle. */
const applicationBundleFor = value => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.length > 4096 || /[\0\r\n]/.test(value)) return null;
  const segments = value.split('/');
  const index = segments.findIndex((segment, position) => position > 0 && segment.endsWith('.app'));
  if (index < 1 || segments[index].length < 5) return null;
  const bundle = segments.slice(0, index + 1).join('/');
  return bundle && bundle !== '/' ? bundle : null;
};
const cleanKind = (value, runId, environmentId) => value?.environmentId !== environmentId ? null :
  validatePFNotionCleanupReceipt(value, runId) ? 'normal' : validatePFNotionPrestageCleanupReceipt(value, runId) ? 'prestage' :
    validatePFNotionPreflightCleanupReceipt(value, runId) ? 'preflight' : null;

export class MacOSPFNotionTrial {
  constructor({ authorizerPath, verifyCandidate = ({ applicationPath, carrierOnly } = {}) => verifyNotionTrialCandidate({ authorizerPath, applicationPath, carrierOnly }),
    verifyNotion = bundle => verifyNotionTrialSignature(bundle ?? '/Applications/Notion.app'),
    createClient = ({ runId } = {}) => {
      /* One authorized root session per Envara launch: the carrier is spawned
       * inside the shared mux on the first attach and reused by every later
       * attach, so the administrator password is asked once. Each run gets its
       * own virtual channel, so ending one run never disturbs another. */
      if (!runId) throw error('PF_NOTION_TRIAL_REQUEST_INVALID');
      const target = this.acquireRunChannel(runId);
      this.activeTarget = target;
      return createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: null, acquireChannel: () => target,
        lifetimeMs: PF_SESSION_CHANNEL_LIFETIME_MS, channelKey: runId });
    },
    /* An attached application runs until it is stopped, it exits, or Envara
     * quits. A bounded trial may pass a finite watch window in milliseconds;
     * the default keeps watching for as long as the run lasts. */
    watchMs = Infinity, onEvent = () => {}, persistDiagnostics = async () => {},
    /* After a run's cleanup is confirmed, its regenerable caches go; sign-in
     * state stays. Tests replace this with a recorder. */
    pruneApplicationData = ({ environmentId, registrationId }) => pruneAttachedApplicationCache({ environmentId, registrationId }),
    /* Only the verified fixed carrier is ever spawned. Tests replace this to
     * run the real shared channel against an inert root helper. */
    spawnCarrier = authorizer => spawn(authorizer, ['--request-controlled-experiment'],
      { shell: false, cwd: '/', env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, stdio: ['pipe', 'pipe', 'pipe'] }) } = {}) {
    if (![verifyCandidate, verifyNotion, createClient, onEvent, persistDiagnostics, spawnCarrier, pruneApplicationData].every(value => typeof value === 'function') ||
        !(watchMs === Infinity || Number.isInteger(watchMs) && watchMs >= 0 && watchMs <= 45000)) throw error('PF_NOTION_TRIAL_REQUEST_INVALID');
    this.verifyCandidate = verifyCandidate; this.verifyNotion = verifyNotion; this.createClient = createClient;
    this.watchMs = watchMs; this.onEvent = onEvent; this.persistDiagnostics = persistDiagnostics;
    this.observationSeconds = Number.isFinite(watchMs) && watchMs > 0 ? watchMs / 1000 : null;
    this.state = null; this.pending = null; this.stopObservation = null; this.closed = false;
    this.mux = null; this.activeTarget = null; this.runTargets = new Map();
    this.authorizerPath = authorizerPath; this.spawnCarrier = spawnCarrier;
    this.pruneApplicationData = pruneApplicationData; this.housekeeping = null; this.lastHousekeeping = null;
  }
  stateFlags() { return { active: false, phase: 'idle', staged: false, resumed: false, cleanupComplete: false, cleanupUncertain: false,
    lifecyclePassed: false, errorCode: null, events: [], ...fixedFlags, initialFailure: null, cleanupFailure: null,
    maximumLifetimeSeconds: PF_APP_SESSION_LEASE_SECONDS,
    observationSeconds: this.observationSeconds }; }
  /* One authorized root session per Envara launch. The first attach opens it and
   * the system asks for the administrator password once; every later attach in
   * this launch reuses it, and quitting Envara is what closes it. The carrier is
   * spawned inside the mux, so nothing runs and no dialog appears until the
   * first attach actually acquires a run channel. */
  ensureMux() {
    /* A shared session that has ended (its carrier exited, or it refused
     * authorization) can carry nothing more. Reusing it made every later attach
     * in the same launch fail; a new one is opened, which honestly needs a new
     * authorization. */
    if (this.mux?.snapshot().ended === true) this.mux = null;
    return this.mux ??= createPFAuthorizedChannelMux({ spawnRootControlledLifecycle: () => this.spawnSharedCarrier() });
  }
  /* Only the verified fixed carrier is ever spawned, and only here. */
  spawnSharedCarrier() {
    return this.spawnCarrier(this.authorizerPath);
  }
  acquireRunChannel(key) {
    const target = this.ensureMux().acquire({ key });
    this.runTargets.set(key, target);
    return target;
  }
  /* Ending one run's channel leaves the shared authorized session open for the
   * next attach; only disposeShared() closes the root session itself. */
  closeRunChannel() {
    const target = this.activeTarget; this.activeTarget = null;
    if (target?.key) this.runTargets.delete(target.key);
    try { target?.end?.(); } catch { /* already ended */ }
    return Promise.resolve({ closed: true, cleanupUncertain: false });
  }
  async disposeShared() {
    const mux = this.mux;
    this.mux = null;
    if (mux) await mux.dispose();
  }
  /* What attached applications keep on disk, and its removal, served on a
   * channel of its own in the shared session: never while an application is
   * attached, and only after the same carrier checks as an attach. */
  async storage(method, params, { housekeeping = false } = {}) {
    /* Housekeeping runs between runs on the session that is still open: a
     * later start waits for it, and quitting waits for it before the session
     * closes. Everything else keeps the ordinary checks. */
    if (this.closed && !housekeeping) throw error('PF_NOTION_TRIAL_STOPPED');
    if (this.pending && !housekeeping) throw error('PF_NOTION_TRIAL_BUSY');
    if (this.state?.cleanupUncertain) throw error('PF_OWNED_RUNTIME_NOT_EMPTY');
    // Housekeeping never opens a session: no administrator prompt for cleanup.
    if (housekeeping && (!this.mux || this.mux.snapshot().ended === true)) throw error('PF_NOTION_TRIAL_STOPPED');
    await this.verifyCandidate({ carrierOnly: true });
    if (this.pending && !housekeeping) throw error('PF_NOTION_TRIAL_BUSY');
    const key = randomUUID(), target = this.ensureMux().acquire({ key });
    const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: null, acquireChannel: () => target,
      lifetimeMs: PF_SESSION_CHANNEL_LIFETIME_MS, channelKey: key });
    try { return await call(method, params, { timeoutMs: 60000 }); }
    finally {
      try { await call.close({ timeoutMs: 5000 }); } catch { /* reported by the call above */ }
      try { target.end(); } catch { /* already ended */ }
    }
  }
  /* A stopped application keeps only its sign-in data: the sealed copy made
   * for its run is removed on the same open session (the next start copies the
   * original again), and its caches are emptied. Only a confirmed cleanup
   * starts this, so nothing of the application is still running. */
  scheduleHousekeeping(request) {
    let registrationId, environmentId;
    try { registrationId = pfApplicationRegistrationId(applicationBundleFor(request.application.executablePath));
      environmentId = pfAttachEnvironmentId(request.application.profileId); } catch { return null; }
    const previous = this.housekeeping ?? Promise.resolve();
    const work = previous.catch(() => {}).then(async () => {
      const outcome = { applicationId: request.application.id, copy: null, cacheBytesFreed: null };
      try {
        const result = await this.storage('reclaimApplicationStorage', { registrationIds: [registrationId], environmentIds: [] }, { housekeeping: true });
        outcome.copy = result?.registrations?.find(item => item.registrationId === registrationId)?.outcome ?? 'failed';
      } catch { outcome.copy = 'failed'; }
      try { outcome.cacheBytesFreed = await this.pruneApplicationData({ environmentId, registrationId }); } catch { outcome.cacheBytesFreed = null; }
      this.lastHousekeeping = outcome;
      try { this.onEvent({ housekeeping: { ...outcome } })?.catch?.(() => {}); } catch { /* observers never affect cleanup */ }
      return outcome;
    });
    this.housekeeping = work;
    work.finally(() => { if (this.housekeeping === work) this.housekeeping = null; }).catch(() => {});
    return work;
  }
  applicationStorage() { return this.storage('applicationStorage', {}); }
  reclaimApplicationStorage({ registrationIds, environmentIds } = {}) {
    return this.storage('reclaimApplicationStorage', { registrationIds, environmentIds });
  }
  snapshot(applicationId) {
    if (!this.state || applicationId && this.state.applicationId !== applicationId) return { applicationId: applicationId ?? null, ...this.stateFlags() };
    return structuredClone(this.state);
  }
  emit(stage, failure) {
    if (failure) this.captureFailure(failure, stage === 'stopping');
    const event = { sequence: this.state.events.length ? this.state.events.at(-1).sequence + 1 : 1, stage,
      ...(failure ? { code: safeCode(failure), ...nativeDiagnostic(failure) } : {}),
      ...(!this.state.active && this.state.sessionDiagnostics ? {
        /* A long session's per-request numbers are what stays comparable; the
         * observation window, when one exists, is reported separately. */
        diagnostics: { ...structuredClone(this.state.sessionDiagnostics),
          ...(Number.isFinite(this.observationSeconds) ? { observationSeconds: this.observationSeconds } : {}) } } : {}) };
    this.state.events.push(event); if (this.state.events.length > 64) this.state.events.shift();
    if (failure) this.state.errorCode ??= event.code;
    try { this.onEvent({ applicationId: this.state.applicationId, profileId: this.state.profileId, ...event })?.catch?.(() => {}); } catch { /* UI logging cannot alter cleanup. */ }
    const report = exportPFNotionTrialDiagnostics(this.state);
    if (report) try { Promise.resolve(this.persistDiagnostics(report)).catch(() => {}); } catch { /* History failure cannot overwrite native failure or block cleanup. */ }
  }
  captureFailure(value, cleanup = false) {
    if (!cleanup && safeTrialFailure(value?.cleanupFailure)) this.captureFailure({ cleanupFailure: value.cleanupFailure }, true);
    const key = cleanup ? 'cleanupFailure' : 'initialFailure';
    const failure = cleanup ? safeTrialFailure(value?.cleanupFailure) ?? trialFailure(value, 'cleanup') : trialFailure(value, this.state.phase);
    if (!failure) return;
    if (!this.state[key]) this.state[key] = failure;
    // A later snapshot can supply native details omitted by an older RPC frame;
    // it cannot replace the first error with an unrelated cleanup failure.
    else if (!this.state[key].native && failure.native && this.state[key].code === failure.code)
      this.state[key] = { ...failure };
  }
  /* A snapshot the trial took while the application was still running must
   * not erase the fact that it ended: the later cleanup receipts carry no such
   * field, and silently dropping it would report a finished run as live. */
  captureSnapshot(value) {
    const first = projectPFNotionFailureDiagnostic(value?.initialFailure ?? value?.failure);
    if (first) this.captureFailure(first);
    const cleanup = projectPFNotionFailureDiagnostic(value?.cleanupFailure);
    if (cleanup) this.captureFailure({ cleanupFailure: cleanup }, true);
  }
  /** Availability is a property of the fixed carrier, not of one application. */
  async available() {
    try { await this.verifyCandidate(); return { controlledNotionTrialAvailable: true, errorCode: null, ...fixedFlags }; }
    catch (failure) { return { controlledNotionTrialAvailable: false, errorCode: safeCode(failure), ...fixedFlags }; }
  }
  stop(applicationId) {
    if (this.pending && this.state.applicationId === applicationId) { this.state.stopRequested = true; this.stopObservation?.(); }
    return this.snapshot(applicationId);
  }
  /* The running application is polled until it is stopped, it ends on its own,
   * the owner quits, or a bounded trial's own window elapses. A poll is
   * scheduled only after the previous one settled, so the channel never carries
   * two outstanding requests and a finished run is never reported as unverified. */
  async observe(call, runId, windowMs) {
    let done = false, timer = null, settle;
    const settleObservation = new Promise(resolve => { settle = resolve; });
    /* A watch window that has already elapsed, or a stop that was already
     * requested, must not wait for the next poll: a bounded trial zero
     * milliseconds long would otherwise idle for a full poll interval. */
    const elapsed = () => Number.isFinite(windowMs) && Date.now() - this.observedAt >= windowMs;
    const finish = () => { if (done) return; done = true; clearTimeout(timer); this.stopObservation = null;
      Promise.resolve(this.observationInFlight).catch(() => {}).then(() => settle()); };
    const poll = () => {
      if (done) return;
      if (this.state.stopRequested || this.closed || elapsed()) {
        if (Number.isFinite(windowMs)) this.state.observationCompleted = true;
        finish(); return;
      }
      this.observationInFlight = (async () => {
        try {
          const current = await call('applicationSnapshot', { runId }, { timeoutMs: 5000, observation: true });
          this.captureSnapshot(current);
          if (current.applicationEnded === true) {
            this.state.applicationEnded = true; this.state.applicationEndedChildReaped = current.endedChildReaped === true;
            finish(); return;
          }
        } catch { /* A failed poll is not evidence; the run continues. */ }
        if (!done) timer = setTimeout(poll, PF_ATTACH_POLL_INTERVAL_MS);
      })();
    };
    this.observedAt = Date.now();
    this.stopObservation = finish;
    if (this.state.stopRequested || this.closed || elapsed()) { if (Number.isFinite(windowMs)) this.state.observationCompleted = true; finish(); }
    else timer = setTimeout(poll, PF_ATTACH_POLL_INTERVAL_MS);
    await settleObservation;
  }
  /* Stops the attached application and then tears the shared authorized session
   * down. This is the quit path: Envara does not exit while a run is still live,
   * and the root controller is closed here rather than left behind. */
  async shutdownAll({ onProgress = () => {} } = {}) {
    this.closed = true;
    const pending = this.pending;
    if (pending) { this.state.stopRequested = true; this.stopObservation?.(); }
    try { await pending; } catch { /* the run records its own first failure */ }
    try { await this.housekeeping; } catch { /* housekeeping reports its own outcome */ }
    try { await this.closeRunChannel(); } catch { /* a failed end is reported by the run */ }
    try { await this.disposeShared(); } catch { /* dispose never spawns and never throws */ }
    onProgress({ closed: true, cleanupUncertain: this.state?.cleanupUncertain === true });
    return this.snapshot();
  }
  run({ request, applicationId, activationAuthorized }) {
    if (this.pending || this.state?.cleanupUncertain) return Promise.reject(error(this.state?.cleanupUncertain ? 'PF_OWNED_RUNTIME_NOT_EMPTY' : 'PF_NOTION_TRIAL_BUSY'));
    if (activationAuthorized !== true || typeof applicationId !== 'string' || request?.application?.id !== applicationId)
      return Promise.reject(error('PF_NOTION_TRIAL_REQUEST_INVALID'));
    try { validatePFNotionSessionRequest('prepareRoute', request); } catch { return Promise.reject(error('PF_NOTION_TRIAL_REQUEST_INVALID')); }
    this.state = { applicationId, profileId: request.application.profileId, active: true, phase: 'verifying', staged: false, resumed: false,
      stopRequested: false, cleanupComplete: false, cleanupUncertain: false, lifecyclePassed: false, errorCode: null,
      initialFailure: null, cleanupFailure: null, events: [], ...fixedFlags,
      maximumLifetimeSeconds: PF_APP_SESSION_LEASE_SECONDS,
      observationSeconds: this.observationSeconds };
    /* A start right after a stop waits for that stop's housekeeping, so the
     * removal of the old copy never races the registration of the new one. */
    const before = this.housekeeping;
    const task = (before ? before.catch(() => {}).then(() => this.execute(request)) : this.execute(request)); this.pending = task;
    task.finally(() => { if (this.pending === task) this.pending = null; }).catch(() => {});
    task.then(snapshot => { if (snapshot?.cleanupComplete === true && snapshot.cleanupUncertain !== true) this.scheduleHousekeeping(request); }).catch(() => {});
    return task;
  }
  async execute(request) {
    let call, routeRequested = false, prepared = false, stoppedKind = null, snapshotKind = null, closeConfirmed = false, statusOnlyClosed = false,
      statusOnlyDetached = false, refusedDetached = false;
    /* The environment's identity is derived from its own id, so the same
     * environment always reaches the same data. A non-UUID id used to be
     * replaced by a random one on every attach. */
    const runId = randomUUID(), environmentId = pfAttachEnvironmentId(request.application.profileId);
    this.state.runId = runId; this.state.environmentId = environmentId;
    const advance = (phase, failure) => { this.state.phase = phase; this.emit(phase, failure); };
    const checkStop = () => { if (this.state.stopRequested) throw error('PF_NOTION_TRIAL_STOPPED'); };
    try {
      /* Both the carrier and the bound application are re-verified read-only.
       * The bound bundle comes from the sealed request, never from the renderer
       * at this point. */
      const boundBundle = applicationBundleFor(request.application.executablePath);
      advance('verifying'); await this.verifyCandidate({ applicationPath: boundBundle }); checkStop();
      call = this.createClient({ runId }); advance('authorizing');
      const status = await call('status', { runId }, { timeoutMs: 60000 });
      if (status.anchor !== pfRoutingAnchor(runId)) throw error('PF_HELPER_RESPONSE_INVALID');
      this.state.statusFacts = Object.fromEntries(statusFacts.map(key => [key, status[key] === true]));
      if (status.ownedRootHookCanCreate !== true) throw error('PF_OWNED_RUNTIME_NOT_EMPTY');
      if (statusFacts.some(key => status[key] !== true)) throw error('APPLICATION_ROUTING_NOT_READY');
      checkStop(); advance('preparing'); routeRequested = true;
      /* No stop check between the route and the run: a route without its run
       * has nothing to stop it by. A stop asked for meanwhile is honoured once
       * the run is staged, before the application ever executes. */
      const route = await call('prepareRoute', request, { timeoutMs: 15000 });
      prepared = true;
      // Register, first transport ACK and cold-stage ACK each have independent
      // native deadlines. A session-bound run has no channel lifetime to clamp
      // to, so each of these waits is bounded only by its own timeout.
      const stage = await call('prepareNotionApplication', { routeId: route.routeId, runId, environmentId,
        lifetimeSeconds: PF_APP_SESSION_LEASE_SECONDS, activationAuthorized: true }, { timeoutMs: 110000 });
      this.captureSnapshot(stage);
      if (stage.phase !== 'staged' || stage.staged !== true || stage.resumed !== false)
        throw Object.assign(error(safeCode(stage.failure?.code ? stage.failure : { code: 'APPLICATION_APP_STAGE_UNCONFIRMED' })),
          { native: stage.failure?.native, failureStage: stage.failure?.stage, initialFailure: stage.initialFailure });
      this.state.staged = true; advance('staged'); checkStop();
      await this.verifyNotion(); checkStop(); advance('resuming');
      // This covers controller preflight plus cold native validation and ACK.
      const resumed = await call('resumeNotionApplication', { runId, activationAuthorized: true }, { timeoutMs: PF_NOTION_RESUME_TIMEOUT_MS });
      this.captureSnapshot(resumed);
      if (resumed.phase !== 'running' || resumed.resumed !== true) throw error('APPLICATION_APP_RESUME_UNCONFIRMED');
      this.state.resumed = true; advance('running');
      /* The application runs until it is stopped, it exits on its own, or
       * Envara quits. There is no observation window: the run is kept honest by
       * polling the controller, so an application that ended is reported as
       * ended instead of being shown as running. A bounded trial keeps its
       * window as an upper limit only. */
      await this.observe(call, runId, this.watchMs);
    } catch (failure) { this.emit('failed', failure); }
    finally {
      this.stopObservation?.();
      this.stopObservation = null;
      /* A refused preparation may have been refused before the controller
       * created anything for it. A fresh read-only status tells: a run the
       * controller created stays listed until its cleanup is confirmed, so an
       * unlisted run has nothing to stop. Asking it to stop anyway is what
       * reported a refusal as an unconfirmed cleanup. The close below accepts
       * "nothing held" only when that same status lists nothing at all. */
      let runCreated = prepared;
      if (routeRequested && call && !this.state.staged) {
        try { const fresh = await call('status', { runId }, { timeoutMs: 15000 }); runCreated = prepared && fresh.applicationListed !== false; }
        catch { /* unanswered, so the run is treated as created */ }
      }
      if (runCreated && call) {
        advance('stopping');
        try { const stopped = await call('stopNotionApplication', { runId }, { timeoutMs: 25000 }); stoppedKind = cleanKind(stopped, runId, environmentId);
          this.captureSnapshot(stopped);
          if (stopped.cleanupFailure) this.emit('stopping', stopped.cleanupFailure);
          else if (!stoppedKind && stopped.failure) this.emit('stopping', stopped.failure);
        } catch (failure) { this.emit('stopping', failure); }
        try { const snapshot = await call('applicationSnapshot', { runId }, { timeoutMs: 5000 }); snapshotKind = cleanKind(snapshot, runId, environmentId);
          this.captureSnapshot(snapshot);
          this.state.applicationSnapshotDiagnostic = projectPFNotionResponseDiagnostic('applicationSnapshot', snapshot, runId, environmentId); }
        catch (failure) { this.emit('stopping', failure); }
      }
      if (call) {
        try { const closed = await call.close({ timeoutMs: 15000 }); closeConfirmed = closed.closed === true && closed.cleanupUncertain === false;
          statusOnlyClosed = !prepared && closeConfirmed && validatePFNotionStatusOnlyCloseEvidence(closed.statusOnlyEvidence, runId);
          /* On the shared session the run detaches instead of the session
           * closing; the client establishes that it held nothing. */
          statusOnlyDetached = !prepared && closeConfirmed && closed.statusOnlyDetached === true;
          refusedDetached = !runCreated && closeConfirmed && closed.refusedDetached === true; }
        catch (failure) { this.emit('stopping', failure); }
        /* This run's virtual channel ends here; the shared authorized session
         * stays open so the next attach asks for no password. */
        try { await this.closeRunChannel(); } catch { /* reported by the run above */ }
        try { this.state.sessionDiagnostics = sessionDiagnostics(call.snapshot().diagnostics, runId, environmentId);
          if (this.state.sessionDiagnostics && this.state.applicationSnapshotDiagnostic)
            this.state.sessionDiagnostics.lastApplicationSnapshot = structuredClone(this.state.applicationSnapshotDiagnostic); }
        catch { this.state.sessionDiagnostics = null; }
        for (const diagnostic of [this.state.sessionDiagnostics?.lastLatePrepare, this.state.sessionDiagnostics?.lastApplicationSnapshot]) {
          if (!diagnostic) continue;
          this.captureSnapshot(diagnostic);
          if (diagnostic.kind === 'error') this.captureFailure({ code: diagnostic.code, nativeFailure: diagnostic.native,
            failureStage: diagnostic.failureStage, initialFailure: diagnostic.initialFailure });
        }
      }
      this.state.cleanupComplete = prepared && stoppedKind != null && stoppedKind === snapshotKind && closeConfirmed;
      this.state.statusOnlySessionClosed = statusOnlyClosed;
      this.state.statusOnlyRunDetached = statusOnlyDetached;
      this.state.refusedRunDetached = refusedDetached;
      this.state.cleanupUncertain = call != null && (!closeConfirmed || prepared && !this.state.cleanupComplete && !refusedDetached ||
        this.state.errorCode === 'PF_OWNED_RUNTIME_NOT_EMPTY' && !statusOnlyClosed && !statusOnlyDetached);
      this.state.lifecyclePassed = this.state.resumed && this.state.cleanupComplete && !this.state.errorCode;
      this.state.active = false;
      advance(this.state.cleanupUncertain ? 'cleanup-required' : this.state.cleanupComplete ? 'cleaned' : 'failed');
    }
    return this.snapshot();
  }
}
