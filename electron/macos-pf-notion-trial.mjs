// Main-process-only bounded trial. This is separate from generic app readiness.
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, realpath } from 'node:fs/promises';
import { execFile, spawn } from 'node:child_process';
import { verifyPFInstallation, PF_INSTALL_ROOT } from '../native/macos-pf-routing/controller.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';
import { createPersistentPFNotionSessionClient, validatePFNotionSessionRequest,
  PF_NOTION_RESUME_TIMEOUT_MS, validatePFNotionCallTimingDiagnostic,
  validatePFNotionStatusOnlyCloseEvidence,
  validatePFNotionResponseDiagnostic, projectPFNotionResponseDiagnostic, projectPFNotionFailureDiagnostic,
  validatePFNotionCleanupReceipt, validatePFNotionPrestageCleanupReceipt,
  validatePFNotionPreflightCleanupReceipt } from './macos-pf-notion-session.mjs';

export const PF_NOTION_TRIAL_CANDIDATE = Object.freeze({
  authorizerSHA256: 'e752db63f629567e7201a9444775897fd5dd662b0a1a0e4877e3f51043f8842d',
  manifestSHA256: '4b9f859585a10e31eb98d43682595a9e152b3f93439ebea6ef1de0a4659ba557',
});
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
  'APPLICATION_APP_STAGE_TIMEOUT', 'APPLICATION_APP_RESUME_TIMEOUT', 'APPLICATION_APP_RESUME_UNCONFIRMED', 'APPLICATION_APP_CLEANUP_UNCONFIRMED', 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED', 'APPLICATION_NATIVE_REFUSED']);
const safeCode = value => codes.has(value?.code) ? value.code : 'PF_NOTION_TRIAL_FAILED';
const nativeStages = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn',
  'front-handshake', 'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const registerReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const operationReasons = new Set(['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED', 'NATIVE_ORIGINAL_SOCKET_REFUSED', 'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED', 'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED', 'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED', 'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED', 'NATIVE_TICKET_BINDING_REFUSED', 'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED', 'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED']);
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
/** Read-only on every invocation; fixed local candidate, never renderer pins. */
export async function verifyNotionTrialCandidate({ authorizerPath } = {}) {
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
  await verifyNotionTrialSignature('/Applications/Notion.app');
  return true;
}
const cleanKind = (value, runId, environmentId) => value?.environmentId !== environmentId ? null :
  validatePFNotionCleanupReceipt(value, runId) ? 'normal' : validatePFNotionPrestageCleanupReceipt(value, runId) ? 'prestage' :
    validatePFNotionPreflightCleanupReceipt(value, runId) ? 'preflight' : null;

export class MacOSPFNotionTrial {
  constructor({ authorizerPath, verifyCandidate = () => verifyNotionTrialCandidate({ authorizerPath }), verifyNotion = () => verifyNotionTrialSignature('/Applications/Notion.app'),
    createClient = () => createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => spawn(authorizerPath,
      ['--request-controlled-experiment'], { shell: false, cwd: '/', env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, stdio: ['pipe', 'pipe', 'pipe'] }) }),
    observationMs = 45000, onEvent = () => {}, persistDiagnostics = async () => {} } = {}) {
    if (![verifyCandidate, verifyNotion, createClient, onEvent, persistDiagnostics].every(value => typeof value === 'function') ||
        !Number.isInteger(observationMs) || observationMs < 0 || observationMs > 45000) throw error('PF_NOTION_TRIAL_REQUEST_INVALID');
    this.verifyCandidate = verifyCandidate; this.verifyNotion = verifyNotion; this.createClient = createClient;
    this.observationMs = observationMs; this.onEvent = onEvent; this.persistDiagnostics = persistDiagnostics;
    this.state = null; this.pending = null; this.stopObservation = null;
  }
  snapshot(applicationId) {
    if (!this.state || applicationId && this.state.applicationId !== applicationId) return { applicationId: applicationId ?? null, active: false, phase: 'idle', staged: false,
      resumed: false, cleanupComplete: false, cleanupUncertain: false, lifecyclePassed: false, errorCode: null, events: [], ...fixedFlags,
      initialFailure: null, cleanupFailure: null, maximumLifetimeSeconds: 180, observationSeconds: this.observationMs / 1000 };
    return structuredClone(this.state);
  }
  emit(stage, failure) {
    if (failure) this.captureFailure(failure, stage === 'stopping');
    const event = { sequence: this.state.events.length ? this.state.events.at(-1).sequence + 1 : 1, stage,
      ...(failure ? { code: safeCode(failure), ...nativeDiagnostic(failure) } : {}),
      ...(!this.state.active && this.state.sessionDiagnostics ? { diagnostics: structuredClone(this.state.sessionDiagnostics) } : {}) };
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
  captureSnapshot(value) {
    const first = projectPFNotionFailureDiagnostic(value?.initialFailure ?? value?.failure);
    if (first) this.captureFailure(first);
    const cleanup = projectPFNotionFailureDiagnostic(value?.cleanupFailure);
    if (cleanup) this.captureFailure({ cleanupFailure: cleanup }, true);
  }
  async available() {
    try { await this.verifyCandidate(); return { controlledNotionTrialAvailable: true, errorCode: null, ...fixedFlags }; }
    catch (failure) { return { controlledNotionTrialAvailable: false, errorCode: safeCode(failure), ...fixedFlags }; }
  }
  stop(applicationId) {
    if (this.pending && this.state.applicationId === applicationId) { this.state.stopRequested = true; this.stopObservation?.(); }
    return this.snapshot(applicationId);
  }
  run({ request, applicationId, activationAuthorized }) {
    if (this.pending || this.state?.cleanupUncertain) return Promise.reject(error(this.state?.cleanupUncertain ? 'PF_OWNED_RUNTIME_NOT_EMPTY' : 'PF_NOTION_TRIAL_BUSY'));
    if (activationAuthorized !== true || typeof applicationId !== 'string' || request?.application?.id !== applicationId)
      return Promise.reject(error('PF_NOTION_TRIAL_REQUEST_INVALID'));
    try { validatePFNotionSessionRequest('prepareRoute', request); } catch { return Promise.reject(error('PF_NOTION_TRIAL_REQUEST_INVALID')); }
    this.state = { applicationId, profileId: request.application.profileId, active: true, phase: 'verifying', staged: false, resumed: false,
      stopRequested: false, cleanupComplete: false, cleanupUncertain: false, lifecyclePassed: false, errorCode: null,
      initialFailure: null, cleanupFailure: null, events: [], ...fixedFlags, maximumLifetimeSeconds: 180, observationSeconds: this.observationMs / 1000 };
    const task = this.execute(request); this.pending = task;
    task.finally(() => { if (this.pending === task) this.pending = null; }).catch(() => {});
    return task;
  }
  async execute(request) {
    let call, prepared = false, stoppedKind = null, snapshotKind = null, closeConfirmed = false, statusOnlyClosed = false;
    const runId = randomUUID(), environmentId = canonicalUUID(request.application.profileId) ? request.application.profileId : randomUUID();
    this.state.runId = runId; this.state.environmentId = environmentId;
    const advance = (phase, failure) => { this.state.phase = phase; this.emit(phase, failure); };
    const checkStop = () => { if (this.state.stopRequested) throw error('PF_NOTION_TRIAL_STOPPED'); };
    try {
      advance('verifying'); await this.verifyCandidate(); checkStop();
      call = this.createClient(); advance('authorizing');
      const status = await call('status', { runId }, { timeoutMs: 60000 });
      if (status.anchor !== pfRoutingAnchor(runId)) throw error('PF_HELPER_RESPONSE_INVALID');
      this.state.statusFacts = Object.fromEntries(statusFacts.map(key => [key, status[key] === true]));
      if (status.ownedRootHookCanCreate !== true) throw error('PF_OWNED_RUNTIME_NOT_EMPTY');
      if (statusFacts.some(key => status[key] !== true)) throw error('APPLICATION_ROUTING_NOT_READY');
      checkStop(); advance('preparing');
      const route = await call('prepareRoute', request, { timeoutMs: 15000 }); checkStop();
      prepared = true;
      // Register, first transport ACK and cold-stage ACK each have independent
      // native deadlines. The client still clamps this wait to the 180s channel
      // lifetime while reserving 40s for cleanup.
      const stage = await call('prepareNotionApplication', { routeId: route.routeId, runId, environmentId, lifetimeSeconds: 180, activationAuthorized: true }, { timeoutMs: 110000 });
      this.captureSnapshot(stage);
      if (stage.phase !== 'staged' || stage.staged !== true || stage.resumed !== false)
        throw Object.assign(error(safeCode(stage.failure?.code ? stage.failure : { code: 'APPLICATION_APP_STAGE_UNCONFIRMED' })),
          { native: stage.failure?.native, failureStage: stage.failure?.stage, initialFailure: stage.initialFailure });
      this.state.staged = true; advance('staged'); checkStop();
      await this.verifyNotion(); checkStop(); advance('resuming');
      // This covers controller preflight plus cold native validation and ACK.
      // The session client caps it at the remaining lifetime minus 40s cleanup.
      const resumed = await call('resumeNotionApplication', { runId, activationAuthorized: true }, { timeoutMs: PF_NOTION_RESUME_TIMEOUT_MS });
      this.captureSnapshot(resumed);
      if (resumed.phase !== 'running' || resumed.resumed !== true) throw error('APPLICATION_APP_RESUME_UNCONFIRMED');
      this.state.resumed = true; advance('running');
      const observation = Math.min(this.observationMs, Math.max(0, call.snapshot().remainingMs - 40000));
      if (!this.state.stopRequested && observation > 0) await new Promise(resolve => {
        const timer = setTimeout(() => { this.stopObservation = null; resolve(); }, observation);
        this.stopObservation = () => { clearTimeout(timer); this.stopObservation = null; resolve(); };
      });
    } catch (failure) { this.emit('failed', failure); }
    finally {
      this.stopObservation = null;
      if (prepared && call) {
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
          statusOnlyClosed = !prepared && closeConfirmed && validatePFNotionStatusOnlyCloseEvidence(closed.statusOnlyEvidence, runId); }
        catch (failure) { this.emit('stopping', failure); }
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
      this.state.cleanupUncertain = call != null && (!closeConfirmed || prepared && !this.state.cleanupComplete ||
        this.state.errorCode === 'PF_OWNED_RUNTIME_NOT_EMPTY' && !statusOnlyClosed);
      this.state.lifecyclePassed = this.state.resumed && this.state.cleanupComplete && !this.state.errorCode;
      this.state.active = false;
      advance(this.state.cleanupUncertain ? 'cleanup-required' : this.state.cleanupComplete ? 'cleaned' : 'failed');
    }
    return this.snapshot();
  }
}
