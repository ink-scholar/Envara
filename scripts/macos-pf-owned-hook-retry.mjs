// Controlled retry pinned to the reviewed single-FILTER installed snapshot. Historical runs remain in ignored diagnostics.
// No invocation is authorized by this file. The explicit user approval flag is required before resource checks.
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createPersistentPFHelperClient, verifyPFHelperInstallation } from './accept-macos-pf-routing.mjs';
import { runPFAcceptanceMatrix, PF_ACCEPTANCE_HELPER_ROOT, PF_ACCEPTANCE_PROTOCOL,
  validatePFControlledCleanupEvidence } from '../native/macos-pf-routing/acceptance-plan.mjs';
import { isPFRoutingRunId } from '../native/macos-pf-routing/policy.mjs';

export const RETRY_RESOURCE_PINS = Object.freeze({
  authorizationAppRelative: 'build/local-authorization/EnvaraPFAuthorization-6f8386e1586a.app',
  installedManifestSHA256: '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f',
  authorizerSHA256: 'da4b12697ad6561b86adc1754851c149ac4889b837d912f24c49a907060731ee',
});
export const RETRY_CASES = Object.freeze(['realm-identities', 'tcp-concurrent', 'tcp-half-close', 'dns-tcp53', 'udp-concurrent']);
export const RETRY_BUDGETS = Object.freeze({ nativeTotalMs: 180000, initialStatusMs: 60000, workMs: 110000,
  cleanupMs: 20000, localFinalizationReserveMs: 9000, postStatusMs: 5000, closeMs: 15000, closeGraceMs: 2000 });
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
const bool = value => typeof value === 'boolean' ? value : null;
const stages = new Set(['registry-lock', 'baseline-snapshot', 'root-hook-intent', 'root-hook-insert', 'root-hook-receipt',
  'owned-anchor-check', 'group-allocation', 'deny-rules', 'pf-reference', 'tunnel-start', 'fixture-start',
  'fixture-resume', 'socket-reservation', 'stateless-rules', 'fixture-commit']);
const caseStages = new Set(['state-before', 'rule-readback', 'process-before', 'challenge-validation', 'reservation',
  'probe-transport', 'probe-binding', 'process-after', 'state-after', 'evidence']);
const fixtureCodes = ['PROBE_TIMEOUT', 'PROBE_TRANSPORT_FAILED', 'PROBE_SIZE_LIMIT', 'INVALID_REQUEST', 'FORBIDDEN_ENDPOINT',
  'CHILD_UNAVAILABLE', 'CHILD_LIMIT', 'CLEANUP_UNVERIFIED', 'RESERVATION_REQUIRED', 'RESERVATION_UNAVAILABLE',
  'RESERVATION_LIMIT', 'REPLY_REFUSED', 'RPC_TIMEOUT'].map(code => `APPLICATION_PF_FIXTURE_${code}`);
const filterCodes = ['REPLACEMENT_UNCERTAIN', 'REPLACEMENT_UNCONFIRMED', 'AUTHENTICATED_ROOT_CONTROLLER_REQUIRED',
  'SIGNAL_BOUNDARY_UNAVAILABLE', 'BOUNDED_PRIVATE_INPUT_REQUIRED', 'INVALID_PRIVATE_FILTER_INPUT',
  'EXACT_ISSUED_LEASE_REQUIRED', 'SEALED_PENDING_FILTER_INTENT_REQUIRED', 'OWNED_FILTER_DEVICE_REFUSED',
  'PRIOR_FILTER_READBACK_REFUSED', 'GENERATED_FILTER_REPLACEMENT_REFUSED', 'INVALID_CONTEXT', 'INVALID_CONFIG',
  'ALREADY_USED', 'GUARD_REJECTED', 'BEGIN_FAILED', 'BEGIN_REPLY_INVALID', 'POOL_FAILED', 'POOL_REPLY_INVALID',
  'ADD_ADDRESS_FAILED', 'ADD_ADDRESS_REPLY_INVALID', 'ADD_RULE_FAILED', 'ADD_RULE_REPLY_INVALID',
  'COMMIT_FAILED', 'COMMIT_REPLY_INVALID', 'VERIFY_FAILED'].map(code => `APPLICATION_PF_FILTER_${code}`);
const udpCountKeys = ['udpAssociations', 'udpPacketsReceived', 'udpPeerRejected', 'udpHeaderRejected', 'udpDestinationRejected',
  'udpChallengeRejected', 'udpDNSRejected', 'udpRepliesQueued', 'udpReplySendFailed', 'udpSocketErrors'];
const phases = new Set(['preparing', 'fixtures-running', 'fault', 'transport-fault', 'cleaning', 'cleaned', 'cleanup-required']);
const reasons = new Set([
  ...fixtureCodes,
  ...filterCodes,
  'APPLICATION_ROUTING_NOT_READY', 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'APPLICATION_ROUTING_PROTOCOL_ERROR',
  'APPLICATION_ROUTING_CLOSED', 'APPLICATION_ROUTING_TIMEOUT', 'APPLICATION_ROUTING_UNAVAILABLE',
  'APPLICATION_PROXY_UNAVAILABLE', 'APPLICATION_PF_HOOK_READ_REFUSED',
  'APPLICATION_PF_HOOK_WRITE_REFUSED', 'APPLICATION_PF_HOOK_SIGNAL_REFUSED', 'APPLICATION_PF_HOOK_INPUT_REFUSED',
  'APPLICATION_PF_HOOK_HOST_REFUSED', 'APPLICATION_PF_HOOK_PREFLIGHT_REFUSED', 'APPLICATION_PF_HOOK_CLEANUP_REFUSED',
  'APPLICATION_PF_HOOK_CLEANUP_UNCONFIRMED', 'APPLICATION_PF_HOOK_PREFLIGHT_CHANGED', 'APPLICATION_PF_HOOK_INSERT_UNCONFIRMED',
  'APPLICATION_PF_NAMESPACE_CLEANUP_PENDING',
  'PF_UDP_SIZE_DIAGNOSTIC_SCOPE_INVALID', 'PF_ACCEPTANCE_RESPONSE_INVALID', 'PF_ACCEPTANCE_OPTIONS_INVALID', 'PF_ACCEPTANCE_ABORTED', 'PF_ACCEPTANCE_DEADLINE',
  'PF_ACCEPTANCE_PREFLIGHT_REQUIRED', 'PF_STATELESS_CONTROLLED_PREFLIGHT_REQUIRED', 'PF_ACCEPTANCE_CASES_UNAVAILABLE',
  'PF_OWNED_ROOT_HOOK_EVIDENCE_REQUIRED', 'PF_FOREIGN_STATE_PREFLIGHT_EVIDENCE_REQUIRED', 'PF_NATIVE_EVIDENCE_INCOMPLETE',
  'PF_NATIVE_ACCEPTANCE_INCOMPLETE', 'PF_UNBOUND_CONTROL_FAILED', 'PF_ACCEPTANCE_OPERATION_FAILED',
  'PF_ACCEPTANCE_REALM_IDENTITY_INVALID', 'PF_ACCEPTANCE_CASE_ID_MISMATCH', 'PF_STATELESS_NATIVE_EVIDENCE_REQUIRED',
  'PF_HELPER_CLEANUP_UNCERTAIN', 'PF_HELPER_REQUEST_INVALID', 'PF_HELPER_RESPONSE_INVALID', 'PF_HELPER_RESPONSE_TOO_LARGE',
  'PF_HELPER_INPUT_FAILED', 'PF_HELPER_UNEXPECTED_EXIT', 'PF_HELPER_UNAVAILABLE', 'PF_HELPER_ABORTED', 'PF_HELPER_DEADLINE',
  'PF_HELPER_CHANNEL_CLOSED', 'PF_HELPER_REQUEST_TOO_LARGE', 'PF_HELPER_PATH_INVALID', 'PF_HELPER_INSTALLATION_PATH_REJECTED',
  'PF_HELPER_INSTALLATION_UNTRUSTED', 'PF_HELPER_MANIFEST_INVALID', 'PF_HELPER_HASH_MISMATCH',
  'PF_RETRY_PINS_PENDING', 'PF_RETRY_PIN_MISMATCH', 'PF_RETRY_AUTHORIZE_FLAG_REQUIRED', 'PF_RETRY_SIGNATURE_REFUSED',
  'PF_RETRY_PLATFORM_REQUIRED', 'PF_RETRY_OPERATION_FAILED', 'PF_RETRY_TOTAL_DEADLINE', 'PF_RETRY_CLEANUP_BUDGET_EXHAUSTED',
  'PF_RETRY_POST_STATUS_UNAVAILABLE', 'PF_RETRY_RUN_ID_MISMATCH', 'PF_RETRY_CLEANUP_INCOMPLETE', 'PF_RETRY_METHOD_REFUSED',
]);
const reason = value => reasons.has(value) ? value : 'PF_RETRY_OPERATION_FAILED';
const failed = code => Object.assign(new Error('Owned PF retry refused'), { code });
export const safeRetryError = error => ({ reason: reason(error?.reason ?? error?.code), ...(stages.has(error?.stage) ? { stage: error.stage } : {}) });
const safeCaseFailure = value => value && RETRY_CASES.includes(value.caseId) && caseStages.has(value.stage)
  ? { caseId: value.caseId, stage: value.stage, code: reason(value.code) } : null;
export function safeUDPSizeDiagnostics(value) {
  if (!Array.isArray(value)) return [];
  const entries = value.slice(0, 6).filter(item => ['one', 'two'].includes(item?.slot) &&
    ['parent', 'child', 'detached'].includes(item?.role) && [1200, 2048].includes(item?.payloadBytes));
  if (new Set(entries.map(item => `${item.slot}/${item.role}`)).size !== entries.length) return [];
  return entries.map(item => ({ slot: item.slot, role: item.role, payloadBytes: item.payloadBytes,
    authenticatedFixtureReceipts: Number.isSafeInteger(item.authenticatedFixtureReceipts) && item.authenticatedFixtureReceipts >= 0 &&
      item.authenticatedFixtureReceipts <= 128 ? item.authenticatedFixtureReceipts : null }));
}
export function safeFixtureUDPDiagnostics(value) {
  if (!Array.isArray(value)) return [];
  const selected = value.slice(0, 2).filter(item => ['one', 'two'].includes(item?.slot));
  if (new Set(selected.map(item => item.slot)).size !== selected.length) return [];
  return selected.map(item => ({ slot: item.slot, source: item.source === 'owned-loopback-socks' ? item.source : 'UNRECOGNIZED',
    routingEvidence: false, counts: item.counts && typeof item.counts === 'object' && !Array.isArray(item.counts)
      ? Object.fromEntries(udpCountKeys.map(key => [key, Number.isSafeInteger(item.counts[key]) && item.counts[key] >= 0 && item.counts[key] <= 1048576 ? item.counts[key] : null])) : null }));
}
const preparationFailure = value => value && stages.has(value.stage) ? { stage: value.stage, reason: reason(value.code) } : null;
const statusKeys = ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized', 'privilegedRuntimeVerified',
  'stockAppleAnchorHookVerified', 'ownedRootHookCanCreate', 'ownedRootHookVerified', 'priorPFAnchorsCompatible', 'fixtureEgressSkipVerified', 'lo0SkipVerified',
  'statelessControlledFixtures', 'noStateNativeAvailable', 'ready', 'protectedLaunchAllowed', 'readOnly'];
export function safeRetryStatus(value) {
  if (!value || typeof value !== 'object') return null;
  return { ...Object.fromEntries(statusKeys.map(key => [key, bool(value[key])])),
    runs: Array.isArray(value.runs) ? value.runs.slice(0, 32).filter(run => uuid(run?.runId)).map(run => ({ runId: run.runId,
      phase: phases.has(run.phase) ? run.phase : 'UNRECOGNIZED', cleanupUncertain: bool(run.cleanupUncertain), caseFailure: safeCaseFailure(run.caseFailure) })) : [],
    runsTruncated: Array.isArray(value.runs) && value.runs.length > 32 };
}
const cleanupKeys = ['ownedProcessesExited', 'ownedAnchorStatesPurged', 'ownedTunnelsRemoved', 'ownedAnchorRemoved', 'unrelatedPFUnchanged',
  'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'ownedRootHookRemoved', 'originalRootRestored', 'ownedPFReferenceReleased',
  'noOwnedStatesCreatedVerified', 'noOwnedStatesRemainVerified', 'cleanupUncertain', 'namespaceReclaimed', 'receiptRetired'];
const safeNamespaceState = value => ['absent', 'present', 'unknown'].includes(value) ? value : 'unknown';
export function safeRetryCleanup(value, runId) {
  if (!value || value.runId !== runId || value.acceptanceProtocol !== PF_ACCEPTANCE_PROTOCOL || value.acceptanceOnly !== true ||
      value.ready !== false || value.productionReceiptAllowed !== false) return { receiptValid: false, reason: 'PF_ACCEPTANCE_RESPONSE_INVALID' };
  const evidence = value.evidence;
  return { receiptValid: true, runId, ...Object.fromEntries(cleanupKeys.map(key => [key, bool(value[key])])),
    namespaceState: safeNamespaceState(value.namespaceState),
    preparationFailure: preparationFailure(value.preparationFailure), caseFailure: safeCaseFailure(value.caseFailure),
    nativeControlledEvidenceAccepted: validatePFControlledCleanupEvidence(evidence),
    evidence: evidence && typeof evidence === 'object' ? {
      source: ['native-pf', 'simulated'].includes(evidence.source) ? evidence.source : 'UNRECOGNIZED',
      platform: evidence.platform === 'darwin' ? 'darwin' : 'UNRECOGNIZED', complete: bool(evidence.complete),
      namespaceState: safeNamespaceState(evidence.namespaceState),
      ...Object.fromEntries(cleanupKeys.map(key => [key, bool(evidence[key])])),
    } : null };
}
function safeMatrixReport(value) {
  const allowedChecks = new Set([...RETRY_CASES, 'cleanup', 'owned-root-hook-prepare', 'unbound-loopback-before', 'unbound-loopback-final',
    ...RETRY_CASES.map(id => `unbound-loopback-after-${id}`)]);
  return { nativeRoutingAttempted: value?.nativeRoutingAttempted === true, selectedCasesPassed: value?.selectedCasesPassed === true,
    localFixturesClosed: bool(value?.localFixturesClosed), fixtureUDPDiagnostics: safeFixtureUDPDiagnostics(value?.fixtureUDPDiagnostics),
    controlledUDPSizeDiagnostic: bool(value?.controlledUDPSizeDiagnostic), udpSizeDiagnostics: safeUDPSizeDiagnostics(value?.udpSizeDiagnostics), reason: value?.reason == null ? null : reason(value.reason),
    checks: Object.fromEntries(Object.entries(value?.checks ?? {}).filter(([id]) => allowedChecks.has(id)).map(([id, check]) =>
      [id, { passed: bool(check?.passed), nativeVerified: bool(check?.nativeVerified), ...(check?.code ? { reason: reason(check.code) } : {}) }])),
    cleanup: value?.cleanup ? { confirmed: bool(value.cleanup.confirmed), uncertain: bool(value.cleanup.uncertain) } : null };
}

/** Only injected call is used. Tests inject stubs; CLI pins its one native relay.
 * No private response/lease, params/slots, payload, credentials, or subprocess
 * output is copied to the report. Post-status is collected before close/EOF. */
export async function runOwnedHookRetrySession({ call, matrix = runPFAcceptanceMatrix, now = () => performance.now(),
  runId: candidateRunId = randomUUID() } = {}) {
  if (typeof call !== 'function' || typeof call.close !== 'function' || typeof matrix !== 'function') throw failed('PF_RETRY_METHOD_REFUSED');
  if (!isPFRoutingRunId(candidateRunId)) throw failed('PF_RETRY_RUN_ID_MISMATCH');
  const started = now(), deadline = started + RETRY_BUDGETS.nativeTotalMs;
  const trace = [], cleanupReceipts = []; let runId = null, initialStatus = null, matrixValue = null,
    operationError = null, postStatus = null, postStatusError = null, transport = null, cleanupStarted = null, actualWorkMs = null;
  const remaining = reserve => Math.floor(deadline - now() - reserve);
  const wrapped = async (method, params = {}, options = {}) => {
    if (!['status', 'prepareOwnedFixtures', 'runOwnedFixtureCase', 'cleanupOwnedFixtures'].includes(method)) throw failed('PF_RETRY_METHOD_REFUSED');
    if (method === 'status' && Object.hasOwn(params, 'runId') && params.runId !== candidateRunId) throw failed('PF_RETRY_RUN_ID_MISMATCH');
    if (method === 'prepareOwnedFixtures') {
      if (params.runId !== candidateRunId) throw failed('PF_RETRY_RUN_ID_MISMATCH');
      runId = candidateRunId; // Record an attempted prepare BEFORE it can fail.
    }
    if (['runOwnedFixtureCase', 'cleanupOwnedFixtures'].includes(method) && (!runId || params.runId !== runId)) throw failed('PF_RETRY_RUN_ID_MISMATCH');
    if (method === 'runOwnedFixtureCase' && !RETRY_CASES.includes(params.caseId)) throw failed('PF_RETRY_METHOD_REFUSED');
    if (method === 'cleanupOwnedFixtures') cleanupStarted ??= now();
    // Existing matrix finalization closes both local SOCKS fixtures (<=1.5s
    // concurrently), checks existing/fresh loopback (<=6s), and closes the
    // loopback control (<=1s). Reserve 9s before post-status and native EOF.
    const reserve = RETRY_BUDGETS.closeMs + (method === 'cleanupOwnedFixtures'
      ? RETRY_BUDGETS.postStatusMs + RETRY_BUDGETS.localFinalizationReserveMs : 0);
    const available = Math.min(remaining(reserve), method === 'cleanupOwnedFixtures' ? cleanupStarted + RETRY_BUDGETS.cleanupMs - now() : 60000);
    if (available < 1) throw failed(method === 'cleanupOwnedFixtures' ? 'PF_RETRY_CLEANUP_BUDGET_EXHAUSTED' : 'PF_RETRY_TOTAL_DEADLINE');
    const timeoutMs = Math.max(1, Math.floor(Math.min(options.timeoutMs ?? 15000, available)));
    const item = { method, startedMs: Math.floor(now() - started), ...(runId ? { runId } : {}),
      ...(method === 'runOwnedFixtureCase' ? { caseId: params.caseId } : {}) }; trace.push(item);
    try {
      const value = await call(method, params, { ...options, timeoutMs }); item.returned = true;
      if (method === 'cleanupOwnedFixtures') cleanupReceipts.push(safeRetryCleanup(value, runId));
      return value; // Raw response remains in memory only for the existing validators.
    } catch (error) { item.returned = false; item.error = safeRetryError(error); throw error; }
    finally { item.elapsedMs = Math.max(0, Math.floor(now() - started) - item.startedMs); }
  };
  try {
    initialStatus = await wrapped('status', { runId: candidateRunId }, { timeoutMs: RETRY_BUDGETS.initialStatusMs });
    // Let the human finish the native authorization prompt for up to 60s.
    // Its actual elapsed time reduces fixture work; cleanup/status/EOF keep
    // their own reserves inside the same 180s controlled-runtime ceiling.
    actualWorkMs = Math.min(RETRY_BUDGETS.workMs, remaining(RETRY_BUDGETS.cleanupMs + RETRY_BUDGETS.localFinalizationReserveMs
      + RETRY_BUDGETS.postStatusMs + RETRY_BUDGETS.closeMs));
    if (actualWorkMs < 1000) throw failed('PF_RETRY_TOTAL_DEADLINE');
    let firstMatrixStatus = true;
    matrixValue = await matrix({ runId: candidateRunId, controlledCaseIds: [...RETRY_CASES], controlledUDPSizeDiagnostic: false, workTimeoutMs: actualWorkMs, cleanupTimeoutMs: RETRY_BUDGETS.cleanupMs,
      call: (method, params = {}, options) => {
        if (method === 'status' && firstMatrixStatus) {
          firstMatrixStatus = false;
          if (params.runId === candidateRunId && Object.keys(params).length === 1) return Promise.resolve(initialStatus);
        }
        return wrapped(method, params, options);
      } });
  } catch (error) { operationError = safeRetryError(error); }
  finally {
    // Matrix already attempts cleanup after prepare is called, including a
    // rejected prepare. Only if it did not request cleanup do it here, once.
    if (runId && !trace.some(item => item.method === 'cleanupOwnedFixtures')) {
      try { await wrapped('cleanupOwnedFixtures', { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL, runId }, { timeoutMs: RETRY_BUDGETS.cleanupMs }); }
      catch (error) { cleanupReceipts.push({ receiptValid: false, runId, error: safeRetryError(error) }); }
    }
    // This read includes safe run phases even if prepare failed or cleanup's
    // evidence is incomplete. It MUST happen before EOF/transport.close.
    try { postStatus = safeRetryStatus(await wrapped('status', {}, { timeoutMs: RETRY_BUDGETS.postStatusMs })); }
    catch (error) { postStatusError = safeRetryError(error); }
    try {
      const closeBudget = Math.max(1, Math.min(RETRY_BUDGETS.closeMs, remaining(0)) - RETRY_BUDGETS.closeGraceMs);
      const value = await call.close({ timeoutMs: Math.max(1, closeBudget) });
      transport = { closed: bool(value?.closed), started: bool(value?.started), cleanupUncertain: bool(value?.cleanupUncertain) };
    } catch (error) { transport = { closed: false, cleanupUncertain: true, error: safeRetryError(error) }; }
  }
  const matrixSummary = safeMatrixReport(matrixValue), receipt = cleanupReceipts.at(-1) ?? null;
  const observedRun = postStatus?.runs.find(run => run.runId === runId) ?? null;
  const diagnosticsComplete = postStatus !== null && transport?.closed === true && transport.cleanupUncertain === false;
  const cleanupConfirmed = receipt?.nativeControlledEvidenceAccepted === true && observedRun?.phase === 'cleaned' && observedRun.cleanupUncertain === false;
  const selectedCasesPassed = matrixSummary.selectedCasesPassed && cleanupConfirmed && diagnosticsComplete;
  return { schema: PF_ACCEPTANCE_PROTOCOL, operation: 'owned-hook-retry', checkedAt: new Date().toISOString(), runId,
    acceptanceOnly: true, ready: false, productionReady: false, productionReceiptAllowed: false, fullMatrix: false, nativeRoutingAcceptance: false,
    selectedCases: [...RETRY_CASES], budgets: { ...RETRY_BUDGETS, actualWorkMs }, elapsedMs: Math.max(0, Math.floor(now() - started)),
    ...matrixSummary, selectedCasesPassed, preparationAttempted: trace.some(item => item.method === 'prepareOwnedFixtures'),
    nativeFixtureCasesAttempted: trace.some(item => item.method === 'runOwnedFixtureCase'),
    initialStatus: safeRetryStatus(initialStatus), cleanupReceipts, postStatusBeforeEOF: postStatus, postStatusError, observedRun,
    diagnosticsComplete, cleanupConfirmed, transport, trace, operationError,
    reason: operationError?.reason ?? matrixSummary.reason ?? (transport?.cleanupUncertain !== false
      ? 'PF_HELPER_CLEANUP_UNCERTAIN' : postStatus === null ? 'PF_RETRY_POST_STATUS_UNAVAILABLE'
      : !cleanupConfirmed ? 'PF_RETRY_CLEANUP_INCOMPLETE' : null) };
}

export function assertRetryPins(pins = RETRY_RESOURCE_PINS) {
  if (!/^[0-9a-f]{64}$/.test(pins.installedManifestSHA256 ?? '') || !/^[0-9a-f]{64}$/.test(pins.authorizerSHA256 ?? '') ||
      typeof pins.authorizationAppRelative !== 'string' || !/^build\/local-authorization\/EnvaraPFAuthorization-[0-9a-f]{12}\.app$/.test(pins.authorizationAppRelative)) throw failed('PF_RETRY_PINS_PENDING');
  return path.join(root, pins.authorizationAppRelative);
}
async function streamHash(filename) {
  const before = await fs.lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.size > 150 * 1024 * 1024) throw failed('PF_RETRY_PIN_MISMATCH');
  const hash = createHash('sha256'); for await (const bytes of createReadStream(filename, { highWaterMark: 65536 })) hash.update(bytes);
  const after = await fs.lstat(filename);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw failed('PF_RETRY_PIN_MISMATCH');
  return hash.digest('hex');
}
async function verifySignature(application) {
  await new Promise((resolve, reject) => execFile('/usr/bin/codesign', ['--verify', '--strict', application],
    { timeout: 10000, maxBuffer: 65536 }, error => error ? reject(failed('PF_RETRY_SIGNATURE_REFUSED')) : resolve()));
}
export async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 1 || argv[0] !== '--explicit-user-approved') throw failed('PF_RETRY_AUTHORIZE_FLAG_REQUIRED');
  if (process.platform !== 'darwin' || process.getuid?.() === 0) throw failed('PF_RETRY_PLATFORM_REQUIRED');
  const application = assertRetryPins(), authorizer = path.join(application, 'Contents/Resources/app-routing/macos-pf/EnvaraPFInstall');
  if (await streamHash(authorizer) !== RETRY_RESOURCE_PINS.authorizerSHA256) throw failed('PF_RETRY_PIN_MISMATCH');
  await verifySignature(application); await verifyPFHelperInstallation();
  if (await streamHash(path.join(PF_ACCEPTANCE_HELPER_ROOT, 'manifest.json')) !== RETRY_RESOURCE_PINS.installedManifestSHA256) throw failed('PF_RETRY_PIN_MISMATCH');
  // Exactly one persistent native relay. No controller/installer alteration.
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawn(authorizer, ['--request-controlled-experiment'],
    { cwd: '/', env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, stdio: ['pipe', 'pipe', 'pipe'] }) });
  const report = await runOwnedHookRetrySession({ call }); report.installedManifestSHA256 = RETRY_RESOURCE_PINS.installedManifestSHA256;
  const destination = path.join(root, 'test-artifacts/mac-pf-routing', `owned-hook-retry-${Date.now()}-${randomUUID()}.json`);
  await fs.writeFile(destination, JSON.stringify(report, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ reportPath: destination, runId: report.runId, selectedCasesPassed: report.selectedCasesPassed,
    reason: report.reason, nativeFixtureCasesAttempted: report.nativeFixtureCasesAttempted, cleanupConfirmed: report.cleanupConfirmed,
    diagnosticsComplete: report.diagnosticsComplete, productionReady: false }));
  if (!report.selectedCasesPassed) process.exitCode = 1;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.log(JSON.stringify({ operation: 'refused', acceptanceOnly: true, productionReady: false, ...safeRetryError(error) })); process.exitCode = 1; });
}
