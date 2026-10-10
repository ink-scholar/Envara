#!/usr/bin/env node
// This driver is inert on import. Its CLI requires a separately approved native
// test and exact reviewed carrier pins. Private route settings enter stdin only.
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, execFile } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { createPersistentPFHelperClient, verifyPFHelperInstallation, validatePFNotionCleanupReceipt, validatePFNotionPrestageCleanupReceipt, validatePFNotionPreflightCleanupReceipt } from './accept-macos-pf-routing.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const failed = code => Object.assign(new Error('Bounded Notion acceptance did not complete'), { code });
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const bool = value => typeof value === 'boolean' ? value : null;
const phases = new Set(['preparing', 'staged', 'running', 'stopping', 'cleaned', 'cleanup-required', 'prestage-aborted', 'prestage-stopping', 'prestage-cleaned',
  'preflight-aborted', 'preflight-stopping', 'preflight-cleaned']);
const appStages = new Set(['register', 'registry-lock', 'root-hook', 'group-allocation', 'sealed-context', 'pf-reference', 'transport', 'cold-stage', 'resume', 'cleanup']);
const nativeStages = new Set(['register', 'preflight', 'gui-session', 'route-read', 'transport-start', 'front-listen', 'front-spawn', 'front-handshake', 'factory-open', 'deny-commit', 'transport-ack', 'front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']);
const registerReasons = new Set(['INVALID_NATIVE_APP_REQUEST', 'FIXED_ROOT_NATIVE_ENTRY_REQUIRED', 'APP_REGISTRY_UNAVAILABLE', 'NATIVE_APP_OPERATION_REFUSED']);
const flags = ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'];
const cleanupKeys = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
  'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
  'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const prestageCleanupKeys = ['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
  'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
  'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged',
  'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const prestageFalseKeys = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted'];
const preflightCleanupKeys = ['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
  'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
  'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
  'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const preflightFalseKeys = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted'];
const cleanupConfirmed = (value, runId) => validatePFNotionCleanupReceipt(value, runId) || validatePFNotionPrestageCleanupReceipt(value, runId) || validatePFNotionPreflightCleanupReceipt(value, runId);
const errorCodes = new Set(['PF_NOTION_APPROVAL_REQUIRED', 'PF_NOTION_INPUT_INVALID', 'PF_NOTION_PLATFORM_REQUIRED', 'PF_NOTION_PINS_REQUIRED', 'PF_NOTION_PIN_MISMATCH',
  'PF_NOTION_SIGNATURE_REFUSED', 'PF_NOTION_STATUS_REFUSED', 'PF_NOTION_STAGE_UNCONFIRMED', 'PF_NOTION_RESUME_UNCONFIRMED', 'PF_NOTION_CLEANUP_UNCONFIRMED', 'PF_NOTION_DEADLINE',
  'PF_NOTION_OPERATION_FAILED', 'PF_HELPER_REQUEST_INVALID', 'PF_HELPER_CLEANUP_UNCERTAIN', 'PF_HELPER_ABORTED', 'PF_HELPER_DEADLINE', 'PF_HELPER_CHANNEL_CLOSED',
  'PF_HELPER_UNAVAILABLE', 'PF_HELPER_UNEXPECTED_EXIT', 'PF_HELPER_RESPONSE_INVALID', 'PF_HELPER_RESPONSE_TOO_LARGE', 'PF_HELPER_INPUT_FAILED',
  'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', 'APPLICATION_ROUTING_NOT_READY', 'APPLICATION_PROXY_UNAVAILABLE', 'APPLICATION_ROUTING_PROTOCOL_ERROR',
  'APPLICATION_APP_CONTEXT_REFUSED', 'APPLICATION_APP_IDENTITY_REFUSED', 'APPLICATION_APP_NATIVE_REFUSED', 'APPLICATION_APP_STAGE_UNCONFIRMED',
  'APPLICATION_APP_TRANSPORT_UNCONFIRMED', 'APPLICATION_APP_STAGE_TIMEOUT', 'APPLICATION_APP_RESUME_TIMEOUT', 'APPLICATION_APP_RESUME_UNCONFIRMED', 'APPLICATION_APP_CLEANUP_UNCONFIRMED', 'APPLICATION_NATIVE_REFUSED']);
const safeError = error => ({ code: errorCodes.has(error?.code) ? error.code : 'PF_NOTION_OPERATION_FAILED' });
export function safeNotionResponse(value, runId, environmentId) {
  if (!value || value.runId !== runId || value.environmentId !== environmentId) return { responseBound: false };
  const failure = value.failure;
  return { responseBound: true, phase: phases.has(value.phase) ? value.phase : 'UNRECOGNIZED', profile: value.profile === 'seatbelt-front-only' ? value.profile : 'UNRECOGNIZED',
    ...Object.fromEntries([...flags, 'staged', 'resumed', 'prestageAborted', 'preflightAborted', 'cleanupUncertain', 'cleanupComplete'].map(key => [key, bool(value[key])])),
    failure: failure && appStages.has(failure.stage) ? { stage: failure.stage, ...safeError(failure),
      ...(failure.native && Object.keys(failure.native).sort().join('|') === 'error|reason|stage' && nativeStages.has(failure.native.stage) &&
        (failure.native.stage === 'register' ? registerReasons.has(failure.native.reason) : failure.native.reason === 'NATIVE_OPERATION_REFUSED') &&
        Number.isInteger(failure.native.error) && failure.native.error > 0 && failure.native.error <= 1024
        ? { native: { stage: failure.native.stage, reason: failure.native.reason, error: failure.native.error } } : {}) } : null,
    cleanupEvidence: validatePFNotionCleanupReceipt(value, runId) ? { schema: value.cleanupEvidence.schema, source: 'native-notion-controller',
      complete: true, cleanupUncertain: false, ...Object.fromEntries(cleanupKeys.map(key => [key, true])) } :
      validatePFNotionPrestageCleanupReceipt(value, runId) ? { schema: value.cleanupEvidence.schema, source: 'native-notion-controller',
        complete: true, cleanupUncertain: false, ...Object.fromEntries(prestageCleanupKeys.map(key => [key, true])),
        ...Object.fromEntries(prestageFalseKeys.map(key => [key, false])) } :
      validatePFNotionPreflightCleanupReceipt(value, runId) ? { schema: value.cleanupEvidence.schema, source: 'native-notion-controller',
        complete: true, cleanupUncertain: false, ...Object.fromEntries(preflightCleanupKeys.map(key => [key, true])),
        ...Object.fromEntries(preflightFalseKeys.map(key => [key, false])) } : null };
}
const statusKeys = ['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized', 'privilegedRuntimeVerified',
  'ownedRootHookCanCreate', 'priorPFAnchorsCompatible', 'lo0FilteringVerified', 'ready', 'protectedLaunchAllowed'];
const safeStatus = value => Object.fromEntries(statusKeys.map(key => [key, bool(value?.[key])]));

/** Calls only the injected persistent client. Tests never start a native entry. */
export async function runPFNotionAcceptance({ call, routeRequest, beforeResume, observe = delay, observationMs = 5000,
  runId = randomUUID(), environmentId = randomUUID(), now = () => performance.now() } = {}) {
  if (typeof call !== 'function' || typeof call.close !== 'function' || typeof beforeResume !== 'function' || typeof observe !== 'function' ||
      !uuid(runId) || !uuid(environmentId) || !Number.isInteger(observationMs) || observationMs < 0 || observationMs > 20000 ||
      !routeRequest || Object.keys(routeRequest).sort().join('|') !== 'application|managedRoute|route|workspace') throw failed('PF_NOTION_INPUT_INVALID');
  const started = now(), deadline = started + 180000;
  const report = { schema: 'envara.macos-pf-notion-acceptance/v1', runId, environmentId, profile: 'seatbelt-front-only',
    ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false,
    applicationTrafficVerified: false, trace: [], status: null, cleanup: null, snapshot: null, transport: null,
    resumed: false, prestageAborted: false, preflightAborted: false, cleanupConfirmed: false, operationError: null };
  let attempted = false;
  const rpc = async (method, params, maximumMs, reserveMs = 40000) => {
    const timeoutMs = Math.floor(Math.min(maximumMs, deadline - now() - reserveMs));
    if (timeoutMs < 1) throw failed('PF_NOTION_DEADLINE');
    const item = { method, startedMs: Math.max(0, Math.floor(now() - started)) }; report.trace.push(item);
    try { const response = await call(method, params, { timeoutMs }); item.completed = true;
      if (method !== 'status' && method !== 'prepareRoute') item.response = safeNotionResponse(response, runId, environmentId);
      return response;
    } catch (error) { item.completed = false; item.error = safeError(error); throw error; }
  };
  try {
    const status = await rpc('status', {}, 60000); report.status = safeStatus(status);
    if (['rootOwnedInstallationVerified', 'callerConsoleUIDVerified', 'privilegedOperationsAuthorized', 'privilegedRuntimeVerified', 'lo0FilteringVerified'].some(key => status[key] !== true) ||
        status.ready !== false || status.protectedLaunchAllowed !== false) throw failed('PF_NOTION_STATUS_REFUSED');
    const route = await rpc('prepareRoute', routeRequest, 15000);
    if (typeof route?.routeId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(route.routeId)) throw failed('PF_NOTION_STAGE_UNCONFIRMED');
    attempted = true; // A lost prepare reply still requires explicit cleanup.
    const prepared = await rpc('prepareNotionApplication', { routeId: route.routeId, runId, environmentId, lifetimeSeconds: 180, activationAuthorized: true }, 20000);
    if (prepared.runId !== runId || prepared.environmentId !== environmentId || prepared.phase !== 'staged' || prepared.staged !== true || prepared.resumed !== false ||
        prepared.cleanupUncertain !== false || flags.some(key => prepared[key] !== false)) throw failed('PF_NOTION_STAGE_UNCONFIRMED');
    // The CLI supplies an actual fixed Notion codesign check. This callback is
    // separate from the native guardian's executed image/CDhash verification.
    if (await beforeResume() !== true) throw failed('PF_NOTION_SIGNATURE_REFUSED');
    const running = await rpc('resumeNotionApplication', { runId, activationAuthorized: true }, 15000);
    if (running.runId !== runId || running.environmentId !== environmentId || running.phase !== 'running' || running.resumed !== true || running.cleanupUncertain !== false ||
        flags.some(key => running[key] !== false)) throw failed('PF_NOTION_RESUME_UNCONFIRMED');
    report.resumed = true;
    if (deadline - now() - observationMs < 40000) throw failed('PF_NOTION_DEADLINE');
    await observe(observationMs);
  } catch (error) { report.operationError = safeError(error); }
  finally {
    if (attempted) {
      try { const cleanup = await rpc('stopNotionApplication', { runId }, 25000, 20000); report.cleanup = safeNotionResponse(cleanup, runId, environmentId);
        report.cleanupConfirmed = cleanup.environmentId === environmentId && cleanupConfirmed(cleanup, runId);
        report.prestageAborted = cleanup.environmentId === environmentId && validatePFNotionPrestageCleanupReceipt(cleanup, runId);
        report.preflightAborted = cleanup.environmentId === environmentId && validatePFNotionPreflightCleanupReceipt(cleanup, runId);
        if (!report.cleanupConfirmed) report.operationError ??= safeError(failed('PF_NOTION_CLEANUP_UNCONFIRMED'));
      } catch (error) { report.cleanup = { error: safeError(error) }; }
      try { const snapshot = await rpc('applicationSnapshot', { runId }, 5000, 15000); report.snapshot = safeNotionResponse(snapshot, runId, environmentId);
        if (snapshot.environmentId !== environmentId || !cleanupConfirmed(snapshot, runId) ||
            validatePFNotionPrestageCleanupReceipt(snapshot, runId) !== report.prestageAborted ||
            validatePFNotionPreflightCleanupReceipt(snapshot, runId) !== report.preflightAborted) report.cleanupConfirmed = false;
      } catch (error) { report.snapshot = { error: safeError(error) }; report.cleanupConfirmed = false; }
    }
    try { const closed = await call.close({ timeoutMs: 15000 }); report.transport = { closed: bool(closed?.closed), started: bool(closed?.started), cleanupUncertain: bool(closed?.cleanupUncertain) };
      if (closed?.closed !== true || closed?.cleanupUncertain !== false) report.cleanupConfirmed = false;
    } catch (error) { report.transport = { error: safeError(error), cleanupUncertain: true }; report.cleanupConfirmed = false; }
  }
  report.elapsedMs = Math.max(0, Math.floor(now() - started)); report.lifecyclePassed = report.resumed && !report.prestageAborted && !report.preflightAborted && report.cleanupConfirmed && report.operationError === null;
  return report;
}

async function streamHash(filename) {
  const before = await fs.lstat(filename);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.mode & 0o022 || await fs.realpath(filename) !== filename) throw failed('PF_NOTION_PIN_MISMATCH');
  const hash = createHash('sha256'); for await (const chunk of createReadStream(filename)) hash.update(chunk);
  const after = await fs.lstat(filename);
  if (['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs'].some(key => before[key] !== after[key])) throw failed('PF_NOTION_PIN_MISMATCH');
  return hash.digest('hex');
}
async function verifySignature(application) {
  try { await new Promise((resolve, reject) => execFile('/usr/bin/codesign', ['--verify', '--strict', application],
    { timeout: 10000, maxBuffer: 16384, env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } }, error => error ? reject(error) : resolve())); return true;
  } catch { throw failed('PF_NOTION_SIGNATURE_REFUSED'); }
}
async function privateInput(input) {
  let bytes = Buffer.alloc(0);
  try { for await (const chunk of input) { bytes = Buffer.concat([bytes, chunk]); if (bytes.length > 32768) throw failed('PF_NOTION_INPUT_INVALID'); }
    return JSON.parse(bytes.toString('utf8'));
  } catch { throw failed('PF_NOTION_INPUT_INVALID'); } finally { bytes.fill(0); }
}
export async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 1 || argv[0] !== '--explicit-user-approved-notion-test') throw failed('PF_NOTION_APPROVAL_REQUIRED');
  if (process.platform !== 'darwin') throw failed('PF_NOTION_PLATFORM_REQUIRED');
  const authorizer = process.env.ENVARA_NOTION_AUTHORIZER, authorizerSHA = process.env.ENVARA_NOTION_AUTHORIZER_SHA256,
    manifestSHA = process.env.ENVARA_NOTION_MANIFEST_SHA256, observationMs = Number(process.env.ENVARA_NOTION_OBSERVE_MS ?? '5000');
  const suffix = '/Contents/Resources/app-routing/macos-pf/EnvaraPFInstall';
  if (typeof authorizer !== 'string' || !path.isAbsolute(authorizer) || /[\0\r\n]/.test(authorizer) || !authorizer.endsWith(`.app${suffix}`) ||
      !/^[0-9a-f]{64}$/.test(authorizerSHA ?? '') || !/^[0-9a-f]{64}$/.test(manifestSHA ?? '') || !Number.isInteger(observationMs) || observationMs < 0 || observationMs > 20000) throw failed('PF_NOTION_PINS_REQUIRED');
  if (await streamHash(authorizer) !== authorizerSHA || await streamHash(path.join(path.dirname(authorizer), 'manifest.json')) !== manifestSHA ||
      await streamHash('/Library/PrivilegedHelperTools/io.envara.pf-routing/manifest.json') !== manifestSHA) throw failed('PF_NOTION_PIN_MISMATCH');
  await verifySignature(authorizer.slice(0, -suffix.length)); await verifyPFHelperInstallation(); await verifySignature('/Applications/Notion.app');
  const routeRequest = await privateInput(process.stdin);
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawn(authorizer, ['--request-controlled-experiment'],
    { shell: false, stdio: ['pipe', 'pipe', 'pipe'], cwd: '/', env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } }) });
  const report = await runPFNotionAcceptance({ call, routeRequest, beforeResume: () => verifySignature('/Applications/Notion.app'), observationMs });
  const directory = path.join(root, 'test-artifacts/mac-pf-routing'); await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const filename = path.join(directory, `notion-acceptance-${Date.now()}-${report.runId}.json`);
  await fs.writeFile(filename, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  process.stdout.write(`${JSON.stringify({ lifecyclePassed: report.lifecyclePassed, resumed: report.resumed, cleanupConfirmed: report.cleanupConfirmed, evidenceFile: filename })}\n`);
  if (!report.lifecyclePassed) process.exitCode = 1;
  return report;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) main().catch(error => { process.stderr.write(`${JSON.stringify(safeError(error))}\n`); process.exitCode = 1; });
