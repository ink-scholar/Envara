#!/usr/bin/env node
import fs from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { PF_ACCEPTANCE_HELPER, PF_ACCEPTANCE_HELPER_ROOT, PF_ACCEPTANCE_PROTOCOL,
  inspectPFAcceptanceFoundation, createPFAcceptancePlan, runPFAcceptanceMatrix,
  validatePFControlledCleanupEvidence } from '../native/macos-pf-routing/acceptance-plan.mjs';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const PF_AUTHORIZER_PATH = path.join(projectRoot, 'build/app-routing/macos-pf/EnvaraPFInstall');
const safeCode = error => /^[A-Z][A-Z0-9_]{0,63}$/.test(error?.code ?? '') ? error.code : 'PF_ACCEPTANCE_OPERATION_FAILED';
const failed = code => Object.assign(new Error('Owned PF acceptance refused'), { code });
const notionMethods = new Set(['prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot']);
const canonicalUUID = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
const exact = (value, keys, optional = []) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  keys.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => [...keys, ...optional].includes(key));
const text = value => typeof value === 'string' && value.length > 0 && !/[\0\r\n]/.test(value);
const absolute = value => text(value) && value.startsWith('/') && value.length <= 4095;
function validateNotionClientRequest(method, params) {
  if (method === 'prepareRoute') {
    if (!exact(params, ['application', 'workspace', 'route', 'managedRoute']) ||
        !exact(params.application, ['id', 'profileId', 'executablePath']) || ['id', 'profileId'].some(key => !/^[A-Za-z0-9_-]{1,128}$/.test(params.application[key] ?? '')) ||
        !['/Applications/Notion.app', '/Applications/Notion.app/Contents/MacOS/Notion'].includes(params.application.executablePath) ||
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
        (!/^[A-Za-z0-9_-]{1,128}$/.test(params.routeId ?? '') || !canonicalUUID(params.environmentId) || !Number.isInteger(params.lifetimeSeconds) || params.lifetimeSeconds < 10 || params.lifetimeSeconds > 180) ||
        Object.hasOwn(params, 'activationAuthorized') && params.activationAuthorized !== true) throw failed('PF_HELPER_REQUEST_INVALID');
  }
}
export function validatePFNotionCleanupReceipt(result, requestedRunId) {
  const evidence = result?.cleanupEvidence;
  const truths = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
    'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
    'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
  return canonicalUUID(requestedRunId) && result?.runId === requestedRunId && canonicalUUID(result.environmentId) && result.phase === 'cleaned' &&
    result.cleanupComplete === true && result.cleanupUncertain === false && result.profile === 'seatbelt-front-only' &&
    ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => result[key] === false) &&
    exact(evidence, ['schema', 'source', 'runId', 'environmentId', 'profile', 'complete', 'cleanupUncertain', ...truths]) &&
    evidence.schema === 'envara.macos-pf-notion-cleanup/v1' && evidence.source === 'native-notion-controller' && evidence.runId === requestedRunId &&
    evidence.environmentId === result.environmentId && evidence.profile === result.profile && evidence.complete === true && evidence.cleanupUncertain === false && truths.every(key => evidence[key] === true);
}

// A failed preparation can release its resources without ever staging an app.
// Keep this proof distinct from a successfully staged child's cleanup receipt.
export function validatePFNotionPrestageCleanupReceipt(result, requestedRunId) {
  const evidence = result?.cleanupEvidence;
  const truths = ['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
    'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
    'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged',
    'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
  const falsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted'];
  return canonicalUUID(requestedRunId) && result?.runId === requestedRunId && canonicalUUID(result.environmentId) && result.phase === 'prestage-cleaned' &&
    result.prestageAborted === true && result.staged === false && result.resumed === false && result.cleanupComplete === true && result.cleanupUncertain === false &&
    result.profile === 'seatbelt-front-only' && ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => result[key] === false) &&
    exact(evidence, ['schema', 'source', 'runId', 'environmentId', 'profile', 'complete', 'cleanupUncertain', ...truths, ...falsehoods]) &&
    evidence.schema === 'envara.macos-pf-notion-prestage-cleanup/v1' && evidence.source === 'native-notion-controller' && evidence.runId === requestedRunId &&
    evidence.environmentId === result.environmentId && evidence.profile === result.profile && evidence.complete === true && evidence.cleanupUncertain === false &&
    truths.every(key => evidence[key] === true) && falsehoods.every(key => evidence[key] === false);
}

// A direct native preflight refusal has no app/core/front resource receipt.
// Its independently proved root-resource cleanup must never pass either of
// the established launch or later-factory abort validators.
export function validatePFNotionPreflightCleanupReceipt(result, requestedRunId) {
  const evidence = result?.cleanupEvidence, native = result?.failure?.native;
  const truths = ['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
    'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
    'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
    'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
  const falsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted'];
  return canonicalUUID(requestedRunId) && result?.runId === requestedRunId && canonicalUUID(result.environmentId) && result.phase === 'preflight-cleaned' &&
    result.preflightAborted === true && result.prestageAborted === false && result.staged === false && result.resumed === false &&
    result.cleanupComplete === true && result.cleanupUncertain === false && result.profile === 'seatbelt-front-only' &&
    ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => result[key] === false) &&
    result.failure?.stage === 'transport' && result.failure?.code === 'APPLICATION_APP_NATIVE_REFUSED' && exact(native, ['stage', 'reason', 'error']) &&
    native.stage === 'preflight' && native.reason === 'NATIVE_OPERATION_REFUSED' && Number.isInteger(native.error) && native.error > 0 && native.error <= 1024 &&
    exact(evidence, ['schema', 'source', 'runId', 'environmentId', 'profile', 'complete', 'cleanupUncertain', ...truths, ...falsehoods]) &&
    evidence.schema === 'envara.macos-pf-notion-preflight-cleanup/v1' && evidence.source === 'native-notion-controller' && evidence.runId === requestedRunId &&
    evidence.environmentId === result.environmentId && evidence.profile === result.profile && evidence.complete === true && evidence.cleanupUncertain === false &&
    truths.every(key => evidence[key] === true) && falsehoods.every(key => evidence[key] === false);
}

/** Root-owned manifest and every declared file must be immutable to the caller. */
export async function verifyPFHelperInstallation({ helperPath = PF_ACCEPTANCE_HELPER } = {}) {
  if (helperPath !== PF_ACCEPTANCE_HELPER) throw failed('PF_HELPER_INSTALLATION_PATH_REJECTED');
  let current = PF_ACCEPTANCE_HELPER_ROOT;
  while (current !== '/') {
    const stat = await fs.lstat(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022)) throw failed('PF_HELPER_INSTALLATION_UNTRUSTED');
    current = path.dirname(current);
  }
  const filename = path.join(PF_ACCEPTANCE_HELPER_ROOT, 'manifest.json'), s = await fs.lstat(filename);
  if (!s.isFile() || s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o022) || s.size > 262144) throw failed('PF_HELPER_INSTALLATION_UNTRUSTED');
  const manifest = JSON.parse(await fs.readFile(filename, 'utf8'));
  if (manifest?.schema !== 'envara.macos-pf-installation/v1' || manifest.version !== '1' ||
      manifest.component !== 'envara-pf-routing' || manifest.backend !== 'pf-utun' ||
      !manifest.files || typeof manifest.files !== 'object' || Array.isArray(manifest.files) ||
      !manifest.files.EnvaraPFHelper || Object.keys(manifest.files).length < 6 || Object.keys(manifest.files).length > 128) throw failed('PF_HELPER_MANIFEST_INVALID');
  for (const [relative, digest] of Object.entries(manifest.files)) {
    if (!/^[A-Za-z0-9_./-]{1,200}$/.test(relative) || relative.split('/').some(p => !p || p === '.' || p === '..') ||
        !/^[a-f0-9]{64}$/.test(digest ?? '')) throw failed('PF_HELPER_MANIFEST_INVALID');
    const file = path.join(PF_ACCEPTANCE_HELPER_ROOT, relative); let parent = path.dirname(file);
    while (parent !== PF_ACCEPTANCE_HELPER_ROOT) {
      const p = await fs.lstat(parent); if (!p.isDirectory() || p.isSymbolicLink() || p.uid !== 0 || (p.mode & 0o022)) throw failed('PF_HELPER_INSTALLATION_UNTRUSTED');
      parent = path.dirname(parent);
    }
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) || stat.size > 150 * 1024 * 1024 ||
        (relative === 'EnvaraPFHelper' && !(stat.mode & 0o111)) || await fs.realpath(file) !== file) throw failed('PF_HELPER_INSTALLATION_UNTRUSTED');
    const hash = createHash('sha256');
    for await (const chunk of createReadStream(file, { highWaterMark: 65536 })) hash.update(chunk);
    const after = await fs.lstat(file);
    if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs ||
        hash.digest('hex') !== digest) throw failed('PF_HELPER_HASH_MISMATCH');
  }
  return { verified: true, filesVerified: Object.keys(manifest.files).length };
}

/** One persistent, private stdio channel. EOF is sent only after explicit cleanup. */
export function createPersistentPFHelperClient({ spawnRootControlledLifecycle, maximumBytes = 65536 } = {}) {
  if (typeof spawnRootControlledLifecycle !== 'function' || !Number.isInteger(maximumBytes) || maximumBytes < 1024 || maximumBytes > 131072) throw failed('PF_HELPER_PATH_INVALID');
  let child, starting, buffer = Buffer.alloc(0), pending = null, closed = false, closing = false, uncertain = false,
    terminalError = null, terminal = null, closePromise;
  const observedRuns = new Set(), cleanedRuns = new Set(), requestedEnvironments = new Map(), prestageStops = new Set(), preflightStops = new Set(); let unknownRun = false;
  const runId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : null;
  const observeRun = value => { const id = runId(value); if (id) observedRuns.add(id); else unknownRun = true; };
  const cleanupComplete = () => !unknownRun && observedRuns.size > 0 && [...observedRuns].every(id => cleanedRuns.has(id));
  const environmentMatches = (result, id, requireRequested = false) => {
    const expected = requestedEnvironments.get(id);
    return expected ? result.environmentId === expected : !requireRequested;
  };
  const normalReceipt = (result, id) => validatePFNotionCleanupReceipt(result, id) && environmentMatches(result, id);
  const prestageReceipt = (result, id) => validatePFNotionPrestageCleanupReceipt(result, id) && environmentMatches(result, id, true);
  const preflightReceipt = (result, id) => validatePFNotionPreflightCleanupReceipt(result, id) && environmentMatches(result, id, true);
  const reportsUncertainty = value => value?.cleanupUncertain === true || value?.cleanupRequired === true ||
    ['uncertain', 'cleanup-required', 'cleanupRequired'].includes(value?.phase) ||
    ['uncertain', 'cleanup-required', 'cleanupRequired'].includes(value?.status);
  const observeResult = (request, result) => {
    // A root controller receipt outlives the outer relay's exit status. Never
    // clear explicit uncertainty, even if a later response claims cleanup.
    if (reportsUncertainty(result) || reportsUncertainty(result.evidence) ||
        (Array.isArray(result.runs) && result.runs.some(reportsUncertainty)) ||
        (Array.isArray(result.applications) && result.applications.some(reportsUncertainty))) uncertain = true;
    if (Object.hasOwn(result, 'runId')) observeRun(result.runId);
    if (request.method === 'acceptanceSnapshot' && result.phase !== 'cleaned') cleanedRuns.delete(runId(result.runId));
    if (request.method === 'applicationSnapshot') {
      if (normalReceipt(result, request.runId)) { /* A stop remains required for normal cleanup. */ }
      else if (prestageReceipt(result, request.runId) && prestageStops.has(request.runId)) cleanedRuns.add(request.runId);
      else if (preflightReceipt(result, request.runId) && preflightStops.has(request.runId)) cleanedRuns.add(request.runId);
      else { cleanedRuns.delete(request.runId); prestageStops.delete(request.runId); preflightStops.delete(request.runId); }
    }
    if (Array.isArray(result.runs)) for (const run of result.runs) {
      observeRun(run?.runId);
      if (run?.phase !== 'cleaned') cleanedRuns.delete(runId(run?.runId));
    }
    if (Array.isArray(result.applications)) for (const run of result.applications) {
      observeRun(run?.runId); if (!environmentMatches(run, run?.runId) || (run?.phase !== 'cleaned' && !prestageReceipt(run, run?.runId) && !preflightReceipt(run, run?.runId))) {
        cleanedRuns.delete(runId(run?.runId)); prestageStops.delete(runId(run?.runId)); preflightStops.delete(runId(run?.runId));
      }
    }
    if (request.method === 'cleanupOwnedFixtures' && request.runId && result.runId === request.runId &&
        result.acceptanceProtocol === PF_ACCEPTANCE_PROTOCOL && result.acceptanceOnly === true && result.ready === false &&
        result.productionReceiptAllowed === false && result.cleanupUncertain === false &&
        validatePFControlledCleanupEvidence(result.evidence)) cleanedRuns.add(request.runId);
    if (request.method === 'stopNotionApplication') {
      if (normalReceipt(result, request.runId)) cleanedRuns.add(request.runId);
      else if (prestageReceipt(result, request.runId)) prestageStops.add(request.runId);
      else if (preflightReceipt(result, request.runId)) preflightStops.add(request.runId);
    }
  };
  const retired = new Set(); let settleExit;
  const exit = new Promise(resolve => { settleExit = resolve; });
  const failChannel = error => {
    terminalError ??= error; uncertain = true;
    if (pending) { const current = pending; pending = null; current.finish(error); }
  };
  const onData = bytes => {
    buffer = Buffer.concat([buffer, bytes]);
    if (buffer.length > maximumBytes * 2) return failChannel(failed('PF_HELPER_RESPONSE_TOO_LARGE'));
    let newline;
    while ((newline = buffer.indexOf(10)) >= 0) {
      const line = buffer.subarray(0, newline); buffer = buffer.subarray(newline + 1);
      if (!line.length || line.length > maximumBytes) return failChannel(failed('PF_HELPER_RESPONSE_INVALID'));
      try {
        const message = JSON.parse(line.toString('utf8'));
        if (message.protocol !== 'envara.application-routing' || message.version !== 1 ||
            Object.hasOwn(message, 'result') === Object.hasOwn(message, 'error')) throw failed('PF_HELPER_RESPONSE_INVALID');
        // The fixed native authorizer cannot know a request ID before its
        // private root relay exists. A safe id:null error is a refusal only.
        if (message.id === null && Object.hasOwn(message, 'error')) return failChannel(failed(safeCode(message.error)));
        if (typeof message.id !== 'string') throw failed('PF_HELPER_RESPONSE_INVALID');
        if (retired.delete(message.id)) continue; // Only a known, timed-out reply may arrive late.
        if (!pending || message.id !== pending.id) throw failed('PF_HELPER_RESPONSE_INVALID');
        const current = pending; pending = null;
        if (Object.hasOwn(message, 'error')) current.finish(failed(safeCode(message.error)));
        else if (!message.result || typeof message.result !== 'object' || Array.isArray(message.result)) current.finish(failed('PF_HELPER_RESPONSE_INVALID'));
        else { observeResult(current, message.result); current.finish(null, message.result); }
      } catch (error) { return failChannel(failed(safeCode(error))); }
    }
    if (buffer.length > maximumBytes) failChannel(failed('PF_HELPER_RESPONSE_TOO_LARGE'));
  };
  const start = () => starting ??= Promise.resolve().then(spawnRootControlledLifecycle).then(process => {
    if (!process?.stdin || !process?.stdout || typeof process.on !== 'function' || typeof process.kill !== 'function') throw failed('PF_HELPER_UNAVAILABLE');
    child = process;
    child.stdin.on('error', () => failChannel(failed('PF_HELPER_INPUT_FAILED')));
    child.stdout.on('data', onData); child.stderr?.on('data', () => {});
    child.on('error', () => failChannel(failed('PF_HELPER_UNAVAILABLE')));
    child.once('close', (exitCode, exitSignal) => {
      closed = true; terminal = { exitCode, exitSignal };
      if (buffer.length || pending || !closing || exitCode !== 0 || exitSignal) failChannel(failed('PF_HELPER_UNEXPECTED_EXIT'));
      settleExit(terminal);
    });
    if (closing) child.stdin.end();
    return child;
  }).catch(error => { closed = true; failChannel(failed(safeCode(error))); settleExit(null); throw error; });
  const call = async (method, params = {}, { timeoutMs = 15000, signal } = {}) => {
    if (!['status', 'prepareOwnedFixtures', 'runOwnedFixtureCase', 'cleanupOwnedFixtures', 'acceptanceSnapshot', 'prepareRoute', ...notionMethods].includes(method) ||
        !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 || signal?.aborted || closing || closed || pending ||
        terminalError || (uncertain && !['status', 'cleanupOwnedFixtures', 'acceptanceSnapshot', 'stopNotionApplication', 'applicationSnapshot'].includes(method))) throw failed(uncertain ? 'PF_HELPER_CLEANUP_UNCERTAIN' : 'PF_HELPER_REQUEST_INVALID');
    validateNotionClientRequest(method, params);
    if (method === 'prepareNotionApplication' && requestedEnvironments.has(params.runId) &&
        requestedEnvironments.get(params.runId) !== params.environmentId) throw failed('PF_HELPER_REQUEST_INVALID');
    const id = randomUUID(), input = Buffer.from(JSON.stringify({ protocol: 'envara.application-routing', version: 1, id, method, params }) + '\n');
    if (input.length > maximumBytes) throw failed('PF_HELPER_REQUEST_TOO_LARGE');
    return await new Promise((resolve, reject) => {
      let finished = false;
      const finish = (error, value) => {
        if (finished) return; finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
        error ? reject(error) : resolve(value);
      };
      const abandon = code => {
        if (pending?.id !== id) return;
        pending = null; uncertain = true; retired.add(id); finish(failed(code));
      };
      const abort = () => abandon('PF_HELPER_ABORTED'), timer = setTimeout(() => abandon('PF_HELPER_DEADLINE'), timeoutMs);
      const requestedRun = runId(params?.runId);
      if (method === 'prepareNotionApplication') requestedEnvironments.set(requestedRun, params.environmentId);
      if (method !== 'status' && method !== 'prepareRoute') {
        observeRun(params?.runId);
        if (!['acceptanceSnapshot', 'applicationSnapshot'].includes(method)) {
          cleanedRuns.delete(requestedRun); prestageStops.delete(requestedRun); preflightStops.delete(requestedRun);
        }
      }
      pending = { id, method, runId: requestedRun, finish }; signal?.addEventListener('abort', abort, { once: true });
      start().then(() => {
        if (pending?.id === id && !closing && !closed && !terminalError) child.stdin.write(input);
      }).catch(error => { if (pending?.id === id) { pending = null; finish(failed(safeCode(error))); } });
      if (signal?.aborted) abort();
    });
  };
  call.close = ({ timeoutMs = 10000 } = {}) => closePromise ??= (async () => {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 20000) throw failed('PF_HELPER_REQUEST_INVALID');
    closing = true;
    if (!starting) return { closed: true, cleanupUncertain: false, started: false };
    if (pending) { const p = pending; pending = null; uncertain = true; p.finish(failed('PF_HELPER_CHANNEL_CLOSED')); }
    let startTimer;
    await Promise.race([start().catch(() => {}), new Promise(resolve => { startTimer = setTimeout(resolve, timeoutMs); })]); clearTimeout(startTimer);
    if (!child && !closed) { uncertain = true; return { closed: false, started: true, cleanupUncertain: true }; }
    child?.stdin.end(); // Preserve stdout and continue reading final helper cleanup output.
    let timer;
    await Promise.race([exit, new Promise(resolve => { timer = setTimeout(resolve, timeoutMs); })]); clearTimeout(timer);
    if (!closed) {
      uncertain = true; child?.kill('SIGTERM');
      let grace; await Promise.race([exit, new Promise(resolve => { grace = setTimeout(resolve, 1000); })]); clearTimeout(grace);
      if (!closed) { child?.kill('SIGKILL'); let last; await Promise.race([exit, new Promise(resolve => { last = setTimeout(resolve, 1000); })]); clearTimeout(last); }
    }
    return { closed, started: true, cleanupUncertain: uncertain || !cleanupComplete() || !closed || terminal?.exitCode !== 0 || Boolean(terminal?.exitSignal) };
  })();
  call.snapshot = () => ({ started: Boolean(starting), closed, closing,
    cleanupUncertain: uncertain || (Boolean(starting) && !cleanupComplete()), pending: Boolean(pending) });
  return call;
}

/** Read-only --rpc or a separately authorized, fixed native Security relay. */
export function createPFHelperRPC({ helperPath = PF_ACCEPTANCE_HELPER, controlled = false,
  authorizerPath = PF_AUTHORIZER_PATH, spawnProcess = spawn } = {}) {
  if (typeof helperPath !== 'string' || !path.isAbsolute(helperPath) || helperPath.includes('\0') ||
      (controlled && (helperPath !== PF_ACCEPTANCE_HELPER || authorizerPath !== PF_AUTHORIZER_PATH))) throw failed('PF_HELPER_PATH_INVALID');
  return createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawnProcess(
    controlled ? authorizerPath : helperPath, controlled ? ['--request-controlled-experiment'] : ['--rpc'],
    { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' }, cwd: '/' }) });
}

export async function main(argv = process.argv.slice(2)) {
  let operation = 'plan', helperPath = PF_ACCEPTANCE_HELPER, authorized = false, controlledCaseIds = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--plan' && operation === 'plan') continue;
    if (argv[i] === '--status' && operation === 'plan') { operation = 'status'; continue; }
    if (argv[i] === '--run-fixtures' && operation === 'plan') { operation = 'run'; continue; }
    if (argv[i] === '--run-controlled-cases' && operation === 'plan' && argv[i + 1]) {
      operation = 'run'; controlledCaseIds = argv[++i].split(','); continue;
    }
    if (argv[i] === '--activation-authorized' && !authorized) { authorized = true; continue; }
    if (argv[i] === '--helper' && argv[i + 1]) { helperPath = path.resolve(argv[++i]); continue; }
    throw failed('PF_ACCEPTANCE_ARGUMENT_INVALID');
  }
  if (process.platform !== 'darwin') throw failed('PF_ACCEPTANCE_MACOS_REQUIRED');
  if (operation !== 'run' && authorized) throw failed('PF_ACCEPTANCE_ARGUMENT_INVALID');
  if (operation === 'plan') return createPFAcceptancePlan(await inspectPFAcceptanceFoundation());
  if (operation === 'status') {
    const call = createPFHelperRPC({ helperPath });
    try { return createPFAcceptancePlan(await inspectPFAcceptanceFoundation(), await call('status', {}, { timeoutMs: 5000 })); }
    finally { await call.close(); }
  }
  if (!authorized) throw failed('PF_CONTROLLED_ACTIVATION_AUTHORIZATION_REQUIRED');
  try { await verifyPFHelperInstallation({ helperPath }); }
  catch (error) { if (error.code === 'ENOENT') throw failed('PF_HELPER_INSTALLATION_UNAVAILABLE'); throw error; }
  const call = createPFHelperRPC({ helperPath, controlled: true }); let report;
  try {
    // Give the separate native system authorization dialog time to complete.
    const runId = randomUUID(), initialStatus = await call('status', { runId }, { timeoutMs: 60000 }); let initial = true;
    report = await runPFAcceptanceMatrix({ runId, controlledCaseIds, call: (method, params, options) => {
      if (method === 'status' && initial && params.runId === runId) { initial = false; return Promise.resolve(initialStatus); }
      return call(method, params, options);
    } });
  } finally {
    const transport = await call.close();
    if (report) { report.transport = transport;
      if (transport.cleanupUncertain) { report.selectedCasesPassed = false; report.fixtureMatrixPassed = false;
        report.nativeRoutingAcceptance = false; report.reason = 'PF_HELPER_CLEANUP_UNCERTAIN'; } }
  }
  const folder = path.join(projectRoot, 'test-artifacts', 'mac-pf-routing'); await fs.mkdir(folder, { recursive: true });
  const filename = path.join(folder, `${report.startedAt.replace(/[:.]/g, '-')}-${randomUUID()}.json`);
  await fs.writeFile(filename, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { ...report, reportPath: filename };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(result => { process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    if (result.operation === 'runOwnedPFFixtures' && !result.selectedCasesPassed) process.exitCode = 1;
  }).catch(error => { process.stdout.write(JSON.stringify({ schema: PF_ACCEPTANCE_PROTOCOL, operation: 'refused',
    acceptanceOnly: true, productionReady: false, productionReceiptAllowed: false,
    activatesSystem: false, nativeRoutingAcceptance: false, reason: safeCode(error) }, null, 2) + '\n'); process.exitCode = 1; });
}
