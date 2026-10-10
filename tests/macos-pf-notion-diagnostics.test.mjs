import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { MacOSPFController } from '../native/macos-pf-routing/controller.mjs';
import { servePFHelper, projectPFHelperError } from '../native/macos-pf-routing/helper.mjs';
import { createPersistentPFNotionSessionClient, validatePFNotionCleanupReceipt, validatePFNotionPreflightCleanupReceipt } from '../electron/macos-pf-notion-session.mjs';
import { MacOSPFNotionTrial, exportPFNotionTrialDiagnostics } from '../electron/macos-pf-notion-trial.mjs';
import { safeNotionTrial, notionTrialFailureLine, notionTrialControls, notionTrialLocksConfiguration } from '../src/notion-trial-state.mjs';

const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false };
const original = { stage: 'transport', code: 'APPLICATION_APP_NATIVE_REFUSED',
  native: { stage: 'factory-open', reason: 'NATIVE_LISTENER_CREDENTIAL_REFUSED', error: 13 } };
const cleanup = { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' };
const privateText = 'PRIVATE_DIAGNOSTIC_SENTINEL';
const request = () => ({ application: { id: 'notion_bound', profileId: 'owned_profile', executablePath: '/Applications/Notion.app/Contents/MacOS/Notion' },
  workspace: { cwd: '/tmp', timezone: 'Asia/Manila', locale: 'en-PH', timezoneSource: 'proxy-egress' },
  route: { protocol: 'socks5', host: '127.0.0.1', port: 20101, username: privateText, password: privateText, udpPolicy: 'block' },
  managedRoute: { profileId: 'owned_profile', proxyId: 'owned_node', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 999, coreVersion: 'v1.19.32' } });
function channel(controller) {
  const input = new PassThrough(), child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { input.end(); return true; };
  child.stdin = new Writable({ write(bytes, encoding, done) { input.write(Buffer.from(bytes)); done(); }, final(done) { input.end(); done(); } });
  return createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => {
    servePFHelper({ controller, input, output: child.stdout, signalSource: null }).then(() => { child.stdout.end(); child.emit('close', 0, null); });
    return child;
  } });
}

test('real helper RPC preserves first native refusal independently of cleanup and safe history/UI export', async () => {
  let bound, resumed = false;
  const history = [], events = [];
  const status = new MacOSPFController({ inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
    identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, executor: { readOnlyStatus: async ({ runId } = {}) => ({ consoleUID: 501,
      pf: { priorAnchorsCompatible: true, lo0FilteringVerified: true }, ownedRootHook: { canCreateOwnedHook: !!runId, pfDisabled: true, pinsVerified: true, originalRootCompatible: true } }) } });
  const controller = { closed: false, status: value => status.status(value), prepareRoute: async () => ({ routeId: 'owned_route', profileId: 'owned_profile',
    ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false }), prepareNotionApplication: async value => {
    bound = { runId: value.runId, environmentId: value.environmentId };
    throw Object.assign(new Error(privateText), { code: original.code, nativeFailure: original.native, failureStage: original.stage, initialFailure: original,
      cause: { password: privateText }, route: { password: privateText }, privatePath: `/private/${privateText}` });
  }, resumeNotionApplication: async () => { resumed = true; throw new Error(); }, stopNotionApplication: async () => {
    throw Object.assign(new Error(privateText), { code: cleanup.code, failureStage: cleanup.stage, initialFailure: original, cleanupFailure: cleanup });
  }, applicationSnapshot: async () => ({ ...flags, ...bound, profile: 'seatbelt-front-only', phase: 'cleanup-required', staged: false, resumed: false,
    cleanupComplete: false, cleanupUncertain: true, failure: original, initialFailure: original, cleanupFailure: cleanup, private: privateText }),
  shutdown: async () => ({ closed: true, cleanupRequired: false }) };
  const trial = new MacOSPFNotionTrial({ verifyCandidate: async () => true, verifyNotion: async () => true, createClient: () => channel(controller),
    observationMs: 0, onEvent: event => events.push(event), persistDiagnostics: report => { history.push(report); } });
  const result = await trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: true });
  assert.deepEqual(result.initialFailure, original); assert.deepEqual(result.cleanupFailure, cleanup);
  assert.equal(result.errorCode, original.code); assert.equal(resumed, false); assert.equal(result.cleanupUncertain, true);
  const failed = events.find(event => event.stage === 'failed');
  assert.deepEqual({ nativeStage: failed.nativeStage, nativeReason: failed.nativeReason, errno: failed.errno },
    { nativeStage: original.native.stage, nativeReason: original.native.reason, errno: 13 });
  assert.ok(history.some(item => item.initialFailure?.native?.error === 13));
  assert.deepEqual(history.at(-1).cleanupFailure, cleanup);
  const exported = exportPFNotionTrialDiagnostics(result);
  assert.deepEqual(exported.initialFailure, original); assert.deepEqual(exported.cleanupFailure, cleanup);
  for (const key of Object.keys(flags)) assert.equal(exported[key], false);
  assert.equal(exported.diagnosticOnly, true);
  const ui = safeNotionTrial({ id: 'notion_bound', notionTrial: result });
  assert.deepEqual(ui.initialFailure, original); assert.deepEqual(ui.cleanupFailure, cleanup);
  assert.match(notionTrialFailureLine(ui.initialFailure), /factory-open · NATIVE_LISTENER_CREDENTIAL_REFUSED · errno=13$/);
  assert.equal(JSON.stringify({ exported, ui, history, events }).includes(privateText), false);
});

test('helper discards malformed diagnostic payloads and client rejects injected diagnostic enum/extra fields', async () => {
  for (const invalid of [{ ...original.native, reason: privateText }, { ...original.native, path: `/private/${privateText}` },
    { ...original.native, error: true }, { ...original.native, error: 1025 }]) {
    const projected = projectPFHelperError({ code: original.code, nativeFailure: invalid, initialFailure: { ...original, native: invalid } });
    assert.equal(Object.hasOwn(projected, 'nativeFailure'), false); assert.equal(Object.hasOwn(projected, 'initialFailure'), false);
    assert.equal(JSON.stringify(projected).includes(privateText), false);
  }
  for (const injected of [{ ...original, stage: privateText }, { ...original, native: { ...original.native, password: privateText } },
    { ...original, extra: privateText }]) {
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
    child.stdin = new Writable({ write(bytes, encoding, done) {
      const request = JSON.parse(bytes); child.stdout.write(JSON.stringify({ protocol: request.protocol, version: request.version, id: request.id, ok: false,
        error: { code: original.code, initialFailure: injected } }) + '\n'); done(); },
    final(done) { child.stdout.end(); queueMicrotask(() => child.emit('close', 0, null)); done(); } });
    const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => child });
    await assert.rejects(call('status'), { code: 'PF_HELPER_RESPONSE_INVALID' });
    assert.equal((await call.close()).cleanupUncertain, true);
    assert.equal(JSON.stringify(call.snapshot()).includes(privateText), false);
  }
});

test('renderer recovers validated cached failure, rejects foreign snapshots and never renders arbitrary enum text', () => {
  const runId = randomUUID(), environmentId = randomUUID();
  const application = { id: 'notion_bound', notionTrial: { applicationId: 'notion_bound', phase: 'cleanup-required', runId, environmentId,
    applicationSnapshotDiagnostic: { schema: 'envara.macos-pf-notion-response-diagnostic/v1', source: 'verified-authorizer-session-client', diagnosticOnly: true,
      runId, environmentId, profile: 'seatbelt-front-only', failure: original } } };
  assert.deepEqual(safeNotionTrial(application).initialFailure, original);
  application.notionTrial.applicationSnapshotDiagnostic.environmentId = randomUUID();
  assert.equal(safeNotionTrial(application).initialFailure, null);
  application.notionTrial.initialFailure = { ...original, native: { ...original.native, reason: privateText } };
  assert.equal(safeNotionTrial(application).initialFailure, null);
  assert.equal(notionTrialFailureLine(application.notionTrial.initialFailure), '');
});

test('throwing safe-history writer cannot change first error or prevent bounded cleanup', async () => {
  let cleanupAttempted = false;
  const trial = new MacOSPFNotionTrial({ verifyCandidate: async () => { throw Object.assign(new Error(privateText), { code: 'PF_NOTION_SIGNATURE_REFUSED' }); },
    persistDiagnostics: () => { throw new Error(privateText); }, onEvent: event => { if (event.stage === 'failed') cleanupAttempted = true; } });
  const result = await trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: true });
  assert.equal(result.initialFailure.code, 'PF_NOTION_SIGNATURE_REFUSED'); assert.equal(cleanupAttempted, true);
  assert.equal(result.cleanupUncertain, false); assert.equal(JSON.stringify(exportPFNotionTrialDiagnostics(result)).includes(privateText), false);
});

test('all fixed native reasons cross the actual helper/client wire; unknown reason stays excluded', async () => {
  const reasons = ['NATIVE_OPERATION_REFUSED', 'NATIVE_CONTEXT_LOAD_REFUSED', 'NATIVE_CONTROLLER_BINDING_REFUSED', 'NATIVE_ORIGINAL_SOCKET_REFUSED',
    'NATIVE_LISTENER_CREDENTIAL_REFUSED', 'NATIVE_PIPE_BINDING_REFUSED', 'NATIVE_GUI_SESSION_REFUSED', 'NATIVE_APP_IDENTITY_REFUSED', 'NATIVE_HOOK_LEASE_REFUSED',
    'NATIVE_PF_OPEN_REFUSED', 'NATIVE_PF_GUARD_REFUSED', 'NATIVE_FILTER_READBACK_REFUSED', 'NATIVE_FILTER_TRANSACTION_REFUSED', 'NATIVE_JOURNAL_REFUSED',
    'NATIVE_TICKET_BINDING_REFUSED', 'NATIVE_TICKET_FILTER_REFUSED', 'NATIVE_SCOPE_CHECK_REFUSED', 'NATIVE_GUARD_DESCRIPTOR_REFUSED', 'NATIVE_LEASE_EXPIRED_REFUSED',
    'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED'];
  for (const reason of reasons) {
    const native = { stage: 'guardian', reason, error: 13 };
    const initialFailure = { stage: 'cold-stage', code: original.code, native };
    const call = channel({ closed: false, status: async () => { throw Object.assign(new Error(privateText), { code: original.code, nativeFailure: native,
      failureStage: initialFailure.stage, initialFailure }); }, shutdown: async () => ({ cleanupRequired: false }) });
    await assert.rejects(call('status'), failure => { assert.deepEqual(failure.nativeFailure, native); assert.deepEqual(failure.initialFailure, initialFailure);
      assert.equal(notionTrialFailureLine(failure.initialFailure).includes(reason), true); return true; });
    await call.close();
  }
});

test('saved prior failure is visible and exportable without becoming current launch or cleanup authority', () => {
  const history = { schema: 'envara.macos-pf-notion-trial-diagnostics/v1', diagnosticOnly: true, applicationId: 'notion_bound',
    runId: randomUUID(), environmentId: randomUUID(), profile: 'seatbelt-front-only', phase: 'cleanup-required', active: false,
    staged: false, resumed: false, cleanupComplete: false, cleanupUncertain: true, initialFailure: original, cleanupFailure: cleanup,
    events: [{ sequence: 1, stage: 'failed', code: original.code }], ...flags };
  const application = { id: 'notion_bound', identity: 'bundle:notion.id', notionTrialHistory: history };
  const controls = notionTrialControls(application, { controlledNotionTrialAvailable: true }, true);
  assert.deepEqual(controls.history.initialFailure, original); assert.equal(controls.trial, null);
  assert.equal(controls.canRun, true); assert.equal(controls.canStop, false); assert.equal(controls.active, false);
  assert.equal(notionTrialLocksConfiguration(application), false);
  assert.equal(notionTrialControls({ ...application, notionTrialHistory: { ...history, protected: true } }, {}, true).history, null);
});

test('safe export reconstructs the first native error from an older same-bound cached snapshot', () => {
  const runId = randomUUID(), environmentId = randomUUID();
  const value = { applicationId: 'notion_bound', runId, environmentId, phase: 'cleanup-required', events: [],
    applicationSnapshotDiagnostic: { schema: 'envara.macos-pf-notion-response-diagnostic/v1', source: 'verified-authorizer-session-client', kind: 'result',
      method: 'applicationSnapshot', runId, environmentId, profile: 'seatbelt-front-only', diagnosticOnly: true, phase: 'cleanup-required', staged: false,
      resumed: false, cleanupComplete: false, cleanupUncertain: true, failure: original } };
  assert.deepEqual(exportPFNotionTrialDiagnostics(value).initialFailure, original);
  value.applicationSnapshotDiagnostic.runId = randomUUID();
  assert.equal(exportPFNotionTrialDiagnostics(value).initialFailure, null);
});

test('cleanup before creating a child uses explicit absence proof and never invents child-reaped evidence', () => {
  const runId = randomUUID(), environmentId = randomUUID();
  const facts = ['coreReaped', 'frontReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
    'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
    'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
  const value = { ...flags, runId, environmentId, profile: 'seatbelt-front-only', phase: 'cleaned', cleanupComplete: true, cleanupUncertain: false,
    cleanupEvidence: { schema: 'envara.macos-pf-notion-cleanup/v1', source: 'native-notion-controller', runId, environmentId, profile: 'seatbelt-front-only',
      complete: true, cleanupUncertain: false, childReaped: false, childAbsent: true, ...Object.fromEntries(facts.map(key => [key, true])) } };
  assert.equal(validatePFNotionCleanupReceipt(value, runId), true);
  assert.equal(value.cleanupEvidence.childReaped, false);
  for (const change of [{ childReaped: true }, { childAbsent: false }, { childAbsent: 'true' }, { childAbsent: true, scopeQuiescentObserved: false }])
    assert.equal(validatePFNotionCleanupReceipt({ ...value, cleanupEvidence: { ...value.cleanupEvidence, ...change } }, runId), false);
  const unproven = structuredClone(value); delete unproven.cleanupEvidence.childAbsent;
  assert.equal(validatePFNotionCleanupReceipt(unproven, runId), false);
  assert.equal(validatePFNotionPreflightCleanupReceipt(value, runId), false);
});
