import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { MacOSPFController } from '../native/macos-pf-routing/controller.mjs';
import { servePFHelper, projectPFHelperError } from '../native/macos-pf-routing/helper.mjs';
import { createPersistentPFNotionSessionClient, validatePFNotionCleanupReceipt, validatePFNotionPreflightCleanupReceipt, projectPFNotionResponseDiagnostic, validatePFNotionResponseDiagnostic, safePFNativeStageTimings, safePFNotionPreparationPending } from '../electron/macos-pf-notion-session.mjs';
import { MacOSPFNotionTrial, exportPFNotionTrialDiagnostics } from '../electron/macos-pf-notion-trial.mjs';
import { safeNotionTrial, notionTrialFailureLine, notionTrialControls, notionTrialLocksConfiguration, notionTrialTimingLine } from '../src/notion-trial-state.mjs';

const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false };
const original = { stage: 'transport', code: 'APPLICATION_APP_NATIVE_REFUSED',
  native: { stage: 'factory-open', reason: 'NATIVE_LISTENER_CREDENTIAL_REFUSED', error: 13 } };
const cleanup = { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' };
const privateText = 'PRIVATE_DIAGNOSTIC_SENTINEL';
const nativeStepNames = [...readFileSync(new URL('../native/macos-pf-routing/gui-launch.h', import.meta.url), 'utf8')
  .match(/enum envara_gui_step \{([^}]+)\}/s)[1].matchAll(/ENVARA_GUI_STEP_([A-Z_]+)/g)]
  .map(match => match[1]).filter(name => name !== 'COUNT').map(name => name.toLowerCase().replaceAll('_', '-'));
const pendingFacts = () => {
  const first = { cleanupAttempt: 0, denyVerified: true, frontClosedVerified: true, familyStoppedVerified: false,
    familyFailureReason: 'churn', familyFailureErrno: 35, familyFailureMach: 0 };
  return { first, latest: { ...first, cleanupAttempt: 2 } };
};
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
  const history = [], events = [], pending = pendingFacts();
  const status = new MacOSPFController({ inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
    identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, executor: { readOnlyStatus: async ({ runId } = {}) => ({ consoleUID: 501,
      pf: { priorAnchorsCompatible: true, lo0FilteringVerified: true }, ownedRootHook: { canCreateOwnedHook: !!runId, pfDisabled: true, pinsVerified: true, originalRootCompatible: true } }) } });
  /* This refusal is a native one after the run was created, so the controller
   * keeps listing that run until its cleanup is confirmed, as the real one does. */
  const listed = () => ({ ...flags, ...bound, profile: 'seatbelt-front-only', phase: 'cleanup-required', staged: false, resumed: false, cleanupComplete: false, cleanupUncertain: true });
  const controller = { closed: false, status: async value => { const result = await status.status(value); return bound ? { ...result, applications: [listed()] } : result; },
    prepareRoute: async () => ({ routeId: 'owned_route', profileId: 'owned_profile',
    ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false }), prepareNotionApplication: async value => {
    bound = { runId: value.runId, environmentId: value.environmentId };
    throw Object.assign(new Error(privateText), { code: original.code, nativeFailure: original.native, failureStage: original.stage, initialFailure: original,
      cause: { password: privateText }, route: { password: privateText }, privatePath: `/private/${privateText}` });
  }, resumeNotionApplication: async () => { resumed = true; throw new Error(); }, stopNotionApplication: async () => {
    throw Object.assign(new Error(privateText), { code: cleanup.code, failureStage: cleanup.stage, initialFailure: original, cleanupFailure: cleanup });
  }, applicationSnapshot: async () => ({ ...flags, ...bound, profile: 'seatbelt-front-only', phase: 'cleanup-required', staged: false, resumed: false,
    cleanupComplete: false, cleanupUncertain: true, failure: original, initialFailure: original, cleanupFailure: cleanup,
    cleanupPending: pending, private: privateText }),
  shutdown: async () => ({ closed: true, cleanupRequired: false }) };
  const trial = new MacOSPFNotionTrial({ verifyCandidate: async () => true, verifyNotion: async () => true, createClient: () => channel(controller),
    watchMs: 0, onEvent: event => events.push(event), persistDiagnostics: report => { history.push(report); } });
  const result = await trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: true });
  assert.deepEqual(result.initialFailure, original); assert.deepEqual(result.cleanupFailure, cleanup);
  assert.equal(result.errorCode, original.code); assert.equal(resumed, false); assert.equal(result.cleanupUncertain, true);
  const failed = events.find(event => event.stage === 'failed');
  assert.deepEqual({ nativeStage: failed.nativeStage, nativeReason: failed.nativeReason, errno: failed.errno },
    { nativeStage: original.native.stage, nativeReason: original.native.reason, errno: 13 });
  assert.ok(history.some(item => item.initialFailure?.native?.error === 13));
  assert.deepEqual(history.at(-1).cleanupFailure, cleanup);
  assert.deepEqual(history.at(-1).cleanupPending, pending);
  const exported = exportPFNotionTrialDiagnostics(result);
  assert.deepEqual(exported.initialFailure, original); assert.deepEqual(exported.cleanupFailure, cleanup);
  assert.deepEqual(exported.cleanupPending, pending);
  assert.deepEqual(exported.sessionDiagnostics.cleanupPending, pending);
  for (const key of Object.keys(flags)) assert.equal(exported[key], false);
  assert.equal(exported.diagnosticOnly, true);
  const ui = safeNotionTrial({ id: 'notion_bound', notionTrial: result });
  assert.deepEqual(ui.initialFailure, original); assert.deepEqual(ui.cleanupFailure, cleanup);
  assert.match(notionTrialFailureLine(ui.initialFailure), /factory-open · NATIVE_LISTENER_CREDENTIAL_REFUSED · errno=13$/);
  assert.equal(JSON.stringify({ exported, ui, history, events }).includes(privateText), false);
});

test('cleanup facts survive safe export only through exact bounded projections without becoming cleanup authority', () => {
  const runId = randomUUID(), environmentId = randomUUID(), pending = pendingFacts();
  const value = { applicationId: 'notion_bound', runId, environmentId, phase: 'cleanup-required', events: [],
    initialFailure: original, cleanupFailure: cleanup, sessionDiagnostics: { cleanupPending: pending } };
  const exported = exportPFNotionTrialDiagnostics(value);
  assert.deepEqual(exported.cleanupPending, pending);
  assert.deepEqual(exported.sessionDiagnostics.cleanupPending, pending);
  assert.deepEqual(exported.initialFailure, original);
  assert.equal(exported.cleanupComplete, false); assert.equal(exported.protected, false); assert.equal(exported.ready, false);
  pending.latest.familyStoppedVerified = true;
  assert.equal(exported.cleanupPending.latest.familyStoppedVerified, false, 'the export owns its copy');
  for (const change of [{ familyFailureReason: privateText }, { familyFailureErrno: 1025 }, { familyFailureMach: '0' },
    { path: `/private/${privateText}` }, { pid: 42 }, { token: privateText }, { denyVerified: 1 }]) {
    const invalid = pendingFacts(); Object.assign(invalid.latest, change);
    const rejected = exportPFNotionTrialDiagnostics({ ...value, sessionDiagnostics: { cleanupPending: invalid } });
    assert.equal(Object.hasOwn(rejected, 'cleanupPending'), false);
    assert.equal(Object.hasOwn(rejected.sessionDiagnostics, 'cleanupPending'), false);
    assert.equal(JSON.stringify(rejected).includes(privateText), false);
  }
  const legacy = pendingFacts();
  for (const fact of Object.values(legacy)) Object.assign(fact, { familyFailureReason: 'unknown', familyFailureErrno: null, familyFailureMach: null });
  assert.deepEqual(exportPFNotionTrialDiagnostics({ ...value, sessionDiagnostics: { cleanupPending: legacy } }).cleanupPending, legacy);
  const diagnostic = projectPFNotionResponseDiagnostic('applicationSnapshot', { ...flags, runId, environmentId, profile: 'seatbelt-front-only',
    phase: 'cleanup-required', staged: true, resumed: true, cleanupComplete: false, cleanupUncertain: true, cleanupPending: pendingFacts() }, runId, environmentId);
  assert.deepEqual(exportPFNotionTrialDiagnostics({ ...value, sessionDiagnostics: {}, applicationSnapshotDiagnostic: diagnostic }).cleanupPending, pendingFacts());
  assert.equal(Object.hasOwn(exportPFNotionTrialDiagnostics({ ...value, sessionDiagnostics: {},
    applicationSnapshotDiagnostic: { ...diagnostic, runId: randomUUID() } }), 'cleanupPending'), false);
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
    'NATIVE_NOTION_DATA_PREPARE_REFUSED', 'NATIVE_NOTION_STAGE_REFUSED', 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED'];
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

test('native step timings cross the snapshot diagnostic, export and renderer only as fixed bounded rows', () => {
  const runId = randomUUID(), environmentId = randomUUID();
  const timings = [{ step: 'ticket-prepare', stepMs: 2889, totalMs: 3301, fullChecks: 2, identityChecks: 12, receivedMs: 3302 },
    { step: 'ticket-claim', stepMs: 2768, totalMs: 6069, fullChecks: 2, identityChecks: 8, receivedMs: 6070 },
    ...['keychain-begin', 'keychain-scoped', 'keychain-normal', 'keychain-stage-ready', 'keychain-select', 'keychain-published',
      'keychain-stage-cleaned', 'keychain-verify', 'keychain-host-verify', 'keychain-complete', 'keychain-helper-set-default'].map((step, index) =>
      ({ step, stepMs: index, totalMs: 6070 + index, fullChecks: 0, identityChecks: 1, receivedMs: 6071 + index }))];
  const result = { ...flags, runId, environmentId, profile: 'seatbelt-front-only', phase: 'cleaned', staged: false, resumed: false,
    cleanupComplete: true, cleanupUncertain: false, failure: { stage: 'cold-stage', code: 'APPLICATION_APP_STAGE_TIMEOUT' }, nativeStageTimings: timings };
  const diagnostic = projectPFNotionResponseDiagnostic('applicationSnapshot', result, runId, environmentId);
  assert.deepEqual(diagnostic.nativeStageTimings, timings);
  assert.equal(validatePFNotionResponseDiagnostic(diagnostic, 'applicationSnapshot', runId, environmentId), true);
  assert.equal(projectPFNotionResponseDiagnostic('prepareNotionApplication', result, runId, environmentId).nativeStageTimings, undefined,
    'timings belong only to the snapshot diagnostic');
  for (const bad of [[{ ...timings[0], step: privateText }], [{ ...timings[0], stepMs: 9999, totalMs: 1 }], [{ ...timings[0], path: '/tmp' }],
    [{ ...timings[0], receivedMs: -1 }], Array.from({ length: 33 }, () => timings[0]), 'ticket-prepare']) {
    assert.equal(safePFNativeStageTimings(bad), null);
    const projected = projectPFNotionResponseDiagnostic('applicationSnapshot', { ...result, nativeStageTimings: bad }, runId, environmentId);
    assert.ok(projected, 'a malformed diagnostic list is dropped, never a failed snapshot');
    assert.equal(Object.hasOwn(projected, 'nativeStageTimings'), false);
    assert.equal(validatePFNotionResponseDiagnostic({ ...projected, nativeStageTimings: bad }, 'applicationSnapshot', runId, environmentId), false);
  }
  const value = { applicationId: 'notion_bound', runId, environmentId, phase: 'failed', events: [{ sequence: 1, stage: 'failed', code: 'APPLICATION_APP_STAGE_TIMEOUT' }],
    applicationSnapshotDiagnostic: diagnostic, sessionDiagnostics: { lastApplicationSnapshot: diagnostic } };
  const exported = exportPFNotionTrialDiagnostics(value);
  assert.deepEqual(exported.sessionDiagnostics.lastApplicationSnapshot.nativeStageTimings, timings);
  const live = safeNotionTrial({ id: 'notion_bound', notionTrial: value });
  assert.deepEqual(live.nativeTimings, timings);
  const atLimit = Array.from({ length: 32 }, (_, index) => timings[index % timings.length]);
  const limitDiagnostic = projectPFNotionResponseDiagnostic('applicationSnapshot', { ...result, nativeStageTimings: atLimit }, runId, environmentId);
  assert.deepEqual(safePFNativeStageTimings(atLimit), atLimit);
  assert.equal(validatePFNotionResponseDiagnostic(limitDiagnostic, 'applicationSnapshot', runId, environmentId), true);
  assert.deepEqual(safeNotionTrial({ id: 'notion_bound', notionTrial: { ...value, applicationSnapshotDiagnostic: limitDiagnostic } }).nativeTimings, atLimit);
  assert.equal(notionTrialTimingLine(live.nativeTimings[0]), 'ticket-prepare · 2889 ms · Σ 3301 ms · fullChecks=2 · identityChecks=12');
  const history = { ...exported, applicationId: 'notion_bound' };
  assert.deepEqual(notionTrialControls({ id: 'notion_bound', identity: 'bundle:com.microsoft.VSCode', notionTrialHistory: history }, {}, true).history.nativeTimings, timings);
  const foreign = { ...value, applicationSnapshotDiagnostic: { ...diagnostic, runId: randomUUID() }, sessionDiagnostics: {} };
  assert.deepEqual(safeNotionTrial({ id: 'notion_bound', notionTrial: foreign }).nativeTimings, []);
  assert.equal(JSON.stringify(exported).includes(privateText), false);
});

test('every fixed native Keychain step survives only its bounded snapshot, export and renderer diagnostic', () => {
  assert.equal(nativeStepNames.length, 81);
  const runId = randomUUID(), environmentId = randomUUID();
  for (let offset = 0; offset < nativeStepNames.length; offset += 32) {
    const timings = nativeStepNames.slice(offset, offset + 32).map((step, index) =>
      ({ step, stepMs: index, totalMs: index * 2, fullChecks: 0, identityChecks: 1, receivedMs: index * 2 }));
    const result = { ...flags, runId, environmentId, profile: 'seatbelt-front-only', phase: 'cleanup-required',
      staged: false, resumed: false, cleanupComplete: false, cleanupUncertain: true, failure: original, nativeStageTimings: timings };
    const diagnostic = projectPFNotionResponseDiagnostic('applicationSnapshot', result, runId, environmentId);
    assert.deepEqual(diagnostic.nativeStageTimings, timings);
    assert.equal(validatePFNotionResponseDiagnostic(diagnostic, 'applicationSnapshot', runId, environmentId), true);
    assert.equal(diagnostic.ready, undefined, 'a timing diagnostic adds no readiness field');
    assert.deepEqual(diagnostic.failure, original);
    assert.equal(diagnostic.cleanupComplete, false);
    assert.equal(diagnostic.cleanupUncertain, true);
    const value = { applicationId: 'notion_bound', runId, environmentId, phase: 'cleanup-required', events: [],
      applicationSnapshotDiagnostic: diagnostic, sessionDiagnostics: { lastApplicationSnapshot: diagnostic } };
    assert.deepEqual(exportPFNotionTrialDiagnostics(value).sessionDiagnostics.lastApplicationSnapshot.nativeStageTimings, timings);
    assert.deepEqual(safeNotionTrial({ id: 'notion_bound', notionTrial: value }).nativeTimings, timings);
    const foreign = { ...value, applicationSnapshotDiagnostic: { ...diagnostic, environmentId: randomUUID() }, sessionDiagnostics: {} };
    assert.deepEqual(safeNotionTrial({ id: 'notion_bound', notionTrial: foreign }).nativeTimings, []);
  }
});

test('host PF, route and DNS changes are reported observations, while every owned-resource fact stays mandatory', () => {
  const runId = randomUUID(), environmentId = randomUUID();
  const owned = ['coreReaped', 'frontReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
    'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
    'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'sealedContextRetired', 'registryReleased'];
  const value = { ...flags, runId, environmentId, profile: 'seatbelt-front-only', phase: 'cleaned', cleanupComplete: true, cleanupUncertain: false,
    cleanupEvidence: { schema: 'envara.macos-pf-notion-cleanup/v1', source: 'native-notion-controller', runId, environmentId, profile: 'seatbelt-front-only',
      complete: true, cleanupUncertain: false, childReaped: true, ...Object.fromEntries(owned.map(key => [key, true])),
      unrelatedPFUnchanged: true, unrelatedRoutesUnchanged: true, hostDNSUnchanged: false } };
  assert.equal(validatePFNotionCleanupReceipt(value, runId), true, 'a reported host DNS change does not make Envara cleanup incomplete');
  for (const key of ['unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged']) {
    const missing = structuredClone(value); delete missing.cleanupEvidence[key];
    assert.equal(validatePFNotionCleanupReceipt(missing, runId), false, `${key} must be reported`);
    assert.equal(validatePFNotionCleanupReceipt({ ...value, cleanupEvidence: { ...value.cleanupEvidence, [key]: 'false' } }, runId), false, `${key} must be a boolean`);
  }
  for (const key of owned) assert.equal(validatePFNotionCleanupReceipt({ ...value, cleanupEvidence: { ...value.cleanupEvidence, [key]: false } }, runId), false, `${key} stays mandatory`);
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


test('Keychain preparation refusal retains its original error and separate custody through helper, client and export', async () => {
  const runId = randomUUID(), environmentId = randomUUID(), preparationId = randomUUID();
  const native = { stage: 'guardian', reason: 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED', error: 13 };
  const initialFailure = { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native };
  const first = { preparationId, generation: 3, command: 'automatic', cleanupAttempt: 0,
    childState: 'unreaped', denyVerified: false, frontClosedVerified: false };
  let pending = { first, latest: first };
  const state = () => ({ ...flags, runId, environmentId, profile: 'seatbelt-front-only', phase: 'cleanup-required',
    staged: false, resumed: false, cleanupComplete: false, cleanupUncertain: true, cleanupRetryable: true,
    failure: initialFailure, initialFailure, preparationCleanupPending: pending });
  const call = channel({ closed: false,
    prepareRoute: async () => ({ routeId: 'owned_route', profileId: 'owned_profile', ready: false,
      failClosed: false, guardArmed: false, managedRouteVerified: false }),
    prepareNotionApplication: async () => { throw Object.assign(new Error(privateText), {
      code: initialFailure.code, nativeFailure: native, failureStage: 'cold-stage', initialFailure }); },
    applicationSnapshot: async () => state(), shutdown: async () => ({ closed: true, cleanupRequired: false }) });
  await call('prepareRoute', request());
  await assert.rejects(call('prepareNotionApplication', { routeId: 'owned_route', runId, environmentId,
    lifetimeSeconds: 180, activationAuthorized: true }), error => {
    assert.equal(error.code, initialFailure.code); assert.deepEqual(error.nativeFailure, native); return true;
  });
  const automatic = await call('applicationSnapshot', { runId });
  assert.deepEqual(automatic.preparationCleanupPending, pending);
  assert.equal(automatic.cleanupEvidence, null);
  pending = { first, latest: { ...first, command: 'S', cleanupAttempt: 1, childState: 'reaped',
    denyVerified: true, frontClosedVerified: true } };
  const subsequent = await call('applicationSnapshot', { runId });
  assert.deepEqual(subsequent.preparationCleanupPending, pending);
  const diagnostics = call.snapshot().diagnostics;
  assert.equal(diagnostics.uncertaintyLatched, false, 'a valid negative custody report retains the channel');
  assert.deepEqual(diagnostics.preparationCleanupPending, pending);
  const exported = exportPFNotionTrialDiagnostics({ applicationId: 'code_bound', runId, environmentId,
    phase: 'cleanup-required', initialFailure, sessionDiagnostics: diagnostics, events: [] });
  assert.deepEqual(exported.initialFailure, initialFailure);
  assert.deepEqual(exported.preparationCleanupPending, pending);
  assert.equal(exported.cleanupComplete, false);
  assert.equal(notionTrialFailureLine(exported.initialFailure).includes(native.reason), true);
  assert.equal(JSON.stringify(exported).includes(privateText), false);
  pending = { ...pending, first: { ...first, generation: 4 }, latest: { ...pending.latest, generation: 4 } };
  await assert.rejects(call('applicationSnapshot', { runId }), { code: 'PF_HELPER_RESPONSE_INVALID' });
  assert.equal(call.snapshot().diagnostics.uncertaintyLatched, true, 'changing the original slot poisons the channel');
  await call.close();
});

test('preparation diagnostics reject fabricated application facts, changed bindings and invalid ordinals', () => {
  const first = { preparationId: randomUUID(), generation: 1, command: 'automatic', cleanupAttempt: 0,
    childState: 'launcher-clear', denyVerified: false, frontClosedVerified: false };
  const valid = { first, latest: { ...first, command: 'S', cleanupAttempt: 2, childState: 'reaped' } };
  assert.deepEqual(safePFNotionPreparationPending(valid), valid);
  const invalid = [
    { ...valid, latest: { ...valid.latest, pid: 123 } },
    { ...valid, latest: { ...valid.latest, preparationId: randomUUID() } },
    { ...valid, latest: { ...valid.latest, generation: 2 } },
    { ...valid, latest: { ...valid.latest, childState: 'running' } },
    { ...valid, latest: { ...valid.latest, cleanupAttempt: 0 } },
    { ...valid, first: { ...first, command: 'S', cleanupAttempt: 1 } },
    { first, latest: { ...first, denyVerified: true } },
  ];
  for (const value of invalid) assert.equal(safePFNotionPreparationPending(value), null);
});
