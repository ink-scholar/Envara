import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { main, runPFNotionAcceptance, safeNotionResponse } from '../scripts/accept-macos-pf-notion.mjs';

const keys = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
  'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
  'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false, profile: 'seatbelt-front-only' };
function fixture(fault = null) {
  const runId = randomUUID(), environmentId = randomUUID(), calls = [];
  const response = phase => ({ ...flags, runId, environmentId, phase, staged: true, resumed: phase === 'running', cleanupUncertain: false, cleanupComplete: phase === 'cleaned' });
  const clean = { ...response('cleaned'), cleanupEvidence: { schema: 'envara.macos-pf-notion-cleanup/v1', source: 'native-notion-controller',
    runId, environmentId, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false, ...Object.fromEntries(keys.map(key => [key, true])) } };
  const call = async (method, params, options) => {
    calls.push({ method, params, options });
    if (method === fault) throw Object.assign(new Error('DO_NOT_PUBLISH_PRIVATE_INPUT'), { code: 'DO_NOT_PUBLISH_PRIVATE_INPUT' });
    if (method === 'status') return { rootOwnedInstallationVerified: true, callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true,
      privilegedRuntimeVerified: true, lo0FilteringVerified: true, ready: false, protectedLaunchAllowed: false, password: 'PRIVATE_VALUE' };
    if (method === 'prepareRoute') return { routeId: 'owned_route', username: 'PRIVATE_VALUE' };
    if (method === 'prepareNotionApplication') return response('staged');
    if (method === 'resumeNotionApplication') return response('running');
    if (['stopNotionApplication', 'applicationSnapshot'].includes(method)) return clean;
    assert.fail(`Unexpected inert call ${method}`);
  };
  call.close = async options => { calls.push({ method: 'close', options }); return { closed: true, started: true, cleanupUncertain: fault === 'close' }; };
  // These are synthetic typed replies, never native acceptance evidence.
  const routeRequest = { application: { id: 'notion', profileId: 'fixture', executablePath: '/Applications/Notion.app' },
    workspace: { cwd: '/tmp/owned-fixture', timezone: 'Asia/Manila', locale: 'en-PH' },
    route: { protocol: 'socks5', host: '127.0.0.1', port: 20001, username: 'PRIVATE_USER', password: 'PRIVATE_PASSWORD', udpPolicy: 'block' },
    managedRoute: { profileId: 'fixture', proxyId: 'fixture', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 99, coreVersion: 'v1.19.32' } };
  return { runId, environmentId, calls, call, clean, routeRequest, beforeResume: async () => { calls.push({ method: 'signature-check' }); return true; },
    observe: async ms => { calls.push({ method: 'observe', ms }); }, observationMs: 5000 };
}
test('inert driver orders exact RPCs and fresh signature before one resume, then obtains both same-run receipts before EOF', async () => {
  const owned = fixture(), report = await runPFNotionAcceptance(owned);
  assert.equal(report.lifecyclePassed, true); assert.equal(report.applicationTrafficVerified, false);
  assert.deepEqual(owned.calls.map(item => item.method), ['status', 'prepareRoute', 'prepareNotionApplication', 'signature-check', 'resumeNotionApplication', 'observe', 'stopNotionApplication', 'applicationSnapshot', 'close']);
  const prepare = owned.calls.find(item => item.method === 'prepareNotionApplication'); assert.equal(prepare.params.lifetimeSeconds, 180); assert.equal(prepare.params.activationAuthorized, true);
  assert.ok(owned.calls.filter(item => item.options?.timeoutMs).every(item => item.options.timeoutMs > 0 && item.options.timeoutMs <= 60000));
  const text = JSON.stringify(report); assert.ok(!text.includes('PRIVATE_')); assert.ok(!text.includes('/tmp/owned-fixture')); assert.ok(!text.includes('corePid'));
  for (const key of ['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported']) assert.equal(report[key], false);
});
for (const fault of ['prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot', 'close']) test(`inert ${fault} failure still runs bounded final cleanup and cannot pass`, async () => {
  const owned = fixture(fault), report = await runPFNotionAcceptance(owned);
  assert.equal(report.lifecyclePassed, false);
  assert.deepEqual(owned.calls.slice(-3).map(item => item.method), ['stopNotionApplication', 'applicationSnapshot', 'close']);
  assert.ok(!JSON.stringify(report).includes('DO_NOT_PUBLISH_PRIVATE_INPUT'));
});
test('signature refusal never resumes a cold child and still requests stop, snapshot and close', async () => {
  const owned = fixture(), report = await runPFNotionAcceptance({ ...owned, beforeResume: async () => false });
  assert.equal(report.operationError.code, 'PF_NOTION_SIGNATURE_REFUSED'); assert.equal(report.resumed, false);
  assert.equal(owned.calls.some(item => item.method === 'resumeNotionApplication'), false);
  assert.deepEqual(owned.calls.slice(-3).map(item => item.method), ['stopNotionApplication', 'applicationSnapshot', 'close']);
});

test('verified prestage abort confirms resource cleanup while preserving launch failure and skipping signature, resume and observation', async () => {
  const owned = fixture(), original = owned.call;
  const prestageTruths = ['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
    'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
    'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged',
    'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
  const falseKeys = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted'];
  const clean = { ...flags, runId: owned.runId, environmentId: owned.environmentId, phase: 'prestage-cleaned', staged: false, resumed: false,
    prestageAborted: true, cleanupUncertain: false, cleanupComplete: true,
    cleanupEvidence: { schema: 'envara.macos-pf-notion-prestage-cleanup/v1', source: 'native-notion-controller', runId: owned.runId,
      environmentId: owned.environmentId, profile: flags.profile, complete: true, cleanupUncertain: false,
      ...Object.fromEntries(prestageTruths.map(key => [key, true])), ...Object.fromEntries(falseKeys.map(key => [key, false])) } };
  const call = async (method, ...rest) => {
    if (method === 'prepareNotionApplication') { owned.calls.push({ method }); throw Object.assign(new Error('PRIVATE_DETAIL'), { code: 'APPLICATION_APP_NATIVE_REFUSED' }); }
    if (['stopNotionApplication', 'applicationSnapshot'].includes(method)) { owned.calls.push({ method }); return structuredClone(clean); }
    return original(method, ...rest);
  };
  call.close = original.close;
  const report = await runPFNotionAcceptance({ ...owned, call });
  assert.equal(report.cleanupConfirmed, true); assert.equal(report.prestageAborted, true);
  assert.equal(report.resumed, false); assert.equal(report.lifecyclePassed, false); assert.equal(report.applicationTrafficVerified, false);
  assert.equal(report.operationError.code, 'APPLICATION_APP_NATIVE_REFUSED');
  assert.deepEqual(owned.calls.map(x => x.method), ['status', 'prepareRoute', 'prepareNotionApplication', 'stopNotionApplication', 'applicationSnapshot', 'close']);
  assert.equal(report.cleanup.cleanupEvidence.childReaped, undefined);
  assert.equal(report.cleanup.cleanupEvidence.filterWriteAttempted, false);
  assert.ok(!JSON.stringify(report).includes('PRIVATE_DETAIL'));
  for (const change of [p => { p.environmentId = randomUUID(); p.cleanupEvidence.environmentId = p.environmentId; },
    p => { p.cleanupEvidence.source = 'simulated-notion-controller'; }, p => { p.cleanupEvidence.coldStageAttempted = true; },
    p => { delete p.cleanupEvidence.nativeGIDScopeAbsentBeforeExit; }]) {
    const invalidCall = async (method, ...rest) => { const result = await call(method, ...rest); if (method === 'applicationSnapshot') change(result); return result; };
    invalidCall.close = call.close;
    const invalid = await runPFNotionAcceptance({ ...owned, call: invalidCall });
    assert.equal(invalid.cleanupConfirmed, false); assert.equal(invalid.lifecyclePassed, false);
  }
});
test('verified native preflight refusal reports root resource cleanup, never Notion launch or traffic, and preserves its specific failure', async () => {
  const owned = fixture(), original = owned.call;
  const truths = ['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
    'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
    'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
    'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
  const falsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted'];
  const clean = { ...flags, runId: owned.runId, environmentId: owned.environmentId, phase: 'preflight-cleaned', preflightAborted: true,
    prestageAborted: false, staged: false, resumed: false, cleanupUncertain: false, cleanupComplete: true,
    failure: { stage: 'transport', code: 'APPLICATION_APP_NATIVE_REFUSED', native: { stage: 'preflight', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } },
    cleanupEvidence: { schema: 'envara.macos-pf-notion-preflight-cleanup/v1', source: 'native-notion-controller', runId: owned.runId,
      environmentId: owned.environmentId, profile: flags.profile, complete: true, cleanupUncertain: false,
      ...Object.fromEntries(truths.map(key => [key, true])), ...Object.fromEntries(falsehoods.map(key => [key, false])) } };
  const call = async (method, ...rest) => {
    if (method === 'prepareNotionApplication') { owned.calls.push({ method }); throw Object.assign(new Error('DO_NOT_PUBLISH'), { code: 'APPLICATION_APP_NATIVE_REFUSED' }); }
    if (['stopNotionApplication', 'applicationSnapshot'].includes(method)) { owned.calls.push({ method }); return structuredClone(clean); }
    return original(method, ...rest);
  }; call.close = original.close;
  const report = await runPFNotionAcceptance({ ...owned, call });
  assert.equal(report.cleanupConfirmed, true); assert.equal(report.preflightAborted, true); assert.equal(report.prestageAborted, false);
  assert.equal(report.resumed, false); assert.equal(report.lifecyclePassed, false); assert.equal(report.applicationTrafficVerified, false);
  assert.equal(report.operationError.code, 'APPLICATION_APP_NATIVE_REFUSED');
  assert.deepEqual(report.snapshot.failure.native, { stage: 'preflight', reason: 'NATIVE_OPERATION_REFUSED', error: 13 });
  assert.deepEqual(owned.calls.map(item => item.method), ['status', 'prepareRoute', 'prepareNotionApplication', 'stopNotionApplication', 'applicationSnapshot', 'close']);
  for (const field of ['coreReaped', 'frontReaped', 'childReaped', 'originalUTunClosed']) assert.equal(report.cleanup.cleanupEvidence[field], undefined);
  assert.ok(!JSON.stringify(report).includes('DO_NOT_PUBLISH'));
  for (const edit of [r => { r.environmentId = randomUUID(); r.cleanupEvidence.environmentId = r.environmentId; },
    r => { r.cleanupEvidence.source = 'simulated-notion-controller'; }, r => { r.cleanupEvidence.nativeGIDScopeAbsentBeforeExit = 1; },
    r => { r.cleanupEvidence.transportAttempted = true; }, r => { r.failure.native.stage = 'factory-open'; }]) {
    const invalid = async (method, ...rest) => { const result = await call(method, ...rest); if (['stopNotionApplication', 'applicationSnapshot'].includes(method)) edit(result); return result; };
    invalid.close = call.close; const result = await runPFNotionAcceptance({ ...owned, call: invalid });
    assert.equal(result.cleanupConfirmed, false); assert.equal(result.lifecyclePassed, false); assert.equal(result.applicationTrafficVerified, false);
  }
  const changedType = async (method, ...rest) => method === 'applicationSnapshot' ? owned.clean : call(method, ...rest);
  changedType.close = call.close; const result = await runPFNotionAcceptance({ ...owned, call: changedType });
  assert.equal(result.cleanupConfirmed, false); assert.equal(result.lifecyclePassed, false);
});
test('snapshot missing one native fact or bound environment rejects cleanup even after valid stop', async () => {
  for (const change of [value => { value.environmentId = randomUUID(); }, value => { value.environmentId = randomUUID(); value.cleanupEvidence.environmentId = value.environmentId; }, value => { value.cleanupEvidence.originalListenerClosed = 1; }]) {
    const owned = fixture(), original = owned.call;
    const call = async (...args) => { const result = await original(...args); if (args[0] === 'applicationSnapshot') { const value = structuredClone(result); change(value); return value; } return result; };
    call.close = original.close; assert.equal((await runPFNotionAcceptance({ ...owned, call })).lifecyclePassed, false);
  }
});
test('a valid same-run cleanup for another environment cannot turn either stop or snapshot into success', async () => {
  const owned = fixture(), original = owned.call, otherEnvironment = randomUUID();
  const call = async (...args) => { const result = await original(...args); if (['stopNotionApplication', 'applicationSnapshot'].includes(args[0])) {
    const value = structuredClone(result); value.environmentId = otherEnvironment; value.cleanupEvidence.environmentId = otherEnvironment; return value;
  } return result; }; call.close = original.close;
  const report = await runPFNotionAcceptance({ ...owned, call });
  assert.equal(report.lifecyclePassed, false); assert.equal(report.cleanupConfirmed, false); assert.equal(report.cleanup.responseBound, false);
});
test('safe response keeps only fixed enums, typed booleans and complete native cleanup without private paths or text', () => {
  const owned = fixture(); const input = { ...owned.clean, privatePath: '/private/DO_NOT_PUBLISH', password: 'DO_NOT_PUBLISH',
    failure: { stage: 'transport', code: 'DO_NOT_PUBLISH', native: { stage: 'front-handshake', reason: 'NATIVE_OPERATION_REFUSED', error: 5 } } };
  const safe = safeNotionResponse(input, owned.runId, owned.environmentId);
  assert.equal(safe.failure.native.error, 5); assert.equal(safe.failure.code, 'PF_NOTION_OPERATION_FAILED'); assert.ok(!JSON.stringify(safe).includes('DO_NOT_PUBLISH'));
  input.failure.native.error = 1025; assert.equal(safeNotionResponse(input, owned.runId, owned.environmentId).failure.native, undefined);
  input.failure.native.error = 5; input.failure.native.lease = 'DO_NOT_PUBLISH'; assert.equal(safeNotionResponse(input, owned.runId, owned.environmentId).failure.native, undefined);
});
test('invalid CLI approval flags and missing reviewed pins refuse before stdin, native creation or filesystem verification', async () => {
  for (const argv of [[], ['--plan'], ['--explicit-user-approved-notion-test', '--extra'], ['--approved']]) await assert.rejects(main(argv), { code: 'PF_NOTION_APPROVAL_REQUIRED' });
  // Do not invoke the approved CLI path or inspect real resources in this test.
});
