import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createPersistentPFHelperClient, validatePFNotionCleanupReceipt, validatePFNotionPrestageCleanupReceipt, validatePFNotionPreflightCleanupReceipt } from '../scripts/accept-macos-pf-routing.mjs';

const truths = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
  'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
  'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false, profile: 'seatbelt-front-only' };
function receipt(runId, environmentId) { return { ...flags, runId, environmentId, phase: 'cleaned', cleanupComplete: true, cleanupUncertain: false,
  cleanupEvidence: { schema: 'envara.macos-pf-notion-cleanup/v1', source: 'native-notion-controller', runId, environmentId, profile: 'seatbelt-front-only',
    complete: true, cleanupUncertain: false, ...Object.fromEntries(truths.map(key => [key, true])) } }; }
const prestageTruths = ['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
  'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
  'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged',
  'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const prestageFalsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted'];
function prestageReceipt(runId, environmentId) { return { ...flags, runId, environmentId, phase: 'prestage-cleaned', prestageAborted: true,
  staged: false, resumed: false, cleanupComplete: true, cleanupUncertain: false,
  cleanupEvidence: { schema: 'envara.macos-pf-notion-prestage-cleanup/v1', source: 'native-notion-controller', runId, environmentId, profile: flags.profile,
    complete: true, cleanupUncertain: false, ...Object.fromEntries(prestageTruths.map(key => [key, true])), ...Object.fromEntries(prestageFalsehoods.map(key => [key, false])) } }; }
const preflightTruths = ['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
  'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
  'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
  'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const preflightFalsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted'];
function preflightReceipt(runId, environmentId) { return { ...flags, runId, environmentId, phase: 'preflight-cleaned', preflightAborted: true,
  prestageAborted: false, staged: false, resumed: false, cleanupComplete: true, cleanupUncertain: false,
  failure: { stage: 'transport', code: 'APPLICATION_APP_NATIVE_REFUSED', native: { stage: 'preflight', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } },
  cleanupEvidence: { schema: 'envara.macos-pf-notion-preflight-cleanup/v1', source: 'native-notion-controller', runId, environmentId, profile: flags.profile,
    complete: true, cleanupUncertain: false, ...Object.fromEntries(preflightTruths.map(key => [key, true])), ...Object.fromEntries(preflightFalsehoods.map(key => [key, false])) } }; }
function processClient(t, replies) {
  const program = `import readline from 'node:readline'; const replies=${JSON.stringify(replies)};
    readline.createInterface({input:process.stdin}).on('line',line=>{const r=JSON.parse(line);
      process.stdout.write(JSON.stringify({protocol:r.protocol,version:r.version,id:r.id,result:replies.shift()??{}})+'\\n');});`;
  let child; const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => {
    child = spawn(process.execPath, ['--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] }); return child;
  } });
  t.after(async () => { await call.close(); if (child && child.exitCode === null) child.kill('SIGTERM'); });
  return call;
}
const prepare = routeId => ({ routeId, runId: randomUUID(), environmentId: randomUUID(), lifetimeSeconds: 30, activationAuthorized: true });
function route() { return { application: { id: 'notion', profileId: 'owned', executablePath: '/Applications/Notion.app' },
  workspace: { cwd: '/tmp/owned', timezone: 'Asia/Manila', locale: 'en-PH', timezoneSource: 'proxy-egress' },
  route: { protocol: 'socks5', host: '127.0.0.1', port: 20101, username: 'fixture-user', password: 'fixture-secret', udpPolicy: 'block' },
  managedRoute: { profileId: 'owned', proxyId: 'node', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 999, coreVersion: 'v1.19.32' } }; }
test('real persistent own child carries prepareRoute and all four fixed Notion RPCs before accepting only complete same-run cleanup', async t => {
  const request = prepare('pf_fixture'), cleaned = receipt(request.runId, request.environmentId);
  const stage = { ...flags, runId: request.runId, environmentId: request.environmentId, phase: 'staged', cleanupUncertain: false, cleanupComplete: false };
  const call = processClient(t, [{ routeId: request.routeId }, stage, stage, { ...stage, phase: 'running' }, cleaned, cleaned]);
  await call('prepareRoute', route()); await call('prepareNotionApplication', request); await call('applicationSnapshot', { runId: request.runId });
  await call('resumeNotionApplication', { runId: request.runId, activationAuthorized: true }); await call('stopNotionApplication', { runId: request.runId });
  await call('applicationSnapshot', { runId: request.runId });
  assert.deepEqual(await call.close(), { closed: true, started: true, cleanupUncertain: false });
});
test('new method schemas reject before invoking any authorizer or serializing proof/FD/executable overrides', async () => {
  const request = prepare('pf_fixture'); let calls = 0;
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => { calls++; throw new Error(); } });
  const invalid = [['prepareNotionApplication', { ...request, fd: 3 }], ['prepareNotionApplication', { ...request, activationAuthorized: false }],
    ['prepareNotionApplication', { ...request, runId: request.runId.toUpperCase() }], ['prepareNotionApplication', { ...request, lifetimeSeconds: 181 }],
    ['prepareNotionApplication', { ...request, nativeProof: true }], ['resumeNotionApplication', { runId: request.runId, activationAuthorized: true, protected: true }],
    ['applicationSnapshot', { runId: request.runId, pid: 1 }], ['stopNotionApplication', {}], ['applicationTransportControl', { runId: request.runId }]];
  for (const entry of invalid) await assert.rejects(call(...entry), { code: 'PF_HELPER_REQUEST_INVALID' });
  for (const change of [r => { r.application.executablePath = '/Applications/Other.app'; }, r => { r.route.host = '203.0.113.1'; },
    r => { r.managedRoute.corePid = true; }, r => { r.workspace.locale = null; }, r => { r.workspace.timezone = 'unverified'; }, r => { r.application.args = ['--unknown']; }]) {
    const value = route(); change(value); await assert.rejects(call('prepareRoute', value), { code: 'PF_HELPER_REQUEST_INVALID' });
  }
  assert.equal(calls, 0); assert.deepEqual(await call.close(), { closed: true, cleanupUncertain: false, started: false });
});
test('Notion native cleanup requires every actual bound fact and never substitutes phase flags or simulated receipts', async t => {
  const runId = randomUUID(), environmentId = randomUUID(); assert.equal(validatePFNotionCleanupReceipt(receipt(runId, environmentId), runId), true);
  for (const change of [r => { delete r.cleanupEvidence.originalListenerClosed; }, r => { r.cleanupEvidence.transportExitConfirmed = 1; },
    r => { r.cleanupEvidence.source = 'simulated-notion-controller'; }, r => { r.cleanupEvidence.runId = randomUUID(); }, r => { r.cleanupEvidence.environmentId = randomUUID(); },
    r => { r.cleanupEvidence.registryReleased = false; }, r => { r.ready = true; }, r => { r.cleanupEvidence.privatePath = '/private'; }, r => { delete r.cleanupEvidence; }]) {
    const value = receipt(runId, environmentId); change(value); assert.equal(validatePFNotionCleanupReceipt(value, runId), false);
    const call = processClient(t, [value]); await call('stopNotionApplication', { runId }); assert.equal((await call.close()).cleanupUncertain, true);
  }
});
test('app/controller uncertainty latches across a later valid stop and clean outer EOF', async t => {
  for (const previous of [{ runId: randomUUID(), phase: 'cleanup-required', cleanupUncertain: true },
    { applications: [{ runId: randomUUID(), phase: 'running', cleanupUncertain: true }] }]) {
    const runId = previous.runId ?? previous.applications[0].runId, environmentId = randomUUID();
    const call = processClient(t, [previous, receipt(runId, environmentId)]);
    await call(previous.applications ? 'status' : 'applicationSnapshot', previous.applications ? {} : { runId });
    await call('stopNotionApplication', { runId }); assert.equal((await call.close()).cleanupUncertain, true);
  }
});
test('fresh status contradicting a cleaned application invalidates its previous close receipt', async t => {
  const runId = randomUUID(), environmentId = randomUUID();
  const call = processClient(t, [receipt(runId, environmentId), { applications: [{ runId, phase: 'running', cleanupUncertain: false }] }]);
  await call('stopNotionApplication', { runId }); await call('status'); assert.equal((await call.close()).cleanupUncertain, true);
});

test('prestage cleanup uses distinct evidence and both fresh same-run responses before accepting real child EOF', async t => {
  const request = prepare('pf_fixture'), { runId, environmentId } = request, clean = prestageReceipt(runId, environmentId);
  assert.equal(validatePFNotionPrestageCleanupReceipt(clean, runId), true);
  assert.equal(validatePFNotionCleanupReceipt(clean, runId), false);
  assert.equal(validatePFNotionPrestageCleanupReceipt(receipt(runId, environmentId), runId), false);
  const call = processClient(t, [{ ...flags, runId, environmentId, phase: 'prestage-aborted' }, clean, clean, { applications: [clean] }]);
  await call('prepareNotionApplication', request);
  await call('stopNotionApplication', { runId }); await call('applicationSnapshot', { runId }); await call('status');
  assert.equal((await call.close()).cleanupUncertain, false);
});

test('prestage close requires the requested environment and a snapshot after stop', async t => {
  for (const scenario of ['missing-snapshot', 'snapshot-before-stop', 'snapshot-only', 'foreign-stop', 'foreign-snapshot', 'foreign-both', 'unbound-run']) {
    const request = prepare('pf_fixture'), { runId, environmentId } = request;
    const clean = prestageReceipt(runId, environmentId), foreign = prestageReceipt(runId, randomUUID());
    const steps = [];
    if (scenario !== 'unbound-run') steps.push(['prepareNotionApplication', request, { ...flags, runId, environmentId, phase: 'prestage-aborted' }]);
    if (scenario === 'snapshot-before-stop' || scenario === 'snapshot-only') steps.push(['applicationSnapshot', { runId }, clean]);
    if (scenario !== 'snapshot-only') steps.push(['stopNotionApplication', { runId }, ['foreign-stop', 'foreign-both'].includes(scenario) ? foreign : clean]);
    if (!['missing-snapshot', 'snapshot-before-stop', 'snapshot-only'].includes(scenario)) steps.push(['applicationSnapshot', { runId }, ['foreign-snapshot', 'foreign-both'].includes(scenario) ? foreign : clean]);
    const call = processClient(t, steps.map(entry => entry[2]));
    for (const [method, params] of steps) await call(method, params);
    assert.equal((await call.close()).cleanupUncertain, true, scenario);
  }
});

test('prestage cleanup refuses missing, coerced, cross-run, simulated or launch evidence without clearing uncertainty', async t => {
  const request = prepare('pf_fixture'), { runId, environmentId } = request;
  for (const change of [
    r => { delete r.cleanupEvidence.filterJournalAbsent; }, r => { r.cleanupEvidence.coreReaped = 1; },
    r => { r.cleanupEvidence.source = 'simulated-notion-controller'; }, r => { r.cleanupEvidence.environmentId = randomUUID(); },
    r => { r.cleanupEvidence.runId = randomUUID(); }, r => { r.cleanupEvidence.denyAttempted = true; },
    r => { r.cleanupEvidence.launchCommandAccepted = true; }, r => { r.cleanupEvidence.childReaped = true; },
    r => { r.resumed = true; }, r => { r.prestageAborted = false; }, r => { r.phase = 'cleaned'; }
  ]) {
    const invalid = prestageReceipt(runId, environmentId); change(invalid);
    assert.equal(validatePFNotionPrestageCleanupReceipt(invalid, runId), false);
    const call = processClient(t, [{ ...flags, runId, environmentId, phase: 'prestage-aborted' }, prestageReceipt(runId, environmentId), invalid]);
    await call('prepareNotionApplication', request);
    await call('stopNotionApplication', { runId }); await call('applicationSnapshot', { runId });
    assert.equal((await call.close()).cleanupUncertain, true);
  }
  const call = processClient(t, [{ runId, cleanupUncertain: true }, prestageReceipt(runId, environmentId)]);
  await call('applicationSnapshot', { runId }); await call('stopNotionApplication', { runId });
  assert.equal((await call.close()).cleanupUncertain, true);
});
test('preflight cleanup accepts only its separate same-request stop and subsequent fresh native snapshot before real own child EOF', async t => {
  const request = prepare('pf_fixture'), { runId, environmentId } = request, clean = preflightReceipt(runId, environmentId);
  assert.equal(validatePFNotionPreflightCleanupReceipt(clean, runId), true);
  assert.equal(validatePFNotionCleanupReceipt(clean, runId), false); assert.equal(validatePFNotionPrestageCleanupReceipt(clean, runId), false);
  assert.equal(validatePFNotionPreflightCleanupReceipt(receipt(runId, environmentId), runId), false);
  const call = processClient(t, [{ ...flags, runId, environmentId, phase: 'preflight-aborted', cleanupUncertain: false }, clean, clean, { applications: [clean] }]);
  await call('prepareNotionApplication', request); await call('stopNotionApplication', { runId }); await call('applicationSnapshot', { runId }); await call('status');
  assert.equal((await call.close()).cleanupUncertain, false);
});
test('preflight receipt refuses missing/Boolean facts, unknown native stage, simulated sources and invented launched resources', () => {
  const request = prepare('pf_fixture');
  for (const edit of [r => { delete r.cleanupEvidence.nativePrivateChildrenAbsentBeforeExit; }, r => { r.cleanupEvidence.bootstrapExitConfirmed = 1; },
    r => { r.cleanupEvidence.nativeOwnedFilterClassesEmptyBeforeExit = false; }, r => { r.cleanupEvidence.source = 'simulated-notion-controller'; },
    r => { r.cleanupEvidence.runId = randomUUID(); }, r => { r.cleanupEvidence.environmentId = randomUUID(); },
    r => { r.cleanupEvidence.bootstrapAttempted = true; }, r => { r.cleanupEvidence.coreReaped = true; }, r => { r.resumed = true; },
    r => { r.preflightAborted = false; }, r => { r.prestageAborted = true; }, r => { r.failure.native.stage = 'factory-open'; },
    r => { r.failure.native.error = true; }, r => { delete r.failure; }, r => { r.ready = true; }]) {
    const clean = preflightReceipt(request.runId, request.environmentId); edit(clean);
    assert.equal(validatePFNotionPreflightCleanupReceipt(clean, request.runId), false);
  }
});
test('preflight close rejects absent/out-of-order/cross-environment/cross-schema receipts and never clears explicit uncertainty', async t => {
  for (const scenario of ['no-prepare', 'no-snapshot', 'snapshot-first', 'foreign-both', 'prestage-snapshot', 'explicit-uncertainty']) {
    const request = prepare('pf_fixture'), { runId, environmentId } = request, clean = preflightReceipt(runId, environmentId), steps = [];
    if (scenario === 'foreign-both') { clean.environmentId = randomUUID(); clean.cleanupEvidence.environmentId = clean.environmentId; }
    if (scenario !== 'no-prepare') steps.push(['prepareNotionApplication', request, { ...flags, runId, environmentId, phase: 'preflight-aborted' }]);
    if (scenario === 'snapshot-first') steps.push(['applicationSnapshot', { runId }, clean]);
    if (scenario === 'explicit-uncertainty') steps.push(['applicationSnapshot', { runId }, { runId, environmentId, phase: 'cleanup-required', cleanupUncertain: true }]);
    steps.push(['stopNotionApplication', { runId }, clean]);
    if (!['no-snapshot', 'snapshot-first'].includes(scenario)) steps.push(['applicationSnapshot', { runId }, scenario === 'prestage-snapshot' ? prestageReceipt(runId, environmentId) : clean]);
    const call = processClient(t, steps.map(step => step[2])); for (const [method, params] of steps) await call(method, params);
    assert.equal((await call.close()).cleanupUncertain, true, scenario);
  }
});
