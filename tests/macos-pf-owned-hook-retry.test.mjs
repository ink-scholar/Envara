// Source contract checks only: all executor and fixture I/O is inert JavaScript.
// CLI refusal checks start only Node with missing/invalid approval flags.
// No native process, authorization, network listener or system operation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PF_ACCEPTANCE_PROTOCOL, runPFAcceptanceMatrix } from '../native/macos-pf-routing/acceptance-plan.mjs';
import { MacOSPFController, PF_ROOT_HOOK_LEASE_SCHEMA } from '../native/macos-pf-routing/controller.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';
import { RETRY_RESOURCE_PINS, RETRY_CASES, RETRY_BUDGETS, assertRetryPins, safeRetryError,
  safeRetryStatus, safeRetryCleanup, safeFixtureUDPDiagnostics, safeUDPSizeDiagnostics, runOwnedHookRetrySession, main } from '../scripts/macos-pf-owned-hook-retry.mjs';

const runId = '1350575c-bf18-409c-8a50-1a49ed6eb155';
const privateMarker = 'PRIVATE_RESPONSE_MUST_NOT_ESCAPE';
const flags = { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL, acceptanceOnly: true, ready: false, productionReceiptAllowed: false };
const restoredKeys = ['ownedProcessesExited', 'ownedTunnelsRemoved', 'ownedAnchorRemoved', 'unrelatedPFUnchanged',
  'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'noOwnedStatesCreatedVerified', 'noOwnedStatesRemainVerified',
  'ownedRootHookRemoved', 'originalRootRestored', 'ownedPFReferenceReleased'];
const cleanup = (extra = {}) => ({ ...flags, runId, cleanupUncertain: false,
  ...Object.fromEntries(restoredKeys.map(key => [key, true])),
  evidence: { source: 'native-pf', platform: 'darwin', complete: true, cleanupUncertain: false,
    ...Object.fromEntries(restoredKeys.map(key => [key, true])) }, ...extra });
const status = (phase = 'cleaned') => ({ ...flags, rootOwnedInstallationVerified: true,
  runs: [{ runId, phase, cleanupUncertain: false, lease: privateMarker }], proxy: { password: privateMarker }, lease: privateMarker });
function client(handler) {
  const sequence = []; let statusCount = 0;
  const call = async (method, params, options) => { sequence.push({ method, timeoutMs: options.timeoutMs });
    if (method === 'status') return status(++statusCount > 1 ? 'cleaned' : 'preparing');
    return await handler(method, params, options); };
  call.close = async options => { sequence.push({ method: 'EOF', timeoutMs: options.timeoutMs });
    return { closed: true, started: true, cleanupUncertain: false, stdout: privateMarker }; };
  return { call, sequence };
}
const assertPrivateAbsent = value => assert.ok(!JSON.stringify(value).includes(privateMarker));
const otherRunId = 'efc79686-70c4-4444-a629-f36d41598a9a';

// Exercise the actual controller and matrix together. Every executor method
// below changes only JavaScript memory; proxy/control fixtures open no sockets.
function inertControllerMatrix() {
  const sequence = [], reads = [], logs = []; let group = 7100, tunnel = 90;
  const gone = { ownedRootHookRemoved: true, originalRootRestored: true, namespaceState: 'absent',
    namespaceReclaimed: true, namespaceExists: false, receiptRetired: true, cleanupPending: false };
  const executor = {
    kind: 'simulated', statelessControlledFixtures: true, fixtureOperations: [...RETRY_CASES, 'cleanup'],
    readOnlyStatus: async ({ runId: candidate } = {}) => {
      reads.push(candidate ?? null);
      return { consoleUID: 501, pf: { priorAnchorsCompatible: true, fixtureEgressSkipVerified: true },
        ownedRootHook: { canCreateOwnedHook: Boolean(candidate), pfDisabled: true, pinsVerified: true, originalRootCompatible: true },
        statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: [...RETRY_CASES, 'cleanup'] };
    },
    acquireLock: async () => logs.push('lock'),
    snapshotUnrelatedNetwork: async () => ({ pfDigest: 'pf', routeDigest: 'routes', dnsDigest: 'dns' }),
    installOwnedRootHook: async candidate => {
      logs.push('insert-hook');
      return { schema: PF_ROOT_HOOK_LEASE_SCHEMA, runId: candidate, leaseId: otherRunId,
        anchor: pfRoutingAnchor(candidate), owner: pfRoutingAnchor(candidate),
        label: `envara.hook.v2.${createHash('sha256').update(`${candidate}|${otherRunId}`).digest('hex').slice(0, 32)}`,
        ticket: '1234605616436508552', rootBeforeSHA256: 'a'.repeat(64), rootBeforeTextSHA256: 'b'.repeat(64) };
    },
    removeOwnedRootHook: async () => { logs.push('delete-hook'); return gone; },
    requireEmptyOwnedAnchor: async () => logs.push('empty-anchor'),
    allocateGroup: async () => ({ gid: ++group, fresh: true }),
    replaceOwnedRules: async () => logs.push('rules'),
    enableOwnedReference: async () => ({ existingForeignPFStatesAbsentBeforeEnable: true }),
    startTunnelCore: async ({ ipv4Address }) => ({ interfaceName: `utun${++tunnel}`, pid: 3200 + tunnel,
      instanceId: `inert_tunnel_${tunnel}`, ipv4Address }),
    launchFixture: async ({ gid }) => [{ role: 'parent', pid: 10000 + gid, birth: '1:000001', gid, suspended: true }],
    resumeOwnedFixtures: async () => logs.push('resume'), discoverFixtureChildren: async () => {},
    reserveFixtureTuples: async run => { run.stateChecks = [{ reservedDestinationsAbsent: true }];
      return { source: 'simulated', freshTuplesVerified: true, noExistingOwnedStatesVerified: true,
        noStateRulesVerified: true, denyBeforeResumeVerified: true }; },
    verifyInstalledStatelessRules: async () => ({ noStateRulesVerified: true }),
    runFixtureCase: async () => assert.fail('simulated root proof must prevent any fixture case'),
    terminateOwnedFixtures: async () => logs.push('stop-fixtures'), assertNoOwnedGroupProcesses: async () => {},
    clearExactOwnedStates: async run => { run.noOwnedStatesRemainVerified = true; },
    stopOwnedTunnel: async () => logs.push('stop-tunnel'), removeGroups: async () => {},
    releaseOwnedReference: async () => logs.push('release-reference'), releaseLock: async () => logs.push('unlock'),
  };
  const controller = new MacOSPFController({ executor,
    inspectInstallation: async () => ({ available: true, verified: true, runtimeVerified: true }),
    inspectBundledComponent: async () => ({}), authenticateProxy: async () => true,
    identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true } });
  const call = async (method, params) => { sequence.push({ method, runId: params.runId ?? null }); return controller[method](params); };
  call.close = async () => { sequence.push({ method: 'EOF' }); const result = await controller.shutdown();
    return { closed: result.closed, started: true, cleanupUncertain: result.cleanupRequired }; };
  const created = { controls: 0, proxies: 0 };
  const matrix = options => runPFAcceptanceMatrix({ ...options, evidenceMode: 'simulation',
    createControl: async () => { created.controls++; return { existing: async () => true, fresh: async () => true, close: async () => true }; },
    createProxy: async () => { created.proxies++; return { route: { protocol: 'socks5', host: '127.0.0.1',
      port: 12000 + created.proxies, username: privateMarker, password: privateMarker }, close: async () => true }; } });
  return { controller, call, matrix, sequence, reads, logs, created };
}

test('pending or malformed resource pins fail closed and an exact authorization app is required', () => {
  const pending = { authorizationAppRelative: 'FINAL_AUTHORIZATION_APP_PATH_PENDING',
    installedManifestSHA256: 'FINAL_INSTALLED_MANIFEST_SHA256_PENDING', authorizerSHA256: 'FINAL_AUTHORIZER_SHA256_PENDING' };
  assert.throws(() => assertRetryPins(pending), { code: 'PF_RETRY_PINS_PENDING' });
  assert.ok(Object.isFrozen(RETRY_RESOURCE_PINS));
  assert.deepEqual(RETRY_RESOURCE_PINS, {
    authorizationAppRelative: 'build/local-authorization/EnvaraPFAuthorization-6f8386e1586a.app',
    installedManifestSHA256: '6f8386e1586af12775c9aadd1de339568d29cf93dc4135d8de00b8661407026f',
    authorizerSHA256: 'da4b12697ad6561b86adc1754851c149ac4889b837d912f24c49a907060731ee',
  });
  assert.ok(assertRetryPins().endsWith(RETRY_RESOURCE_PINS.authorizationAppRelative));
  const valid = { authorizationAppRelative: 'build/local-authorization/EnvaraPFAuthorization-123456abcdef.app',
    installedManifestSHA256: 'a'.repeat(64), authorizerSHA256: 'b'.repeat(64) };
  assert.ok(assertRetryPins(valid).endsWith(valid.authorizationAppRelative));
  assert.throws(() => assertRetryPins({ ...valid, authorizationAppRelative: '../arbitrary.app' }), { code: 'PF_RETRY_PINS_PENDING' });
});

test('the actual CLI refuses missing or invalid approval flags before resource checks or native spawn', async () => {
  const script = fileURLToPath(new URL('../scripts/macos-pf-owned-hook-retry.mjs', import.meta.url));
  // Never invoke main or the CLI with the valid approval flag. Immutable real
  // pins now pass validation; only these rejected arguments keep this inert.
  for (const argv of [[], ['--explicit-user-approved=1'], ['--explicit-user-approved', '--extra'], ['--request-controlled-experiment']]) {
    await assert.rejects(main(argv), { code: 'PF_RETRY_AUTHORIZE_FLAG_REQUIRED' });
    const result = spawnSync(process.execPath, [script, ...argv], {
      cwd: '/', env: { PATH: process.env.PATH ?? '/usr/bin:/bin' }, encoding: 'utf8', timeout: 10000, maxBuffer: 65536,
    });
    assert.equal(result.error, undefined); assert.equal(result.signal, null); assert.equal(result.status, 1);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), {
      operation: 'refused', acceptanceOnly: true, productionReady: false, reason: 'PF_RETRY_AUTHORIZE_FLAG_REQUIRED',
    });
  }
});

test('only known stages/reasons and boolean cleanup/status fields enter diagnostics', () => {
  assert.deepEqual(safeRetryError({ code: 'APPLICATION_ROUTING_NOT_READY', stage: 'fixture-start', message: privateMarker }),
    { reason: 'APPLICATION_ROUTING_NOT_READY', stage: 'fixture-start' });
  assert.deepEqual(safeRetryError({ code: privateMarker, stage: privateMarker }), { reason: 'PF_RETRY_OPERATION_FAILED' });
  const value = safeRetryCleanup(cleanup({ lease: privateMarker, proxySlots: privateMarker,
    preparationFailure: { stage: 'socket-reservation', code: 'APPLICATION_ROUTING_TIMEOUT', raw: privateMarker } }), runId);
  assert.equal(value.nativeControlledEvidenceAccepted, true);
  assert.deepEqual(value.preparationFailure, { stage: 'socket-reservation', reason: 'APPLICATION_ROUTING_TIMEOUT' });
  assertPrivateAbsent(value); assertPrivateAbsent(safeRetryStatus(status()));
  assert.equal(safeRetryStatus({ ready: privateMarker, runs: [{ runId: privateMarker }] }).ready, null);
  assert.equal(safeRetryCleanup(cleanup({ runId: 'not-owned' }), runId).receiptValid, false);
});

test('candidate run ID must be canonical v4 before any RPC or close', async () => {
  for (const candidate of [runId.toUpperCase(), runId.replace('-409c-', '-509c-'), runId.replace('-8a50-', '-7a50-'), null]) {
    const call = async () => assert.fail('invalid candidate must not call a helper');
    call.close = async () => assert.fail('invalid candidate must not open or close a helper');
    await assert.rejects(runOwnedHookRetrySession({ call, runId: candidate }), { code: 'PF_RETRY_RUN_ID_MISMATCH' });
  }
});

test('retired namespace diagnostics distinguish restoration from reclamation without private values', () => {
  const value = safeRetryCleanup(cleanup({ namespaceState: 'present', namespaceReclaimed: false, receiptRetired: true,
    lease: privateMarker, evidence: { ...cleanup().evidence, namespaceState: 'present', namespaceReclaimed: false,
      receiptRetired: true, ticket: privateMarker } }), runId);
  assert.equal(value.originalRootRestored, true);
  assert.equal(value.namespaceState, 'present'); assert.equal(value.namespaceReclaimed, false); assert.equal(value.receiptRetired, true);
  assert.equal(value.evidence.namespaceState, 'present'); assertPrivateAbsent(value);
  assert.deepEqual(safeRetryError({ code: 'APPLICATION_PF_NAMESPACE_CLEANUP_PENDING', lease: privateMarker }),
    { reason: 'APPLICATION_PF_NAMESPACE_CLEANUP_PENDING' });
  const unknown = safeRetryCleanup(cleanup({ namespaceState: privateMarker, namespaceReclaimed: 'true', receiptRetired: 1,
    evidence: { ...cleanup().evidence, namespaceState: privateMarker, namespaceReclaimed: 1, receiptRetired: 'true' } }), runId);
  assert.equal(unknown.namespaceState, 'unknown'); assert.equal(unknown.namespaceReclaimed, null); assert.equal(unknown.receiptRetired, null);
  assert.equal(unknown.evidence.namespaceState, 'unknown'); assertPrivateAbsent(unknown);
});

test('a default candidate is generated once for status and matrix without preparing an unknown run', async () => {
  const queried = []; let selected;
  const call = async (method, params) => { assert.equal(method, 'status'); queried.push(params.runId ?? null); return status(); };
  call.close = async () => ({ closed: true, started: false, cleanupUncertain: false });
  const report = await runOwnedHookRetrySession({ call, matrix: async options => {
    selected = options.runId;
    assert.match(selected, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    await options.call('status', { runId: selected }); return { selectedCasesPassed: false };
  } });
  assert.deepEqual(queried, [selected, null]); assert.equal(report.runId, null);
  assert.equal(report.preparationAttempted, false); assert.equal(report.cleanupReceipts.length, 0);
});

test('baseline matrix status never receives the cached candidate response', async () => {
  const queried = []; let candidateReads = 0;
  const call = async (method, params) => {
    assert.equal(method, 'status'); queried.push(params.runId ?? null);
    return { ...status(), anchor: params.runId ? pfRoutingAnchor(params.runId) : null, candidateRead: params.runId ? ++candidateReads : null };
  };
  call.close = async () => ({ closed: true, started: false, cleanupUncertain: false });
  await runOwnedHookRetrySession({ call, runId, matrix: async options => {
    assert.equal((await options.call('status', {})).anchor, null);
    assert.equal((await options.call('status', { runId })).candidateRead, 2);
    return { selectedCasesPassed: false };
  } });
  assert.deepEqual(queried, [runId, null, runId, null]);
});

test('actual controller and matrix use one candidate and still reject simulated native evidence', async () => {
  const fixture = inertControllerMatrix();
  const baseline = await fixture.controller.status();
  assert.equal(baseline.anchor, null); assert.equal(baseline.ownedRootHookCanCreate, false);
  fixture.reads.length = 0;
  const report = await runOwnedHookRetrySession({ call: fixture.call, matrix: fixture.matrix, runId });
  assert.equal(report.reason, 'PF_OWNED_ROOT_HOOK_EVIDENCE_REQUIRED');
  assert.equal(report.initialStatus.ownedRootHookCanCreate, true);
  assert.equal(report.preparationAttempted, true); assert.equal(report.nativeFixtureCasesAttempted, false);
  assert.deepEqual(fixture.created, { controls: 1, proxies: 2 });
  assert.deepEqual(fixture.reads, [runId, runId, null]);
  assert.deepEqual(fixture.sequence.map(value => value.method), ['status', 'prepareOwnedFixtures', 'cleanupOwnedFixtures', 'status', 'EOF']);
  assert.ok(fixture.sequence.filter(value => ['prepareOwnedFixtures', 'cleanupOwnedFixtures'].includes(value.method)).every(value => value.runId === runId));
  assert.equal(fixture.controller.runs.get(runId).phase, 'cleaned');
  assert.ok(fixture.logs.includes('insert-hook') && fixture.logs.includes('delete-hook'));
  assert.equal(report.cleanupReceipts[0].evidence.source, 'simulated');
  assert.equal(report.cleanupConfirmed, false); assert.equal(report.selectedCasesPassed, false);
  assert.equal(report.productionReady, false); assert.equal(report.nativeRoutingAcceptance, false); assertPrivateAbsent(report);
});

test('a foreign candidate in the actual matrix cannot adopt a cached controller status or prepare', async () => {
  const fixture = inertControllerMatrix();
  const report = await runOwnedHookRetrySession({ call: fixture.call, runId,
    matrix: options => fixture.matrix({ ...options, runId: otherRunId }) });
  assert.equal(report.reason, 'PF_RETRY_RUN_ID_MISMATCH');
  assert.equal(report.runId, null); assert.equal(report.preparationAttempted, false);
  assert.deepEqual(fixture.created, { controls: 0, proxies: 0 });
  assert.deepEqual(fixture.reads, [runId, null]); assert.deepEqual(fixture.logs, []);
  assert.deepEqual(fixture.sequence.map(value => value.method), ['status', 'status', 'EOF']);
  assert.equal(fixture.controller.runs.size, 0); assert.equal(report.cleanupReceipts.length, 0);
});

test('a foreign prepare ID is refused before capture or cleanup', async () => {
  const { call, sequence } = client(async () => assert.fail('foreign prepare must not reach the helper'));
  const report = await runOwnedHookRetrySession({ call, runId,
    matrix: options => options.call('prepareOwnedFixtures', { runId: otherRunId }) });
  assert.equal(report.reason, 'PF_RETRY_RUN_ID_MISMATCH'); assert.equal(report.runId, null);
  assert.equal(report.preparationAttempted, false); assert.equal(report.cleanupReceipts.length, 0);
  assert.deepEqual(sequence.map(value => value.method), ['status', 'status', 'EOF']);
});

test('failed prepare retains own run and stage/cleanup/post-status before EOF without private fields', async () => {
  const { call, sequence } = client(async method => {
    if (method === 'prepareOwnedFixtures') throw Object.assign(new Error(privateMarker),
      { code: 'APPLICATION_ROUTING_NOT_READY', stage: 'fixture-start', lease: privateMarker });
    if (method === 'cleanupOwnedFixtures') return cleanup({ preparationFailure: { stage: 'fixture-start', code: 'APPLICATION_ROUTING_NOT_READY' },
      evidence: { ...cleanup().evidence, noOwnedStatesCreatedVerified: false }, proxy: { password: privateMarker } });
    assert.fail('unexpected case RPC after failed prepare');
  });
  const report = await runOwnedHookRetrySession({ call, runId, matrix: async options => {
    assert.equal(options.runId, runId);
    assert.deepEqual(options.controlledCaseIds, RETRY_CASES);
    assert.equal(options.workTimeoutMs, 110000); assert.equal(options.cleanupTimeoutMs, 20000);
    await options.call('status', { runId });
    try { await options.call('prepareOwnedFixtures', { runId, slots: privateMarker }); }
    finally { await options.call('cleanupOwnedFixtures', { ...flags, runId }); }
  }, now: () => 0 });
  assert.equal(report.runId, runId); assert.equal(report.preparationAttempted, true);
  assert.equal(report.nativeFixtureCasesAttempted, false); assert.equal(report.selectedCasesPassed, false);
  assert.deepEqual(report.cleanupReceipts[0].preparationFailure, { stage: 'fixture-start', reason: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal(report.cleanupReceipts[0].nativeControlledEvidenceAccepted, false);
  assert.equal(report.observedRun.phase, 'cleaned'); assert.equal(report.cleanupConfirmed, false);
  assert.equal(report.diagnosticsComplete, true);
  assert.deepEqual(sequence.map(value => value.method), ['status', 'prepareOwnedFixtures', 'cleanupOwnedFixtures', 'status', 'EOF']);
  assertPrivateAbsent(report);
});

test('outer fallback cleans a known rejected prepare once then reads runs before EOF', async () => {
  const { call, sequence } = client(async method => {
    if (method === 'prepareOwnedFixtures') throw Object.assign(new Error(privateMarker), { code: 'APPLICATION_ROUTING_NOT_READY' });
    if (method === 'cleanupOwnedFixtures') return cleanup();
    assert.fail('unexpected RPC');
  });
  const report = await runOwnedHookRetrySession({ call, runId, matrix: async ({ call: rpc }) => rpc('prepareOwnedFixtures', { runId }) });
  assert.equal(report.cleanupReceipts.length, 1); assert.equal(report.cleanupConfirmed, true);
  assert.equal(report.selectedCasesPassed, false); assert.equal(report.productionReady, false); assert.equal(report.nativeRoutingAcceptance, false);
  assert.deepEqual(sequence.map(value => value.method), ['status', 'prepareOwnedFixtures', 'cleanupOwnedFixtures', 'status', 'EOF']);
  assertPrivateAbsent(report);
});

test('five successful selected checks require exact nested cleanup and safe final status; full acceptance stays false', async () => {
  const { call, sequence } = client(async method => method === 'cleanupOwnedFixtures' ? cleanup() : { privateResponse: privateMarker });
  const report = await runOwnedHookRetrySession({ call, runId, matrix: async ({ call: rpc }) => {
    await rpc('prepareOwnedFixtures', { runId });
    for (const caseId of RETRY_CASES) await rpc('runOwnedFixtureCase', { runId, caseId, challenges: privateMarker });
    await rpc('cleanupOwnedFixtures', { runId });
    return { nativeRoutingAttempted: true, selectedCasesPassed: true, localFixturesClosed: true, privateOutput: privateMarker,
      checks: { ...Object.fromEntries(RETRY_CASES.map(id => [id, { passed: true, nativeVerified: true, payload: privateMarker }])),
        privateCheck: { output: privateMarker } } };
  } });
  assert.equal(report.selectedCasesPassed, true); assert.equal(report.cleanupConfirmed, true);
  assert.equal(report.fullMatrix, false); assert.equal(report.productionReady, false); assert.equal(report.nativeRoutingAcceptance, false);
  assert.equal(sequence.at(-2).method, 'status'); assert.equal(sequence.at(-1).method, 'EOF');
  assertPrivateAbsent(report);
});

test('deadline clamps cleanup with local-finalization/status/close reserves and preserves close grace', async () => {
  let clock = 0;
  const { call, sequence } = client(async method => method === 'cleanupOwnedFixtures' ? cleanup() : {});
  await runOwnedHookRetrySession({ call, runId, now: () => clock, matrix: async ({ call: rpc }) => {
    await rpc('prepareOwnedFixtures', { runId }); clock = 140000;
    await rpc('cleanupOwnedFixtures', { runId }, { timeoutMs: 60000 });
    clock = 155000; return { selectedCasesPassed: false };
  } });
  assert.equal(sequence.find(value => value.method === 'cleanupOwnedFixtures').timeoutMs, 11000);
  assert.equal(sequence.at(-2).timeoutMs, 5000); assert.equal(sequence.at(-1).timeoutMs, 13000);
  assert.equal(RETRY_BUDGETS.initialStatusMs, 60000);
});

test('a slow native human authorization reduces fixture work inside the overall 180s ceiling', async () => {
  let clock = 0;
  const call = async () => { clock = 60000; return status(); };
  call.close = async () => ({ closed: true, cleanupUncertain: false });
  const report = await runOwnedHookRetrySession({ call, runId, now: () => clock, matrix: async options => {
    assert.equal(options.workTimeoutMs, 71000); return { selectedCasesPassed: false };
  } });
  assert.equal(report.budgets.actualWorkMs, 71000);
  assert.equal(60000 + report.budgets.actualWorkMs + RETRY_BUDGETS.cleanupMs + RETRY_BUDGETS.localFinalizationReserveMs +
    RETRY_BUDGETS.postStatusMs + RETRY_BUDGETS.closeMs, 180000);
});

test('no prepared run means no cleanup mutation; failed post-status is recorded before close', async () => {
  let statusCount = 0; const sequence = [];
  const call = async method => { sequence.push(method); if (++statusCount === 1) return status();
    throw Object.assign(new Error(privateMarker), { code: 'PF_HELPER_DEADLINE' }); };
  call.close = async () => { sequence.push('EOF'); return { closed: true, cleanupUncertain: false }; };
  const report = await runOwnedHookRetrySession({ call, runId, matrix: async () => ({ selectedCasesPassed: false }) });
  assert.equal(report.runId, null); assert.equal(report.cleanupReceipts.length, 0); assert.equal(report.diagnosticsComplete, false);
  assert.equal(report.reason, 'PF_RETRY_POST_STATUS_UNAVAILABLE');
  assert.deepEqual(report.postStatusError, { reason: 'PF_HELPER_DEADLINE' });
  assert.deepEqual(sequence, ['status', 'status', 'EOF']); assertPrivateAbsent(report);
});


test('UDP diagnostics preserve only bounded owned counters and cannot become routing evidence', () => {
  const value = safeFixtureUDPDiagnostics([{slot:'one', source:'owned-loopback-socks', routingEvidence:true,
    password:privateMarker, counts:{udpAssociations:2, udpPacketsReceived:1, udpPeerRejected:-1,
      udpHeaderRejected:1048577, udpDestinationRejected:NaN, udpChallengeRejected:privateMarker,
      udpDNSRejected:0, udpRepliesQueued:1, udpReplySendFailed:0, udpSocketErrors:0, payload:privateMarker}}]);
  assert.equal(value[0].routingEvidence,false); assert.equal(value[0].counts.udpAssociations,2);
  for (const key of ['udpPeerRejected','udpHeaderRejected','udpDestinationRejected','udpChallengeRejected']) assert.equal(value[0].counts[key],null);
  assertPrivateAbsent(value); assert.deepEqual(safeFixtureUDPDiagnostics([{slot:'one'},{slot:'one'}]),[]);
  assert.deepEqual(safeFixtureUDPDiagnostics([{slot:privateMarker}]),[]);
});

test('case failures retain only a known case, stage and fixed fixture code', () => {
  const caseFailure={caseId:'udp-concurrent', stage:'probe-transport', code:'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT', message:privateMarker};
  const value=safeRetryCleanup(cleanup({caseFailure}),runId);
  assert.deepEqual(value.caseFailure,{caseId:'udp-concurrent',stage:'probe-transport',code:'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT'});
  const observed=safeRetryStatus({...status(),runs:[{runId,phase:'cleanup-required',cleanupUncertain:true,caseFailure}]});
  assert.deepEqual(observed.runs[0].caseFailure,value.caseFailure); assertPrivateAbsent(observed);
  assert.equal(safeRetryCleanup(cleanup({caseFailure:{...caseFailure,stage:privateMarker}}),runId).caseFailure,null);
  assert.equal(safeRetryCleanup(cleanup({caseFailure:{...caseFailure,caseId:privateMarker}}),runId).caseFailure,null);
  assert.equal(safeRetryCleanup(cleanup({caseFailure:{...caseFailure,code:privateMarker}}),runId).caseFailure.code,'PF_RETRY_OPERATION_FAILED');
});


test('size diagnostics retain only fixed role/size/receipt fields and reject duplicate attribution', () => {
  const value=safeUDPSizeDiagnostics([{slot:'one',role:'parent',payloadBytes:1200,authenticatedFixtureReceipts:1,password:privateMarker},
    {slot:'two',role:'child',payloadBytes:2048,authenticatedFixtureReceipts:129,payload:privateMarker}]);
  assert.deepEqual(value,[{slot:'one',role:'parent',payloadBytes:1200,authenticatedFixtureReceipts:1},
    {slot:'two',role:'child',payloadBytes:2048,authenticatedFixtureReceipts:null}]);
  assertPrivateAbsent(value); assert.deepEqual(safeUDPSizeDiagnostics([{slot:'one',role:'parent',payloadBytes:1200},
    {slot:'one',role:'parent',payloadBytes:2048}]),[]);
  assert.deepEqual(safeUDPSizeDiagnostics([{slot:'one',role:'parent',payloadBytes:4096}]),[]);
});

test('the retry selects DNS before UDP and restores full-size payloads for every process', async () => {
  let captured;
  const {call}=client(async ()=>assert.fail('no fixtures should start in this option-only check'));
  await runOwnedHookRetrySession({call,runId,matrix:async options=>{captured=options; return {selectedCasesPassed:false};}});
  assert.equal(captured.controlledUDPSizeDiagnostic,false);
  assert.deepEqual(captured.controlledCaseIds,['realm-identities','tcp-concurrent','tcp-half-close','dns-tcp53','udp-concurrent']);
});
