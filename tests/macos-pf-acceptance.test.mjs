import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, randomUUID } from 'node:crypto';
import { SocketReader, openSocksStream } from '../native/macos-local-routing/socks-stream.mjs';
import { PF_ACCEPTANCE_PROTOCOL, PF_ACCEPTANCE_CASES, PF_ACCEPTANCE_ANCHOR, PF_FIXTURE_TARGET,
  createPFAcceptancePlan, createPFFixtureSocksServer, validatePFCaseEvidence,
  validatePFProbeBinding, validatePFControlledCleanupEvidence, validatePFPreparedRootHook, runPFAcceptanceMatrix } from '../native/macos-pf-routing/acceptance-plan.mjs';
import { makeCachedFixtureDnsResponse } from '../scripts/macos-app-proxy-fixture-matrix.mjs';
import { createPersistentPFHelperClient } from '../scripts/accept-macos-pf-routing.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

const flags = { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL, acceptanceOnly: true, ready: false, productionReceiptAllowed: false };
const ownedRootHook = runId => ({ source: 'native-pf-root-hook', anchor: pfRoutingAnchor(runId),
  runId, verified: true, ticketSource: 'this-INSERT-return-only' });
const boundStatus = (status, params) => ({ ...status, anchor: pfRoutingAnchor(params.runId) });
const controlledCleanup = runId => ({ ...flags, runId, cleanupUncertain: false, evidence: {
  source: 'native-pf', platform: 'darwin', complete: true, cleanupUncertain: false,
  ownedProcessesExited: true, ownedTunnelsRemoved: true, ownedAnchorRemoved: true, unrelatedPFUnchanged: true,
  unrelatedRoutesUnchanged: true, hostDNSUnchanged: true, noOwnedStatesCreatedVerified: true,
  noOwnedStatesRemainVerified: true, ownedRootHookRemoved: true, originalRootRestored: true, ownedPFReferenceReleased: true,
} });
const timeout = (promise, milliseconds = 2000) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('test deadline')), milliseconds);
  promise.then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
});
function realms() {
  return ['one', 'two'].map((slot, i) => ({ slot, realmId: randomUUID(), gid: 7100 + i,
    tunnel: { interfaceName: `utun${80 + i}`, pid: 200 + i, instanceId: `fixture-instance-${i}` },
    fixtures: ['parent', 'child', 'detached'].map((role, r) => ({ role, pid: 100 + i * 10 + r, birth: '1:000001', gid: 7100 + i })) }));
}
const packetObserver = { native: true, independent: true, pid: 400, birth: '1:000002', complete: true, selectedAttempts: 4, physicalSelectedPackets: 0 };

test('default plan has all concrete cases and never grants activation or native acceptance', () => {
  const plan = createPFAcceptancePlan({ platform: 'darwin', pfReadStatus: 'PERMISSION_DENIED' });
  assert.equal(plan.activatesSystem, false); assert.equal(plan.productionReady, false); assert.equal(plan.nativeRoutingAcceptance, false);
  assert.equal(plan.anchor, PF_ACCEPTANCE_ANCHOR); assert.equal(plan.cases.length, 16);
  assert.ok(plan.cases.every(c => c.nativeVerified === false && c.implementedByHelper === false));
  assert.ok(plan.fixtures.every(f => f.roles.includes('detached') && f.transports.includes('udp')));
  assert.ok(plan.controlledPreconditions.status.includes('ownedRootHookCanCreate'));
  assert.ok(!plan.controlledPreconditions.status.includes('stockAppleAnchorHookVerified'));
});

test('timeouts and helper passed flags cannot attest block, crash or name-reuse behavior', () => {
  for (const id of ['udp-block', 'first-packet', 'core-crash', 'helper-crash', 'utun-reuse', 'ipv6-icmp-raw']) {
    assert.equal(validatePFCaseEvidence(id, { source: 'native-pf', platform: 'darwin', complete: true, passed: true, timeout: true }), false);
  }
});

test('whole supervisor crash requires a surviving independent observer with attempted packets', () => {
  const evidence = { source: 'native-pf', platform: 'darwin', complete: true, packetObserver,
    supervisorExitConfirmed: true, observerSurvivedSupervisor: true, bothRealmsBlocked: true, existingSelectedBlocked: true, newSelectedBlocked: true };
  assert.equal(validatePFCaseEvidence('helper-crash', evidence), true);
  assert.equal(validatePFCaseEvidence('helper-crash', { ...evidence, packetObserver: { ...packetObserver, independent: false } }), false);
  assert.equal(validatePFCaseEvidence('helper-crash', { ...evidence, packetObserver: { ...packetObserver, selectedAttempts: 0 } }), false);
  assert.equal(validatePFCaseEvidence('helper-crash', { ...evidence, packetObserver: { ...packetObserver, physicalSelectedPackets: 1 } }), false);
});

test('interface reuse requires actual different unrelated instance and zero selected replacement packets', () => {
  const evidence = { source: 'native-pf', platform: 'darwin', complete: true, packetObserver,
    originalInstanceRemoved: true, sameNameRecreated: true, replacementUnrelated: true,
    replacementInstanceDifferent: true, selectedPacketsOnReplacement: 0 };
  assert.equal(validatePFCaseEvidence('utun-reuse', evidence), true);
  assert.equal(validatePFCaseEvidence('utun-reuse', { ...evidence, replacementInstanceDifferent: false }), false);
  assert.equal(validatePFCaseEvidence('utun-reuse', { ...evidence, selectedPacketsOnReplacement: 1 }), false);
});

test('cleanup proof refuses broad state deletion or incomplete unrelated-state preservation', () => {
  const evidence = { source: 'native-pf', platform: 'darwin', complete: true, exactOwnedStateIDsObserved: true,
    exactOwnedStateIDsRemoved: true, unrelatedStateIDsPreserved: true, globalFlushUsed: false, addressWideKillUsed: false };
  assert.equal(validatePFCaseEvidence('exact-state-purge', evidence), true);
  assert.equal(validatePFCaseEvidence('exact-state-purge', { ...evidence, globalFlushUsed: true }), false);
  assert.equal(validatePFCaseEvidence('exact-state-purge', { ...evidence, unrelatedStateIDsPreserved: false }), false);
});

test('missing exact cleanup rejects before creating even local fixtures or issuing mutation RPC', async () => {
  const methods = []; let fixtureCount = 0;
  const report = await runPFAcceptanceMatrix({ call: async method => { methods.push(method); return flags; },
    createProxy: async () => { fixtureCount++; throw new Error('must not create'); },
    createControl: async () => { fixtureCount++; throw new Error('must not create'); } });
  assert.deepEqual(methods, ['status']); assert.equal(fixtureCount, 0);
  assert.equal(report.nativeRoutingAttempted, false); assert.equal(report.nativeRoutingAcceptance, false);
  assert.equal(report.reason, 'PF_ACCEPTANCE_PREFLIGHT_REQUIRED');
});

test('unsupported native case refuses before prepare even if other preflight flags are true', async () => {
  const methods = [], status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true,
    callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, stockAppleAnchorHookVerified: false, ownedRootHookCanCreate: true,
    exactStateCleanupVerified: true, independentPacketObserverVerified: true, fixtureOperations: ['tcp-concurrent'] };
  const report = await runPFAcceptanceMatrix({ call: async (method, params) => { methods.push(method); return boundStatus(status, params); } });
  assert.deepEqual(methods, ['status']); assert.equal(report.reason, 'PF_ACCEPTANCE_CASES_UNAVAILABLE');
});

test('a supported stateless subset does not require unsupported full-matrix cases and never promotes full acceptance', async () => {
  const activeRealms = realms().map(r => ({ ...r, fixtures: r.fixtures.filter(f => f.role !== 'detached') })), methods = [];
  const status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true, callerConsoleUIDVerified: true,
    privilegedOperationsAuthorized: true, stockAppleAnchorHookVerified: false, ownedRootHookCanCreate: true, statelessControlledFixtures: true,
    noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'tcp-concurrent', 'cleanup'] };
  const report = await runPFAcceptanceMatrix({ controlledCaseIds: ['tcp-concurrent'], evidenceMode: 'simulation',
    createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => true }),
    createProxy: async () => ({ route: {}, register: () => {}, received: () => true, snapshot: () => ({ crossRouteRejected: 0 }), close: async () => true }),
    call: async (method, params) => {
      methods.push(method);
      if (method === 'status') return boundStatus(status, params);
      if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms: activeRealms,
        ownedRootHook: ownedRootHook(params.runId), existingForeignPFStatesAbsentBeforeEnable: true,
        statelessEvidence: { source: 'native-pf', freshTuplesVerified: true, noExistingOwnedStatesVerified: true,
          noStateRulesVerified: true, denyBeforeResumeVerified: true } };
      if (method === 'cleanupOwnedFixtures') return { ...flags, runId: params.runId, evidence: { source: 'native-pf', platform: 'darwin', complete: true,
        ownedProcessesExited: true, ownedTunnelsRemoved: true, ownedAnchorRemoved: true, unrelatedPFUnchanged: true,
        unrelatedRoutesUnchanged: true, hostDNSUnchanged: true, noOwnedStatesCreatedVerified: true, noOwnedStatesRemainVerified: true,
        ownedRootHookRemoved: true, originalRootRestored: true, ownedPFReferenceReleased: true, cleanupUncertain: false } };
      return { ...flags, runId: params.runId, caseId: params.caseId,
        evidence: { source: 'native-pf', platform: 'darwin', complete: true, threeGIDsVerified: true, coldExecVerified: true,
          overlapVerified: true, exactProcessAttribution: true, freshTuplesVerified: true, noExistingMatchingStatesVerified: true, noStateRulesVerified: true },
        probes: params.challenges.map(challenge => ({ slot: challenge.slot, role: challenge.role,
          fixture: activeRealms.find(r => r.slot === challenge.slot).fixtures.find(f => f.role === challenge.role),
          result: { ok: true, matches: true, payloadBase64: challenge.request.payloadBase64, receivedBytes: 2048,
            reservationId: randomUUID(), consumed: true, usedReservedSocket: true, protocol: challenge.request.op,
            remoteHost: challenge.request.host, remotePort: challenge.request.port,
            sourceAddressResolved: true, sourceWildcard: false, localHost: '192.0.2.21', localPort: 50123 } })) };
    } });
  assert.ok(methods.includes('prepareOwnedFixtures')); assert.equal(report.selectedCasesPassed, true);
  assert.equal(report.controlledExperiment, true); assert.equal(report.fullMatrix, false);
  assert.equal(report.fixtureMatrixPassed, false); assert.equal(report.nativeRoutingAcceptance, false); assert.equal(report.productionReady, false);
  assert.ok(report.fixtureScope.every(r => r.fixtures.length === 2 && r.fixtures.every(f => f.role !== 'detached')));
});

test('each stateless probe requires same-FD fresh tuple and actual no-state observations', () => {
  const evidence = { source: 'native-pf', platform: 'darwin', complete: true, overlapVerified: true, exactProcessAttribution: true,
    freshTuplesVerified: true, noExistingMatchingStatesVerified: true, noStateRulesVerified: true };
  assert.equal(validatePFCaseEvidence('tcp-concurrent', evidence, { controlledExperiment: true }), true);
  for (const key of ['freshTuplesVerified', 'noExistingMatchingStatesVerified', 'noStateRulesVerified']) {
    assert.equal(validatePFCaseEvidence('tcp-concurrent', { ...evidence, [key]: false }, { controlledExperiment: true }), false);
  }
});

test('same-FD result verifies the native consumed reservation and resolved actual destination tuple', () => {
  const request = { op: 'tcp', host: PF_FIXTURE_TARGET, port: 44441 };
  const result = { reservationId: randomUUID(), consumed: true, usedReservedSocket: true, protocol: 'tcp',
    remoteHost: PF_FIXTURE_TARGET, remotePort: 44441, sourceAddressResolved: true, sourceWildcard: false, localHost: '192.0.2.21', localPort: 50123 };
  assert.equal(validatePFProbeBinding(result, request), true);
  for (const patch of [{ usedReservedSocket: false }, { consumed: false }, { protocol: 'udp' }, { remotePort: 44442 },
    { remoteHost: '203.0.113.21' }, { sourceAddressResolved: false }, { sourceWildcard: true }, { localHost: '0.0.0.0' }]) {
    assert.equal(validatePFProbeBinding({ ...result, ...patch }, request), false);
  }
});

test('controlled cleanup requires every native receipt field and cannot substitute a false purge claim or bare flags', () => {
  const evidence = { source: 'native-pf', platform: 'darwin', complete: true, ownedProcessesExited: true,
    ownedTunnelsRemoved: true, ownedAnchorRemoved: true, unrelatedPFUnchanged: true, unrelatedRoutesUnchanged: true,
    hostDNSUnchanged: true, noOwnedStatesCreatedVerified: true, noOwnedStatesRemainVerified: true,
    ownedRootHookRemoved: true, originalRootRestored: true, ownedPFReferenceReleased: true, cleanupUncertain: false };
  assert.equal(validatePFControlledCleanupEvidence(evidence), true);
  for (const key of Object.keys(evidence)) { const partial = { ...evidence }; delete partial[key]; assert.equal(validatePFControlledCleanupEvidence(partial), false, key); }
  assert.equal(validatePFControlledCleanupEvidence({ ...evidence, cleanupUncertain: true }), false);
  assert.equal(validatePFControlledCleanupEvidence({ ...flags, ownedAnchorStatesPurged: true, cleanupUncertain: false }), false);
});

test('prepared root hook must bind the exact run and owned anchor to an INSERT-return receipt', () => {
  const runId = randomUUID(), proof = ownedRootHook(runId);
  assert.equal(validatePFPreparedRootHook(proof, runId), true);
  for (const patch of [{ source: 'stock-apple-hook' }, { anchor: 'com.apple/envara.pf.v1' },
    { anchor: 'io.envara.pf.root.v1' }, { anchor: PF_ACCEPTANCE_ANCHOR }, { anchor: pfRoutingAnchor(randomUUID()) },
    { runId: randomUUID() }, { verified: false }, { ticketSource: 'observed-rule-by-name' }]) {
    assert.equal(validatePFPreparedRootHook({ ...proof, ...patch }, runId), false);
  }
  assert.equal(validatePFPreparedRootHook(null, runId), false);
  assert.equal(validatePFPreparedRootHook(proof, runId.toUpperCase()), false);
});

test('candidate status binds the same run before any local fixture or prepare operation', async () => {
  const runId = randomUUID(), methods = []; let localFixtures = 0;
  const report = await runPFAcceptanceMatrix({ runId, controlledCaseIds: ['realm-identities'],
    call: async (method, params) => {
      methods.push(method); assert.deepEqual(params, { runId });
      return { ...flags, anchor: pfRoutingAnchor(randomUUID()), rootOwnedInstallationVerified: true,
        callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, ownedRootHookCanCreate: true,
        statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'cleanup'] };
    }, createControl: async () => { localFixtures++; throw new Error('must not create'); } });
  assert.deepEqual(methods, ['status']); assert.equal(localFixtures, 0);
  assert.equal(report.anchor, pfRoutingAnchor(runId)); assert.equal(report.nativeRoutingAttempted, false);
  assert.equal(report.reason, 'PF_ACCEPTANCE_CASES_UNAVAILABLE');
});

test('noncanonical run identities refuse before invoking the helper', async () => {
  for (const runId of [randomUUID().toUpperCase(), 'io.envara.pf.root.v1', '1350575c-bf18-109c-8a50-1a49ed6eb155']) {
    await assert.rejects(runPFAcceptanceMatrix({ runId, call: async () => assert.fail('must not call helper') }),
      { code: 'PF_ACCEPTANCE_OPTIONS_INVALID' });
  }
});

test('stock Apple availability cannot substitute for owned root-hook creation preflight', async () => {
  const methods = []; let localFixtures = 0;
  const status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true,
    callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, stockAppleAnchorHookVerified: true,
    statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'cleanup'] };
  const report = await runPFAcceptanceMatrix({ controlledCaseIds: ['realm-identities'],
    call: async (method, params) => { methods.push(method); return boundStatus(status, params); },
    createControl: async () => { localFixtures++; throw new Error('must not create'); },
    createProxy: async () => { localFixtures++; throw new Error('must not create'); } });
  assert.deepEqual(methods, ['status']); assert.equal(localFixtures, 0);
  assert.equal(report.reason, 'PF_ACCEPTANCE_PREFLIGHT_REQUIRED');
});

test('missing root-hook prepare proof triggers cleanup before any fixture probe', async () => {
  const methods = [], status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true,
    callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, ownedRootHookCanCreate: true,
    statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'cleanup'] };
  const report = await runPFAcceptanceMatrix({ controlledCaseIds: ['realm-identities'], evidenceMode: 'simulation',
    createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => true }),
    createProxy: async () => ({ route: {}, close: async () => true }),
    call: async (method, params) => { methods.push(method); if (method === 'status') return boundStatus(status, params);
      if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms: realms() };
      return { ...flags, runId: params.runId, cleanupUncertain: true }; } });
  assert.equal(report.reason, 'PF_OWNED_ROOT_HOOK_EVIDENCE_REQUIRED');
  assert.ok(methods.includes('cleanupOwnedFixtures')); assert.ok(!methods.includes('runOwnedFixtureCase'));
  assert.equal(report.productionReady, false); assert.equal(report.cleanup.uncertain, true);
});

test('owned root-hook proof does not substitute for absence of stale foreign states before PF enable', async () => {
  const methods = [], status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true,
    callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, ownedRootHookCanCreate: true,
    statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'cleanup'] };
  const report = await runPFAcceptanceMatrix({ controlledCaseIds: ['realm-identities'], evidenceMode: 'simulation',
    createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => true }),
    createProxy: async () => ({ route: {}, close: async () => true }),
    call: async (method, params) => { methods.push(method); if (method === 'status') return boundStatus(status, params);
      if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms: realms(),
        ownedRootHook: ownedRootHook(params.runId) };
      return { ...flags, runId: params.runId, cleanupUncertain: true }; } });
  assert.equal(report.reason, 'PF_FOREIGN_STATE_PREFLIGHT_EVIDENCE_REQUIRED');
  assert.ok(methods.includes('cleanupOwnedFixtures')); assert.ok(!methods.includes('runOwnedFixtureCase'));
  assert.equal(report.nativeRoutingAcceptance, false);
});

test('full matrix refuses missing detached identities instead of reusing parent metadata', () => {
  const actual = realms().map(r => ({ ...r, fixtures: r.fixtures.filter(f => f.role !== 'detached') }));
  const evidence = { source: 'native-pf', platform: 'darwin', complete: true, threeGIDsVerified: true, coldExecVerified: true };
  assert.equal(validatePFCaseEvidence('realm-identities', evidence, { realms: actual }), false);
  assert.equal(validatePFCaseEvidence('realm-identities', evidence, { realms: actual, controlledExperiment: true }), true);
});

test('stateless proof must come from prepare native evidence, not claimed request fields', async () => {
  const methods = [], activeRealms = realms();
  const status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true, callerConsoleUIDVerified: true,
    privilegedOperationsAuthorized: true, stockAppleAnchorHookVerified: false, ownedRootHookCanCreate: true, statelessControlledFixtures: true,
    noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'tcp-concurrent', 'cleanup'] };
  const report = await runPFAcceptanceMatrix({ controlledCaseIds: ['tcp-concurrent'], evidenceMode: 'simulation',
    createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => true }),
    createProxy: async () => ({ route: {}, close: async () => true }), call: async (method, params) => {
      methods.push(method); if (method === 'status') return boundStatus(status, params);
      if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms: activeRealms,
        ownedRootHook: ownedRootHook(params.runId), existingForeignPFStatesAbsentBeforeEnable: true,
        freshTuplesVerified: true, noExistingOwnedStatesVerified: true, noStateRulesVerified: true };
      return { ...flags, runId: params.runId, cleanupUncertain: true };
    } });
  assert.equal(report.reason, 'PF_STATELESS_NATIVE_EVIDENCE_REQUIRED');
  assert.ok(methods.includes('cleanupOwnedFixtures')); assert.ok(!methods.includes('runOwnedFixtureCase'));
  assert.equal(report.nativeRoutingAcceptance, false); assert.equal(report.cleanup.uncertain, true);
});

async function receive(socket, payload, { fin = false } = {}) {
  return await timeout(new Promise((resolve, reject) => {
    let received = Buffer.alloc(0);
    socket.on('data', bytes => { received = Buffer.concat([received, bytes]); if (!fin && received.length >= payload.length) resolve(received); });
    socket.once('end', () => resolve(received)); socket.once('error', reject); socket.resume();
    // Deliberately split the upload: a partial allowed payload is not cross-route leakage.
    socket.write(payload.subarray(0, 7)); setTimeout(() => fin ? socket.end(payload.subarray(7)) : socket.write(payload.subarray(7)), 5);
  }));
}

test('real loopback SOCKS TCP framing accepts fragmented owned payload and rejects cross-route payload', async t => {
  const one = await createPFFixtureSocksServer({ slot: 'one' }), two = await createPFFixtureSocksServer({ slot: 'two' });
  t.after(async () => { await one.close(); await two.close(); });
  const payload = randomBytes(2048), other = randomBytes(2048); one.register('own', payload, 'tcp'); two.register('other', other, 'tcp');
  const a = await openSocksStream(one.route, { host: PF_FIXTURE_TARGET, port: 44441 }); t.after(() => a.socket.destroy());
  assert.deepEqual(await receive(a.socket, payload), payload); assert.equal(one.received('own'), true); assert.equal(one.snapshot().crossRouteRejected, 0);
  const b = await openSocksStream(two.route, { host: PF_FIXTURE_TARGET, port: 44441 }); t.after(() => b.socket.destroy());
  const ended = timeout(new Promise(resolve => b.socket.once('end', resolve))); b.socket.resume(); b.socket.write(payload); await ended;
  assert.equal(two.snapshot().crossRouteRejected, 1); assert.equal(two.received('other'), false);
});

test('real loopback upstream waits for upload FIN before replying, leaving the read direction alive', async t => {
  const proxy = await createPFFixtureSocksServer({ slot: 'one' }); t.after(() => proxy.close());
  const payload = randomBytes(4096); proxy.register('fin', payload, 'fin');
  const wire = await openSocksStream(proxy.route, { host: PF_FIXTURE_TARGET, port: 44442 }); t.after(() => wire.socket.destroy());
  assert.deepEqual(await receive(wire.socket, payload, { fin: true }), payload);
  assert.equal(proxy.snapshot().halfCloseReceipts, 1); assert.equal(proxy.received('fin'), true);
});

async function udpAssociation(proxy) {
  const socket = net.createConnection({ host: proxy.host, port: proxy.port }); socket.on('error', () => {});
  const reader = new SocketReader(socket); socket.write(Buffer.from([5, 1, 2]));
  assert.deepEqual(await reader.read(2), Buffer.from([5, 2]));
  const u = Buffer.from(proxy.username), p = Buffer.from(proxy.password);
  socket.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
  assert.deepEqual(await reader.read(2), Buffer.from([1, 0])); socket.write(Buffer.from([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]));
  assert.deepEqual(await reader.read(4), Buffer.from([5, 0, 0, 1])); const destination = await reader.read(6);
  reader.release(); socket.resume(); return { socket, port: destination.readUInt16BE(4) };
}

test('real fixture TCP53 parses DNS and preserves its complete response after caller FIN', async t => {
  const proxy = await createPFFixtureSocksServer({ slot: 'one' }); t.after(() => proxy.close());
  const hostname = 'owned-pf.envara-fixture.test'; proxy.allowHostname(hostname);
  const header = Buffer.alloc(12); header.writeUInt16BE(2301, 0); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
  const query = Buffer.concat([header, ...hostname.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0, 0, 1, 0, 1])]);
  proxy.register('dns53', query, 'dns');
  const socket = net.createConnection({ host: proxy.route.host, port: proxy.route.port, allowHalfOpen: true }); t.after(() => socket.destroy()); socket.on('error', () => {});
  const reader = new SocketReader(socket); socket.write(Buffer.from([5, 1, 2])); assert.deepEqual(await timeout(reader.read(2)), Buffer.from([5, 2]));
  const u = Buffer.from(proxy.route.username), p = Buffer.from(proxy.route.password);
  socket.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p])); assert.deepEqual(await timeout(reader.read(2)), Buffer.from([1, 0]));
  socket.write(Buffer.from([5, 1, 0, 1, 1, 1, 1, 1, 0, 53])); assert.deepEqual(await timeout(reader.read(4)), Buffer.from([5, 0, 0, 1])); await timeout(reader.read(6)); reader.release();
  const prefix = Buffer.alloc(2); prefix.writeUInt16BE(query.length);
  const result = await receive(socket, Buffer.concat([prefix, query]), { fin: true });
  const response = makeCachedFixtureDnsResponse(query, { address4: proxy.answers[0], address6: proxy.answers[1] }), expectedPrefix = Buffer.alloc(2); expectedPrefix.writeUInt16BE(response.length);
  assert.deepEqual(result, Buffer.concat([expectedPrefix, response])); assert.equal(proxy.received('dns53'), true);
  assert.equal(proxy.snapshot().dnsAReplies, 1);
});

test('real authenticated SOCKS UDP association only echoes a registered route payload', async t => {
  const proxy = await createPFFixtureSocksServer({ slot: 'two' }); t.after(() => proxy.close());
  const association = await timeout(udpAssociation(proxy.route)); t.after(() => association.socket.destroy());
  const udp = dgram.createSocket('udp4'); udp.on('error', () => {}); t.after(() => { try { udp.close(); } catch {} });
  const payload = randomBytes(2048); proxy.register('udp', payload, 'udp');
  const header = Buffer.from([0, 0, 0, 1, 198, 51, 100, 42, 0, 0]); header.writeUInt16BE(44444, 8);
  const reply = timeout(new Promise((resolve, reject) => { udp.once('message', resolve); udp.send(Buffer.concat([header, payload]), association.port, '127.0.0.1', error => { if (error) reject(error); }); }));
  assert.deepEqual(await reply, Buffer.concat([header, payload])); assert.equal(proxy.received('udp'), true);
  assert.equal(proxy.snapshot().udpReceipts, 1);
});

test('real fixture authentication refuses a wrong password before accepting a route', async t => {
  const proxy = await createPFFixtureSocksServer({ slot: 'one' }); t.after(() => proxy.close());
  await assert.rejects(openSocksStream({ ...proxy.route, password: 'wrong-fixture-password' }, { host: PF_FIXTURE_TARGET, port: 44441 }));
  assert.equal(proxy.snapshot().authenticated, 0); assert.equal(proxy.snapshot().rejected, 1);
});

test('simulated helper contracts can never promote native acceptance and never expose payloads or credentials', async () => {
  const activeRealms = realms(), status = { ...flags, anchor: PF_ACCEPTANCE_ANCHOR, rootOwnedInstallationVerified: true,
    callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, stockAppleAnchorHookVerified: false, ownedRootHookCanCreate: true,
    exactStateCleanupVerified: true, independentPacketObserverVerified: true, fixtureOperations: PF_ACCEPTANCE_CASES.map(c => c.id) };
  const privateValues = [];
  const report = await runPFAcceptanceMatrix({ evidenceMode: 'simulation', createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => true }),
    createProxy: async ({ slot }) => ({ route: { password: `synthetic-private-${slot}` }, answers: ['203.0.113.42'],
      register: (_id, bytes) => privateValues.push(bytes.toString('base64')), received: () => true, allowHostname: () => {},
      snapshot: () => ({ crossRouteRejected: 0, dnsAReplies: 0, dnsAAAAReplies: 0 }), close: async () => true }),
    call: async (method, params) => {
      if (method === 'status') return boundStatus(status, params);
      if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms: activeRealms, ownedRootHook: ownedRootHook(params.runId) };
      if (method === 'cleanupOwnedFixtures') return { ...flags, runId: params.runId, evidence: { source: 'native-pf', platform: 'darwin', complete: true,
        ownedProcessesExited: true, ownedTunnelsRemoved: true, ownedAnchorStatesPurged: true, ownedAnchorRemoved: true,
        unrelatedPFUnchanged: true, unrelatedRoutesUnchanged: true, hostDNSUnchanged: true, cleanupUncertain: false }, cleanupUncertain: false };
      const evidence = { source: 'native-pf', platform: 'darwin', complete: true, threeGIDsVerified: true, coldExecVerified: true,
        overlapVerified: true, exactProcessAttribution: true };
      // A missing FIN proof stops the matrix. Mock flags must not become native completion.
      return { ...flags, runId: params.runId, caseId: params.caseId, evidence,
        probes: params.challenges.map(challenge => ({ slot: challenge.slot, role: challenge.role,
          fixture: activeRealms.find(r => r.slot === challenge.slot).fixtures.find(f => f.role === challenge.role),
          result: { ok: true, matches: true, payloadBase64: challenge.request.payloadBase64, receivedBytes: 2048 } })) };
    } });
  assert.equal(report.nativeRoutingAcceptance, false); assert.equal(report.nativeRoutingAttempted, false);
  assert.equal(report.checks['tcp-concurrent'].passed, true); assert.equal(report.checks['tcp-concurrent'].nativeVerified, false);
  assert.equal(report.checks['tcp-half-close'].passed, false);
  const serialized = JSON.stringify(report); assert.ok(!serialized.includes('synthetic-private'));
  assert.ok(privateValues.every(value => !serialized.includes(value))); assert.ok(!serialized.includes('envara-fixture.test'));
});

test('real persistent private process keeps prepare/case/cleanup state on one channel, using native result-or-error envelopes', async t => {
  const runId = randomUUID(), receipt = controlledCleanup(runId);
  const program = `import readline from 'node:readline'; let prepared=false, count=0;
    for await(const line of readline.createInterface({input:process.stdin})){
      const r=JSON.parse(line); count++;
      if(r.method==='prepareOwnedFixtures') prepared=true;
      const result={pid:process.pid,count,prepared,ready:false};
      if(r.method==='cleanupOwnedFixtures'){prepared=false;result.cleaned=true;Object.assign(result,${JSON.stringify(receipt)});}
      process.stdout.write(JSON.stringify({protocol:r.protocol,version:r.version,id:r.id,result})+'\\n');
    }`;
  let spawnCount = 0;
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => {
    spawnCount++; return spawn(process.execPath, ['--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] });
  } });
  t.after(() => call.close());
  const status = await call('status'), prepared = await call('prepareOwnedFixtures', { runId }),
    ran = await call('runOwnedFixtureCase', { runId }), cleaned = await call('cleanupOwnedFixtures', { runId });
  assert.equal(spawnCount, 1); assert.equal(status.pid, prepared.pid); assert.equal(prepared.pid, ran.pid); assert.equal(ran.pid, cleaned.pid);
  assert.equal(ran.prepared, true); assert.equal(cleaned.cleaned, true); assert.equal(cleaned.count, 4);
  assert.deepEqual(await call.close(), { closed: true, started: true, cleanupUncertain: false });
});

test('actual unprivileged source helper accepts repeated read-only requests on one persistent channel', async t => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'); let spawnCount = 0;
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => {
    spawnCount++; return spawn(process.execPath, [path.join(root, 'native/macos-pf-routing/helper.mjs'), '--rpc'], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } });
  } });
  t.after(() => call.close());
  const first = await call('status', {}, { timeoutMs: 5000 }), second = await call('status', {}, { timeoutMs: 5000 });
  assert.equal(spawnCount, 1); assert.equal(first.acceptanceProtocol, PF_ACCEPTANCE_PROTOCOL); assert.equal(second.acceptanceOnly, true);
  assert.equal(first.ready, false); assert.equal(second.ready, false); assert.equal(second.privilegedOperationsAuthorized, false);
  // Read-only replies prove no native activation, but cannot attest controller
  // cleanup of a controlled lifecycle solely from an outer process exit.
  const closing = await call.close(); assert.equal(closing.closed, true); assert.equal(closing.cleanupUncertain, true);
});

function replyClient(t, replies) {
  const program = `import readline from 'node:readline'; const replies=${JSON.stringify(replies)};
    for await(const line of readline.createInterface({input:process.stdin})){
      const r=JSON.parse(line), result=replies.shift();
      process.stdout.write(JSON.stringify({protocol:r.protocol,version:r.version,id:r.id,result})+'\\n');
    }`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] });
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => child });
  t.after(() => call.close());
  return { call, child };
}

test('controller cleanup uncertainty survives a normal outer relay exit', async t => {
  const runId = randomUUID(), receipt = controlledCleanup(runId);
  const { call, child } = replyClient(t, [{ ...flags, runId }, { ...receipt, cleanupUncertain: true,
    evidence: { ...receipt.evidence, complete: false, cleanupUncertain: true, ownedRootHookRemoved: false } }]);
  await call('prepareOwnedFixtures', { runId });
  const cleaned = await call('cleanupOwnedFixtures', { runId }); assert.equal(cleaned.cleanupUncertain, true);
  const closing = await call.close();
  assert.equal(child.exitCode, 0); assert.equal(closing.closed, true); assert.equal(closing.cleanupUncertain, true);
  assert.equal(call.snapshot().cleanupUncertain, true);
});

test('successful status and snapshot uncertainty are permanent even after a complete cleanup receipt', async t => {
  const runId = randomUUID();
  for (const [name, method, result] of [
    ['status phase', 'status', { runs: [{ runId, phase: 'cleanup-required', cleanupUncertain: false }] }],
    ['status cleanupRequired', 'status', { cleanupRequired: true }],
    ['snapshot uncertainty', 'acceptanceSnapshot', { runId, phase: 'uncertain', cleanupUncertain: true }],
    ['nested evidence', 'acceptanceSnapshot', { runId, phase: 'cleaned', evidence: { cleanupUncertain: true } }],
  ]) await t.test(name, async t => {
    const { call, child } = replyClient(t, [result, controlledCleanup(runId)]);
    await call(method, method === 'status' ? {} : { runId });
    await call('cleanupOwnedFixtures', { runId });
    await assert.rejects(call('prepareOwnedFixtures', { runId: randomUUID() }), { code: 'PF_HELPER_CLEANUP_UNCERTAIN' });
    assert.equal((await call.close()).cleanupUncertain, true); assert.equal(child.exitCode, 0);
  });
});

test('clean outer EOF requires complete cleanup evidence bound to every observed run', async t => {
  const runId = randomUUID(), otherRunId = randomUUID(), receipt = controlledCleanup(runId);
  for (const [name, results, methods] of [
    ['no receipt', [{ ...flags, runs: [] }], [['status', {}]]],
    ['cleaned flag without proof', [{ ...flags, runId, cleanupUncertain: false, cleaned: true }], [['cleanupOwnedFixtures', { runId }]]],
    ['missing root restoration', [{ ...receipt, evidence: { ...receipt.evidence, originalRootRestored: false } }], [['cleanupOwnedFixtures', { runId }]]],
    ['foreign run receipt', [controlledCleanup(otherRunId)], [['cleanupOwnedFixtures', { runId }]]],
    ['another observed run remains', [{ ...flags, runs: [{ runId, phase: 'fixtures-running' }, { runId: otherRunId, phase: 'fixtures-running' }] }, receipt],
      [['status', {}], ['cleanupOwnedFixtures', { runId }]]],
    ['post-clean snapshot contradicts receipt', [receipt, { ...flags, runId, phase: 'fixtures-running', cleanupUncertain: false }],
      [['cleanupOwnedFixtures', { runId }], ['acceptanceSnapshot', { runId }]]],
  ]) await t.test(name, async t => {
    const { call, child } = replyClient(t, results);
    for (const [method, params] of methods) await call(method, params);
    assert.equal((await call.close()).cleanupUncertain, true); assert.equal(child.exitCode, 0);
  });
  await t.test('all run-bound native cleanup proofs and cleaned status permit normal closure', async t => {
    const { call, child } = replyClient(t, [receipt, controlledCleanup(otherRunId), { ...flags,
      runs: [{ runId, phase: 'cleaned', cleanupUncertain: false }, { runId: otherRunId, phase: 'cleaned', cleanupUncertain: false }] }]);
    await call('cleanupOwnedFixtures', { runId }); await call('cleanupOwnedFixtures', { runId: otherRunId }); await call('status');
    assert.equal(call.snapshot().cleanupUncertain, false);
    assert.deepEqual(await call.close(), { closed: true, started: true, cleanupUncertain: false }); assert.equal(child.exitCode, 0);
  });
});

test('persistent client rejects a foreign response ID and marks the channel uncertain', async t => {
  const program = `process.stdin.once('data',()=>{process.stdout.write(JSON.stringify({protocol:'envara.application-routing',version:1,id:'foreign',result:{}})+'\\n');});`;
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawn(process.execPath, ['--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] }) });
  t.after(() => call.close());
  await assert.rejects(call('status'), { code: 'PF_HELPER_RESPONSE_INVALID' }); assert.equal(call.snapshot().cleanupUncertain, true);
  await assert.rejects(call('prepareOwnedFixtures'), { code: 'PF_HELPER_CLEANUP_UNCERTAIN' });
  const closing = await call.close(); assert.equal(closing.cleanupUncertain, true);
});

test('native authorizer id:null safe error is a refusal, never a successful RPC or generic protocol completion', async t => {
  const program = `process.stdin.once('data',()=>{process.stdout.write(JSON.stringify({protocol:'envara.application-routing',version:1,id:null,error:{code:'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED'}})+'\\n');});`;
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawn(process.execPath, ['--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] }) });
  t.after(() => call.close());
  await assert.rejects(call('status'), { code: 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED' });
  assert.equal(call.snapshot().cleanupUncertain, true); assert.equal((await call.close()).cleanupUncertain, true);
});

test('a timed-out case preserves the channel for explicit cleanup and safely discards only its known late reply', async t => {
  const program = `import readline from 'node:readline';
    for await(const line of readline.createInterface({input:process.stdin})){
      const r=JSON.parse(line); if(r.method==='runOwnedFixtureCase') await new Promise(resolve=>setTimeout(resolve,90));
      process.stdout.write(JSON.stringify({protocol:r.protocol,version:r.version,id:r.id,result:{cleaned:r.method==='cleanupOwnedFixtures'}})+'\\n');
    }`;
  const call = createPersistentPFHelperClient({ spawnRootControlledLifecycle: () => spawn(process.execPath, ['--input-type=module', '-e', program], { stdio: ['pipe', 'pipe', 'pipe'] }) });
  t.after(() => call.close());
  await call('status'); await assert.rejects(call('runOwnedFixtureCase', {}, { timeoutMs: 20 }), { code: 'PF_HELPER_DEADLINE' });
  const cleanup = await call('cleanupOwnedFixtures'); assert.equal(cleanup.cleaned, true);
  assert.equal((await call.close()).cleanupUncertain, true); // The timeout cannot be promoted to a clean terminal receipt.
});
