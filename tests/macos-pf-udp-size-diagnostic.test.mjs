import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { PF_ACCEPTANCE_PROTOCOL, PF_FIXTURE_UDP_COUNTS, runPFAcceptanceMatrix } from '../native/macos-pf-routing/acceptance-plan.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

const flags = { acceptanceProtocol: PF_ACCEPTANCE_PROTOCOL, acceptanceOnly: true, ready: false, productionReceiptAllowed: false };
function matrix({ failUDP = false, observer = 'known', detached = false } = {}) {
  const realms = ['one', 'two'].map((slot, index) => ({ slot, realmId: randomUUID(), gid: 7100 + index,
    tunnel: { interfaceName: `utun${90 + index}`, pid: 300 + index, instanceId: `owned-instance-${index}` },
    fixtures: (detached ? ['parent', 'child', 'detached'] : ['parent', 'child']).map((role, offset) => ({ role,
      pid: 100 + index * 10 + offset, birth: '1:000001', gid: 7100 + index })) }));
  const requests = [], methods = []; let closed = 0, controlClosed = false;
  const registered = new Map();
  const options = {
    evidenceMode: 'simulation', controlledCaseIds: ['udp-concurrent'],
    createControl: async () => ({ existing: async () => true, fresh: async () => true, close: async () => { controlClosed = true; return true; } }),
    createProxy: async ({ slot }) => ({ route: {}, register: (id, bytes, kind) => { assert.equal(kind, 'udp'); registered.set(`${slot}/${id}`, bytes.length); },
      received: () => true, ...(observer === 'missing' ? {} : { receiptCount: id => {
        if (observer === 'throwing') throw new Error('private-node-password');
        return failUDP && registered.get(`${slot}/${id}`) === 2048 ? 0 : 1;
      } }), snapshot: () => ({ crossRouteRejected: 0, ...Object.fromEntries(PF_FIXTURE_UDP_COUNTS.map(key => [key, 0])) }),
      close: async () => { closed++; return true; } }),
    call: async (method, params) => {
      methods.push(method);
      if (method === 'status') return { ...flags, anchor: pfRoutingAnchor(params.runId), rootOwnedInstallationVerified: true,
        callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, ownedRootHookCanCreate: true,
        statelessControlledFixtures: true, noStateNativeAvailable: true, fixtureOperations: ['realm-identities', 'udp-concurrent', 'cleanup'] };
      if (method === 'prepareOwnedFixtures') return { ...flags, runId: params.runId, realms,
        ownedRootHook: { source: 'native-pf-root-hook', anchor: pfRoutingAnchor(params.runId), runId: params.runId, verified: true, ticketSource: 'this-INSERT-return-only' },
        existingForeignPFStatesAbsentBeforeEnable: true, statelessEvidence: { source: 'native-pf', freshTuplesVerified: true,
          noExistingOwnedStatesVerified: true, noStateRulesVerified: true, denyBeforeResumeVerified: true } };
      if (method === 'cleanupOwnedFixtures') return { ...flags, runId: params.runId, cleanupUncertain: false, evidence: { source: 'native-pf', platform: 'darwin',
        complete: true, cleanupUncertain: false, ownedProcessesExited: true, ownedTunnelsRemoved: true, ownedAnchorRemoved: true, unrelatedPFUnchanged: true,
        unrelatedRoutesUnchanged: true, hostDNSUnchanged: true, noOwnedStatesCreatedVerified: true, noOwnedStatesRemainVerified: true,
        ownedRootHookRemoved: true, originalRootRestored: true, ownedPFReferenceReleased: true } };
      assert.equal(method, 'runOwnedFixtureCase');
      if (params.caseId === 'udp-concurrent') {
        requests.push(...params.challenges.map(challenge => ({ slot: challenge.slot, role: challenge.role,
          payloadBytes: Buffer.from(challenge.request.payloadBase64, 'base64').length })));
        if (failUDP) throw Object.assign(new Error('private-node-password'), { code: 'APPLICATION_PF_FIXTURE_PROBE_TIMEOUT' });
      }
      return { ...flags, runId: params.runId, caseId: params.caseId, evidence: { source: 'native-pf', platform: 'darwin', complete: true,
        threeGIDsVerified: true, coldExecVerified: true, overlapVerified: true, exactProcessAttribution: true,
        freshTuplesVerified: true, noExistingMatchingStatesVerified: true, noStateRulesVerified: true }, probes: params.challenges.map(challenge => ({
        slot: challenge.slot, role: challenge.role, fixture: realms.find(realm => realm.slot === challenge.slot).fixtures.find(fixture => fixture.role === challenge.role),
        result: { ok: true, matches: true, payloadBase64: challenge.request.payloadBase64, receivedBytes: Buffer.from(challenge.request.payloadBase64, 'base64').length,
          reservationId: randomUUID(), consumed: true, usedReservedSocket: true, protocol: challenge.request.op, remoteHost: challenge.request.host, remotePort: challenge.request.port,
          sourceAddressResolved: true, sourceWildcard: false, localHost: '192.0.2.21', localPort: 50123 } })) };
    },
  };
  return { options, requests, methods, closed: () => closed, controlClosed: () => controlClosed };
}

test('UDP size diagnostics require an explicit boolean and controlled selected UDP scope before any helper call', async () => {
  for (const options of [ { controlledUDPSizeDiagnostic: 1 }, { controlledUDPSizeDiagnostic: true },
    { controlledUDPSizeDiagnostic: true, controlledCaseIds: ['tcp-concurrent'] } ]) {
    let calls = 0;
    await assert.rejects(runPFAcceptanceMatrix({ call: async () => { calls++; }, ...options }), { code: 'PF_ACCEPTANCE_OPTIONS_INVALID' });
    assert.equal(calls, 0);
  }
});

test('the actual matrix generates balanced 1200/2048 probes and retains a failed case despite small receipts', async () => {
  const fixture = matrix({ failUDP: true }); const report = await runPFAcceptanceMatrix({ ...fixture.options, controlledUDPSizeDiagnostic: true });
  assert.deepEqual(fixture.requests, ['one', 'two'].flatMap(slot => [{ slot, role: 'parent', payloadBytes: 1200 }, { slot, role: 'child', payloadBytes: 2048 }]));
  assert.deepEqual(report.udpSizeDiagnostics, fixture.requests.map(request => ({ ...request, authenticatedFixtureReceipts: request.role === 'parent' ? 1 : 0 })));
  assert.equal(report.controlledUDPSizeDiagnostic, true); assert.equal(report.checks['udp-concurrent'].passed, false);
  assert.equal(report.selectedCasesPassed, false); assert.equal(report.fullMatrix, false); assert.equal(report.nativeRoutingAcceptance, false); assert.equal(report.productionReady, false);
  assert.equal(fixture.closed(), 2); assert.equal(fixture.controlClosed(), true);
  assert.equal(JSON.stringify(report).includes('private-node-password'), false);
  assert.ok(report.udpSizeDiagnostics.every(value => Object.keys(value).sort().join(',') === 'authenticatedFixtureReceipts,payloadBytes,role,slot'));
});

test('the default matrix preserves all original 2048-byte UDP challenges', async () => {
  const fixture = matrix(); const report = await runPFAcceptanceMatrix(fixture.options);
  assert.deepEqual(fixture.requests.map(request => request.payloadBytes), [2048, 2048, 2048, 2048]);
  assert.equal(report.controlledUDPSizeDiagnostic, false); assert.equal(report.selectedCasesPassed, true);
  assert.equal(report.fullMatrix, false); assert.equal(report.productionReady, false);
});

test('missing or throwing receipt observers remain unknown and never prevent cleanup', async () => {
  for (const observer of ['missing', 'throwing']) {
    const fixture = matrix({ failUDP: true, observer }); const report = await runPFAcceptanceMatrix({ ...fixture.options, controlledUDPSizeDiagnostic: true });
    assert.deepEqual(report.udpSizeDiagnostics.map(value => value.authenticatedFixtureReceipts), [null, null, null, null]);
    assert.equal(fixture.closed(), 2); assert.equal(fixture.controlClosed(), true); assert.equal(report.selectedCasesPassed, false);
  }
});

test('detached or incomplete role sets cannot silently alter the balanced diagnostic scope', async () => {
  const fixture = matrix({ detached: true }); const report = await runPFAcceptanceMatrix({ ...fixture.options, controlledUDPSizeDiagnostic: true });
  assert.equal(report.reason, 'PF_UDP_SIZE_DIAGNOSTIC_SCOPE_INVALID'); assert.equal(fixture.requests.length, 0);
  assert.equal(report.selectedCasesPassed, false); assert.equal(fixture.closed(), 2); assert.equal(fixture.controlClosed(), true);
});
