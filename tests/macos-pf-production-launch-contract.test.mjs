import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  ProductionLaunchContract,
  PRODUCTION_APP_REGISTRY_ROOT,
  PRODUCTION_LAUNCH_GATES,
  PRODUCTION_LAUNCH_HOOKS,
  PRODUCTION_LAUNCH_PROTOCOL,
} from '../native/macos-pf-routing/production-launch-contract.mjs';

// Entirely inert: these closures model proof responses and ownership bookkeeping.
// The synthetic nativeObserved/fixtureOnly fields exercise the validator; they are
// not observations, native acceptance, a real front, or a production backend.
const uuid = number => `00000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const request = () => ({
  requestId: uuid(1), applicationId: 'notion', environmentId: uuid(2), managedRouteId: uuid(3),
  workspace: { cwd: '/Users/fixture/Workspace', timezone: 'Asia/Shanghai', locale: 'zh-CN' },
});
const pids = { controller: 2001, core: 2002, tunnel: 2003, child: 2004, front: 2005, guardian: 2006 };
const born = value => `${value}:123456`;
const cleanupOrder = ['revokeLease', 'retainDeny', 'terminateOwnedScope', 'cleanupOwnedScope', 'retireLease'];
const launchOrder = [
  'inspectLaunch', 'reserveLease', 'inspectLaunch', 'commitDeny', 'verifyDeny', 'inspectLaunch',
  'stageGUI', 'inspectLaunch', 'prepareNotionFront', 'permitOwnedFront', 'inspectLaunch',
  'armWholeGuardian', 'inspectLaunch', 'verifyBeforeResume', 'beginResume', 'inspectLaunch',
  'resumeGUI', 'verifyRunning',
];
function flagsRemainClosed(value) {
  for (const flag of ['ready', 'productionReady', 'protected', 'productionReceiptAllowed']) assert.equal(value[flag], false, flag);
}
function refused(reason, detail) {
  return error => {
    assert.equal(error.code, 'APPLICATION_PRODUCTION_LAUNCH_REFUSED');
    assert.equal(error.reason, reason);
    if (detail !== undefined) assert.equal(error.detail, detail);
    return true;
  };
}
function inertFixture(options = {}) {
  const inputRequest = options.request ?? request();
  const identity = {
    applicationId: inputRequest.applicationId,
    registrationId: uuid(10), registrationEpoch: uuid(11), environmentId: inputRequest.environmentId,
    runId: uuid(12), realmId: uuid(13), bootstrapEpoch: uuid(14), managedRouteId: inputRequest.managedRouteId,
    routeRegistryEpoch: uuid(15), coreGeneration: uuid(16), tunnelInstanceId: uuid(17),
    registryRoot: PRODUCTION_APP_REGISTRY_ROOT, anchor: `io.envara.pf.run.${uuid(12)}`,
    gid: 7101, consoleUID: 501, guiAuditSession: 123,
    controllerPID: pids.controller, controllerBirth: born(pids.controller),
    corePID: pids.core, coreBirth: born(pids.core), coreVersion: 'v1.19.32',
    tunnelName: 'utun123', tunnelPID: pids.tunnel, tunnelBirth: born(pids.tunnel),
    originalManifestSHA256: sha('original manifest'), snapshotManifestSHA256: sha('snapshot manifest'),
    originalContentSHA256: sha('same app content'), snapshotContentSHA256: sha('same app content'),
    codeIdentitySHA256: sha('code'), installManifestSHA256: sha('installed manifest'),
    nativeSHA256: sha('native'), controllerSHA256: sha('controller'), guardianSHA256: sha('guardian'),
    frontSHA256: sha('front'), attestorSHA256: sha('attestor'), workspaceSHA256: sha(inputRequest.workspace),
    workspaceIdentitySHA256: sha('held directory'), coreExecutableSHA256: sha('core executable'),
    nodeIdentitySHA256: sha('managed node'), routeEndpointIdentitySHA256: sha('route endpoint'),
    kernelInterfaceIdentitySHA256: sha('original kernel interface'),
    ...options.identity,
  };
  const state = {
    events: [], inputs: [], inspections: 0, identity, denied: false, revoked: false,
    namespaceReleased: false, retired: false, childOwned: false, frontOwned: false, resumeCount: 0,
  };
  const proof = (input, source, fields = {}) => ({
    schema: PRODUCTION_LAUNCH_PROTOCOL, source, nativeObserved: true, fixtureOnly: false,
    challenge: input.challenge, leaseId: input.lease.leaseId, bindingDigest: input.lease.bindingDigest, ...fields,
  });
  const defaults = {
    inspectLaunch(input) {
      state.inspections++;
      options.inspect?.(state.inspections, state, input);
      return {
        schema: PRODUCTION_LAUNCH_PROTOCOL, source: 'native-live-launch-inspection', challenge: input.challenge,
        nativeObserved: true, fixtureOnly: false, identity: { ...state.identity },
        gates: { ...Object.fromEntries(PRODUCTION_LAUNCH_GATES.map(name => [name, true])), ...options.gates },
      };
    },
    reserveLease: input => proof(input, 'native-launch-ledger', { state: 'reserved', durable: true, exclusive: true, rootOwned: true }),
    commitDeny(input) { state.denied = true; return proof(input, 'native-pf-deny', { committed: true }); },
    verifyDeny: input => proof(input, 'native-pf-deny', { verified: state.denied, persistent: true }),
    stageGUI(input) {
      state.childOwned = true;
      return proof(input, 'native-gui-stopped', {
        stoppedBeforeExec: true, bootstrapVerified: true, closedInheritedDescriptors: true,
        pid: pids.child, birth: born(pids.child), codeIdentitySHA256: identity.codeIdentitySHA256,
        realUID: identity.consoleUID, effectiveUID: identity.consoleUID, savedUID: identity.consoleUID,
        realGID: identity.gid, effectiveGID: identity.gid, savedGID: identity.gid, supplementaryGroups: [identity.gid],
      });
    },
    prepareNotionFront(input) {
      state.frontOwned = true;
      return proof(input, 'native-owned-notion-front', {
        raceProtected: true, sealedIdentityVerified: true, domainBytesPreserved: true, raceFree: true,
        proofKind: 'native-kernel-owned-front-v1', listenerOwnershipVerified: true,
        upstreamAuthenticationRequired: true, directFallbackForbidden: true, hostResolverForbidden: true,
        instanceId: uuid(20), pid: pids.front, birth: born(pids.front), host: '127.0.0.1', port: 24001,
        managedRouteId: identity.managedRouteId, registryEpoch: identity.routeRegistryEpoch,
        frontSHA256: identity.frontSHA256, attestorSHA256: identity.attestorSHA256,
        coreGeneration: identity.coreGeneration, corePID: identity.corePID, coreBirth: identity.coreBirth,
        coreExecutableSHA256: identity.coreExecutableSHA256, routeEndpointIdentitySHA256: identity.routeEndpointIdentitySHA256,
        nodeIdentitySHA256: identity.nodeIdentitySHA256,
      });
    },
    permitOwnedFront: input => proof(input, 'native-pf-owned-front', {
      verified: true, exactOwnedEndpointOnly: true, allOtherDenyPreserved: true,
      realmGID: identity.gid, host: input.front.host, port: input.front.port, frontInstanceId: input.front.instanceId,
    }),
    armWholeGuardian: input => proof(input, 'native-whole-launch-guardian', {
      armed: true, ownsOriginalTunnelFD: true, persistentDeny: true, independentActor: true, expiryEnforced: true,
      controllerFailureSafe: true, frontFailureSafe: true, coreFailureSafe: true, guardianFailureSafe: true, interfaceReuseSafe: true,
      instanceId: uuid(21), pid: pids.guardian, birth: born(pids.guardian), guardianSHA256: identity.guardianSHA256,
      tunnelInstanceId: identity.tunnelInstanceId, childPID: input.child.pid, childBirth: input.child.birth,
      frontInstanceId: input.front.instanceId, kernelInterfaceIdentitySHA256: identity.kernelInterfaceIdentitySHA256,
      realUID: 0, effectiveUID: 0, savedUID: 0, expiresAtUnixMs: Date.now() + 60_000,
    }),
    verifyBeforeResume: input => proof(input, 'native-before-resume', {
      verified: true, atomicResumeBarrier: true, childPID: input.child.pid, childBirth: input.child.birth,
      guardianInstanceId: input.guardian.instanceId, guardianLeaseUnexpired: true,
      expiresAtUnixMs: input.guardian.expiresAtUnixMs, workspaceIdentitySHA256: identity.workspaceIdentitySHA256,
    }),
    beginResume: input => proof(input, 'native-launch-ledger', { state: 'resume-intent', durable: true, singleUse: true }),
    resumeGUI(input) {
      if (state.revoked) throw new Error('inert backend rejects revoked resume');
      state.resumeCount++;
      return proof(input, 'native-gui-exec', {
        execACK: true, atomicResumeBarrier: true, pid: input.child.pid, birth: input.child.birth,
        codeIdentitySHA256: input.child.codeIdentitySHA256,
      });
    },
    verifyRunning: input => proof(input, 'native-running-launch', {
      verified: true, pid: input.child.pid, birth: input.child.birth,
      guardianInstanceId: input.guardian.instanceId, frontInstanceId: input.front.instanceId, sessionId: uuid(22),
    }),
    revokeLease(input) {
      state.revoked = true;
      return proof(input, 'native-launch-ledger', { state: 'revoked', durable: true, resumeForbidden: true, lateMutationForbidden: true });
    },
    retainDeny(input) { state.denied = true; return proof(input, 'native-pf-deny', { verified: true, persistent: true }); },
    terminateOwnedScope(input) {
      state.childOwned = false;
      return proof(input, 'native-owned-scope-stopped', { scopeQuiescent: true, ownedProcessesExited: true });
    },
    cleanupOwnedScope(input) {
      state.frontOwned = false; state.namespaceReleased = true;
      return proof(input, 'native-owned-scope-cleanup', {
        scopeQuiescent: true, ownedFrontClosed: true, ownedTunnelClosed: true, noOwnedStatesRemain: true,
        ownedRootHookRemoved: true, originalRootRestored: true, hookReceiptRetired: true,
        namespaceReclaimed: true, unrelatedNetworkUnchanged: true,
      });
    },
    retireLease(input) { state.retired = true; return proof(input, 'native-launch-ledger', { state: 'retired', durable: true, resumeForbidden: true }); },
  };
  const backend = Object.fromEntries(PRODUCTION_LAUNCH_HOOKS.map(name => [name, async (input, context) => {
    state.events.push(name); state.inputs.push({ name, input, context });
    const handler = options.handlers?.[name] ?? defaults[name];
    const value = await handler(input, context, { state, proof, defaults });
    return options.editProof?.(name, value, input, state) ?? value;
  }]));
  return { state, backend, proof, request: inputRequest,
    contract: new ProductionLaunchContract({ backend, timeoutMs: options.timeoutMs ?? 1000 }) };
}

test('default backend cannot launch; status is read-only and closed', async () => {
  const contract = new ProductionLaunchContract();
  for (const name of ['invoke', 'inspect', 'cleanup', 'serialized', 'backend', 'records', 'requestIds']) assert.equal(contract[name], undefined);
  flagsRemainClosed(contract.status());
  assert.equal(contract.status().integrated, false);
  assert.deepEqual(contract.status().missingHooks, PRODUCTION_LAUNCH_HOOKS);
  await assert.rejects(contract.start(request()), refused('BACKEND_HOOK_MISSING', 'inspectLaunch'));
  assert.deepEqual(contract.status().leases, []);
  let resumed = false;
  const resumeOnly = new ProductionLaunchContract({ backend: { resumeGUI() { resumed = true; } } });
  await assert.rejects(resumeOnly.start(request()), refused('BACKEND_HOOK_MISSING', 'inspectLaunch'));
  assert.equal(resumed, false);
});

test('missing hooks and every missing/false acceptance gate refuse before reservation', async () => {
  const fixture = inertFixture();
  const missingHook = new ProductionLaunchContract({ backend: { ...fixture.backend, stageGUI: undefined } });
  await assert.rejects(missingHook.start(fixture.request), refused('BACKEND_HOOK_MISSING', 'stageGUI'));
  assert.deepEqual(fixture.state.events, []);
  for (const gate of PRODUCTION_LAUNCH_GATES) {
    for (const value of [undefined, false]) {
      const denied = inertFixture({ gates: { [gate]: value } });
      const plan = await denied.contract.plan(denied.request);
      assert.equal(plan.allowed, false, gate); flagsRemainClosed(plan);
      assert.deepEqual(plan.missingGates, [gate]);
      await assert.rejects(denied.contract.start(denied.request), refused('GATE_UNVERIFIED', gate));
      assert.deepEqual(denied.state.events, ['inspectLaunch', 'inspectLaunch']);
      assert.deepEqual(denied.contract.status().leases, []);
    }
  }
});

test('injected lifecycle has strict order, immutable hook inputs, and never opens readiness', async () => {
  const fixture = inertFixture();
  const plan = await fixture.contract.plan(fixture.request);
  assert.equal(plan.allowed, true); flagsRemainClosed(plan);
  assert.deepEqual(fixture.state.events, ['inspectLaunch']);
  fixture.state.events.length = 0;
  const result = await fixture.contract.start(fixture.request);
  assert.equal(result.started, true); flagsRemainClosed(result);
  assert.deepEqual(fixture.state.events, launchOrder);
  const reservation = fixture.state.inputs.find(value => value.name === 'reserveLease').input;
  assert.ok(Object.isFrozen(reservation) && Object.isFrozen(reservation.lease) && Object.isFrozen(reservation.request.workspace));
  assert.throws(() => { reservation.request.workspace.cwd = '/mutated'; }, TypeError);
  fixture.request.workspace.cwd = '/caller-change';
  assert.equal(reservation.request.workspace.cwd, '/Users/fixture/Workspace');
  const calls = fixture.state.inputs.filter(value => value.name !== 'inspectLaunch');
  assert.equal(new Set(calls.map(value => value.input.challenge)).size, calls.length);
  const stopped = await fixture.contract.stop({ sessionId: result.sessionId });
  assert.equal(stopped.stopped, true); flagsRemainClosed(stopped);
  assert.deepEqual(fixture.state.events, [...launchOrder, ...cleanupOrder]);
  assert.equal(fixture.state.resumeCount, 1); assert.equal(fixture.state.retired, true);
  const beforeRepeat = [...fixture.state.events];
  await fixture.contract.stop({ sessionId: result.sessionId });
  assert.deepEqual(fixture.state.events, beforeRepeat);
  flagsRemainClosed(fixture.contract.status());
});

test('renderer-supplied proofs/hooks and malformed workspace cannot reach the backend', async () => {
  for (const extra of [{ proof: { protected: true } }, { gates: {} }, { backend: {} }, { identity: {} }]) {
    const fixture = inertFixture();
    await assert.rejects(fixture.contract.start({ ...fixture.request, ...extra }), refused('REQUEST_INVALID'));
    assert.deepEqual(fixture.state.events, []);
  }
  for (const workspace of [{ cwd: '/x/../y' }, { cwd: '/x\0y' }, { timezone: 'Local' }, { locale: 'en_US' }]) {
    const fixture = inertFixture();
    await assert.rejects(fixture.contract.start({ ...fixture.request, workspace: { ...fixture.request.workspace, ...workspace } }), refused('REQUEST_INVALID'));
    assert.deepEqual(fixture.state.events, []);
  }
});

test('stale nonce, fixture proof, and unobserved proof cannot reserve a trusted lease', async () => {
  for (const [edit, expected] of [
    [{ challenge: uuid(99) }, 'BACKEND_NONCE_MISMATCH'],
    [{ fixtureOnly: true }, 'BACKEND_PROOF_INVALID'],
    [{ nativeObserved: false }, 'BACKEND_PROOF_INVALID'],
  ]) {
    const fixture = inertFixture({ editProof: (name, value) => name === 'reserveLease' ? { ...value, ...edit } : value });
    await assert.rejects(fixture.contract.start(fixture.request), refused(expected));
    assert.ok(!fixture.state.events.includes('commitDeny'));
    assert.deepEqual(fixture.state.events.slice(-5), cleanupOrder);
    assert.equal(fixture.contract.status().leases[0].phase, 'retired');
  }
});

test('changed identity after deny, stopped staging, or front binding revokes and blocks the next step', async () => {
  for (const [inspection, lastCompleted, forbidden] of [
    [3, 'verifyDeny', 'stageGUI'], [4, 'stageGUI', 'prepareNotionFront'], [5, 'permitOwnedFront', 'armWholeGuardian'],
  ]) {
    const fixture = inertFixture({ inspect: (count, state) => {
      if (count === inspection) state.identity.routeRegistryEpoch = uuid(98);
    } });
    await assert.rejects(fixture.contract.start(fixture.request), refused('IDENTITY_CHANGED'));
    assert.ok(fixture.state.events.includes(lastCompleted));
    assert.ok(!fixture.state.events.includes(forbidden));
    assert.ok(!fixture.state.events.includes('resumeGUI'));
    assert.deepEqual(fixture.state.events.slice(-5), cleanupOrder);
    assert.equal(fixture.state.revoked, true);
  }
});

test('failed deny readback forbids staging any GUI process', async () => {
  const fixture = inertFixture({ editProof: (name, value) => name === 'verifyDeny' ? { ...value, verified: false } : value });
  await assert.rejects(fixture.contract.start(fixture.request), refused('BACKEND_PROOF_INVALID', 'native-pf-deny'));
  assert.ok(!fixture.state.events.includes('stageGUI')); assert.equal(fixture.state.childOwned, false);
  assert.deepEqual(fixture.state.events.slice(-5), cleanupOrder);
});

test('prototype front, wrong realm permission, and compromised stopped credentials block resume', async () => {
  for (const [hook, edit, reason] of [
    ['prepareNotionFront', { raceFree: false, proofKind: 'fixture-socket-owner-v1' }, 'BACKEND_PROOF_INVALID'],
    ['permitOwnedFront', { realmGID: 7102 }, 'BACKEND_PROOF_INVALID'],
    ['stageGUI', { savedUID: 0 }, 'CHILD_IDENTITY_INVALID'],
  ]) {
    const fixture = inertFixture({ editProof: (name, value) => name === hook ? { ...value, ...edit } : value });
    await assert.rejects(fixture.contract.start(fixture.request), refused(reason));
    assert.ok(!fixture.state.events.includes('armWholeGuardian'));
    assert.ok(!fixture.state.events.includes('beginResume'));
    assert.equal(fixture.state.resumeCount, 0); assert.equal(fixture.state.revoked, true);
  }
});

test('guardian must be a separate root actor with a live original-interface lease', async () => {
  for (const edit of [
    { pid: pids.controller }, { effectiveUID: 501 }, { expiresAtUnixMs: 1 },
    { kernelInterfaceIdentitySHA256: sha('replacement interface') },
  ]) {
    const fixture = inertFixture({ editProof: (name, value) => name === 'armWholeGuardian' ? { ...value, ...edit } : value });
    await assert.rejects(fixture.contract.start(fixture.request), refused('GUARDIAN_IDENTITY_INVALID'));
    assert.ok(!fixture.state.events.includes('verifyBeforeResume'));
    assert.ok(!fixture.state.events.includes('resumeGUI'));
  }
});

test('concurrent replay and replay after retirement never duplicate the resume capability', async () => {
  const fixture = inertFixture();
  const results = await Promise.allSettled([fixture.contract.start(fixture.request), fixture.contract.start(fixture.request)]);
  assert.equal(results[0].status, 'fulfilled'); assert.equal(results[1].status, 'rejected');
  refused('REQUEST_ALREADY_CONSUMED')(results[1].reason);
  assert.equal(fixture.state.events.filter(name => name === 'reserveLease').length, 1);
  assert.equal(fixture.state.events.filter(name => name === 'beginResume').length, 1);
  assert.equal(fixture.state.resumeCount, 1);
  await fixture.contract.stop({ sessionId: results[0].value.sessionId });
  await assert.rejects(fixture.contract.start(fixture.request), refused('REQUEST_ALREADY_CONSUMED'));
  await assert.rejects(fixture.contract.start({ ...fixture.request, requestId: uuid(90) }), refused('RUN_ALREADY_CONSUMED'));
  assert.equal(fixture.state.events.filter(name => name === 'reserveLease').length, 1);
  assert.equal(fixture.state.resumeCount, 1);
});

test('lost resume acknowledgement revokes before late completion and never retries', async () => {
  let release, resumeInput, resumeContext;
  const deferred = new Promise(resolve => { release = resolve; });
  const fixture = inertFixture({ timeoutMs: 30, handlers: {
    async resumeGUI(input, context, { state, proof }) {
      resumeInput = input; resumeContext = context;
      await deferred;
      // Model the required durable native revocation check, not timer cancellation.
      if (!state.revoked) state.resumeCount++;
      return proof(input, 'native-gui-exec', {
        execACK: true, atomicResumeBarrier: true, pid: input.child.pid, birth: input.child.birth,
        codeIdentitySHA256: input.child.codeIdentitySHA256,
      });
    },
  } });
  await assert.rejects(fixture.contract.start(fixture.request), error => {
    refused('BACKEND_TIMEOUT', 'resumeGUI')(error);
    assert.equal(error.cleanupConfirmed, true); return true;
  });
  assert.ok(resumeInput); assert.equal(resumeContext.signal.aborted, true);
  assert.equal(fixture.state.revoked, true);
  assert.deepEqual(fixture.state.events.slice(-5), cleanupOrder);
  release(); await deferred; await Promise.resolve(); await Promise.resolve();
  assert.equal(fixture.state.resumeCount, 0);
  assert.ok(!fixture.state.events.includes('verifyRunning'));
  const lease = fixture.contract.status().leases[0];
  assert.equal(lease.resumeAttempted, true); assert.equal(lease.phase, 'retired');
  await assert.rejects(fixture.contract.start(fixture.request), refused('REQUEST_ALREADY_CONSUMED'));
  assert.equal(fixture.state.events.filter(name => name === 'resumeGUI').length, 1);
});

test('unconfirmed cleanup preserves the unreleased lease and reports recovery required', async () => {
  const fixture = inertFixture({ handlers: {
    cleanupOwnedScope: (input, context, { proof }) => proof(input, 'native-owned-scope-cleanup', { scopeQuiescent: false }),
  } });
  const started = await fixture.contract.start(fixture.request);
  await assert.rejects(fixture.contract.stop({ sessionId: started.sessionId }), refused('CLEANUP_UNCONFIRMED'));
  assert.equal(fixture.state.revoked, true); assert.equal(fixture.state.denied, true);
  assert.equal(fixture.state.frontOwned, true); assert.equal(fixture.state.namespaceReleased, false);
  assert.equal(fixture.state.retired, false); assert.ok(!fixture.state.events.includes('retireLease'));
  const status = fixture.contract.status(); flagsRemainClosed(status);
  assert.equal(status.leases[0].phase, 'recovery-required'); assert.equal(status.leases[0].recoveryRequired, true);
  status.leases[0].phase = 'running';
  assert.equal(fixture.contract.status().leases[0].phase, 'recovery-required');
  await assert.rejects(fixture.contract.start(fixture.request), refused('REQUEST_ALREADY_CONSUMED'));
});

test('failed or timed-out revocation still retains denial and forbids releasing uncertain ownership', async () => {
  for (const failure of ['throw', 'timeout']) {
    const fixture = inertFixture({ timeoutMs: 30, handlers: {
      revokeLease() {
        if (failure === 'throw') throw new Error('synthetic unavailable ledger');
        return new Promise(() => {});
      },
    } });
    const started = await fixture.contract.start(fixture.request);
    await assert.rejects(fixture.contract.stop({ sessionId: started.sessionId }), refused('CLEANUP_UNCONFIRMED'));
    assert.deepEqual(fixture.state.events.slice(-2), ['revokeLease', 'retainDeny']);
    for (const hook of ['terminateOwnedScope', 'cleanupOwnedScope', 'retireLease']) assert.ok(!fixture.state.events.includes(hook));
    assert.equal(fixture.state.denied, true); assert.equal(fixture.state.namespaceReleased, false);
    assert.equal(fixture.state.childOwned, true); assert.equal(fixture.state.frontOwned, true);
    assert.equal(fixture.contract.status().leases[0].recoveryRequired, true);
    flagsRemainClosed(fixture.contract.status());
  }
});
