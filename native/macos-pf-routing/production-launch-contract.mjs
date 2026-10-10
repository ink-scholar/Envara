import { createHash, randomUUID } from 'node:crypto';
import { isPFRoutingRunId, pfRoutingAnchor } from './policy.mjs';

export const PRODUCTION_LAUNCH_PROTOCOL = 'envara.pf-production-launch/v1';
// Keep mutable app registrations outside the installer's exact immutable tree.
export const PRODUCTION_APP_REGISTRY_ROOT = '/Library/PrivilegedHelperTools/io.envara.pf-apps';
export const PRODUCTION_LAUNCH_GATES = Object.freeze([
  'sealedRuntime', 'immutableRegistration', 'originalSignature', 'sealedSnapshot', 'noUnownedOriginalInstance',
  'consoleGUIBootstrap', 'closedInheritedDescriptors', 'descriptorTransferSafety', 'heldWorkspaceIdentity', 'managedCoreIdentity',
  'applicationDNS', 'externalHelperScope', 'ipv6AndRawDenial', 'existingStatesSafe', 'persistentDeny',
  'wholeGuardianFailureSafe', 'tunnelEpochSafety', 'unrelatedApplicationsPreserved', 'frontOwnershipRaceSafe',
  'atomicResumeBarrier', 'originalApplicationAcceptance',
]);
export const PRODUCTION_LAUNCH_HOOKS = Object.freeze([
  'inspectLaunch', 'reserveLease', 'commitDeny', 'verifyDeny', 'stageGUI', 'prepareNotionFront',
  'permitOwnedFront', 'armWholeGuardian', 'verifyBeforeResume', 'beginResume', 'resumeGUI',
  'verifyRunning', 'revokeLease', 'retainDeny', 'terminateOwnedScope', 'cleanupOwnedScope', 'retireLease',
]);
const reasons = new Set(['REQUEST_INVALID', 'OPTIONS_INVALID', 'INSPECTION_INVALID', 'IDENTITY_INVALID', 'GATE_UNVERIFIED',
  'BACKEND_PROOF_INVALID', 'CHILD_IDENTITY_INVALID', 'FRONT_IDENTITY_INVALID', 'GUARDIAN_IDENTITY_INVALID',
  'BACKEND_HOOK_MISSING', 'BACKEND_TIMEOUT', 'BACKEND_NONCE_MISMATCH', 'IDENTITY_CHANGED', 'LEASE_CAPACITY_EXHAUSTED',
  'REQUEST_ALREADY_CONSUMED', 'RUN_ALREADY_CONSUMED', 'SESSION_IDENTITY_INVALID', 'BACKEND_OPERATION_FAILED', 'SESSION_UNKNOWN', 'CLEANUP_UNCONFIRMED']);
const proofSources = ['native-live-launch-inspection', 'native-launch-ledger', 'native-pf-deny', 'native-gui-stopped',
  'native-owned-notion-front', 'native-pf-owned-front', 'native-whole-launch-guardian', 'native-before-resume',
  'native-gui-exec', 'native-running-launch', 'native-owned-scope-stopped', 'native-owned-scope-cleanup'];
const details = new Set([...PRODUCTION_LAUNCH_GATES, ...PRODUCTION_LAUNCH_HOOKS, ...proofSources]);
export const PRODUCTION_LAUNCH_INTEGRATION = Object.freeze({
  controller: 'MacOSPFController.launch must call this coordinator with fixed backend hooks; RPC accepts identifiers/workspace only, never proofs or hooks.',
  native: 'Add fixed gui-launch-lease dispatch, private root-sealed app/lease readers, compiled committed-deny verifier, bootstrap attestation and atomic resume/exec ACK.',
  guardian: 'Every mutating hook must check the durable lease epoch/revocation immediately before mutation; guardian retains denial across controller/front/core/guardian failure.',
  front: 'Use a UUID route identity and sealed front/attestor identity; add only an attested per-realm front loopback permission. Current fixture attestor/raceFree:false is refused.',
  desktop: 'MacOSPFApplicationRouting may forward the returned opaque session only after native acceptance; it must not turn this lifecycle receipt into readiness.',
  resources: 'Add GUI/front/attestor/registry resources to build/installer trust maps only in a separately reviewed payload; do not weaken exact helper-tree checks.',
});

const hashPattern = /^[0-9a-f]{64}$/;
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,160}$/.test(value);
const pid = value => Number.isSafeInteger(value) && value > 1;
const birth = value => typeof value === 'string' && /^[0-9]{1,20}:[0-9]{6}$/.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fixedFlags = Object.freeze({ ready: false, productionReady: false, protected: false, productionReceiptAllowed: false });
const freeze = value => {
  for (const item of Object.values(value)) if (object(item) || Array.isArray(item)) freeze(item);
  return Object.freeze(value);
};
const refusal = (reason, detail) => Object.assign(new Error('Production application launch refused'), {
  code: 'APPLICATION_PRODUCTION_LAUNCH_REFUSED', reason, ...(detail ? { detail } : {}),
});
const fail = (reason, detail) => { throw refusal(reason, detail); };
const validUUID = value => isPFRoutingRunId(value);

function requestOf(input) {
  if (!object(input) || Object.keys(input).some(key => !['requestId', 'applicationId', 'environmentId', 'managedRouteId', 'workspace'].includes(key)) ||
      !validUUID(input.requestId) || !safeId(input.applicationId) || !validUUID(input.environmentId) || !validUUID(input.managedRouteId) ||
      !object(input.workspace) || Object.keys(input.workspace).some(key => !['cwd', 'timezone', 'locale'].includes(key))) fail('REQUEST_INVALID');
  const { cwd, timezone, locale } = input.workspace;
  if (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.length > 4096 || /[\0\r\n]/.test(cwd) ||
      cwd.split('/').some(part => part === '.' || part === '..') ||
      typeof timezone !== 'string' || timezone.length > 128 || !/^[A-Za-z0-9_+/-]+$/.test(timezone) ||
      timezone.split('/').some(part => part === '.' || part === '..') || timezone === 'Local' ||
      typeof locale !== 'string' || !/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/.test(locale) || locale.length > 64) fail('REQUEST_INVALID');
  try { new Intl.DateTimeFormat('en', { timeZone: timezone }); } catch { fail('REQUEST_INVALID'); }
  return freeze({ requestId: input.requestId, applicationId: input.applicationId, environmentId: input.environmentId,
    managedRouteId: input.managedRouteId, workspace: { cwd, timezone, locale } });
}

const uuidIdentityKeys = ['registrationId', 'registrationEpoch', 'environmentId', 'runId', 'realmId', 'bootstrapEpoch',
  'managedRouteId', 'routeRegistryEpoch', 'coreGeneration', 'tunnelInstanceId'];
const hashIdentityKeys = ['originalManifestSHA256', 'snapshotManifestSHA256', 'codeIdentitySHA256', 'installManifestSHA256',
  'originalContentSHA256', 'snapshotContentSHA256', 'nativeSHA256', 'controllerSHA256', 'guardianSHA256', 'frontSHA256',
  'attestorSHA256', 'workspaceSHA256', 'workspaceIdentitySHA256', 'coreExecutableSHA256', 'nodeIdentitySHA256',
  'routeEndpointIdentitySHA256', 'kernelInterfaceIdentitySHA256'];
const identityKeys = ['applicationId', ...uuidIdentityKeys, ...hashIdentityKeys, 'registryRoot', 'anchor', 'gid',
  'consoleUID', 'guiAuditSession', 'controllerPID', 'controllerBirth', 'corePID', 'coreBirth', 'coreVersion', 'tunnelName', 'tunnelPID', 'tunnelBirth'];
function inspectionOf(value, request, challenge, requireGates) {
  if (!object(value) || value.schema !== PRODUCTION_LAUNCH_PROTOCOL || value.source !== 'native-live-launch-inspection' ||
      value.challenge !== challenge || value.nativeObserved !== true || value.fixtureOnly !== false || !object(value.identity) || !object(value.gates)) fail('INSPECTION_INVALID');
  const identity = Object.fromEntries(identityKeys.map(key => [key, value.identity[key]]));
  if (identity.applicationId !== request.applicationId || identity.environmentId !== request.environmentId ||
      identity.managedRouteId !== request.managedRouteId || identity.workspaceSHA256 !== digest(request.workspace) ||
      uuidIdentityKeys.some(key => !validUUID(identity[key])) || hashIdentityKeys.some(key => !hashPattern.test(identity[key] ?? '')) ||
      identity.originalContentSHA256 !== identity.snapshotContentSHA256 ||
      identity.registryRoot !== PRODUCTION_APP_REGISTRY_ROOT || identity.anchor !== pfRoutingAnchor(identity.runId) ||
      !Number.isSafeInteger(identity.gid) || identity.gid < 7100 || identity.gid > 7999 ||
      !Number.isSafeInteger(identity.consoleUID) || identity.consoleUID < 1 ||
      !Number.isSafeInteger(identity.guiAuditSession) || identity.guiAuditSession < 1 ||
      !pid(identity.controllerPID) || !birth(identity.controllerBirth) || !pid(identity.corePID) || !birth(identity.coreBirth) || identity.coreVersion !== 'v1.19.32' ||
      !/^utun[0-9]{1,6}$/.test(identity.tunnelName ?? '') || !pid(identity.tunnelPID) || !birth(identity.tunnelBirth)) fail('IDENTITY_INVALID');
  const gates = Object.fromEntries(PRODUCTION_LAUNCH_GATES.map(key => [key, value.gates[key] === true]));
  const missingGates = PRODUCTION_LAUNCH_GATES.filter(key => !gates[key]);
  if (requireGates && missingGates.length) fail('GATE_UNVERIFIED', missingGates[0]);
  return freeze({ identity, gates, missingGates, bindingDigest: digest(identity) });
}

function proofOf(value, record, source, predicates = {}) {
  if (!object(value) || value.schema !== PRODUCTION_LAUNCH_PROTOCOL || value.source !== source ||
      value.nativeObserved !== true || value.fixtureOnly !== false ||
      value.leaseId !== record.lease.leaseId || value.bindingDigest !== record.lease.bindingDigest ||
      Object.entries(predicates).some(([key, expected]) => value[key] !== expected)) fail('BACKEND_PROOF_INVALID', source);
  return value;
}
function childOf(value, record) {
  proofOf(value, record, 'native-gui-stopped', { stoppedBeforeExec: true, bootstrapVerified: true, closedInheritedDescriptors: true });
  const identity = record.inspection.identity;
  if (!pid(value.pid) || !birth(value.birth) || value.codeIdentitySHA256 !== identity.codeIdentitySHA256 ||
      ['realUID', 'effectiveUID', 'savedUID'].some(key => value[key] !== identity.consoleUID) ||
      ['realGID', 'effectiveGID', 'savedGID'].some(key => value[key] !== identity.gid) ||
      !Array.isArray(value.supplementaryGroups) || value.supplementaryGroups.length !== 1 || value.supplementaryGroups[0] !== identity.gid) fail('CHILD_IDENTITY_INVALID');
  return freeze({ pid: value.pid, birth: value.birth, codeIdentitySHA256: value.codeIdentitySHA256 });
}
function frontOf(value, record) {
  proofOf(value, record, 'native-owned-notion-front', { raceProtected: true, sealedIdentityVerified: true, domainBytesPreserved: true,
    raceFree: true, proofKind: 'native-kernel-owned-front-v1', listenerOwnershipVerified: true,
    upstreamAuthenticationRequired: true, directFallbackForbidden: true, hostResolverForbidden: true });
  const identity = record.inspection.identity;
  if (!validUUID(value.instanceId) || !pid(value.pid) || !birth(value.birth) || value.host !== '127.0.0.1' ||
      !Number.isSafeInteger(value.port) || value.port < 1024 || value.port > 65535 || value.managedRouteId !== identity.managedRouteId ||
      value.registryEpoch !== identity.routeRegistryEpoch || value.frontSHA256 !== identity.frontSHA256 ||
      value.attestorSHA256 !== identity.attestorSHA256 || value.coreGeneration !== identity.coreGeneration || value.corePID !== identity.corePID ||
      value.coreBirth !== identity.coreBirth || value.coreExecutableSHA256 !== identity.coreExecutableSHA256 ||
      value.routeEndpointIdentitySHA256 !== identity.routeEndpointIdentitySHA256 || value.nodeIdentitySHA256 !== identity.nodeIdentitySHA256) fail('FRONT_IDENTITY_INVALID');
  return freeze({ instanceId: value.instanceId, pid: value.pid, birth: value.birth, host: value.host, port: value.port,
    managedRouteId: value.managedRouteId, registryEpoch: value.registryEpoch });
}
function guardianOf(value, record) {
  proofOf(value, record, 'native-whole-launch-guardian', { armed: true, ownsOriginalTunnelFD: true, persistentDeny: true,
    independentActor: true, expiryEnforced: true, controllerFailureSafe: true, frontFailureSafe: true,
    coreFailureSafe: true, guardianFailureSafe: true, interfaceReuseSafe: true });
  const identity = record.inspection.identity;
  if (!validUUID(value.instanceId) || !pid(value.pid) || !birth(value.birth) || value.guardianSHA256 !== identity.guardianSHA256 ||
      value.tunnelInstanceId !== identity.tunnelInstanceId || value.childPID !== record.child.pid || value.childBirth !== record.child.birth ||
      value.frontInstanceId !== record.front.instanceId || value.kernelInterfaceIdentitySHA256 !== identity.kernelInterfaceIdentitySHA256 ||
      [identity.controllerPID, identity.corePID, identity.tunnelPID, record.child.pid, record.front.pid].includes(value.pid) ||
      ['realUID', 'effectiveUID', 'savedUID'].some(key => value[key] !== 0) ||
      !Number.isSafeInteger(value.expiresAtUnixMs) || value.expiresAtUnixMs <= Date.now()) fail('GUARDIAN_IDENTITY_INVALID');
  return freeze({ instanceId: value.instanceId, pid: value.pid, birth: value.birth, expiresAtUnixMs: value.expiresAtUnixMs });
}

/**
 * A portable coordinator for the future sealed production backend, not a native
 * implementation or a readiness override. Construct only inside trusted helper
 * code; renderer/REST input cannot supply backend callbacks or inspection proofs.
 * Every hook must derive proofs from native observations and sealed registries.
 * In particular, a timeout is not cancellation: revokeLease must durably forbid
 * late hook mutations/resume, and each native hook must recheck that revocation.
 * The current runtime has no such backend and will refuse before reserveLease.
 */
export class ProductionLaunchContract {
  #backend; #timeoutMs; #maxLeases; #records = new Map(); #requestIds = new Set(); #queue = Promise.resolve();
  constructor({ backend = {}, timeoutMs = 15000, maxLeases = 64 } = {}) {
    if (!object(backend) || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000 ||
        !Number.isSafeInteger(maxLeases) || maxLeases < 1 || maxLeases > 64) fail('OPTIONS_INVALID');
    this.#backend = Object.freeze(Object.fromEntries(PRODUCTION_LAUNCH_HOOKS.map(name => [name, backend[name]])));
    this.#timeoutMs = timeoutMs; this.#maxLeases = maxLeases;
  }
  status() {
    return { schema: PRODUCTION_LAUNCH_PROTOCOL, ...fixedFlags, readOnly: true, integrated: false,
      missingHooks: PRODUCTION_LAUNCH_HOOKS.filter(name => typeof this.#backend[name] !== 'function'),
      leases: [...this.#records.values()].map(record => ({ leaseId: record.lease.leaseId, phase: record.phase,
        resumeAttempted: record.resumeAttempted, recoveryRequired: record.phase === 'recovery-required' })) };
  }
  #serialized(operation) { const result = this.#queue.then(operation); this.#queue = result.catch(() => {}); return result; }
  async #invoke(name, input) {
    if (typeof this.#backend[name] !== 'function') fail('BACKEND_HOOK_MISSING', name);
    const abort = new AbortController(), challenge = input.challenge ?? randomUUID(); let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => { abort.abort(); reject(refusal('BACKEND_TIMEOUT', name)); }, this.#timeoutMs); });
    try {
      const value = await Promise.race([Promise.resolve().then(() => this.#backend[name](freeze({ ...input, challenge }), { signal: abort.signal })), timeout]);
      if (!object(value) || value.challenge !== challenge) fail('BACKEND_NONCE_MISMATCH', name);
      return value;
    }
    catch (error) {
      throw refusal(error?.code === 'APPLICATION_PRODUCTION_LAUNCH_REFUSED' && reasons.has(error.reason)
        ? error.reason : 'BACKEND_OPERATION_FAILED', details.has(error?.detail) ? error.detail : name);
    }
    finally { clearTimeout(timer); }
  }
  async #inspect(request, record, requireGates = true) {
    const challenge = randomUUID();
    const value = await this.#invoke('inspectLaunch', { request, challenge, ...(record ? { lease: record.lease,
      ...(record.child ? { child: record.child } : {}) } : {}) });
    const inspected = inspectionOf(value, request, challenge, requireGates);
    if (record && inspected.bindingDigest !== record.lease.bindingDigest) fail('IDENTITY_CHANGED');
    return inspected;
  }
  async plan(input) {
    const request = requestOf(input), inspection = await this.#inspect(request, null, false);
    const missingHooks = PRODUCTION_LAUNCH_HOOKS.filter(name => typeof this.#backend[name] !== 'function');
    return { schema: PRODUCTION_LAUNCH_PROTOCOL, ...fixedFlags, readOnly: true, allowed: inspection.missingGates.length === 0 && missingHooks.length === 0,
      applicationId: request.applicationId, environmentId: request.environmentId,
      missingGates: [...inspection.missingGates], missingHooks, integration: PRODUCTION_LAUNCH_INTEGRATION };
  }
  start(input) {
    return this.#serialized(async () => {
      const request = requestOf(input);
      if (this.#records.size >= this.#maxLeases) fail('LEASE_CAPACITY_EXHAUSTED');
      if (this.#requestIds.has(request.requestId)) fail('REQUEST_ALREADY_CONSUMED');
      const missing = PRODUCTION_LAUNCH_HOOKS.find(name => typeof this.#backend[name] !== 'function');
      if (missing) fail('BACKEND_HOOK_MISSING', missing);
      const inspection = await this.#inspect(request);
      if ([...this.#records.values()].some(record => record.lease.runId === inspection.identity.runId)) fail('RUN_ALREADY_CONSUMED');
      const lease = freeze({ schema: PRODUCTION_LAUNCH_PROTOCOL, leaseId: randomUUID(), requestId: request.requestId,
        bindingDigest: inspection.bindingDigest, runId: inspection.identity.runId, anchor: inspection.identity.anchor });
      const record = { request, inspection, lease, phase: 'reservation-intent', resumeAttempted: false, child: null, front: null, guardian: null };
      // Never prune or reuse a consumed request/lease, including uncertain I/O.
      this.#requestIds.add(request.requestId); this.#records.set(lease.leaseId, record);
      try {
        proofOf(await this.#invoke('reserveLease', { lease, request, identity: inspection.identity }), record,
          'native-launch-ledger', { state: 'reserved', durable: true, exclusive: true, rootOwned: true });
        record.phase = 'reserved'; await this.#inspect(request, record);
        record.phase = 'deny-intent';
        proofOf(await this.#invoke('commitDeny', { lease }), record, 'native-pf-deny', { committed: true });
        proofOf(await this.#invoke('verifyDeny', { lease }), record, 'native-pf-deny', { verified: true, persistent: true });
        record.phase = 'deny-committed'; await this.#inspect(request, record);
        record.phase = 'gui-stage-intent';
        record.child = childOf(await this.#invoke('stageGUI', { lease }), record);
        record.phase = 'gui-stopped'; await this.#inspect(request, record);
        record.phase = 'front-intent';
        record.front = frontOf(await this.#invoke('prepareNotionFront', { lease, child: record.child }), record);
        proofOf(await this.#invoke('permitOwnedFront', { lease, front: record.front }), record, 'native-pf-owned-front', {
          verified: true, exactOwnedEndpointOnly: true, allOtherDenyPreserved: true,
          realmGID: inspection.identity.gid, host: record.front.host, port: record.front.port, frontInstanceId: record.front.instanceId });
        record.phase = 'front-prepared'; await this.#inspect(request, record);
        record.guardian = guardianOf(await this.#invoke('armWholeGuardian', { lease, child: record.child, front: record.front }), record);
        record.phase = 'guard-armed'; await this.#inspect(request, record);
        proofOf(await this.#invoke('verifyBeforeResume', { lease, child: record.child, front: record.front, guardian: record.guardian }),
          record, 'native-before-resume', { verified: true, atomicResumeBarrier: true, childPID: record.child.pid,
            childBirth: record.child.birth, guardianInstanceId: record.guardian.instanceId, guardianLeaseUnexpired: true,
            expiresAtUnixMs: record.guardian.expiresAtUnixMs, workspaceIdentitySHA256: inspection.identity.workspaceIdentitySHA256 });
        // Burn the resume capability before sending it. Lost ACK never retries.
        record.phase = 'resume-intent'; record.resumeAttempted = true;
        proofOf(await this.#invoke('beginResume', { lease }), record, 'native-launch-ledger', {
          state: 'resume-intent', durable: true, singleUse: true });
        await this.#inspect(request, record);
        if (record.guardian.expiresAtUnixMs <= Date.now()) fail('GUARDIAN_IDENTITY_INVALID');
        proofOf(await this.#invoke('resumeGUI', { lease, child: record.child, front: record.front, guardian: record.guardian }),
          record, 'native-gui-exec', { execACK: true, atomicResumeBarrier: true, pid: record.child.pid,
            birth: record.child.birth, codeIdentitySHA256: inspection.identity.codeIdentitySHA256 });
        const running = proofOf(await this.#invoke('verifyRunning', { lease, child: record.child, front: record.front, guardian: record.guardian }),
          record, 'native-running-launch', { verified: true, pid: record.child.pid, birth: record.child.birth,
            guardianInstanceId: record.guardian.instanceId, frontInstanceId: record.front.instanceId });
        if (!validUUID(running.sessionId)) fail('SESSION_IDENTITY_INVALID');
        record.phase = 'running'; record.sessionId = running.sessionId;
        // Lifecycle success does not authorize the desktop to publish readiness.
        return { schema: PRODUCTION_LAUNCH_PROTOCOL, ...fixedFlags, started: true, phase: record.phase,
          leaseId: lease.leaseId, sessionId: record.sessionId, runId: lease.runId };
      } catch (error) {
        const cleanupConfirmed = await this.#cleanup(record);
        const reported = refusal(error?.code === 'APPLICATION_PRODUCTION_LAUNCH_REFUSED' && reasons.has(error.reason)
          ? error.reason : 'BACKEND_OPERATION_FAILED', details.has(error?.detail) ? error.detail : undefined);
        Object.assign(reported, { leaseId: lease.leaseId, phase: record.phase, cleanupConfirmed }); throw reported;
      }
    });
  }
  async #cleanup(record) {
    if (record.phase === 'retired') return true;
    record.phase = 'recovery-required'; const { lease } = record;
    let revoked = false, denyRetained = false;
    try {
      proofOf(await this.#invoke('revokeLease', { lease }), record, 'native-launch-ledger', {
        state: 'revoked', durable: true, resumeForbidden: true, lateMutationForbidden: true });
      revoked = true;
    } catch {}
    // Cancellation uncertainty must not skip the independent denial action.
    // Neither action authorizes releasing a scope without both native proofs.
    try {
      proofOf(await this.#invoke('retainDeny', { lease }), record, 'native-pf-deny', { verified: true, persistent: true });
      denyRetained = true;
    } catch {}
    if (!revoked || !denyRetained) return false;
    try {
      proofOf(await this.#invoke('terminateOwnedScope', { lease }), record, 'native-owned-scope-stopped', {
        scopeQuiescent: true, ownedProcessesExited: true });
      proofOf(await this.#invoke('cleanupOwnedScope', { lease }), record, 'native-owned-scope-cleanup', {
        scopeQuiescent: true, ownedFrontClosed: true, ownedTunnelClosed: true, noOwnedStatesRemain: true,
        ownedRootHookRemoved: true, originalRootRestored: true, hookReceiptRetired: true,
        namespaceReclaimed: true, unrelatedNetworkUnchanged: true });
      proofOf(await this.#invoke('retireLease', { lease }), record, 'native-launch-ledger', {
        state: 'retired', durable: true, resumeForbidden: true });
      record.phase = 'retired'; return true;
    } catch { return false; } // Unknown ownership survives; no ticket/DELETE replay.
  }
  stop({ sessionId } = {}) {
    return this.#serialized(async () => {
      if (!validUUID(sessionId)) fail('SESSION_IDENTITY_INVALID');
      const record = [...this.#records.values()].find(value => value.sessionId === sessionId);
      if (!record) fail('SESSION_UNKNOWN');
      if (!await this.#cleanup(record)) fail('CLEANUP_UNCONFIRMED');
      return { schema: PRODUCTION_LAUNCH_PROTOCOL, ...fixedFlags, stopped: true, phase: 'retired', leaseId: record.lease.leaseId, sessionId };
    });
  }
}
