import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { MacOSPFController, MacOSPFExecutor, validatePFAppBoundLease, validatePFRootHookLease, validatePFApplicationPrestageAbort, validatePFApplicationPreflightAbort, PF_APP_BOUND_LEASE_SCHEMA, PF_APP_SESSION_LEASE_MS, PF_APP_RELEASE_RETRY_MS, PF_APP_STAGE_CLEANUP_WAIT_MS, PF_APP_PREPARATION_STOP_TIMEOUT_MS, PF_ROOT_HOOK_LEASE_SCHEMA, PF_INSTALL_ROOT, PF_RUNTIME_ROOT, dispatchPFRequest, APP_STAGE_PROGRESS_LIMIT, projectStageProgress } from '../native/macos-pf-routing/controller.mjs';
import { pfApplicationRegistrationId } from '../native/macos-pf-routing/policy.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
import { parseNativeApplicationEnvelope } from '../native/macos-pf-routing/helper-production-native.mjs';
import { projectPFHelperError } from '../native/macos-pf-routing/helper.mjs';
import { safeNotionResponse } from '../scripts/accept-macos-pf-notion.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
function hook(runId) { const leaseId = randomUUID(); return { schema: PF_ROOT_HOOK_LEASE_SCHEMA, runId, leaseId,
  anchor: pfRoutingAnchor(runId), owner: pfRoutingAnchor(runId), label: `envara.hook.v2.${sha(`${runId}|${leaseId}`).slice(0, 32)}`,
  ticket: '1', rootBeforeSHA256: 'a'.repeat(64), rootBeforeTextSHA256: 'b'.repeat(64) }; }
function lease() { const runId = randomUUID(); return { schema: PF_APP_BOUND_LEASE_SCHEMA, runId, environmentId: randomUUID(), realmId: randomUUID(),
  leaseId: randomUUID(), generation: randomUUID(), registrationId: randomUUID(), versionId: randomUUID(), consoleUID: 501, gid: 7100,
  cwd: '/tmp/owned-workspace', timezone: 'Asia/Manila', locale: 'en-PH', issuedMonotonicMs: 5000, expiresMonotonicMs: 35000,
  bootTimeSeconds: 1000, controllerPid: 321, controllerBirth: '100:000001', ipv4Address: '198.18.1.1', rootHookLease: hook(runId) }; }
test('sealed app context is exact, native-clock bounded, immutable copy and strictly binds root hook', () => {
  const source = lease(), copy = validatePFAppBoundLease(source); source.rootHookLease.ticket = '2'; assert.equal(copy.rootHookLease.ticket, '1');
  for (const edit of [v => { v.extra = true; }, v => { delete v.locale; }, v => { v.gid = true; }, v => { v.consoleUID = 0; },
    v => { v.expiresMonotonicMs = v.issuedMonotonicMs + PF_APP_SESSION_LEASE_MS + 1; }, v => { v.expiresMonotonicMs = v.issuedMonotonicMs; },
    v => { v.bootTimeSeconds = true; }, v => { v.controllerBirth = 'invalid'; }, v => { v.timezone = 'invalid'; },
    v => { v.cwd = 'relative'; }, v => { v.locale = 'en\n'; }, v => { v.ipv4Address = '127.0.0.1'; }, v => { v.rootHookLease.runId = randomUUID(); }]) {
    const value = lease(); edit(value); assert.throws(() => validatePFAppBoundLease(value), { code: 'APPLICATION_APP_CONTEXT_REFUSED' });
  }
});
const proxy = { protocol: 'socks5', host: '127.0.0.1', port: 20101, username: 'fixture-only-user', password: 'fixture-only-password', udpPolicy: 'proxy' };
const baseline = { digest: 'base', routeDigest: 'routes', dnsDigest: 'dns', pfDigest: 'pf' };
function fixture(overrides = {}, extra = {}) {
  const calls = [], identities = new Map(), managedPid = 710, child = { pid: 999, birth: '123:000005' };
  identities.set(managedPid, { uid: 501, path: '/owned/proxy-core/mihomo', birth: '123:000003' });
  identities.set(process.pid, { uid: 0, realUID: 0, savedUID: 0, path: `${PF_INSTALL_ROOT}/node`, birth: '123:000001' });
  const executor = { kind: 'fixture', readOnlyStatus: async () => ({ consoleUID: 501, noStateNativeAvailable: true,
    pf: { lo0SkipVerified: true }, ownedRootHook: { canCreateOwnedHook: true, pfDisabled: true, pinsVerified: true, originalRootCompatible: true } }),
    identify: async pid => { calls.push(`identity:${pid}`); return identities.get(pid); }, acquireLock: async () => calls.push('lock'),
    snapshotUnrelatedNetwork: async () => { calls.push('network-snapshot'); return baseline; }, persistRun: async () => calls.push('persist'),
    installOwnedRootHook: async runId => { calls.push('hook'); return hook(runId); }, requireEmptyOwnedAnchor: async () => calls.push('empty'),
    allocateGroup: async () => { calls.push('group'); return { gid: 7100, groupPath: '/Groups/_envara_pf_7100' }; },
    applicationContextClock: async () => ({ schema: 'envara.macos-pf-app-context-clock/v1', ok: true, bootTimeSeconds: 1000, nowMonotonicMilliseconds: 5000 }),
    sealApplicationLease: async value => { calls.push('seal'); executor.sealed = validatePFAppBoundLease(value); return { leaseSHA256: 'a'.repeat(64) }; },
    verifyApplicationLease: async () => calls.push('verify-lease'), enableOwnedReference: async () => { calls.push('enable'); return { existingForeignPFStatesAbsentBeforeEnable: true }; },
    startApplicationTransport: async () => { calls.push('transport'); return { keeperPID: 700, corePID: 701, frontPID: 702, ownsOriginalUTunFD: true, ownsOriginalListenerFD: true }; },
    applicationTransportControl: async (runId, operation) => { calls.push(`control:${operation}`);
      if (operation === 'L') return { ...child, stoppedBeforeExec: true, persistentDenyObserved: true };
      if (operation === 'B') return { ...child, executedIdentityVerified: true, seatbeltAppliedByFixedExec: true, frontAdmissionVerified: true, profile: 'seatbelt-front-only' };
      if (operation === 'S') return { persistentDenyObserved: true };
      if (operation === 'R') return { childAbsent: false, ...Object.fromEntries(['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified', 'privateJournalRetired'].map(key => [key, true])) };
    }, confirmApplicationTransportExited: async () => calls.push('transport-exit'),
    assertNoOwnedGroupProcesses: async () => calls.push('process-absence'), releaseOwnedReference: async () => calls.push('release-reference'),
    removeOwnedRootHook: async value => { validatePFRootHookLease(value, executor.sealed.runId);
      assert.deepEqual(value, executor.sealed.rootHookLease); calls.push('remove-hook');
      return { ownedRootHookRemoved: true, originalRootRestored: true, namespaceReclaimed: true, receiptRetired: true }; },
    removeGroups: async () => calls.push('remove-groups'), retireApplicationLease: async () => calls.push('retire-lease'), releaseLock: async () => calls.push('unlock'), ...overrides };
  const registered = [], deletedRegistrations = [];
  /* The native registry as the controller sees it: one registration per
   * application, reused while current. Tests set its state directly. */
  const registry = { state: 'absent', versionId: null, registerFailures: [] };
  const commands = {
    current: async ({ registrationId }) => { calls.push('current'); return { state: registry.state, registrationId, versionId: registry.versionId }; },
    register: async input => { calls.push('register'); registered.push(input);
      if (registry.registerFailures.length) throw registry.registerFailures.shift();
      registry.state = 'current'; registry.versionId = input.versionId; return { ...input, applicationIdentityVerified: true }; },
    deleteRegistration: async ({ registrationId }) => { calls.push('delete-registration'); deletedRegistrations.push(registrationId);
      registry.state = 'absent'; registry.versionId = null; return { deleted: true, absent: false }; } };
  const controller = new MacOSPFController({ executor, applicationCommands: commands, inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
    authenticateProxy: async () => {}, identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, ...extra });
  const prepareRoute = async (change = {}) => controller.prepareRoute({ application: { id: 'notion', profileId: 'profile', executablePath: '/Applications/Notion.app' },
    workspace: { cwd: '/tmp/owned-workspace', timezone: 'Asia/Manila', locale: 'en-PH' }, route: proxy,
    managedRoute: { profileId: 'profile', proxyId: 'node', nodeType: 'anytls', corePid: managedPid, routeIdentity: randomUUID(), coreGeneration: randomUUID(), coreVersion: 'v1.19.32' }, ...change });
  return { controller, executor, calls, prepareRoute, commands, identities, child, registered, registry, deletedRegistrations };
}
const input = routeId => ({ routeId, runId: randomUUID(), environmentId: randomUUID(), lifetimeSeconds: 30, activationAuthorized: true });
test('successful stop passes only the issued lease through the real executor validator, DELETE and independent STATUS before complete cleanup', async () => {
  const f = fixture(), route = await f.prepareRoute(), request = input(route.routeId);
  await f.controller.prepareNotionApplication(request);
  const native = new MacOSPFExecutor(), issuedLease = structuredClone(f.executor.sealed.rootHookLease), nativeCalls = [];
  native.runtimeRunId = request.runId; native.rootHookLease = issuedLease;
  native.nativeRootHookRequest = async (operation, params) => {
    assert.deepEqual(params, { lease: issuedLease });
    nativeCalls.push(operation); f.calls.push(operation);
    return { readOnly: operation === 'hook-status', ticketSource: 'this-INSERT-return-only',
      ownedRootHookRemoved: true, originalRootRestored: true, receiptRetired: true, pinsVerified: true, pfDisabled: true,
      namespaceState: 'absent', namespaceReclaimed: true, namespaceExists: false, cleanupPending: false,
      originalRootSHA256: issuedLease.rootBeforeSHA256, originalRootTextSHA256: issuedLease.rootBeforeTextSHA256 };
  };
  const run = f.controller.appRuns.get(request.runId);
  await assert.rejects(native.removeOwnedRootHook(run), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(nativeCalls, [], 'The orchestration object must fail before any native DELETE or STATUS.');
  f.executor.removeOwnedRootHook = value => native.removeOwnedRootHook(value);
  const cleanupStart = f.calls.length, clean = await f.controller.stopNotionApplication({ runId: request.runId });
  assert.deepEqual(f.calls.slice(cleanupStart).filter(value => value !== 'persist'), [
    'control:S', 'control:R', 'transport-exit', 'process-absence', 'release-reference',
    'delete-owned-root-hook', 'hook-status', 'remove-groups', 'network-snapshot', 'retire-lease', 'unlock']);
  const evidence = clean.cleanupEvidence, keys = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved',
    'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified', 'privateJournalRetired', 'transportExitConfirmed',
    'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
    'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged',
    'sealedContextRetired', 'registryReleased'];
  assert.equal(evidence.runId, request.runId); assert.equal(evidence.environmentId, request.environmentId);
  assert.equal(evidence.complete, true); assert.equal(evidence.cleanupUncertain, false);
  assert.equal(clean.cleanupComplete, true); assert.equal(keys.length, 21); assert.ok(keys.every(key => evidence[key] === true));
  assert.ok(['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => clean[key] === false));
  assert.deepEqual(nativeCalls, ['delete-owned-root-hook', 'hook-status']);
  await f.controller.shutdown();
});
test('actual orchestration orders signed snapshot, sealed clock context, same native transport and one-time cold ticket before native resume', async () => {
  const { controller, executor, calls, prepareRoute } = fixture(); const route = await prepareRoute(), request = input(route.routeId);
  const prepared = await controller.prepareNotionApplication(request);
  assert.equal(prepared.staged, true); assert.equal(prepared.resumed, false); assert.equal(prepared.ready, false);
  assert.ok(calls.indexOf('register') < calls.indexOf('lock')); assert.ok(calls.indexOf('hook') < calls.indexOf('seal'));
  assert.ok(calls.indexOf('seal') < calls.indexOf('transport')); assert.ok(calls.indexOf('transport') < calls.indexOf('control:L'));
  assert.equal(executor.sealed.rootHookLease.runId, request.runId); assert.equal(executor.sealed.consoleUID, 501);
  const running = await controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true });
  assert.equal(running.resumed, true); assert.equal(running.profile, 'seatbelt-front-only'); assert.equal(running.protected, false); assert.equal(running.udpSupported, false);
  await assert.rejects(controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true }));
  assert.equal(calls.filter(value => value === 'control:B').length, 1);
  const publicText = JSON.stringify(await controller.status()); assert.ok(!publicText.includes(proxy.password)); assert.ok(!publicText.includes('/tmp/owned-workspace')); assert.ok(!publicText.includes('rootHookLease'));
  const clean = await controller.stopNotionApplication({ runId: request.runId }); assert.equal(clean.cleanupComplete, true); assert.equal(clean.protected, false);
  assert.equal(clean.cleanupEvidence.source, 'simulated-notion-controller'); assert.equal(clean.cleanupEvidence.runId, request.runId);
  assert.equal(clean.cleanupEvidence.registryReleased, true); assert.equal(clean.cleanupEvidence.privateJournalRetired, true);
  assert.ok(['ready', 'protected', 'productionReady', 'genericApplicationRouting', 'udpSupported'].every(key => clean[key] === false));
  assert.ok(calls.indexOf('control:R') < calls.indexOf('release-reference')); assert.ok(calls.indexOf('transport-exit') < calls.indexOf('remove-hook'));
  assert.ok(calls.indexOf('retire-lease') < calls.indexOf('unlock')); await controller.shutdown();
});
/* Attaching software is not limited to one product: any locally selected
 * application is accepted here, and the fixed native registry independently
 * inspects and seals the real signed bundle. A path that is not a bundle at all
 * is still refused, and that refusal must precede every native mutation. */
for (const kind of ['no-root', 'no-runtime', 'no-activation', 'lo-skipped', 'not-a-bundle', 'injected-proof']) test(`application ${kind} refuses before native mutation`, async () => {
  const options = kind === 'no-root' ? { identity: { uid: 501, euid: 501, callerUID: 501, controlledSession: true } } :
    kind === 'no-runtime' ? { inspectInstallation: async () => ({ verified: true, runtimeVerified: false }) } : {};
  const f = fixture({}, options), route = await f.prepareRoute(kind === 'not-a-bundle' ? { application: { id: 'other', profileId: 'profile', executablePath: '/Applications/Other' } } : {});
  const request = input(route.routeId); if (kind === 'no-activation') request.activationAuthorized = false;
  if (kind === 'injected-proof') request.nativeVerified = true;
  if (kind === 'lo-skipped') f.executor.readOnlyStatus = async () => ({ consoleUID: 501, pf: { lo0SkipVerified: false } });
  await assert.rejects(f.controller.prepareNotionApplication(request)); assert.ok(!f.calls.includes('register') && !f.calls.includes('lock'));
  await f.controller.shutdown();
});
test('an application keeps one registration: reused while current, a new version only when its original changed', async () => {
  /* A fresh registration per attach filled the 32-registration registry, put
   * every attach on a new, logged-out data directory and copied the whole
   * application again each time. */
  const expected = pfApplicationRegistrationId('/Applications/Notion.app');
  const first = fixture(), route = await first.prepareRoute(); await first.controller.prepareNotionApplication(input(route.routeId));
  assert.equal(first.executor.sealed.registrationId, expected, 'the registration is derived from the application, not random');
  assert.equal(first.registered.length, 1); assert.equal(first.registered[0].previousVersionId, undefined);
  const copied = first.executor.sealed.versionId;

  const again = fixture(); again.registry.state = 'current'; again.registry.versionId = copied;
  const second = await again.prepareRoute(); await again.controller.prepareNotionApplication(input(second.routeId));
  assert.equal(again.registered.length, 0, 'an exact current version is reused, never copied again');
  assert.equal(again.executor.sealed.registrationId, expected); assert.equal(again.executor.sealed.versionId, copied);

  const updated = fixture(); updated.registry.state = 'stale'; updated.registry.versionId = copied;
  const third = await updated.prepareRoute(); await updated.controller.prepareNotionApplication(input(third.routeId));
  assert.equal(updated.registered.length, 1); assert.equal(updated.registered[0].previousVersionId, copied, 'a new version names the one it supersedes');
  assert.equal(updated.executor.sealed.registrationId, expected); assert.notEqual(updated.executor.sealed.versionId, copied);
});
test('a full, retired or interrupted registration is removed and registered again under the same id', async () => {
  const expected = pfApplicationRegistrationId('/Applications/Notion.app'), full = Object.assign(new Error('full'),
    { code: 'APPLICATION_NATIVE_REFUSED', nativeFailure: { stage: 'register', reason: 'NATIVE_APP_OPERATION_REFUSED', error: 28 } });
  for (const [state, failures] of [['stale', [full]], ['retired', []], ['incomplete', []]]) {
    const f = fixture(); f.registry.state = state; f.registry.versionId = state === 'stale' ? randomUUID() : null; f.registry.registerFailures.push(...failures);
    const route = await f.prepareRoute(); await f.controller.prepareNotionApplication(input(route.routeId));
    assert.deepEqual(f.deletedRegistrations, [expected], state);
    assert.equal(f.registered.at(-1).previousVersionId, undefined, `${state}: registered again from nothing`);
    assert.equal(f.executor.sealed.registrationId, expected, `${state}: the id, and so the data directory, is kept`);
    assert.ok(f.calls.indexOf('delete-registration') < f.calls.lastIndexOf('register'));
  }
  const other = Object.assign(new Error('refused'), { code: 'APPLICATION_NATIVE_REFUSED', nativeFailure: { stage: 'register', reason: 'NATIVE_APP_OPERATION_REFUSED', error: 13 } });
  const refused = fixture(); refused.registry.state = 'stale'; refused.registry.versionId = randomUUID(); refused.registry.registerFailures.push(other);
  const route = await refused.prepareRoute();
  await assert.rejects(refused.controller.prepareNotionApplication(input(route.routeId)));
  assert.deepEqual(refused.deletedRegistrations, [], 'only a full registration is removed; any other refusal stops');
  const unknown = fixture(); unknown.registry.state = 'mystery';
  const unknownRoute = await unknown.prepareRoute();
  await assert.rejects(unknown.controller.prepareNotionApplication(input(unknownRoute.routeId)));
  assert.equal(unknown.registered.length, 0); assert.deepEqual(unknown.deletedRegistrations, []);
});
test('a locally selected application outside Notion is accepted and sealed by its own bundle', async () => {
  const f = fixture(), route = await f.prepareRoute({ application: { id: 'other', profileId: 'profile', executablePath: '/Applications/Other.app/Contents/MacOS/Other' } });
  const request = input(route.routeId);
  const prepared = await f.controller.prepareNotionApplication(request);
  assert.equal(prepared.staged, true); assert.equal(prepared.ready, false); assert.equal(prepared.protected, false);
  assert.ok(f.calls.includes('register') && f.calls.includes('lock'), 'the fixed native registry performs the identity work');
  /* The bundle is derived from the selected executable and handed to the fixed
   * native registry, which inspects and seals the real signed bundle itself. */
  const registered = f.registered.at(-1);
  assert.equal(registered.bundlePath, '/Applications/Other.app');
  await f.controller.shutdown();
});
test('lost stage proof permanently retains sealed state and cannot resume or report cleanup', async () => {
  const f = fixture({ applicationTransportControl: async () => { throw new Error('private fixture detail'); } }); const route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), { code: 'APPLICATION_ROUTING_NOT_READY' });
  const state = f.controller.applicationSnapshot({ runId: request.runId }); assert.equal(state.cleanupUncertain, true); assert.equal(state.cleanupComplete, false);
  await assert.rejects(f.controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true }));
  assert.equal(f.calls.includes('unlock'), false); assert.equal((await f.controller.shutdown()).cleanupRequired, true);
});
test('final transport receipt missing original listener close cannot release PF or erase its private lease', async () => {
  const f = fixture(); const route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
  const original = f.executor.applicationTransportControl; f.executor.applicationTransportControl = async (runId, op) => {
    const value = await original(runId, op); if (op === 'R') value.originalListenerClosed = false; return value; };
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  assert.ok(!f.calls.includes('release-reference') && !f.calls.includes('retire-lease') && !f.calls.includes('unlock'));
  assert.equal((await f.controller.shutdown()).cleanupRequired, true);
});
test('forged resume booleans and a changed child birth poison the one-time stage rather than permit a second resume', async () => {
  const f = fixture(); const route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
  const original = f.executor.applicationTransportControl; f.executor.applicationTransportControl = async (runId, op) => {
    const value = await original(runId, op); if (op === 'B') value.birth = '999:000000'; return value; };
  await assert.rejects(f.controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true }), { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
  await assert.rejects(f.controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true }));
  assert.equal(f.controller.applicationSnapshot({ runId: request.runId }).cleanupUncertain, true); await f.controller.shutdown();
});
test('new public RPC names are concrete controller methods and do not permit arbitrary native commands', async () => {
  const f = fixture(); await assert.rejects(dispatchPFRequest(f.controller, { protocol: 'envara.application-routing', version: 1, id: 'fixture', method: 'applicationTransportControl', params: {} }));
  const executor = new MacOSPFExecutor(); assert.equal(executor.allowedCommand(`${PF_INSTALL_ROOT}/envara-pf-native`, ['app-context-clock']), true);
  assert.equal(executor.allowedCommand(`${PF_INSTALL_ROOT}/envara-pf-native`, ['app-context-clock', 'callerproof']), false);
  await f.controller.shutdown();
});
test('production sealed-file writer detects same-size content, replaced inode, hardlink and permissions using actual own-temp files', async t => {
  for (const tamper of ['bytes', 'inode', 'hardlink', 'permissions', 'symlink']) await t.test(tamper, async () => {
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'envara-app-seal-'));
    const value = lease();
    // Redirect the fixed production pathname to only this test-owned tmp.
    // UID metadata is injected for this unprivileged fixture; actual nofollow,
    // inode/links/mode/content and durable writes use the filesystem itself.
    const translate = target => target.replace('/Library/PrivilegedHelperTools/io.envara.pf-runtime', temporary);
    const rootOwner = info => { info.uid = 0; return info; };
    const system = { ...fs, lstat: async target => rootOwner(await fs.lstat(translate(target))),
      open: async (target, ...args) => { const handle = await fs.open(translate(target), ...args), stat = handle.stat.bind(handle);
        handle.stat = async () => rootOwner(await stat()); return handle; },
      unlink: async target => fs.unlink(translate(target)) };
    const executor = new MacOSPFExecutor({ fileSystem: system }); executor.runtimeRunId = value.runId;
    executor.assertRuntimeRootHeld = async () => {}; executor.inspectRuntimeDirectory = async (target, handle) => {
      const info = rootOwner(await fs.lstat(translate(target)));
      if (handle) { const held = await handle.stat(); assert.equal(info.dev, held.dev); assert.equal(info.ino, held.ino); }
      return info;
    };
    executor.createRunDirectory = async (run, realm) => { await fs.mkdir(path.join(temporary, run, realm), { mode: 0o700, recursive: true });
      const handle = await fs.open(path.join(temporary, run), 'r'); executor.runDirectories.set(`/Library/PrivilegedHelperTools/io.envara.pf-runtime/${run}`, handle); };
    try {
      const receipt = await executor.sealApplicationLease(value); assert.match(receipt.leaseSHA256, /^[0-9a-f]{64}$/);
      const target = path.join(temporary, value.runId, 'app-bound-lease.json'), contents = await fs.readFile(target);
      const binding = await executor.applicationTransportBinding(value.runId, value.environmentId, receipt.leaseSHA256);
      const actualFile = await fs.stat(target), actualDirectory = await fs.stat(path.dirname(target));
      assert.equal(binding.leaseInode, String(actualFile.ino)); assert.equal(binding.runDirectoryInode, String(actualDirectory.ino));
      assert.equal(binding.realmId, value.realmId); assert.equal(binding.controllerBirth, value.controllerBirth);
      await assert.rejects(executor.sealApplicationLease(value), { code: 'APPLICATION_APP_CONTEXT_REFUSED' });
      if (tamper === 'bytes') { const changed = Buffer.from(contents); changed[10] = changed[10] === 32 ? 33 : 32; await fs.writeFile(target, changed); }
      if (tamper === 'inode') { await fs.rename(target, `${target}.old`); await fs.writeFile(target, contents, { mode: 0o600 }); }
      if (tamper === 'hardlink') await fs.link(target, `${target}.extra`);
      if (tamper === 'permissions') await fs.chmod(target, 0o644);
      if (tamper === 'symlink') { await fs.rename(target, `${target}.old`); await fs.symlink(`${target}.old`, target); }
      await assert.rejects(executor.verifyApplicationLease(value.runId), { code: 'APPLICATION_APP_CONTEXT_REFUSED' });
      await assert.rejects(executor.applicationTransportBinding(value.runId, value.environmentId, receipt.leaseSHA256), { code: 'APPLICATION_APP_CONTEXT_REFUSED' });
      await assert.rejects(executor.retireApplicationLease(value.runId), { code: 'APPLICATION_APP_CONTEXT_REFUSED' });
      assert.equal((await fs.lstat(target)).isSymbolicLink(), tamper === 'symlink');
    } finally { for (const entry of executor.appLeases.values()) await entry.handle.close();
      for (const handle of executor.runDirectories.values()) await handle.close(); await fs.rm(temporary, { recursive: true, force: true }); }
  });
});
function streamFixture({ forked = false, wrongParent = false, malformed = false, missingListener = false, nativeRefusal = null,
  cleanupReady = null, cleanupStopping = null, cleanupRelease = null, controlRefusal = null, controlRefusalCommand = 'L', coldStageDelay = 0, resumeDelay = 0,
  coldStageStoppedChanges = null, coldStageRefusal = null, coldStageNoAck = false, stopNoAck = false, cleanupPendingStops = [],
  preparationFailure = false, preparationAutomatic = {}, preparationPendingStops = [],
  /* revokeAfterResume: the guardian revokes on its own while the application
   * runs, exactly as a crashed child makes it do. This is the case that left
   * the trial showing 'running' for 44 s after the child had stopped. */
  revokeAfterResume = false,
  abort = null, abortExit = 1, abortSignal = null, abortTrailing = '', refusalStage = 'factory-open', fragmentAbort = false, omitAbort = false, omitRefusal = false,
  preflightAbort = null, preflightBeforeIdentity = false, unavailableIdentity = false, preflightRefusalStage = 'preflight', duplicatePreflightKey = false,
  /* profile: which fixed native profile this run's keeper frames report. The
   * binding under test is that every later frame must match the run's own. */
  profile = 'seatbelt-front-only',
  /* refuseReleases: how many 'R' requests the armed guardian refuses before it
   * releases. The real guardian refuses, without any frame, while a helper of
   * the application is still in the owned group. */
  refuseReleases = 0,
  /* stageProgress: diagnostic native step frames the keeper writes after L,
   * before its stopped ACK; stageProgressRaw: exact lines, for malformed ones. */
  stageProgress = [], stageProgressRaw = [] } = {}) {
  let refusedReleases = 0;
  const context = lease(), keeperPID = forked ? 8991 : 8990;
  context.controllerPid = process.pid;
  const child = Object.assign(new EventEmitter(), { pid: 8990, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  const metadata = inode => ({ isFile: () => true, isSymbolicLink: () => false, uid: 0, gid: 0, mode: 0o100755, nlink: 1, dev: 1, ino: inode, size: 32, mtimeMs: 1, ctimeMs: 1 });
  const executor = new MacOSPFExecutor({ fileSystem: { realpath: async filename => filename, lstat: async filename => {
    if (filename === `${PF_INSTALL_ROOT}/envara-pf-native`) return metadata(4);
    if (filename === `${PF_INSTALL_ROOT}/node`) return metadata(5);
    throw Object.assign(new Error(), { code: 'ENOENT' });
  } }, spawnChild: (executable, argv, options) => {
    assert.equal(executable, `${PF_INSTALL_ROOT}/envara-pf-native`); assert.deepEqual(argv, ['app-tunnel-bootstrap', context.runId, context.environmentId]);
    assert.equal(options.shell, false); assert.ok(!JSON.stringify(options).includes(proxy.password)); return child;
  } });
  executor.appLeases.set(context.runId, { bytes: Buffer.from(JSON.stringify(context)) }); executor.verifyApplicationLease = async () => ({ leaseSHA256: 'a'.repeat(64) });
  const binding = { runId: context.runId, environmentId: context.environmentId, realmId: context.realmId, gid: context.gid, leaseSHA256: 'a'.repeat(64),
    controllerPID: context.controllerPid, controllerBirth: context.controllerBirth, leaseDevice: '1', leaseInode: '2', runDirectoryDevice: '1', runDirectoryInode: '3' };
  executor.applicationTransportBinding = async () => Object.freeze({ ...binding });
  executor.identify = async pid => { if (preflightBeforeIdentity) emitPreflight(); if (unavailableIdentity) throw new Error('fixture child already exited');
    return { ok: true, pid, uid: 0, realUID: 0, savedUID: 0, birth: `${pid}:000001`,
    parentPid: pid === child.pid && forked ? process.pid : pid === keeperPID ? wrongParent ? 7777 : forked ? child.pid : process.pid : keeperPID,
    path: pid === child.pid && forked ? '/bin/launchctl' : pid === 8992 ? `${PF_INSTALL_ROOT}/mihomo` : pid === 8993 ? `${PF_INSTALL_ROOT}/node` : `${PF_INSTALL_ROOT}/envara-pf-native` }; };
  const emit = event => child.stdout.write(`${JSON.stringify(event)}\n`);
  let preflightEmitted = false;
  const emitPreflight = () => {
    if (preflightEmitted) return; preflightEmitted = true;
    const report = { schema: 'envara.macos-pf-app-transport/v1', event: 'preflight-aborted', stage: 'preflight', ...binding,
      bootstrapPID: child.pid, bootstrapBirth: `${child.pid}:000001`, bootstrapParentPID: context.controllerPid, bootstrapParentBirth: context.controllerBirth,
      bootstrapDevice: '1', bootstrapInode: '4', bootstrapParentDevice: '1', bootstrapParentInode: '5', proofNonce: '0'.repeat(32), exitStatus: 1,
      ...Object.fromEntries(['sealedContextVerified', 'privateChildrenAbsent', 'gidScopeAbsent', 'filterJournalAbsent', 'ownedFilterClassesEmpty'].map(key => [key, true])),
      ...Object.fromEntries(['bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted', 'ready', 'protected'].map(key => [key, false])), ...preflightAbort };
    executor.expectedPreflightAbort = report;
    const refusal = { schema: 'envara.macos-pf-app-transport/v1', event: 'transport-refused', runId: context.runId,
      environmentId: context.environmentId, stage: preflightRefusalStage, reason: 'NATIVE_OPERATION_REFUSED', error: 13, ready: false, protected: false };
    let terminal = JSON.stringify(report);
    if (duplicatePreflightKey) terminal = terminal.replace('"sealedContextVerified":true', '"sealedContextVerified":false,"sealedContextVerified":true');
    const output = `${omitRefusal ? '' : `${JSON.stringify(refusal)}\n`}${omitAbort ? '' : `${terminal}\n`}${abortTrailing}`;
    if (fragmentAbort) { child.stdout.write(output.slice(0, 53)); child.stdout.write(output.slice(53)); } else child.stdout.write(output);
    setImmediate(() => child.emit('close', abortExit, abortSignal));
  };
  let commands = '', ticket, guardianArmed = false, guardianRevoked = false, completeColdStage, stopAttempts = 0;
  const controlCommands = [];
  const emitKeeper = (event, changes = {}) => emit({ schema: 'envara.pf-app-keeper/v1', event, ticketId: ticket,
    registrationId: context.registrationId, versionId: context.versionId, environmentId: context.environmentId, runId: context.runId,
    pid: 8994, birth: '8994:000001', keeperPID, profile, persistentDenyObserved: true,
    stoppedBeforeExec: false, childReaped: false, scopeQuiescentObserved: false, resumeSent: false, resumed: false, cancelSent: true,
    executedIdentityVerified: false, seatbeltAppliedByFixedExec: false, frontAdmissionVerified: false, ready: false, protected: false, ...changes });
  const cleanupPending = (cleanupAttempt, changes = {}) => ({ schema: 'envara.pf-app-keeper/v1', event: 'cleanup-pending', ticketId: ticket,
    registrationId: context.registrationId, versionId: context.versionId, environmentId: context.environmentId, runId: context.runId,
    pid: 8994, birth: '8994:000001', keeperPID, keeperBirth: `${keeperPID}:000001`, profile, cleanupAttempt,
    launchAuthorityBurned: true, custodyHeld: true, denyVerified: false, frontClosedVerified: false, familyStoppedVerified: false,
    ready: false, protected: false, ...changes });
  const preparationId = randomUUID();
  const preparationPending = (command, cleanupAttempt, changes = {}) => ({ schema: 'envara.pf-app-preparation/v1', event: 'cleanup-pending',
    ticketId: ticket, registrationId: context.registrationId, versionId: context.versionId, environmentId: context.environmentId, runId: context.runId,
    keeperPID, keeperBirth: `${keeperPID}:000001`, preparationId, generation: 1, command, cleanupAttempt, childState: 'unreaped',
    launchAuthorityBurned: true, custodyHeld: true, denyVerified: false, frontClosedVerified: false, ready: false, protected: false, ...changes });
  child.stdin.on('data', bytes => { commands += bytes; let newline;
    while ((newline = commands.indexOf('\n')) >= 0) {
      const command = commands.slice(0, newline); commands = commands.slice(newline + 1);
      if (!command.startsWith('{')) controlCommands.push(command);
      if (command === 'S') {
        stopAttempts++;
        const preparation = preparationPendingStops.shift();
        if (preparation) { emit(preparationPending('S', stopAttempts, preparation)); continue; }
        const changes = cleanupPendingStops.shift();
        if (changes) { emit(cleanupPending(stopAttempts, changes)); continue; }
      }
      if (controlRefusal && command.split(' ')[0] === controlRefusalCommand) {
        emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-refused', runId: context.runId,
          environmentId: context.environmentId, stage: 'guardian', reason: 'NATIVE_OPERATION_REFUSED', error: 13, ready: false, protected: false, ...controlRefusal });
        continue;
      }
      if (command.startsWith('{')) { const route = JSON.parse(command); assert.equal(route.password, proxy.password);
        if (preflightAbort) { emitPreflight(); continue; }
        if (abort) {
          const report = { schema: 'envara.macos-pf-app-transport/v1', event: 'prestage-aborted', stage: 'factory-open', ...binding,
            keeperPID, keeperBirth: `${keeperPID}:000001`, keeperParentPID: forked ? child.pid : context.controllerPid,
            keeperParentBirth: forked ? `${child.pid}:000001` : context.controllerBirth, corePID: 8992, coreBirth: '8992:000001', frontPID: 8993, frontBirth: '8993:000001',
            utunName: 'utun90', utunDevice: '4', utunInode: '5', utunControlId: 1, utunControlUnit: 91,
            listenerHost: '127.0.0.1', listenerPort: 29999, listenerDevice: '4', listenerInode: '6', exitStatus: 1,
            ...Object.fromEntries(['originalUTunVerified', 'originalListenerVerified', 'coreReaped', 'frontReaped', 'gidScopeAbsent', 'filterJournalAbsent', 'originalUTunClosed', 'originalListenerClosed'].map(key => [key, true])),
            ...Object.fromEntries(['denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted', 'ready', 'protected'].map(key => [key, false])) };
          Object.assign(report, abort); executor.expectedAbort = report;
          const refusal = { schema: 'envara.macos-pf-app-transport/v1', event: 'transport-refused', runId: context.runId,
            environmentId: context.environmentId, stage: refusalStage, reason: 'NATIVE_OPERATION_REFUSED', error: 13, ready: false, protected: false };
          const output = `${omitRefusal ? '' : `${JSON.stringify(refusal)}\n`}${omitAbort ? '' : `${JSON.stringify(report)}\n`}${abortTrailing}`;
          if (fragmentAbort) { child.stdout.write(output.slice(0, 57)); child.stdout.write(output.slice(57)); } else child.stdout.write(output);
          setImmediate(() => child.emit('close', abortExit, abortSignal)); continue;
        }
        if (nativeRefusal) { emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-refused', runId: context.runId,
          environmentId: context.environmentId, stage: 'front-handshake', reason: 'NATIVE_OPERATION_REFUSED', error: 35, ready: false, protected: false, ...nativeRefusal });
          if (cleanupReady) emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-cleanup-ready', runId: context.runId,
            environmentId: context.environmentId, interfaceName: 'utun90', corePID: 8992, coreBirth: '8992:000001', frontPID: 8993, frontBirth: '8993:000001',
            frontPort: 29999, keeperPID, ownsOriginalUTunFD: true, ownsOriginalListenerFD: true, ready: false, protected: false,
            stage: nativeRefusal.stage, cleanupOnly: true, ...cleanupReady });
          continue; }
        emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-started', runId: context.runId, environmentId: context.environmentId,
          interfaceName: 'utun90', corePID: 8992, coreBirth: '8992:000001', frontPID: 8993, frontBirth: '8993:000001', frontPort: 29999, keeperPID,
          ownsOriginalUTunFD: true, ownsOriginalListenerFD: !missingListener, ready: false, protected: false, ...(malformed ? { callerProof: true } : {}) });
      } else if (command.startsWith('L ')) { ticket = command.slice(2); const stopped = { schema: 'envara.pf-app-keeper/v1', event: 'stopped', ticketId: ticket,
        registrationId: context.registrationId, versionId: context.versionId, runId: context.runId, environmentId: context.environmentId,
        keeperPID, pid: 8994, birth: '8994:000001', profile, persistentDenyObserved: true, stoppedBeforeExec: true,
        ...Object.fromEntries(['childReaped', 'scopeQuiescentObserved', 'resumeSent', 'resumed', 'cancelSent', 'executedIdentityVerified', 'seatbeltAppliedByFixedExec', 'frontAdmissionVerified'].map(key => [key, false])), ready: false, protected: false, ...coldStageStoppedChanges };
        const completeStage = () => {
          if (preparationFailure) {
            emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-refused', runId: context.runId,
              environmentId: context.environmentId, stage: 'guardian', reason: 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED', error: 13,
              ready: false, protected: false });
            if (preparationAutomatic) emit(preparationPending('automatic', 0, preparationAutomatic));
            return;
          }
          if (coldStageRefusal) { emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-refused', runId: context.runId,
            environmentId: context.environmentId, stage: 'guardian', reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13,
            ready: false, protected: false, ...coldStageRefusal }); return; }
          guardianArmed = true; emit(stopped);
        };
        completeColdStage = completeStage;
        for (const progress of stageProgress) emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'stage-progress', runId: context.runId,
          environmentId: context.environmentId, step: 'ticket-prepare', stepMs: 10, totalMs: 20, fullChecks: 2, identityChecks: 12, ready: false, protected: false, ...progress });
        for (const raw of stageProgressRaw) child.stdout.write(raw);
        if (!coldStageNoAck) { if (coldStageDelay) setTimeout(completeStage, coldStageDelay); else completeStage(); }
      } else if (command === 'B') {
        const resumed = { schema: 'envara.pf-app-keeper/v1', event: 'resumed', ticketId: ticket,
          registrationId: context.registrationId, versionId: context.versionId, runId: context.runId, environmentId: context.environmentId,
          keeperPID, pid: 8994, birth: '8994:000001', executedIdentityVerified: true, seatbeltAppliedByFixedExec: true,
          frontAdmissionVerified: true, profile: profile, persistentDenyObserved: false, stoppedBeforeExec: false, childReaped: false, scopeQuiescentObserved: false, resumeSent: true, resumed: true, cancelSent: false, ready: false, protected: false };
        if (resumeDelay) setTimeout(() => emit(resumed), resumeDelay); else emit(resumed);
        if (revokeAfterResume) setImmediate(() => {
          /* The guardian revokes once, on its own: the exact child is stopped
           * and the trial is still showing 'running'. */
          if (!guardianRevoked) { guardianRevoked = true; emitKeeper('stopping', { childReaped: true, cancelSent: false, stoppedBeforeExec: false }); }
        });
      } else if (command === 'S' && stopNoAck) {
        continue;
      } else if (command === 'S' && guardianArmed) {
        /* The guardian owns the stopped child: S revokes exactly once and never
         * produces a second stopping frame, and the main loop's own
         * transport-cleanup-stopping frame is unreachable from here. */
        if (!guardianRevoked) { guardianRevoked = true; emitKeeper('stopping', { childReaped: true, cancelSent: true }); }
      } else if (command === 'S') {
        if (executor.appTransports.get(context.runId).cleanupOnly) emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-cleanup-stopping',
          runId: context.runId, environmentId: context.environmentId, keeperPID, keeperBirth: `${keeperPID}:000001`,
          childReaped: !!executor.appTransports.get(context.runId).stoppedIdentity, childAbsent: !executor.appTransports.get(context.runId).stoppedIdentity,
          scopeQuiescentObserved: true, persistentDenyObserved: true, ready: false, protected: false, ...cleanupStopping });
        else emitKeeper('stopping');
      }
      else if (command === 'R' && guardianArmed) {
        /* The guardian re-verifies reap, denial and scope, then emits its own
         * released frame before the transport one. An unrevoked guardian
         * revokes first, exactly as the fixed native side does. */
        if (!guardianRevoked) { guardianRevoked = true; emitKeeper('stopping', { childReaped: true, cancelSent: true }); continue; }
        if (refusedReleases < refuseReleases) { refusedReleases++; continue; }
        emitKeeper('released', { childReaped: true, persistentDenyObserved: true, scopeQuiescentObserved: true, stoppedBeforeExec: false });
        emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-released', runId: context.runId, environmentId: context.environmentId,
          keeperPID, ready: false, protected: false, ...Object.fromEntries(['coreReaped', 'frontReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified', 'privateJournalRetired'].map(key => [key, true])),
          childReaped: true, childAbsent: false, ...cleanupRelease });
        setImmediate(() => child.emit('close', 0, null));
      }
      else if (command === 'R') { emit({ schema: 'envara.macos-pf-app-transport/v1', event: 'transport-released', runId: context.runId, environmentId: context.environmentId,
        keeperPID, ready: false, protected: false, ...Object.fromEntries(['coreReaped', 'frontReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified', 'privateJournalRetired'].map(key => [key, true])),
        childReaped: executor.appTransports.get(context.runId).cleanupOnly ? !!executor.appTransports.get(context.runId).stoppedIdentity : true,
        childAbsent: executor.appTransports.get(context.runId).cleanupOnly ? !executor.appTransports.get(context.runId).stoppedIdentity : false, ...cleanupRelease }); setImmediate(() => child.emit('close', 0, null)); }
    }
  });
  return { executor, child, context, binding, emitKeeper, cleanupPending, emitCleanupPending: (attempt, changes) => emit(cleanupPending(attempt, changes)),
    preparationPending, emitPreparationPending: (command, attempt, changes) => emit(preparationPending(command, attempt, changes)),
    controlCommands, completeColdStage: () => completeColdStage() };
}
test('a one-shot keeper revocation emitted before the stop request still satisfies the later S', async t => {
  /* The fixed guardian records its reason once and returns for every later
   * lease byte, so an 'S' that follows an earlier revocation never produces a
   * second stopping frame. That buffered frame is the only proof the stop
   * happened, and dropping it is what produced a 15 s APPLICATION_APP_STOP_TIMEOUT
   * after a 45 s run. */
  const f = streamFixture({});
  await f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId, proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 });
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  await f.executor.applicationTransportControl(f.context.runId, 'B');
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.phase, 'resumed');
  /* The revocation lands while the run is live and no stop waiter exists. */
  f.emitKeeper('stopping', { childReaped: true, cancelSent: false, persistentDenyObserved: true });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(entry.waiters.length, 0);
  assert.equal(entry.events.filter(event => event.event === 'stopping').length, 1);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const stopping = await f.executor.applicationTransportControl(f.context.runId, 'S');
  assert.equal(stopping.event, 'stopping');
  assert.equal(entry.uncertain, false); assert.equal(entry.stoppingRequested, true);
  assert.equal(entry.cleanupWaitFailure, undefined);
});

test('replay is limited to the one-shot keeper stopping frame and never answers a release', () => {
  /* R is answered per request; replaying a buffered frame into it would
   * release PF custody on a transition the keeper never confirmed. The flag is
   * a call-site argument, so bind it at the source rather than by behaviour. */
  const source = readFileSync(new URL('../native/macos-pf-routing/controller.mjs', import.meta.url), 'utf8');
  assert.match(source, /entry\.wait = \(predicate, timeoutMs = 15000, timeoutCode = null, replay = false\)/);
  assert.match(source, /const captured = replay \? entry\.events\.find\(predicate\) : null;/);
  const start = source.indexOf('const waiting = expected ? entry.wait(');
  const end = source.indexOf('entry.child.stdin.write(', start);
  assert.ok(start > 0 && end > start, 'the control wait must remain a single call site');
  const call = source.slice(start, end);
  assert.match(call, /command === 'S' && \(!entry\.cleanupOnly \|\| guardianOnly\)\)/);
  assert.equal((call.match(/,\s*true\s*\)/g) ?? []).length, 0, 'no command may pass the replay flag unconditionally');
});

test('a run whose launch authority is burned while the guardian holds the child can still stop and release', async () => {
  /* This is the failure that required root recovery. A bound keeper refusal
   * while the guardian is armed latches cleanup-only, but the cleanup-only S
   * waited for transport-cleanup-stopping, which only the native main loop
   * emits -- and that loop is blocked inside the guardian. The wait could not
   * be satisfied by any native behaviour, so S timed out, the channel was
   * poisoned, and the run was left holding PF, the utun and its credential
   * group. S must instead be satisfied by the guardian's own stopping frame,
   * and R by its own released frame. */
  const f = streamFixture({ revokeAfterResume: true });
  await f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId, proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 });
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  await f.executor.applicationTransportControl(f.context.runId, 'B');
  const entry = f.executor.appTransports.get(f.context.runId);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(entry.guardianArmed, true, 'the L ACK binds the guardian');
  assert.equal(entry.applicationEnded?.childReaped, true, 'the revocation is recorded, not silently buffered');
  /* Cleanup-only is latched the way a burned launch authority latches it. */
  entry.cleanupOnly = true;
  const stopping = await f.executor.applicationTransportControl(f.context.runId, 'S');
  assert.equal(stopping.event, 'stopping');
  assert.equal(entry.uncertain, false, 'S must not poison the channel');
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.event, 'transport-released');
  assert.equal(entry.guardianReleased, true, 'the guardian released the child itself');
  assert.equal(entry.uncertain, false);
});

test('actual persistent transport parser binds exec or one verified launchctl fork, then waits for a new stop frame and confirmed outer exit', async () => {
  for (const forked of [false, true]) {
    const f = streamFixture({ forked });
    const started = await f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId, proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 });
    assert.equal(started.ownsOriginalListenerFD, true);
    const stopped = await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()); assert.equal(stopped.event, 'stopped');
    const stopping = await f.executor.applicationTransportControl(f.context.runId, 'S'); assert.equal(stopping.event, 'stopping');
    await f.executor.applicationTransportControl(f.context.runId, 'R'); assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  }
});
test('a release refused while the application family is still leaving is asked again until it is confirmed', async () => {
  /* On a real stop the guardian kills only the main process, and the release
   * it was asked for at once was refused while the helpers were still in the
   * owned group. Asked only once, the run waited out its deadline and the
   * timeout stranded the guardian with no way to receive another request. */
  const f = streamFixture({ refuseReleases: 3 });
  await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'S')).event, 'stopping');
  const startedAt = Date.now();
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.event, 'transport-released');
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.guardianReleased, true); assert.equal(entry.uncertain, false);
  assert.equal(f.controlCommands.filter(command => command === 'R').length, 4, 'three refusals, then the release');
  assert.ok(Date.now() - startedAt < 4 * PF_APP_RELEASE_RETRY_MS + 1000);
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
});
test('release requests stop once their bounded wait ends, and never continue after it', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'] });
  const f = streamFixture({ refuseReleases: Infinity });
  await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  await f.executor.applicationTransportControl(f.context.runId, 'S');
  const release = f.executor.applicationTransportControl(f.context.runId, 'R');
  release.catch(() => {});
  await new Promise(resolve => setImmediate(resolve));
  for (let elapsed = 0; elapsed < 15000; elapsed += PF_APP_RELEASE_RETRY_MS) {
    t.mock.timers.tick(PF_APP_RELEASE_RETRY_MS); await new Promise(resolve => setImmediate(resolve));
  }
  await assert.rejects(release, { code: 'APPLICATION_APP_RELEASE_TIMEOUT' });
  const sent = f.controlCommands.filter(command => command === 'R').length;
  assert.ok(sent > 1, 'the request was repeated within the wait');
  t.mock.timers.tick(10 * PF_APP_RELEASE_RETRY_MS); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.controlCommands.filter(command => command === 'R').length, sent, 'nothing is sent after the wait ended');
});
const progressFrame = (f, changes = {}) => ({ schema: 'envara.macos-pf-app-transport/v1', event: 'stage-progress', runId: f.context.runId,
  environmentId: f.context.environmentId, step: 'stage-plan', stepMs: 5, totalMs: 9, fullChecks: 0, identityChecks: 4, ready: false, protected: false, ...changes });
test('native stage-progress frames are recorded as bounded diagnostics and never settle the stage', async () => {
  const steps = ['front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'ticket-claim', 'stage-fresh', 'data-prepare', 'stage-plan',
    'keychain-begin', 'keychain-scoped', 'keychain-normal', 'keychain-stage-ready', 'keychain-select', 'keychain-published',
    'keychain-stage-cleaned', 'keychain-verify', 'keychain-host-verify', 'keychain-complete',
    'stage-recheck', 'stage-spawn', 'stage-stopped', 'stage-adopt'];
  const f = streamFixture({ stageProgress: steps.map((step, index) => ({ step, stepMs: index, totalMs: index * 2 })) });
  await startStream(f);
  const stopped = await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  assert.equal(stopped.event, 'stopped');
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, false); assert.equal(entry.phase, 'stopped');
  const timings = projectStageProgress(entry.stageProgress);
  assert.deepEqual(timings.map(item => item.step), steps);
  for (const item of timings) {
    assert.deepEqual(Object.keys(item).sort(), ['fullChecks', 'identityChecks', 'receivedMs', 'step', 'stepMs', 'totalMs']);
    assert.ok(Number.isSafeInteger(item.receivedMs) && item.receivedMs >= 0);
  }
  assert.equal(entry.events.some(event => event.event === 'stage-progress'), false, 'diagnostics are not replayable keeper events');
  await f.executor.applicationTransportControl(f.context.runId, 'S');
  await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
});
test('all fixed native diagnostic names cross the controller in bounded batches', async () => {
  const enumeration = readFileSync(new URL('../native/macos-pf-routing/gui-launch.h', import.meta.url), 'utf8')
    .match(/enum envara_gui_step \{([^}]+)\}/s)[1];
  const steps = [...enumeration.matchAll(/ENVARA_GUI_STEP_([A-Z_]+)/g)]
    .map(match => match[1]).filter(name => name !== 'COUNT').map(name => name.toLowerCase().replaceAll('_', '-'));
  assert.equal(steps.length, 81);
  for (let offset = 0; offset < steps.length; offset += APP_STAGE_PROGRESS_LIMIT) {
    const batch = steps.slice(offset, offset + APP_STAGE_PROGRESS_LIMIT);
    const f = streamFixture({ stageProgress: batch.map(step => ({ step })) });
    await startStream(f);
    assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID())).event, 'stopped');
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, false);
    assert.deepEqual(projectStageProgress(entry.stageProgress).map(item => item.step), batch);
    await f.executor.applicationTransportControl(f.context.runId, 'S');
    await f.executor.applicationTransportControl(f.context.runId, 'R');
    assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  }
});
test('stage-progress frames beyond the bound are dropped, while malformed or pre-launch ones are unknown output', async () => {
  const many = streamFixture({ stageProgress: Array.from({ length: APP_STAGE_PROGRESS_LIMIT + 4 }, () => ({})) });
  await startStream(many);
  assert.equal((await many.executor.applicationTransportControl(many.context.runId, 'L', randomUUID())).event, 'stopped');
  assert.equal(many.executor.appTransports.get(many.context.runId).stageProgress.length, APP_STAGE_PROGRESS_LIMIT);
  assert.equal(many.executor.appTransports.get(many.context.runId).uncertain, false);
  for (const changes of [{ step: 'arbitrary-step' }, { stepMs: 30, totalMs: 20 }, { stepMs: -1 }, { fullChecks: 70000 }, { extra: true },
    { identityChecks: 1.5 }, { totalMs: 86400001 }]) {
    const frame = progressFrame({ context: lease() }, changes);
    const f = streamFixture({ coldStageNoAck: true });
    await startStream(f);
    frame.runId = f.context.runId; frame.environmentId = f.context.environmentId;
    const control = f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    f.child.stdout.write(`${JSON.stringify(frame)}\n`);
    await assert.rejects(control);
    assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true, JSON.stringify(changes));
  }
  const early = streamFixture();
  await startStream(early);
  early.child.stdout.write(`${JSON.stringify(progressFrame(early))}\n`);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(early.executor.appTransports.get(early.context.runId).uncertain, true, 'no step can precede the launch command');
});
test('a fixed Keychain failure timing cannot settle launch or grant cleanup authority', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'] });
  const f = streamFixture({ coldStageDelay: 1000, stageProgress: [{ step: 'keychain-helper-set-default', stepMs: 1, totalMs: 2 }] });
  await startStream(f);
  let settled = false;
  const launch = f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  launch.then(() => { settled = true; }, () => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(settled, false);
  assert.equal(Boolean(entry.stoppedIdentity), false);
  assert.equal(entry.uncertain, false);
  assert.equal(entry.events.some(event => event.event === 'stage-progress'), false);
  assert.deepEqual(projectStageProgress(entry.stageProgress).map(item => item.step), ['keychain-helper-set-default']);
  t.mock.timers.tick(1000);
  assert.equal((await launch).event, 'stopped', 'only the subsequent original stopped frame settles L');
  await f.executor.applicationTransportControl(f.context.runId, 'S');
  await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
});
test('late stage-progress after the stage timeout is kept for diagnosis and leaves the cleanup-only channel intact', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageDelay: 61000 }), { entry } = await expireColdStage(t, f);
  f.child.stdout.write(`${JSON.stringify(progressFrame(f, { step: 'data-prepare', stepMs: 61000, totalMs: 61000 }))}\n`);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true);
  assert.deepEqual(projectStageProgress(entry.stageProgress).map(item => item.step), ['data-prepare']);
  t.mock.timers.tick(1000);
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'S')).event, 'stopping');
  await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT');
});
test('a signed cold stage completing after the former 15-second deadline remains bound and accepted', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageDelay: 44000 });
  await f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId, proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 });
  const control = f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(15001);
  assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, false);
  t.mock.timers.tick(28999);
  assert.equal((await control).event, 'stopped');
  assert.equal(f.executor.appTransports.get(f.context.runId).phase, 'stopped');
  await f.executor.applicationTransportControl(f.context.runId, 'S');
  await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
});
async function expireColdStage(t, f) {
  await startStream(f);
  const ticketId = randomUUID(), control = f.executor.applicationTransportControl(f.context.runId, 'L', ticketId);
  const refused = assert.rejects(control, { code: 'APPLICATION_APP_STAGE_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(60000); await refused;
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.cleanupOnly, true); assert.equal(entry.stageTimedOut, true); assert.equal(entry.stageOutcomePending, true);
  assert.equal(entry.uncertain, false); assert.notEqual(entry.phase, 'stopped');
  assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.cleanupWaitFailure, undefined);
  assert.equal(f.child.stdin.writableEnded, false); assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), true);
  for (const command of ['L', 'B', 'K']) await assert.rejects(f.executor.applicationTransportControl(f.context.runId, command, randomUUID()));
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`], 'a timed-out stage can never receive a second launch, resume or heartbeat');
  return { entry, ticketId };
}
for (const stoppedBeforeStop of [true, false]) test(`a late bound stopped frame ${stoppedBeforeStop ? 'before' : 'during'} cleanup permits only guardian stop and release`, async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageDelay: 61000 }), { entry, ticketId } = await expireColdStage(t, f);
  let stopping;
  if (!stoppedBeforeStop) {
    stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(f.controlCommands, [`L ${ticketId}`], 'S waits for the native state before choosing its reachable stop proof');
  }
  t.mock.timers.tick(1000);
  if (stoppedBeforeStop) {
    assert.equal(entry.stageOutcomePending, false); assert.equal(entry.guardianArmed, true);
    assert.deepEqual(entry.stoppedIdentity, { pid: 8994, birth: '8994:000001' });
    assert.notEqual(entry.phase, 'stopped', 'a late ACK supplies cleanup identity, never launch success');
    stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
  }
  assert.equal((await stopping).event, 'stopping');
  assert.equal(entry.stageOutcomePending, false); assert.equal(entry.guardianArmed, true);
  assert.deepEqual(entry.stoppedIdentity, { pid: 8994, birth: '8994:000001' });
  assert.equal(entry.cleanupOnly, true); assert.equal(entry.uncertain, false);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.childReaped, true); assert.equal(released.childAbsent, false); assert.equal(entry.guardianReleased, true);
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.cleanupWaitFailure, undefined);
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`, 'S', 'R']);
});
test('a bound late stage refusal during cleanup resolves the main-loop stop path without replacing the original timeout', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const native = { stage: 'guardian', reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13 };
  const f = streamFixture({ coldStageDelay: 61000, coldStageRefusal: native }), { entry, ticketId } = await expireColdStage(t, f);
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`]);
  t.mock.timers.tick(1000);
  const stopped = await stopping;
  assert.equal(stopped.event, 'transport-cleanup-stopping'); assert.equal(stopped.childAbsent, true); assert.equal(stopped.childReaped, false);
  assert.equal(entry.stageOutcomePending, false); assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
  assert.deepEqual(entry.failure, native); assert.equal(entry.cleanupFailure, undefined);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.cleanupWaitFailure, undefined);
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.childAbsent, true); assert.equal(released.childReaped, false);
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`, 'S', 'R']);
});
test('repeated no-ACK cleanup-state waits stay bounded and retryable until an exact late outcome permits cleanup', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageNoAck: true }), { entry, ticketId } = await expireColdStage(t, f);
  for (let attempt = 0; attempt < 2; attempt++) {
    const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
    const refused = assert.rejects(stopping, { code: 'APPLICATION_APP_STOP_TIMEOUT' });
    await new Promise(resolve => setImmediate(resolve));
    t.mock.timers.tick(PF_APP_STAGE_CLEANUP_WAIT_MS - 1);
    assert.equal(entry.uncertain, false); assert.deepEqual(f.controlCommands, [`L ${ticketId}`]);
    t.mock.timers.tick(1); await refused;
    assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true); assert.equal(entry.stageOutcomePending, true);
    assert.equal(f.child.stdin.writableEnded, false); assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), true);
    assert.equal(entry.waiters.length, 0); assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT');
    assert.equal(entry.cleanupWaitFailure, 'APPLICATION_APP_STOP_TIMEOUT'); assert.equal(entry.stoppedIdentity, undefined);
    assert.equal(entry.events.some(event => ['transport-cleanup-stopping', 'transport-released'].includes(event.event)), false);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
    await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
    assert.deepEqual(f.controlCommands, [`L ${ticketId}`], 'no cleanup command or false proof exists before the native stage outcome');
  }
  f.completeColdStage();
  assert.equal(entry.stageOutcomePending, false); assert.deepEqual(entry.stoppedIdentity, { pid: 8994, birth: '8994:000001' });
  assert.notEqual(entry.phase, 'stopped'); await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'S')).event, 'stopping');
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'R')).childReaped, true);
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`, 'S', 'R']);
});
test('an actual S ACK timeout still poisons after the late stopped frame established guardian custody', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageNoAck: true, stopNoAck: true }), { entry, ticketId } = await expireColdStage(t, f);
  f.completeColdStage();
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
  const refused = assert.rejects(stopping, { code: 'APPLICATION_APP_STOP_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`, 'S']);
  t.mock.timers.tick(15000); await refused;
  assert.equal(entry.uncertain, true); assert.equal(entry.phase, 'recovery-required'); assert.equal(f.child.stdin.writableEnded, true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.cleanupWaitFailure, 'APPLICATION_APP_STOP_TIMEOUT');
  assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), false);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
});
for (const [name, changes] of [
  ['foreign run', { runId: randomUUID() }], ['foreign environment', { environmentId: randomUUID() }], ['foreign ticket', { ticketId: randomUUID() }],
  ['foreign registration', { registrationId: randomUUID() }], ['foreign version', { versionId: randomUUID() }], ['foreign keeper', { keeperPID: 8888 }],
  ['invalid child PID', { pid: 1 }], ['invalid child birth', { birth: 'invalid' }], ['unknown profile', { profile: 'unknown' }],
  ['unknown field', { callerProof: true }], ['non-Boolean proof', { stoppedBeforeExec: 1 }], ['no stopped child', { stoppedBeforeExec: false }],
  ['denial absent', { persistentDenyObserved: false }], ['already reaped child', { childReaped: true }], ['resume sent', { resumeSent: true }],
  ['already resumed', { resumed: true }], ['cancel sent', { cancelSent: true }], ['executed identity', { executedIdentityVerified: true }],
  ['unexpected resume', { event: 'resumed' }], ['unexpected release', { event: 'released' }], ['unbound stopping event', { event: 'stopping' }],
]) test(`a late stopped frame with ${name} poisons instead of enabling cleanup authority`, async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageDelay: 61000, coldStageStoppedChanges: changes }), { entry } = await expireColdStage(t, f);
  t.mock.timers.tick(1000);
  assert.equal(entry.uncertain, true); assert.equal(entry.phase, 'recovery-required'); assert.equal(f.child.stdin.writableEnded, true);
  assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT');
  for (const command of ['B', 'S', 'R']) await assert.rejects(f.executor.applicationTransportControl(f.context.runId, command));
});
for (const changes of [{ runId: randomUUID() }, { stage: 'preflight' }, { error: true }, { extra: 'unknown' }]) test(`a malformed or foreign late stage refusal cannot preserve cleanup (${JSON.stringify(changes)})`, async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageDelay: 61000, coldStageRefusal: changes }), { entry } = await expireColdStage(t, f);
  t.mock.timers.tick(1000);
  assert.equal(entry.uncertain, true); assert.equal(entry.failure, undefined); assert.equal(entry.cleanupFailure, undefined);
  assert.equal(f.child.stdin.writableEnded, true); assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT');
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
});
test('malformed output while awaiting the late stage outcome closes the channel without claiming cleanup', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ coldStageNoAck: true }), { entry, ticketId } = await expireColdStage(t, f);
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
  const refused = assert.rejects(stopping);
  await new Promise(resolve => setImmediate(resolve));
  f.child.stdout.write('{malformed-json}\n'); await refused;
  assert.equal(entry.uncertain, true); assert.equal(f.child.stdin.writableEnded, true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.stoppedIdentity, undefined);
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`]);
  await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
});
for (const outcome of ['stopped', 'refused']) test(`an overdue L ${outcome} frame observed before the timer fires preserves the stage timeout and exact cleanup path`, async t => {
  let now = Date.now(); t.mock.method(Date, 'now', () => now);
  const native = { stage: 'guardian', reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13 };
  const f = streamFixture({ coldStageNoAck: true, ...(outcome === 'refused' ? { coldStageRefusal: native } : {}) });
  await startStream(f);
  const ticketId = randomUUID(), control = f.executor.applicationTransportControl(f.context.runId, 'L', ticketId);
  const refused = assert.rejects(control, { code: 'APPLICATION_APP_STAGE_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.stageTimedOut, undefined);
  // Move wall-clock evidence past the bound without letting the real timer run.
  now += 60001; f.completeColdStage(); await refused;
  assert.equal(entry.stageTimedOut, true); assert.equal(entry.stageOutcomePending, false);
  assert.equal(entry.cleanupOnly, true); assert.equal(entry.uncertain, false); assert.notEqual(entry.phase, 'stopped');
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.cleanupFailure, undefined);
  if (outcome === 'stopped') assert.deepEqual(entry.stoppedIdentity, { pid: 8994, birth: '8994:000001' });
  else { assert.equal(entry.stoppedIdentity, undefined); assert.deepEqual(entry.failure, native); }
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
  const stopped = await f.executor.applicationTransportControl(f.context.runId, 'S');
  assert.equal(stopped.event, outcome === 'stopped' ? 'stopping' : 'transport-cleanup-stopping');
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.childReaped, outcome === 'stopped'); assert.equal(released.childAbsent, outcome === 'refused');
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`, 'S', 'R']);
});
for (const [name, changes] of [
  ['foreign registration', { registrationId: randomUUID() }], ['foreign version', { versionId: randomUUID() }],
  ['foreign keeper', { keeperPID: 8888 }], ['invalid child PID', { pid: 1 }],
]) test(`an overdue L frame with ${name} poisons even when its timer has not fired`, async t => {
  let now = Date.now(); t.mock.method(Date, 'now', () => now);
  const f = streamFixture({ coldStageNoAck: true, coldStageStoppedChanges: changes }); await startStream(f);
  const control = f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  const refused = assert.rejects(control, { code: 'APPLICATION_APP_STAGE_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  now += 60001; f.completeColdStage(); await refused;
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, true); assert.equal(entry.phase, 'recovery-required'); assert.equal(f.child.stdin.writableEnded, true);
  assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), false);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
});
test('a late stage outcome after the cleanup-state deadline but before its timer fires helps only a later explicit Stop', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let now = Date.now(); t.mock.method(Date, 'now', () => now);
  const f = streamFixture({ coldStageNoAck: true }); await startStream(f);
  const ticketId = randomUUID(), launch = f.executor.applicationTransportControl(f.context.runId, 'L', ticketId);
  const launchRefused = assert.rejects(launch, { code: 'APPLICATION_APP_STAGE_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  now += 60000; t.mock.timers.tick(60000); await launchRefused;
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
  const stopRefused = assert.rejects(stopping, { code: 'APPLICATION_APP_STOP_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  now += PF_APP_STAGE_CLEANUP_WAIT_MS + 1; f.completeColdStage(); await stopRefused;
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true); assert.equal(entry.stageOutcomePending, false);
  assert.equal(entry.guardianArmed, true); assert.equal(f.child.stdin.writableEnded, false); assert.equal(entry.waiters.length, 0);
  assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT'); assert.equal(entry.cleanupWaitFailure, 'APPLICATION_APP_STOP_TIMEOUT');
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`], 'the expired Stop request cannot turn a late outcome into a sent S command');
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'S')).event, 'stopping');
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'R')).childReaped, true);
  assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.deepEqual(f.controlCommands, [`L ${ticketId}`, 'S', 'R']);
});
for (const fault of ['wrongParent', 'malformed', 'missingListener']) test(`actual native transport ${fault} poisons without sending a cold-stage ticket`, async () => {
  const f = streamFixture({ [fault]: true });
  await assert.rejects(f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId, proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 }), { code: 'APPLICATION_APP_TRANSPORT_UNCONFIRMED' });
  assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID())); assert.equal(f.child.stdin.writableEnded, true);
});
test('signed resume verification may exceed 15 seconds while retaining its bound child identity', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ resumeDelay: 32000 }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  const resumed = f.executor.applicationTransportControl(f.context.runId, 'B');
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(15001); assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, false);
  t.mock.timers.tick(16999);
  const event = await resumed; assert.equal(event.event, 'resumed'); assert.equal(event.birth, '8994:000001');
  assert.equal(f.executor.appTransports.get(f.context.runId).phase, 'resumed');
});
test('expired resume verification cannot accept a late ACK or send another resume', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ resumeDelay: 46000 }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  const resumed = f.executor.applicationTransportControl(f.context.runId, 'B');
  const refused = assert.rejects(resumed, { code: 'APPLICATION_APP_RESUME_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(45000); await refused; t.mock.timers.tick(1000);
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, true); assert.notEqual(entry.phase, 'resumed');
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
  assert.equal(f.child.stdin.writableEnded, true);
});
test('a bound keeper revocation before resume prevents B without treating its report as cleanup', async () => {
  const f = streamFixture(); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  f.emitKeeper('stopping', { childReaped: true, scopeQuiescentObserved: true });
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'), { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true);
  assert.equal(f.controlCommands.includes('B'), false); assert.equal(f.child.stdin.writableEnded, false);
  assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), true);
  await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
});
test('a keeper revocation during resume preflight is retained before the B waiter or write exists', async () => {
  const f = streamFixture(); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  const identify = f.executor.identify; let entered, release;
  const identifying = new Promise(resolve => { entered = resolve; }), held = new Promise(resolve => { release = resolve; });
  f.executor.identify = async pid => { entered(); await held; return identify(pid); };
  const resume = f.executor.applicationTransportControl(f.context.runId, 'B');
  const refused = assert.rejects(resume, { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
  await identifying; f.emitKeeper('stopping'); release(); await refused;
  assert.equal(f.controlCommands.includes('B'), false);
  assert.equal(f.executor.appTransports.get(f.context.runId).waiters.length, 0);
  assert.equal(f.child.stdin.writableEnded, false);
});
test('exact negative keeper ACKs reject a pending B immediately and freeze out its late resumed frame', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  for (const event of ['stopping', 'released', 'release-refused']) {
    const f = streamFixture({ resumeDelay: 1000 }); await startStream(f);
    await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    const resume = f.executor.applicationTransportControl(f.context.runId, 'B');
    const refused = assert.rejects(resume, { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
    await new Promise(resolve => setImmediate(resolve));
    f.emitKeeper(event, { resumeSent: true }); await refused;
    const entry = f.executor.appTransports.get(f.context.runId), before = structuredClone(entry.events);
    assert.equal(entry.waiters.length, 0); assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true);
    assert.equal(f.controlCommands.filter(command => command === 'B').length, 1);
    t.mock.timers.tick(1000);
    assert.deepEqual(entry.events, before); assert.equal(entry.events.some(value => value.event === 'resumed'), false);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'), { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
    assert.equal(f.child.stdin.writableEnded, false);
  }
});
test('a cold-profile run accepts its own keeper frames and reports its ended child, while a frame claiming another profile is still refused', async () => {
  /* The keeper profile gates used to accept only 'seatbelt-front-only' by name,
   * so a cold-profile application's own frames were treated as foreign: its
   * ended child was never reported and the run stayed 'running'. Binding to the
   * run's own profile fixes that without admitting a foreign frame. */
  const cold = streamFixture({ profile: 'cold' }); await startStream(cold);
  const coldEntry = cold.executor.appTransports.get(cold.context.runId);
  await cold.executor.applicationTransportControl(cold.context.runId, 'L', randomUUID());
  cold.emitKeeper('stopped'); await new Promise(resolve => setImmediate(resolve));
  assert.equal(coldEntry.uncertain, false, 'a cold run accepts its own stopped frame');
  const resumed = await cold.executor.applicationTransportControl(cold.context.runId, 'B');
  assert.equal(resumed.profile, 'cold');
  assert.equal(coldEntry.keeperProfile, 'cold', 'the resume ACK establishes the run profile');
  const ended = streamFixture({ profile: 'cold' }); await startStream(ended);
  await ended.executor.applicationTransportControl(ended.context.runId, 'L', randomUUID());
  ended.emitKeeper('stopped'); await new Promise(resolve => setImmediate(resolve));
  await ended.executor.applicationTransportControl(ended.context.runId, 'B');
  ended.emitKeeper('stopping');
  await new Promise(resolve => setImmediate(resolve));
  assert.notEqual(ended.executor.appTransports.get(ended.context.runId).applicationEnded, undefined,
    'a cold-profile application that ended on its own is reported as ended');
  /* A frame that claims a different profile than the run established is refused. */
  const foreign = streamFixture({ resumeDelay: 1000 }); await startStream(foreign);
  await foreign.executor.applicationTransportControl(foreign.context.runId, 'L', randomUUID());
  const refused = assert.rejects(foreign.executor.applicationTransportControl(foreign.context.runId, 'B'), { code: 'APPLICATION_APP_TRANSPORT_UNCONFIRMED' });
  assert.equal(foreign.executor.appTransports.get(foreign.context.runId).keeperProfile, 'seatbelt-front-only');
  await new Promise(resolve => setImmediate(resolve)); foreign.emitKeeper('stopping', { profile: 'cold' }); await refused;
  assert.equal(foreign.executor.appTransports.get(foreign.context.runId).uncertain, true);
});
test('foreign identities and malformed negative keeper reports poison without becoming a bound resume refusal', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  for (const change of [{ ticketId: randomUUID() }, { registrationId: randomUUID() }, { versionId: randomUUID() },
    { keeperPID: 8999 }, { pid: 8999 }, { birth: '8994:000002' }, { persistentDenyObserved: 1 }, { profile: 'cold' }, { extra: proxy.password }]) {
    const f = streamFixture({ resumeDelay: 1000 }); await startStream(f);
    await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    const resume = f.executor.applicationTransportControl(f.context.runId, 'B');
    const refused = assert.rejects(resume, { code: 'APPLICATION_APP_TRANSPORT_UNCONFIRMED' });
    await new Promise(resolve => setImmediate(resolve)); f.emitKeeper('stopping', change); await refused;
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.notEqual(entry.resumeRefused, true); assert.equal(entry.uncertain, true);
    assert.equal(JSON.stringify(entry.events).includes(proxy.password), false);
    t.mock.timers.tick(1000); assert.equal(entry.events.some(value => value.event === 'resumed'), false);
  }
});
test('fixed native failure stage and bounded errno propagate without admitting private text or a successful transport', async () => {
  for (const [edit, valid] of [[{}, true], [{ stage: '/private/path' }, false], [{ reason: proxy.password }, false], [{ error: true }, false], [{ error: 1025 }, false], [{ extra: 'private' }, false]]) {
    const f = streamFixture({ nativeRefusal: edit });
    await assert.rejects(f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId, proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 }), error => {
      assert.equal(error.code, valid ? 'APPLICATION_APP_NATIVE_REFUSED' : 'APPLICATION_APP_TRANSPORT_UNCONFIRMED');
      if (valid) assert.deepEqual(error.nativeFailure, { stage: 'front-handshake', reason: 'NATIVE_OPERATION_REFUSED', error: 35 });
      else assert.equal(error.nativeFailure, undefined); assert.ok(!JSON.stringify(error).includes(proxy.password)); return true;
    });
    assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true);
  }
});
test('bound post-start native refusal preserves fixed diagnostics while normal outer EOF cannot confirm cleanup', async () => {
  for (const command of ['L', 'S']) for (const stage of ['front-commit', 'front-admission', 'ticket-prepare', 'relay-fork', 'guardian']) {
    const f = streamFixture({ controlRefusal: { stage, error: 70 }, controlRefusalCommand: command });
    await startStream(f);
    if (command === 'S') await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, command, command === 'L' ? randomUUID() : null), error => {
      assert.equal(error.code, 'APPLICATION_APP_NATIVE_REFUSED');
      assert.deepEqual(error.nativeFailure, { stage, reason: 'NATIVE_OPERATION_REFUSED', error: 70 });
      assert.ok(!JSON.stringify(error).includes(proxy.password)); return true;
    });
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true); assert.equal(f.child.stdin.writableEnded, false);
    f.child.emit('close', 0, null);
    assert.equal(entry.uncertain, true); assert.equal(entry.abortReceipt, undefined); assert.equal(entry.preflightAbortReceipt, undefined);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
    await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
  }
});
test('post-start refusal rejects foreign bindings, invalid schemas and startup-only stages without importing diagnostics', async () => {
  for (const edit of [{ runId: randomUUID() }, { environmentId: randomUUID() }, { schema: 'envara.foreign/v1' },
    { stage: 'preflight' }, { stage: 'factory-open' }, { stage: 'front-handshake' }, { stage: '/private/path' },
    { reason: proxy.password }, { error: true }, { error: 1025 }, { extra: 'private' }]) {
    const f = streamFixture({ controlRefusal: edit }); await startStream(f);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()), error => {
      assert.equal(error.code, 'APPLICATION_APP_TRANSPORT_UNCONFIRMED'); assert.equal(error.nativeFailure, undefined);
      assert.ok(!JSON.stringify(error).includes(proxy.password)); return true;
    });
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, true); assert.equal(entry.failure, undefined); assert.equal(f.child.stdin.writableEnded, true);
  }
});
test('a native register refusal keeps errno13 and errno70, holds nothing, retires its route and blocks no later attach', async () => {
  for (const errno of [13, 70]) {
    const f = fixture(), route = await f.prepareRoute(), request = input(route.routeId);
    f.commands.register = async () => parseNativeApplicationEnvelope({ schema: 1, ok: false, error: errno, ready: false, protected: false,
      activatesSystem: false, applicationIdentityVerified: false, environmentLeaseVerified: false, ticketIssued: false,
      reason: 'NATIVE_APP_OPERATION_REFUSED', registrationId: '', versionId: '', ticketId: '', snapshotContentSHA256: '', privatePath: '/private/never-publish' }, {}, 'app-register');
    const refusal = await f.controller.prepareNotionApplication(request).then(() => null, error => error);
    assert.equal(refusal?.code, 'APPLICATION_NATIVE_REFUSED');
    // The diagnostic travels with the refusal itself, through the fixed RPC projection.
    const projected = projectPFHelperError(refusal), native = { stage: 'register', reason: 'NATIVE_APP_OPERATION_REFUSED', error: errno };
    assert.equal(projected.failureStage, 'register'); assert.deepEqual(projected.nativeFailure, native);
    assert.deepEqual(projected.initialFailure, { stage: 'register', code: 'APPLICATION_NATIVE_REFUSED', native });
    assert.ok(!JSON.stringify(projected).includes('never-publish'));
    // The registry holds no per-run resource: no run, no lock, and the route is gone.
    assert.equal(f.calls.includes('lock'), false);
    assert.throws(() => f.controller.applicationSnapshot({ runId: request.runId }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
    const status = await f.controller.status({ runId: request.runId });
    assert.deepEqual([status.routes.length, status.applications.length, status.runs.length], [0, 0, 0]);
    // A refused run id is never reused, and the next attach is admitted.
    f.commands.register = async value => { f.registry.state = 'current'; f.registry.versionId = value.versionId; return { ...value, applicationIdentityVerified: true }; };
    await assert.rejects(f.controller.prepareNotionApplication({ ...request, routeId: (await f.prepareRoute()).routeId }), { code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
    assert.equal((await f.controller.prepareNotionApplication(input((await f.prepareRoute()).routeId))).phase, 'staged');
    await f.controller.shutdown();
  }
});
test('one controller session admits a second attachment once the first is clean, and refuses a second beside a live one before touching anything', async () => {
  const f = fixture({ beginNextApplicationRun: () => { f.calls.push('next-run'); return true; } });
  const first = input((await f.prepareRoute()).routeId);
  assert.equal((await f.controller.prepareNotionApplication(first)).phase, 'staged');
  const besideRoute = await f.prepareRoute(), before = f.calls.length;
  await assert.rejects(f.controller.prepareNotionApplication(input(besideRoute.routeId)), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.deepEqual(f.calls.slice(before), []);
  const listed = await f.controller.status();
  assert.deepEqual(listed.routes.map(route => route.routeId), [first.routeId], 'the refused attempt retired only its own route');
  assert.deepEqual(listed.applications.map(run => run.runId), [first.runId]);
  assert.equal((await f.controller.stopNotionApplication({ runId: first.runId })).phase, 'cleaned');
  const second = input((await f.prepareRoute()).routeId), start = f.calls.length;
  assert.equal((await f.controller.prepareNotionApplication(second)).phase, 'staged');
  const calls = f.calls.slice(start);
  assert.ok(calls.indexOf('next-run') >= 0 && calls.indexOf('next-run') < calls.indexOf('lock'), 'the executor confirms the earlier run released before the lock');
  assert.equal((await f.controller.stopNotionApplication({ runId: second.runId })).phase, 'cleaned');
  await f.controller.shutdown();
});
test('register diagnostics refuse unknown reasons, unbounded or Boolean errno and never relabel other native commands', () => {
  const value = { schema: 1, ok: false, error: 13, ready: false, protected: false, activatesSystem: false,
    applicationIdentityVerified: false, environmentLeaseVerified: false, ticketIssued: false, reason: 'NATIVE_APP_OPERATION_REFUSED',
    registrationId: '', versionId: '', ticketId: '', snapshotContentSHA256: '' };
  for (const [change, command] of [[{ reason: 'PRIVATE_UNKNOWN' }, 'app-register'], [{ error: true }, 'app-register'], [{ error: 0 }, 'app-register'],
    [{ error: 1025 }, 'app-register'], [{}, 'app-plan']]) assert.throws(() => parseNativeApplicationEnvelope({ ...value, ...change }, {}, command), error => {
      assert.equal(error.code, 'APPLICATION_NATIVE_REFUSED'); assert.equal(error.nativeFailure, undefined); assert.ok(!JSON.stringify(error).includes('PRIVATE_UNKNOWN')); return true;
    });
});
const startStream = f => f.executor.startApplicationTransport({ runId: f.context.runId, environmentId: f.context.environmentId,
  proxy, udpPolicy: 'block', leaseSHA256: 'a'.repeat(64), consoleUID: 501 });
test('factory refusal waits for fragmented/coalesced exact abort and actual exit1; neither direct nor launchctl keeper is queried after exit', async () => {
  for (const forked of [false, true]) {
    const f = streamFixture({ forked, abort: {}, fragmentAbort: forked });
    const identify = f.executor.identify, observed = [];
    f.executor.identify = async pid => { observed.push(pid); if (observed.length > 1) throw new Error('already exited'); return identify(pid); };
    await assert.rejects(startStream(f), error => error.code === 'APPLICATION_APP_NATIVE_REFUSED' && error.prestageAborted === true);
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.phase, 'prestage-aborted'); assert.equal(entry.uncertain, false); assert.equal(entry.exitCode, 1); assert.equal(entry.exitSignal, null);
    const proof = await f.executor.confirmApplicationPrestageAborted(f.context.runId);
    assert.equal(proof.transportExitConfirmed, true); assert.equal(proof.filterJournalAbsent, true);
    assert.equal(proof.childReaped, undefined); assert.deepEqual(observed, [f.child.pid]);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()));
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
    await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
  }
});
for (const [name, change, options] of [
  ['wrong environment', { environmentId: randomUUID() }], ['wrong lease', { leaseSHA256: 'b'.repeat(64) }], ['wrong realm', { realmId: randomUUID() }],
  ['wrong group', { gid: 7101 }], ['wrong held lease inode', { leaseInode: '7' }], ['wrong held directory', { runDirectoryDevice: '7' }],
  ['wrong controller birth', { controllerBirth: '999:000001' }], ['wrong keeper birth', { keeperBirth: '999:000001' }],
  ['wrong parent', { keeperParentPID: 7777 }], ['wrong parent birth', { keeperParentBirth: '999:000001' }],
  ['duplicate child identity', { corePID: 8990 }], ['false complete scope', { gidScopeAbsent: false }], ['numeric truth', { coreReaped: 1 }],
  ['filter written', { filterWriteAttempted: true }], ['deny attempted', { denyAttempted: true }], ['launch accepted', { launchCommandAccepted: true }],
  ['cold attempted', { coldStageAttempted: true }], ['private extras', { secret: 'never-report' }], ['invalid decimal', { listenerInode: '01' }],
  ['wrong original interface', { utunName: 'en0' }], ['wrong original listener', { listenerHost: '0.0.0.0' }],
  ['missing true field', { originalListenerVerified: undefined }], ['missing false field', { coldStageAttempted: undefined }],
  ['overflow identity', { listenerDevice: '18446744073709551616' }], ['wrong declared exit', { exitStatus: 0 }],
  ['exit1 without terminal', {}, { omitAbort: true }], ['terminal without initial refusal', {}, { omitRefusal: true }],
  ['normal exit is not abort proof', {}, { abortExit: 0 }], ['signal is not abort proof', {}, { abortExit: null, abortSignal: 'SIGTERM' }],
  ['partial output is not empty', {}, { abortTrailing: '{' }], ['late abort after poisoned stage', {}, { refusalStage: 'deny-commit' }],
]) test(`prestage abort rejects ${name} without normal cleanup or cold commands`, async () => {
  const f = streamFixture({ abort: change, ...options });
  await assert.rejects(startStream(f)); const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, true); await assert.rejects(f.executor.confirmApplicationPrestageAborted(f.context.runId));
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()));
});
test('accepted abort cannot survive changed held context or a newly appeared private journal', async () => {
  for (const tamper of ['context', 'journal']) {
    const f = streamFixture({ abort: {} }); await assert.rejects(startStream(f), { prestageAborted: true });
    if (tamper === 'context') f.executor.applicationTransportBinding = async () => ({ ...f.binding, runDirectoryInode: '9' });
    else f.executor.fs.lstat = async () => ({ isDirectory: () => true });
    await assert.rejects(f.executor.confirmApplicationPrestageAborted(f.context.runId));
  }
});
function abortControllerFixture() {
  const f = fixture();
  f.executor.startApplicationTransport = async () => { f.calls.push('transport'); throw Object.assign(new Error(), { code: 'APPLICATION_APP_NATIVE_REFUSED', prestageAborted: true,
    nativeFailure: { stage: 'factory-open', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } }); };
  f.executor.confirmApplicationPrestageAborted = async () => {
    f.calls.push('confirm-abort'); const sealed = f.executor.sealed;
    return { schema: 'envara.macos-pf-app-transport/v1', event: 'prestage-aborted', stage: 'factory-open', runId: sealed.runId,
      environmentId: sealed.environmentId, realmId: sealed.realmId, gid: sealed.gid, leaseSHA256: 'a'.repeat(64), exitStatus: 1,
      ...Object.fromEntries(['originalUTunVerified', 'originalListenerVerified', 'coreReaped', 'frontReaped', 'gidScopeAbsent', 'filterJournalAbsent', 'originalUTunClosed', 'originalListenerClosed', 'transportExitConfirmed'].map(key => [key, true])),
      ...Object.fromEntries(['denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted', 'ready', 'protected'].map(key => [key, false])) };
  };
  return f;
}
test('proven factory abort cleans only owned reference/issued lease/groups/context and preserves the original launch error and independent schema', async () => {
  const f = abortControllerFixture(), route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), { code: 'APPLICATION_APP_NATIVE_REFUSED' });
  const aborted = f.controller.applicationSnapshot({ runId: request.runId });
  assert.equal(aborted.phase, 'prestage-aborted'); assert.equal(aborted.cleanupUncertain, false); assert.equal(aborted.cleanupComplete, false);
  assert.equal(aborted.staged, false); assert.equal(aborted.resumed, false); assert.equal(aborted.prestageAborted, true);
  const start = f.calls.length, clean = await f.controller.stopNotionApplication({ runId: request.runId });
  assert.deepEqual(f.calls.slice(start).filter(value => value !== 'persist'), ['confirm-abort', 'process-absence', 'release-reference', 'remove-hook', 'remove-groups', 'network-snapshot', 'retire-lease', 'unlock']);
  assert.equal(clean.phase, 'prestage-cleaned'); assert.equal(clean.cleanupComplete, true); assert.equal(clean.failure.code, 'APPLICATION_APP_NATIVE_REFUSED');
  assert.equal(clean.cleanupEvidence.schema, 'envara.macos-pf-notion-prestage-cleanup/v1');
  assert.equal(clean.cleanupEvidence.nativeGIDScopeAbsentBeforeExit, true); assert.equal(clean.cleanupEvidence.ownedEffectiveGIDProcessesAbsentAtCleanup, true);
  for (const key of ['childReaped', 'privateJournalRetired', 'ownedGIDProcessesAbsent']) assert.equal(clean.cleanupEvidence[key], undefined);
  for (const key of ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted']) assert.equal(clean.cleanupEvidence[key], false);
  assert.equal(f.calls.some(value => value.startsWith('control:')), false);
  assert.deepEqual(await f.controller.stopNotionApplication({ runId: request.runId }), clean); assert.equal((await f.controller.shutdown()).cleanupRequired, false);
  assert.ok(!JSON.stringify(clean).includes('leaseSHA256') && !JSON.stringify(clean).includes('rootHookLease'));
});
test('an untrusted abort flag and every failed fresh cleanup step retain sealed state rather than erase the original failure', async () => {
  for (const failed of ['confirmApplicationPrestageAborted', 'persistRun', 'assertNoOwnedGroupProcesses', 'releaseOwnedReference', 'removeOwnedRootHook', 'removeGroups', 'retireApplicationLease', 'releaseLock']) {
    const f = abortControllerFixture(), route = await f.prepareRoute(), request = input(route.routeId);
    await assert.rejects(f.controller.prepareNotionApplication(request));
    f.executor[failed] = async () => { throw new Error('private detail'); };
    await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    const state = f.controller.applicationSnapshot({ runId: request.runId });
    assert.equal(state.cleanupComplete, false); assert.equal(state.cleanupUncertain, true); assert.equal(state.cleanupEvidence, null);
    assert.equal(state.failure.code, 'APPLICATION_APP_NATIVE_REFUSED'); assert.equal((await f.controller.shutdown()).cleanupRequired, true);
  }
  const f = abortControllerFixture(), route = await f.prepareRoute(); f.executor.confirmApplicationPrestageAborted = async () => ({ transportExitConfirmed: true });
  const request = input(route.routeId); await assert.rejects(f.controller.prepareNotionApplication(request));
  assert.equal(f.controller.applicationSnapshot({ runId: request.runId }).cleanupUncertain, true);
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId })); assert.ok(!f.calls.includes('release-reference'));
  await f.controller.shutdown();
});
test('fresh effective-GID cleanup refuses nonempty malformed ps records and matching owned groups', async () => {
  const executor = new MacOSPFExecutor(), realms = [{ gid: 7100 }];
  for (const output of ['broken-row\n', '12 0 7100\n', '12 true 20\n', '0 0 20\n', '999999999999999999999 0 20\n']) {
    executor.command = async () => ({ stdout: output }); await assert.rejects(executor.assertNoOwnedGroupProcesses(realms));
  }
  executor.command = async () => ({ stdout: ' 12 0 20\n\n13 501 20\n' }); assert.equal(await executor.assertNoOwnedGroupProcesses(realms), true);
});
test('preflight terminal binds the direct native child, full sealed identity and fixed executable metadata without inventing transport resources', async () => {
  for (const [preflightBeforeIdentity, unavailableIdentity] of [[false, false], [true, false], [true, true]]) {
    const f = streamFixture({ preflightAbort: {}, preflightBeforeIdentity, unavailableIdentity, fragmentAbort: preflightBeforeIdentity });
    await assert.rejects(startStream(f), error => error.code === 'APPLICATION_APP_NATIVE_REFUSED' && error.preflightAborted === true);
    const entry = f.executor.appTransports.get(f.context.runId), proof = await f.executor.confirmApplicationPreflightAborted(f.context.runId);
    assert.equal(entry.phase, 'preflight-aborted'); assert.equal(entry.uncertain, false); assert.equal(entry.exitCode, 1); assert.equal(entry.exitSignal, null);
    assert.equal(proof.transportExitConfirmed, true); assert.equal(Object.keys(f.executor.expectedPreflightAbort).length, 35);
    assert.equal(proof.privateChildrenAbsent, true); assert.equal(proof.ownedFilterClassesEmpty, true); assert.equal(proof.bootstrapPID, f.child.pid);
    for (const field of ['childReaped', 'coreReaped', 'frontReaped', 'originalUTunClosed', 'originalListenerClosed']) assert.equal(proof[field], undefined);
    await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
    await assert.rejects(f.executor.confirmApplicationPrestageAborted(f.context.runId));
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()));
  }
});
for (const [name, edit, options] of [
  ['another environment', { environmentId: randomUUID() }], ['another realm', { realmId: randomUUID() }], ['another lease', { leaseSHA256: 'b'.repeat(64) }],
  ['another group', { gid: 7101 }], ['another live child', { bootstrapPID: 8991 }], ['changed parent birth', { bootstrapParentBirth: '999:000001' }],
  ['changed own birth', { bootstrapBirth: '999:000001' }], ['unverified private children', { privateChildrenAbsent: false }],
  ['unverified full GID scope', { gidScopeAbsent: false }], ['nonempty kernel class', { ownedFilterClassesEmpty: false }],
  ['numeric positive', { sealedContextVerified: 1 }], ['bootstrap attempted', { bootstrapAttempted: true }], ['transport attempted', { transportAttempted: true }],
  ['FILTER attempted', { filterWriteAttempted: true }], ['cold stage attempted', { coldStageAttempted: true }], ['unknown nonce', { proofNonce: '0'.repeat(31) }],
  ['Boolean nonce', { proofNonce: true }], ['noncanonical metadata', { bootstrapInode: '04' }], ['wrong native inode', { bootstrapInode: '6' }],
  ['wrong parent inode', { bootstrapParentInode: '6' }], ['private extra field', { privatePath: '/never-report' }],
  ['launchctl cannot be an early direct abort', {}, { forked: true }], ['a factory refusal is not preflight', {}, { preflightRefusalStage: 'factory-open' }],
  ['a late refusal is not preflight', {}, { preflightRefusalStage: 'deny-commit' }], ['missing terminal', {}, { omitAbort: true }],
  ['missing diagnostic', {}, { omitRefusal: true }], ['exit zero is not failure cleanup', {}, { abortExit: 0 }],
  ['signal is not a waitpid proof', {}, { abortExit: null, abortSignal: 'SIGTERM' }], ['partial trailing stdout', {}, { abortTrailing: '{' }],
  ['duplicate contradictory key', {}, { duplicatePreflightKey: true }],
]) test(`preflight abort rejects ${name} without permitting cold launch or cleanup`, async () => {
  const f = streamFixture({ preflightAbort: edit, ...options }); await assert.rejects(startStream(f));
  assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true);
  await assert.rejects(f.executor.confirmApplicationPreflightAborted(f.context.runId));
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()));
});
test('preflight accepted receipt cannot survive changed executable metadata, context, journal, nonce or a repeated terminal', async () => {
  for (const fault of ['native-file', 'parent-file', 'context', 'journal', 'repeat']) {
    const f = streamFixture({ preflightAbort: {} }); await assert.rejects(startStream(f), { preflightAborted: true });
    const previous = f.executor.fs.lstat;
    if (fault.endsWith('-file')) f.executor.fs.lstat = async filename => {
      const result = await previous(filename);
      if (filename.endsWith(fault === 'native-file' ? '/envara-pf-native' : '/node')) result.ino = 7;
      return result;
    };
    if (fault === 'context') f.executor.applicationTransportBinding = async () => ({ ...f.binding, leaseInode: '7' });
    if (fault === 'journal') f.executor.fs.lstat = async filename => filename.endsWith('/app-filter-events') ? { isDirectory: () => true } : previous(filename);
    if (fault === 'repeat') f.child.stdout.write(`${JSON.stringify(f.executor.expectedPreflightAbort)}\n`);
    await assert.rejects(f.executor.confirmApplicationPreflightAborted(f.context.runId));
  }
});
function preflightControllerFixture() {
  const f = fixture();
  f.executor.startApplicationTransport = async () => { f.calls.push('transport'); throw Object.assign(new Error(), {
    code: 'APPLICATION_APP_NATIVE_REFUSED', preflightAborted: true, nativeFailure: { stage: 'preflight', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } }); };
  f.executor.confirmApplicationPreflightAborted = async () => {
    f.calls.push('confirm-preflight'); const sealed = f.executor.sealed;
    return { stage: 'preflight', runId: sealed.runId, environmentId: sealed.environmentId, realmId: sealed.realmId, gid: sealed.gid,
      leaseSHA256: 'a'.repeat(64), exitStatus: 1, transportExitConfirmed: true,
      ...Object.fromEntries(['sealedContextVerified', 'privateChildrenAbsent', 'gidScopeAbsent', 'filterJournalAbsent', 'ownedFilterClassesEmpty'].map(key => [key, true])),
      ...Object.fromEntries(['bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted', 'ready', 'protected'].map(key => [key, false])) };
  };
  f.executor.inspectOwnedRootHook = async value => { assert.deepEqual(value, f.executor.sealed.rootHookLease); f.calls.push('inspect-hook'); };
  return f;
}

test('a verified original cleanup-ready transport preserves its first refusal and can only stop/release its exact custody', async () => {
  for (const forked of [false, true]) {
    const f = streamFixture({ forked, nativeRefusal: { stage: 'deny-commit', error: 13, reason: 'NATIVE_PF_GUARD_REFUSED' }, cleanupReady: {} });
    await assert.rejects(startStream(f), error => error.code === 'APPLICATION_APP_NATIVE_REFUSED' && error.cleanupAvailable === true && error.nativeFailure.reason === 'NATIVE_PF_GUARD_REFUSED');
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, false); assert.equal(entry.cleanupOnly, true);
    assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), true);
    for (const command of ['L', 'B', 'K']) await assert.rejects(f.executor.applicationTransportControl(f.context.runId, command, randomUUID()));
    const stopped = await f.executor.applicationTransportControl(f.context.runId, 'S');
    assert.equal(stopped.childReaped, false); assert.equal(stopped.childAbsent, true);
    const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
    assert.equal(released.childReaped, false); assert.equal(released.childAbsent, true);
    assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
    assert.equal(entry.failure.error, 13); assert.deepEqual(f.controlCommands, ['S', 'R']);
    assert.equal(entry.phase, 'released');
  }
});
test('a guardian refusal before stopped ACK keeps cleanup available without inventing a staged application child', async () => {
  const f = streamFixture({ controlRefusal: { reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13 } }); await startStream(f);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()), error => error.nativeFailure.reason === 'NATIVE_NOTION_STAGE_REFUSED');
  assert.equal(f.executor.appTransports.get(f.context.runId).stoppedIdentity, undefined);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
  await f.executor.applicationTransportControl(f.context.runId, 'S');
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.childAbsent, true); assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.equal(f.controlCommands.some(command => command === 'B'), false);
});
test('cleanup-only transport rejects foreign custody, unproved child absence and unknown terminal fields', async () => {
  for (const cleanupReady of [{ keeperPID: 8888 }, { coreBirth: '8992:000002' }, { ownsOriginalListenerFD: false }, { extra: proxy.password }]) {
    const f = streamFixture({ nativeRefusal: { stage: 'deny-commit' }, cleanupReady });
    await assert.rejects(startStream(f)); assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
  }
  for (const cleanupRelease of [{ childAbsent: false }, { childAbsent: true, childReaped: true }, { privateJournalRetired: false }, { extra: proxy.password }]) {
    const f = streamFixture({ nativeRefusal: { stage: 'deny-commit' }, cleanupReady: {}, cleanupRelease });
    await assert.rejects(startStream(f), { cleanupAvailable: true }); await f.executor.applicationTransportControl(f.context.runId, 'S');
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
    assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true);
    await assert.rejects(f.executor.confirmApplicationTransportExited(f.context.runId));
  }
});
test('original guardian errno and controller stage survive outward throws and cleanup failure without being overwritten', async () => {
  const original = { stage: 'guardian', reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13 }, f = fixture();
  f.executor.applicationTransportControl = async (runId, operation) => {
    f.calls.push(`control:${operation}`);
    if (operation === 'L') throw Object.assign(new Error('private detail'), { code: 'APPLICATION_APP_NATIVE_REFUSED', nativeFailure: original });
    throw Object.assign(new Error('cleanup detail'), { code: 'APPLICATION_APP_TRANSPORT_UNCONFIRMED' });
  };
  f.executor.applicationCleanupAvailable = () => true;
  const route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), error => {
    assert.equal(error.failureStage, 'cold-stage'); assert.deepEqual(error.nativeFailure, original);
    assert.deepEqual(error.initialFailure, { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native: original }); return true;
  });
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), error => {
    assert.deepEqual(error.nativeFailure, original); assert.equal(error.cleanupFailure.code, 'APPLICATION_APP_TRANSPORT_UNCONFIRMED'); return true;
  });
  const snapshot = f.controller.applicationSnapshot({ runId: request.runId });
  assert.deepEqual(snapshot.failure, snapshot.initialFailure); assert.equal(snapshot.initialFailure.native.error, 13);
  assert.equal(snapshot.cleanupFailure.stage, 'cleanup'); assert.equal(JSON.stringify(snapshot).includes('private detail'), false);
  await f.controller.shutdown();
});
test('the controller preserves the original cold-stage timeout separately from a later cleanup-state timeout', async () => {
  let cleanupAvailable = true;
  const f = fixture({ applicationCleanupAvailable: () => cleanupAvailable });
  f.executor.applicationTransportControl = async (runId, operation) => {
    f.calls.push(`control:${operation}`);
    throw Object.assign(new Error('private fixture detail'), { code: operation === 'L' ? 'APPLICATION_APP_STAGE_TIMEOUT' : 'APPLICATION_APP_STOP_TIMEOUT' });
  };
  const route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), error => {
    assert.equal(error.code, 'APPLICATION_APP_STAGE_TIMEOUT');
    assert.deepEqual(error.initialFailure, { stage: 'cold-stage', code: 'APPLICATION_APP_STAGE_TIMEOUT' }); return true;
  });
  assert.equal(f.controller.applicationSnapshot({ runId: request.runId }).cleanupRetryable, true);
  cleanupAvailable = false;
  assert.equal(f.controller.applicationSnapshot({ runId: request.runId }).cleanupRetryable, false, 'a hard-poisoned channel cannot advertise retryable cleanup');
  cleanupAvailable = true;
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), error => {
    assert.equal(error.initialFailure.code, 'APPLICATION_APP_STAGE_TIMEOUT');
    assert.deepEqual(error.cleanupFailure, { stage: 'cleanup', code: 'APPLICATION_APP_STOP_TIMEOUT' }); return true;
  });
  const snapshot = f.controller.applicationSnapshot({ runId: request.runId });
  assert.deepEqual(snapshot.failure, snapshot.initialFailure); assert.equal(snapshot.initialFailure.code, 'APPLICATION_APP_STAGE_TIMEOUT');
  assert.equal(snapshot.cleanupFailure.code, 'APPLICATION_APP_STOP_TIMEOUT'); assert.equal(snapshot.cleanupComplete, false);
  assert.equal(snapshot.staged, false); assert.equal(snapshot.resumed, false);
  assert.equal(f.calls.includes('release-reference'), false); assert.equal(f.calls.includes('control:R'), false);
  assert.equal(JSON.stringify(snapshot).includes('private fixture detail'), false);
  cleanupAvailable = false;
  assert.equal(f.controller.applicationSnapshot({ runId: request.runId }).cleanupRetryable, false);
  await f.controller.shutdown();
});
test('a host network change observed after every owned resource is reclaimed is reported, never left wedging the runtime', async () => {
  /* Host PF, routes and DNS are not Envara's to restore. A difference from the
   * baseline, or a snapshot that cannot be taken, used to abandon the lease and
   * lock after everything Envara owned was already released, leaving a runtime
   * directory that blocked every later trial and the component installer. */
  for (const finalSnapshot of ['dns-changed', 'unavailable']) {
    const f = fixture(), route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
    await f.controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true });
    const baseline = await f.executor.snapshotUnrelatedNetwork();
    f.executor.snapshotUnrelatedNetwork = async () => {
      if (finalSnapshot === 'unavailable') throw Object.assign(new Error(), { code: 'APPLICATION_ROUTING_NOT_READY' });
      return { ...baseline, dnsDigest: 'f'.repeat(64), digest: 'e'.repeat(64) };
    };
    const clean = await f.controller.stopNotionApplication({ runId: request.runId });
    assert.equal(clean.cleanupComplete, true, finalSnapshot);
    assert.equal(clean.cleanupUncertain, false, finalSnapshot);
    assert.ok(f.calls.includes('retire-lease') && f.calls.includes('unlock'), 'the lease is retired and the lock released');
    const evidence = clean.cleanupEvidence;
    assert.equal(evidence.hostDNSUnchanged, false, 'a change or an unprovable state is never reported as unchanged');
    if (finalSnapshot === 'dns-changed') { assert.equal(evidence.unrelatedPFUnchanged, true); assert.equal(evidence.unrelatedRoutesUnchanged, true); }
    else { assert.equal(evidence.unrelatedPFUnchanged, false); assert.equal(evidence.unrelatedRoutesUnchanged, false); }
    for (const key of ['ownedGroupsRemoved', 'ownedRootHookRemoved', 'ownedPFReferenceReleased', 'registryReleased']) assert.equal(evidence[key], true, key);
    await f.controller.shutdown();
  }
});
test('the public snapshot reports an application the guardian already stopped as ended', async () => {
  /* The executor records the revocation as an object. Comparing that object to
   * true reported every ended run as still running, so the trial kept
   * observing a process that had exited within a second of starting. */
  const f = fixture(), route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
  await f.controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true });
  f.executor.appTransports = new Map();
  assert.equal(f.controller.applicationSnapshot({ runId: request.runId }).applicationEnded, false);
  f.executor.appTransports.set(request.runId, { applicationEnded: Object.freeze({ pid: 4242, birth: '4242:000001', childReaped: true, childSignalled: false }) });
  const ended = f.controller.applicationSnapshot({ runId: request.runId });
  assert.equal(ended.applicationEnded, true);
  assert.equal(ended.endedChildReaped, true); assert.equal(ended.endedChildSignalled, false);
  assert.equal(ended.ready, false); assert.equal(ended.protected, false);
  await f.controller.shutdown();
});
test('an unchanged host is still reported as unchanged after cleanup', async () => {
  const f = fixture(), route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
  await f.controller.resumeNotionApplication({ runId: request.runId, activationAuthorized: true });
  const clean = await f.controller.stopNotionApplication({ runId: request.runId });
  for (const key of ['unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged']) assert.equal(clean.cleanupEvidence[key], true, key);
  await f.controller.shutdown();
});
test('application cleanup retries only unfinished owned tail steps after a native release and preserves the initial failure', async () => {
  for (const step of ['removeGroups', 'retireApplicationLease', 'releaseLock']) {
    const f = fixture(), route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
    const run = f.controller.appRuns.get(request.runId);
    run.initialFailure = Object.freeze({ stage: 'resume', code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
    const operation = f.executor[step]; let failed = false;
    f.executor[step] = async (...args) => { if (!failed) { failed = true; throw Object.assign(new Error(), { code: 'APPLICATION_ROUTING_NOT_READY' }); } return operation(...args); };
    await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }));
    const released = f.calls.filter(value => value === 'control:R').length, reference = f.calls.filter(value => value === 'release-reference').length;
    const clean = await f.controller.stopNotionApplication({ runId: request.runId });
    assert.equal(clean.cleanupComplete, true); assert.equal(clean.failure.code, 'APPLICATION_APP_RESUME_UNCONFIRMED');
    assert.equal(f.calls.filter(value => value === 'control:R').length, released);
    assert.equal(f.calls.filter(value => value === 'release-reference').length, reference);
    assert.equal(clean.cleanupFailure.code, 'APPLICATION_ROUTING_NOT_READY');
    await f.controller.shutdown();
  }
});
test('proved direct preflight failure cleans only this controllers issued root resources and preserves the failed launch under an independent schema', async () => {
  const f = preflightControllerFixture(), route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), { code: 'APPLICATION_APP_NATIVE_REFUSED' });
  const pending = f.controller.applicationSnapshot({ runId: request.runId });
  assert.equal(pending.phase, 'preflight-aborted'); assert.equal(pending.cleanupUncertain, false); assert.equal(pending.cleanupComplete, false);
  assert.equal(pending.preflightAborted, true); assert.equal(pending.prestageAborted, false); assert.equal(pending.staged, false); assert.equal(pending.resumed, false);
  const start = f.calls.length, clean = await f.controller.stopNotionApplication({ runId: request.runId });
  assert.deepEqual(f.calls.slice(start).filter(call => call !== 'persist'), ['confirm-preflight', 'empty', 'inspect-hook', 'process-absence',
    'release-reference', 'remove-hook', 'remove-groups', 'network-snapshot', 'retire-lease', 'unlock']);
  assert.equal(clean.phase, 'preflight-cleaned'); assert.equal(clean.cleanupComplete, true); assert.equal(clean.failure.code, 'APPLICATION_APP_NATIVE_REFUSED');
  assert.equal(clean.cleanupEvidence.schema, 'envara.macos-pf-notion-preflight-cleanup/v1');
  assert.equal(clean.cleanupEvidence.nativePrivateChildrenAbsentBeforeExit, true); assert.equal(clean.cleanupEvidence.nativeGIDScopeAbsentBeforeExit, true);
  assert.equal(clean.cleanupEvidence.bootstrapExitConfirmed, true); assert.equal(clean.cleanupEvidence.nativeOwnedFilterClassesEmptyBeforeExit, true);
  for (const field of ['childReaped', 'coreReaped', 'frontReaped', 'originalUTunClosed', 'originalListenerClosed', 'ownedGIDProcessesAbsent']) assert.equal(clean.cleanupEvidence[field], undefined);
  for (const field of ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted']) assert.equal(clean.cleanupEvidence[field], false);
  assert.equal(f.calls.some(call => call.startsWith('control:')), false); assert.equal(clean.ready, false); assert.equal(clean.protected, false);
  assert.ok(!JSON.stringify(clean).includes('proofNonce') && !JSON.stringify(clean).includes('leaseSHA256'));
  assert.deepEqual(await f.controller.stopNotionApplication({ runId: request.runId }), clean); assert.equal((await f.controller.shutdown()).cleanupRequired, false);
});
test('every failed fresh preflight cleanup check and an unproven error flag retain private state and never claim a normal app lifetime', async () => {
  for (const step of ['confirmApplicationPreflightAborted', 'persistRun', 'requireEmptyOwnedAnchor', 'inspectOwnedRootHook', 'assertNoOwnedGroupProcesses',
    'releaseOwnedReference', 'removeOwnedRootHook', 'removeGroups', 'retireApplicationLease', 'releaseLock']) {
    const f = preflightControllerFixture(), route = await f.prepareRoute(), request = input(route.routeId);
    await assert.rejects(f.controller.prepareNotionApplication(request));
    f.executor[step] = async () => { throw new Error('fixture-only private error'); };
    await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    const failed = f.controller.applicationSnapshot({ runId: request.runId });
    assert.equal(failed.cleanupUncertain, true); assert.equal(failed.cleanupComplete, false); assert.equal(failed.cleanupEvidence, null);
    assert.equal(failed.failure.code, 'APPLICATION_APP_NATIVE_REFUSED'); assert.equal(failed.staged, false); assert.equal(failed.resumed, false);
    assert.equal((await f.controller.shutdown()).cleanupRequired, true);
  }
  const f = preflightControllerFixture(), route = await f.prepareRoute(), request = input(route.routeId);
  f.executor.confirmApplicationPreflightAborted = async () => ({ transportExitConfirmed: true });
  await assert.rejects(f.controller.prepareNotionApplication(request)); await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }));
  assert.equal(f.calls.includes('release-reference'), false); assert.equal((await f.controller.shutdown()).cleanupRequired, true);
});

test('automatic cleanup-pending burns launch without claiming exit or answering the next S', async () => {
  const f = streamFixture({ cleanupPendingStops: [{ denyVerified: true, frontClosedVerified: true, familyStoppedVerified: true }] }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  f.emitCleanupPending(0);
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.cleanupOnly, true); assert.equal(entry.uncertain, false);
  assert.equal(entry.applicationEnded, undefined); assert.equal(entry.stopAttempts, undefined);
  assert.equal(entry.events.some(event => event.event === 'cleanup-pending'), false);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'), { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' });
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'), { code: 'APPLICATION_APP_TRANSPORT_UNCONFIRMED' });
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  assert.equal(entry.lastCleanupPendingAttempt, 1); assert.equal(entry.waiters.length, 0);
  assert.equal(entry.phase, 'cleanup-pending'); assert.equal(entry.uncertain, false);
  assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), true);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
  const stopped = await f.executor.applicationTransportControl(f.context.runId, 'S');
  assert.equal(stopped.event, 'stopping'); assert.equal(entry.stopAttempts, 2);
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.event, 'transport-released'); assert.equal(entry.uncertain, false);
  assert.deepEqual(f.controlCommands.filter(command => ['S', 'R'].includes(command)), ['S', 'S', 'R']);
});

test('a cleanup-only guardian accepts a fresh S negative then retries with the original stopping proof shape', async () => {
  const f = streamFixture({ cleanupPendingStops: [{}] }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  // An established native refusal already burned launch authority.
  f.executor.appTransports.get(f.context.runId).denyLaunch();
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(entry.uncertain, false); assert.equal(f.child.stdin.writableEnded, false);
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'S')).event, 'stopping');
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'R')).event, 'transport-released');
});

test('cleanup-pending validates every binding, exact shape and strict boolean before preserving the channel', async () => {
  const changes = [{ ticketId: randomUUID() }, { registrationId: randomUUID() }, { versionId: randomUUID() },
    { environmentId: randomUUID() }, { runId: randomUUID() }, { keeperPID: 8999 }, { keeperBirth: '8990:000002' },
    { pid: 8995 }, { birth: '8994:000002' }, { profile: 'cold' }, { cleanupAttempt: 0 }, { cleanupAttempt: 2 },
    { cleanupAttempt: true }, { cleanupAttempt: -1 }, { cleanupAttempt: Number.MAX_SAFE_INTEGER + 1 },
    { launchAuthorityBurned: false }, { custodyHeld: false }, { denyVerified: 1 }, { frontClosedVerified: 'false' },
    { familyStoppedVerified: null }, { ready: true }, { protected: true }, { extra: 'INERT_NEGATIVE_SECRET' }];
  for (const change of changes) {
    const f = streamFixture({ stopNoAck: true }); await startStream(f);
    await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
    const rejected = assert.rejects(stopping);
    await new Promise(resolve => setImmediate(resolve));
    let frame = f.cleanupPending(1, change);
    // A first auto0 is legal but cannot answer S; exercise its replay instead.
    if (change.cleanupAttempt === 0) { f.emitCleanupPending(0); frame = f.cleanupPending(0); }
    f.child.stdout.write(`${JSON.stringify(frame)}\n`); await rejected;
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, true, JSON.stringify(change)); assert.equal(f.child.stdin.writableEnded, true);
    assert.equal(entry.events.some(event => event.event === 'cleanup-pending'), false);
    assert.equal(JSON.stringify(entry.events).includes('INERT_NEGATIVE_SECRET'), false);
  }
});

test('a negative is not buffered and repeated, skipped, unsolicited or duplicate-key responses poison', async () => {
  for (const variant of ['same', 'skip', 'unsolicited', 'duplicate-key']) {
    const f = streamFixture({ cleanupPendingStops: [{}], stopNoAck: true }); await startStream(f);
    await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    let rejected;
    if (variant !== 'unsolicited') {
      rejected = assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
      await new Promise(resolve => setImmediate(resolve));
    }
    let line = JSON.stringify(f.cleanupPending(variant === 'same' || variant === 'unsolicited' ? 1 : variant === 'skip' ? 3 : 2));
    if (variant === 'duplicate-key') line = line.replace('"denyVerified":false', '"denyVerified":true,"denyVerified":false');
    f.child.stdout.write(`${line}\n`); if (rejected) await rejected;
    assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true, variant);
  }
});

test('late cleanup-pending cannot repair a stop timeout or become release evidence even when all flags are true', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ stopNoAck: true }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S');
  const rejected = assert.rejects(stopping, { code: 'APPLICATION_APP_STOP_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve)); t.mock.timers.tick(15000); await rejected;
  f.emitCleanupPending(1, { denyVerified: true, frontClosedVerified: true, familyStoppedVerified: true });
  assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
  assert.equal(f.controlCommands.includes('R'), false);
});

test('an auto0 consumed while S1 is pending cannot settle it and a real stopping still can', async () => {
  const f = streamFixture({ stopNoAck: true }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  let settled = false;
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S').then(value => { settled = true; return value; });
  await new Promise(resolve => setImmediate(resolve)); f.emitCleanupPending(0);
  await new Promise(resolve => setImmediate(resolve));
  const entry = f.executor.appTransports.get(f.context.runId);
  assert.equal(settled, false); assert.equal(entry.pendingStopAttempt, 1); assert.equal(entry.uncertain, false);
  f.emitKeeper('stopping', { childReaped: true, persistentDenyObserved: true });
  assert.equal((await stopping).event, 'stopping'); assert.equal(entry.phase, 'stopping'); assert.equal(entry.uncertain, false);
});

test('a failed stop of a previously healthy run keeps the same cleanup channel retryable and records no false release', async () => {
  const f = fixture({ applicationCleanupAvailable: () => true });
  const original = f.executor.applicationTransportControl; let stops = 0;
  f.executor.applicationTransportControl = async (runId, command) => {
    if (command === 'S' && ++stops === 1) {
      f.calls.push('negative:S1'); throw Object.assign(new Error('INERT_CLEANUP_SECRET'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    }
    return original(runId, command);
  };
  const route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), error => {
    assert.deepEqual(error.cleanupFailure, { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' }); return true;
  });
  const snapshot = f.controller.applicationSnapshot({ runId: request.runId });
  assert.equal(snapshot.cleanupRetryable, true); assert.equal(snapshot.cleanupComplete, false);
  assert.equal(f.calls.includes('control:R'), false); assert.equal(f.calls.includes('release-reference'), false);
  assert.equal(JSON.stringify(snapshot).includes('INERT_CLEANUP_SECRET'), false);
  const clean = await f.controller.stopNotionApplication({ runId: request.runId });
  assert.equal(clean.cleanupComplete, true); assert.equal(stops, 2);
  assert.deepEqual(clean.cleanupFailure, snapshot.cleanupFailure);
  await f.controller.shutdown();
});

test('a verified cleanup-pending snapshot reports required cleanup without claiming an ended application', async () => {
  const f = fixture({ applicationCleanupAvailable: () => true, appTransports: new Map() });
  const route = await f.prepareRoute(), request = input(route.routeId); await f.controller.prepareNotionApplication(request);
  f.executor.appTransports.set(request.runId, { cleanupOnly: true, phase: 'cleanup-pending' });
  const snapshot = f.controller.applicationSnapshot({ runId: request.runId });
  assert.equal(snapshot.phase, 'cleanup-required'); assert.equal(snapshot.cleanupUncertain, true);
  assert.equal(snapshot.cleanupRetryable, true); assert.equal(snapshot.applicationEnded, false); assert.equal(snapshot.cleanupComplete, false);
  assert.equal(f.controller.appRuns.get(request.runId).phase, 'staged', 'the read-only snapshot does not mutate native/run state');
  f.executor.appTransports.clear(); await f.controller.stopNotionApplication({ runId: request.runId }); await f.controller.shutdown();
});

test('a fresh cleanup refusal remains separate from the first launch refusal through successful retry', async () => {
  const f = fixture({ applicationCleanupAvailable: () => true });
  const original = f.executor.applicationTransportControl;
  const native = { stage: 'guardian', reason: 'NATIVE_NOTION_STAGE_REFUSED', error: 13 }; let stops = 0;
  f.executor.applicationTransportControl = async (runId, command) => {
    if (command === 'L') throw Object.assign(new Error(), { code: 'APPLICATION_APP_NATIVE_REFUSED', nativeFailure: native });
    if (command === 'S' && ++stops === 1) throw Object.assign(new Error(), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    return original(runId, command);
  };
  const route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), { code: 'APPLICATION_APP_NATIVE_REFUSED' });
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), error => {
    assert.deepEqual(error.initialFailure, { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native });
    assert.deepEqual(error.cleanupFailure, { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' }); return true;
  });
  const failed = f.controller.applicationSnapshot({ runId: request.runId });
  assert.deepEqual(failed.failure, failed.initialFailure); assert.equal(failed.cleanupRetryable, true);
  assert.equal(f.calls.includes('control:R'), false);
  const clean = await f.controller.stopNotionApplication({ runId: request.runId });
  assert.equal(clean.cleanupComplete, true); assert.deepEqual(clean.initialFailure, failed.initialFailure);
  assert.deepEqual(clean.cleanupFailure, failed.cleanupFailure); await f.controller.shutdown();
});

const familyFailure = (reason = 'token', error = 13, mach = 5) => ({ familyFailureReason: reason, familyFailureErrno: error, familyFailureMach: mach });
test('legacy and diagnostic cleanup negatives preserve bounded first/latest facts without changing stop authority', async () => {
  const f = streamFixture({ cleanupPendingStops: [familyFailure(), { ...familyFailure('stop-timeout', 110, 0), denyVerified: true,
    frontClosedVerified: true, familyStoppedVerified: true }] }); await startStream(f);
  await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
  f.emitCleanupPending(0);
  const entry = f.executor.appTransports.get(f.context.runId);
  const first = { cleanupAttempt: 0, denyVerified: false, frontClosedVerified: false, familyStoppedVerified: false,
    familyFailureReason: 'unknown', familyFailureErrno: null, familyFailureMach: null };
  assert.deepEqual(entry.firstCleanupPending, first);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  assert.deepEqual(entry.latestCleanupPending, { cleanupAttempt: 1, denyVerified: false, frontClosedVerified: false,
    familyStoppedVerified: false, ...familyFailure() });
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  assert.deepEqual(entry.firstCleanupPending, first);
  const latest = { cleanupAttempt: 2, denyVerified: true, frontClosedVerified: true, familyStoppedVerified: true,
    ...familyFailure('stop-timeout', 110, 0) };
  assert.deepEqual(entry.latestCleanupPending, latest);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
  assert.equal(entry.applicationEnded, undefined); assert.equal(entry.events.some(event => event.event === 'cleanup-pending'), false);
  const controller = new MacOSPFController({ executor: f.executor });
  const projected = controller.publicApplication({ runId: f.context.runId, environmentId: f.context.environmentId, phase: 'staged', staged: true });
  assert.deepEqual(projected.cleanupPending, { first, latest }); assert.equal(projected.cleanupComplete, false);
  projected.cleanupPending.first.denyVerified = true; assert.deepEqual(entry.firstCleanupPending, first);
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'S')).event, 'stopping');
  assert.equal((await f.executor.applicationTransportControl(f.context.runId, 'R')).event, 'transport-released');
});

test('all diagnostic family reasons accept only their exact numeric contract', async () => {
  for (const reason of ['none', 'identity', 'token', 'inventory', 'churn', 'capacity', 'signal', 'stop-timeout', 'unavailable']) {
    const f = streamFixture(); await startStream(f); await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    f.emitCleanupPending(0, familyFailure(reason, reason === 'none' ? 0 : 13, 0));
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, false); assert.equal(entry.firstCleanupPending.familyFailureReason, reason);
    assert.equal(entry.firstCleanupPending.familyFailureMach, 0);
    await f.executor.applicationTransportControl(f.context.runId, 'S'); await f.executor.applicationTransportControl(f.context.runId, 'R');
  }
  for (const change of [familyFailure('unknown', 13, 0), familyFailure('INERT_DIAG_SECRET', 13, 0), familyFailure('none', 13, 0),
    familyFailure('none', 0, 5), familyFailure('token', 0, 5), familyFailure('token', 1025, 5), familyFailure('token', -1, 5),
    familyFailure('token', true, 5), familyFailure('token', 13, null), familyFailure('token', 13, true),
    familyFailure('token', 13, 2147483648), familyFailure('token', 13, -2147483649), { familyFailureReason: 'token' },
    { ...familyFailure(), privatePID: 42 }, { ...familyFailure(), familyFailureErrno: null }]) {
    const f = streamFixture({ stopNoAck: true }); await startStream(f); await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    const rejected = assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
    await new Promise(resolve => setImmediate(resolve)); f.emitCleanupPending(1, change); await rejected;
    const entry = f.executor.appTransports.get(f.context.runId);
    assert.equal(entry.uncertain, true, JSON.stringify(change)); assert.equal(entry.firstCleanupPending, undefined);
    assert.equal(JSON.stringify(entry.events).includes('INERT_DIAG_SECRET'), false);
  }
});

async function refusePreparation(f) {
  await startStream(f);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()), error => {
    assert.deepEqual(error.nativeFailure, { stage: 'guardian', reason: 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED', error: 13 });
    return error.code === 'APPLICATION_APP_NATIVE_REFUSED';
  });
  return f.executor.appTransports.get(f.context.runId);
}

test('preparation negatives retain only prep custody and retry through real S then R without inventing an application', async () => {
  for (const childState of ['unreaped', 'reaped', 'launcher-clear', 'unknown']) {
    const f = streamFixture({ preparationFailure: true, preparationPendingStops: [{ childState, denyVerified: true, frontClosedVerified: true }] });
    const entry = await refusePreparation(f), initial = { ...entry.failure };
    assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
    assert.equal(entry.applicationEnded, undefined); assert.equal(entry.resumeAttempted, undefined);
    assert.equal(entry.firstPreparationPending.command, 'automatic'); assert.equal(entry.uncertain, false);
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'B'));
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()));
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
    await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    assert.equal(entry.phase, 'cleanup-pending'); assert.equal(entry.latestPreparationPending.childState, childState);
    assert.equal(entry.uncertain, false); assert.equal(f.executor.applicationCleanupAvailable(f.context.runId), true);
    assert.equal(entry.events.some(event => event.schema === 'envara.pf-app-preparation/v1'), false);
    const stopped = await f.executor.applicationTransportControl(f.context.runId, 'S');
    assert.equal(stopped.event, 'transport-cleanup-stopping'); assert.equal(stopped.childAbsent, true); assert.equal(stopped.childReaped, false);
    const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
    assert.equal(released.event, 'transport-released'); assert.equal(released.childAbsent, true); assert.equal(released.childReaped, false);
    assert.deepEqual(entry.failure, initial); assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
    assert.notEqual(entry.guardianReleased, true); assert.equal(entry.applicationEnded, undefined); assert.equal(entry.uncertain, false);
    assert.deepEqual(f.controlCommands.filter(command => ['S', 'R'].includes(command)), ['S', 'S', 'R']);
  }
});

test('preparation launch failure and a failed cleanup attempt remain separate through complete controller cleanup', async () => {
  const f = fixture({ applicationCleanupAvailable: () => true });
  const original = f.executor.applicationTransportControl;
  const native = { stage: 'guardian', reason: 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED', error: 13 }; let attempts = 0;
  f.executor.applicationTransportControl = async (runId, command) => {
    if (command === 'L') throw Object.assign(new Error('INERT_PREPARATION_SECRET'), { code: 'APPLICATION_APP_NATIVE_REFUSED', nativeFailure: native });
    if (command === 'S' && ++attempts === 1) throw Object.assign(new Error(), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
    const result = await original(runId, command);
    return command === 'R' ? { ...result, childAbsent: true, childReaped: false } : result;
  };
  const route = await f.prepareRoute(), request = input(route.routeId);
  await assert.rejects(f.controller.prepareNotionApplication(request), { code: 'APPLICATION_APP_NATIVE_REFUSED' });
  const run = f.controller.appRuns.get(request.runId);
  assert.equal(run.staged, false); assert.equal(run.applicationChild, undefined); assert.equal(run.resumed, false);
  await assert.rejects(f.controller.stopNotionApplication({ runId: request.runId }), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  const failed = f.controller.applicationSnapshot({ runId: request.runId });
  assert.deepEqual(failed.initialFailure, { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native });
  assert.deepEqual(failed.cleanupFailure, { stage: 'cleanup', code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  assert.equal(failed.applicationEnded, false); assert.equal(failed.cleanupComplete, false); assert.equal(failed.cleanupRetryable, true);
  assert.equal(f.calls.includes('control:R'), false); assert.equal(JSON.stringify(failed).includes('INERT_PREPARATION_SECRET'), false);
  const clean = await f.controller.stopNotionApplication({ runId: request.runId });
  assert.equal(clean.cleanupComplete, true); assert.equal(clean.staged, false); assert.equal(clean.resumed, false);
  assert.equal(clean.cleanupEvidence.childAbsent, true); assert.equal(clean.cleanupEvidence.childReaped, false);
  assert.deepEqual(clean.initialFailure, failed.initialFailure); assert.deepEqual(clean.cleanupFailure, failed.cleanupFailure);
  await f.controller.shutdown();
});

test('preparation diagnostics are bounded copies and never report an ended application or completed cleanup', async () => {
  const f = streamFixture({ preparationFailure: true, preparationPendingStops: [{ childState: 'reaped' }] }); const entry = await refusePreparation(f);
  await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
  const controller = new MacOSPFController({ executor: f.executor });
  const snapshot = controller.publicApplication({ runId: f.context.runId, environmentId: f.context.environmentId, phase: 'preparing', staged: false, resumed: false });
  assert.equal(snapshot.phase, 'cleanup-required'); assert.equal(snapshot.staged, false); assert.equal(snapshot.resumed, false);
  assert.equal(snapshot.cleanupComplete, false); assert.equal(snapshot.cleanupRetryable, true);
  assert.equal(snapshot.preparationCleanupPending.first.command, 'automatic');
  assert.equal(snapshot.preparationCleanupPending.latest.childState, 'reaped');
  snapshot.preparationCleanupPending.latest.childState = 'unknown'; assert.equal(entry.latestPreparationPending.childState, 'reaped');
  await f.executor.applicationTransportControl(f.context.runId, 'S'); await f.executor.applicationTransportControl(f.context.runId, 'R');
});

test('an inactive preparation failure cleans through the original no-application path without a prep slot frame', async () => {
  const f = streamFixture({ preparationFailure: true, preparationAutomatic: null }); const entry = await refusePreparation(f);
  assert.equal(entry.preparationId, undefined); assert.equal(entry.firstPreparationPending, undefined);
  assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
  const stopped = await f.executor.applicationTransportControl(f.context.runId, 'S');
  assert.equal(stopped.childAbsent, true); assert.equal(stopped.childReaped, false);
  const released = await f.executor.applicationTransportControl(f.context.runId, 'R');
  assert.equal(released.childAbsent, true); assert.equal(released.childReaped, false);
  assert.equal(entry.uncertain, false); assert.equal(await f.executor.confirmApplicationTransportExited(f.context.runId), true);
  assert.deepEqual(f.controlCommands.filter(command => ['S', 'R'].includes(command)), ['S', 'R']);
});

test('preparation messages validate exact binding, shape, bounded diagnostics and the outstanding S ordinal', async () => {
  const mutations = [{ ticketId: randomUUID() }, { registrationId: randomUUID() }, { versionId: randomUUID() },
    { environmentId: randomUUID() }, { runId: randomUUID() }, { keeperPID: 8999 }, { keeperBirth: '8990:000002' },
    { preparationId: randomUUID() }, { generation: 2 }, { generation: 0 }, { generation: 6 }, { generation: true },
    { command: 'automatic', cleanupAttempt: 0 }, { command: 'R' }, { command: 'B' }, { cleanupAttempt: 0 }, { cleanupAttempt: 2 },
    { cleanupAttempt: true }, { cleanupAttempt: -1 }, { cleanupAttempt: 2147483648 }, { childState: 'absent' },
    { launchAuthorityBurned: false }, { custodyHeld: false }, { denyVerified: 1 }, { frontClosedVerified: null },
    { ready: true }, { protected: true }, { pid: 8994 }, { birth: '8994:000001' }, { armed: true }, { extra: 'INERT_PREPARATION_SECRET' }];
  for (const mutation of mutations) {
    const f = streamFixture({ preparationFailure: true, stopNoAck: true }); const entry = await refusePreparation(f);
    const rejected = assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
    await new Promise(resolve => setImmediate(resolve)); f.emitPreparationPending('S', 1, mutation); await rejected;
    assert.equal(entry.uncertain, true, JSON.stringify(mutation)); assert.equal(f.child.stdin.writableEnded, true);
    assert.equal(entry.latestPreparationPending.command, 'automatic');
    assert.equal(JSON.stringify(entry.events).includes('INERT_PREPARATION_SECRET'), false);
  }
});

test('preparation auto0 never answers S and the same consumed negative cannot answer another S', async () => {
  const f = streamFixture({ preparationFailure: true, preparationAutomatic: null, stopNoAck: true }); const entry = await refusePreparation(f);
  let settled = false;
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S').finally(() => { settled = true; });
  const rejected = assert.rejects(stopping, { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  await new Promise(resolve => setImmediate(resolve)); f.emitPreparationPending('automatic', 0);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false); assert.equal(entry.pendingStopAttempt, 1); assert.equal(entry.uncertain, false);
  f.emitPreparationPending('S', 1); await rejected;
  const second = assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
  await new Promise(resolve => setImmediate(resolve)); f.emitPreparationPending('S', 1); await second;
  assert.equal(entry.uncertain, true); assert.equal(f.controlCommands.includes('R'), false);
});

test('preparation auto0 requires the original preparation refusal and cannot replace a real application identity', async () => {
  for (const mode of ['no-launch', 'ordinary-child', 'duplicate-auto', 'bad-generation', 'duplicate-key']) {
    const f = streamFixture({ preparationFailure: mode !== 'no-launch' && mode !== 'ordinary-child' }); await startStream(f);
    if (mode === 'ordinary-child') await f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID());
    else if (mode !== 'no-launch') await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()));
    let line = JSON.stringify(f.preparationPending('automatic', 0, mode === 'bad-generation' ? { generation: 6 } : {}));
    if (mode === 'duplicate-key') line = line.replace('"custodyHeld":true', '"custodyHeld":false,"custodyHeld":true');
    f.child.stdout.write(`${line}\n`);
    assert.equal(f.executor.appTransports.get(f.context.runId).uncertain, true, mode);
  }
});

test('preparation S uses its own deadline and a late negative cannot repair an actual S timeout', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ preparationFailure: true, stopNoAck: true }); const entry = await refusePreparation(f);
  let settled = false;
  const stopping = f.executor.applicationTransportControl(f.context.runId, 'S').finally(() => { settled = true; });
  const rejected = assert.rejects(stopping, { code: 'APPLICATION_APP_STOP_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve)); t.mock.timers.tick(15000);
  await new Promise(resolve => setImmediate(resolve)); assert.equal(settled, false); assert.equal(entry.uncertain, false);
  t.mock.timers.tick(PF_APP_PREPARATION_STOP_TIMEOUT_MS - 15000); await rejected;
  f.emitPreparationPending('S', 1, { childState: 'reaped', denyVerified: true, frontClosedVerified: true });
  assert.equal(entry.uncertain, true); await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R'));
});

test('a preparation refusal after the L deadline settles only the cleanup state and retains the original failure', async t => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const f = streamFixture({ preparationFailure: true, coldStageNoAck: true, preparationPendingStops: [{ childState: 'reaped' }] }); await startStream(f);
  const launched = assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'L', randomUUID()), { code: 'APPLICATION_APP_STAGE_TIMEOUT' });
  await new Promise(resolve => setImmediate(resolve)); t.mock.timers.tick(60000); await launched;
  const entry = f.executor.appTransports.get(f.context.runId);
  const stopping = assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'), { code: 'APPLICATION_APP_CLEANUP_UNCONFIRMED' });
  await new Promise(resolve => setImmediate(resolve)); assert.equal(f.controlCommands.includes('S'), false);
  f.completeColdStage(); await stopping;
  assert.equal(entry.stageOutcomePending, false); assert.equal(entry.waitFailure, 'APPLICATION_APP_STAGE_TIMEOUT');
  assert.equal(entry.failure.reason, 'NATIVE_APP_KEYCHAIN_PREPARATION_REFUSED'); assert.equal(entry.uncertain, false);
  await f.executor.applicationTransportControl(f.context.runId, 'S'); await f.executor.applicationTransportControl(f.context.runId, 'R');
});

test('preparation success cannot fabricate a reaped application or skip final transport resource gates', async () => {
  for (const variant of ['stopping-child', 'release-child', 'release-resource']) {
    const f = streamFixture({ preparationFailure: true,
      ...(variant === 'stopping-child' ? { cleanupStopping: { childReaped: true, childAbsent: false } } :
        { cleanupRelease: variant === 'release-child' ? { childReaped: true, childAbsent: false } : { originalUTunClosed: false } }) });
    const entry = await refusePreparation(f);
    if (variant === 'stopping-child') await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'S'));
    else { await f.executor.applicationTransportControl(f.context.runId, 'S'); await assert.rejects(f.executor.applicationTransportControl(f.context.runId, 'R')); }
    assert.equal(entry.uncertain, true); assert.equal(entry.stoppedIdentity, undefined); assert.notEqual(entry.guardianArmed, true);
  }
});
