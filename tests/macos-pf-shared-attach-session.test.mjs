import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { MacOSPFNotionTrial } from '../electron/macos-pf-notion-trial.mjs';
import { createPFAuthorizedChannelMux } from '../electron/macos-pf-channel-mux.mjs';
import { createPersistentPFNotionSessionClient } from '../electron/macos-pf-notion-session.mjs';
import { servePFHelper } from '../native/macos-pf-routing/helper.mjs';
import { MacOSPFController } from '../native/macos-pf-routing/controller.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

// The packaged attach path, end to end: the trial's own default client, the
// shared channel mux, the session client and the real root helper envelope.
// Every other attach test supplies its own client, which is how a first attach
// that could never succeed reached a packaged build. Only the carrier process
// and the root controller are inert stand-ins: no authorizer, privilege
// dialog, PF command, application, proxy or network is used.
const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false };
const facts = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
  'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
  'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const request = () => ({ application: { id: 'notion_bound', profileId: 'owned_profile', executablePath: '/Applications/Notion.app/Contents/MacOS/Notion' },
  workspace: { cwd: '/tmp', timezone: 'Asia/Manila', locale: 'en-PH', timezoneSource: 'proxy-egress' },
  route: { protocol: 'socks5', host: '127.0.0.1', port: 20101, username: 'PRIVATE_SHARED_USERNAME', password: 'PRIVATE_SHARED_PASSWORD', udpPolicy: 'block' },
  managedRoute: { profileId: 'owned_profile', proxyId: 'owned_node', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 999, coreVersion: 'v1.19.32' } });
const until = async (predicate, ms = 3000) => {
  const end = Date.now() + ms;
  while (!predicate()) { if (Date.now() > end) throw new Error('condition not reached'); await new Promise(resolve => setTimeout(resolve, 5)); }
};
// Exactly what the carrier prints when the password dialog is cancelled.
const refusalFrame = { protocol: 'envara.application-routing', version: 1, id: null,
  error: { code: 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED', message: 'authorization-denied' },
  nativeAuthorization: { stage: 'AuthorizationCopyRights', status: -60006 } };

/** One root session: a scripted controller behind the real helper envelope,
 *  answering status with the root controller's own logic. */
function rootSession({ canCreate, onPrepareRoute, hangStatus = false, refusePrepare = () => false, refusePrepareRoute = () => false, leaveRoute = () => false, answerUnstaged = () => false }) {
  const calls = [], prepared = [], reclaimed = []; let bound = null, shutdowns = 0;
  const statusController = new MacOSPFController({ inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
    identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, executor: { readOnlyStatus: async ({ runId } = {}) => ({ consoleUID: 501,
      pf: { priorAnchorsCompatible: true, lo0FilteringVerified: true }, ownedRootHook: { canCreateOwnedHook: Boolean(runId) && canCreate(),
        pfDisabled: true, pinsVerified: true, originalRootCompatible: true } }) } });
  const state = phase => ({ ...flags, ...bound, profile: 'seatbelt-front-only', phase, staged: true, resumed: phase === 'running', cleanupComplete: false, cleanupUncertain: false });
  const cleanup = () => ({ ...state('cleaned'), cleanupComplete: true, cleanupEvidence: { schema: 'envara.macos-pf-notion-cleanup/v1',
    source: 'native-notion-controller', ...bound, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false,
    ...Object.fromEntries(facts.map(key => [key, true])) } });
  const controller = { closed: false,
    status: async params => { calls.push('status'); if (hangStatus) return new Promise(() => {});
      // A controller that kept a refused attempt's route would still list it.
      const result = await statusController.status(params); return leaveRoute() ? { ...result, routes: [{ routeId: 'route_owned' }] } : result; },
    prepareRoute: async value => { calls.push('prepareRoute');
      if (refusePrepareRoute()) throw Object.assign(new Error('refused'), { code: 'APPLICATION_PROXY_UNAVAILABLE' });
      if (onPrepareRoute) return onPrepareRoute();
      return { routeId: 'route_owned', profileId: value.application.profileId, ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false }; },
    prepareNotionApplication: async value => { calls.push('prepare'); prepared.push(value);
      // Refused before the controller created the run: nothing is listed for it.
      if (refusePrepare()) throw Object.assign(new Error('refused'), { code: 'APPLICATION_ROUTING_NOT_READY' });
      bound = { runId: value.runId, environmentId: value.environmentId };
      // Answered with a run that is not staged, by a controller that then lists nothing.
      if (answerUnstaged()) { const answered = { ...state('preparing'), staged: false }; bound = null; return answered; }
      return state('staged'); },
    applicationStorage: async () => { calls.push('storage');
      return { ...flags, profile: 'seatbelt-front-only', readOnly: true, attachedApplicationActive: false,
        registrations: [{ registrationId: storageIds.registration, identifier: 'notion.id', bundle: '/Applications/Notion.app', versions: 1, retired: false, bytes: 307232768 }],
        environments: [{ environmentId: storageIds.environment, bytes: 141000000 }] }; },
    reclaimApplicationStorage: async value => { calls.push('reclaim'); reclaimed.push(value);
      return { ...flags, profile: 'seatbelt-front-only', registrations: value.registrationIds.map(registrationId => ({ registrationId, outcome: 'deleted' })),
        environments: value.environmentIds.map(environmentId => ({ environmentId, outcome: 'deleted' })) }; },
    resumeNotionApplication: async () => { calls.push('resume'); return state('running'); },
    stopNotionApplication: async () => { calls.push('stop'); return cleanup(); },
    applicationSnapshot: async () => { calls.push('snapshot'); return cleanup(); },
    shutdown: async () => { shutdowns++; calls.push('shutdown'); return { closed: true, cleanupRequired: false }; } };
  return { controller, calls, prepared, reclaimed, shutdowns: () => shutdowns };
}
const storageIds = { registration: randomUUID(), environment: randomUUID() };

/** Stands in for the authorization carrier: each spawn is one root session. */
function carrierFactory({ canCreate = () => true, refuseFirst = false, refusalStage = 'AuthorizationCopyRights', dieOnPrepareRoute = false, hangStatus = false,
  refusePrepare, refusePrepareRoute, leaveRoute, answerUnstaged } = {}) {
  const sessions = [];
  const spawnCarrier = () => {
    const input = new PassThrough(), child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough();
    child.stdin = new Writable({ write(bytes, encoding, done) { input.write(Buffer.from(bytes)); done(); }, final(done) { input.end(); done(); } });
    child.kill = () => { input.end(); return true; };
    const session = { child, exited: false, root: null };
    const exit = code => { if (session.exited) return; session.exited = true; setImmediate(() => child.emit('close', code, null)); };
    sessions.push(session);
    if (refuseFirst && sessions.length === 1) {
      const frame = { ...refusalFrame, nativeAuthorization: { ...refusalFrame.nativeAuthorization, stage: refusalStage } };
      setImmediate(() => { child.stdout.write(`${JSON.stringify(frame)}\n`); child.stdout.end(); exit(1); });
      return child;
    }
    session.root = rootSession({ canCreate, hangStatus, refusePrepare, refusePrepareRoute, leaveRoute, answerUnstaged,
      onPrepareRoute: dieOnPrepareRoute ? () => { exit(1); return new Promise(() => {}); } : null });
    servePFHelper({ controller: session.root.controller, input, output: child.stdout, signalSource: null })
      .then(() => { child.stdout.end(); exit(0); });
    return child;
  };
  return { spawnCarrier, sessions };
}

function attachFixture(options = {}) {
  let canCreate = options.canCreate ?? true;
  const carrier = carrierFactory({ ...options, canCreate: () => canCreate });
  // No createClient: this is the default the packaged app uses.
  const pruned = [];
  const trial = new MacOSPFNotionTrial({ authorizerPath: '/fixture/EnvaraPFInstall', verifyCandidate: async () => true,
    verifyNotion: async () => true, watchMs: 0, spawnCarrier: carrier.spawnCarrier,
    pruneApplicationData: async value => { pruned.push(value); return 1024; } });
  return { trial, carrier, pruned, setCanCreate: value => { canCreate = value; },
    attach: () => trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: true }) };
}

test('a session client takes a shared channel handed over synchronously and reads its newline-framed answer', async () => {
  const carrier = carrierFactory();
  const mux = createPFAuthorizedChannelMux({ spawnRootControlledLifecycle: carrier.spawnCarrier });
  const runId = randomUUID(), target = mux.acquire({ key: runId });
  const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: null, acquireChannel: () => target,
    lifetimeMs: Infinity, channelKey: runId });
  /* This is the request the packaged build failed with PF_HELPER_REQUEST_INVALID
   * before anything was sent. With only that fixed, an answer delivered without
   * its newline would have sat unparsed until this deadline. */
  const status = await call('status', { runId }, { timeoutMs: 5000 });
  assert.equal(status.anchor, pfRoutingAnchor(runId)); assert.equal(status.ownedRootHookCanCreate, true);
  const closed = await call.close();
  assert.equal(closed.cleanupUncertain, false); assert.equal(closed.statusOnlyDetached, true);
  assert.equal(closed.statusOnlyEvidence, undefined, 'a shared channel never claims its authorizer exited');
  assert.equal(carrier.sessions.length, 1); assert.equal(carrier.sessions[0].exited, false, 'detaching one run leaves the session open');
  await mux.dispose(); await until(() => carrier.sessions[0].exited);
  assert.equal(carrier.sessions[0].root.shutdowns(), 1);
});

test('the default shared channel runs two attachments in one launch over one carrier and closes it on quit', async () => {
  const f = attachFixture();
  const first = await f.attach();
  assert.equal(first.errorCode, null, JSON.stringify(first.events));
  assert.equal(first.phase, 'cleaned'); assert.equal(first.lifecyclePassed, true); assert.equal(first.cleanupUncertain, false);
  const second = await f.attach();
  assert.equal(second.errorCode, null, JSON.stringify(second.events));
  assert.equal(second.phase, 'cleaned'); assert.equal(second.lifecyclePassed, true); assert.notEqual(first.runId, second.runId);
  assert.equal(f.carrier.sessions.length, 1, 'the administrator password is asked once per launch');
  const session = f.carrier.sessions[0];
  await f.trial.housekeeping;
  assert.deepEqual(session.root.calls, ['status', 'prepareRoute', 'prepare', 'resume', 'stop', 'snapshot', 'reclaim',
    'status', 'prepareRoute', 'prepare', 'resume', 'stop', 'snapshot', 'reclaim']);
  assert.equal(session.exited, false, 'ending a run leaves the shared root session open');
  await f.trial.shutdownAll(); await until(() => session.exited);
  assert.equal(session.root.shutdowns(), 1); assert.equal(f.carrier.sessions.length, 1, 'quitting opens no new session');
  assert.equal(JSON.stringify({ first, second }).includes('PRIVATE_SHARED_'), false);
});

test('quitting after a channel was acquired but before any request was sent opens no session', async () => {
  // The state the failed first attach left behind in the packaged build.
  const f = attachFixture();
  f.trial.acquireRunChannel(randomUUID());
  await f.trial.shutdownAll();
  assert.equal(f.carrier.sessions.length, 0, 'no administrator dialog appears on quit');
});

test('a cancelled password dialog fails at once, holds nothing, and the next attach in the same launch works', async () => {
  /* A refusal at AuthorizationCopyRights (a cancelled dialog) comes before any
   * privileged process could run. It used to latch "cleanup required", so the
   * only way to try again was to restart Envara. */
  const f = attachFixture({ refuseFirst: true });
  const startedAt = Date.now();
  const refused = await f.attach();
  assert.ok(Date.now() - startedAt < 5000, 'the pending request does not wait out its deadline');
  assert.equal(refused.errorCode, 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
  assert.equal(refused.initialFailure?.code, 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
  assert.equal(refused.cleanupUncertain, false); assert.equal(refused.phase, 'failed');
  assert.equal(f.trial.mux.snapshot().ended, true, 'the refused session is not reused');
  const retried = await f.attach();
  assert.equal(retried.phase, 'cleaned', JSON.stringify(retried.events));
  assert.equal(f.carrier.sessions.length, 2, 'the retry asks for authorization again in a new session');
  await f.trial.shutdownAll();
});
test('a refusal once a privileged process may have started stays fail-closed', async () => {
  const f = attachFixture({ refuseFirst: true, refusalStage: 'AuthorizationExecuteWithPrivileges' });
  const refused = await f.attach();
  assert.equal(refused.errorCode, 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
  assert.equal(refused.cleanupUncertain, true, 'a later stage cannot prove that nothing ran');
  await f.trial.shutdownAll();
});
test('a run refused at its first status check holds nothing, demands no cleanup and leaves the next attach possible', async () => {
  const f = attachFixture({ canCreate: false });
  const refused = await f.attach();
  assert.equal(refused.errorCode, 'PF_OWNED_RUNTIME_NOT_EMPTY');
  assert.equal(refused.statusOnlyRunDetached, true); assert.equal(refused.statusOnlySessionClosed, false);
  assert.equal(refused.cleanupUncertain, false); assert.equal(refused.phase, 'failed');
  f.setCanCreate(true);
  const next = await f.attach();
  assert.equal(next.phase, 'cleaned', JSON.stringify(next.events)); assert.equal(f.carrier.sessions.length, 1);
  await f.trial.shutdownAll();
});

test('a preparation refused before its run exists is not stopped, holds nothing, and the next attach in the same launch works', async () => {
  /* The second attach of a launch was refused this way, then asked to stop a
   * run that never existed, and showed "cleanup unconfirmed" with every later
   * attach refused until Envara restarted. */
  let refuse = true;
  const f = attachFixture({ refusePrepare: () => refuse });
  const refused = await f.attach();
  assert.equal(refused.errorCode, 'APPLICATION_ROUTING_NOT_READY');
  assert.equal(refused.phase, 'failed'); assert.equal(refused.cleanupUncertain, false); assert.equal(refused.refusedRunDetached, true);
  assert.equal(refused.cleanupFailure, null, 'a refusal is not reported as a cleanup failure');
  const session = f.carrier.sessions[0];
  assert.deepEqual(session.root.calls, ['status', 'prepareRoute', 'prepare', 'status']);
  refuse = false;
  const next = await f.attach();
  assert.equal(next.phase, 'cleaned', JSON.stringify(next.events)); assert.equal(f.carrier.sessions.length, 1, 'no second password');
  await f.trial.shutdownAll();
});
test('a refused route preparation holds nothing and leaves the next attach possible', async () => {
  let refuse = true;
  const f = attachFixture({ refusePrepareRoute: () => refuse });
  const refused = await f.attach();
  assert.equal(refused.errorCode, 'APPLICATION_PROXY_UNAVAILABLE');
  assert.equal(refused.phase, 'failed'); assert.equal(refused.cleanupUncertain, false); assert.equal(refused.refusedRunDetached, true);
  assert.deepEqual(f.carrier.sessions[0].root.calls, ['status', 'prepareRoute', 'status']);
  refuse = false;
  assert.equal((await f.attach()).phase, 'cleaned');
  await f.trial.shutdownAll();
});
test('a refused preparation whose route the controller still lists stays fail-closed', async () => {
  const f = attachFixture({ refusePrepare: () => true, leaveRoute: () => true });
  const refused = await f.attach();
  assert.equal(refused.refusedRunDetached, false); assert.equal(refused.cleanupUncertain, true); assert.equal(refused.phase, 'cleanup-required');
  await f.trial.shutdownAll();
});

test('a preparation answered with a run is never taken for a refusal, even when no run is listed', async () => {
  const f = attachFixture({ answerUnstaged: () => true });
  const answered = await f.attach();
  assert.equal(answered.refusedRunDetached, false); assert.equal(answered.cleanupUncertain, true);
  await f.trial.shutdownAll();
});

test('a request in flight fails at once when the shared session ends under it', async () => {
  const f = attachFixture({ dieOnPrepareRoute: true });
  const startedAt = Date.now();
  const report = await f.attach();
  assert.ok(Date.now() - startedAt < 5000, 'the pending request does not wait out its deadline');
  assert.ok(['PF_HELPER_UNEXPECTED_EXIT', 'PF_HELPER_UNAVAILABLE'].includes(report.errorCode), report.errorCode);
  assert.equal(report.cleanupUncertain, true, 'a session lost mid-preparation is never reported clean');
  assert.equal(f.trial.mux.snapshot().ended, true);
  await f.trial.shutdownAll();
});

/* Each of the two ways the shared channel reports trouble must fail a request
 * in flight on its own; when the carrier exits the mux sends both, which is
 * why the run above cannot tell them apart. */
async function hungStatus() {
  const carrier = carrierFactory({ hangStatus: true });
  const mux = createPFAuthorizedChannelMux({ spawnRootControlledLifecycle: carrier.spawnCarrier });
  const runId = randomUUID(), target = mux.acquire({ key: runId });
  const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: null, acquireChannel: () => target,
    lifetimeMs: Infinity, channelKey: runId });
  const request = call('status', { runId }, { timeoutMs: 5000 }); request.catch(() => {});
  await until(() => carrier.sessions[0]?.root.calls.includes('status'));
  return { carrier, mux, target, call, request };
}
test('a shared channel error fails the request in flight at once, while the carrier itself stays up', async () => {
  const value = await hungStatus(), startedAt = Date.now();
  // A garbled carrier frame: the mux reports it as an error and nothing closes,
  // because the root helper is still busy with the hung request.
  value.carrier.sessions[0].child.stdout.write('not a frame\n');
  await assert.rejects(value.request, { code: 'PF_HELPER_UNAVAILABLE' });
  assert.ok(Date.now() - startedAt < 2000); assert.equal(value.carrier.sessions[0].exited, false);
  assert.equal((await value.call.close({ timeoutMs: 200 })).cleanupUncertain, true);
});
test('a shared channel closed without an error fails the request in flight at once', async () => {
  const value = await hungStatus(), startedAt = Date.now();
  value.target.end();
  await assert.rejects(value.request, { code: 'PF_HELPER_UNEXPECTED_EXIT' });
  assert.ok(Date.now() - startedAt < 2000);
  assert.equal((await value.call.close({ timeoutMs: 200 })).cleanupUncertain, true);
});

test('the same environment reaches the same environment id on every attach, so its data is kept', async () => {
  /* Environment ids are not UUIDs, and a random one used to replace them on
   * every attach: each attach started logged out and left its data behind. */
  const f = attachFixture();
  await f.attach(); await f.attach();
  const [first, second] = f.carrier.sessions[0].root.prepared;
  assert.equal(first.environmentId, second.environmentId);
  assert.notEqual(first.runId, second.runId, 'each attach is still its own run');
  await f.trial.shutdownAll();
});
test('storage is listed and removed on a channel of its own, never while an application is attached', async () => {
  const f = attachFixture();
  const listed = await f.trial.applicationStorage();
  assert.equal(listed.registrations[0].bundle, '/Applications/Notion.app'); assert.equal(listed.environments[0].bytes, 141000000);
  const removed = await f.trial.reclaimApplicationStorage({ registrationIds: [storageIds.registration], environmentIds: [storageIds.environment] });
  assert.deepEqual(removed.registrations, [{ registrationId: storageIds.registration, outcome: 'deleted' }]);
  assert.deepEqual(f.carrier.sessions[0].root.reclaimed, [{ registrationIds: [storageIds.registration], environmentIds: [storageIds.environment] }]);
  assert.equal(f.carrier.sessions.length, 1, 'the same authorized session serves storage and attaching');
  await assert.rejects(f.trial.reclaimApplicationStorage({ registrationIds: ['not-a-uuid'], environmentIds: [] }), { code: 'PF_HELPER_REQUEST_INVALID' });
  /* While an attach is in progress, storage is not touched. */
  const attaching = f.attach();
  await assert.rejects(f.trial.applicationStorage(), { code: 'PF_NOTION_TRIAL_BUSY' });
  await attaching;
  await f.trial.shutdownAll();
});

test('a confirmed stop removes that run\'s copy and caches on the open session; sign-in data and the session stay', async () => {
  const f = attachFixture();
  const done = await f.attach();
  assert.equal(done.phase, 'cleaned');
  const outcome = await f.trial.housekeeping;
  const session = f.carrier.sessions[0], registrationId = '4bf0f214-bcaa-4cea-af6f-b7e29800b4c5';
  assert.deepEqual(session.root.reclaimed, [{ registrationIds: [registrationId], environmentIds: [] }], 'only the copy, never the data');
  assert.equal(outcome.copy, 'deleted'); assert.equal(outcome.cacheBytesFreed, 1024);
  assert.equal(f.pruned.length, 1); assert.equal(f.pruned[0].registrationId, registrationId);
  assert.equal(f.carrier.sessions.length, 1); assert.equal(session.exited, false, 'cleanup opens no session and closes none');
  await f.trial.shutdownAll();
});

test('quitting right after a stop waits for its housekeeping before the session closes', async () => {
  const f = attachFixture();
  const run = f.attach();
  await run;
  await f.trial.shutdownAll();
  const session = f.carrier.sessions[0];
  assert.ok(session.root.calls.indexOf('reclaim') > session.root.calls.indexOf('snapshot'));
  assert.equal(f.pruned.length, 1);
  await until(() => session.exited); assert.equal(session.root.shutdowns(), 1);
});

test('a run without confirmed cleanup, and a session that ended, get no housekeeping and no new session', async () => {
  const refused = attachFixture({ refusePrepare: () => true });
  const result = await refused.attach();
  assert.notEqual(result.phase, 'cleaned');
  assert.equal(refused.trial.housekeeping, null);
  assert.ok(!refused.carrier.sessions[0].root.calls.includes('reclaim'));
  await refused.trial.shutdownAll();
  const ended = attachFixture();
  await ended.attach(); await ended.trial.housekeeping; await ended.trial.disposeShared();
  const outcome = await ended.trial.scheduleHousekeeping(request());
  assert.equal(outcome.copy, 'failed', 'an ended session is not reopened for cleanup');
  assert.equal(ended.carrier.sessions.length, 1, 'no administrator prompt for housekeeping');
});
