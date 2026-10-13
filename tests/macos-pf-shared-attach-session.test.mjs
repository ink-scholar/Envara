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
function rootSession({ canCreate, onPrepareRoute, hangStatus = false }) {
  const calls = []; let bound = null, shutdowns = 0;
  const statusController = new MacOSPFController({ inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
    identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, executor: { readOnlyStatus: async ({ runId } = {}) => ({ consoleUID: 501,
      pf: { priorAnchorsCompatible: true, lo0FilteringVerified: true }, ownedRootHook: { canCreateOwnedHook: Boolean(runId) && canCreate(),
        pfDisabled: true, pinsVerified: true, originalRootCompatible: true } }) } });
  const state = phase => ({ ...flags, ...bound, profile: 'seatbelt-front-only', phase, staged: true, resumed: phase === 'running', cleanupComplete: false, cleanupUncertain: false });
  const cleanup = () => ({ ...state('cleaned'), cleanupComplete: true, cleanupEvidence: { schema: 'envara.macos-pf-notion-cleanup/v1',
    source: 'native-notion-controller', ...bound, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false,
    ...Object.fromEntries(facts.map(key => [key, true])) } });
  const controller = { closed: false,
    status: async params => { calls.push('status'); return hangStatus ? new Promise(() => {}) : statusController.status(params); },
    prepareRoute: async value => { calls.push('prepareRoute'); if (onPrepareRoute) return onPrepareRoute();
      return { routeId: 'route_owned', profileId: value.application.profileId, ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false }; },
    prepareNotionApplication: async value => { calls.push('prepare'); bound = { runId: value.runId, environmentId: value.environmentId }; return state('staged'); },
    resumeNotionApplication: async () => { calls.push('resume'); return state('running'); },
    stopNotionApplication: async () => { calls.push('stop'); return cleanup(); },
    applicationSnapshot: async () => { calls.push('snapshot'); return cleanup(); },
    shutdown: async () => { shutdowns++; calls.push('shutdown'); return { closed: true, cleanupRequired: false }; } };
  return { controller, calls, shutdowns: () => shutdowns };
}

/** Stands in for the authorization carrier: each spawn is one root session. */
function carrierFactory({ canCreate = () => true, refuseFirst = false, dieOnPrepareRoute = false, hangStatus = false } = {}) {
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
      setImmediate(() => { child.stdout.write(`${JSON.stringify(refusalFrame)}\n`); child.stdout.end(); exit(1); });
      return child;
    }
    session.root = rootSession({ canCreate, hangStatus,
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
  const trial = new MacOSPFNotionTrial({ authorizerPath: '/fixture/EnvaraPFInstall', verifyCandidate: async () => true,
    verifyNotion: async () => true, watchMs: 0, spawnCarrier: carrier.spawnCarrier });
  return { trial, carrier, setCanCreate: value => { canCreate = value; },
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
  assert.deepEqual(session.root.calls, ['status', 'prepareRoute', 'prepare', 'resume', 'stop', 'snapshot',
    'status', 'prepareRoute', 'prepare', 'resume', 'stop', 'snapshot']);
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

test('a refused authorization fails the attach at once with its own reason and the ended session is not reused', async () => {
  const f = attachFixture({ refuseFirst: true });
  const startedAt = Date.now();
  const refused = await f.attach();
  assert.ok(Date.now() - startedAt < 5000, 'the pending request does not wait out its deadline');
  assert.equal(refused.errorCode, 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
  assert.equal(refused.initialFailure?.code, 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED');
  // A refused authorization stays fail-closed, as the session contract requires.
  assert.equal(refused.cleanupUncertain, true);
  assert.equal(f.trial.mux.snapshot().ended, true);
  const replacement = f.trial.ensureMux();
  assert.equal(replacement.snapshot().ended, false); assert.equal(replacement.snapshot().spawned, false);
  assert.equal(f.carrier.sessions.length, 1);
  await f.trial.shutdownAll(); assert.equal(f.carrier.sessions.length, 1);
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
