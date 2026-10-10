import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import { realpath } from 'node:fs/promises';
import { MacOSPFNotionTrial } from '../electron/macos-pf-notion-trial.mjs';
import { MacOSPFApplicationRouting } from '../electron/macos-pf-application-routing.mjs';
import { createPersistentPFNotionSessionClient } from '../electron/macos-pf-notion-session.mjs';
import { servePFHelper } from '../native/macos-pf-routing/helper.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';
import { MacOSPFController } from '../native/macos-pf-routing/controller.mjs';

// The production JSONL client/helper framing is exercised with an inert peer.
// No authorizer, OS command, app, proxy, network or native helper is started.
const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false, udpSupported: false };
const facts = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
  'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
  'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const request = () => ({ application: { id: 'notion_bound', profileId: 'owned_profile', executablePath: '/Applications/Notion.app/Contents/MacOS/Notion' },
  workspace: { cwd: '/tmp', timezone: 'Asia/Manila', locale: 'en-PH', timezoneSource: 'proxy-egress' },
  route: { protocol: 'socks5', host: '127.0.0.1', port: 20101, username: 'PRIVATE_TRIAL_USERNAME', password: 'PRIVATE_TRIAL_PASSWORD', udpPolicy: 'block' },
  managedRoute: { profileId: 'owned_profile', proxyId: 'owned_node', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 999, coreVersion: 'v1.19.32' } });
function fixture({ dirty = false, selectedRefused = false, missingEOF = false, foreignSnapshot = false, foreignStatus = false,
  resumeFailure = false, snapshotFailure = false, prepareDelayMs = 0, prepareTimeoutMs = null, resumeDelayMs = 0, now,
  diagnosticOverride = null, onEvent = () => {}, observationMs = 0 } = {}) {
  const input = new PassThrough(), child = new EventEmitter(), calls = [], statusRequests = []; let bound, stageResolve;
  const running = new Promise(resolve => { stageResolve = resolve; });
  const state = phase => ({ ...flags, ...bound, profile: 'seatbelt-front-only', phase, staged: true, resumed: phase === 'running', cleanupComplete: false, cleanupUncertain: false });
  const cleanup = () => ({ ...state('cleaned'), cleanupComplete: true, cleanupEvidence: {
    schema: 'envara.macos-pf-notion-cleanup/v1', source: 'native-notion-controller', ...bound, profile: 'seatbelt-front-only', complete: true, cleanupUncertain: false,
    ...Object.fromEntries(facts.map(key => [key, true])) } });
  const statusController = new MacOSPFController({ inspectInstallation: async () => ({ verified: true, runtimeVerified: true }),
    identity: { uid: 0, euid: 0, callerUID: 501, controlledSession: true }, executor: { readOnlyStatus: async ({ runId } = {}) => ({ consoleUID: 501,
      pf: { priorAnchorsCompatible: true, lo0FilteringVerified: true }, ownedRootHook: { canCreateOwnedHook: Boolean(runId) && !dirty && !selectedRefused,
        pfDisabled: true, pinsVerified: true, originalRootCompatible: true } }) } });
  if (dirty) statusController.runs.set('old', { runId: randomUUID(), phase: 'cleanup-required', cleanupUncertain: true });
  const controller = { closed: false,
    status: async params => { statusRequests.push(params); const result = await statusController.status(params);
      if (foreignStatus) result.anchor = pfRoutingAnchor(randomUUID()); return result; },
    prepareRoute: async value => { calls.push('prepareRoute'); assert.equal(value.route.password, 'PRIVATE_TRIAL_PASSWORD');
      return { routeId: 'route_owned', profileId: value.application.profileId, ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false }; },
    prepareNotionApplication: async value => { calls.push('prepare'); assert.equal(value.runId, statusRequests[0].runId);
      bound = { runId: value.runId, environmentId: value.environmentId };
      if (prepareDelayMs) await new Promise(resolve => setTimeout(resolve, prepareDelayMs)); return state('staged'); },
    resumeNotionApplication: async () => { calls.push('resume'); stageResolve();
      if (resumeDelayMs) await new Promise(resolve => setTimeout(resolve, resumeDelayMs));
      if (resumeFailure) throw Object.assign(new Error('PRIVATE_TRIAL_PASSWORD'), { code: 'APPLICATION_APP_RESUME_UNCONFIRMED' }); return state('running'); },
    stopNotionApplication: async () => { calls.push('stop'); return cleanup(); },
    applicationSnapshot: async () => { calls.push('snapshot'); const value = cleanup();
      if (snapshotFailure) return { ...state('cleanup-required'), cleanupUncertain: true,
        failure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED',
          native: { stage: 'ticket-prepare', reason: 'NATIVE_OPERATION_REFUSED', error: 70 } }, private: 'PRIVATE_TRIAL_PASSWORD' };
      if (foreignSnapshot) value.environmentId = value.cleanupEvidence.environmentId = randomUUID(); return value; },
    shutdown: async () => { calls.push('shutdown'); return { closed: true, cleanupRequired: false }; } };
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { input.end(); return true; };
  child.stdin = new Writable({ write(bytes, encoding, done) { input.write(Buffer.from(bytes)); done(); }, final(done) { input.end(); done(); } });
  let starts = 0;
  const trial = new MacOSPFNotionTrial({ verifyCandidate: async () => true, verifyNotion: async () => true, observationMs, onEvent,
    createClient: () => {
      const call = createPersistentPFNotionSessionClient({ ...(now ? { now } : {}), spawnRootControlledLifecycle: () => {
      starts++; servePFHelper({ controller, input, output: child.stdout, signalSource: null }).then(() => {
        if (!missingEOF) child.stdout.end(); setImmediate(() => child.emit('close', 0, null)); }); return child;
      } });
      const controlled = (method, params, options) => call(method, params, method === 'prepareNotionApplication' && prepareTimeoutMs !== null
        ? { ...options, timeoutMs: prepareTimeoutMs } : options);
      controlled.close = call.close;
      controlled.snapshot = () => { const value = call.snapshot();
        if (diagnosticOverride) diagnosticOverride(value.diagnostics, bound); return value; };
      return controlled;
    } });
  return { trial, calls, running, statusRequests, starts: () => starts };
}
const run = value => value.trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: true });

test('candidate mismatch and invalid approval/schema never create a channel', async () => {
  let starts = 0;
  const trial = new MacOSPFNotionTrial({ verifyCandidate: async () => { throw Object.assign(new Error('PRIVATE_TRIAL_PASSWORD'), { code: 'PF_INSTALLED_CANDIDATE_MISMATCH' }); },
    createClient: () => { starts++; throw new Error(); } });
  assert.equal((await trial.available()).errorCode, 'PF_INSTALLED_CANDIDATE_MISMATCH');
  const value = await trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: true });
  assert.equal(value.errorCode, 'PF_INSTALLED_CANDIDATE_MISMATCH'); assert.equal(value.cleanupUncertain, false); assert.equal(starts, 0);
  await assert.rejects(trial.run({ request: request(), applicationId: 'notion_bound', activationAuthorized: false }), { code: 'PF_NOTION_TRIAL_REQUEST_INVALID' });
  const changed = request(); changed.route.addressOverride = 'private';
  await assert.rejects(trial.run({ request: changed, applicationId: 'notion_bound', activationAuthorized: true }), { code: 'PF_NOTION_TRIAL_REQUEST_INVALID' });
  assert.equal(JSON.stringify(value).includes('PRIVATE_TRIAL_PASSWORD'), false); assert.equal(trial.snapshot('foreign').phase, 'idle');
});

test('real client framing requires prepare/resume/stop/fresh receipt/actual EOF for a successful bounded trial', async () => {
  const events = [], value = fixture({ onEvent: event => events.push(event) }); const report = await run(value);
  assert.deepEqual(value.calls, ['prepareRoute', 'prepare', 'resume', 'stop', 'snapshot', 'shutdown']);
  assert.equal(value.starts(), 1); assert.equal(report.phase, 'cleaned'); assert.equal(report.lifecyclePassed, true);
  assert.deepEqual(value.statusRequests, [{ runId: report.runId }]);
  assert.equal(report.cleanupComplete, true); assert.equal(report.cleanupUncertain, false);
  for (const key of Object.keys(flags)) assert.equal(report[key], false);
  assert.equal(report.maximumLifetimeSeconds, 180); assert.equal(events.some(event => event.stage === 'running'), true);
  assert.equal(report.sessionDiagnostics.terminalExitCode, 0);
  assert.deepEqual(report.sessionDiagnostics.callHistory, ['status', 'prepareRoute', 'prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot']);
  assert.equal(JSON.stringify({ report, events }).includes('PRIVATE_TRIAL_'), false);
});
test('multi-step preparation can exceed 60 seconds without the client abandoning the bound native stage', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const value = fixture({ prepareDelayMs: 65000 }), completion = run(value);
  // Drain the real stream framing until the controller begins preparation.
  while (!value.calls.includes('prepare')) await new Promise(resolve => setImmediate(resolve));
  t.mock.timers.tick(60001);
  assert.equal(value.trial.snapshot().errorCode, null);
  assert.equal(value.calls.includes('resume'), false);
  t.mock.timers.tick(4999);
  const report = await completion;
  assert.equal(report.lifecyclePassed, true); assert.equal(report.cleanupComplete, true);
  assert.equal(report.maximumLifetimeSeconds, 180);
  for (const key of Object.keys(flags)) assert.equal(report[key], false);
});

test('resume covers slow controller preflight and cold validation beyond 15 seconds with a fixed 60 second budget', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let current = 0;
  const value = fixture({ resumeDelayMs: 20000, now: () => current }), completion = run(value);
  while (!value.calls.includes('resume')) await new Promise(resolve => setImmediate(resolve));
  current = 15001; t.mock.timers.tick(15001);
  assert.equal(value.trial.snapshot().errorCode, null); assert.equal(value.trial.snapshot().resumed, false);
  current = 20000; t.mock.timers.tick(4999);
  const report = await completion, timing = report.sessionDiagnostics.callTimings.find(item => item.method === 'resumeNotionApplication');
  assert.equal(report.lifecyclePassed, true); assert.equal(report.maximumLifetimeSeconds, 180);
  assert.equal(timing.requestedTimeoutMs, 60000); assert.equal(timing.effectiveTimeoutMs, 60000);
  assert.equal(timing.elapsedMs, 20000); assert.equal(timing.cleanupReserveMs, 40000); assert.equal(timing.outcome, 'result');
  assert.equal(timing.lateResponseObserved, false); assert.equal(JSON.stringify(report).includes('PRIVATE_TRIAL_'), false);
});

test('cold staging shortens resume to preserve 40 seconds of cleanup and a late ACK never admits the child', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let current = 0;
  const value = fixture({ prepareDelayMs: 100000, resumeDelayMs: 50000, now: () => current }), completion = run(value);
  while (!value.calls.includes('prepare')) await new Promise(resolve => setImmediate(resolve));
  current = 100000; t.mock.timers.tick(100000);
  while (!value.calls.includes('resume')) await new Promise(resolve => setImmediate(resolve));
  current = 139999; t.mock.timers.tick(39999); assert.equal(value.trial.snapshot().errorCode, null);
  current = 140000; t.mock.timers.tick(1);
  while (value.trial.snapshot().phase !== 'stopping') await new Promise(resolve => setImmediate(resolve));
  assert.equal(value.trial.snapshot().resumed, false);
  current = 150000; t.mock.timers.tick(10000);
  const report = await completion, timing = report.sessionDiagnostics.callTimings.find(item => item.method === 'resumeNotionApplication');
  assert.equal(timing.requestedTimeoutMs, 60000); assert.equal(timing.effectiveTimeoutMs, 40000);
  assert.equal(timing.remainingMsAtStart, 80000); assert.equal(timing.remainingMsAtFinish, 40000);
  assert.equal(timing.outcome, 'deadline'); assert.equal(timing.lateResponseObserved, true);
  assert.equal(report.errorCode, 'PF_HELPER_DEADLINE'); assert.equal(report.resumed, false);
  assert.equal(report.lifecyclePassed, false); assert.equal(report.cleanupUncertain, true);
  assert.deepEqual(value.calls, ['prepareRoute', 'prepare', 'resume', 'stop', 'snapshot', 'shutdown']);
});

test('timing projection discards malformed fields and cannot expose credentials or change lifecycle evidence', async () => {
  for (const change of [{ private: 'PRIVATE_TRIAL_PASSWORD' }, { cleanupReserveMs: 0 }, { elapsedMs: 'PRIVATE_TRIAL_PASSWORD' }]) {
    const value = fixture({ diagnosticOverride: diagnostic => Object.assign(diagnostic.callTimings[0], change) }), report = await run(value);
    assert.equal(Object.hasOwn(report.sessionDiagnostics, 'callTimings'), false);
    assert.equal(JSON.stringify(report).includes('PRIVATE_TRIAL_'), false); assert.equal(report.lifecyclePassed, true);
  }
});

test('old owned runtime is refused before prepare and clean outer EOF cannot erase uncertainty', async () => {
  const value = fixture({ dirty: true }); const report = await run(value);
  assert.equal(report.errorCode, 'PF_OWNED_RUNTIME_NOT_EMPTY'); assert.equal(report.phase, 'cleanup-required');
  assert.equal(report.cleanupUncertain, true); assert.equal(report.lifecyclePassed, false); assert.deepEqual(value.calls, ['shutdown']);
  await assert.rejects(run(value), { code: 'PF_OWNED_RUNTIME_NOT_EMPTY' });
});

test('foreign selected status scope cannot prepare or erase the failed trial through normal EOF', async () => {
  const value = fixture({ foreignStatus: true }); const report = await run(value);
  assert.equal(report.errorCode, 'PF_HELPER_RESPONSE_INVALID'); assert.equal(report.phase, 'cleanup-required');
  assert.equal(report.cleanupUncertain, true); assert.equal(report.resumed, false); assert.equal(report.lifecyclePassed, false);
  assert.deepEqual(value.calls, ['shutdown']); assert.equal(report.sessionDiagnostics.uncertaintyLatched, true);
});

test('a refused selected namespace with empty fresh inventories closes only its status-only session, without launching or claiming cleanup', async () => {
  const value = fixture({ selectedRefused: true }), report = await run(value);
  assert.equal(report.errorCode, 'PF_OWNED_RUNTIME_NOT_EMPTY'); assert.equal(report.phase, 'failed');
  assert.equal(report.statusOnlySessionClosed, true); assert.equal(report.cleanupUncertain, false);
  assert.equal(report.cleanupComplete, false); assert.equal(report.lifecyclePassed, false); assert.equal(report.staged, false); assert.equal(report.resumed, false);
  assert.deepEqual(value.calls, ['shutdown']); assert.deepEqual(report.sessionDiagnostics.callHistory, ['status']);
  for (const key of Object.keys(flags)) assert.equal(report[key], false);
});

test('the same status-only refusal without actual EOF retains its cleanup uncertainty', async () => {
  const value = fixture({ selectedRefused: true, missingEOF: true }), report = await run(value);
  assert.equal(report.errorCode, 'PF_OWNED_RUNTIME_NOT_EMPTY'); assert.equal(report.phase, 'cleanup-required');
  assert.equal(report.statusOnlySessionClosed, false); assert.equal(report.cleanupUncertain, true);
  assert.equal(report.sessionDiagnostics.stdoutEOF, false); assert.deepEqual(value.calls, ['shutdown']);
  await assert.rejects(run(value), { code: 'PF_OWNED_RUNTIME_NOT_EMPTY' });
});

test('foreign cleanup snapshot cannot be laundered by valid stop and normal outer EOF', async () => {
  const value = fixture({ foreignSnapshot: true }); const report = await run(value);
  assert.equal(report.phase, 'cleanup-required'); assert.equal(report.cleanupComplete, false); assert.equal(report.cleanupUncertain, true);
  assert.equal(report.lifecyclePassed, false);
});

test('stop interrupts only observation, serializes normal cleanup, and refuses a simultaneous trial', async () => {
  const value = fixture({ observationMs: 45000 }); const pending = run(value); await value.running;
  await assert.rejects(run(value), { code: 'PF_NOTION_TRIAL_BUSY' });
  value.trial.stop('foreign'); assert.equal(value.trial.snapshot('notion_bound').active, true);
  value.trial.stop('notion_bound'); const report = await pending;
  assert.equal(report.stopRequested, true); assert.equal(report.cleanupComplete, true); assert.equal(report.active, false);
  assert.equal(value.calls.filter(method => method === 'stop').length, 1);
});

test('native failure and async rejected logger cannot skip cleanup or expose raw errors', async () => {
  const value = fixture({ resumeFailure: true, onEvent: async () => { throw new Error('PRIVATE_TRIAL_PASSWORD'); } }); const report = await run(value);
  assert.equal(report.errorCode, 'APPLICATION_APP_RESUME_UNCONFIRMED'); assert.equal(report.lifecyclePassed, false);
  assert.equal(report.cleanupComplete, true); assert.equal(report.resumed, false);
  assert.equal(JSON.stringify(report).includes('PRIVATE_TRIAL_PASSWORD'), false);
});

test('fresh bound failure diagnostics reach the final log, while late prepare remains abandoned despite positive cleanup', async () => {
  for (const variant of ['fresh-failure', 'late-prepare']) {
    const events = [], value = fixture({ onEvent: event => events.push(event),
      ...(variant === 'fresh-failure' ? { snapshotFailure: true } : { prepareDelayMs: 60, prepareTimeoutMs: 10 }) });
    const report = await run(value), final = events.at(-1);
    assert.equal(report.phase, 'cleanup-required'); assert.equal(report.cleanupUncertain, true);
    assert.equal(report.cleanupComplete, false); assert.equal(report.lifecyclePassed, false);
    assert.equal(final.stage, 'cleanup-required'); assert.deepEqual(final.diagnostics, report.sessionDiagnostics);
    if (variant === 'fresh-failure') {
      assert.equal(final.diagnostics.lastApplicationSnapshot.failure.stage, 'cold-stage');
      assert.equal(final.diagnostics.lastApplicationSnapshot.failure.native.error, 70);
    } else {
      assert.equal(report.errorCode, 'PF_HELPER_DEADLINE'); assert.equal(report.staged, false); assert.equal(report.resumed, false);
      assert.equal(final.diagnostics.lastLatePrepare.phase, 'staged'); assert.equal(final.diagnostics.lastLatePrepare.diagnosticOnly, true);
      assert.equal(final.diagnostics.uncertaintyLatched, true); assert.equal(value.calls.includes('resume'), false);
    }
    assert.equal(JSON.stringify({ report, events }).includes('PRIVATE_TRIAL_PASSWORD'), false);
  }
});

test('final diagnostic logs reject a foreign source, environment or numeric bool from an injected client', async () => {
  for (const variant of ['source', 'environment', 'boolean']) {
    const events = [], value = fixture({ onEvent: event => events.push(event), diagnosticOverride: (diagnostics, bound) => {
      const diagnostic = diagnostics.lastApplicationSnapshot;
      assert.equal(diagnostic.runId, bound.runId);
      if (variant === 'source') diagnostic.source = 'PRIVATE_TRIAL_PASSWORD';
      if (variant === 'environment') diagnostic.environmentId = randomUUID();
      if (variant === 'boolean') diagnostic.diagnosticOnly = 1;
      // Do not let the valid directly returned snapshot replace this fixture's
      // intentionally invalid client-only late-response diagnostic.
      diagnostics.lastLatePrepare = { ...diagnostic, method: 'prepareNotionApplication' };
    } });
    const report = await run(value);
    assert.equal(report.sessionDiagnostics.lastLatePrepare, null);
    assert.equal(events.at(-1).diagnostics.lastLatePrepare, null);
    assert.equal(JSON.stringify({ report, events }).includes('PRIVATE_TRIAL_PASSWORD'), false);
  }
});

test('uncertain trial prevents adapter from reporting clean shutdown or installing over an active trial', async () => {
  let shutdowns = 0;
  const trial = { state: { cleanupUncertain: true }, pending: null };
  const adapter = new MacOSPFApplicationRouting({ notionTrial: trial, native: { shutdown: async () => { shutdowns++; } } });
  await assert.rejects(adapter.shutdown(), { code: 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED' });
  assert.equal(shutdowns, 0); assert.equal(adapter.closed, false);
});

test('adapter projects only private exact context into the dedicated trial and never changes generic readiness', async () => {
  const cwd = await realpath(os.tmpdir()); let passed;
  const application = { id: 'notion_bound', profileId: 'owned_profile', path: '/Applications/Notion.app', executablePath: '/Applications/Notion.app/Contents/MacOS/Notion', identity: 'bundle:notion.id', name: 'Notion', args: [] };
  const value = request(); const context = { profileId: application.profileId, cwd, timezone: 'Asia/Manila', timezoneSource: 'manual', locale: 'en-PH', privacy: { mode: 'standard' },
    network: { ok: true, ip: '203.0.113.7' }, proxyEndpoint: { ...value.route, udp: true }, managedRoute: value.managedRoute };
  const trial = { available: async () => ({ controlledNotionTrialAvailable: true }), run: async params => { passed = params; return flags; } };
  const adapter = new MacOSPFApplicationRouting({ native: { status: async () => ({ installed: true, backend: 'pf-utun', ready: false }) }, notionTrial: trial,
    inspectApplication: async () => application });
  await adapter.controlledNotionTrial({ application, context, activationAuthorized: true });
  assert.deepEqual(Object.keys(passed.request), ['application', 'workspace', 'route', 'managedRoute']);
  assert.deepEqual(Object.keys(passed.request.application), ['id', 'profileId', 'executablePath']);
  assert.equal(passed.request.route.udpPolicy, 'block'); assert.equal(Object.hasOwn(passed.request.route, 'udp'), false);
  assert.equal(passed.request.workspace.timezoneSource, 'fixed'); assert.equal((await adapter.status()).ready, false);
  await assert.rejects(adapter.controlledNotionTrial({ application, context: { ...context, network: { ok: false } }, activationAuthorized: true }), { code: 'PF_NOTION_TRIAL_CONTEXT_REQUIRED' });
  await assert.rejects(adapter.controlledNotionTrial({ application: { ...application, args: ['--anything'] }, context, activationAuthorized: true }), { code: 'PF_NOTION_TRIAL_REQUEST_INVALID' });
});
