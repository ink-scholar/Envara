import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { randomUUID, createHash } from 'node:crypto';
import { createPersistentPFNotionSessionClient, PF_NOTION_CHANNEL_LIFETIME_MS,
  validatePFNotionCallTimingDiagnostic,
  validatePFNotionCleanupReceipt, validatePFNotionPrestageCleanupReceipt, validatePFNotionPreflightCleanupReceipt } from '../electron/macos-pf-notion-session.mjs';
import { servePFHelper } from '../native/macos-pf-routing/helper.mjs';
import { runPFNotionAcceptance } from '../scripts/accept-macos-pf-notion.mjs';
import { pfRoutingAnchor } from '../native/macos-pf-routing/policy.mjs';

// All process fixtures below are inert Node peers. No native authorizer,
// privilege popup, PF command, application, proxy or network is invoked.
const flags = { ready: false, protected: false, productionReady: false, genericApplicationRouting: false,
  udpSupported: false, profile: 'seatbelt-front-only' };
const normalFacts = ['coreReaped', 'frontReaped', 'childReaped', 'scopeQuiescentObserved', 'originalUTunClosed', 'originalListenerClosed', 'filterEmptyVerified',
  'privateJournalRetired', 'transportExitConfirmed', 'ownedGIDProcessesAbsent', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored',
  'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const prestageFacts = ['coreReaped', 'frontReaped', 'originalUTunVerified', 'originalListenerVerified', 'originalUTunClosed', 'originalListenerClosed',
  'filterJournalAbsent', 'transportExitConfirmed', 'nativeGIDScopeAbsentBeforeExit', 'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved',
  'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed', 'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged',
  'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const prestageFalsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'denyAttempted', 'filterWriteAttempted', 'launchCommandAccepted', 'coldStageAttempted'];
const preflightFacts = ['sealedContextVerified', 'nativePrivateChildrenAbsentBeforeExit', 'nativeGIDScopeAbsentBeforeExit',
  'nativeOwnedFilterClassesEmptyBeforeExit', 'filterJournalAbsent', 'bootstrapExitConfirmed', 'ownedFilterEmptyAtCleanup',
  'ownedEffectiveGIDProcessesAbsentAtCleanup', 'ownedGroupsRemoved', 'ownedRootHookRemoved', 'originalRootRestored', 'namespaceReclaimed',
  'receiptRetired', 'ownedPFReferenceReleased', 'unrelatedPFUnchanged', 'unrelatedRoutesUnchanged', 'hostDNSUnchanged', 'sealedContextRetired', 'registryReleased'];
const preflightFalsehoods = ['staged', 'resumed', 'notionLaunched', 'lifecyclePassed', 'bootstrapAttempted', 'transportAttempted', 'filterWriteAttempted', 'coldStageAttempted'];
function cleanup(request, kind = 'normal') {
  const { runId, environmentId } = request;
  const facts = kind === 'normal' ? normalFacts : kind === 'prestage' ? prestageFacts : preflightFacts;
  const falsehoods = kind === 'normal' ? [] : kind === 'prestage' ? prestageFalsehoods : preflightFalsehoods;
  return { ...flags, runId, environmentId, phase: kind === 'normal' ? 'cleaned' : `${kind}-cleaned`,
    ...(kind === 'prestage' ? { prestageAborted: true, staged: false, resumed: false } : kind === 'preflight'
      ? { preflightAborted: true, prestageAborted: false, staged: false, resumed: false,
        failure: { stage: 'transport', code: 'APPLICATION_APP_NATIVE_REFUSED', native: { stage: 'preflight', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } } } : {}),
    cleanupComplete: true, cleanupUncertain: false, cleanupEvidence: { schema: `envara.macos-pf-notion${kind === 'normal' ? '' : `-${kind}`}-cleanup/v1`,
      source: 'native-notion-controller', runId, environmentId, profile: flags.profile, complete: true, cleanupUncertain: false,
      ...Object.fromEntries(facts.map(key => [key, true])), ...Object.fromEntries(falsehoods.map(key => [key, false])) } };
}
const request = () => ({ routeId: 'pf_fixture', runId: randomUUID(), environmentId: randomUUID(), lifetimeSeconds: 180, activationAuthorized: true });
function route() { return { application: { id: 'notion', profileId: 'owned', executablePath: '/Applications/Notion.app' },
  workspace: { cwd: '/tmp/owned', timezone: 'Asia/Manila', locale: 'en-PH', timezoneSource: 'proxy-egress' },
  route: { protocol: 'socks5', host: '127.0.0.1', port: 20101, username: 'session-fixture-user', password: 'session-fixture-secret', udpPolicy: 'block' },
  managedRoute: { profileId: 'owned', proxyId: 'node', nodeType: 'anytls', routeIdentity: randomUUID(), coreGeneration: randomUUID(), corePid: 999, coreVersion: 'v1.19.32' } }; }
const routed = { routeId: 'pf_fixture', profileId: 'owned', ready: false, failClosed: false, guardArmed: false, managedRouteVerified: false };
const stage = value => ({ ...flags, runId: value.runId, environmentId: value.environmentId,
  phase: 'staged', staged: true, resumed: false, cleanupComplete: false, cleanupUncertain: false });
const status = { ready: false, protectedLaunchAllowed: false, anchor: null, ownedRootHookCanCreate: false,
  readOnly: true, acceptanceOnly: true, productionReceiptAllowed: false, runs: [], applications: [], routes: [] };
const selectedStatus = (runId, changes = {}) => ({ ...status, anchor: pfRoutingAnchor(runId), ownedRootHookCanCreate: true, ...changes });

function peer(t, replies, { fragment = false, suffix = '', exitCode = 0, delayIndex = -1, delayMs = 0,
  duplicateIndex = -1, errorIndex = -1, stderr = '', now, credentialHash = null, initialFrame = null } = {}) {
  const source = `import readline from 'node:readline'; import {createHash} from 'node:crypto'; const replies=${JSON.stringify(replies)}; let index=0;
    if (${JSON.stringify(stderr)}) process.stderr.write(${JSON.stringify(stderr)});
    if (${JSON.stringify(initialFrame)}) process.stdout.write(JSON.stringify(${JSON.stringify(initialFrame)})+'\\n');
    readline.createInterface({input:process.stdin}).on('line',line=>{const r=JSON.parse(line); const i=index++;
      if (r.method==='prepareRoute' && ${JSON.stringify(credentialHash)} &&
        createHash('sha256').update(r.params.route.password).digest('hex')!==${JSON.stringify(credentialHash)}) process.exit(91);
      const result=replies.shift()??{}; const value=JSON.stringify(i===${errorIndex}
        ? {protocol:r.protocol,version:r.version,ok:false,id:r.id,error:{code:'APPLICATION_ROUTING_NOT_READY'}}
        : {protocol:r.protocol,version:r.version,ok:true,id:r.id,result})+'\\n';
      const send=()=>{if (${fragment}) {process.stdout.write(value.slice(0,13)); process.stdout.write(value.slice(13));}
        else process.stdout.write(value); if (i===${duplicateIndex}) process.stdout.write(value);};
      if (i===${delayIndex}) setTimeout(send,${delayMs}); else send();
    }).on('close',()=>{process.stdout.write(${JSON.stringify(suffix)});process.exitCode=${exitCode};});`;
  let child, spawnCount = 0; const spawnArgs = [];
  const call = createPersistentPFNotionSessionClient({ ...(now ? { now } : {}), spawnRootControlledLifecycle: () => {
    spawnCount++; spawnArgs.push(source);
    child = spawn(process.execPath, ['--input-type=module', '-e', source], { stdio: ['pipe', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin' } });
    return child;
  } });
  t.after(async () => { await call.close({ timeoutMs: 200 }); if (child && child.exitCode == null) child.kill('SIGTERM'); });
  return { call, spawnCount: () => spawnCount, spawnArgs };
}
async function prepare(call, value) { await call('prepareRoute', route()); await call('prepareNotionApplication', value); }
async function stopAndSnapshot(call, value) { const stopped = await call('stopNotionApplication', { runId: value.runId });
  const snapshot = await call('applicationSnapshot', { runId: value.runId }); return { stopped, snapshot }; }

test('construction and invalid schemas are inert and cannot select executable/credentials/activation overrides', async () => {
  let starts = 0; const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => { starts++; throw new Error(); } });
  const invalid = [['status', { activate: true }], ['status', { runId: randomUUID().toUpperCase() }],
    ['status', { runId: randomUUID(), extra: true }], ['status', { runId: true }], ['unknown', {}], ['prepareRoute', { ...route(), proof: true }],
    ['prepareNotionApplication', { ...request(), lifetimeSeconds: 181 }], ['resumeNotionApplication', { runId: randomUUID(), activationAuthorized: true }]];
  for (const [method, params] of invalid) await assert.rejects(call(method, params), { code: 'PF_HELPER_REQUEST_INVALID' });
  assert.equal(starts, 0); assert.equal(call.snapshot().ready, false); assert.equal(call.snapshot().maximumLifetimeSeconds, 180);
  assert.deepEqual(await call.close(), { closed: true, started: false, cleanupUncertain: false });
});

test('fixed authorizer refusals retain their code and discard native diagnostics and raw error messages', async t => {
  for (const variant of ['authorization', 'cleanup', 'invalid-diagnostic']) {
    const frame = { protocol: 'envara.application-routing', version: 1, id: null,
      error: { code: variant === 'cleanup' ? 'APPLICATION_ROUTING_CLEANUP_UNCONFIRMED' : 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED',
        message: 'INERT_REFUSAL_SECRET' }, ...(variant === 'cleanup' ? { terminal: true, cleanupUncertain: true }
        : { nativeAuthorization: { stage: 'AuthorizationCopyPrivilegedReference', status: -60007 } }) };
    if (variant === 'invalid-diagnostic') frame.nativeAuthorization.extra = 'INERT_REFUSAL_SECRET';
    const { call } = peer(t, [], { initialFrame: frame });
    await assert.rejects(call('status'), error => {
      assert.equal(error.code, variant === 'invalid-diagnostic' ? 'PF_HELPER_RESPONSE_INVALID' : frame.error.code);
      assert.equal(error.message.includes('INERT_REFUSAL_SECRET'), false); return true;
    });
    assert.equal(JSON.stringify(call.snapshot()).includes('INERT_REFUSAL_SECRET'), false);
    assert.equal((await call.close()).cleanupUncertain, true);
  }
});

test('permitted Notion state fields cannot echo nested credentials or a foreign route identity', async t => {
  for (const key of ['routeId', 'staged', 'resumed', 'prestageAborted', 'preflightAborted', 'cleanupComplete']) {
    const value = request(), changed = { ...stage(value), [key]: key === 'routeId' ? 'INERT_STATE_SECRET' : { password: 'INERT_STATE_SECRET' } };
    const { call } = peer(t, [routed, changed]); await call('prepareRoute', route());
    await assert.rejects(call('prepareNotionApplication', value), { code: 'PF_HELPER_RESPONSE_INVALID' });
    assert.equal(JSON.stringify(call.snapshot()).includes('INERT_STATE_SECRET'), false);
    assert.equal((await call.close()).cleanupUncertain, true);
  }
});

test('fixed native stage and errno cross result projection while malformed diagnostics and secrets are discarded', async t => {
  for (const stageName of ['ticket-prepare', 'relay-fork', 'guardian', 'register']) {
    const value = request(), native = { stage: stageName, reason: stageName === 'register' ? 'NATIVE_APP_OPERATION_REFUSED' : 'NATIVE_OPERATION_REFUSED', error: 13 };
    const failure = { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED', native, privatePath: 'INERT_DIAGNOSTIC_SECRET' };
    const { call } = peer(t, [routed, { ...stage(value), failure }]);
    await call('prepareRoute', route());
    const response = await call('prepareNotionApplication', value);
    assert.deepEqual(response.failure, { stage: 'cold-stage', code: failure.code, native });
    assert.equal(JSON.stringify(response).includes('INERT_DIAGNOSTIC_SECRET'), false);
  }
  for (const invalid of [{ stage: 'secret', reason: 'NATIVE_OPERATION_REFUSED', error: 13 },
    { stage: 'guardian', reason: 'INERT_DIAGNOSTIC_SECRET', error: 13 }, { stage: 'guardian', reason: 'NATIVE_OPERATION_REFUSED', error: true },
    { stage: 'guardian', reason: 'NATIVE_OPERATION_REFUSED', error: 1025 }, { stage: 'guardian', reason: 'NATIVE_OPERATION_REFUSED', error: 13, path: 'INERT_DIAGNOSTIC_SECRET' }]) {
    const value = request(), failure = { code: 'APPLICATION_APP_NATIVE_REFUSED', stage: 'cold-stage', native: invalid };
    const { call } = peer(t, [routed, { ...stage(value), failure }]); await call('prepareRoute', route());
    const response = await call('prepareNotionApplication', value);
    assert.deepEqual(response.failure, { code: failure.code, stage: 'cold-stage' });
    assert.equal(JSON.stringify(response).includes('INERT_DIAGNOSTIC_SECRET'), false);
  }
});

test('matched RPC errors retain only strict nativeFailure and never raw error messages', async () => {
  for (const valid of [true, false]) {
    const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
    child.stdin = new Writable({ write(bytes, encoding, done) { const request = JSON.parse(bytes);
      const nativeFailure = { stage: 'register', reason: 'NATIVE_APP_OPERATION_REFUSED', error: 70, ...(valid ? {} : { path: 'INERT_DIAGNOSTIC_SECRET' }) };
      queueMicrotask(() => child.stdout.write(JSON.stringify({ protocol: request.protocol, version: request.version, id: request.id, ok: false,
        error: { code: 'APPLICATION_NATIVE_REFUSED', message: 'INERT_DIAGNOSTIC_SECRET', nativeFailure } }) + '\n')); done(); },
    final(done) { done(); queueMicrotask(() => child.emit('close', 0, null)); } });
    const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => child });
    await assert.rejects(call('status'), failure => {
      assert.equal(failure.code, valid ? 'APPLICATION_NATIVE_REFUSED' : 'PF_HELPER_RESPONSE_INVALID');
      if (valid) assert.deepEqual(failure.nativeFailure, { stage: 'register', reason: 'NATIVE_APP_OPERATION_REFUSED', error: 70 });
      assert.equal(JSON.stringify(failure).includes('INERT_DIAGNOSTIC_SECRET'), false); assert.equal(failure.message.includes('INERT_DIAGNOSTIC_SECRET'), false); return true;
    });
    assert.equal((await call.close()).cleanupUncertain, true);
  }
});

test('production JSONL helper framing works with a wholly inert controller and retains positive cleanup through EOF', async () => {
  const value = request(), clean = cleanup(value), input = new PassThrough(), child = new EventEmitter();
  const controller = { closed: false, status: async () => status, prepareRoute: async input => {
    assert.equal(input.route.password, route().route.password); return routed;
  }, prepareNotionApplication: async input => { assert.deepEqual(input, value); return stage(value); },
  resumeNotionApplication: async () => ({ ...stage(value), phase: 'running', resumed: true }),
  stopNotionApplication: async () => clean, applicationSnapshot: async () => clean,
  shutdown: async () => ({ closed: true, cleanupRequired: false }) };
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { input.end(); return true; };
  child.stdin = new Writable({ write: (bytes, encoding, done) => { input.write(Buffer.from(bytes)); done(); }, final: done => { input.end(); done(); } });
  const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => {
    servePFHelper({ controller, input, output: child.stdout, signalSource: null }).then(() => {
      child.stdout.end(); child.emit('close', 0, null);
    }); return child;
  } });
  await call('status'); await prepare(call, value); await call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true });
  await stopAndSnapshot(call, value); assert.deepEqual(await call.close(), { closed: true, started: true, cleanupUncertain: false });
});

test('one real own JSONL peer carries stdin credentials and four Notion RPCs with fragmented responses and normal EOF', async t => {
  const value = request(), clean = cleanup(value); const { call, spawnCount, spawnArgs } = peer(t,
    [status, { ...routed, password: 'untrusted-echo' }, stage(value), { ...stage(value), phase: 'running', resumed: true }, clean, clean],
    { fragment: true, stderr: 'discard-private-native-diagnostic',
      credentialHash: createHash('sha256').update(route().route.password).digest('hex') });
  await call('status'); const prepared = await call('prepareRoute', route()); assert.equal(Object.hasOwn(prepared, 'password'), false);
  await call('prepareNotionApplication', value); await call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true });
  await stopAndSnapshot(call, value);
  assert.equal(spawnCount(), 1); assert.equal(spawnArgs[0].includes('session-fixture-secret'), false);
  assert.equal(JSON.stringify(call.snapshot()).includes('session-fixture-secret'), false);
  assert.equal(call.snapshot().protectedLaunchAllowed, false);
  assert.deepEqual(await call.close(), { closed: true, started: true, cleanupUncertain: false });
});

test('the existing CLI lifecycle can use this shared client with only inert injected acceptance evidence', async t => {
  const value = request(), clean = cleanup(value), verifiedStatus = { ...status, rootOwnedInstallationVerified: true,
    callerConsoleUIDVerified: true, privilegedOperationsAuthorized: true, privilegedRuntimeVerified: true, lo0FilteringVerified: true };
  const { call } = peer(t, [verifiedStatus, routed, stage(value), { ...stage(value), phase: 'running', resumed: true }, clean, clean]);
  const report = await runPFNotionAcceptance({ call, routeRequest: route(), beforeResume: async () => true, observe: async () => {},
    observationMs: 0, runId: value.runId, environmentId: value.environmentId });
  assert.equal(report.lifecyclePassed, true); assert.equal(report.applicationTrafficVerified, false);
  assert.equal(report.ready, false); assert.equal(report.protected, false); assert.equal(report.productionReady, false);
});

test('every cleanup schema needs the same environment and a fresh snapshot after stop', async t => {
  for (const kind of ['normal', 'prestage', 'preflight']) {
    const value = request(), clean = cleanup(value, kind), validators = [validatePFNotionCleanupReceipt, validatePFNotionPrestageCleanupReceipt, validatePFNotionPreflightCleanupReceipt];
    assert.deepEqual(validators.map(validate => validate(clean, value.runId)), ['normal', 'prestage', 'preflight'].map(item => kind === item));
    const { call } = peer(t, [routed, stage(value), clean, clean]); await prepare(call, value);
    const outputs = await stopAndSnapshot(call, value), validator = validators[['normal', 'prestage', 'preflight'].indexOf(kind)];
    assert.equal(validator(outputs.stopped, value.runId), true); assert.equal(validator(outputs.snapshot, value.runId), true);
    assert.equal(call.snapshot().cleanupKind, kind);
    assert.equal((await call.close()).cleanupUncertain, false, kind);
    for (const order of ['stop-only', 'snapshot-only', 'snapshot-before-stop']) {
      const second = peer(t, [routed, stage(value), clean, clean]).call; await prepare(second, value);
      if (order !== 'stop-only') await second('applicationSnapshot', { runId: value.runId });
      if (order !== 'snapshot-only') await second('stopNotionApplication', { runId: value.runId });
      assert.equal((await second.close()).cleanupUncertain, true, `${kind}: ${order}`);
    }
  }
});

test('missing cleanup facts and mismatched schemas cannot pass a later phase or outer exit', async t => {
  for (const variant of ['missing', 'coerced', 'foreign', 'schema-mismatch']) {
    const value = request(), clean = cleanup(value), changed = structuredClone(clean);
    if (variant === 'missing') delete changed.cleanupEvidence.originalListenerClosed;
    if (variant === 'coerced') changed.cleanupEvidence.originalListenerClosed = 1;
    if (variant === 'foreign') changed.environmentId = changed.cleanupEvidence.environmentId = randomUUID();
    if (variant === 'schema-mismatch') Object.assign(changed, cleanup(value, 'preflight'));
    const { call } = peer(t, [routed, stage(value), clean, changed]); await prepare(call, value);
    await call('stopNotionApplication', { runId: value.runId });
    if (variant === 'foreign') await assert.rejects(call('applicationSnapshot', { runId: value.runId }), { code: 'PF_HELPER_RESPONSE_INVALID' });
    else { const result = await call('applicationSnapshot', { runId: value.runId });
      if (variant !== 'schema-mismatch') { assert.equal(result.cleanupComplete, false); assert.equal(result.cleanupUncertain, true); } }
    assert.equal((await call.close()).cleanupUncertain, true, variant);
  }
});

test('stopping permanently closes resume admission even when the native peer reports a complete cleanup', async t => {
  const value = request(), clean = cleanup(value); const { call } = peer(t, [routed, stage(value), clean, clean]);
  await prepare(call, value); await stopAndSnapshot(call, value);
  await assert.rejects(call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true }), { code: 'PF_HELPER_REQUEST_INVALID' });
  assert.equal((await call.close()).cleanupUncertain, false);
});

test('an explicit uncertain controller state stays uncertain after a complete stop and snapshot', async t => {
  const value = request(), clean = cleanup(value); const { call } = peer(t,
    [routed, { ...stage(value), phase: 'cleanup-required', cleanupUncertain: true }, clean, clean]);
  await prepare(call, value); await assert.rejects(call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true }), { code: 'PF_HELPER_CLEANUP_UNCERTAIN' });
  await stopAndSnapshot(call, value); assert.equal((await call.close()).cleanupUncertain, true);
});

test('the 180 second channel cannot extend its active deadline or retry a run, while cleanup keeps its reserved budget', async t => {
  let current = 0; const value = request(), clean = cleanup(value);
  const { call } = peer(t, [routed, stage(value), clean, clean], { now: () => current }); await prepare(call, value);
  await assert.rejects(call('prepareNotionApplication', value), { code: 'PF_HELPER_REQUEST_INVALID' });
  current = 140001; assert.equal(call.snapshot().cleanupDue, true);
  await assert.rejects(call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true }), { code: 'PF_HELPER_DEADLINE' });
  await stopAndSnapshot(call, value); assert.equal(call.snapshot().remainingMs, PF_NOTION_CHANNEL_LIFETIME_MS - current);
  assert.equal((await call.close()).cleanupUncertain, false);
});

test('resume uses 60 seconds including preflight, refuses an overdue ACK before its timer fires, and retains a typed native timeout', async () => {
  for (const variant of ['late-ack', 'native-timeout']) {
    let current = 0, replyResume;
    const value = request(), clean = cleanup(value), child = new EventEmitter();
    child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
    child.stdin = new Writable({ write(bytes, encoding, done) {
      const input = JSON.parse(bytes);
      const send = (result, error) => child.stdout.write(JSON.stringify({ protocol: input.protocol, version: input.version,
        id: input.id, ok: !error, ...(error ? { error } : { result: { ...result, private: 'INERT_TIMING_SECRET' } }) }) + '\n');
      if (input.method === 'resumeNotionApplication') replyResume = () => variant === 'late-ack'
        ? send({ ...stage(value), phase: 'running', resumed: true })
        : send(null, { code: 'APPLICATION_APP_RESUME_TIMEOUT', message: 'INERT_TIMING_SECRET' });
      else queueMicrotask(() => send(input.method === 'prepareRoute' ? routed : input.method === 'prepareNotionApplication' ? stage(value) : clean));
      done();
    }, final(done) { child.stdout.end(); done(); setImmediate(() => child.emit('close', 0, null)); } });
    const call = createPersistentPFNotionSessionClient({ now: () => current, spawnRootControlledLifecycle: () => child });
    await prepare(call, value);
    const resume = call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true });
    while (!replyResume) await new Promise(resolve => setImmediate(resolve));
    let timing = call.snapshot().diagnostics.callTimings.at(-1);
    assert.equal(timing.method, 'resumeNotionApplication'); assert.equal(timing.requestedTimeoutMs, 60000);
    assert.equal(timing.effectiveTimeoutMs, 60000); assert.equal(timing.cleanupReserveMs, 40000);
    assert.equal(timing.outcome, 'pending'); assert.equal(validatePFNotionCallTimingDiagnostic(timing), true);
    // Do not advance the timer: the monotonic deadline must also guard parsing.
    current = variant === 'late-ack' ? 60000 : 45000;
    replyResume();
    await assert.rejects(resume, { code: variant === 'late-ack' ? 'PF_HELPER_DEADLINE' : 'APPLICATION_APP_RESUME_TIMEOUT' });
    timing = call.snapshot().diagnostics.callTimings.at(-1);
    assert.equal(timing.elapsedMs, current); assert.equal(timing.outcome, variant === 'late-ack' ? 'deadline' : 'error');
    assert.equal(timing.lateResponseObserved, variant === 'late-ack'); assert.equal(validatePFNotionCallTimingDiagnostic(timing), true);
    if (variant === 'late-ack') await assert.rejects(call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true }),
      { code: 'PF_HELPER_CLEANUP_UNCERTAIN' });
    await stopAndSnapshot(call, value);
    assert.equal((await call.close()).cleanupUncertain, variant === 'late-ack');
    assert.equal(JSON.stringify(call.snapshot()).includes('INERT_TIMING_SECRET'), false);
    assert.equal(call.snapshot().ready, false); assert.equal(call.snapshot().protectedLaunchAllowed, false);
  }
});

test('a timed-out prepare retains its run binding and uncertainty even after a late reply and positive cleanup', async t => {
  const value = request(), clean = cleanup(value); const { call } = peer(t,
    [routed, stage(value), clean, clean], { delayIndex: 1, delayMs: 60 }); await call('prepareRoute', route());
  await assert.rejects(call('prepareNotionApplication', value, { timeoutMs: 20 }), { code: 'PF_HELPER_DEADLINE' });
  await stopAndSnapshot(call, value); assert.equal((await call.close()).cleanupUncertain, true);
  assert.equal(call.snapshot().diagnostics.lastLatePrepare.phase, 'staged');
  assert.equal(call.snapshot().diagnostics.lastLatePrepare.diagnosticOnly, true);
});

test('late known prepare results and errors are diagnostic only, never admission or cleanup evidence', async t => {
  for (const variant of ['clean-result', 'failed-result', 'rpc-error']) {
    const value = request(), response = variant === 'clean-result' ? { ...cleanup(value), staged: true, resumed: false } : {
      ...stage(value), phase: 'cleanup-required', cleanupUncertain: true,
      failure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED',
        native: { stage: 'front-admission', reason: 'NATIVE_OPERATION_REFUSED', error: 13 } }, private: 'LATE_PRIVATE_SECRET' };
    const { call } = peer(t, [routed, response], { delayIndex: 1, delayMs: 50, errorIndex: variant === 'rpc-error' ? 1 : -1 });
    await call('prepareRoute', route());
    await assert.rejects(call('prepareNotionApplication', value, { timeoutMs: 10 }), { code: 'PF_HELPER_DEADLINE' });
    assert.equal((await call.close()).cleanupUncertain, true);
    const snapshot = call.snapshot(), diagnostic = snapshot.diagnostics.lastLatePrepare;
    assert.equal(diagnostic.runId, value.runId); assert.equal(diagnostic.environmentId, value.environmentId);
    assert.equal(diagnostic.diagnosticOnly, true); assert.equal(snapshot.cleanupKind, null);
    assert.equal(snapshot.diagnostics.uncertaintyLatched, true);
    if (variant === 'rpc-error') { assert.equal(diagnostic.kind, 'error'); assert.equal(diagnostic.code, 'APPLICATION_ROUTING_NOT_READY'); }
    else { assert.equal(diagnostic.phase, response.phase); assert.equal(diagnostic.kind, 'result');
      assert.equal(Object.hasOwn(diagnostic, 'cleanupEvidence'), false); }
    assert.equal(JSON.stringify(snapshot).includes('LATE_PRIVATE_SECRET'), false);
  }
});

test('late prepare refuses foreign binding, wrong profiles, malformed phases and failure diagnostics', async t => {
  for (const variant of ['run', 'environment', 'profile', 'phase', 'boolean', 'route', 'failure-extra', 'native-error']) {
    const value = request(), response = { ...stage(value), failure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED',
      native: { stage: 'ticket-prepare', reason: 'NATIVE_OPERATION_REFUSED', error: 70 } } };
    if (variant === 'run') response.runId = randomUUID();
    if (variant === 'environment') response.environmentId = randomUUID();
    if (variant === 'profile') response.profile = 'foreign';
    if (variant === 'phase') response.phase = 'LATE_PRIVATE_SECRET';
    if (variant === 'boolean') response.staged = 1;
    if (variant === 'route') response.routeId = 'foreign_route';
    if (variant === 'failure-extra') response.failure.private = 'LATE_PRIVATE_SECRET';
    if (variant === 'native-error') response.failure.native.error = true;
    const { call } = peer(t, [routed, response], { delayIndex: 1, delayMs: 50 }); await call('prepareRoute', route());
    await assert.rejects(call('prepareNotionApplication', value, { timeoutMs: 10 }), { code: 'PF_HELPER_DEADLINE' });
    assert.equal((await call.close()).cleanupUncertain, true, variant);
    assert.equal(call.snapshot().diagnostics.lastLatePrepare, null, variant);
    assert.equal(call.snapshot().cleanupKind, null); assert.equal(JSON.stringify(call.snapshot()).includes('LATE_PRIVATE_SECRET'), false);
  }
});

test('only a fresh same-bound snapshot records the fixed failure diagnostic, without private output', async t => {
  for (const variant of ['valid', 'foreign', 'malformed-native']) {
    const value = request(), response = { ...stage(value), phase: 'cleanup-required', cleanupUncertain: true,
      failure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED',
        native: { stage: 'ticket-prepare', reason: 'NATIVE_OPERATION_REFUSED', error: 70 } }, private: 'SNAPSHOT_PRIVATE_SECRET' };
    if (variant === 'foreign') response.environmentId = randomUUID();
    if (variant === 'malformed-native') response.failure.native.private = 'SNAPSHOT_PRIVATE_SECRET';
    const { call } = peer(t, [routed, stage(value), response]); await prepare(call, value);
    if (variant === 'foreign') await assert.rejects(call('applicationSnapshot', { runId: value.runId }), { code: 'PF_HELPER_RESPONSE_INVALID' });
    else await call('applicationSnapshot', { runId: value.runId });
    const diagnostic = call.snapshot().diagnostics.lastApplicationSnapshot;
    if (variant === 'valid') { assert.equal(diagnostic.failure.stage, 'cold-stage'); assert.equal(diagnostic.failure.native.error, 70); }
    else assert.equal(diagnostic, null);
    assert.equal((await call.close()).cleanupUncertain, true);
    assert.equal(JSON.stringify(call.snapshot()).includes('SNAPSHOT_PRIVATE_SECRET'), false);
  }
});

test('a clean native receipt cannot conceal a partial final line, duplicate reply or failed outer process', async t => {
  for (const variant of ['partial-tail', 'outer-failure', 'duplicate']) {
    const value = request(), clean = cleanup(value); const { call } = peer(t, [routed, stage(value), clean, clean],
      { suffix: variant === 'partial-tail' ? '{"private-tail":' : '', exitCode: variant === 'outer-failure' ? 1 : 0,
        duplicateIndex: variant === 'duplicate' ? 1 : -1 });
    await prepare(call, value);
    if (variant !== 'duplicate') await stopAndSnapshot(call, value);
    assert.equal((await call.close()).cleanupUncertain, true, variant);
  }
});

test('contradictory fresh status revokes a previously complete cleanup observation', async t => {
  const value = request(), clean = cleanup(value); const { call } = peer(t,
    [routed, stage(value), clean, clean, { ...status, applications: [{ ...stage(value), phase: 'running' }] }]);
  await prepare(call, value); await stopAndSnapshot(call, value); await call('status');
  assert.equal((await call.close()).cleanupUncertain, true);
});

test('foreign root-controller activity blocks mutations and cannot be hidden by an empty public status', async t => {
  const foreign = request(); const { call } = peer(t, [{ ...status, applications: [stage(foreign)] }]);
  const visible = await call('status'); assert.equal(visible.ready, false);
  await assert.rejects(call('prepareRoute', route()), { code: 'PF_HELPER_CLEANUP_UNCERTAIN' });
  assert.equal((await call.close()).cleanupUncertain, true);
});

test('a rewound injected clock cannot extend the bounded channel', async t => {
  let current = 100; const { call } = peer(t, [status], { now: () => current }); await call('status');
  current = 101; call.snapshot(); current = 100;
  assert.throws(() => call.snapshot(), { code: 'PF_HELPER_REQUEST_INVALID' });
  await assert.rejects(call('prepareRoute', route()), { code: 'PF_HELPER_REQUEST_INVALID' });
  current = 102; assert.equal((await call.close()).cleanupUncertain, true);
});

test('baseline status stays unselected; a selected status and subsequent prepare share one actual anchor and run', async t => {
  const value = request(), clean = cleanup(value);
  const { call } = peer(t, [status, selectedStatus(value.runId), routed, stage(value), clean, clean]);
  const baseline = await call('status'); assert.equal(baseline.anchor, null); assert.equal(baseline.ownedRootHookCanCreate, false);
  const selected = await call('status', { runId: value.runId });
  assert.equal(selected.anchor, pfRoutingAnchor(value.runId)); assert.equal(selected.ownedRootHookCanCreate, true);
  await assert.rejects(call('status', { runId: randomUUID() }), { code: 'PF_HELPER_REQUEST_INVALID' });
  await call('prepareRoute', route());
  await assert.rejects(call('prepareNotionApplication', { ...value, runId: randomUUID() }), { code: 'PF_HELPER_REQUEST_INVALID' });
  await call('prepareNotionApplication', value); await stopAndSnapshot(call, value);
  assert.equal((await call.close()).cleanupUncertain, false);
});

test('a selected query rejects missing, baseline or foreign response anchors before mutation', async t => {
  for (const anchor of [undefined, null, pfRoutingAnchor(randomUUID()), 'private-status-secret']) {
    const value = request(), reply = selectedStatus(value.runId, { anchor });
    const { call } = peer(t, [reply]);
    await assert.rejects(call('status', { runId: value.runId }), { code: 'PF_HELPER_RESPONSE_INVALID' });
    assert.equal((await call.close()).cleanupUncertain, true);
    assert.equal(JSON.stringify(call.snapshot()).includes('private-status-secret'), false);
  }
});

test('only a successful status-only history, complete empty raw inventories and actual EOF/zero close produce the distinct receipt', async t => {
  const runId = randomUUID(), { call } = peer(t, [selectedStatus(runId)]);
  await call('status', { runId });
  assert.equal(call.snapshot().statusOnlyEvidence, null);
  const closed = await call.close();
  assert.equal(closed.cleanupUncertain, false);
  assert.equal(closed.statusOnlyEvidence.schema, 'envara.macos-pf-notion-status-only-close/v1');
  assert.equal(closed.statusOnlyEvidence.runId, runId);
  assert.equal(closed.statusOnlyEvidence.cleanupComplete, false);
  assert.equal(closed.statusOnlyEvidence.lifecyclePassed, false);
  const diagnostic = call.snapshot().diagnostics;
  assert.deepEqual(diagnostic.callHistory, ['status']);
  assert.deepEqual(diagnostic.lastStatusInventory, { runs: 0, applications: 0, routes: 0 });
  assert.equal(diagnostic.terminalExitCode, 0); assert.equal(diagnostic.terminalExitSignal, null);
  assert.equal(diagnostic.stdoutEOF, true); assert.equal(diagnostic.pending, false); assert.equal(diagnostic.bufferedBytes, 0);
  assert.equal(diagnostic.uncertaintyLatched, false); assert.equal(call.snapshot().cleanupUncertain, false);
});

test('status-only evidence refuses incomplete or nonempty inventories, uncertain states and all lost/failed closure paths', async t => {
  for (const variant of ['missing-runs', 'missing-routes', 'non-array', 'routes-live', 'runs-live', 'applications-live', 'not-readonly', 'uncertain', 'partial-tail', 'outer-failure', 'timeout']) {
    const runId = randomUUID(), reply = selectedStatus(runId), options = {};
    if (variant === 'missing-runs') delete reply.runs;
    if (variant === 'missing-routes') delete reply.routes;
    if (variant === 'non-array') reply.routes = {};
    if (variant === 'routes-live') reply.routes = [{ private: 'STATUS_PRIVATE_SECRET' }];
    if (variant === 'runs-live') reply.runs = [{ runId: randomUUID() }];
    if (variant === 'applications-live') reply.applications = [stage(request())];
    if (variant === 'not-readonly') reply.readOnly = false;
    if (variant === 'uncertain') reply.cleanupUncertain = true;
    if (variant === 'partial-tail') options.suffix = '{"STATUS_PRIVATE_SECRET":';
    if (variant === 'outer-failure') options.exitCode = 1;
    if (variant === 'timeout') Object.assign(options, { delayIndex: 0, delayMs: 60 });
    const { call } = peer(t, [reply], options);
    if (variant === 'timeout') await assert.rejects(call('status', { runId }, { timeoutMs: 20 }), { code: 'PF_HELPER_DEADLINE' });
    else await call('status', { runId });
    const closed = await call.close(); assert.equal(closed.cleanupUncertain, true, variant);
    assert.equal(closed.statusOnlyEvidence, undefined, variant); assert.equal(call.snapshot().statusOnlyEvidence, null, variant);
    assert.equal(JSON.stringify(call.snapshot()).includes('STATUS_PRIVATE_SECRET'), false, variant);
  }
});

test('a prepare request cannot use a later empty status to claim status-only closure', async t => {
  const runId = randomUUID(), { call } = peer(t, [selectedStatus(runId), routed, selectedStatus(runId)]);
  await call('status', { runId }); await call('prepareRoute', route()); await call('status', { runId });
  const closed = await call.close(); assert.equal(closed.cleanupUncertain, true); assert.equal(closed.statusOnlyEvidence, undefined);
  assert.equal(call.snapshot().diagnostics.nonStatusRequestAttempted, true);
});

test('a failed latest status cannot reuse an earlier empty inventory for status-only closure', async t => {
  const runId = randomUUID(), { call } = peer(t, [selectedStatus(runId), selectedStatus(runId)], { errorIndex: 1 });
  await call('status', { runId });
  await assert.rejects(call('status', { runId }), { code: 'APPLICATION_ROUTING_NOT_READY' });
  assert.equal((await call.close()).cleanupUncertain, true); assert.equal(call.snapshot().statusOnlyEvidence, null);
});

test('zero close without observed stdout EOF cannot claim status-only closure', async () => {
  const runId = randomUUID(), child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => true;
  child.stdin = new Writable({ write(bytes, encoding, done) { const request = JSON.parse(bytes);
    child.stdout.write(JSON.stringify({ protocol: request.protocol, version: request.version, id: request.id, ok: true, result: selectedStatus(runId) }) + '\n'); done(); },
  final(done) { done(); queueMicrotask(() => child.emit('close', 0, null)); } });
  const call = createPersistentPFNotionSessionClient({ spawnRootControlledLifecycle: () => child });
  await call('status', { runId }); assert.equal((await call.close()).cleanupUncertain, true);
  assert.equal(call.snapshot().diagnostics.terminalExitCode, 0); assert.equal(call.snapshot().diagnostics.stdoutEOF, false);
  child.stdout.end(); child.stderr.end();
});

test('routine observations are counted, so a long run still records the stop sequence that explains its cleanup', async t => {
  /* A real attached run polled every two seconds; the bounded history filled
   * after about two minutes and the stop, the one call a failed cleanup
   * depends on, was never recorded. */
  const value = request(), running = { ...stage(value), phase: 'running', resumed: true }, clean = cleanup(value);
  const polls = 70;
  const { call } = peer(t, [routed, stage(value), running, ...Array(polls).fill(running), clean, clean]);
  await prepare(call, value);
  await call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true });
  await assert.rejects(call('resumeNotionApplication', { runId: value.runId, activationAuthorized: true }, { observation: true }), { code: 'PF_HELPER_REQUEST_INVALID' });
  await assert.rejects(call('applicationSnapshot', { runId: value.runId }, { observation: 'yes' }), { code: 'PF_HELPER_REQUEST_INVALID' });
  for (let index = 0; index < polls; index++) await call('applicationSnapshot', { runId: value.runId }, { timeoutMs: 5000, observation: true });
  const { stopped, snapshot } = await stopAndSnapshot(call, value);
  assert.equal(stopped.cleanupComplete, true); assert.equal(snapshot.cleanupComplete, true);
  const diagnostics = call.snapshot().diagnostics;
  assert.deepEqual(diagnostics.callHistory, ['prepareRoute', 'prepareNotionApplication', 'resumeNotionApplication', 'stopNotionApplication', 'applicationSnapshot']);
  assert.equal(diagnostics.callHistoryComplete, true);
  assert.equal(diagnostics.callTimings.length, diagnostics.callHistory.length);
  assert.deepEqual(diagnostics.callTimings.map(timing => timing.sequence), [1, 2, 3, 4, 5]);
  assert.equal(diagnostics.observationPolls, polls); assert.equal(diagnostics.observationPollFailures, 0);
});
