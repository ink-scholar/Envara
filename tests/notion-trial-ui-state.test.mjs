import test from 'node:test';
import assert from 'node:assert/strict';
import { safeNotionTrial, notionTrialControls, notionTrialLogLine, notionTrialErrorHint, attachedApplicationStatus } from '../src/notion-trial-state.mjs';

const application = { id: 'bound-notion', identity: 'bundle:notion.id' };
const routing = { ready: false, controlledNotionTrialAvailable: true };

test('a controlled trial requires a bound local application identity and explicit desktop capability', () => {
  assert.equal(notionTrialControls(application, routing, true).canRun, true);
  // Any locally added application may be attached; what must still refuse is an
  // unbound/empty identity, a missing capability, or a non-desktop caller.
  assert.equal(notionTrialControls({ ...application, identity: 'bundle:other' }, routing, true).canRun, true);
  for (const [app, capability, desktop] of [[{ ...application, identity: '' }, routing, true], [{ ...application, identity: undefined }, routing, true],
    [application, { ready: true }, true], [application, { controlledNotionTrialAvailable: 'true' }, true], [application, routing, false]]) {
    assert.equal(notionTrialControls(app, capability, desktop).show, false);
    assert.equal(notionTrialControls(app, capability, desktop).canRun, false);
  }
  assert.equal(routing.ready, false);
});

test('pending activation, active trial and uncertain cleanup prevent another run while stop remains separate', () => {
  assert.equal(notionTrialControls(application, routing, true, { 'runNotionTrial:bound-notion': true }).canRun, false);
  const active = { ...application, notionTrial: { applicationId: application.id, active: true, phase: 'running' } };
  assert.equal(notionTrialControls(active, routing, true).canStop, true);
  assert.equal(notionTrialControls(active, routing, true).canRun, false);
  assert.equal(notionTrialControls(active, { controlledNotionTrialAvailable: false }, true).canStop, true);
  assert.equal(notionTrialControls({ ...active, notionTrial: { ...active.notionTrial, phase: 'stopping' } }, routing, true).canStop, false);
  const uncertain = { ...application, notionTrial: { applicationId: application.id, active: false, phase: 'cleanup-required', cleanupUncertain: true } };
  assert.equal(notionTrialControls(uncertain, routing, true).canRun, false);
});

test('trial log projection rejects another binding and never renders raw messages, paths or route objects', () => {
  assert.equal(safeNotionTrial({ ...application, notionTrial: { applicationId: 'other', phase: 'failed' } }), null);
  const trial = safeNotionTrial({ ...application, notionTrial: { applicationId: application.id, phase: 'failed', errorCode: 'APPLICATION_NATIVE_REFUSED',
    route: { password: 'fixture-secret' }, message: 'raw fixture-secret', events: [{ sequence: 1, stage: 'prepare', code: 'APPLICATION_NATIVE_REFUSED', nativeStage: 'preflight', errno: 13,
      message: 'fixture-secret', path: '/private/fixture' }, { sequence: 2, stage: 'https://example.test/token' }] } });
  assert.equal(trial.events.length, 1);
  assert.equal(notionTrialLogLine(trial.events[0]), '1. prepare · APPLICATION_NATIVE_REFUSED · preflight · errno=13');
  assert.equal(JSON.stringify(trial).includes('fixture-secret'), false);
  assert.equal(JSON.stringify(trial).includes('/private'), false);
});

test('a live cleanup-only endpoint permits Stop without reopening launch or replaying history authority', () => {
  const trial = { applicationId: application.id, active: false, phase: 'cleanup-required', cleanupUncertain: true, cleanupRetryable: true };
  const controls = notionTrialControls({ ...application, notionTrial: trial }, routing, true);
  assert.equal(controls.canRun, false);
  assert.equal(controls.canStop, true);
  assert.equal(attachedApplicationStatus(controls), 'error');
  for (const change of [{ cleanupRetryable: 'true' }, { cleanupRetryable: false }, { cleanupUncertain: false }, { phase: 'failed' }]) {
    assert.equal(notionTrialControls({ ...application, notionTrial: { ...trial, ...change } }, routing, true).canStop, false);
  }
  assert.equal(notionTrialControls({ ...application, notionTrial: trial }, routing, true, { 'stopNotionTrial:bound-notion': true }).canStop, false);
  assert.equal(notionTrialControls({ ...application, notionTrialHistory: trial }, routing, true).canStop, false);
});

test('a refused PF baseline explains the restart and VPN causes without changing trial controls', () => {
  const hint = notionTrialErrorHint('PF_OWNED_RUNTIME_NOT_EMPTY');
  assert.match(hint, /重启电脑/); assert.match(hint, /VPN/);
  for (const code of [null, undefined, 42, 'PF_NOTION_TRIAL_FAILED', '__proto__', 'toString', 'constructor']) assert.equal(notionTrialErrorHint(code), null, String(code));
});

test('the row shows running only while the application itself runs, and a failed start as an error', () => {
  const row = (trial, extra = {}) => attachedApplicationStatus({ trial, requestPending: false, stopPending: false, ...extra });
  assert.equal(row(null), 'stopped');
  assert.equal(row(null, { requestPending: true }), 'starting');
  for (const phase of ['verifying', 'authorizing', 'preparing', 'staged', 'resuming']) assert.equal(row({ active: true, phase }), 'starting', phase);
  assert.equal(row({ active: true, phase: 'running' }), 'running');
  assert.equal(row({ active: true, phase: 'running' }, { stopPending: true }), 'stopping');
  assert.equal(row({ active: true, phase: 'stopping' }), 'stopping');
  assert.equal(row({ active: false, phase: 'cleaned' }), 'stopped', 'stopped, or ended on its own');
  assert.equal(row({ active: false, phase: 'failed' }), 'error');
  assert.equal(row({ active: false, phase: 'cleanup-required', cleanupUncertain: true }), 'error');
});

test('bound lifecycle results update one application and retain validated run identity', async () => {
  const { applyNotionTrialOperationResult } = await import('../src/notion-trial-state.mjs');
  const beforeRun = '534692dd-b2e8-498a-8018-32441ce490ca', runId = 'bb756095-daf2-4137-b7e6-f8714b0c9ad0', environmentId = '76e164dd-3827-4746-9e5d-43ae1f4219de';
  const before = { profiles: [], proxies: [], system: {}, applications: [{ ...application, notionTrial: { applicationId: application.id, runId: beforeRun, environmentId, phase: 'cleaned' } }, { id: 'unrelated', status: 'running' }] };
  const result = { applicationId: application.id, runId, environmentId, phase: 'cleaned', active: false, cleanupComplete: true, cleanupUncertain: false,
    errorCode: 'APPLICATION_APP_NATIVE_REFUSED', initialFailure: { stage: 'cold-stage', code: 'APPLICATION_APP_NATIVE_REFUSED' }, cleanupFailure: null,
    events: [{ sequence: 1, stage: 'failed', code: 'APPLICATION_APP_NATIVE_REFUSED' }], secret: 'never-render-this' };
  const next = applyNotionTrialOperationResult(before, result, { method: 'runNotionTrial', applicationId: application.id, previousRunId: beforeRun });
  assert.notEqual(next, before); assert.equal(next.applications[1], before.applications[1]);
  assert.equal(next.applications[0].notionTrial.runId, runId); assert.equal(next.applications[0].notionTrial.environmentId, environmentId);
  assert.deepEqual(next.applications[0].notionTrial.initialFailure, result.initialFailure); assert.equal(JSON.stringify(next).includes(result.secret), false);
  assert.equal(notionTrialControls(next.applications[0], routing, true).active, false);
  assert.equal(attachedApplicationStatus(notionTrialControls(next.applications[0], routing, true)), 'stopped');
});

test('partial action results cannot overwrite another application, environment, newer run or unbound state', async () => {
  const { applyNotionTrialOperationResult } = await import('../src/notion-trial-state.mjs');
  const old = '534692dd-b2e8-498a-8018-32441ce490ca', current = 'bb756095-daf2-4137-b7e6-f8714b0c9ad0', environmentId = '76e164dd-3827-4746-9e5d-43ae1f4219de';
  const result = { applicationId: application.id, runId: current, environmentId, phase: 'cleaned', active: false, cleanupComplete: true, cleanupUncertain: false };
  const before = { applications: [{ ...application, notionTrial: { ...result, runId: old } }] };
  const options = { method: 'runNotionTrial', applicationId: application.id, previousRunId: old };
  for (const patch of [{ applicationId: 'foreign' }, { runId: old }, { runId: current.toUpperCase() }, { environmentId: old }, { phase: 'running' }, { active: true }, { cleanupComplete: 'true' }, { cleanupUncertain: null }])
    assert.equal(applyNotionTrialOperationResult(before, { ...result, ...patch }, options), null);
  const newer = { applications: [{ ...application, notionTrial: { ...result, runId: 'a3975362-a88a-43c0-ab8d-6f0688d871bd', phase: 'running', active: true } }] };
  assert.equal(applyNotionTrialOperationResult(newer, result, options), null, 'a late result may not overwrite a new run');
  assert.equal(applyNotionTrialOperationResult({ applications: [{ ...application, identity: '' }] }, result, options), null);
  assert.equal(applyNotionTrialOperationResult(before, result, { ...options, method: 'saveApplication' }), null);
  assert.equal(applyNotionTrialOperationResult(before, result, { ...options, method: 'stopNotionTrial' }), null, 'Stop must match the run selected when requested');
  assert.ok(applyNotionTrialOperationResult({ applications: [{ ...application, notionTrial: { ...result, active: true, phase: 'running' } }] }, result,
    { ...options, method: 'stopNotionTrial', previousRunId: current }));
});
