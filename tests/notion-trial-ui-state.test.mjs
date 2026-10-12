import test from 'node:test';
import assert from 'node:assert/strict';
import { safeNotionTrial, notionTrialControls, notionTrialLogLine, notionTrialErrorHint } from '../src/notion-trial-state.mjs';

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

test('a refused PF baseline explains the restart and VPN causes without changing trial controls', () => {
  const hint = notionTrialErrorHint('PF_OWNED_RUNTIME_NOT_EMPTY');
  assert.match(hint, /重启电脑/); assert.match(hint, /VPN/);
  for (const code of [null, undefined, 42, 'PF_NOTION_TRIAL_FAILED', '__proto__', 'toString', 'constructor']) assert.equal(notionTrialErrorHint(code), null, String(code));
});
