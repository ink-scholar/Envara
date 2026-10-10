import test from 'node:test';
import assert from 'node:assert/strict';
import { safeNotionTrial, notionTrialControls, notionTrialLogLine } from '../src/notion-trial-state.mjs';

const application = { id: 'bound-notion', identity: 'bundle:notion.id' };
const routing = { ready: false, controlledNotionTrialAvailable: true };

test('a controlled trial requires the exact bound Notion identity and explicit desktop capability', () => {
  assert.equal(notionTrialControls(application, routing, true).canRun, true);
  for (const [app, capability, desktop] of [[{ ...application, identity: 'bundle:other' }, routing, true], [{ ...application, identity: 'bundle:notion.id.fake' }, routing, true],
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
