import test from 'node:test';
import assert from 'node:assert/strict';
import { browserSessionControls } from '../src/browser-session-state.mjs';

const profile = { id: 'fixture-browser', status: 'stopped' };
const runtime = { id: 'fixture-runtime', supported: true, installed: true };

test('stopped browsers offer only an available runtime action', () => {
  const ready = browserSessionControls(profile, runtime);
  assert.equal(ready.action, 'start');
  assert.equal(ready.label, '启动');
  assert.equal(ready.primaryDisabled, false);
  assert.equal(ready.stopDisabled, true);
  const missing = browserSessionControls(profile, { ...runtime, installed: false });
  assert.equal(missing.action, 'install');
  assert.equal(missing.primaryDisabled, false);
  for (const unavailable of [undefined, { ...runtime, supported: false }]) {
    const controls = browserSessionControls(profile, unavailable);
    assert.equal(controls.label, '不可用');
    assert.equal(controls.primaryDisabled, true);
  }
});

test('a running browser retains open and stop when its runtime is unavailable', () => {
  for (const current of [undefined, runtime, { ...runtime, supported: false }, { ...runtime, installing: true }]) {
    const controls = browserSessionControls({ ...profile, status: 'running' }, current);
    assert.equal(controls.active, true);
    assert.equal(controls.action, 'focus');
    assert.equal(controls.detailLabel, '打开浏览器');
    assert.equal(controls.primaryDisabled, false);
    assert.equal(controls.stopDisabled, false);
  }
});

test('pending starts and backend preparation do not expose a second launch or a cancel action', () => {
  for (const [current, pending] of [[{ ...profile, status: 'starting' }, {}], [profile, { [`startProfile:${profile.id}`]: true }]]) {
    const controls = browserSessionControls(current, runtime, { pending });
    assert.equal(controls.active, true);
    assert.equal(controls.label, '启动中…');
    assert.equal(controls.detailLabel, '启动中…');
    assert.equal(controls.primaryDisabled, true);
    assert.equal(controls.stopDisabled, true);
  }
});

test('installation and in-flight operations lock controls only for the affected browser', () => {
  for (const [current, pending] of [[{ ...runtime, installing: true }, {}], [runtime, { [`installEngine:${runtime.id}`]: true }]]) {
    const controls = browserSessionControls(profile, current, { pending });
    assert.equal(controls.label, '安装中…');
    assert.equal(controls.primaryDisabled, true);
  }
  const pending = { 'installEngine:other-runtime': true, 'startProfile:other-browser': true };
  assert.equal(browserSessionControls(profile, runtime, { pending }).primaryDisabled, false);
  const busy = browserSessionControls({ ...profile, status: 'running' }, runtime, { busy: true });
  assert.equal(busy.primaryDisabled, true);
  assert.equal(busy.stopDisabled, true);
});
