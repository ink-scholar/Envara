import test from 'node:test';
import assert from 'node:assert/strict';
import { TerminalStreamStore, splitTerminalInput, terminalHeightForPointer, terminalHeightForKey } from '../src/terminal-state.mjs';

const state = (sequence, replay, status = 'running') => ({ profiles: [{ profileId: 'profile-1', name: 'One', cwd: '/workspace', sessions: [{ sessionId: 'session-1', profileId: 'profile-1', sequence, replay, status, startedAt: '2026-10-07T00:00:00.000Z' }] }] });
const data = (sequence, value) => ({ type: 'data', profileId: 'profile-1', sessionId: 'session-1', sequence, data: value });

test('buffers events arriving before the snapshot and drops replay-covered sequences', () => {
  const store = new TerminalStreamStore();
  assert.equal(store.applyEvent(data(3, 'already in replay')).refreshNeeded, true);
  store.applyEvent(data(4, 'live'));
  assert.deepEqual(store.applySnapshot(state(3, 'history')).writes, [{ sessionId: 'session-1', data: 'history' }, { sessionId: 'session-1', data: 'live' }]);
  assert.equal(store.getSession('session-1').sequence, 4);
  assert.equal(store.snapshot().profiles[0].sessions[0].replay, undefined);
});

test('stale snapshots cannot erase later data or replace an exit with running', () => {
  const store = new TerminalStreamStore();
  store.applySnapshot(state(2, 'initial'));
  store.applyEvent(data(3, 'later'));
  store.applyEvent({ type: 'exit', profileId: 'profile-1', sessionId: 'session-1', sequence: 4, exitCode: 7 });
  assert.deepEqual(store.applySnapshot(state(2, 'initial', 'running')).writes, []);
  assert.equal(store.getSession('session-1').status, 'exited');
  assert.equal(store.getSession('session-1').exitCode, 7);
  assert.deepEqual(store.applyEvent(data(3, 'later')).writes, []);
});

test('out-of-order live events wait for the missing sequence and write once', () => {
  const store = new TerminalStreamStore();
  store.applySnapshot(state(1, 'A'));
  assert.deepEqual(store.applyEvent(data(3, 'C')), { writes: [], refreshNeeded: true });
  assert.deepEqual(store.applyEvent(data(2, 'B')).writes, [{ sessionId: 'session-1', data: 'B' }, { sessionId: 'session-1', data: 'C' }]);
  assert.deepEqual(store.applyEvent(data(3, 'C')).writes, []);
  assert.deepEqual(store.applySnapshot(state(3, 'ABC')).writes, []);
});

test('a current rolling replay repairs missed output and discards covered queued events', () => {
  const store = new TerminalStreamStore();
  store.applySnapshot(state(1, 'ABC'));
  store.applyEvent(data(4, 'F'));
  assert.deepEqual(store.applySnapshot(state(3, 'BCDE')).writes, [{ sessionId: 'session-1', data: 'DE', reset: false }, { sessionId: 'session-1', data: 'F' }]);
  assert.equal(store.getSession('session-1').sequence, 4);
  assert.deepEqual(store.applySnapshot(state(4, 'BCDEF')).writes, []);
});

test('snapshot repair resets only when no rolling replay overlap remains', () => {
  const store = new TerminalStreamStore();
  store.applySnapshot(state(1, 'old output'));
  assert.deepEqual(store.applySnapshot(state(10, 'latest output')).writes, [{ sessionId: 'session-1', data: 'latest output', reset: true }]);
  store.applyEvent(data(11, ' new'));
  assert.deepEqual(store.applySnapshot(state(10, 'latest output')).writes, []);
});

test('rolling unicode replay retains emoji boundaries and remount replay includes live output', () => {
  const store = new TerminalStreamStore();
  store.applySnapshot(state(1, '之前🦆中文'));
  assert.deepEqual(store.applySnapshot(state(2, '🦆中文之后')).writes, [{ sessionId: 'session-1', data: '之后', reset: false }]);
  store.applyEvent(data(3, '新数据'));
  assert.equal(store.replayFor('session-1'), '🦆中文之后新数据');
  assert.deepEqual(store.applySnapshot(state(2, '🦆中文之后')).writes, []);
  assert.equal(store.replayFor('session-1'), '🦆中文之后新数据');
});

test('unknown sessions survive unrelated snapshots and profiles keep their sessions separate', () => {
  const store = new TerminalStreamStore();
  store.applyEvent({ ...data(1, 'other'), sessionId: 'session-2', profileId: 'profile-2' });
  assert.equal(store.applySnapshot(state(1, 'one')).refreshNeeded, true);
  const result = store.applySnapshot({ profiles: [{ profileId: 'profile-2', cwd: '/other', sessions: [{ sessionId: 'session-2', sequence: 0, replay: '', status: 'starting' }] }] });
  assert.deepEqual(result.writes, [{ sessionId: 'session-2', data: 'other' }]);
  assert.deepEqual(store.snapshot().profiles.map(profile => profile.sessions.map(session => session.sessionId)), [['session-1'], ['session-2']]);
});

test('large pasted unicode input preserves content and fits UTF-8 IPC limits', () => {
  const input = '中文🦆x'.repeat(15000);
  const chunks = splitTerminalInput(input);
  assert.equal(chunks.join(''), input);
  assert(chunks.length > 1);
  assert(chunks.every(chunk => Buffer.byteLength(chunk) <= 32 * 1024));
  assert(chunks.every(chunk => !/[\uD800-\uDBFF]$/.test(chunk)));
  assert.deepEqual(splitTerminalInput(''), []);
});

test('bottom-anchored terminal dragging grows upward and stays inside viewport bounds', () => {
  assert.equal(terminalHeightForPointer(360, 500, 450, 320, 620), 410);
  assert.equal(terminalHeightForPointer(360, 500, 900, 320, 620), 320);
  assert.equal(terminalHeightForPointer(360, 500, -100, 320, 620), 620);
});

test('keyboard separator changes height without requiring pointer input', () => {
  assert.equal(terminalHeightForKey(360, 'ArrowUp', 320, 620), 392);
  assert.equal(terminalHeightForKey(330, 'ArrowDown', 320, 620), 320);
  assert.equal(terminalHeightForKey(360, 'Home', 320, 620), 320);
  assert.equal(terminalHeightForKey(360, 'End', 320, 620), 620);
  assert.equal(terminalHeightForKey(360, 'ArrowUp', 320, 620, 64), 424);
  assert.equal(terminalHeightForKey(360, 'Enter', 320, 620), null);
});

test('same-profile duplicate process output and exit stay separate from the source', () => {
  const store = new TerminalStreamStore();
  store.applySnapshot(state(2, 'source command'));
  const duplicate = { sessionId: 'duplicate-1', profileId: 'profile-1', sequence: 1, status: 'running', replay: 'new shell', cwd: '/workspace' };
  store.applyEvent({ ...data(2, 'duplicate live'), sessionId: duplicate.sessionId });
  const result = store.applySnapshot({ profiles: [{ profileId: 'profile-1', sessions: [duplicate] }] });
  assert.deepEqual(result.writes, [{ sessionId: 'duplicate-1', data: 'new shell' }, { sessionId: 'duplicate-1', data: 'duplicate live' }]);
  store.applyEvent({ type: 'exit', profileId: 'profile-1', sessionId: 'duplicate-1', sequence: 3, exitCode: 0 });
  assert.equal(store.getSession('session-1').status, 'running');
  assert.equal(store.getSession('duplicate-1').status, 'exited');
  assert.equal(store.replayFor('session-1'), 'source command');
  assert.equal(store.replayFor('duplicate-1'), 'new shellduplicate live');
});
