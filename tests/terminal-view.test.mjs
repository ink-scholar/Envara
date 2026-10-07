import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveTerminalView, terminalViewSnapshot } from '../electron/terminal-view.mjs';

test('opening a view validates profile ownership and never silently attaches an unavailable session', () => {
  const workspace = { profiles: [{ id: 'prof_a', name: 'A' }, { id: 'prof_b', name: 'B' }] };
  const state = { profiles: [{ profileId: 'prof_a', sessions: [{ sessionId: 'term_a', status: 'running' }] }, { profileId: 'prof_b', sessions: [{ sessionId: 'term_b', status: 'running' }] }] };
  assert.deepEqual(resolveTerminalView({ id: 'prof_a' }, workspace, state), { profileId: 'prof_a', name: 'A', sessionId: 'term_a' });
  for (const sessionId of ['term_missing', 'term_b']) assert.throws(() => resolveTerminalView({ id: 'prof_a', sessionId }, workspace, state), { code: 'TERMINAL_SESSION_NOT_FOUND' });
  assert.throws(() => resolveTerminalView({ id: '../a' }, workspace, state), { code: 'VALIDATION_ERROR' });
  assert.throws(() => resolveTerminalView({ id: 'missing' }, workspace, state), { code: 'PROFILE_NOT_FOUND' });
  assert.equal(resolveTerminalView({ id: 'prof_a' }, workspace, { profiles: [] }).sessionId, undefined);
});

test('independent terminal workspace notifications omit credentials and privileged connection configuration', () => {
  const safe = terminalViewSnapshot({ profiles: [{ id: 'prof_a', name: 'A', notes: 'private notes', proxy: { password: 'secret' }, status: 'stopped' }], proxies: [{ username: 'private', password: 'secret' }], settings: { secret: 'secret' }, system: { platform: 'darwin', appVersion: '0.3.0', localApi: 'privileged', terminal: { supported: true } }, integration: { mcp: { token: 'secret' } } });
  assert.deepEqual(safe.profiles, [{ id: 'prof_a', name: 'A', status: 'stopped' }]);
  assert.equal(JSON.stringify(safe).includes('secret'), false);
  assert.equal(safe.system.localApi, undefined);
  const event = { sessionId: 'term_a', profileId: 'prof_a', sequence: 3, status: 'running' };
  assert.equal(terminalViewSnapshot(event), event);
});
