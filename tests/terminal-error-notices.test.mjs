import test from 'node:test';
import assert from 'node:assert/strict';
import { TerminalErrorNotices } from '../src/terminal-error-notices.mjs';

test('a failed session retains the error after its tab exits without repeating status, exit and snapshot notices', () => {
  const notices = new TerminalErrorNotices();
  const failure = { sessionId: 'term_a', error: 'Network component exited.', errorCode: 'CLAUDE_ROUTE_EXITED' };
  assert.deepEqual(notices.take({ ...failure, type: 'status', status: 'closing' }), { sessionId: 'term_a', message: failure.error, code: failure.errorCode, cleanupError: '' });
  assert.equal(notices.take({ ...failure, type: 'exit', status: 'closed' }), null);
  assert.equal(notices.take({ ...failure, status: 'closed', kind: 'claude-code' }), null);
  assert.equal(notices.take({ sessionId: 'term_a', status: 'closed', error: failure.error }), null, 'an older snapshot without a code cannot erase it');
  assert.equal(notices.take({ sessionId: 'term_b', status: 'closed' }), null, 'a normal close is not an error');
});

test('a later error code enriches the same incident and a different session remains reportable', () => {
  const notices = new TerminalErrorNotices();
  assert.deepEqual(notices.take({ sessionId: 'term_a', error: 'Stopped.' }), { sessionId: 'term_a', message: 'Stopped.', code: '', cleanupError: '' });
  assert.deepEqual(notices.take({ sessionId: 'term_a', error: 'Stopped.', errorCode: 'CLAUDE_ROUTE_EXITED' }), { sessionId: 'term_a', message: 'Stopped.', code: 'CLAUDE_ROUTE_EXITED', cleanupError: '' });
  assert.deepEqual(notices.take({ sessionId: 'term_b', error: 'Stopped.', errorCode: 'CLAUDE_ROUTE_EXITED' }), { sessionId: 'term_b', message: 'Stopped.', code: 'CLAUDE_ROUTE_EXITED', cleanupError: '' });
  assert.equal(notices.take({ error: 'No session identity' }), null);
  assert.deepEqual(notices.take({ sessionId: 'term_c', error: 'Stopped.', errorCode: 'invalid\ncode' }), { sessionId: 'term_c', message: 'Stopped.', code: '', cleanupError: '' });
});

test('cleanup failure is shown separately even when the primary failure was already reported', () => {
  const notices = new TerminalErrorNotices();
  const primary = { sessionId: 'term_a', error: 'Proxy core exited.', errorCode: 'CLAUDE_NETWORK_ROUTE_LOST', status: 'closing' };
  notices.take({ ...primary, sequence: 1 });
  const cleanup = { ...primary, sequence: 2, cleanupError: 'Try closing again.' };
  assert.deepEqual(notices.take(cleanup), { sessionId: 'term_a', message: primary.error, code: primary.errorCode, cleanupError: cleanup.cleanupError });
  assert.equal(notices.take(cleanup), null);
  assert.equal(notices.take({ ...primary, sequence: 3 }), null, 'an intermediate event omitting cleanup is not proof of completed cleanup');
  const resolved = notices.take({ ...primary, status: 'error', sequence: 4 });
  assert.deepEqual(resolved, { sessionId: 'term_a', message: primary.error, code: primary.errorCode, cleanupError: '', updateOnly: true });
  assert.equal(notices.take({ ...primary, status: 'error', sequence: 4 }), null, 'resolved snapshots do not repeat the primary failure');
  assert.equal(notices.take(cleanup), null, 'a stale cleanup event cannot resurrect its warning');
  assert.equal(notices.take({ ...cleanup, sequence: undefined }), null, 'a duplicate without sequence cannot resurrect the warning either');
});

test('cleanup text is bounded and explicit successful cleanup only updates the current notice', () => {
  const notices = new TerminalErrorNotices();
  const primary = { sessionId: 'term_a', error: 'Stopped.', status: 'closing' };
  const notice = notices.take({ ...primary, cleanupError: 'x'.repeat(2000) });
  assert.equal(notice.cleanupError.length, 512);
  const resolved = notices.take({ ...primary, cleanupError: null });
  assert.equal(resolved.cleanupError, ''); assert.equal(resolved.updateOnly, true); assert.equal(resolved.sessionId, 'term_a');
  assert.equal(notices.take({ ...primary, status: 'closed' }), null);
});
