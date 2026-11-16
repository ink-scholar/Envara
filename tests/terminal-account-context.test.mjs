import test from 'node:test';
import assert from 'node:assert/strict';
import { terminalAccountName, terminalsForAccount } from '../src/terminal-account-context.mjs';

test('terminal account associations require both environment and account identity and an active dedicated session', () => {
  const session = { sessionId: 'owned', profileId: 'environment_a', kind: 'claude-code', claudeAccountId: 'account_a', status: 'running' };
  const snapshot = [{ profileId: 'environment_a', sessions: [session,
    { ...session, sessionId: 'starting', status: 'starting' }, { ...session, sessionId: 'closing', status: 'closing' },
    { ...session, sessionId: 'ended', status: 'closed' }, { ...session, sessionId: 'shell', kind: 'shell' },
    { ...session, sessionId: 'same-name', claudeAccountId: 'account_b' }, { ...session, sessionId: 'wrong-owner', profileId: 'environment_b' }] },
  { profileId: 'environment_b', sessions: [{ ...session, sessionId: 'foreign', profileId: 'environment_b' }] }];
  assert.deepEqual(terminalsForAccount(snapshot, 'environment_a', 'account_a').map(item => item.sessionId), ['owned', 'starting', 'closing']);
  assert.deepEqual(terminalsForAccount(snapshot, 'environment_a', ''), []);
});

test('terminal account labels preserve renamed default names and never infer authentication', () => {
  const t = value => `translated:${value}`;
  assert.equal(terminalAccountName({ kind: 'claude-code', claudeAccountId: 'default', claudeAccountName: '默认' }, t), 'translated:默认档案');
  assert.equal(terminalAccountName({ kind: 'claude-code', claudeAccountId: 'default', claudeAccountName: 'My named profile' }, t), 'My named profile');
  assert.equal(terminalAccountName({ kind: 'claude-code', claudeAccountId: 'unknown' }, t), 'translated:登录档案不可用');
  assert.equal(terminalAccountName({ kind: 'shell', claudeAccountName: 'ignored' }, t), null);
});
