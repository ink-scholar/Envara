import { claudeAccountLabel } from './claude-account-choice.mjs';
import { CLAUDE_SESSION } from './terminal-session-choice.mjs';

import { activeStatuses } from './terminal-session-status.mjs';

// Names come from the session's bound profile metadata, never credentials or
// an inferred signed-in state. The default profile may have been renamed.
export function terminalAccountName(session, t) {
  if (session?.kind !== CLAUDE_SESSION) return null;
  if (!session.claudeAccountName) return t('登录档案不可用');
  return claudeAccountLabel({ default: session.claudeAccountId === 'default', name: session.claudeAccountName }, t);
}

export function terminalSessionName(session, sessions, t) {
  if (session.savedTerminalName) {
    const named = sessions.filter(item => item.savedTerminalName === session.savedTerminalName);
    return named.length > 1 ? `${session.savedTerminalName} · ${named.findIndex(item => item.sessionId === session.sessionId) + 1}` : session.savedTerminalName;
  }
  const index = sessions.findIndex(item => item.sessionId === session.sessionId) + 1;
  return session.kind === CLAUDE_SESSION
    ? `Claude Code${session.claudeAccountId && session.claudeAccountId !== 'default' ? ` · ${session.claudeAccountName || session.claudeAccountId}` : ''} ${index}`
    : t('会话 {index}', { index });
}

export function terminalsForAccount(profiles, profileId, accountId) {
  if (!profileId || !accountId) return [];
  return (profiles ?? []).filter(profile => profile.profileId === profileId)
    .flatMap(profile => profile.sessions ?? [])
    .filter(session => session.profileId === profileId && session.kind === CLAUDE_SESSION
      && session.claudeAccountId === accountId && activeStatuses.has(session.status));
}
