import { sanitizeClaudeKeychainDiagnostic } from '../shared/claude-keychain-diagnostic.mjs';
import React from 'react';

const messages = Object.freeze({
  CLAUDE_KEYCHAIN_LOCKED: '登录钥匙串已锁定。终端仍可使用；需要钥匙串的登录操作请在解锁后重试。',
  CLAUDE_KEYCHAIN_MISSING: '未找到默认钥匙串。终端仍可使用；请检查 macOS 钥匙串后新建终端。',
});

/** A recoverable storage warning belongs to the selected ordinary session. */
export function TerminalKeychainNotice({ session, t = value => value }) {
  if (session?.kind !== 'shell' || session.status !== 'running'
    || !Object.hasOwn(messages, session.keychainWarningCode)) return null;
  const message = t(messages[session.keychainWarningCode]);
  return React.createElement('span', { className: 'terminal-keychain-notice', role: 'status', title: message }, message);
}

export function terminalKeychainDiagnosticText(value) {
  const diagnostic = sanitizeClaudeKeychainDiagnostic(value);
  return diagnostic ? `${diagnostic.stage}${diagnostic.osStatus == null ? '' : ` / OSStatus ${diagnostic.osStatus}`}` : '';
}
