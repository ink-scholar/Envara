import React from 'react';
import { CLAUDE_SESSION } from './terminal-session-choice.mjs';

/** Only a confirmed property of this exact dedicated session is displayed. */
export function TerminalDeviceIdentifierDetails({ session, t = value => value, inline = false }) {
  if (session?.kind !== CLAUDE_SESSION || session.deviceIdentifierRestrictions !== true) return null;
  return React.createElement(inline ? 'div' : 'details', { className: 'terminal-claude-settings terminal-session-settings' },
    !inline && React.createElement('summary', null, t('会话设置')),
    React.createElement('dl', null,
      React.createElement('div', null,
        React.createElement('dt', null, t('设备标识')),
        React.createElement('dd', null, t('已限制序列号与 UUID 读取'),
          React.createElement('small', null, t('仅覆盖已验证接口，不提供虚拟硬件身份。'))))));
}
