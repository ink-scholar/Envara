import React from 'react';

const messages = Object.freeze({
  AUTH_REQUIRED: '代理认证失败，请检查用户名和密码。',
  DENIED: '代理拒绝了连接，请检查访问权限。',
  RATE_LIMITED: '代理请求过于频繁，请稍后重试。',
  DESTINATION_DNS_FAILED: '目标地址解析失败，请稍后重试。',
  CONNECT_FAILED: '代理隧道未建立，请检查线路后重试。',
  TLS_FAILED: '代理 TLS 验证失败，请检查证书配置。',
  RECOVERED: '已自动恢复兼容连接。',
});
const count = value => Number.isSafeInteger(value) && value >= 0;

// Project only counters, a bounded HTTP status and fixed copy. Raw connection
// errors and extra snapshot fields never become renderer diagnostic text.
export function proxyCompatibilityPresentation(value) {
  if (!value || Array.isArray(value) || value.enabled !== true ||
      !count(value.recoveredConnections) || !count(value.failedConnections)) return null;
  const code = value.lastErrorCode;
  return {
    recovered: value.recoveredConnections,
    failed: value.failedConnections,
    status: Number.isInteger(value.lastUpstreamStatus) && value.lastUpstreamStatus >= 100 && value.lastUpstreamStatus <= 599 ? value.lastUpstreamStatus : null,
    message: code == null ? null : typeof code === 'string' && Object.hasOwn(messages, code) ? messages[code] : '兼容连接未完成，请检查线路后重试。',
  };
}

export function ProxyCompatibilityDetails({ compatibility, t = value => value }) {
  const result = proxyCompatibilityPresentation(compatibility);
  if (!result) return null;
  return React.createElement('details', { className: 'advanced-settings' },
    React.createElement('summary', null, t('连接诊断')),
    React.createElement('p', { className: 'field-hint' }, t('兼容恢复 {recovered} 次 · 未完成 {failed} 次', result)),
    result.message && React.createElement('p', { className: 'field-hint' }, t(result.message)),
    result.status != null && React.createElement('p', { className: 'field-hint' }, t('代理响应：{status}', { status: result.status })));
}
