import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ProxyCompatibilityDetails, proxyCompatibilityPresentation } from '../src/proxy-compatibility.mjs';
import { languages, translationCatalog, translate } from '../src/i18n.mjs';

const snapshot = overrides => ({ enabled: true, recoveredConnections: 2, failedConnections: 1, lastErrorCode: null, lastUpstreamStatus: null, ...overrides });
const render = (compatibility, language = 'zh-CN') => renderToStaticMarkup(React.createElement(ProxyCompatibilityDetails, {
  compatibility, t: (text, vars) => translate(text, language, vars),
}));
const errors = {
  AUTH_REQUIRED: '代理认证失败，请检查用户名和密码。',
  DENIED: '代理拒绝了连接，请检查访问权限。',
  RATE_LIMITED: '代理请求过于频繁，请稍后重试。',
  DESTINATION_DNS_FAILED: '目标地址解析失败，请稍后重试。',
  CONNECT_FAILED: '代理隧道未建立，请检查线路后重试。',
  TLS_FAILED: '代理 TLS 验证失败，请检查证书配置。',
  RECOVERED: '已自动恢复兼容连接。',
};

test('runtime compatibility diagnostics stay collapsed and do not appear without explicit active metadata', () => {
  for (const value of [null, undefined, {}, [], snapshot({ enabled: false }), snapshot({ enabled: 'true' }), snapshot({ enabled: 1 })]) {
    assert.equal(render(value), '');
  }
  const html = render(snapshot({ lastUpstreamStatus: 200 }));
  assert.match(html, /^<details class="advanced-settings"><summary>连接诊断<\/summary>/);
  assert.ok(html.includes('兼容恢复 2 次 · 未完成 1 次'));
  assert.ok(html.includes('代理响应：200'));
  assert.doesNotMatch(html, /\bopen(?:=|\s|>)/);
});

test('each fixed connection outcome has a distinct actionable description', () => {
  for (const [code, message] of Object.entries(errors)) {
    const html = render(snapshot({ lastErrorCode: code }));
    assert.ok(html.includes(message), code);
    assert.equal(proxyCompatibilityPresentation(snapshot({ lastErrorCode: code })).message, message);
  }
});

test('unknown and malformed diagnostic errors cannot expose connection fields or invoke string conversion', () => {
  const privateText = 'https://fixture-user:fixture-password@private.example.test:34567/path';
  const compatibility = snapshot({ lastErrorCode: privateText, lastUpstreamStatus: '407 ' + privateText,
    message: privateText, host: privateText, port: 34567, password: privateText, upstream: { url: privateText } });
  const html = render(compatibility);
  assert.ok(html.includes('兼容连接未完成，请检查线路后重试。'));
  assert.doesNotMatch(html, /fixture-user|fixture-password|private\.example|34567|\/path|代理响应/);
  assert.deepEqual(Object.keys(proxyCompatibilityPresentation(compatibility)).sort(), ['failed', 'message', 'recovered', 'status']);
  for (const lastErrorCode of [{ toString() { throw new Error('must not convert raw diagnostics'); } }, ['AUTH_REQUIRED'], 407]) {
    assert.ok(render(snapshot({ lastErrorCode })).includes('兼容连接未完成，请检查线路后重试。'));
  }
});

test('only safe counters and integer HTTP status codes are displayed without coercion', () => {
  for (const value of [-1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '2', {}, null]) {
    assert.equal(render(snapshot({ recoveredConnections: value })), '');
    assert.equal(render(snapshot({ failedConnections: value })), '');
  }
  assert.ok(render(snapshot({ recoveredConnections: 0, failedConnections: 0 })).includes('兼容恢复 0 次 · 未完成 0 次'));
  for (const lastUpstreamStatus of [99, 600, 407.5, '407', NaN, {}, null]) {
    assert.doesNotMatch(render(snapshot({ lastUpstreamStatus })), /代理响应/);
  }
  for (const status of [100, 407, 429, 599]) assert.ok(render(snapshot({ lastUpstreamStatus: status })).includes(`代理响应：${status}`));
});

test('the actual diagnostics component renders its complete translated copy in all nine languages', () => {
  const keys = ['连接诊断', '兼容恢复 {recovered} 次 · 未完成 {failed} 次', '代理响应：{status}', ...Object.values(errors), '兼容连接未完成，请检查线路后重试。'];
  assert.equal(languages.length, 9);
  for (const language of languages) {
    for (const key of keys) assert.ok(Object.hasOwn(translationCatalog[language], key), `${language}: ${key}`);
    for (const code of [...Object.keys(errors), 'UNKNOWN']) {
      const html = render(snapshot({ lastErrorCode: code, lastUpstreamStatus: 407 }), language);
      assert.ok(html.includes(translate('连接诊断', language)));
      const message = errors[code] || '兼容连接未完成，请检查线路后重试。';
      const escaped = renderToStaticMarkup(React.createElement('span', null, translate(message, language))).replace(/^<span>|<\/span>$/g, '');
      assert.ok(html.includes(escaped), `${language}: ${code}`);
      assert.ok(html.includes('407'));
      assert.doesNotMatch(html, /\{recovered\}|\{failed\}|\{status\}/);
    }
  }
});
