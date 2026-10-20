import test from 'node:test';
import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFile } from 'node:fs/promises';
import { TerminalDeviceIdentifierDetails } from '../src/terminal-device-identifiers.mjs';
import { translationCatalog, translate } from '../src/i18n.mjs';

const render = (session, language = 'zh-CN', inline = false) => renderToStaticMarkup(React.createElement(TerminalDeviceIdentifierDetails,
  { session, t: value => translate(value, language), inline }));

test('confirmed dedicated-session metadata shows a collapsed device-identifier row and its boundary', () => {
  const html = render({ kind: 'claude-code', sessionId: 'owned_session', deviceIdentifierRestrictions: true });
  assert.match(html, /^<details class="terminal-claude-settings terminal-session-settings">/);
  assert.match(html, /<summary>会话设置<\/summary>/);
  assert.match(html, /<dt>设备标识<\/dt>/);
  assert.match(html, /<dd>已限制序列号与 UUID 读取<small>仅覆盖已验证接口，不提供虚拟硬件身份。<\/small><\/dd>/);
  assert.doesNotMatch(html, /\bopen(?:=|\s|>)/);
  assert.doesNotMatch(html, /owned_session/);
});

test('ordinary terminals never display the device restriction even with other privacy/fence flags', () => {
  for (const kind of ['shell', 'terminal', '', undefined]) {
    for (const inline of [false, true]) assert.equal(render({ kind, deviceIdentifierRestrictions: true, network: { fenced: true }, privacy: { mode: 'strict' } }, 'zh-CN', inline), '');
  }
});

test('confirmed metadata renders inline inside session settings without a second disclosure or borrowed identity', () => {
  const html = render({ kind: 'claude-code', sessionId: 'owned_session', deviceIdentifierRestrictions: true }, 'zh-CN', true);
  assert.match(html, /^<div class="terminal-claude-settings terminal-session-settings">/);
  assert.doesNotMatch(html, /<details|<summary|owned_session/);
  assert.match(html, /<dt>设备标识<\/dt>/);
  assert.match(html, /<dd>已限制序列号与 UUID 读取<small>仅覆盖已验证接口，不提供虚拟硬件身份。<\/small><\/dd>/);
});

test('missing, disabled, in-progress and truthy non-boolean metadata do not make a protection claim', () => {
  for (const value of [undefined, null, false, 'true', 1, {}, []]) {
    for (const inline of [false, true]) assert.equal(render({ kind: 'claude-code', deviceIdentifierRestrictions: value, network: { fenced: true }, privacy: { mode: 'strict' } }, 'zh-CN', inline), '');
  }
  assert.equal(render(null), ''); assert.equal(render(undefined), '');
  assert.equal(render({ kind: 'claude-code', status: 'starting', network: { fenced: true } }), '');
});

test('switching between session snapshots cannot borrow a previous Claude restriction', () => {
  const restricted = { kind: 'claude-code', deviceIdentifierRestrictions: true };
  assert.ok(render(restricted));
  assert.equal(render({ kind: 'claude-code' }), '');
  assert.equal(render({ kind: 'shell', deviceIdentifierRestrictions: true }), '');
  assert.ok(render(restricted));
});

test('the three pieces of copy are complete in all nine languages and the real component renders each one', () => {
  const keys = ['设备标识', '已限制序列号与 UUID 读取', '仅覆盖已验证接口，不提供虚拟硬件身份。'];
  assert.equal(Object.keys(translationCatalog).length, 9);
  for (const [language, catalog] of Object.entries(translationCatalog)) {
    for (const key of keys) {
      assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
      assert.ok(catalog[key].trim());
      const text = renderToStaticMarkup(React.createElement('span', null, translate(key, language))).replace(/^<span>|<\/span>$/g, '');
      for (const inline of [false, true]) {
        const html = render({ kind: 'claude-code', deviceIdentifierRestrictions: true }, language, inline);
        assert.ok(html.includes(text), `${language}: actual translated component text, inline=${inline}`);
      }
    }
  }
});

test('the dock passes only the selected live session, never chooser values or profile-level defaults', async () => {
  const source = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  assert.match(source, /<TerminalDeviceIdentifierDetails session=\{selectedSession\} t=\{t\} inline \/>/);
  assert.equal(source.match(/<TerminalDeviceIdentifierDetails/g)?.length, 1);
  const chooserStart = source.indexOf('{newSession && (() => {');
  const chooserEnd = source.indexOf('})()}', chooserStart);
  assert.ok(chooserStart >= 0 && chooserEnd > chooserStart, 'the actual chooser block must be inspected');
  const chooser = source.slice(chooserStart, chooserEnd);
  assert.doesNotMatch(chooser, /deviceIdentifierRestrictions|已限制序列号/);
});
