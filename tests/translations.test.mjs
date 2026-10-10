import test from 'node:test';
import assert from 'node:assert/strict';
import { languages, english, translationCatalog, translate } from '../src/i18n.mjs';

const variables = value => [...value.matchAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g)].map(match => match[1]).sort();

test('every offered language translates the full interface catalog and preserves interpolation', () => {
  const keys = Object.keys(english).sort();
  assert.ok(keys.length >= 562);
  assert.deepEqual(Object.keys(translationCatalog).sort(), [...languages].sort());
  for (const language of languages) {
    const dictionary = translationCatalog[language];
    assert.deepEqual(Object.keys(dictionary).sort(), keys, language);
    for (const key of keys) {
      assert.equal(typeof dictionary[key], 'string', `${language}: ${key}`);
      assert.ok(dictionary[key].trim(), `${language}: ${key}`);
      assert.deepEqual(variables(dictionary[key]), variables(english[key]), `${language}: ${key}`);
      assert.equal(translate(key, language), dictionary[key]);
    }
  }
});

test('translations interpolate live session data and retain arbitrary user text', () => {
  for (const language of languages) {
    const result = translate('{name} · 终端 · Envara', language, { name: 'my-local-project' });
    assert.ok(result.includes('my-local-project') && result.includes('Envara'));
    assert.equal(result.includes('{name}'), false);
    for (const text of ['my-local-project', '/Users/me/a-project', 'constructor', 'toString', '__proto__']) assert.equal(translate(text, language), text);
  }
  assert.equal(translate(null, 'ja'), null);
});

test('unsupported language values fall back to English for known UI text', () => {
  assert.equal(translate('保存', 'not-supported'), 'Save');
  assert.equal(translate('保存', 'zh-CN'), '保存');
});
