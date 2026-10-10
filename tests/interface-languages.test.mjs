import test from 'node:test';
import assert from 'node:assert/strict';
import { languageOptions, languages, isInterfaceLanguage, localeForInterfaceLanguage, recommendInterfaceLanguage } from '../shared/interface-languages.mjs';

test('the interface catalog has native names and a strict persisted language set', () => {
  assert.equal(languages.length, 9);
  assert.equal(new Set(languages).size, 9);
  assert.ok(languageOptions.every(option => option.nativeName && option.englishName && isInterfaceLanguage(option.code)));
  assert.ok(Object.isFrozen(languageOptions) && Object.isFrozen(languageOptions[0]));
  for (const value of [null, {}, ['en'], '__proto__', 'en-US']) assert.equal(isInterfaceLanguage(value), false);
});

test('system recommendations distinguish Chinese scripts and respect preference order', () => {
  for (const value of ['zh-TW', 'zh-HK', 'zh-MO', 'zh-Hant', 'zh-Hant-CN']) assert.equal(recommendInterfaceLanguage([value]), 'zh-TW');
  for (const value of ['zh-CN', 'zh-SG', 'zh-Hans-TW', 'zh']) assert.equal(recommendInterfaceLanguage([value]), 'zh-CN');
  assert.equal(recommendInterfaceLanguage(['ar-SA', 'ko-KR', 'en-US']), 'ko');
  assert.equal(recommendInterfaceLanguage(['de-DE', 'fr-FR']), 'de');
  assert.equal(recommendInterfaceLanguage('ja_JP'), 'ja');
  assert.equal(recommendInterfaceLanguage(['pt-PT']), 'pt-BR');
});

test('unsupported or malformed system locales use English without changing host settings', () => {
  for (const value of [undefined, null, {}, [], [12, 'not_a_locale!'], ['ar-SA']]) assert.equal(recommendInterfaceLanguage(value), 'en');
  assert.equal(localeForInterfaceLanguage('en'), 'en-US');
  assert.equal(localeForInterfaceLanguage('zh-TW'), 'zh-TW');
  assert.equal(localeForInterfaceLanguage('pt-BR'), 'pt-BR');
});
