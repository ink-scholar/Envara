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

test('appearance settings and workspace controls do not fall back to Chinese', () => {
  const messages = [
    '界面外观', '跟随系统', '浅色', '深色',
    '仅改变境舱界面，不影响环境内的软件。', '无法保存外观，请重试。',
    '状态', '打开', '不可用', '待检测', '已移除的软件', '正在读取…', '查看日志', '默认',
    '关闭窗口不会退出软件，点「打开窗口」或程序坞图标即可重新打开。',
  ];
  for (const language of languages) {
    for (const key of messages) {
      assert(Object.hasOwn(translationCatalog[language], key), `${language}: ${key}`);
      if (!language.startsWith('zh')) assert.notEqual(translate(key, language), key, `${language}: ${key}`);
    }
    assert(translate(messages.at(-1), language).includes(translate('打开窗口', language)), language);
  }
  assert.equal(translate('附加软件', 'en'), 'Attached applications');
  assert.equal(translate('添加软件', 'en'), 'Attach application');
});


test('routing boundaries and incomplete cleanup messages are available in all nine languages', () => {
  const messages = [
  "经「{name}」代理访问公网，围栏阻止直接公网连接。本地开发服务仍可访问，其联网不受此围栏控制。",
  "环境已删除，但部分附加软件绑定或应用数据未清理完成。请到「附加软件」检查并清理。",
  "普通终端和附加软件的链接使用境舱浏览器；关闭后改用本机浏览器。Claude 会话的链接与浏览器工具仍使用绑定的境舱浏览器。"
];
  for (const language of languages) {
    for (const key of messages) assert(Object.hasOwn(translationCatalog[language], key), `${language}: ${key}`);
    const route = translate(messages[0], language, { name: 'Owned route' });
    assert(route.includes('Owned route'));
    assert.equal(route.includes('{name}'), false);
  }
});
