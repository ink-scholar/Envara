import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initialBrowserDeviceFields, selectBrowserDeviceProfile, changeBrowserDeviceEngine } from '../src/browser-device-form.mjs';
import { BROWSER_DEVICE_PROFILES } from '../shared/browser-device-profile.mjs';
import { translationCatalog, translate } from '../src/i18n.mjs';

test('new supported browsers default to the host platform while existing devices stay untouched', () => {
  for (const [platform, id] of [['darwin', 'mac-standard-v1'], ['win32', 'windows-standard-v1'], ['linux', 'linux-standard-v1']]) {
    assert.equal(initialBrowserDeviceFields(null, platform, 'cloakbrowser').deviceProfileId, id);
  }
  const old = { platform: 'windows', width: 1366, height: 768, seed: 42, fingerprint: { 'navigator.hardwareConcurrency': 4 } };
  const fields = initialBrowserDeviceFields(old, 'darwin', 'cloakbrowser');
  assert.deepEqual(fields, { deviceProfileId: 'provider-default' });
  assert.deepEqual({ ...old, ...fields }, { ...old, deviceProfileId: 'provider-default' });
  assert.deepEqual(initialBrowserDeviceFields(null, 'darwin', 'camoufox'), { deviceProfileId: 'provider-default' });
});

test('only explicit preset selection changes device fields and custom keeps the current values', () => {
  const form = { engine: 'cloakbrowser', platform: 'macos', width: 1440, height: 900, seed: 42, proxyId: 'ph', locale: 'zh-CN', timezone: 'Asia/Manila', deviceProfileId: 'provider-default' };
  const selected = selectBrowserDeviceProfile(form, 'windows-standard-v1');
  assert.deepEqual(selected, { ...form, platform: 'windows', width: 1920, height: 1080, deviceProfileId: 'windows-standard-v1' });
  const custom = selectBrowserDeviceProfile(selected, 'provider-default');
  assert.deepEqual(custom, { ...selected, deviceProfileId: 'provider-default' });
  const differentNetwork = { ...selected, proxyId: 'jp' };
  assert.equal(differentNetwork.seed, form.seed);
  assert.equal(differentNetwork.deviceProfileId, selected.deviceProfileId);
  assert.equal(differentNetwork.width, selected.width);
  assert.throws(() => selectBrowserDeviceProfile(form, 'unknown'));
});

test('choosing a provider without verified device mappings stops applying fixed presets', () => {
  const form = selectBrowserDeviceProfile({ engine: 'cloakbrowser', seed: 42 }, 'mac-standard-v1');
  const other = changeBrowserDeviceEngine(form, 'camoufox');
  assert.deepEqual(other, { ...form, engine: 'camoufox', deviceProfileId: 'provider-default' });
  assert.equal(changeBrowserDeviceEngine(other, 'cloakbrowser').deviceProfileId, 'provider-default', 'returning to CloakBrowser does not silently replace custom settings');
});

test('device form wires explicit changes, readonly fixed summaries and persisted metadata', async () => {
  const pane = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  assert.match(pane, /initialBrowserDeviceFields\(profile, systemPlatform/);
  assert.match(pane, /selectBrowserDeviceProfile\(value, event\.target\.value\)/);
  assert.match(pane, /deviceProfileId: form\.deviceProfileId/);
  assert.match(pane, /const profileFields = .*"deviceProfileId"/);
  for (const field of ['platform', 'width', 'height']) assert.ok(pane.includes(`!selectedDevice && field("${field}"`));
  assert.match(pane, /className="browser-device-summary"/);
  assert.match(pane, /BROWSER_DEVICE_PROFILES\.filter\(device => device\.id === defaultBrowserDeviceProfileId\(systemPlatform\)\)/);
  assert.match(pane, /selectedDevice\.hardwareConcurrency/);
  assert.match(pane, /selectedDevice\.deviceMemory/);
  assert.match(pane, /浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。/);
  const terminal = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  assert.match(terminal, /selectedSession\?\.language \?\? selectedMetadata\?\.language/);
  assert.match(terminal, /title=\{languageLabel\}/);
});

test('device and effective-language copy is available in all nine languages', () => {
  const keys = ['设备档案', '自定义（保留当前配置）', '选择档案会填写平台与屏幕；切换网络不改变设备。', '平台', '屏幕', '逻辑处理器', '浏览器内存', '浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。', '当前内核暂不支持固定设备档案。', '有效语言', '{requested} → {effective}（系统未提供所选语言）', ...BROWSER_DEVICE_PROFILES.map(item => item.label)];
  for (const [language, catalog] of Object.entries(translationCatalog)) {
    for (const key of keys) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    for (const key of ['浏览器设备档案无效。', '此浏览器内核暂不支持固定设备档案，请保留现有配置。', '设备档案与平台或硬件参数不一致。请先切换为自定义配置。', '固定设备档案须与本机平台一致。跨平台配置请使用自定义。']) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    assert.ok(translate(keys[10], language, { requested: 'ms-MY', effective: 'en-US' }).includes('ms-MY'));
    assert.ok(translate(keys[10], language, { requested: 'ms-MY', effective: 'en-US' }).includes('en-US'));
  }
});
