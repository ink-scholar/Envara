import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { initialBrowserDeviceFields, selectBrowserDeviceProfile, changeBrowserDeviceEngine, browserDimensionValue, validBrowserDimension } from '../src/browser-device-form.mjs';
import { BROWSER_DEVICE_PROFILES } from '../shared/browser-device-profile.mjs';
import { translationCatalog, translate } from '../src/i18n.mjs';

test('new browsers leave device and dimensions to their provider on every host', () => {
  for (const platform of ['darwin', 'win32', 'linux']) {
    for (const engine of ['cloakbrowser', 'camoufox', 'browseforge-chromium']) {
      assert.deepEqual(initialBrowserDeviceFields(null, platform, engine), { deviceProfileId: 'provider-default', width: '', height: '' });
    }
  }
});

test('editing legacy, custom and fixed environments preserves exact values and seed', () => {
  const old = { platform: 'windows', width: 1366, height: 768, seed: 42, fingerprint: { 'navigator.hardwareConcurrency': 4, 'screen.width': 1366 } };
  for (const deviceProfileId of [undefined, 'provider-default', 'windows-standard-v1']) {
    const profile = { ...old, ...(deviceProfileId ? { deviceProfileId } : {}) };
    const before = structuredClone(profile);
    const fields = initialBrowserDeviceFields(profile, 'darwin', 'cloakbrowser');
    assert.deepEqual(fields, { deviceProfileId: deviceProfileId ?? 'provider-default' });
    assert.deepEqual({ ...profile, ...fields }, { ...before, deviceProfileId: deviceProfileId ?? 'provider-default' });
    assert.deepEqual(profile, before, 'initialization never mutates a saved profile');
  }
});

test('blank dimensions explicitly restore automatic while filled values remain numeric and bounded', () => {
  for (const value of ['', '  ', null, undefined]) {
    assert.equal(browserDimensionValue(value), null);
    assert.equal(validBrowserDimension(value, 800, 7680), true);
    assert.equal(validBrowserDimension(value, 600, 4320), true);
  }
  for (const [value, dimension] of [[1440, 1440], ['1920', 1920], ['900', 900], [' 1080 ', 1080]]) {
    assert.equal(browserDimensionValue(value), dimension);
    assert.equal(validBrowserDimension(value, 800, 7680), true);
  }
  for (const value of [0, '0', 799, 7681, 1440.5, 'invalid', NaN, Infinity, true, [], {}]) assert.equal(validBrowserDimension(value, 800, 7680), false);
  assert.equal(validBrowserDimension('800', 800, 7680), true);
  assert.equal(validBrowserDimension('7680', 800, 7680), true);
  assert.equal(validBrowserDimension('599', 600, 4320), false);
  assert.equal(validBrowserDimension('4321', 600, 4320), false);
  assert.deepEqual(JSON.parse(JSON.stringify({ width: browserDimensionValue(''), height: browserDimensionValue('1080') })), { width: null, height: 1080 });
});

test('returning from a preset restores the custom fields it temporarily replaced', () => {
  const form = { engine: 'cloakbrowser', platform: 'macos', width: 1440, height: 900, seed: 42, proxyId: 'ph', locale: 'zh-CN', timezone: 'Asia/Manila', deviceProfileId: 'provider-default' };
  const selected = selectBrowserDeviceProfile(form, 'windows-standard-v1');
  assert.equal(selected.platform, 'windows'); assert.equal(selected.width, 1920); assert.equal(selected.height, 1080);
  const custom = selectBrowserDeviceProfile(selected, 'provider-default');
  assert.deepEqual(custom, form);
  const automaticWidth = { ...custom, width: '' };
  assert.equal(browserDimensionValue(automaticWidth.width), null);
  assert.equal(browserDimensionValue(automaticWidth.height), 900);
  assert.equal(automaticWidth.seed, form.seed);
  const differentNetwork = { ...selected, proxyId: 'jp' };
  assert.equal(differentNetwork.seed, form.seed);
  assert.equal(differentNetwork.deviceProfileId, selected.deviceProfileId);
  assert.equal(differentNetwork.width, selected.width);
  assert.throws(() => selectBrowserDeviceProfile(form, 'unknown'));
});

test('choosing a provider without verified device mappings stops applying fixed presets', () => {
  const form = selectBrowserDeviceProfile({ engine: 'cloakbrowser', seed: 42 }, 'mac-standard-v1');
  const other = changeBrowserDeviceEngine(form, 'unmapped-provider');
  assert.equal(other.engine, 'unmapped-provider'); assert.equal(other.deviceProfileId, 'provider-default');
  assert.equal(browserDimensionValue(other.width), null); assert.equal(browserDimensionValue(other.height), null);
  assert.equal(changeBrowserDeviceEngine(other, 'cloakbrowser').deviceProfileId, 'provider-default', 'returning to CloakBrowser does not silently replace custom settings');
});

test('leaving a saved fixed preset clears only dimensions still supplied by that preset', () => {
  const fixed = { engine: 'cloakbrowser', deviceProfileId: 'mac-standard-v1', platform: 'macos', width: 1440, height: 900, seed: 42 };
  const automatic = selectBrowserDeviceProfile(fixed, 'provider-default');
  assert.equal(browserDimensionValue(automatic.width), null); assert.equal(browserDimensionValue(automatic.height), null);
  assert.equal(automatic.platform, 'macos'); assert.equal(automatic.seed, 42);
  const edited = changeBrowserDeviceEngine({ ...fixed, width: 1366 }, 'unmapped-provider');
  assert.equal(edited.width, 1366, 'an independently edited dimension is not discarded');
  assert.equal(browserDimensionValue(edited.height), null);
  const custom = { ...fixed, deviceProfileId: 'provider-default' };
  assert.deepEqual(changeBrowserDeviceEngine(custom, 'camoufox'), { ...custom, engine: 'camoufox' }, 'matching numbers alone do not make saved custom fields preset-owned');
  assert.deepEqual(fixed, { engine: 'cloakbrowser', deviceProfileId: 'mac-standard-v1', platform: 'macos', width: 1440, height: 900, seed: 42 });
});

test('preset switching retains the original custom baseline across ordinary form edits', () => {
  const original = { engine: 'cloakbrowser', deviceProfileId: 'provider-default', platform: '', width: '', height: 800, seed: 42 };
  const first = selectBrowserDeviceProfile(original, 'mac-standard-v1');
  const second = selectBrowserDeviceProfile({ ...first, name: 'Renamed' }, 'windows-standard-v1');
  const automatic = selectBrowserDeviceProfile(second, 'provider-default');
  assert.deepEqual(automatic, { ...original, name: 'Renamed' });
  assert.deepEqual(changeBrowserDeviceEngine(second, 'unmapped-provider'), { ...original, name: 'Renamed', engine: 'unmapped-provider' });
  assert.equal(JSON.stringify(second).includes('Baseline'), false, 'transient preset provenance never enters serialized configuration');
});

test('switching supported providers keeps the explicitly chosen draft template and custom baseline', () => {
  for (const engine of ['cloakbrowser', 'camoufox', 'browseforge-chromium']) {
    const original = { engine: 'cloakbrowser', deviceProfileId: 'provider-default', platform: '', width: '', height: '', seed: 42 };
    const selected = selectBrowserDeviceProfile(original, 'mac-standard-v1');
    const changed = changeBrowserDeviceEngine(selected, engine);
    assert.equal(changed.deviceProfileId, 'mac-standard-v1');
    assert.equal(changed.width, 1440); assert.equal(changed.height, 900);
    assert.equal(changed.seed, 42);
    assert.deepEqual(selectBrowserDeviceProfile(changed, 'provider-default'), { ...original, engine });
  }
});

test('the actual edit form and save payload preserve an automatic platform', async () => {
  const source = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  const initializer = source.match(/const \[form, setForm\] = useState\(\(\) => \(([\s\S]*?)\)\);/)?.[1];
  const payload = source.match(/onSave\((\{\s+name: form\.name\.trim\(\),[\s\S]*?)\);\s+\};\s+const field/)?.[1];
  assert.ok(initializer); assert.ok(payload);
  const saved = { name: 'Automatic platform', engine: 'cloakbrowser', platform: null, width: null, height: null, seed: 42 };
  const form = runInNewContext(`(${initializer})`, { profile: saved, systemPlatform: 'darwin', engines: [], defaultEngine: 'cloakbrowser', preferredEngine: () => 'cloakbrowser', initialBrowserDeviceFields });
  assert.equal(form.platform, ''); assert.equal(form.seed, saved.seed);
  form.name = 'Renamed only';
  const output = runInNewContext(`(${payload})`, { form, profile: saved, runtime: {}, allows: () => true, browserDimensionValue, confirmedNetworkTimezone: null });
  assert.equal(Object.hasOwn(output, 'platform'), false, 'an unrelated edit must not turn provider policy into a fixed OS override');
  form.platform = 'windows';
  const explicit = runInNewContext(`(${payload})`, { form, profile: saved, runtime: {}, allows: () => true, browserDimensionValue, confirmedNetworkTimezone: null });
  assert.equal(explicit.platform, 'windows');
  assert.match(source, /!profile\?\.platform && <option value="">\{t\("自动（由内核决定）"\)\}<\/option>/);
});

test('the actual edit form never supplies a replacement seed for an existing identity', async () => {
  const source = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  const initializer = source.match(/const \[form, setForm\] = useState\(\(\) => \(([\s\S]*?)\)\);/)?.[1];
  const payload = source.match(/onSave\((\{\s+name: form\.name\.trim\(\),[\s\S]*?)\);\s+\};\s+const field/)?.[1];
  assert.ok(initializer); assert.ok(payload);
  const initialize = profile => runInNewContext(`(${initializer})`, { profile, systemPlatform: 'darwin', engines: [], defaultEngine: 'cloakbrowser', preferredEngine: () => 'cloakbrowser', initialBrowserDeviceFields });
  const save = (form, profile) => runInNewContext(`(${payload})`, { form, profile, runtime: {}, allows: () => true, browserDimensionValue, confirmedNetworkTimezone: null });
  for (const seed of [null, undefined, 0, 42]) {
    const profile = { name: 'Existing identity', engine: 'cloakbrowser', seed };
    const form = initialize(profile);
    assert.equal(form.seed, seed == null ? '' : seed);
    form.name = 'Renamed only';
    assert.equal(Object.hasOwn(save(form, profile), 'seed'), false, 'read-only identity must be preserved by the existing native record');
  }
  const created = initialize(null);
  created.name = 'Fresh identity';
  const output = save(created, null);
  assert.ok(Number.isSafeInteger(output.seed) && output.seed > 0);
  assert.equal(output.seed, created.seed);
});

test('device form wires explicit changes, readonly fixed summaries and persisted metadata', async () => {
  const pane = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  assert.match(pane, /initialBrowserDeviceFields\(profile, systemPlatform/);
  assert.match(pane, /selectBrowserDeviceProfile\(value, event\.target\.value\)/);
  assert.match(pane, /deviceProfileId: form\.deviceProfileId/);
  assert.match(pane, /const profileFields = .*"deviceProfileId"/);
  for (const field of ['platform', 'width', 'height']) assert.ok(pane.includes(`!selectedDevice && field("${field}"`));
  assert.match(pane, /className="browser-device-summary"/);
  assert.match(pane, /BROWSER_DEVICE_PROFILES\.filter\(device => device\.id === defaultBrowserDeviceProfileId\(systemPlatform\) \|\| device\.id === profile\?\.deviceProfileId\)/);
  const profileForm = pane.slice(pane.indexOf('function ProfileForm('), pane.indexOf('function GroupForm('));
  const advanced = profileForm.indexOf('<details className="advanced-settings"');
  assert.match(profileForm.slice(advanced), /<summary>\{t\("高级设置"\)\}<\/summary>/);
  assert.ok(profileForm.indexOf('field("engine"') < advanced, 'engine is available before Advanced');
  assert.equal(profileForm.match(/field\("engine"/g)?.length, 1);
  assert.match(profileForm, /width: "",\s+height: ""/);
  assert.match(profileForm, /width: browserDimensionValue\(form\.width\)/);
  assert.match(profileForm, /height: browserDimensionValue\(form\.height\)/);
  assert.match(profileForm, /validBrowserDimension\(form\[key\], minimum, maximum\)/);
  assert.doesNotMatch(profileForm, /Number\(form\.(?:width|height)\)/);
  for (const dimension of ['width', 'height']) {
    const input = profileForm.match(new RegExp(`<input[^>]*value=\\{form\\.${dimension}\\}[^>]*>`))?.[0];
    assert.ok(input, `${dimension} input exists`);
    assert.doesNotMatch(input, /\brequired\b/);
    assert.ok(input.includes('placeholder={t("自动（由内核决定）")}'));
  }
  assert.match(profileForm, /profile \? "保留当前配置" : "内核自动生成"/);
  assert.match(profileForm, /darwin: "macos",\s+win32: "windows",\s+linux: "linux"/);
  assert.match(profileForm, /seed: Number\(form\.seed\)/);
  assert.match(pane, /selectedDevice\.hardwareConcurrency/);
  assert.match(pane, /selectedDevice\.deviceMemory/);
  assert.match(profileForm, /form\.engine !== "camoufox" && <div><dt>\{t\("内存规格"\)\}/);
  assert.match(profileForm, /selectedDevice && form\.engine === "camoufox"/);
  assert.match(profileForm, /Camoufox 自动管理设备指纹，无需设置内存。固定模板会固定外层窗口尺寸。/);
  assert.match(pane, /浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。/);
  assert.match(profileForm, /standard: "拦截已知第三方追踪；个别网站可能需要调整防护设置。"/);
  assert.doesNotMatch(profileForm, /不影响登录和网站功能/);
  const terminal = await readFile(new URL('../src/TerminalPane.jsx', import.meta.url), 'utf8');
  assert.match(terminal, /selectedSession\?\.language \?\? selectedMetadata\?\.language/);
  const terminalContext = terminal.slice(terminal.indexOf('<details className="terminal-context-menu"'), terminal.indexOf('<TerminalDeviceIdentifierDetails'));
  assert.match(terminalContext, /languageLabel && <div><dt>\{t\('有效语言'\)\}<\/dt><dd className=\{sessionLanguage\.fallback \? 'is-fallback' : ''\}>\{languageLabel\}<\/dd>/);
});

test('device and effective-language copy is available in all nine languages', () => {
  const keys = ['设备档案', '自定义（保留当前配置）', '选择档案会填写平台与屏幕；切换网络不改变设备。', '平台', '屏幕', '逻辑处理器', '内存规格', '浏览器语言与 Envara 界面语言独立；网站可能自行选择语言。', '当前内核暂不支持固定设备档案。', '有效语言', '{requested} → {effective}（系统未提供所选语言）', ...BROWSER_DEVICE_PROFILES.map(item => item.label), '内核自动生成', '保留当前配置', '自动（由内核决定）', '未填写的设备参数由内核处理；已填写的自定义值会保留。', '设备模板（可选）'];
  for (const [language, catalog] of Object.entries(translationCatalog)) {
    assert.equal(typeof catalog['Camoufox 自动管理设备指纹，无需设置内存。固定模板会固定外层窗口尺寸。'], 'string', language);
    assert.equal(typeof catalog['现有 Camoufox 身份与所选模板的平台不一致或无法确认。请保留自定义配置，或新建环境后选择模板。'], 'string', language);
    assert.equal(typeof catalog['拦截已知第三方追踪；个别网站可能需要调整防护设置。'], 'string', language);
    assert.equal(Object.hasOwn(catalog, '拦截已知的第三方追踪：内置规则加 EasyPrivacy 名单，不影响登录和网站功能。'), false, language);
    for (const key of keys) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    for (const key of ['浏览器设备档案无效。', '此浏览器内核暂不支持固定设备档案，请保留现有配置。', '设备档案与平台或硬件参数不一致。请先切换为自定义配置。', '固定设备档案须与本机平台一致。跨平台配置请使用自定义。']) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
    assert.ok(translate(keys[10], language, { requested: 'ms-MY', effective: 'en-US' }).includes('ms-MY'));
    assert.ok(translate(keys[10], language, { requested: 'ms-MY', effective: 'en-US' }).includes('en-US'));
  }
});
