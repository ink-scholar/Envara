import test from 'node:test';
import assert from 'node:assert/strict';
import { createInterfaceLanguageController, isSettingsSnapshot } from '../src/interface-language-state.mjs';

const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const snapshot = (settings = {}) => ({ profiles: [], proxies: [], settings, system: { platform: 'darwin', appVersion: '0.5.0' } });
const flush = async () => { await Promise.resolve(); await Promise.resolve(); };
function fixture(value = snapshot()) {
  const listeners = new Set();
  const calls = [];
  let current = value;
  let load = async () => current;
  let save = async args => { current = snapshot({ ...current.settings, ...args.settings }); listeners.forEach(listener => listener(current)); return current; };
  const api = {
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    call(method, args) { calls.push({ method, args }); return method === 'snapshot' ? load() : save(args); },
  };
  return { api, calls, setLoad(value) { load = value; }, setSave(value) { save = value; }, emit(value) { current = value; listeners.forEach(listener => listener(value)); }, listeners };
}

test('first-run decision requires real settings, system identity and snapshot arrays', () => {
  assert.equal(isSettingsSnapshot({ profiles: [], proxies: [], settings: {}, system: {} }), false);
  assert.equal(isSettingsSnapshot({ settings: { language: 'ja' } }), false);
  assert.equal(isSettingsSnapshot({ ...snapshot(), settings: [] }), false);
  assert.equal(isSettingsSnapshot(snapshot()), true);
});

test('missing saved language recommends the system language only after the settings read', async () => {
  const f = fixture(); const pending = deferred(); f.setLoad(() => pending.promise);
  const controller = createInterfaceLanguageController({ api: f.api, preferences: ['zh-Hant-HK'] });
  controller.start();
  assert.equal(controller.getState().phase, 'loading');
  assert.equal(controller.getState().language, 'zh-TW');
  f.emit({ profiles: [], proxies: [], settings: {}, system: {} });
  assert.equal(controller.getState().phase, 'loading');
  pending.resolve(snapshot()); await flush();
  assert.equal(controller.getState().phase, 'required'); controller.stop();
});

test('an existing saved language suppresses onboarding and wins over the system recommendation', async () => {
  const f = fixture(snapshot({ language: 'pt-BR' }));
  const controller = createInterfaceLanguageController({ api: f.api, preferences: ['ja-JP'] });
  controller.start(); await flush();
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().language, 'pt-BR');
  assert.equal(f.calls.filter(item => item.method === 'saveSettings').length, 0); controller.stop();
});

test('placeholder or language-less subscription cannot override a saved first snapshot', async () => {
  const f = fixture(); const pending = deferred(); f.setLoad(() => pending.promise);
  const controller = createInterfaceLanguageController({ api: f.api }); controller.start();
  f.emit(snapshot());
  pending.resolve(snapshot({ language: 'de' })); await flush();
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().language, 'de'); controller.stop();
});

test('a newer saved-language subscription wins over a stale first snapshot', async () => {
  const f = fixture(); const pending = deferred(); f.setLoad(() => pending.promise);
  const controller = createInterfaceLanguageController({ api: f.api }); controller.start();
  f.emit(snapshot({ language: 'ko' }));
  pending.resolve(snapshot({ language: 'en' })); await flush();
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().language, 'ko'); controller.stop();
});

test('a first-run choice previews locally and closes only after persistence resolves', async () => {
  const f = fixture(); const pending = deferred();
  f.setSave(args => { f.emit(snapshot(args.settings)); return pending.promise; });
  const controller = createInterfaceLanguageController({ api: f.api, preferences: ['en'] }); controller.start(); await flush();
  controller.previewLanguage('ja');
  assert.equal(controller.getState().language, 'ja');
  assert.equal(f.calls.filter(item => item.method === 'saveSettings').length, 0);
  const saving = controller.setLanguage('ja');
  assert.equal(controller.getState().phase, 'required'); assert.equal(controller.getState().saving, true);
  assert.deepEqual(f.calls.at(-1).args, { settings: { closeBrowsersOnExit: true, language: 'ja' } });
  pending.resolve(snapshot({ closeBrowsersOnExit: true, language: 'ja' })); await saving;
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().saving, false); controller.stop();
});

test('failed first-run save keeps the choice and can retry without replaying any workspace operation', async () => {
  const f = fixture(); f.setSave(async () => { throw new Error('disk failure'); });
  const controller = createInterfaceLanguageController({ api: f.api }); controller.start(); await flush();
  controller.previewLanguage('fr'); await assert.rejects(controller.setLanguage('fr'));
  assert.equal(controller.getState().phase, 'required'); assert.equal(controller.getState().language, 'fr');
  assert.equal(controller.getState().error, '无法保存语言，请重试。'); assert.equal(controller.getState().saving, false);
  f.setSave(async args => snapshot(args.settings)); await controller.setLanguage('fr');
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().language, 'fr');
  assert.ok(f.calls.every(item => ['snapshot', 'saveSettings'].includes(item.method))); controller.stop();
});

test('failed settings reads have a separate retry state and never infer a fresh installation', async () => {
  const f = fixture(); f.setLoad(async () => { throw new Error('unavailable'); });
  const controller = createInterfaceLanguageController({ api: f.api }); controller.start(); await flush();
  assert.equal(controller.getState().phase, 'error'); assert.equal(controller.getState().error, '无法读取设置，请重试。');
  f.setLoad(async () => snapshot({ language: 'es' })); await controller.reload();
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().language, 'es'); controller.stop();
});

test('settings language changes preserve the exit preference and roll back after failed persistence', async () => {
  const f = fixture(snapshot({ language: 'en', closeBrowsersOnExit: false }));
  const controller = createInterfaceLanguageController({ api: f.api }); controller.start(); await flush();
  f.setSave(async () => { throw new Error('not saved'); }); await assert.rejects(controller.setLanguage('zh-TW'));
  assert.equal(controller.getState().phase, 'ready'); assert.equal(controller.getState().language, 'en');
  assert.deepEqual(f.calls.at(-1).args, { settings: { closeBrowsersOnExit: false, language: 'zh-TW' } }); controller.stop();
});

test('a persisted notification does not make the selector interactive before the save IPC completes', async () => {
  const f = fixture(snapshot({ language: 'fr' })); const pending = deferred();
  f.setSave(args => { f.emit(snapshot(args.settings)); return pending.promise; });
  const controller = createInterfaceLanguageController({ api: f.api }); controller.start(); await flush();

  const saving = controller.setLanguage('zh-CN');
  assert.equal((await f.api.call('snapshot')).settings.language, 'zh-CN');
  assert.equal(controller.getState().language, 'zh-CN');
  assert.equal(controller.getState().saving, true);
  assert.equal(await controller.setLanguage('zh-TW'), false);
  assert.equal(f.calls.filter(item => item.method === 'saveSettings').length, 1);

  pending.resolve(snapshot({ language: 'zh-CN' })); await saving;
  assert.equal(controller.getState().saving, false);
  f.setSave(async args => { const value = snapshot(args.settings); f.emit(value); return value; });
  assert.equal(await controller.setLanguage('zh-TW'), true);
  assert.equal((await f.api.call('snapshot')).settings.language, 'zh-TW');
  assert.equal(controller.getState().language, 'zh-TW'); controller.stop();
});

test('independent window controllers follow persisted language notifications without creating sessions', async () => {
  const f = fixture(snapshot({ language: 'en' }));
  const main = createInterfaceLanguageController({ api: f.api }); const terminal = createInterfaceLanguageController({ api: f.api });
  main.start(); terminal.start(); await flush(); await main.setLanguage('ko');
  assert.equal(main.getState().language, 'ko'); assert.equal(terminal.getState().language, 'ko');
  main.stop(); terminal.stop(); assert.equal(f.listeners.size, 0);
  assert.ok(f.calls.every(item => ['snapshot', 'saveSettings'].includes(item.method)));
});

test('stopped reads and unsupported language choices cannot change or persist the interface', async () => {
  const f = fixture(); const pending = deferred(); f.setLoad(() => pending.promise);
  const controller = createInterfaceLanguageController({ api: f.api, preferences: ['en'] }); controller.start(); controller.stop();
  pending.resolve(snapshot({ language: 'ja' })); await flush();
  assert.equal(controller.getState().language, 'en'); controller.previewLanguage('unsupported');
  assert.equal(await controller.setLanguage('unsupported'), false);
  assert.equal(f.calls.filter(item => item.method === 'saveSettings').length, 0);
});
