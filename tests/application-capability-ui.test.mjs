import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { supportsAttachedApplication, canDeleteApplicationData } from '../src/application-capability.mjs';
import { translationCatalog } from '../src/i18n.mjs';

let ApplicationsWorkspace, ApplicationDataPanel;
before(async () => {
  // Render the real components with fixture props, without a desktop service,
  // saved user data or a frontend build.
  const result = await build({ entryPoints: [fileURLToPath(new URL('../src/workspace-pages.jsx', import.meta.url))],
    bundle: true, platform: 'node', format: 'cjs', mainFields: ['module', 'main'], external: ['react', 'react-dom'], write: false });
  const module = { exports: {} };
  new Function('require', 'module', 'exports', 'window', result.outputFiles[0].text)(createRequire(import.meta.url), module, module.exports, { envara: {} });
  ({ ApplicationsWorkspace, ApplicationDataPanel } = module.exports);
});
const noop = () => {};
const fixture = (application, extra = {}) => ({
  profiles: [{ id: 'env', name: 'Fixture environment' }], proxies: [], selectedId: 'env', applications: [application],
  routing: { backend: 'pf-utun', ready: false, controlledNotionTrialAvailable: true }, desktop: true, systemPlatform: 'darwin',
  onSelect: noop, onPick: noop, onStart: noop, onStop: noop, onRunNotionTrial: noop, onStopNotionTrial: noop,
  onChooseLinkBrowser: noop, linkCandidates: () => [], onDelete: noop, pending: {}, t: value => value, ...extra,
});
const app = { id: 'app', name: 'Fixture app', identity: 'bundle:fixture.app', path: '/Applications/Fixture.app', profileId: 'env', status: 'stopped' };
const supported = { supported: true, adapter: 'chromium-front', verification: 'pending', dataScope: 'environment' };
const renderApp = (value, extra) => renderToStaticMarkup(React.createElement(ApplicationsWorkspace, fixture(value, extra)));
const action = (html, text) => [...html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)].find(match => match[2].endsWith(text))?.[1];
const readiness = html => /<div class="routing-readiness"[^>]*>([\s\S]*?)<\/div>/.exec(html)?.[1];

test('preview routing renders its repeated desktop requirement only once in every interface language', () => {
  for (const [language, catalog] of Object.entries(translationCatalog)) {
    const html = renderApp(app, { desktop: false, routing: { ready: false, message: '本地软件需要桌面应用。' }, t: key => catalog[key] ?? key });
    const notice = readiness(html);
    assert.ok(notice, language); assert.match(notice, /<strong>/, language);
    assert.doesNotMatch(notice, /<span>/, language);
  }
});

test('routing deduplicates only the same notice and retains detailed failures, fallback guidance and installation actions', () => {
  for (const [status, title] of [['prepared', '网络组件已准备'], ['authorization-required', '需要系统授权'], ['unavailable', '网络接管尚未就绪']]) {
    const repeated = readiness(renderApp(app, { routing: { ready: false, status, message: `  ${title}。  ` } }));
    assert.doesNotMatch(repeated, /<span>/);
    const failure = `${title}。权限检查失败：APPLICATION_ROUTING_NOT_READY`;
    assert.ok(readiness(renderApp(app, { routing: { ready: false, status, message: failure } })).includes(failure));
  }
  const html = renderApp(app, { routing: { backend: 'pf-utun', ready: false, installed: false,
    component: { available: true, verified: true } }, onInstall: noop });
  assert.ok(readiness(html).includes('完成系统网络组件安装后，才能启动附加软件。'));
  assert.doesNotMatch(action(html, '安装网络组件'), /disabled/);
});

test('only inspected Mac adapters enable attach; other platforms retain their existing routing gate', () => {
  for (const candidate of [app, { ...app, compatibility: { ...supported, supported: false } },
    { ...app, compatibility: { ...supported, adapter: 'unsupported' } }]) assert.equal(supportsAttachedApplication(candidate, 'darwin'), false);
  assert.equal(supportsAttachedApplication({ ...app, compatibility: supported }, 'darwin'), true);
  for (const platform of ['win32', 'linux']) assert.equal(supportsAttachedApplication(app, platform), true);
});

test('unsupported Mac rows refuse start while retaining stop for an existing run', () => {
  const blocked = renderApp(app);
  assert.match(action(blocked, '启动'), /disabled/);
  assert.match(blocked, /暂不支持此软件的网络隔离/);
  const allowed = renderApp({ ...app, compatibility: supported });
  assert.doesNotMatch(action(allowed, '启动'), /disabled/);
  assert.doesNotMatch(allowed, /已保护|硬件已隔离|验证通过/);
  const running = renderApp({ ...app, notionTrial: { applicationId: app.id, active: true, phase: 'running', events: [] } });
  assert.doesNotMatch(action(running, '停止'), /disabled/);
  assert.doesNotMatch(running, /暂不支持此软件的网络隔离/);
  const windows = renderApp(app, { systemPlatform: 'win32', routing: { ready: true } });
  assert.doesNotMatch(action(windows, '启动'), /disabled/);
});

test('application data actions distinguish missing directories, real empty data and running software', () => {
  const base = { id: 'env:app', bytes: 0, application: { name: 'Fixture app' }, environment: { name: 'Fixture environment' }, running: false };
  const renderData = item => renderToStaticMarkup(React.createElement(ApplicationDataPanel, {
    items: [item], totalBytes: 0, pending: {}, onReload: noop, onDelete: noop, formatBytes: value => `${value} B`, t: value => value,
  }));
  for (const missing of [base, { ...base, dataScope: 'unavailable', hasDataDirectory: false }]) {
    assert.equal(canDeleteApplicationData(missing), false);
    const html = renderData(missing);
    assert.match(html, /未生成应用数据/);
    assert.doesNotMatch(html, /aria-label="删除"/);
  }
  const exists = { ...base, dataScope: 'environment', hasDataDirectory: true };
  assert.equal(canDeleteApplicationData(exists), true);
  assert.match(renderData(exists), /没有应用数据/);
  assert.match(renderData(exists), /aria-label="删除"/);
  assert.equal(canDeleteApplicationData({ ...exists, running: true }), false);
  assert.doesNotMatch(renderData({ ...exists, running: true }), /aria-label="删除"/);
});

test('an unconfirmed cleanup keeps its diagnostic and exposes only cleanup retry', () => {
  const trial = { applicationId: app.id, active: false, phase: 'cleanup-required', cleanupUncertain: true,
    cleanupRetryable: true, errorCode: 'APPLICATION_APP_STAGE_TIMEOUT', events: [] };
  const html = renderApp({ ...app, notionTrial: trial });
  assert.doesNotMatch(action(html, '重试清理'), /disabled/);
  assert.equal(action(html, '启动'), undefined);
  assert.match(html, /清理未确认/);
  const pending = renderApp({ ...app, notionTrial: trial }, { pending: { 'stopNotionTrial:app': true } });
  assert.match(action(pending, '重试清理'), /disabled/);
});

test('file picker, next/save and existing app rows all use the same platform-aware capability gate', async () => {
  const source = await readFile(new URL('../src/App.jsx', import.meta.url), 'utf8');
  assert.match(source, /!supportsAttachedApplication\(result, systemPlatform\)/);
  assert.match(source, /!supportsAttachedApplication\(picked, systemPlatform\)/);
  assert.match(source, /!supportsAttachedApplication\(application, system\.platform\)/);
  assert.match(source, /disabled=\{attached \|\| !supported\}/);
  assert.match(source, /step !== "application" && error/);
  assert.match(source, /删除「\{value1\}」的应用数据？/);
  assert.match(source, /登录信息、设置与本地内容，无法恢复。软件本身和外部项目文件不受影响。/);
});

test('capability and application-data explanations are available in all nine languages', () => {
  const keys = ['重试清理', '下一步', '未选择', '应用数据', '未生成应用数据', '没有应用数据', '暂不支持此软件的网络隔离', '暂不支持此软件的网络隔离。',
    '此软件尚未生成境舱应用数据。', '应用数据没有全部清除，请退出这个软件后重试。', '删除「{value1}」的应用数据？',
    '将删除此境舱内该软件的登录信息、设置与本地内容，无法恢复。软件本身和外部项目文件不受影响。',
    '独立数据目录不等于系统沙箱；软件的硬件信息、系统定位与钥匙串不会被替换。'];
  for (const [language, catalog] of Object.entries(translationCatalog))
    for (const key of keys) assert.equal(typeof catalog[key], 'string', `${language}: ${key}`);
});
